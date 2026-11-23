package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	bodyLimit  = 1 << 20
	fileCount  = 16
	messageTTL = 7 * 24 * time.Hour
)

type delivery struct {
	To       string `json:"to"`
	From     string `json:"from"`
	Body     string `json:"body"`
	Encoding string `json:"encoding"`
	ReplyTo  string `json:"reply_to"`
}

type attachment struct {
	ID   string `json:"attachment_id"`
	Name string `json:"filename"`
	Size int64  `json:"size"`
}

type upload struct {
	delivery
	files []attachment
	size  int64
	// Maximum charge this member can make, held stable against other sends
	// until this upload commits or discards its staged bytes.
	quota int64
}

func quotaExceeded() error { return &httpError{507, "member storage quota exceeded"} }

// capacity returns the tightest applicable remaining limit and its error.
func (r *Relay) capacity(u *upload, part int64) (int64, error) {
	limit, reason := part, oversized("message part too large")
	if msg := r.cfg.MaxMessageBytes - u.size; msg < limit {
		limit, reason = msg, oversized("message exceeds total byte limit")
	}
	if available := u.quota - u.size; available < limit {
		limit, reason = available, quotaExceeded()
	}
	return limit, reason
}

func (r *Relay) localID(address string) (string, bool) {
	id, host, ok := strings.Cut(address, "@")
	return id, ok && id != "" && strings.EqualFold(host, r.cfg.Host) && validText(id, 128) && !strings.ContainsAny(id, "/\\ ")
}

func (r *Relay) send(w http.ResponseWriter, req *http.Request, m *member) error {
	if req.Header.Get("X-Inbox-Secret") == "" {
		return forbidden()
	}
	media, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && media != "multipart/form-data") {
		return &httpError{415, "expected application/json or multipart/form-data"}
	}
	ctx := req.Context()
	select {
	case m.upload <- struct{}{}:
		defer func() { <-m.upload }()
	case <-ctx.Done():
		return ctx.Err()
	}
	var used int64
	if err := r.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(byte_count),0) FROM messages WHERE member=?", m.label).Scan(&used); err != nil {
		return err
	}
	u := upload{quota: r.cfg.QuotaBytes - used}
	if u.quota < 0 {
		return quotaExceeded()
	}
	if media == "application/json" {
		// JSON control characters can use six wire bytes per stored byte.
		if err := readJSON(w, req, 6*bodyLimit+8192, false, &u.delivery); err != nil {
			return err
		}
		limit, reason := r.capacity(&u, bodyLimit)
		if int64(len(u.Body)) > limit {
			return reason
		}
		u.size = int64(len(u.Body))
	} else {
		defer func() {
			for _, a := range u.files {
				removeUnused(filepath.Join(r.staging, a.ID))
			}
		}()
		if err := r.multipart(w, req, &u); err != nil {
			return err
		}
	}
	if u.Encoding == "" {
		u.Encoding = "plain"
	}
	switch u.Encoding {
	case "plain":
		if !utf8.ValidString(u.Body) {
			return bad("plain body must be UTF-8")
		}
	case "age":
		if _, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(u.Body))); err != nil {
			return bad("age body must be base64 encoded")
		}
	default:
		return bad("unknown message encoding")
	}
	if u.Body == "" && len(u.files) == 0 {
		return bad("body or attachment required")
	}
	if u.ReplyTo != "" {
		if n, ok := decimalID(u.ReplyTo); !ok || n == 0 {
			return bad("invalid reply_to message ID")
		}
	}
	from, ok := r.localID(u.From)
	if !ok {
		return forbidden()
	}
	if err := r.authorize(req, from); err != nil {
		return err
	}
	to, ok := r.localID(u.To)
	if !ok {
		return bad("expected a local recipient address")
	}
	var exists bool
	if err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM inboxes WHERE id=?)", to).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return missing("recipient inbox not found")
	}
	id, expires, err := r.deliver(ctx, m, &u, from, to)
	if err != nil {
		return err
	}
	writeJSON(w, 201, struct {
		ID      string    `json:"message_id"`
		Expires time.Time `json:"expires_at"`
	}{strconv.FormatInt(id, 10), expires})
	return nil
}

func removeUnused(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("spool relay: removing unused file: %v", err)
	}
}

func (r *Relay) multipart(w http.ResponseWriter, req *http.Request, u *upload) error {
	wireMax := min(r.cfg.MaxMessageBytes, int64(math.MaxInt64)-(1<<20)) + (1 << 20)
	if req.ContentLength > wireMax {
		return oversized("multipart request too large")
	}
	req.Body = http.MaxBytesReader(w, req.Body, wireMax)
	reader, err := req.MultipartReader()
	if err != nil {
		return bad("invalid multipart content type")
	}
	seen := make(map[string]bool)
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if errors.Is(err, multipart.ErrMessageTooLarge) {
				return oversized("multipart headers too large")
			}
			return inputError(err)
		}
		// Parse the original filename, not Part.FileName(), which applies
		// platform-specific filepath.Base and obscures path separators.
		disposition, fields, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || disposition != "form-data" {
			return bad("invalid multipart disposition")
		}
		name := fields["name"]
		filename, isFile := fields["filename"]
		if name == "files[]" {
			if !isFile || filename == "" || filename == "." || filename == ".." || !validText(filename, 255) || strings.ContainsAny(filename, "/\\") {
				return bad("expected a safe attachment basename")
			}
			if len(u.files) == fileCount {
				return oversized("too many attachments")
			}
			if err := r.stage(part, u, filename); err != nil {
				return err
			}
			continue
		}
		if isFile || seen[name] {
			return bad("unexpected or duplicate multipart field")
		}
		seen[name] = true
		var dst *string
		limit, reason := int64(512), oversized("multipart field too large")
		switch name {
		case "from":
			dst = &u.From
		case "to":
			dst = &u.To
		case "reply_to":
			dst = &u.ReplyTo
		case "encoding":
			dst = &u.Encoding
		case "body":
			dst = &u.Body
			limit, reason = r.capacity(u, bodyLimit)
		default:
			return bad("unknown multipart field")
		}
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			return inputError(err)
		}
		if int64(len(data)) > limit {
			return reason
		}
		*dst = string(data)
		if name == "body" {
			u.size += int64(len(data))
		}
	}
}

func (r *Relay) stage(part *multipart.Part, u *upload, name string) error {
	id := "a_" + rand.Text()
	f, err := os.OpenFile(filepath.Join(r.staging, id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	a := attachment{ID: id, Name: name}
	u.files = append(u.files, a) // Schedule cleanup even when copy or close fails.
	limit, reason := r.capacity(u, r.cfg.MaxFileBytes)
	n, err := io.Copy(f, io.LimitReader(part, limit))
	if err == nil && n == limit {
		var one [1]byte
		if extra, probeErr := io.ReadFull(part, one[:]); extra != 0 {
			err = reason
		} else if !errors.Is(probeErr, io.EOF) {
			err = probeErr
		}
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		var osErr *os.PathError
		var limitErr *httpError
		if errors.As(err, &osErr) || errors.As(err, &limitErr) {
			return err
		}
		return inputError(err)
	}
	if closeErr != nil {
		return closeErr
	}
	u.files[len(u.files)-1].Size = n
	u.size += n
	return nil
}

func (r *Relay) deliver(ctx context.Context, m *member, u *upload, from, to string) (int64, time.Time, error) {
	r.files.Lock()
	defer r.files.Unlock()
	now := r.cfg.Now().UTC()
	expires := now.Add(messageTTL)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, expires, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(sender,recipient,body,encoding,reply_to,created,expires,member,byte_count) VALUES(?,?,?,?,?,?,?,?,?)`, from, to, u.Body, u.Encoding, u.ReplyTo, now.UnixNano(), expires.UnixNano(), m.label, u.size)
	if err != nil {
		return 0, expires, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, expires, err
	}
	promoted := 0
	defer func() {
		for _, a := range u.files[:promoted] {
			removeUnused(filepath.Join(r.blobs, a.ID))
		}
	}()
	for _, a := range u.files {
		if _, err := tx.ExecContext(ctx, `INSERT INTO attachments(id,message_id,filename,size) VALUES(?,?,?,?)`, a.ID, id, a.Name, a.Size); err != nil {
			return 0, expires, err
		}
		dest := filepath.Join(r.blobs, a.ID)
		if _, err := os.Lstat(dest); err == nil {
			return 0, expires, errors.New("attachment ID collision")
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, expires, err
		}
		if err := os.Rename(filepath.Join(r.staging, a.ID), dest); err != nil {
			return 0, expires, err
		}
		promoted++
	}
	if err := tx.Commit(); err != nil {
		return 0, expires, err
	}
	promoted = 0
	return id, expires, nil
}
