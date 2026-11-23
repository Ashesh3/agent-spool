package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
)

type httpError struct {
	status int
	text   string
}

func (e *httpError) Error() string { return e.text }

func bad(text string) error       { return &httpError{400, text} }
func forbidden() error            { return &httpError{403, "invalid inbox credentials"} }
func missing(text string) error   { return &httpError{404, text} }
func oversized(text string) error { return &httpError{413, text} }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func handleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	status, text := 500, "internal relay error"
	var e *httpError
	if errors.As(err, &e) {
		status, text = e.status, e.text
	} else if !errors.Is(err, context.Canceled) {
		log.Printf("spool relay: %v", err)
	}
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{text})
}

func (r *Relay) gate(req *http.Request) *member {
	scheme, token, ok := strings.Cut(req.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	var found *member
	for _, m := range r.members {
		if subtle.ConstantTimeCompare(digest[:], m.digest[:]) == 1 {
			found = m
		}
	}
	return found
}

func (m *member) rate(now time.Time, limit int) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !now.Before(m.until) {
		m.until, m.count = now.Add(time.Minute), 0
	}
	if m.count >= limit {
		return m.until.Sub(now)
	}
	m.count++
	return 0
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if req.Method == http.MethodGet && req.URL.Path == "/healthz" {
		writeJSON(w, 200, struct {
			Status string `json:"status"`
		}{"ok"})
		return
	}
	m := r.gate(req)
	if m == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="spool"`)
		handleError(w, &httpError{401, "invalid gate key"})
		return
	}
	if d := m.rate(r.cfg.Now(), r.cfg.RequestsPerMinute); d > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((d+time.Second-1)/time.Second), 10))
		handleError(w, &httpError{429, "request rate limit exceeded"})
		return
	}
	handleError(w, r.route(w, req, m))
}

func (r *Relay) route(w http.ResponseWriter, req *http.Request, m *member) error {
	path := req.URL.Path
	if req.Method == http.MethodPost {
		switch path {
		case "/v1/inboxes":
			return r.provision(w, req)
		case "/v1/messages":
			return r.send(w, req, m)
		}
	}
	rest, ok := strings.CutPrefix(path, "/v1/inboxes/")
	id, action, hasAction := strings.Cut(rest, "/")
	if !ok || !hasAction || id == "" {
		return missing("route not found")
	}
	if req.Method == http.MethodGet && action == "pubkey" {
		var key string
		err := r.db.QueryRowContext(req.Context(), "SELECT public_key FROM inboxes WHERE id=?", id).Scan(&key)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && key == "") {
			return missing("no public key for this inbox")
		}
		if err != nil {
			return err
		}
		writeJSON(w, 200, struct {
			PublicKey string `json:"public_key"`
		}{key})
		return nil
	}
	if req.Method == http.MethodGet && action == "messages" {
		if err := r.authorize(req, id); err != nil {
			return err
		}
		return r.poll(w, req, id)
	}
	kind, item, ok := strings.Cut(action, "/")
	if ok && item != "" && !strings.Contains(item, "/") {
		switch {
		case req.Method == http.MethodGet && kind == "attachments":
			if err := r.authorize(req, id); err != nil {
				return err
			}
			return r.download(w, req, id, item)
		case req.Method == http.MethodDelete && kind == "messages":
			if err := r.authorize(req, id); err != nil {
				return err
			}
			return r.delete(w, req, id, item)
		}
	}
	return missing("route not found")
}

func (r *Relay) authorize(req *http.Request, id string) error {
	digest := sha256.Sum256([]byte(req.Header.Get("X-Inbox-Secret")))
	var expected []byte
	err := r.db.QueryRowContext(req.Context(), "SELECT secret_hash FROM inboxes WHERE id=?", id).Scan(&expected)
	if errors.Is(err, sql.ErrNoRows) {
		return forbidden()
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
		return forbidden()
	}
	return nil
}

func inputError(err error) error {
	var large *http.MaxBytesError
	if errors.As(err, &large) {
		return oversized("request exceeds wire size limit")
	}
	return bad("invalid request body")
}

func readJSON(w http.ResponseWriter, req *http.Request, limit int64, optional bool, dst any) error {
	reader := http.MaxBytesReader(w, req.Body, limit)
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return nil
		}
		return inputError(err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return inputError(err)
	}
	return nil
}

func validText(s string, size int) bool {
	return utf8.ValidString(s) && len(s) <= size && strings.IndexFunc(s, unicode.IsControl) == -1
}

func newHandle() string {
	adjectives := [...]string{"amber", "brisk", "coral", "dusk", "fern", "lunar", "opal", "swift"}
	animals := [...]string{"crane", "finch", "fox", "hare", "ibis", "lynx", "otter", "wren"}
	var b [10]byte
	rand.Read(b[:])
	return adjectives[b[0]%8] + "-" + animals[b[1]%8] + "-" + hex.EncodeToString(b[2:])
}

func (r *Relay) provision(w http.ResponseWriter, req *http.Request) error {
	var input struct {
		Label     string `json:"label"`
		PublicKey string `json:"public_key"`
	}
	if err := readJSON(w, req, 8192, true, &input); err != nil {
		return err
	}
	if !validText(input.Label, 128) {
		return bad("invalid inbox label")
	}
	if input.PublicKey != "" {
		key, err := age.ParseX25519Recipient(input.PublicKey)
		if err != nil || key.String() != input.PublicKey {
			return bad("expected an age X25519 public key")
		}
	}
	secret := "is_" + rand.Text()
	digest := sha256.Sum256([]byte(secret))
	for {
		id := newHandle()
		res, err := r.db.ExecContext(req.Context(), `INSERT INTO inboxes(id,secret_hash,label,public_key) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING`, id, digest[:], input.Label, input.PublicKey)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 0 {
			writeJSON(w, 201, struct {
				Address string `json:"address"`
				ID      string `json:"inbox_id"`
				Secret  string `json:"inbox_secret"`
			}{id + "@" + r.cfg.Host, id, secret})
			return nil
		}
	}
}

func decimalID(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= 0 && s == strconv.FormatInt(n, 10)
}
