package relay

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type messageView struct {
	ID          string          `json:"message_id"`
	From        string          `json:"from"`
	To          string          `json:"to"`
	Body        string          `json:"body"`
	Encoding    string          `json:"encoding"`
	ReplyTo     string          `json:"reply_to,omitempty"`
	Created     time.Time       `json:"created_at"`
	Expires     time.Time       `json:"expires_at"`
	Attachments json.RawMessage `json:"attachments"`
}

const pageQuery = `SELECT m.id, m.sender, m.body, m.encoding, m.reply_to, m.created, m.expires,
 (SELECT json_group_array(json_object('attachment_id',a.id,'filename',a.filename,'size',a.size) ORDER BY a.rowid)
  FROM attachments a WHERE a.message_id=m.id)
 FROM messages m WHERE m.recipient=? AND m.id>? AND m.expires>? ORDER BY m.id LIMIT ?`

func (r *Relay) poll(w http.ResponseWriter, req *http.Request, inbox string) error {
	q := req.URL.Query()
	var since int64
	if q.Has("since") {
		var ok bool
		since, ok = decimalID(q.Get("since"))
		if !ok {
			return bad("invalid since cursor")
		}
	}
	limit := 50
	if q.Has("limit") {
		n, ok := decimalID(q.Get("limit"))
		if !ok || n < 1 || n > 100 {
			return bad("limit must be between 1 and 100")
		}
		limit = int(n)
	}
	// A single SELECT provides a consistent view of messages and attachments.
	// Encode each message before advancing instead of buffering 100 large bodies.
	rows, err := r.db.QueryContext(req.Context(), pageQuery, inbox, since, r.cfg.Now().UnixNano(), limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	cursor := strconv.FormatInt(since, 10)
	address := inbox + "@" + r.cfg.Host
	started := false
	for rows.Next() {
		var m messageView
		var id, created, expires int64
		var attachments []byte
		if err := rows.Scan(&id, &m.From, &m.Body, &m.Encoding, &m.ReplyTo, &created, &expires, &attachments); err != nil {
			if started {
				log.Printf("wire relay: poll read: %v", err)
				panic(http.ErrAbortHandler)
			}
			return err
		}
		m.ID = strconv.FormatInt(id, 10)
		m.From += "@" + r.cfg.Host
		m.To = address
		m.Created, m.Expires = time.Unix(0, created).UTC(), time.Unix(0, expires).UTC()
		m.Attachments = attachments
		if !started {
			writeFragment(w, `{"messages":[`)
			started = true
		} else {
			writeFragment(w, ",")
		}
		if err := enc.Encode(m); err != nil {
			panic(http.ErrAbortHandler)
		}
		cursor = m.ID
	}
	if err := rows.Err(); err != nil {
		if started {
			log.Printf("wire relay: poll read: %v", err)
			panic(http.ErrAbortHandler)
		}
		return err
	}
	if !started {
		writeFragment(w, `{"messages":[`)
	}
	// cursor is an internally generated nonnegative decimal, never raw input.
	writeFragment(w, `],"next_cursor":"`+cursor+`"}`)
	return nil
}

func writeFragment(w io.Writer, s string) {
	if _, err := io.WriteString(w, s); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (r *Relay) openAttachment(req *http.Request, inbox, id string) (*os.File, attachment, string, error) {
	r.files.Lock()
	defer r.files.Unlock()
	var a attachment
	var encoding string
	err := r.db.QueryRowContext(req.Context(), `SELECT a.id,a.filename,a.size,m.encoding FROM attachments a
	 JOIN messages m ON m.id=a.message_id WHERE a.id=? AND m.recipient=? AND m.expires>?`, id, inbox, r.cfg.Now().UnixNano()).Scan(&a.ID, &a.Name, &a.Size, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, a, "", missing("attachment not found")
	}
	if err != nil {
		return nil, a, "", err
	}
	// Only a generated ID read from committed metadata is used as a disk path.
	f, err := os.Open(filepath.Join(r.blobs, a.ID))
	return f, a, encoding, err
}

func (r *Relay) download(w http.ResponseWriter, req *http.Request, inbox, id string) error {
	f, a, encoding, err := r.openAttachment(req, inbox, id)
	if err != nil {
		return err
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Name}))
	w.Header().Set("Content-Length", strconv.FormatInt(a.Size, 10))
	w.Header().Set("X-Wire-Encoding", encoding)
	w.WriteHeader(200)
	if n, err := io.Copy(w, f); err != nil || n != a.Size {
		panic(http.ErrAbortHandler)
	}
	return nil
}

func (r *Relay) delete(w http.ResponseWriter, req *http.Request, inbox, id string) error {
	n, ok := decimalID(id)
	if !ok || n == 0 {
		return bad("invalid message ID")
	}
	r.files.Lock()
	defer r.files.Unlock()
	ctx := req.Context()
	res, err := r.db.ExecContext(ctx, "DELETE FROM messages WHERE id=? AND recipient=? AND expires>?", n, inbox, r.cfg.Now().UnixNano())
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return missing("message not found")
	}
	if err := r.collect(ctx); err != nil {
		// The logical deletion already committed; its durable unlink queue is
		// retried by Sweep if a download or transient failure delayed removal.
		log.Printf("wire relay: collect deleted attachments: %v", err)
	}
	w.WriteHeader(204)
	return nil
}
