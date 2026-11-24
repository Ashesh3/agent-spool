package relay

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
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

const messageQuery = `SELECT sender.handle, m.body, m.encoding, m.reply_to, m.created, m.expires,
 (SELECT json_group_array(json_object('attachment_id',a.id,'filename',a.filename,'size',a.size) ORDER BY a.rowid)
  FROM attachments a WHERE a.message_id=m.id)
 FROM messages m JOIN inboxes sender ON sender.id=m.sender WHERE m.id=? AND m.recipient=? AND m.expires>?`

func (r *Relay) Poll(ctx context.Context, owner string, id InboxKey, since int64, limit int, out io.Writer) error {
	handle, err := ownedHandle(ctx, r.db, owner, id)
	if err != nil {
		return err
	}
	if since < 0 || limit < 1 || limit > 100 {
		return RequestError("invalid cursor or poll limit")
	}
	if out == nil {
		return errors.New("no poll output writer")
	}
	// Capture a bounded page of IDs, not 100 MiB of bodies. Fetch each body
	// and its attachment metadata in a single SELECT and release the DB before
	// writing to a potentially slow client. Concurrent deletions are skipped.
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM messages WHERE recipient=? AND id>? AND expires>? ORDER BY id LIMIT ?`,
		id, since, r.cfg.Now().UnixNano(), limit)
	if err != nil {
		return err
	}
	ids := make([]int64, 0, limit)
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, n)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := io.WriteString(out, `{"messages":[`); err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	cursor := since
	address := handle + "@" + r.cfg.Host
	for _, n := range ids {
		var m messageView
		var created, expires int64
		var attachments []byte
		err := r.db.QueryRowContext(ctx, messageQuery, n, id, r.cfg.Now().UnixNano()).Scan(
			&m.From, &m.Body, &m.Encoding, &m.ReplyTo, &created, &expires, &attachments)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		m.ID = strconv.FormatInt(n, 10)
		m.From += "@" + r.cfg.Host
		m.To = address
		m.Created, m.Expires = time.Unix(0, created).UTC(), time.Unix(0, expires).UTC()
		m.Attachments = attachments
		if cursor != since {
			if _, err := io.WriteString(out, ","); err != nil {
				return err
			}
		}
		if err := enc.Encode(&m); err != nil {
			return err
		}
		cursor = n
	}
	_, err = io.WriteString(out, `],"next_cursor":"`+strconv.FormatInt(cursor, 10)+`"}`+"\n")
	return err
}

func (r *Relay) openAttachment(ctx context.Context, inbox InboxKey, id string) (*os.File, int64, error) {
	r.files.Lock()
	defer r.files.Unlock()
	var size int64
	err := r.db.QueryRowContext(ctx, `SELECT a.size FROM attachments a JOIN messages m ON m.id=a.message_id
		WHERE a.id=? AND m.recipient=? AND m.expires>?`, id, inbox, r.cfg.Now().UnixNano()).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, RequestError("attachment not found")
	}
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(filepath.Join(r.blobs, id))
	return f, size, err
}

func (r *Relay) Get(ctx context.Context, owner string, id InboxKey, attachmentID string, out io.Writer) error {
	if _, err := ownedHandle(ctx, r.db, owner, id); err != nil {
		return err
	}
	if !validID(attachmentID) {
		return RequestError("invalid attachment ID")
	}
	if out == nil {
		return errors.New("no attachment output writer")
	}
	f, size, err := r.openAttachment(ctx, id, attachmentID)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(out, f)
	if err == nil && n != size {
		return errors.New("attachment size differs from metadata")
	}
	return err
}

func (r *Relay) Delete(ctx context.Context, owner string, id InboxKey, msgID string) error {
	if _, err := ownedHandle(ctx, r.db, owner, id); err != nil {
		return err
	}
	n, ok := decimalID(msgID)
	if !ok {
		return RequestError("invalid message ID")
	}
	r.files.Lock()
	defer r.files.Unlock()
	res, err := r.db.ExecContext(ctx, "DELETE FROM messages WHERE id=? AND recipient=? AND expires>?", n, id, r.cfg.Now().UnixNano())
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return RequestError("message not found")
	}
	if err := r.collect(ctx); err != nil {
		// Queued unlinks remain durable; the logical deletion already succeeded.
		log.Printf("spool relay: collect deleted attachments: %v", err)
	}
	return nil
}
