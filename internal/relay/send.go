package relay

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	bodyLimit  = 1 << 20
	fileCount  = 16
	messageTTL = 7 * 24 * time.Hour
	pendingTTL = time.Hour
)

type SendOptions struct {
	To, ReplyTo, Encoding string
	Attachments           []string
}

type Attachment struct {
	ID       string `json:"attachment_id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type Receipt struct {
	ID      string    `json:"message_id"`
	Expires time.Time `json:"expires_at"`
}

const quotaExceeded = RequestError("SSH key storage quota exceeded")

// Retired sending inboxes still charge their original owner for live mail.
// Moving an attachment from pending to delivered costs zero additional bytes;
// only the new body must fit. Expired content stops counting before its sweep.
func (r *Relay) available(ctx context.Context, q rowQuerier, owner string, now int64) (int64, error) {
	var sent, pending int64
	err := q.QueryRowContext(ctx, `SELECT
	 (SELECT coalesce(sum(m.byte_count),0) FROM inboxes i JOIN messages m ON m.sender=i.id WHERE i.owner=? AND m.expires>?),
	 (SELECT coalesce(sum(p.size),0) FROM inboxes i JOIN pending p ON p.inbox=i.id WHERE i.owner=? AND p.expires>?)`,
		owner, now, owner, now).Scan(&sent, &pending)
	if err != nil {
		return 0, err
	}
	if sent > r.cfg.QuotaBytes || pending > r.cfg.QuotaBytes-sent {
		return 0, quotaExceeded
	}
	return r.cfg.QuotaBytes - sent - pending, nil
}

func (r *Relay) acquireWriter(ctx context.Context, owner string) (*member, error) {
	r.membersMu.Lock()
	m := r.memberLocked(owner)
	r.membersMu.Unlock()
	select {
	case m.upload <- struct{}{}:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *member) releaseWriter() { <-m.upload }

func (r *Relay) Send(ctx context.Context, owner string, id InboxKey, opts SendOptions, src io.Reader) (Receipt, error) {
	if _, err := ownedHandle(ctx, r.db, owner, id); err != nil {
		return Receipt{}, err
	}
	handle, err := r.localID(opts.To)
	if err != nil {
		return Receipt{}, err
	}
	if opts.Encoding == "" {
		opts.Encoding = "plain"
	}
	if opts.Encoding != "plain" && opts.Encoding != "age" {
		return Receipt{}, RequestError("unknown message encoding")
	}
	var replyID int64
	if opts.ReplyTo != "" {
		var ok bool
		if replyID, ok = decimalID(opts.ReplyTo); !ok {
			return Receipt{}, RequestError("invalid reply_to message ID")
		}
	}
	if len(opts.Attachments) > fileCount {
		return Receipt{}, RequestError("too many attachments")
	}
	for i, a := range opts.Attachments {
		if !validID(a) {
			return Receipt{}, RequestError("invalid attachment ID")
		}
		for _, other := range opts.Attachments[:i] {
			if other == a {
				return Receipt{}, RequestError("duplicate attachment ID")
			}
		}
	}
	// Pin the addressee before waiting on stdin: a recycled handle names a
	// different inbox even if both generations have the same owner.
	to, err := activeKey(ctx, r.db, handle)
	if err != nil {
		return Receipt{}, err
	}
	// No database connection or per-owner writer is held over SSH stdin.
	var body strings.Builder
	if src != nil {
		limit := min(int64(bodyLimit), r.cfg.MaxMessageBytes)
		n, err := io.Copy(&body, io.LimitReader(src, limit+1))
		if err != nil {
			return Receipt{}, err
		}
		if n > limit {
			return Receipt{}, RequestError("message body exceeds byte limit")
		}
	}
	text := body.String()
	if text == "" && len(opts.Attachments) == 0 {
		return Receipt{}, RequestError("body or attachment required")
	}
	if opts.Encoding == "plain" && !utf8.ValidString(text) {
		return Receipt{}, RequestError("plain body must be UTF-8")
	}
	if opts.Encoding == "age" {
		// Do not accept padded base64 followed by a second stream, even if
		// their boundary happens to coincide with a decoder read boundary.
		if i := strings.IndexByte(text, '='); i != -1 && strings.Trim(text[i:], "=\r\n") != "" {
			return Receipt{}, RequestError("age body must be standard base64")
		}
		if _, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(text))); err != nil {
			return Receipt{}, RequestError("age body must be standard base64")
		}
	}
	m, err := r.acquireWriter(ctx, owner)
	if err != nil {
		return Receipt{}, err
	}
	defer m.releaseWriter()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	now := r.cfg.Now().UTC()
	expires := now.Add(messageTTL)
	if _, err := ownedHandle(ctx, tx, owner, id); err != nil {
		return Receipt{}, err
	}
	current, err := activeKey(ctx, tx, handle)
	if err != nil {
		return Receipt{}, err
	}
	if current != to {
		return Receipt{}, RequestError("recipient inbox not found")
	}
	if replyID != 0 {
		var valid bool
		err := tx.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM messages WHERE id=? AND recipient=? AND sender=? AND expires>?
		)`, replyID, id, to, now.UnixNano()).Scan(&valid)
		if err != nil {
			return Receipt{}, err
		}
		if !valid {
			return Receipt{}, RequestError("reply_to message unavailable for this recipient")
		}
	}
	available, err := r.available(ctx, tx, owner, now.UnixNano())
	if err != nil {
		return Receipt{}, err
	}
	size := int64(len(text))
	if size > available {
		return Receipt{}, quotaExceeded
	}
	// Insert with the body charge, then add each file's charge in the same
	// transaction. A missing, expired or already-used ID rolls back the lot.
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(sender,recipient,body,encoding,reply_to,created,expires,byte_count)
		VALUES(?,?,?,?,?,?,?,?)`, id, to, text, opts.Encoding, opts.ReplyTo, now.UnixNano(), expires.UnixNano(), size)
	if err != nil {
		return Receipt{}, err
	}
	messageID, err := res.LastInsertId()
	if err != nil {
		return Receipt{}, err
	}
	for _, a := range opts.Attachments {
		var added int64
		err := tx.QueryRowContext(ctx, `INSERT INTO attachments(id,message_id,filename,size)
			SELECT id,?,filename,size FROM pending WHERE id=? AND inbox=? AND expires>? RETURNING size`,
			messageID, a, id, now.UnixNano()).Scan(&added)
		if errors.Is(err, sql.ErrNoRows) {
			return Receipt{}, RequestError("staged attachment unavailable for this inbox")
		}
		if err != nil {
			return Receipt{}, err
		}
		if added > r.cfg.MaxMessageBytes-size {
			return Receipt{}, RequestError("message exceeds total byte limit")
		}
		size += added
		if _, err := tx.ExecContext(ctx, "DELETE FROM pending WHERE id=?", a); err != nil {
			return Receipt{}, err
		}
	}
	if len(opts.Attachments) > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE messages SET byte_count=? WHERE id=?", size, messageID); err != nil {
			return Receipt{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{strconv.FormatInt(messageID, 10), expires}, nil
}
