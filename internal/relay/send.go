package relay

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"strconv"
	"time"
)

const (
	bodyLimit  = 1 << 20
	fileCount  = 16
	messageTTL = 7 * 24 * time.Hour
	pendingTTL = time.Hour
)

type SendOptions struct {
	To, RecipientKey, ReplyTo string
	Attachments               []string
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
	handle, err := r.localID(opts.To)
	if err != nil {
		return Receipt{}, err
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
	to, recipients, err := encryptionPeers(ctx, r.db, owner, id, handle, opts.RecipientKey)
	if err != nil {
		return Receipt{}, err
	}
	// No database connection or per-owner writer is held over SSH stdin.
	var body bytes.Buffer
	size, err := copyAgeEnvelope(&body, src, min(int64(bodyLimit), r.cfg.MaxMessageBytes), recipients)
	if errors.Is(err, errEnvelopeLimit) {
		return Receipt{}, RequestError("message body exceeds byte limit")
	}
	if err != nil {
		return Receipt{}, err
	}
	if size == 0 && len(opts.Attachments) == 0 {
		return Receipt{}, RequestError("body or attachment required")
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
	current, _, err := encryptionPeers(ctx, tx, owner, id, handle, opts.RecipientKey)
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
	if size > available {
		return Receipt{}, quotaExceeded
	}
	// Insert with the body charge, then add each file's charge in the same
	// transaction. A missing, expired or already-used ID rolls back the lot.
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(sender,recipient,body,reply_to,created,expires,byte_count)
		VALUES(?,?,coalesce(?,X''),?,?,?,?)`, id, to, body.Bytes(), opts.ReplyTo, now.UnixNano(), expires.UnixNano(), size)
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
			SELECT id,?,filename,size FROM pending WHERE id=? AND inbox=? AND recipient=? AND expires>? RETURNING size`,
			messageID, a, id, to, now.UnixNano()).Scan(&added)
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
