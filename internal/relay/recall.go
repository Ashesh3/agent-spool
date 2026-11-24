package relay

import (
	"context"
	"log"
)

// Recall removes the relay's copy using the original sending owner's key,
// not the current holder of the public handle, which may have been reclaimed.
func (r *Relay) Recall(ctx context.Context, owner, msgID string) error {
	if !validOwner(owner) {
		return RequestError("message not found")
	}
	n, ok := decimalID(msgID)
	if !ok {
		return RequestError("invalid message ID")
	}
	return r.removeMessage(ctx, `DELETE FROM messages WHERE id=? AND EXISTS (
		SELECT 1 FROM inboxes WHERE id=messages.sender AND owner=?
	) AND expires>?`, n, owner)
}

// The caller's DELETE includes its authorization predicate. Cascades remove
// attachment metadata and durably queue blob unlinks in the same transaction.
func (r *Relay) removeMessage(ctx context.Context, stmt string, id int64, principal any) error {
	r.files.Lock()
	defer r.files.Unlock()
	result, err := r.db.ExecContext(ctx, stmt, id, principal, r.cfg.Now().UnixNano())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return RequestError("message not found")
	}
	if err := r.collect(ctx); err != nil {
		// Logical removal succeeded; the sweeper retries busy files.
		log.Printf("spool relay: collect removed message attachments: %v", err)
	}
	return nil
}
