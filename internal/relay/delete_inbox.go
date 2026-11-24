package relay

import (
	"context"
	"log"
)

// DeleteInbox releases an owned handle and removes what the mailbox holds.
// It does not recall messages already delivered to another mailbox.
func (r *Relay) DeleteInbox(ctx context.Context, owner, handle string) error {
	r.files.Lock()
	defer r.files.Unlock()
	// BEGIN IMMEDIATE serializes the ownership check, all deletes, and the
	// release of the handle with claims and deliveries from other sessions.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key, err := resolveOwnedKey(ctx, tx, owner, handle)
	if err != nil {
		return err
	}
	for _, stmt := range [...]string{
		`DELETE FROM pending WHERE inbox=?`,
		`DELETE FROM messages WHERE recipient=?`,
		`UPDATE inboxes SET retired=1, public_key='' WHERE id=?`,
		// If other recipients still have mail from this incarnation, retain
		// just its historical sender identity until their last copy is gone.
		`DELETE FROM inboxes WHERE id=? AND NOT EXISTS (SELECT 1 FROM messages WHERE sender=inboxes.id)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, key); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Blob unlinks were queued by the same transaction. A busy file does
	// not undo deletion or delay reuse of the handle; Sweep retries it.
	if err := r.collect(ctx); err != nil {
		log.Printf("spool relay: collect deleted inbox attachments: %v", err)
	}
	return nil
}
