package relay

import (
	"database/sql"
	"errors"
	"fmt"
)

const schema = `
CREATE TABLE IF NOT EXISTS inboxes (
 id TEXT PRIMARY KEY NOT NULL,
 handle TEXT NOT NULL,
 retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
 owner TEXT NOT NULL,
 public_key TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS active_handles ON inboxes(handle) WHERE retired=0;
CREATE INDEX IF NOT EXISTS inbox_owners ON inboxes(owner, id);
CREATE TRIGGER IF NOT EXISTS permanent_owner BEFORE UPDATE OF owner ON inboxes
BEGIN SELECT RAISE(ABORT, 'inbox ownership is immutable'); END;
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender TEXT NOT NULL REFERENCES inboxes(id),
 recipient TEXT NOT NULL REFERENCES inboxes(id),
 body TEXT NOT NULL,
 encoding TEXT NOT NULL,
 reply_to TEXT NOT NULL,
 created INTEGER NOT NULL,
 expires INTEGER NOT NULL,
 byte_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox ON messages(recipient, id);
CREATE INDEX IF NOT EXISTS expiry ON messages(expires);
CREATE INDEX IF NOT EXISTS live_sent ON messages(sender, expires, byte_count);
-- A deleted inbox can still be the author of mail retained by someone else.
-- Keep its historical handle and quota owner only while those copies exist.
CREATE TRIGGER IF NOT EXISTS forget_retired_sender AFTER DELETE ON messages
WHEN EXISTS (SELECT 1 FROM inboxes WHERE id=OLD.sender AND retired=1)
BEGIN
 DELETE FROM inboxes WHERE id=OLD.sender
 AND NOT EXISTS (SELECT 1 FROM messages WHERE sender=OLD.sender);
END;
CREATE TABLE IF NOT EXISTS attachments (
 id TEXT PRIMARY KEY NOT NULL,
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 filename TEXT NOT NULL,
 size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS message_files ON attachments(message_id);
CREATE TABLE IF NOT EXISTS pending (
 id TEXT PRIMARY KEY NOT NULL,
 inbox TEXT NOT NULL REFERENCES inboxes(id),
 filename TEXT NOT NULL,
 size INTEGER NOT NULL,
 expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_expiry ON pending(expires);
CREATE INDEX IF NOT EXISTS live_pending ON pending(inbox, expires, size);
CREATE TABLE IF NOT EXISTS garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER IF NOT EXISTS queue_unlink AFTER DELETE ON attachments
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
-- Publishing inserts the delivered attachment before removing its staging row.
-- Expiring an unpublished attachment instead queues its blob for deletion.
CREATE TRIGGER IF NOT EXISTS queue_pending_unlink AFTER DELETE ON pending
WHEN NOT EXISTS (SELECT 1 FROM attachments WHERE id=OLD.id)
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
PRAGMA user_version=2;
`

func (r *Relay) initialize(owners map[string]string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch version {
	case 0:
		var tables int
		if err := tx.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'`).Scan(&tables); err != nil {
			return err
		}
		if tables != 0 {
			if err := migrateLegacy(tx, owners); err != nil {
				return err
			}
			version = 1
		} else if len(owners) != 0 {
			return errors.New("legacy owner map supplied for an empty store")
		}
	case 1:
		// Before upgrading an existing key-owned store, reject a supplied
		// legacy map that disagrees with the ownership already on disk.
		for id, owner := range owners {
			var matches bool
			if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM inboxes WHERE id=? AND owner=?)", id, owner).Scan(&matches); err != nil {
				return err
			}
			if !matches {
				return fmt.Errorf("legacy owner map disagrees with stored ownership of %q", id)
			}
		}
	case 2:
		// A legacy ownership map is never reapplied to a released handle.
	default:
		return fmt.Errorf("unsupported relay schema version %d", version)
	}
	if version == 1 {
		// All existing foreign keys continue to reference the original id.
		// New incarnations get opaque ids; only live handles must be unique.
		if _, err := tx.Exec(`ALTER TABLE inboxes ADD COLUMN handle TEXT NOT NULL DEFAULT '';
			ALTER TABLE inboxes ADD COLUMN retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1));
			UPDATE inboxes SET handle=id;`); err != nil {
			return err
		}
	}
	if version < 2 {
		if _, err := tx.Exec(schema); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = r.db.Exec("PRAGMA journal_mode=WAL")
	return err
}

// ALTER in place so attachment rows, foreign keys and the AUTOINCREMENT
// high-water mark (including previously deleted messages) all survive intact.
func migrateLegacy(tx *sql.Tx, owners map[string]string) error {
	if owners == nil {
		return errors.New("legacy relay database requires an explicit inbox-to-SSH-fingerprint owner map")
	}
	// Validate every entry before any write, including DDL. A refused
	// migration must not change the old schema, hashes, labels or files.
	rows, err := tx.Query("SELECT id FROM inboxes")
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if owner, mapped := owners[id]; !mapped || !validOwner(owner) {
			rows.Close()
			return fmt.Errorf("missing or invalid SSH fingerprint for legacy inbox %q", id)
		}
		count++
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(owners) != count {
		return errors.New("legacy owner map must name exactly the existing inboxes")
	}
	if _, err := tx.Exec("ALTER TABLE inboxes RENAME COLUMN label TO owner"); err != nil {
		return err
	}
	for id, owner := range owners {
		if _, err := tx.Exec("UPDATE inboxes SET owner=? WHERE id=?", owner, id); err != nil {
			return err
		}
	}
	// Quota is now derived from the immutable owner of the sending inbox,
	// never from the old gate-key label. secure_delete is set on this connection.
	_, err = tx.Exec(`ALTER TABLE inboxes DROP COLUMN secret_hash;
		DROP INDEX IF EXISTS storage_use;
		ALTER TABLE messages DROP COLUMN member;`)
	return err
}
