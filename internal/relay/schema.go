package relay

import (
	"errors"
	"fmt"
)

const schema = `
CREATE TABLE IF NOT EXISTS inboxes (
 id TEXT PRIMARY KEY NOT NULL,
 handle TEXT NOT NULL,
 retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
 owner TEXT NOT NULL,
 public_key TEXT NOT NULL CHECK((retired=0 AND length(public_key)=62) OR (retired=1 AND public_key=''))
);
CREATE UNIQUE INDEX IF NOT EXISTS active_handles ON inboxes(handle) WHERE retired=0;
CREATE INDEX IF NOT EXISTS inbox_owners ON inboxes(owner, id);
CREATE TRIGGER IF NOT EXISTS permanent_owner BEFORE UPDATE OF owner ON inboxes
BEGIN SELECT RAISE(ABORT, 'inbox ownership is immutable'); END;
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender TEXT NOT NULL REFERENCES inboxes(id),
 recipient TEXT NOT NULL REFERENCES inboxes(id),
 body BLOB NOT NULL CHECK(typeof(body)='blob'),
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
 recipient TEXT NOT NULL REFERENCES inboxes(id),
 filename TEXT NOT NULL,
 size INTEGER NOT NULL,
 expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_expiry ON pending(expires);
CREATE INDEX IF NOT EXISTS pending_recipient ON pending(recipient);
CREATE INDEX IF NOT EXISTS live_pending ON pending(inbox, expires, size);
CREATE TABLE IF NOT EXISTS garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER IF NOT EXISTS queue_unlink AFTER DELETE ON attachments
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
-- Publishing inserts the delivered attachment before removing its staging row.
-- Expiring an unpublished attachment instead queues its blob for deletion.
CREATE TRIGGER IF NOT EXISTS queue_pending_unlink AFTER DELETE ON pending
WHEN NOT EXISTS (SELECT 1 FROM attachments WHERE id=OLD.id)
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
PRAGMA user_version=3;
`

func (r *Relay) initialize() error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	var highWater int64
	switch version {
	case 0:
		var tables int
		if err := tx.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'`).Scan(&tables); err != nil {
			return err
		}
		if tables != 0 {
			return errors.New("encrypted storage requires an empty data directory")
		}
	case 2:
		// Never drop mail, keys or uploads on startup. A completely empty
		// store can be initialized without changing its host identity or
		// reissuing a message ID a user might still have saved for recall.
		var occupied bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM inboxes UNION ALL SELECT 1 FROM messages
			UNION ALL SELECT 1 FROM attachments UNION ALL SELECT 1 FROM pending)`).Scan(&occupied); err != nil {
			return err
		}
		if occupied {
			return errors.New("cannot initialize encrypted storage in a nonempty mailbox database")
		}
		if err := tx.QueryRow(`SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name='messages'),0)`).Scan(&highWater); err != nil {
			return err
		}
		if _, err := tx.Exec(`DROP TABLE pending; DROP TABLE attachments; DROP TABLE messages; DROP TABLE inboxes;`); err != nil {
			return err
		}
	case 3:
		// Already initialized.
	default:
		return fmt.Errorf("unsupported relay schema version %d", version)
	}
	if version != 3 {
		if _, err := tx.Exec(schema); err != nil {
			return err
		}
		if highWater > 0 {
			if _, err := tx.Exec(`INSERT INTO sqlite_sequence(name,seq) VALUES('messages',?)`, highWater); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = r.db.Exec("PRAGMA journal_mode=WAL")
	return err
}
