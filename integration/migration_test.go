package integration_test

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"spool/internal/relay"
)

// On-disk SSH v2 layout, independent of the schema being tested.
const sshV2Schema = `
CREATE TABLE inboxes (id TEXT PRIMARY KEY NOT NULL, handle TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)), owner TEXT NOT NULL, public_key TEXT NOT NULL);
CREATE UNIQUE INDEX active_handles ON inboxes(handle) WHERE retired=0;
CREATE INDEX inbox_owners ON inboxes(owner,id);
CREATE TRIGGER permanent_owner BEFORE UPDATE OF owner ON inboxes BEGIN SELECT RAISE(ABORT,'inbox ownership is immutable'); END;
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES inboxes(id), recipient TEXT NOT NULL REFERENCES inboxes(id), body TEXT NOT NULL, encoding TEXT NOT NULL, reply_to TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, byte_count INTEGER NOT NULL);
CREATE INDEX mailbox ON messages(recipient,id);
CREATE INDEX expiry ON messages(expires);
CREATE INDEX live_sent ON messages(sender,expires,byte_count);
CREATE TRIGGER forget_retired_sender AFTER DELETE ON messages WHEN EXISTS (SELECT 1 FROM inboxes WHERE id=OLD.sender AND retired=1)
BEGIN DELETE FROM inboxes WHERE id=OLD.sender AND NOT EXISTS (SELECT 1 FROM messages WHERE sender=OLD.sender); END;
CREATE TABLE attachments (id TEXT PRIMARY KEY NOT NULL, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, filename TEXT NOT NULL, size INTEGER NOT NULL);
CREATE INDEX message_files ON attachments(message_id);
CREATE TABLE pending (id TEXT PRIMARY KEY NOT NULL, inbox TEXT NOT NULL REFERENCES inboxes(id), filename TEXT NOT NULL, size INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX pending_expiry ON pending(expires);
CREATE INDEX live_pending ON pending(inbox,expires,size);
CREATE TABLE garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER queue_unlink AFTER DELETE ON attachments BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
CREATE TRIGGER queue_pending_unlink AFTER DELETE ON pending WHEN NOT EXISTS (SELECT 1 FROM attachments WHERE id=OLD.id)
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
PRAGMA user_version=2;
`

func openStoreDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func requireSQLInt(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s: got %d, want %d", query, got, want)
	}
}

func TestFreshAndEmptyV2StoresServeEncryptedMail(t *testing.T) {
	for _, source := range []string{"fresh", "empty v2"} {
		t.Run(source, func(t *testing.T) {
			cfg := relay.Config{DataDir: t.TempDir()}
			db := openStoreDB(t, cfg.DataDir)
			if source == "empty v2" {
				execSQL(t, db, sshV2Schema)
			}
			s := start(t, cfg, keys(t))
			requireSQLInt(t, db, "PRAGMA user_version", 3)
			requireSQLInt(t, db, `SELECT count(*) FROM pragma_table_info('messages') WHERE name='body' AND upper(type)='BLOB' AND "notnull"`, 1)
			requireSQLInt(t, db, `SELECT count(*) FROM pragma_table_info('messages') WHERE name='encoding'`, 0)
			requireSQLInt(t, db, `SELECT count(*) FROM pragma_table_info('pending') WHERE name='recipient' AND upper(type)='TEXT' AND "notnull"`, 1)
			a, b := s.create(t, s.alice), s.create(t, s.bob)
			file := s.put(t, s.alice, a, b, "first", []byte("file"))
			m := s.send(t, s.alice, a, b, " --attach "+file, []byte("hello"))
			p := s.poll(t, s.bob, b, "")
			if len(p.Messages) != 1 || p.Next != m.ID || string(decrypt(t, b, bodyCipher(t, p.Messages[0].Body))) != "hello" {
				t.Fatal("new schema did not deliver encrypted mail")
			}
		})
	}
}

func TestOccupiedV2StoreIsRefusedWithoutDataLoss(t *testing.T) {
	for _, state := range []string{"inbox only", "messages and files"} {
		t.Run(state, func(t *testing.T) {
			cfg := relay.Config{DataDir: t.TempDir(), Host: testHost}
			db := openStoreDB(t, cfg.DataDir)
			execSQL(t, db, sshV2Schema)
			execSQL(t, db, `INSERT INTO inboxes VALUES('a','example',0,'owner','')`)
			if state == "messages and files" {
				execSQL(t, db, `INSERT INTO messages VALUES(41,'a','a','stored body','plain','',1,2,19);
					INSERT INTO attachments VALUES('sent',41,'sent.bin',8);
					INSERT INTO pending VALUES('staged','a','stage.bin',7,2);`)
				dir := filepath.Join(cfg.DataDir, "blobs")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				for name, contents := range map[string]string{"sent": "sentfile", "staged": "pending"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if app, err := relay.Open(cfg); err == nil {
				app.Close()
				t.Fatal("relay adopted an occupied incompatible store")
			}
			requireSQLInt(t, db, "PRAGMA user_version", 2)
			requireSQLInt(t, db, `SELECT count(*) FROM inboxes WHERE id='a' AND handle='example' AND owner='owner' AND public_key=''`, 1)
			if state == "messages and files" {
				requireSQLInt(t, db, `SELECT count(*) FROM messages WHERE id=41 AND body='stored body' AND encoding='plain'`, 1)
				requireSQLInt(t, db, `SELECT count(*) FROM attachments WHERE id='sent' AND message_id=41`, 1)
				requireSQLInt(t, db, `SELECT count(*) FROM pending WHERE id='staged' AND inbox='a'`, 1)
				requireDiskPayload(t, cfg.DataDir, []byte("pending"), true)
				requireDiskPayload(t, cfg.DataDir, []byte("sentfile"), true)
			}
		})
	}
}

func TestUnversionedNonRelayDatabaseIsNeverReinitialized(t *testing.T) {
	cfg := relay.Config{DataDir: t.TempDir(), Host: testHost}
	db := openStoreDB(t, cfg.DataDir)
	execSQL(t, db, `CREATE TABLE important (value BLOB); INSERT INTO important VALUES (x'00ff')`)
	if app, err := relay.Open(cfg); err == nil {
		app.Close()
		t.Fatal("relay adopted an unrelated database")
	}
	var contents []byte
	if err := db.QueryRow(`SELECT value FROM important`).Scan(&contents); err != nil || !bytes.Equal(contents, []byte{0, 255}) {
		t.Fatalf("unrelated data changed: value=%x, err=%v", contents, err)
	}
	requireSQLInt(t, db, "PRAGMA user_version", 0)
}
