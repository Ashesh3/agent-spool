package integration_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

// This is the schema shipped by the HTTPS relay, not the schema under test.
const legacySchema = `
PRAGMA journal_mode=WAL;
CREATE TABLE inboxes (id TEXT PRIMARY KEY NOT NULL, secret_hash BLOB NOT NULL, label TEXT NOT NULL, public_key TEXT NOT NULL);
CREATE TABLE messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES inboxes(id), recipient TEXT NOT NULL REFERENCES inboxes(id),
 body TEXT NOT NULL, encoding TEXT NOT NULL, reply_to TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
 member TEXT NOT NULL, byte_count INTEGER NOT NULL
);
CREATE INDEX mailbox ON messages(recipient,id);
CREATE INDEX expiry ON messages(expires);
CREATE INDEX storage_use ON messages(member,byte_count);
CREATE TABLE attachments (id TEXT PRIMARY KEY NOT NULL, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, filename TEXT NOT NULL, size INTEGER NOT NULL);
CREATE INDEX message_files ON attachments(message_id);
CREATE TABLE garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER queue_unlink AFTER DELETE ON attachments BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
`

func seedLegacy(t *testing.T, dir string, now time.Time, a, b inbox, publicKey, blobID string, data []byte) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(legacySchema)
	for _, row := range []struct{ id, secret, key string }{{a.ID, "is_old_alice", ""}, {b.ID, "is_old_bob", publicKey}} {
		hash := sha256.Sum256([]byte(row.secret))
		exec("INSERT INTO inboxes VALUES(?,?,?,?)", row.id, hash[:], "same arbitrary label", row.key)
	}
	exec(`INSERT INTO messages VALUES(41,?,?,?,'plain','38',?,?,'old gate label',?)`, a.ID, b.ID, "legacy body", now.UnixNano(), now.Add(7*24*time.Hour).UnixNano(), len("legacy body")+len(data))
	exec("INSERT INTO attachments VALUES(?,41,'old.bin',?)", blobID, len(data))
	// A client may have saved cursor 82 before that delivery was deleted.
	exec(`INSERT INTO messages SELECT 82,sender,recipient,body,encoding,reply_to,created,expires,member,byte_count FROM messages WHERE id=41`)
	exec("DELETE FROM messages WHERE id=82")
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", blobID), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMailRequiresCompleteExplicitOwnership(t *testing.T) {
	clock := newClock()
	cfg := relay.Config{DataDir: t.TempDir(), Host: testHost, Now: clock.now}
	k := keys(t)
	a := inbox{ID: "amber-crane-0123456789abcdef", Address: "amber-crane-0123456789abcdef@" + testHost}
	b := inbox{ID: "brisk-finch-fedcba9876543210", Address: "brisk-finch-fedcba9876543210@" + testHost}
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := ageID.Recipient().String()
	const blobID = "a_abcdefghijklmnopqrstuvwxyz"
	blob := []byte{'l', 0, 'e', 255, 'g'}
	seedLegacy(t, cfg.DataDir, clock.now(), a, b, pub, blobID, blob)
	for _, owners := range []map[string]string{nil, {a.ID: ssh.FingerprintSHA256(k.alice.PublicKey())}} {
		cfg.LegacyOwners = owners
		if app, err := relay.Open(cfg); err == nil {
			app.Close()
			t.Fatal("legacy data was adopted without a complete ownership map")
		}
	}
	// The operator must still be able to run the old service after a refused
	// migration, not just recover messages by completing a partial migration.
	db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var remaining int
	oldA, oldB := sha256.Sum256([]byte("is_old_alice")), sha256.Sum256([]byte("is_old_bob"))
	err = db.QueryRow(`SELECT COUNT(*) FROM inboxes WHERE (id=? AND secret_hash=?) OR (id=? AND secret_hash=?)`, a.ID, oldA[:], b.ID, oldB[:]).Scan(&remaining)
	closeErr := db.Close()
	if err != nil || closeErr != nil || remaining != 2 {
		t.Fatalf("refused migration altered the old inboxes: rows=%d, query=%v, close=%v", remaining, err, closeErr)
	}
	cfg.LegacyOwners = map[string]string{a.ID: ssh.FingerprintSHA256(k.alice.PublicKey()), b.ID: ssh.FingerprintSHA256(k.bob.PublicKey())}
	if !t.Run("migrate", func(t *testing.T) {
		s := start(t, cfg, k)
		s.requireList(t, s.alice, a)
		s.requireList(t, s.bob, b)
		s.denyLogin(t, b.ID, ssh.PublicKeys(s.alice))
		s.denyLogin(t, b.ID, ssh.Password("is_old_bob"))
		lookup := s.exec(t, s.alice, "spool", "pubkey "+b.ID, nil, 0)
		if unpack[map[string]string](t, lookup)["public_key"] != pub {
			t.Fatal("migration lost published age recipient")
		}
		p := s.poll(t, s.bob, b, "--since 40")
		if len(p.Messages) != 1 || p.Next != "41" {
			t.Fatalf("migration changed the legacy cursor: %+v", p)
		}
		m := p.Messages[0]
		if m.ID != "41" || m.From != a.Address || m.To != b.Address || m.Body != "legacy body" || m.Encoding != "plain" || m.Reply != "38" || len(m.Attachments) != 1 {
			t.Fatalf("legacy message changed: %+v", m)
		}
		if f := m.Attachments[0]; f != (attachment{ID: blobID, Filename: "old.bin", Size: int64(len(blob))}) {
			t.Fatalf("legacy attachment changed: %+v", f)
		}
		if raw := s.exec(t, s.bob, b.ID, "get "+blobID, nil, 0); !bytes.Equal(raw, blob) {
			t.Fatal("legacy blob bytes not preserved")
		}
	}) {
		t.FailNow()
	}
	// Once migrated the data no longer requires the administrator's map.
	cfg.LegacyOwners = nil
	s := start(t, cfg, k)
	r := s.send(t, s.alice, a, b.Address, []byte("after migration"))
	if p := s.poll(t, s.bob, b, "--since 82"); len(p.Messages) != 1 || p.Next != r.ID {
		t.Fatalf("pre-migration high-water cursor missed the new message: %+v", p)
	}
}
