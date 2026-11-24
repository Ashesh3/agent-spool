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

// Frozen first SSH schema. Do not derive this fixture from the current relay:
// the indexes, triggers, foreign keys and AUTOINCREMENT sequence ship on disk.
const sshV1Schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE inboxes (id TEXT PRIMARY KEY NOT NULL, owner TEXT NOT NULL, public_key TEXT NOT NULL);
CREATE INDEX inbox_owners ON inboxes(owner,id);
CREATE TRIGGER permanent_owner BEFORE UPDATE OF owner ON inboxes BEGIN SELECT RAISE(ABORT,'inbox ownership is immutable'); END;
CREATE TABLE messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES inboxes(id), recipient TEXT NOT NULL REFERENCES inboxes(id),
 body TEXT NOT NULL, encoding TEXT NOT NULL, reply_to TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, byte_count INTEGER NOT NULL
);
CREATE INDEX mailbox ON messages(recipient,id);
CREATE INDEX expiry ON messages(expires);
CREATE INDEX live_sent ON messages(sender,expires,byte_count);
CREATE TABLE attachments (id TEXT PRIMARY KEY NOT NULL, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, filename TEXT NOT NULL, size INTEGER NOT NULL);
CREATE INDEX message_files ON attachments(message_id);
CREATE TABLE pending (id TEXT PRIMARY KEY NOT NULL, inbox TEXT NOT NULL REFERENCES inboxes(id), filename TEXT NOT NULL, size INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX pending_expiry ON pending(expires);
CREATE INDEX live_pending ON pending(inbox,expires,size);
CREATE TABLE garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER queue_unlink AFTER DELETE ON attachments BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
CREATE TRIGGER queue_pending_unlink AFTER DELETE ON pending WHEN NOT EXISTS (SELECT 1 FROM attachments WHERE id=OLD.id)
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
PRAGMA user_version=1;
`

func TestSSHVersionOneUpgradePreservesMailAndStagedFiles(t *testing.T) {
	clock := newClock()
	cfg := relay.Config{DataDir: t.TempDir(), Now: clock.now}
	k := keys(t)
	a := inbox{ID: "Build_bot-2", Address: "Build_bot-2@" + testHost}
	b := inbox{ID: "parcel", Address: "parcel@" + testHost}
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := ageID.Recipient().String()
	const staged = "a_pending_v1"
	const delivered = "a_delivered_v1"
	files := map[string][]byte{staged: {'p', 0, 255}, delivered: {'d', 0, 254}}
	if !t.Run("seed v1 store", func(t *testing.T) {
		db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "relay.sqlite"))
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
		exec(sshV1Schema)
		exec("INSERT INTO inboxes VALUES(?,?,''),(?,?,?)", a.ID, ssh.FingerprintSHA256(k.alice.PublicKey()), b.ID, ssh.FingerprintSHA256(k.bob.PublicKey()), pub)
		now := clock.now()
		exec(`INSERT INTO messages VALUES(41,?,?,'v1 mail','plain','',?,?,?)`, a.ID, b.ID, now.UnixNano(), now.Add(7*24*time.Hour).UnixNano(), len("v1 mail")+len(files[delivered]))
		// Cursor 89 was already issued before its message was deleted.
		exec(`INSERT INTO messages SELECT 89,sender,recipient,body,encoding,reply_to,created,expires,byte_count FROM messages WHERE id=41`)
		exec("DELETE FROM messages WHERE id=89")
		exec("INSERT INTO attachments VALUES(?,41,'sent.bin',?)", delivered, len(files[delivered]))
		exec("INSERT INTO pending VALUES(?,?,'stage.bin',?,?)", staged, a.ID, len(files[staged]), now.Add(time.Hour).UnixNano())
		dir := filepath.Join(cfg.DataDir, "blobs")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for id, data := range files {
			if err := os.WriteFile(filepath.Join(dir, id), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}) {
		t.FailNow()
	}

	s := start(t, cfg, k)
	s.requireList(t, s.alice, a)
	s.requireList(t, s.bob, b)
	s.denyLogin(t, a.ID, ssh.PublicKeys(s.bob))
	if key := unpack[map[string]string](t, s.exec(t, s.alice, "spool", "pubkey "+b.Address, nil, 0)); key["public_key"] != pub {
		t.Fatal("v1 upgrade lost published age recipient")
	}
	p := s.poll(t, s.bob, b, "--since 40")
	if len(p.Messages) != 1 || p.Next != "41" {
		t.Fatalf("v1 delivery or cursor lost: %+v", p)
	}
	m := p.Messages[0]
	if m.ID != "41" || m.From != a.Address || m.To != b.Address || m.Body != "v1 mail" || len(m.Attachments) != 1 || m.Attachments[0] != (attachment{ID: delivered, Filename: "sent.bin", Size: int64(len(files[delivered]))}) {
		t.Fatalf("v1 message changed: %+v", m)
	}
	if got := s.exec(t, s.bob, b.ID, "get "+delivered, nil, 0); !bytes.Equal(got, files[delivered]) {
		t.Fatalf("v1 delivered bytes changed: %x", got)
	}
	s.exec(t, s.bob, b.ID, "send "+a.ID+" --attach "+staged, nil, 1)
	r := s.send(t, s.alice, a, b.Address+" --attach "+staged, nil)
	p = s.poll(t, s.bob, b, "--since 89")
	if len(p.Messages) != 1 || p.Next != r.ID || p.Messages[0].ID != r.ID || len(p.Messages[0].Attachments) != 1 || p.Messages[0].Attachments[0] != (attachment{ID: staged, Filename: "stage.bin", Size: int64(len(files[staged]))}) {
		t.Fatalf("v1 high-water cursor missed the staged file: %+v", p)
	}
	if got := s.exec(t, s.bob, b.ID, "get "+staged, nil, 0); !bytes.Equal(got, files[staged]) {
		t.Fatalf("v1 staged bytes changed: %x", got)
	}
	// A migrated sender's old on-disk ID was its public handle. Reclaiming
	// that handle must not make a reply to v1 mail address the new owner.
	s.deleteInbox(t, s.alice, a)
	replacement := s.createNamed(t, s.bob, a.ID, "")
	s.exec(t, s.bob, b.ID, "send "+m.From+" --reply-to "+m.ID, []byte("private reply"), 1)
	if p := s.poll(t, s.bob, replacement, ""); len(p.Messages) != 0 {
		t.Fatalf("a migrated conversation crossed the ownership boundary: %+v", p)
	}
}

func TestRetainedLegacyOwnerMapCannotRegrantReleasedHandle(t *testing.T) {
	clock := newClock()
	k := keys(t)
	a := inbox{ID: "legacy-sender", Address: "legacy-sender@" + testHost}
	b := inbox{ID: "legacy-recipient", Address: "legacy-recipient@" + testHost}
	cfg := relay.Config{
		DataDir: t.TempDir(), Now: clock.now,
		LegacyOwners: map[string]string{a.ID: ssh.FingerprintSHA256(k.alice.PublicKey()), b.ID: ssh.FingerprintSHA256(k.bob.PublicKey())},
	}
	seedLegacy(t, cfg.DataDir, clock.now(), a, b, "", "a_legacy", []byte("old file"))
	if !t.Run("migrate and reclaim", func(t *testing.T) {
		s := start(t, cfg, k)
		s.deleteInbox(t, s.bob, b)
		s.createNamed(t, s.alice, b.ID, "")
	}) {
		t.FailNow()
	}
	// Simulate an operator who left the migration file configured.
	s := start(t, cfg, k)
	s.requireList(t, s.alice, a, b)
	s.requireList(t, s.bob)
	s.denyLogin(t, b.ID, ssh.PublicKeys(s.bob))
	s.exec(t, s.bob, "spool", "delete-inbox "+b.ID, nil, 1)
	s.send(t, s.alice, b, a.ID, []byte("still owned by its claimant"))
}
