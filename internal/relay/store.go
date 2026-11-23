// Package relay implements the private Dropwire mailbox HTTP service.
package relay

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	DataDir, Host                             string
	GateKeys                                  map[string]string
	MaxFileBytes, MaxMessageBytes, QuotaBytes int64
	RequestsPerMinute                         int
	Now                                       func() time.Time
}

type member struct {
	label  string
	digest [sha256.Size]byte
	// Serialize uploads per member so the quota check includes every other
	// committed upload and at most one request spends the remaining bytes.
	upload chan struct{}
	mu     sync.Mutex
	until  time.Time
	count  int
}

type Relay struct {
	cfg       Config
	db, lease *sql.DB
	blobs     string
	staging   string
	members   []*member
	// Protect promotion of staged files, commit, download open, and GC from
	// each other. Never hold this over network I/O or staging an upload.
	files sync.Mutex
}

const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS inboxes (
 id TEXT PRIMARY KEY NOT NULL,
 secret_hash BLOB NOT NULL,
 label TEXT NOT NULL,
 public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender TEXT NOT NULL REFERENCES inboxes(id),
 recipient TEXT NOT NULL REFERENCES inboxes(id),
 body TEXT NOT NULL,
 encoding TEXT NOT NULL,
 reply_to TEXT NOT NULL,
 created INTEGER NOT NULL,
 expires INTEGER NOT NULL,
 member TEXT NOT NULL,
 byte_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox ON messages(recipient, id);
CREATE INDEX IF NOT EXISTS expiry ON messages(expires);
CREATE INDEX IF NOT EXISTS storage_use ON messages(member, byte_count);
CREATE TABLE IF NOT EXISTS attachments (
 id TEXT PRIMARY KEY NOT NULL,
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 filename TEXT NOT NULL,
 size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS message_files ON attachments(message_id);
-- Keep unlinks retryable across crashes, cancellation, and open file handles.
CREATE TABLE IF NOT EXISTS garbage (id TEXT PRIMARY KEY NOT NULL);
CREATE TRIGGER IF NOT EXISTS queue_unlink AFTER DELETE ON attachments
BEGIN INSERT INTO garbage(id) VALUES (OLD.id); END;
`

func sqliteFile(dir, name string) string {
	p := filepath.ToSlash(filepath.Join(dir, name))
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive letter in a file URI.
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "secure_delete(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	return u.String()
}

func Open(cfg Config) (*Relay, error) {
	if cfg.DataDir == "" || cfg.Host == "" || strings.ContainsAny(cfg.Host, "/\\@?# \t\r\n") {
		return nil, errors.New("data directory and relay host are required")
	}
	if cfg.MaxFileBytes < 0 || cfg.MaxMessageBytes < 0 || cfg.QuotaBytes < 0 || cfg.RequestsPerMinute < 0 {
		return nil, errors.New("relay limits must not be negative")
	}
	if cfg.MaxFileBytes == 0 {
		cfg.MaxFileBytes = 25 << 20
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 50 << 20
	}
	if cfg.QuotaBytes == 0 {
		cfg.QuotaBytes = 1 << 30
	}
	if cfg.RequestsPerMinute == 0 {
		cfg.RequestsPerMinute = 120
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	dir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	r := &Relay{blobs: filepath.Join(dir, "blobs"), staging: filepath.Join(dir, "staging")}
	seen := make(map[[sha256.Size]byte]bool)
	for label, token := range cfg.GateKeys {
		digest := sha256.Sum256([]byte(token))
		if label == "" || token == "" || seen[digest] {
			return nil, errors.New("empty or duplicate gate credential")
		}
		seen[digest] = true
		r.members = append(r.members, &member{label: label, digest: digest, upload: make(chan struct{}, 1)})
	}
	cfg.GateKeys = nil
	r.cfg = cfg
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	// A separate SQLite lease is portable and is released by the OS even on
	// process death. In particular, a second process cannot clean active staging.
	r.lease, err = sql.Open("sqlite", sqliteFile(dir, "lease.sqlite"))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			r.Close()
		}
	}()
	r.lease.SetMaxOpenConns(1)
	if _, err = r.lease.Exec("BEGIN EXCLUSIVE"); err != nil {
		return nil, fmt.Errorf("acquire data directory lease: %w", err)
	}
	if err := os.MkdirAll(r.blobs, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.staging, 0700); err != nil {
		return nil, err
	}
	r.db, err = sql.Open("sqlite", sqliteFile(dir, "relay.sqlite"))
	if err != nil {
		return nil, err
	}
	r.db.SetMaxOpenConns(12)
	if _, err = r.db.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialize relay database: %w", err)
	}
	if err = r.recoverFiles(); err != nil {
		return nil, fmt.Errorf("recover attachment store: %w", err)
	}
	ok = true
	return r, nil
}

// Close releases the store after the HTTP server and sweep worker have stopped.
func (r *Relay) Close() error {
	var err error
	if r.db != nil {
		err = r.db.Close()
	}
	if r.lease != nil {
		err = errors.Join(err, r.lease.Close())
	}
	return err
}

func scanDir(dir string, visit func(string) error) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		names, err := f.Readdirnames(128)
		for _, name := range names {
			if err := visit(name); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// No live upload can exist while Open holds the directory lease. A crash can
// leave a staging file, or a promoted blob without its committed metadata.
func (r *Relay) recoverFiles() error {
	if err := scanDir(r.staging, func(name string) error {
		return os.Remove(filepath.Join(r.staging, name))
	}); err != nil {
		return err
	}
	return scanDir(r.blobs, func(name string) error {
		var keep bool
		if err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM attachments WHERE id=?)", name).Scan(&keep); err != nil {
			return err
		}
		if !keep {
			return os.Remove(filepath.Join(r.blobs, name))
		}
		return nil
	})
}

// Sweep removes expired messages and reclaims blobs for committed deletions.
func (r *Relay) Sweep(ctx context.Context) error {
	r.files.Lock()
	defer r.files.Unlock()
	if _, err := r.db.ExecContext(ctx, "DELETE FROM messages WHERE expires<=?", r.cfg.Now().UnixNano()); err != nil {
		return err
	}
	return r.collect(ctx)
}

func (r *Relay) collect(ctx context.Context) error {
	// Keyset pagination skips temporarily busy files for this pass while
	// preserving the queue entries for another sweep.
	var last string
	var failures error
	for {
		rows, err := r.db.QueryContext(ctx, "SELECT id FROM garbage WHERE id>? ORDER BY id LIMIT 128", last)
		if err != nil {
			return errors.Join(failures, err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return errors.Join(failures, err)
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(ids) == 0 {
			return errors.Join(failures, err)
		}
		last = ids[len(ids)-1]
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return errors.Join(failures, err)
		}
		for _, id := range ids {
			if err := os.Remove(filepath.Join(r.blobs, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
				if failures == nil {
					failures = err
				}
				continue
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM garbage WHERE id=?", id); err != nil {
				tx.Rollback()
				return errors.Join(failures, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return errors.Join(failures, err)
		}
	}
}
