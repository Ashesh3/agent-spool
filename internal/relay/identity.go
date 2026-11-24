package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// RequestError is safe to return to a client. Database and OS errors are not.
type RequestError string

func (e RequestError) Error() string { return string(e) }

const notOwner = RequestError("inbox unavailable for this SSH key")

// ManagementUser is the SSH login for relay-wide commands, never an inbox.
const ManagementUser = "spool"

type Inbox struct {
	ID      string `json:"inbox_id"`
	Address string `json:"address"`
}

// InboxKey identifies one incarnation, not its reusable public handle.
// Mailbox commands use the key resolved when the SSH connection authenticated.
type InboxKey string

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validOwner(owner string) bool {
	s, ok := strings.CutPrefix(owner, "SHA256:")
	if !ok || len(s) != base64.RawStdEncoding.EncodedLen(sha256.Size) {
		return false
	}
	var digest [sha256.Size]byte
	n, err := base64.RawStdEncoding.Strict().Decode(digest[:], []byte(s))
	return err == nil && n == len(digest)
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_')) {
			return false
		}
	}
	return true
}

func decimalID(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0 && s[0] >= '1' && s[0] <= '9'
}

// IDs are opaque, local handles; addresses are routing labels, not destinations
// to connect to. No relay-to-relay routing or domain lookup takes place.
func (r *Relay) localID(address string) (string, error) {
	id, host, full := strings.Cut(address, "@")
	if !validID(id) || full && !strings.EqualFold(host, r.cfg.Host) {
		return "", RequestError("expected a local recipient handle or address")
	}
	return id, nil
}

func (r *Relay) memberLocked(owner string) *member {
	m := r.members[owner]
	if m == nil {
		m = &member{upload: make(chan struct{}, 1)}
		r.members[owner] = m
	}
	return m
}

// Allow charges exactly one exec request for an authenticated fingerprint.
func (r *Relay) Allow(owner string) bool {
	if !validOwner(owner) {
		return false
	}
	r.membersMu.Lock()
	defer r.membersMu.Unlock()
	m := r.memberLocked(owner)
	now := r.cfg.Now()
	if !now.Before(m.until) {
		m.until, m.count = now.Add(time.Minute), 0
	}
	if m.count >= r.cfg.RequestsPerMinute {
		return false
	}
	m.count++
	return true
}

func (r *Relay) ResolveInbox(ctx context.Context, owner, handle string) (InboxKey, error) {
	return resolveOwnedKey(ctx, r.db, owner, handle)
}

func resolveOwnedKey(ctx context.Context, q rowQuerier, owner, handle string) (InboxKey, error) {
	if !validOwner(owner) || !validID(handle) {
		return "", notOwner
	}
	var key InboxKey
	err := q.QueryRowContext(ctx, "SELECT id FROM inboxes WHERE handle=? AND owner=? AND retired=0", handle, owner).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", notOwner
	}
	return key, err
}

func activeKey(ctx context.Context, q rowQuerier, handle string) (InboxKey, error) {
	var key InboxKey
	err := q.QueryRowContext(ctx, "SELECT id FROM inboxes WHERE handle=? AND retired=0", handle).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", RequestError("recipient inbox not found")
	}
	return key, err
}

func ownedHandle(ctx context.Context, q rowQuerier, owner string, key InboxKey) (string, error) {
	if !validOwner(owner) || key == "" {
		return "", notOwner
	}
	var handle string
	err := q.QueryRowContext(ctx, "SELECT handle FROM inboxes WHERE id=? AND owner=? AND retired=0", key, owner).Scan(&handle)
	if errors.Is(err, sql.ErrNoRows) {
		return "", notOwner
	}
	return handle, err
}

func newHandle() string {
	adjectives := [...]string{"amber", "brisk", "coral", "dusk", "fern", "lunar", "opal", "swift"}
	animals := [...]string{"crane", "finch", "fox", "hare", "ibis", "lynx", "otter", "wren"}
	var b [10]byte
	rand.Read(b[:])
	return adjectives[b[0]%8] + "-" + animals[b[1]%8] + "-" + hex.EncodeToString(b[2:])
}

func (r *Relay) Create(ctx context.Context, owner, name, publicKey string) (Inbox, error) {
	if !validOwner(owner) {
		return Inbox{}, notOwner
	}
	if name != "" && !validID(name) {
		return Inbox{}, RequestError("inbox name must be 1–128 ASCII letters, digits, hyphens or underscores, starting with a letter or digit")
	}
	if strings.EqualFold(name, ManagementUser) {
		return Inbox{}, RequestError("spool is reserved for relay commands")
	}
	if publicKey != "" {
		if len(publicKey) != 62 {
			return Inbox{}, RequestError("expected an age X25519 public key")
		}
		key, err := age.ParseX25519Recipient(publicKey)
		if err != nil || key.String() != publicKey {
			return Inbox{}, RequestError("expected an age X25519 public key")
		}
	}
	for {
		handle := name
		if handle == "" {
			handle = newHandle()
		}
		// The prefix can't occur in a v1 public handle, so a new inbox can
		// never acquire the storage identity of a retired v1 mailbox by name.
		res, err := r.db.ExecContext(ctx, `INSERT INTO inboxes(id,handle,owner,public_key) VALUES(?,?,?,?)
			ON CONFLICT(handle) WHERE retired=0 DO NOTHING`, "~"+rand.Text(), handle, owner, publicKey)
		if err != nil {
			return Inbox{}, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return Inbox{}, err
		}
		if n != 0 {
			return Inbox{handle, handle + "@" + r.cfg.Host}, nil
		}
		if name != "" {
			return Inbox{}, RequestError("inbox name already taken")
		}
	}
}

func (r *Relay) List(ctx context.Context, owner string) ([]Inbox, error) {
	if !validOwner(owner) {
		return nil, notOwner
	}
	rows, err := r.db.QueryContext(ctx, "SELECT handle FROM inboxes WHERE owner=? AND retired=0 ORDER BY handle", owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inboxes := []Inbox{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		inboxes = append(inboxes, Inbox{id, id + "@" + r.cfg.Host})
	}
	return inboxes, rows.Err()
}

func (r *Relay) PublicKey(ctx context.Context, recipient string) (string, error) {
	id, err := r.localID(recipient)
	if err != nil {
		return "", err
	}
	var key string
	err = r.db.QueryRowContext(ctx, "SELECT public_key FROM inboxes WHERE handle=? AND retired=0", id).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) || err == nil && key == "" {
		return "", RequestError("no public key for this inbox")
	}
	return key, err
}
