package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
	"spool/internal/sshserver"
)

const testHost = "team.test"

type identities struct{ host, alice, bob, charlie ssh.Signer }

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keys(t *testing.T) identities {
	t.Helper()
	return identities{host: signer(t), alice: signer(t), bob: signer(t), charlie: signer(t)}
}

type harness struct {
	identities
	addr string
	app  *relay.Relay
}

func start(t *testing.T, cfg relay.Config, k identities) *harness {
	t.Helper()
	cfg.Host = testHost
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	app, err := relay.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Error(err)
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		ssh.FingerprintSHA256(k.alice.PublicKey()):   true,
		ssh.FingerprintSHA256(k.bob.PublicKey()):     true,
		ssh.FingerprintSHA256(k.charlie.PublicKey()): true,
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sshserver.Serve(ctx, ln, app, k.host, allowed) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("SSH server did not stop on cancellation")
		}
	})
	return &harness{identities: k, addr: ln.Addr().String(), app: app}
}

// Treat failure to reach the fixture as a test error, never an authentication denial.
func (s *harness) dial(t *testing.T, user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", s.addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, s.addr, &ssh.ClientConfig{
		User: user, Auth: auth, HostKeyCallback: ssh.FixedHostKey(s.host.PublicKey()),
	})
	if err != nil {
		raw.Close()
		return nil, err
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

func (s *harness) client(t *testing.T, key ssh.Signer, user string) *ssh.Client {
	t.Helper()
	c, err := s.dial(t, user, ssh.PublicKeys(key))
	if err != nil {
		t.Fatalf("SSH login as %s: %v", user, err)
	}
	return c
}

func (s *harness) denyLogin(t *testing.T, user string, auth ...ssh.AuthMethod) {
	t.Helper()
	if c, err := s.dial(t, user, auth...); err == nil {
		c.Close()
		t.Fatalf("unauthorized SSH login succeeded as %s", user)
	}
}

const anyRejection = -1 // Input validation may occur at command parsing or in the store.

func (s *harness) exec(t *testing.T, key ssh.Signer, user, cmd string, stdin []byte, want int) []byte {
	t.Helper()
	c := s.client(t, key, user)
	defer c.Close()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var out, diagnostic bytes.Buffer
	session.Stdin = bytes.NewReader(stdin)
	session.Stdout, session.Stderr = &out, &diagnostic
	status := 0
	if err := session.Run(cmd); err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%s: missing SSH exit status: %v", cmd, err)
		}
		status = exit.ExitStatus()
	}
	if want == anyRejection && status != 1 && status != 2 || want != anyRejection && status != want {
		t.Fatalf("%s: exit %d, want %d; stderr %q", cmd, status, want, diagnostic.String())
	}
	if status == 0 {
		if diagnostic.Len() != 0 {
			t.Fatalf("%s: unexpected stderr %q", cmd, diagnostic.String())
		}
	} else {
		if out.Len() != 0 {
			t.Fatalf("%s: failed exec wrote %d bytes to stdout", cmd, out.Len())
		}
		if unpack[struct{ Error string }](t, diagnostic.Bytes()).Error == "" {
			t.Fatalf("%s: missing JSON error on stderr", cmd)
		}
	}
	return out.Bytes()
}

func unpack[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	return result
}

type inbox struct {
	ID       string `json:"inbox_id"`
	Address  string `json:"address"`
	identity *age.X25519Identity
}

type attachment struct {
	ID       string `json:"attachment_id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type receipt struct {
	ID      string    `json:"message_id"`
	Expires time.Time `json:"expires_at"`
}

type page struct {
	Next     string `json:"next_cursor"`
	Messages []struct {
		ID                 string `json:"message_id"`
		From, To, Encoding string
		Body               *string
		Reply              string       `json:"reply_to"`
		Attachments        []attachment `json:"attachments"`
	} `json:"messages"`
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (i inbox) publicKey() string { return i.identity.Recipient().String() }

func (s *harness) create(t *testing.T, owner ssh.Signer) inbox {
	t.Helper()
	return s.createNamed(t, owner, "", newIdentity(t))
}

func (s *harness) createNamed(t *testing.T, owner ssh.Signer, name string, identity *age.X25519Identity) inbox {
	t.Helper()
	cmd := "create"
	if name != "" {
		cmd += " " + name
	}
	out := s.exec(t, owner, "spool", cmd+" --public-key "+identity.Recipient().String(), nil, 0)
	i := unpack[inbox](t, out)
	if i.ID == "" || name != "" && i.ID != name || i.Address != i.ID+"@"+testHost || unpack[map[string]json.RawMessage](t, out)["inbox_secret"] != nil {
		t.Fatal("invalid inbox identity or unexpected legacy credential")
	}
	i.identity = identity
	return i
}

func (s *harness) requireList(t *testing.T, owner ssh.Signer, want ...inbox) {
	t.Helper()
	list := unpack[struct{ Inboxes []inbox }](t, s.exec(t, owner, "spool", "list", nil, 0)).Inboxes
	if list == nil || len(list) != len(want) {
		t.Fatalf("inbox list = %+v, want %+v", list, want)
	}
	seen := make(map[inbox]bool)
	for _, i := range list {
		seen[i] = true
	}
	for _, i := range want {
		i.identity = nil // The private age identity stays with the client.
		if !seen[i] {
			t.Fatalf("owned inbox %+v missing from %+v", i, list)
		}
	}
}

func seal(t *testing.T, from, to inbox, plain []byte) []byte {
	t.Helper()
	sender, recipient := from.identity.Recipient(), to.identity.Recipient()
	if sender.String() == recipient.String() {
		return encryptFor(t, plain, sender)
	}
	return encryptFor(t, plain, sender, recipient)
}

func encryptFor(t *testing.T, plain []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	var cipher bytes.Buffer
	w, err := age.Encrypt(&cipher, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return cipher.Bytes()
}

func bodyCipher(t *testing.T, body *string) []byte {
	t.Helper()
	cipher, err := base64.StdEncoding.Strict().DecodeString(*body)
	if err != nil || strings.ContainsAny(*body, "\r\n") {
		t.Fatal("poll body is not canonical padded base64")
	}
	return cipher
}

func decrypt(t *testing.T, i inbox, cipher []byte) []byte {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(cipher), i.identity)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sendTo(to inbox) string { return "send " + to.Address + " --recipient-key " + to.publicKey() }

func putTo(to inbox, name string) string {
	return "put " + to.ID + " --recipient-key " + to.publicKey() + " " + name
}

func (s *harness) put(t *testing.T, owner ssh.Signer, from, to inbox, name string, plain []byte) string {
	t.Helper()
	return s.putCipher(t, owner, from, to, name, seal(t, from, to, plain))
}

func (s *harness) putCipher(t *testing.T, owner ssh.Signer, from, to inbox, name string, data []byte) string {
	t.Helper()
	a := unpack[attachment](t, s.exec(t, owner, from.ID, putTo(to, name), data, 0))
	if a.ID == "" || a.Filename != name || a.Size != int64(len(data)) {
		t.Fatalf("incorrect upload receipt: %+v", a)
	}
	return a.ID
}

func (s *harness) send(t *testing.T, owner ssh.Signer, from, to inbox, flags string, plain []byte) receipt {
	t.Helper()
	var cipher []byte
	if plain != nil { // nil is a file-only send, not an encrypted zero-byte body.
		cipher = seal(t, from, to, plain)
	}
	return s.sendCipher(t, owner, from, to, flags, cipher)
}

func (s *harness) sendCipher(t *testing.T, owner ssh.Signer, from, to inbox, flags string, cipher []byte) receipt {
	t.Helper()
	r := unpack[receipt](t, s.exec(t, owner, from.ID, sendTo(to)+flags, cipher, 0))
	if id, err := strconv.ParseInt(r.ID, 10, 64); err != nil || id <= 0 || r.Expires.IsZero() {
		t.Fatalf("incorrect send receipt: %+v", r)
	}
	return r
}

func (s *harness) poll(t *testing.T, owner ssh.Signer, i inbox, flags string) page {
	t.Helper()
	cmd := "poll"
	if flags != "" {
		cmd += " " + flags
	}
	p := unpack[page](t, s.exec(t, owner, i.ID, cmd, nil, 0))
	if p.Messages == nil || p.Next == "" {
		t.Fatalf("incomplete poll envelope: %+v", p)
	}
	for _, m := range p.Messages {
		if m.Body == nil {
			t.Fatalf("message %s: body must be a JSON string", m.ID)
		}
		if m.Encoding != "age" {
			t.Fatalf("message %s: unexpected encoding %q", m.ID, m.Encoding)
		}
	}
	return p
}

type clock struct{ seconds atomic.Int64 }

func newClock() *clock {
	c := new(clock)
	c.seconds.Store(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).Unix())
	return c
}

func (c *clock) now() time.Time       { return time.Unix(c.seconds.Load(), 0).UTC() }
func (c *clock) step(d time.Duration) { c.seconds.Add(int64(d / time.Second)) }
