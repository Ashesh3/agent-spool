package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
	"spool/internal/sshserver"
)

const testHost = "team.test"

type identities struct{ host, alice, bob ssh.Signer }

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
	return identities{host: signer(t), alice: signer(t), bob: signer(t)}
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
		ssh.FingerprintSHA256(k.alice.PublicKey()): true,
		ssh.FingerprintSHA256(k.bob.PublicKey()):   true,
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
	ID      string `json:"inbox_id"`
	Address string `json:"address"`
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
		ID                       string `json:"message_id"`
		From, To, Body, Encoding string
		Reply                    string       `json:"reply_to"`
		Attachments              []attachment `json:"attachments"`
	} `json:"messages"`
}

func (s *harness) create(t *testing.T, owner ssh.Signer, publicKey string) inbox {
	t.Helper()
	return s.createNamed(t, owner, "", publicKey)
}

func (s *harness) createNamed(t *testing.T, owner ssh.Signer, name, publicKey string) inbox {
	t.Helper()
	cmd := "create"
	if name != "" {
		cmd += " " + name
	}
	if publicKey != "" {
		cmd += " --public-key " + publicKey
	}
	out := s.exec(t, owner, "spool", cmd, nil, 0)
	i := unpack[inbox](t, out)
	if i.ID == "" || name != "" && i.ID != name || i.Address != i.ID+"@"+testHost || unpack[map[string]json.RawMessage](t, out)["inbox_secret"] != nil {
		t.Fatal("invalid inbox identity or unexpected legacy credential")
	}
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
		if !seen[i] {
			t.Fatalf("owned inbox %+v missing from %+v", i, list)
		}
	}
}

func (s *harness) put(t *testing.T, owner ssh.Signer, i inbox, name string, data []byte) string {
	t.Helper()
	a := unpack[attachment](t, s.exec(t, owner, i.ID, "put "+name, data, 0))
	if a.ID == "" || a.Filename != name || a.Size != int64(len(data)) {
		t.Fatalf("incorrect upload receipt: %+v", a)
	}
	return a.ID
}

func (s *harness) send(t *testing.T, owner ssh.Signer, from inbox, args string, body []byte) receipt {
	t.Helper()
	r := unpack[receipt](t, s.exec(t, owner, from.ID, "send "+args, body, 0))
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
