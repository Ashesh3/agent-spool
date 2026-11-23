package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
)

func TestInterspersedOptions(t *testing.T) {
	o, err := parse([]string{"--json", "send", "someone@mail.example", "--reply-to=7", "-m", "--json", "-f", "first", "--file=second"})
	if err != nil || !o.json || o.message != "--json" || o.replyTo != "7" || strings.Join(o.files, ",") != "first,second" {
		t.Fatal("incorrect parsing of interspersed options and literal values", err)
	}
	o, err = parse([]string{"download", "deadbeef", "-o", "new.bin", "--json"})
	if err != nil || !o.json || o.output != "new.bin" {
		t.Fatal("trailing --json not handled", err)
	}
}

func TestUntrustedFilename(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape", `..\escape`, `C:drive`, `\\server\file`, ".gitconfig", "CON.out", "LPT¹.txt", "sneaky. ", "log\x1b[30m", "report\u202ecod.exe"} {
		disposition := mime.FormatMediaType("attachment", map[string]string{"filename": name})
		if _, err := destination(dir, disposition); err == nil {
			t.Errorf("accepted untrusted basename %q", name)
		}
	}
	path, err := destination(dir, mime.FormatMediaType("attachment", map[string]string{"filename": "日本語 notes.txt"}))
	if err != nil || path != filepath.Join(dir, "日本語 notes.txt") {
		t.Fatal("valid UTF-8 basename rejected", err)
	}
}

func TestAtomicNoClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	err := atomicWrite(path, false, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial"); err != nil {
			return err
		}
		return errors.New("authentication failure at EOF")
	})
	if err == nil {
		t.Fatal("accepted failed write")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial file published", err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	err = atomicWrite(path, false, func(w io.Writer) error { _, err := io.WriteString(w, "changed"); return err })
	if err == nil {
		t.Fatal("overwrote existing file")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "original" {
		t.Fatal("existing file changed", err)
	}
}

func makeProfile(t *testing.T, relayURL string) (*profile, string) {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p := &profile{Relay: relayURL, Gate: "old", Address: "reader@mail.example", InboxID: "reader", InboxSecret: "reader-proof", PrivateKey: key.String(), Cursor: "0", identity: key}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := saveProfile(path, p, false); err != nil {
		t.Fatal(err)
	}
	return p, path
}

type closedOutput struct{}

func (closedOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestPollCursorAndUnreadableMail(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/inboxes/reader/messages" || req.URL.Query().Get("since") != "0" || req.Header.Get("X-Inbox-Secret") != "reader-proof" {
			http.Error(w, "unexpected poll", http.StatusBadRequest)
			return
		}
		io.WriteString(w, `{"next_cursor":"8","messages":[{"message_id":"4","to":"reader@mail.example","encoding":"age","body":"bad !"},{"message_id":"8","to":"reader@mail.example","encoding":"plain","body":"unblocked"}]}`)
	}))
	defer s.Close()
	p, path := makeProfile(t, s.URL)
	r := &relay{p, s.Client()}
	o := options{limit: 2, json: true}
	if err := r.poll(path, o, closedOutput{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("output failure lost", err)
	}
	checkCursor := func(want string) {
		t.Helper()
		p, err := readProfile(path)
		if err != nil || p.Cursor != want {
			t.Fatal("wrong saved cursor", err)
		}
	}
	checkCursor("0")
	var out bytes.Buffer
	if err := r.poll(path, o, &out); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Messages []message `json:"messages"`
	}
	if err := json.Unmarshal(out.Bytes(), &page); err != nil || len(page.Messages) != 2 || page.Messages[0].Body != nil || page.Messages[0].DecryptionError == "" || page.Messages[1].Body == nil || *page.Messages[1].Body != "unblocked" {
		t.Fatal("invalid per-message output", err)
	}
	checkCursor("8")
	o.since = "0"
	if err := r.poll(path, o, io.Discard); err != nil {
		t.Fatal(err)
	}
	checkCursor("8")
}

func TestVerifiedGateRotationAndRedirectRefusal(t *testing.T) {
	var contacted atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted.Store(true) }))
	defer target.Close()
	var pub atomic.Pointer[age.X25519Recipient]
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/inboxes/reader/pubkey" || req.Header.Get("X-Inbox-Secret") != "" {
			http.Error(w, "unexpected credentials or route", 400)
			return
		}
		switch req.Header.Get("Authorization") {
		case "Bearer next":
			json.NewEncoder(w).Encode(map[string]string{"public_key": pub.Load().String()})
		case "Bearer redirect":
			http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
		default:
			http.Error(w, "wrong key", 401)
		}
	}))
	defer s.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DROPWIRE_CA_FILE", caPath)
	p, path := makeProfile(t, s.URL)
	pub.Store(p.identity.Recipient())
	for _, gate := range []string{"redirect", "rejected", "next"} {
		p, err := readProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = provision(path, p, options{relay: s.URL, gate: gate})
		if (err == nil) != (gate == "next") {
			t.Fatalf("unexpected gate rotation result: %v", err)
		}
		stored, err := readProfile(path)
		want := "old"
		if gate == "next" {
			want = gate
		}
		if err != nil || stored.Gate != want || stored.PrivateKey != p.PrivateKey || stored.InboxSecret != p.InboxSecret || stored.Address != p.Address {
			t.Fatal("unsafe credential rotation", err)
		}
	}
	if contacted.Load() {
		t.Fatal("followed a redirect")
	}
}
