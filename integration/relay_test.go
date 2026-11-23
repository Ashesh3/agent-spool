package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"wire/internal/relay"
)

const (
	gateA = "gk_f8230000000000000000000000000011"
	gateB = "gk_90990000000000000000000000000022"
)

type harness struct {
	*httptest.Server
	app *relay.Relay
}

func start(t *testing.T, cfg relay.Config) *harness {
	t.Helper()
	cfg.Host = "team.test"
	cfg.GateKeys = map[string]string{"alice": gateA, "bob": gateB}
	app, err := relay.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(app)
	t.Cleanup(func() {
		s.Close()
		if err := app.Close(); err != nil {
			t.Error(err)
		}
	})
	return &harness{s, app}
}

func (s *harness) call(t *testing.T, method, path, gate, secret, mime string, data io.Reader, status int) ([]byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, data)
	if err != nil {
		t.Fatal(err)
	}
	if gate != "" {
		req.Header.Set("Authorization", "Bearer "+gate)
	}
	if secret != "" {
		req.Header.Set("X-Inbox-Secret", secret)
	}
	if mime != "" {
		req.Header.Set("Content-Type", mime)
	}
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("%s %s: want %d, got %d: %s", method, path, status, resp.StatusCode, body)
	}
	return body, resp.Header
}

func unpack[T any](t *testing.T, body []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	return out
}

type inbox struct {
	ID      string `json:"inbox_id"`
	Address string `json:"address"`
	Secret  string `json:"inbox_secret"`
}

func (s *harness) mint(t *testing.T, gate string) inbox {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pk := key.Recipient().String()
	body, _ := s.call(t, "POST", "/v1/inboxes", gate, "", "application/json", strings.NewReader(`{"public_key":"`+pk+`"}`), 201)
	i := unpack[inbox](t, body)
	if i.ID == "" || i.Address != i.ID+"@team.test" || i.Secret == "" {
		t.Fatal("invalid inbox credentials")
	}
	keyBytes, _ := s.call(t, "GET", "/v1/inboxes/"+i.ID+"/pubkey", gate, "", "", nil, 200)
	if unpack[map[string]string](t, keyBytes)["public_key"] != pk {
		t.Fatal("key discovery returned the wrong recipient")
	}
	return i
}

func (i inbox) path(suffix string) string {
	return "/v1/inboxes/" + url.PathEscape(i.ID) + "/" + suffix
}

type page struct {
	Next     string `json:"next_cursor"`
	Messages []struct {
		ID                       string `json:"message_id"`
		From, To, Body, Encoding string
		Reply                    string `json:"reply_to"`
		Attachments              []struct {
			ID       string `json:"attachment_id"`
			Filename string
			Size     int64
		} `json:"attachments"`
	} `json:"messages"`
}

func upload(t *testing.T, s *harness, from, to inbox, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for field, value := range map[string]string{"from": from.Address, "to": to.Address, "body": "schema", "encoding": "plain"} {
		if err := w.WriteField(field, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := w.CreateFormFile("files[]", "sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	body, _ := s.call(t, "POST", "/v1/messages", gateA, from.Secret, w.FormDataContentType(), &buf, 201)
	id := unpack[map[string]string](t, body)["message_id"]
	if n, err := strconv.ParseInt(id, 10, 64); err != nil || n <= 0 {
		t.Fatal("invalid message ID")
	}
	return id
}

func TestDeliveryAndInboxIsolation(t *testing.T) {
	s := start(t, relay.Config{DataDir: t.TempDir()})
	s.call(t, "GET", "/healthz", "", "", "", nil, 200)
	for _, path := range []string{"/v1/inboxes", "/v1/messages", "/unknown"} {
		s.call(t, "POST", path, "", "", "application/json", strings.NewReader("not json"), 401)
		s.call(t, "POST", path, "gk_invalid", "", "application/json", nil, 401)
	}
	a, b := s.mint(t, gateA), s.mint(t, gateB)
	payload := fmt.Sprintf(`{"from":%q,"to":%q,"body":"second"}`, a.Address, b.Address)
	s.call(t, "POST", "/v1/messages", gateB, b.Secret, "application/json", strings.NewReader(payload), 403)
	file := []byte{255, 0, 1, 13, 10, 128}
	first := upload(t, s, a, b, file)
	reply := strings.TrimSuffix(payload, "}") + `,"reply_to":"` + first + `"}`
	receipt, _ := s.call(t, "POST", "/v1/messages", gateA, a.Secret, "application/json", strings.NewReader(reply), 201)
	second := unpack[map[string]string](t, receipt)["message_id"]
	s.call(t, "GET", b.path("messages"), "", b.Secret, "", nil, 401)
	s.call(t, "GET", b.path("messages"), gateA, a.Secret, "", nil, 403)

	body, _ := s.call(t, "GET", b.path("messages?limit=1"), gateB, b.Secret, "", nil, 200)
	p := unpack[page](t, body)
	if len(p.Messages) != 1 || p.Next != first {
		t.Fatal("first poll did not stop at its limit")
	}
	m := p.Messages[0]
	if m.ID != first || m.From != a.Address || m.To != b.Address || m.Body != "schema" || m.Encoding != "plain" || len(m.Attachments) != 1 {
		t.Fatal("message contents differ")
	}
	f := m.Attachments[0]
	if f.Filename != "sample.bin" || f.Size != int64(len(file)) || f.ID == "" {
		t.Fatalf("invalid attachment metadata: %+v", f)
	}
	attPath := "attachments/" + f.ID
	s.call(t, "GET", b.path(attPath), gateA, a.Secret, "", nil, 403)
	s.call(t, "GET", a.path(attPath), gateA, a.Secret, "", nil, 404)
	got, header := s.call(t, "GET", b.path(attPath), gateB, b.Secret, "", nil, 200)
	if !bytes.Equal(got, file) || header.Get("X-Wire-Encoding") != "plain" {
		t.Fatal("binary download changed")
	}

	body, _ = s.call(t, "GET", b.path("messages?since="+p.Next), gateB, b.Secret, "", nil, 200)
	p = unpack[page](t, body)
	if len(p.Messages) != 1 || p.Messages[0].ID != second || p.Messages[0].Reply != first || p.Next != second {
		t.Fatal("cursor lost the second message or reply reference")
	}
	body, _ = s.call(t, "GET", b.path("messages?since="+second), gateB, b.Secret, "", nil, 200)
	p = unpack[page](t, body)
	if p.Messages == nil || len(p.Messages) != 0 || p.Next != second {
		t.Fatal("empty page must preserve the cursor")
	}
	s.call(t, "DELETE", b.path("messages/"+first), gateA, a.Secret, "", nil, 403)
	s.call(t, "DELETE", b.path("messages/"+first), gateB, b.Secret, "", nil, 204)
	s.call(t, "GET", b.path(attPath), gateB, b.Secret, "", nil, 404)
}

func TestSevenDayExpiryAndPersistentInboxes(t *testing.T) {
	var clock atomic.Int64
	startTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).Unix()
	clock.Store(startTime)
	dir := t.TempDir()
	cfg := relay.Config{DataDir: dir, Now: func() time.Time { return time.Unix(clock.Load(), 0).UTC() }}
	var a, b inbox
	var att string
	t.Run("send", func(t *testing.T) {
		s := start(t, cfg)
		a, b = s.mint(t, gateA), s.mint(t, gateB)
		upload(t, s, a, b, []byte("blob with a seven-day lifetime"))
		body, _ := s.call(t, "GET", b.path("messages"), gateB, b.Secret, "", nil, 200)
		p := unpack[page](t, body)
		if len(p.Messages) != 1 || len(p.Messages[0].Attachments) != 1 {
			t.Fatal("missing message before restart")
		}
		att = b.path("attachments/" + p.Messages[0].Attachments[0].ID)
	})
	s := start(t, cfg)
	clock.Store(startTime + 7*86400 - 1)
	s.call(t, "GET", att, gateB, b.Secret, "", nil, 200)
	clock.Add(1)
	s.call(t, "GET", att, gateB, b.Secret, "", nil, 404)
	body, _ := s.call(t, "GET", b.path("messages"), gateB, b.Secret, "", nil, 200)
	if len(unpack[page](t, body).Messages) != 0 {
		t.Fatal("expired message visible before cleanup")
	}
	if err := s.app.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(filepath.Join(dir, "blobs"), func(_ string, d fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return fmt.Errorf("expired blob still on disk: %s", d.Name())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	upload(t, s, a, b, []byte("same permanent addresses after restart and sweep"))
}
