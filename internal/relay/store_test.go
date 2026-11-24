package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func testOwner(name string) string {
	digest := sha256.Sum256([]byte(name))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func testRelay(t *testing.T, quota int64) *Relay {
	t.Helper()
	r, err := Open(Config{DataDir: t.TempDir(), Host: "relay.example", QuotaBytes: quota})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestRejectIPAddressAsMailboxDomain(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "[2001:db8::10]", "192.0.2.10:2222"} {
		r, err := Open(Config{DataDir: t.TempDir(), Host: host})
		if err == nil {
			r.Close()
			t.Fatalf("accepted literal IP as mailbox suffix: %s", host)
		}
		if strings.Contains(err.Error(), host) {
			t.Fatal("domain configuration error disclosed the rejected address")
		}
	}
}

type testMailbox struct {
	Inbox
	key       InboxKey
	recipient *age.X25519Recipient
}

func testInbox(t *testing.T, r *Relay, owner string) testMailbox {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient()
	box, err := r.Create(t.Context(), owner, "", recipient.String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.ResolveInbox(t.Context(), owner, box.ID)
	if err != nil {
		t.Fatal(err)
	}
	return testMailbox{box, key, recipient}
}

func (box testMailbox) destination() SendOptions {
	return SendOptions{To: box.ID, RecipientKey: box.recipient.String()}
}

func encryptForMailboxes(t *testing.T, from, to testMailbox, text string) []byte {
	t.Helper()
	recipients := []age.Recipient{from.recipient}
	if from.recipient.String() != to.recipient.String() {
		recipients = append(recipients, to.recipient)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// The SSH handshake is not the only line of defense. Supplying a real inbox
// and real object IDs directly to a store method cannot bypass its owner check.
func TestStoreChecksOwnerWithoutTransport(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from, to := testInbox(t, r, a), testInbox(t, r, b)
	payload := encryptForMailboxes(t, from, to, "hello")
	file, err := r.Put(ctx, a, from.key, to.ID, to.recipient.String(), "hello.bin", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	opts := to.destination()
	opts.Attachments = []string{file.ID}
	msg, err := r.Send(ctx, a, from.key, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Send(ctx, b, from.key, to.destination(), bytes.NewReader(payload)); err != notOwner {
		t.Errorf("forged send: %v", err)
	}
	if _, err := r.Put(ctx, b, from.key, to.ID, to.recipient.String(), "x", bytes.NewReader(payload)); err != notOwner {
		t.Errorf("forged put: %v", err)
	}
	if err := r.Poll(ctx, a, to.key, 0, 1, io.Discard); err != notOwner {
		t.Errorf("unauthorized poll: %v", err)
	}
	if err := r.Get(ctx, a, to.key, file.ID, io.Discard); err != notOwner {
		t.Errorf("unauthorized get: %v", err)
	}
	if err := r.Delete(ctx, a, to.key, msg.ID); err != notOwner {
		t.Errorf("unauthorized deletion: %v", err)
	}
	var data bytes.Buffer
	if err := r.Get(ctx, b, to.key, file.ID, &data); err != nil || !bytes.Equal(data.Bytes(), payload) {
		t.Fatalf("legitimate read after unauthorized operations: %d bytes, %v", data.Len(), err)
	}
}

func TestConcurrentUploadsShareQuotaAcrossInboxes(t *testing.T) {
	r := testRelay(t, 0)
	owner := testOwner("alice")
	boxes := []testMailbox{testInbox(t, r, owner), testInbox(t, r, owner)}
	payload := encryptForMailboxes(t, boxes[0], boxes[1], "12345")
	r.cfg.QuotaBytes = int64(len(payload))
	start := make(chan struct{})
	results := make(chan error, len(boxes))
	for i, box := range boxes {
		to := boxes[1-i]
		go func() {
			<-start
			_, err := r.Put(t.Context(), owner, box.key, to.ID, to.recipient.String(), "five.bin", bytes.NewReader(payload))
			results <- err
		}()
	}
	close(start)
	var ok, denied int
	for range boxes {
		switch err := <-results; {
		case err == nil:
			ok++
		case errors.Is(err, quotaExceeded):
			denied++
		default:
			t.Errorf("unexpected upload result: %v", err)
		}
	}
	if ok != 1 || denied != 1 {
		t.Fatalf("got %d successful uploads and %d quota rejections", ok, denied)
	}
}

func TestRawCiphertextStorageAndPoll(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from, to := testInbox(t, r, a), testInbox(t, r, b)
	file := encryptForMailboxes(t, from, to, "hello\x00world")
	upload, err := r.Put(ctx, a, from.key, to.ID, to.recipient.String(), "data.bin", bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if upload.Size != int64(len(file)) {
		t.Fatalf("reported size %d, want %d ciphertext bytes", upload.Size, len(file))
	}
	// An encrypted empty payload is a real body, distinct from file-only mail.
	cipher := encryptForMailboxes(t, from, to, "")
	for _, body := range [][]byte{nil, cipher} {
		opts := to.destination()
		charge := len(body)
		if len(body) == 0 {
			opts.Attachments = []string{upload.ID}
			charge += len(file)
		}
		receipt, err := r.Send(ctx, a, from.key, opts, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var kind string
		var stored []byte
		var size int
		if err := r.db.QueryRow("SELECT typeof(body), body, byte_count FROM messages WHERE id=?", receipt.ID).Scan(&kind, &stored, &size); err != nil {
			t.Fatal(err)
		}
		if kind != "blob" || !bytes.Equal(stored, body) || size != charge {
			t.Fatalf("stored %s, %d bytes, charge %d; want blob, %d bytes, charge %d", kind, len(stored), size, len(body), charge)
		}
	}
	var out bytes.Buffer
	if err := r.Poll(ctx, b, to.key, 0, 2, &out); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Messages []struct {
			Body     *string
			Encoding string
		}
	}
	if err := json.Unmarshal(out.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("got %d messages, want 2", len(page.Messages))
	}
	for i, want := range []string{"", base64.StdEncoding.EncodeToString(cipher)} {
		m := page.Messages[i]
		if m.Encoding != "age" || m.Body == nil || *m.Body != want {
			t.Errorf("message %d did not expose its ciphertext as an age/base64 string", i)
		}
	}
}

func TestStagedAttachmentsBoundToInboxPair(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from, sibling := testInbox(t, r, a), testInbox(t, r, a)
	to := testInbox(t, r, b)
	// Two inboxes with the *same* public key must still be distinct destinations.
	other, err := r.Create(ctx, b, "", to.recipient.String())
	if err != nil {
		t.Fatal(err)
	}
	file := encryptForMailboxes(t, from, to, "secret")
	stage := func(handle string) string {
		t.Helper()
		upload, err := r.Put(ctx, a, from.key, handle, to.recipient.String(), "secret.bin", bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		return upload.ID
	}
	first, second := stage(to.ID), stage(other.ID)
	send := func(sender InboxKey, handle string, ids ...string) error {
		opts := SendOptions{To: handle, RecipientKey: to.recipient.String(), Attachments: ids}
		_, err := r.Send(ctx, a, sender, opts, nil)
		return err
	}
	unavailable := RequestError("staged attachment unavailable for this inbox")
	if err := send(sibling.key, to.ID, first); !errors.Is(err, unavailable) {
		t.Fatalf("sibling reused sender's upload: %v", err)
	}
	// The first pending row matches, but the second belongs to a different
	// destination. Both rows must survive the failed transaction.
	if err := send(from.key, to.ID, first, second); !errors.Is(err, unavailable) {
		t.Fatalf("send with mixed recipients: %v", err)
	}
	if err := send(from.key, to.ID, first); err != nil {
		t.Fatal(err)
	}
	if err := send(from.key, to.ID, first); !errors.Is(err, unavailable) {
		t.Fatalf("consumed attachment reused: %v", err)
	}
	if err := send(from.key, other.ID, second); err != nil {
		t.Fatal(err)
	}
	stale := stage(other.ID)
	// Releasing and reclaiming the handle with the same owner and age key
	// does not transfer uploads that were staged for its previous incarnation.
	if err := r.DeleteInbox(ctx, b, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(ctx, b, other.ID, to.recipient.String()); err != nil {
		t.Fatal(err)
	}
	if err := send(from.key, other.ID, stale); !errors.Is(err, unavailable) {
		t.Fatalf("reclaimed inbox received an older upload: %v", err)
	}
}

func TestStoreRefusesUnencryptedOrMisaddressedInput(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from, to := testInbox(t, r, a), testInbox(t, r, b)
	cipher := encryptForMailboxes(t, from, to, "body")
	for _, op := range []string{"send", "put"} {
		t.Run(op, func(t *testing.T) {
			write := func(key string, input io.Reader) error {
				if op == "put" {
					_, err := r.Put(ctx, a, from.key, to.ID, key, "data", input)
					return err
				}
				opts := SendOptions{To: to.ID, RecipientKey: key}
				_, err := r.Send(ctx, a, from.key, opts, input)
				return err
			}
			for _, wrongKey := range []string{"", from.recipient.String()} {
				input := bytes.NewReader(cipher)
				var rejected RequestError
				if err := write(wrongKey, input); !errors.As(err, &rejected) || input.Len() != len(cipher) {
					t.Fatalf("expected key rejection before stdin; %d of %d bytes left, error %v", input.Len(), len(cipher), err)
				}
			}
			for name, invalid := range map[string][]byte{
				"empty":         nil,
				"plaintext":     []byte("hello"),
				"base64":        []byte(base64.StdEncoding.EncodeToString(cipher)),
				"one recipient": encryptForMailboxes(t, to, to, "body"),
			} {
				var rejected RequestError
				if err := write(to.recipient.String(), bytes.NewReader(invalid)); !errors.As(err, &rejected) {
					t.Errorf("%s: expected rejection, got %v", name, err)
				}
			}
		})
	}
}

func TestOneStanzaWhenInboxesShareAnAgeKey(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from := testInbox(t, r, a)
	to, err := r.Create(ctx, b, "", from.recipient.String())
	if err != nil {
		t.Fatal(err)
	}
	body := encryptForMailboxes(t, from, from, "one recipient")
	file, err := r.Put(ctx, a, from.key, to.ID, from.recipient.String(), "note", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	opts := SendOptions{To: to.ID, RecipientKey: from.recipient.String(), Attachments: []string{file.ID}}
	if _, err := r.Send(ctx, a, from.key, opts, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
}
