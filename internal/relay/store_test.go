package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
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
	key InboxKey
}

func testInbox(t *testing.T, r *Relay, owner string) testMailbox {
	t.Helper()
	box, err := r.Create(t.Context(), owner, "", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.ResolveInbox(t.Context(), owner, box.ID)
	if err != nil {
		t.Fatal(err)
	}
	return testMailbox{box, key}
}

// The SSH handshake is not the only line of defense. Supplying a real inbox
// and real object IDs directly to a store method cannot bypass its owner check.
func TestStoreChecksOwnerWithoutTransport(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	a, b := testOwner("alice"), testOwner("bob")
	from, to := testInbox(t, r, a), testInbox(t, r, b)
	file, err := r.Put(ctx, a, from.key, "hello.bin", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := r.Send(ctx, a, from.key, SendOptions{To: to.ID, Attachments: []string{file.ID}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Send(ctx, b, from.key, SendOptions{To: to.ID}, strings.NewReader("forged")); err != notOwner {
		t.Errorf("forged send: %v", err)
	}
	if _, err := r.Put(ctx, b, from.key, "x", strings.NewReader("forged")); err != notOwner {
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
	var data strings.Builder
	if err := r.Get(ctx, b, to.key, file.ID, &data); err != nil || data.String() != "hello" {
		t.Fatalf("legitimate read after unauthorized operations: %q, %v", data.String(), err)
	}
}

func TestConcurrentUploadsShareQuotaAcrossInboxes(t *testing.T) {
	r := testRelay(t, 5)
	owner := testOwner("alice")
	boxes := []testMailbox{testInbox(t, r, owner), testInbox(t, r, owner)}
	start := make(chan struct{})
	results := make(chan error, len(boxes))
	for _, box := range boxes {
		go func() {
			<-start
			_, err := r.Put(t.Context(), owner, box.key, "five.bin", strings.NewReader("12345"))
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
