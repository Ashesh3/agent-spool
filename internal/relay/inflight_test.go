package relay

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Interleave a store operation with the first stdin read, without scheduling
// goroutines or guessing when the operation has finished its initial checks.
type interruptedInput struct {
	beforeRead func()
	body       *bytes.Reader
}

func (s *interruptedInput) Read(p []byte) (int, error) {
	if s.beforeRead != nil {
		s.beforeRead()
		s.beforeRead = nil
	}
	return s.body.Read(p)
}

func TestReclaimDuringStdin(t *testing.T) {
	for _, op := range []string{"put-from", "put-to", "send-from", "send-to"} {
		t.Run(op, func(t *testing.T) {
			r := testRelay(t, 0)
			ctx := t.Context()
			a, b := testOwner("alice"), testOwner("bob")
			from, to := testInbox(t, r, a), testInbox(t, r, b)
			owner, old, other := a, from, to
			want := notOwner
			if strings.HasSuffix(op, "-to") {
				owner, old, other = b, to, from
				want = RequestError("recipient inbox not found")
			}
			// Keep the retired row alive: merely finding its ID or satisfying a
			// foreign key must not authorize a stage or delivery.
			keep := encryptForMailboxes(t, old, other, "keep")
			if _, err := r.Send(ctx, owner, old.key, other.destination(), bytes.NewReader(keep)); err != nil {
				t.Fatal(err)
			}
			late := encryptForMailboxes(t, from, to, "late")
			src := &interruptedInput{body: bytes.NewReader(late), beforeRead: func() {
				if err := r.DeleteInbox(ctx, owner, old.ID); err != nil {
					t.Fatal(err)
				}
				// Even re-registering the same public key and owner cannot
				// carry an in-flight operation into a new inbox incarnation.
				if _, err := r.Create(ctx, owner, old.ID, old.recipient.String()); err != nil {
					t.Fatal(err)
				}
			}}
			var err error
			if strings.HasPrefix(op, "put-") {
				_, err = r.Put(ctx, a, from.key, to.ID, to.recipient.String(), "late.bin", src)
			} else {
				_, err = r.Send(ctx, a, from.key, to.destination(), src)
			}
			if src.beforeRead != nil || !errors.Is(err, want) {
				t.Fatalf("expected %q after handle reuse during stdin, got %v", want, err)
			}
			var messages, pending int
			if err := r.db.QueryRow(`SELECT (SELECT count(*) FROM messages), (SELECT count(*) FROM pending)`).Scan(&messages, &pending); err != nil {
				t.Fatal(err)
			}
			if messages != 1 || pending != 0 {
				t.Fatalf("got %d messages and %d staged uploads; want only the original message", messages, pending)
			}
			if strings.HasPrefix(op, "put-") {
				for _, dir := range []string{r.staging, r.blobs} {
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 0 {
						t.Fatalf("uncommitted upload left files in %s: %v, %v", dir, entries, err)
					}
				}
			}
		})
	}
}

func TestReplyExpiresDuringStdin(t *testing.T) {
	r := testRelay(t, 0)
	ctx := t.Context()
	now := time.Unix(100, 0)
	r.cfg.Now = func() time.Time { return now }
	a, b := testOwner("alice"), testOwner("bob")
	from, to := testInbox(t, r, a), testInbox(t, r, b)
	question := encryptForMailboxes(t, from, to, "question")
	original, err := r.Send(ctx, a, from.key, to.destination(), bytes.NewReader(question))
	if err != nil {
		t.Fatal(err)
	}
	answer := encryptForMailboxes(t, to, from, "answer")
	src := &interruptedInput{body: bytes.NewReader(answer), beforeRead: func() { now = original.Expires }}
	opts := from.destination()
	opts.ReplyTo = original.ID
	_, err = r.Send(ctx, b, to.key, opts, src)
	if src.beforeRead != nil || !errors.Is(err, RequestError("reply_to message unavailable for this recipient")) {
		t.Fatalf("expected a request error after the original message expired, got %v", err)
	}
}
