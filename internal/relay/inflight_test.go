package relay

import (
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
	body       *strings.Reader
}

func (s *interruptedInput) Read(p []byte) (int, error) {
	if s.beforeRead != nil {
		s.beforeRead()
		s.beforeRead = nil
	}
	return s.body.Read(p)
}

func TestReclaimDuringStdin(t *testing.T) {
	for _, op := range []string{"put", "send-from", "send-to"} {
		t.Run(op, func(t *testing.T) {
			r := testRelay(t, 0)
			ctx := t.Context()
			a, b := testOwner("alice"), testOwner("bob")
			from, to := testInbox(t, r, a), testInbox(t, r, b)
			owner, old, other := a, from, to
			want := notOwner
			if op == "send-to" {
				owner, old, other = b, to, from
				want = RequestError("recipient inbox not found")
			}
			// Keep the retired row alive: merely finding its ID or satisfying a
			// foreign key must not authorize a stage or delivery.
			if _, err := r.Send(ctx, owner, old.key, SendOptions{To: other.ID}, strings.NewReader("keep")); err != nil {
				t.Fatal(err)
			}
			src := &interruptedInput{body: strings.NewReader("late"), beforeRead: func() {
				if err := r.DeleteInbox(ctx, owner, old.ID); err != nil {
					t.Fatal(err)
				}
				// Reuse with the very same owner so an owner+handle check alone
				// cannot distinguish the old and new inboxes.
				if _, err := r.Create(ctx, owner, old.ID, ""); err != nil {
					t.Fatal(err)
				}
			}}
			var err error
			if op == "put" {
				_, err = r.Put(ctx, a, from.key, "late.bin", src)
			} else {
				_, err = r.Send(ctx, a, from.key, SendOptions{To: to.ID}, src)
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
			if op == "put" {
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
	original, err := r.Send(ctx, a, from.key, SendOptions{To: to.ID}, strings.NewReader("question"))
	if err != nil {
		t.Fatal(err)
	}
	src := &interruptedInput{body: strings.NewReader("answer"), beforeRead: func() { now = original.Expires }}
	_, err = r.Send(ctx, b, to.key, SendOptions{To: from.ID, ReplyTo: original.ID}, src)
	var rejected RequestError
	if src.beforeRead != nil || !errors.As(err, &rejected) {
		t.Fatalf("expected a request error after the original message expired, got %v", err)
	}
}
