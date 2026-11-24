package integration_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

func TestRateBudgetIsPerOwnerAndOnlyChargesExec(t *testing.T) {
	c := newClock()
	s := start(t, relay.Config{RequestsPerMinute: 2, Now: c.now}, keys(t))
	a := s.create(t, s.alice)
	for range 3 {
		probe := s.client(t, s.alice, "spool")
		probe.Close()
		s.denyLogin(t, a.ID, ssh.PublicKeys(s.bob))
	}
	s.exec(t, s.alice, a.ID, "unknown-command", nil, 2)
	s.exec(t, s.alice, "spool", "list", nil, 1)
	b := s.create(t, s.bob)
	s.requireList(t, s.bob, b)
	c.step(time.Minute)
	s.requireList(t, s.alice, a)
}

// For a single age stream chunk and two X25519 recipients the framing has
// fixed length. Measure it with the client's actual encoder, not an estimate.
func envelopeOverhead(t *testing.T) int64 {
	t.Helper()
	return int64(len(seal(t, inbox{identity: newIdentity(t)}, inbox{identity: newIdentity(t)}, nil)))
}

func TestQuotaCombinesPendingAndLiveBytesAcrossOwnersInboxes(t *testing.T) {
	overhead := envelopeOverhead(t)
	s := start(t, relay.Config{QuotaBytes: 2*overhead + 8}, keys(t))
	a, sibling := s.create(t, s.alice), s.create(t, s.alice)
	b := s.create(t, s.bob)
	five := s.put(t, s.alice, a, b, "five", []byte("12345"))
	s.exec(t, s.alice, sibling.ID, putTo(b, "too-big"), seal(t, sibling, b, []byte("1234")), 1)
	three := s.put(t, s.alice, sibling, b, "three", []byte("123"))
	s.exec(t, s.alice, a.ID, sendTo(b)+" --attach "+five, seal(t, a, b, []byte("x")), 1)
	first := s.send(t, s.alice, a, b, " --attach "+five, nil)
	// A delivered envelope plus a staged one exactly fill Alice's allowance.
	s.exec(t, s.alice, a.ID, sendTo(b), seal(t, a, b, []byte("x")), 1)
	s.exec(t, s.alice, sibling.ID, putTo(b, "more"), seal(t, sibling, b, []byte("x")), 1)
	s.send(t, s.alice, sibling, b, " --attach "+three, nil)
	s.send(t, s.bob, b, a, "", make([]byte, overhead+8))
	s.exec(t, s.bob, b.ID, "delete "+first.ID, nil, 0)
	s.exec(t, s.alice, sibling.ID, sendTo(b), seal(t, sibling, b, []byte("123456")), 1)
	s.send(t, s.alice, sibling, b, "", []byte("12345"))
}

func TestFileAndAggregateMessageLimits(t *testing.T) {
	overhead := envelopeOverhead(t)
	s := start(t, relay.Config{MaxFileBytes: overhead + 4, MaxMessageBytes: 2*overhead + 6}, keys(t))
	a, b := s.create(t, s.alice), s.create(t, s.bob)
	s.exec(t, s.alice, a.ID, putTo(b, "oversized"), seal(t, a, b, []byte("12345")), 1)
	for _, name := range []string{"../escape", `dir\escape`, ".", "..", strings.Repeat("é", 128)} {
		s.exec(t, s.alice, a.ID, putTo(b, name), seal(t, a, b, []byte("x")), anyRejection)
	}
	f := s.put(t, s.alice, a, b, strings.Repeat("é", 127)+"x", []byte("1234"))
	g := s.put(t, s.alice, a, b, "two", []byte("56"))
	flags := " --attach " + f + " --attach " + g
	s.exec(t, s.alice, a.ID, sendTo(b)+flags, seal(t, a, b, []byte("7")), 1)
	s.send(t, s.alice, a, b, flags, nil)
	s.exec(t, s.alice, a.ID, sendTo(b), seal(t, a, b, make([]byte, overhead+7)), 1)
}

func TestBodyAndAttachmentCountLimits(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a, b := s.create(t, s.alice), s.create(t, s.bob)
	for _, poll := range []string{"poll --since -1", "poll --limit 0", "poll --limit 101"} {
		s.exec(t, s.bob, b.ID, poll, nil, 2)
	}
	s.exec(t, s.alice, a.ID, "send "+b.ID+"@another.test --recipient-key "+b.publicKey(), seal(t, a, b, []byte("x")), anyRejection)

	const limit = 1 << 20
	plain := bytes.Repeat([]byte("x"), limit)
	overhead := len(seal(t, a, b, plain)) - limit // includes the tags of all 16 stream chunks
	fits := seal(t, a, b, plain[:limit-overhead])
	over := seal(t, a, b, plain[:limit-overhead+1])
	if len(fits) != limit || len(over) != limit+1 {
		t.Fatal("fixture did not hit the binary body-size boundary")
	}
	s.exec(t, s.alice, a.ID, sendTo(b), over, 1)
	s.sendCipher(t, s.alice, a, b, "", fits)

	flags := make([]string, 17)
	for i := range flags {
		name := strconv.Itoa(i)
		flags[i] = " --attach " + s.put(t, s.alice, a, b, name, []byte(name))
	}
	s.exec(t, s.alice, a.ID, sendTo(b)+strings.Join(flags, ""), nil, anyRejection)
	published := s.send(t, s.alice, a, b, strings.Join(flags[:16], ""), nil)
	p := s.poll(t, s.bob, b, "")
	if len(p.Messages) != 2 || !bytes.Equal(bodyCipher(t, p.Messages[0].Body), fits) || p.Messages[1].ID != published.ID || len(p.Messages[1].Attachments) != 16 {
		t.Fatalf("wrong deliveries at body/attachment limits: got %d messages", len(p.Messages))
	}
}
