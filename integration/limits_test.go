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
	a := s.create(t, s.alice, "")
	for range 3 {
		probe := s.client(t, s.alice, "spool")
		probe.Close()
		s.denyLogin(t, a.ID, ssh.PublicKeys(s.bob))
	}
	s.exec(t, s.alice, a.ID, "unknown-command", nil, 2)
	s.exec(t, s.alice, "spool", "list", nil, 1)
	b := s.create(t, s.bob, "")
	s.requireList(t, s.bob, b)
	c.step(time.Minute)
	s.requireList(t, s.alice, a)
}

func TestQuotaCombinesPendingAndLiveBytesAcrossOwnersInboxes(t *testing.T) {
	s := start(t, relay.Config{QuotaBytes: 8}, keys(t))
	a, sibling := s.create(t, s.alice, ""), s.create(t, s.alice, "")
	b := s.create(t, s.bob, "")
	five := s.put(t, s.alice, a, "five", []byte("12345"))
	s.exec(t, s.alice, sibling.ID, "put too-big", []byte("1234"), 1)
	three := s.put(t, s.alice, sibling, "three", []byte("123"))
	s.exec(t, s.alice, a.ID, "send "+b.ID+" --attach "+five, []byte("x"), 1)
	first := s.send(t, s.alice, a, b.ID+" --attach "+five, nil)
	// Five delivered bytes plus three staged bytes exactly fill Alice's quota.
	s.exec(t, s.alice, a.ID, "send "+b.ID, []byte("x"), 1)
	s.exec(t, s.alice, sibling.ID, "put more", []byte("x"), 1)
	s.send(t, s.alice, sibling, b.ID+" --attach "+three, nil)
	s.send(t, s.bob, b, a.ID, []byte("12345678"))
	s.exec(t, s.bob, b.ID, "delete "+first.ID, nil, 0)
	s.exec(t, s.alice, sibling.ID, "send "+b.ID, []byte("123456"), 1)
	s.send(t, s.alice, sibling, b.ID, []byte("12345"))
}

func TestFileAndAggregateMessageLimits(t *testing.T) {
	s := start(t, relay.Config{MaxFileBytes: 4, MaxMessageBytes: 6}, keys(t))
	a, b := s.create(t, s.alice, ""), s.create(t, s.bob, "")
	s.exec(t, s.alice, a.ID, "put oversized", []byte("12345"), 1)
	for _, name := range []string{"../escape", `dir\escape`, ".", "..", strings.Repeat("é", 128)} {
		s.exec(t, s.alice, a.ID, "put "+name, []byte("x"), anyRejection)
	}
	f := s.put(t, s.alice, a, strings.Repeat("é", 127)+"x", []byte("1234"))
	g := s.put(t, s.alice, a, "two", []byte("56"))
	args := b.ID + " --attach " + f + " --attach " + g
	s.exec(t, s.alice, a.ID, "send "+args, []byte("7"), 1)
	s.send(t, s.alice, a, args, nil)
	s.exec(t, s.alice, a.ID, "send "+b.ID, []byte("1234567"), 1)
}

func TestBodyEncodingAndCountLimits(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a, b := s.create(t, s.alice, ""), s.create(t, s.bob, "")
	for _, poll := range []string{"poll --since -1", "poll --limit 0", "poll --limit 101"} {
		s.exec(t, s.bob, b.ID, poll, nil, 2)
	}
	s.exec(t, s.alice, a.ID, "send "+b.ID+"@another.test", []byte("x"), anyRejection)
	s.exec(t, s.alice, a.ID, "send "+b.ID+" --encoding age", []byte("not base64!"), 1)
	s.exec(t, s.alice, a.ID, "send "+b.ID, []byte{0xff}, 1)
	body := bytes.Repeat([]byte("x"), (1<<20)+1)
	s.exec(t, s.alice, a.ID, "send "+b.ID, body, 1)
	s.send(t, s.alice, a, b.ID, body[:1<<20])

	flags := make([]string, 17)
	for i := range flags {
		name := strconv.Itoa(i)
		flags[i] = " --attach " + s.put(t, s.alice, a, name, []byte(name))
	}
	s.exec(t, s.alice, a.ID, "send "+b.ID+strings.Join(flags, ""), nil, anyRejection)
	published := s.send(t, s.alice, a, b.ID+strings.Join(flags[:16], ""), nil)
	p := s.poll(t, s.bob, b, "")
	if len(p.Messages) != 2 || len(p.Messages[0].Body) != 1<<20 || p.Messages[1].ID != published.ID || len(p.Messages[1].Attachments) != 16 {
		t.Fatalf("wrong deliveries at body/attachment limits: got %d messages", len(p.Messages))
	}
}
