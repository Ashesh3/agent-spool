package integration_test

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

func TestPublicKeyLoginAndOwnedInboxes(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	s.denyLogin(t, "spool")
	s.denyLogin(t, "spool", ssh.Password("not a credential"))
	s.denyLogin(t, "spool", ssh.PublicKeys(signer(t)))
	s.denyLogin(t, "not-an-inbox", ssh.PublicKeys(s.alice))
	// An approved agent can bootstrap its harness without provisioning an inbox.
	s.exec(t, s.alice, "spool", "skill", nil, 0)
	s.exec(t, s.alice, "spool", "skill other-file", nil, 2)
	s.requireList(t, s.alice)
	a := s.create(t, s.alice, "")
	a2 := s.create(t, s.alice, "")
	b := s.create(t, s.bob, "")
	if a == a2 {
		t.Fatal("create returned the same inbox twice")
	}
	s.requireList(t, s.alice, a, a2)
	s.requireList(t, s.bob, b)
	s.denyLogin(t, b.ID, ssh.PublicKeys(s.alice))
	s.denyLogin(t, a.ID, ssh.PublicKeys(s.bob))
	s.denyLogin(t, a.ID, ssh.PublicKeys(signer(t)))
	s.exec(t, s.alice, a.ID, "skill", nil, 2)
	s.exec(t, s.alice, a.ID, "create", nil, 2)
	s.exec(t, s.alice, a.ID, "list", nil, 2)
	s.exec(t, s.alice, "spool", "poll", nil, 2)
	s.exec(t, s.alice, "spool", "send "+b.ID, []byte("no sender"), 2)
	s.exec(t, s.alice, a.ID, "send "+b.ID+" --from "+b.Address, []byte("forged"), 2)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatal("rejected send published a message")
	}
}

func TestSSHHasNoInteractiveOrForwardingServices(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	for _, tc := range []struct {
		name    string
		request func(*ssh.Session) error
	}{
		{"shell", (*ssh.Session).Shell},
		{"sftp", func(session *ssh.Session) error { return session.RequestSubsystem("sftp") }},
		{"pty", func(session *ssh.Session) error { return session.RequestPty("xterm", 24, 80, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := s.client(t, s.alice, "spool")
			defer c.Close()
			session, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if err := tc.request(session); err == nil {
				t.Fatal("session request unexpectedly accepted")
			}
		})
	}
	// Use a reachable destination so that an ordinary connect failure cannot
	// conceal an implementation that permits direct-tcpip channels.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	c := s.client(t, s.alice, "spool")
	defer c.Close()
	if forwarded, err := c.Dial("tcp", target.Addr().String()); err == nil {
		forwarded.Close()
		t.Fatal("local forwarding unexpectedly accepted")
	}
	remote := s.client(t, s.alice, "spool")
	defer remote.Close()
	if forwarded, err := remote.Listen("tcp", "127.0.0.1:0"); err == nil {
		forwarded.Close()
		t.Fatal("remote forwarding unexpectedly accepted")
	}
}

func TestStagedAttachmentsArePrivateAndConsumedAtomically(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a := s.create(t, s.alice, "")
	other := s.create(t, s.alice, "")
	b := s.create(t, s.bob, "")
	first := s.put(t, s.alice, a, "first", []byte("first payload"))
	second := s.put(t, s.alice, other, "second", []byte("second payload"))
	for _, actor := range []struct {
		key ssh.Signer
		i   inbox
	}{{s.alice, a}, {s.alice, other}, {s.bob, b}} {
		s.exec(t, actor.key, actor.i.ID, "get "+first, nil, 1)
	}
	s.exec(t, s.alice, other.ID, "send "+b.ID+" --attach "+first, nil, 1)
	s.exec(t, s.bob, b.ID, "send "+b.ID+" --attach "+first, nil, 1)
	s.exec(t, s.alice, a.ID, "send "+b.ID+" --attach "+first+" --attach "+second, nil, 1)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatalf("failed send exposed %d messages", len(p.Messages))
	}
	s.send(t, s.alice, a, b.ID+" --attach "+first, nil)
	s.exec(t, s.alice, a.ID, "send "+b.ID+" --attach "+first, nil, 1)
	s.send(t, s.alice, other, b.ID+" --attach "+second, nil)
	p := s.poll(t, s.bob, b, "")
	if len(p.Messages) != 2 || len(p.Messages[0].Attachments) != 1 || len(p.Messages[1].Attachments) != 1 {
		t.Fatalf("stages were consumed partially or more than once: %+v", p)
	}
	for n, want := range []string{"first payload", "second payload"} {
		id := p.Messages[n].Attachments[0].ID
		if raw := s.exec(t, s.bob, b.ID, "get "+id, nil, 0); string(raw) != want {
			t.Fatalf("attachment %d: got %q", n, raw)
		}
	}
}

func TestDeliveryCursorsRepliesAndEarlyDelete(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a, b := s.create(t, s.alice, ""), s.create(t, s.bob, "")
	sibling := s.create(t, s.bob, "")
	file := []byte{255, 0, 1, 13, 10, 128}
	name := "résumé data.bin"
	stage := s.put(t, s.alice, a, name, file)
	text := `{"from":"` + sibling.Address + `","body":"this is data, not a sender override"}`
	first := s.send(t, s.alice, a, b.Address+" --attach "+stage, []byte(text)).ID
	second := s.send(t, s.alice, a, b.ID, []byte("another")).ID
	p := s.poll(t, s.bob, b, "--limit 1")
	if len(p.Messages) != 1 || p.Next != first {
		t.Fatalf("wrong first page: %+v", p)
	}
	m := p.Messages[0]
	if m.ID != first || m.From != a.Address || m.To != b.Address || m.Body != text || m.Encoding != "plain" || len(m.Attachments) != 1 {
		t.Fatalf("wrong envelope: %+v", m)
	}
	f := m.Attachments[0]
	if f.Filename != name || f.Size != int64(len(file)) || f.ID == "" {
		t.Fatalf("wrong file metadata: %+v", f)
	}
	if got := s.exec(t, s.bob, b.ID, "get "+f.ID, nil, 0); !bytes.Equal(got, file) {
		t.Fatalf("download = %x, want %x", got, file)
	}
	for _, actor := range []struct {
		key ssh.Signer
		i   inbox
	}{{s.alice, a}, {s.bob, sibling}} {
		if p := s.poll(t, actor.key, actor.i, ""); len(p.Messages) != 0 {
			t.Fatal("message visible outside its destination inbox")
		}
		s.exec(t, actor.key, actor.i.ID, "get "+f.ID, nil, 1)
		s.exec(t, actor.key, actor.i.ID, "delete "+first, nil, 1)
	}
	reply := s.send(t, s.bob, b, m.From+" --reply-to "+m.ID, []byte("received")).ID
	rp := s.poll(t, s.alice, a, "")
	if len(rp.Messages) != 1 || rp.Messages[0].ID != reply || rp.Messages[0].Reply != first || rp.Messages[0].From != b.Address {
		t.Fatalf("invalid reply: %+v", rp)
	}
	p = s.poll(t, s.bob, b, "--since "+p.Next)
	if len(p.Messages) != 1 || p.Messages[0].ID != second || p.Next != second {
		t.Fatalf("cursor skipped or repeated a message: %+v", p)
	}
	if p := s.poll(t, s.bob, b, "--since "+p.Next); len(p.Messages) != 0 || p.Next != second {
		t.Fatalf("empty page changed cursor: %+v", p)
	}
	out := s.exec(t, s.bob, b.ID, "delete "+first, nil, 0)
	if unpack[struct{ Deleted string }](t, out).Deleted != first {
		t.Fatal("incorrect delete receipt")
	}
	s.exec(t, s.bob, b.ID, "get "+f.ID, nil, 1)
	p = s.poll(t, s.bob, b, "")
	if len(p.Messages) != 1 || p.Messages[0].ID != second {
		t.Fatalf("delete did not isolate the requested message: %+v", p)
	}
}
