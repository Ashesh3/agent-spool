package integration_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"spool/internal/relay"
)

func (s *harness) deleteInbox(t *testing.T, owner ssh.Signer, i inbox) {
	t.Helper()
	out := s.exec(t, owner, "spool", "delete-inbox "+i.ID, nil, 0)
	if result := unpack[map[string]string](t, out); len(result) != 1 || result["deleted_inbox"] != i.ID {
		t.Fatalf("wrong delete-inbox receipt: %s", out)
	}
}

func TestDeleteInboxRequiresExactHandleAndOwnerAtManagementLogin(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := ageID.Recipient().String()
	a := s.createNamed(t, s.alice, "Build_bot-2", pub)
	b := s.create(t, s.bob, "")
	pending := s.put(t, s.alice, a, "pending", []byte("still usable"))
	file := s.put(t, s.bob, b, "received", []byte("private file"))
	r := s.send(t, s.bob, b, a.ID+" --attach "+file, []byte("must not disappear"))

	s.exec(t, s.bob, "spool", "delete-inbox "+a.ID, nil, 1)
	s.exec(t, s.alice, a.ID, "delete-inbox "+a.ID, nil, 2)
	s.exec(t, s.alice, "spool", "delete "+r.ID, nil, 2)
	for _, cmd := range []string{"delete-inbox", "delete-inbox " + a.ID + " extra", "delete-inbox --all"} {
		s.exec(t, s.alice, "spool", cmd, nil, 2)
	}
	for _, operand := range []string{a.Address, "build_bot-2", "spool"} {
		s.exec(t, s.alice, "spool", "delete-inbox "+operand, nil, 1)
	}
	s.requireList(t, s.alice, a)
	if key := unpack[map[string]string](t, s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 0)); key["public_key"] != pub {
		t.Fatal("rejected delete-inbox changed the published age key")
	}
	if p := s.poll(t, s.alice, a, ""); len(p.Messages) != 1 || p.Messages[0].ID != r.ID || p.Messages[0].Body != "must not disappear" {
		t.Fatalf("rejected delete-inbox changed the mailbox: %+v", p)
	}
	if got := s.exec(t, s.alice, a.ID, "get "+file, nil, 0); string(got) != "private file" {
		t.Fatalf("rejected delete-inbox changed the received file: %q", got)
	}
	s.send(t, s.alice, a, b.ID+" --attach "+pending, nil)
	s.deleteInbox(t, s.alice, a)
	s.exec(t, s.alice, "spool", "delete-inbox "+a.ID, nil, 1)
	s.requireList(t, s.alice)
	s.requireList(t, s.bob, b)
}

func TestDeleteAndReclaimPreservesOnlyDeliveredCopiesAcrossRestart(t *testing.T) {
	cfg := relay.Config{DataDir: t.TempDir()}
	k := keys(t)
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := ageID.Recipient().String()
	pendingBytes := []byte("unpublished private attachment")
	incomingBytes := []byte("private received attachment")
	deliveredBytes := []byte{'k', 0, 'e', 255, 'p'}
	var a, peer inbox
	var pending, incomingFile, incomingID, deliveredFile, deliveredID string
	if !t.Run("delete and immediately reclaim", func(t *testing.T) {
		s := start(t, cfg, k)
		a = s.createNamed(t, s.alice, "Reused", oldKey)
		peer = s.create(t, s.bob, "")
		if lookup := unpack[map[string]string](t, s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 0)); lookup["public_key"] != oldKey {
			t.Fatal("original public key unavailable")
		}
		pending = s.put(t, s.alice, a, "unfinished", pendingBytes)
		incomingFile = s.put(t, s.bob, peer, "received", incomingBytes)
		incomingID = s.send(t, s.bob, peer, a.ID+" --attach "+incomingFile, []byte("private inbox history")).ID
		deliveredFile = s.put(t, s.alice, a, "kept.bin", deliveredBytes)
		deliveredID = s.send(t, s.alice, a, peer.ID+" --attach "+deliveredFile, []byte("keep this copy")).ID
		requireDiskPayload(t, cfg.DataDir, pendingBytes, true)
		requireDiskPayload(t, cfg.DataDir, incomingBytes, true)

		s.deleteInbox(t, s.alice, a)
		s.denyLogin(t, a.ID, ssh.PublicKeys(s.alice))
		s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 1)
		s.exec(t, s.bob, peer.ID, "send "+a.Address, []byte("before reclaim"), 1)
		if replacement := s.createNamed(t, s.bob, a.ID, ""); replacement != a {
			t.Fatalf("reclaimed address = %+v, want %+v", replacement, a)
		}
		requireDiskPayload(t, cfg.DataDir, pendingBytes, false)
		requireDiskPayload(t, cfg.DataDir, incomingBytes, false)
	}) {
		t.FailNow()
	}

	s := start(t, cfg, k)
	s.requireList(t, s.alice)
	s.requireList(t, s.bob, a, peer)
	s.denyLogin(t, a.ID, ssh.PublicKeys(s.alice))
	s.exec(t, s.alice, "spool", "delete-inbox "+a.ID, nil, 1)
	s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 1)
	s.exec(t, s.bob, a.ID, "get "+incomingFile, nil, 1)
	s.exec(t, s.bob, a.ID, "delete "+incomingID, nil, 1)
	s.exec(t, s.bob, a.ID, "send "+peer.ID+" --attach "+pending, nil, 1)

	p := s.poll(t, s.bob, peer, "")
	if len(p.Messages) != 1 || p.Next != deliveredID {
		t.Fatalf("old delivery or cursor changed: %+v", p)
	}
	m := p.Messages[0]
	if m.ID != deliveredID || m.From != a.Address || m.To != peer.Address || m.Body != "keep this copy" || len(m.Attachments) != 1 || m.Attachments[0] != (attachment{ID: deliveredFile, Filename: "kept.bin", Size: int64(len(deliveredBytes))}) {
		t.Fatalf("old delivery changed: %+v", m)
	}
	if got := s.exec(t, s.bob, peer.ID, "get "+deliveredFile, nil, 0); !bytes.Equal(got, deliveredBytes) {
		t.Fatalf("recipient's delivered file changed: %x", got)
	}
	s.exec(t, s.bob, peer.ID, "send "+m.From+" --reply-to "+m.ID, []byte("only for the old owner"), 1)
	if p := s.poll(t, s.bob, a, ""); len(p.Messages) != 0 {
		t.Fatalf("replacement received old mail or a stale reply: %+v", p)
	}
	fresh := s.send(t, s.bob, peer, a.Address, []byte("for the new owner"))
	if p := s.poll(t, s.bob, a, ""); len(p.Messages) != 1 || p.Messages[0].ID != fresh.ID || p.Messages[0].From != peer.Address || p.Messages[0].To != a.Address || p.Messages[0].Body != "for the new owner" {
		t.Fatalf("fresh delivery did not reach replacement: %+v", p)
	}
	s.send(t, s.bob, a, peer.Address+" --reply-to "+fresh.ID, []byte("new conversation"))
}

func TestDeletingInboxKeepsOutboundQuotaWithOriginalKey(t *testing.T) {
	s := start(t, relay.Config{QuotaBytes: 8}, keys(t))
	a, sibling := s.create(t, s.alice, ""), s.create(t, s.alice, "")
	b := s.create(t, s.bob, "")
	original := s.send(t, s.alice, a, b.ID, []byte("123456"))
	s.put(t, s.alice, a, "discarded", []byte("78"))
	s.deleteInbox(t, s.alice, a)
	replacement := s.createNamed(t, s.bob, a.ID, "")

	// Alice retains the six delivered bytes, but not the discarded stage.
	s.exec(t, s.alice, sibling.ID, "send "+b.ID, []byte("123"), 1)
	s.send(t, s.alice, sibling, b.ID, []byte("12"))
	// Bob can use his entire allowance, even from the reclaimed address.
	s.send(t, s.bob, replacement, sibling.ID, []byte("12345678"))
	s.exec(t, s.bob, b.ID, "delete "+original.ID, nil, 0)
	s.send(t, s.alice, sibling, b.ID, []byte("123456"))
}

// An implementation may reject commands on an old connection or close it.
// Neither may yield a successful command or any mailbox data on stdout.
func requireRevokedExec(t *testing.T, c *ssh.Client, cmd string, input []byte) {
	t.Helper()
	session, err := c.NewSession()
	if errors.Is(err, io.EOF) {
		return
	}
	if err != nil {
		var denied *ssh.OpenChannelError
		if errors.As(err, &denied) && denied.Reason == ssh.Prohibited {
			return
		}
		t.Fatalf("open stale session: %v", err)
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(input)
	out, err := session.Output(cmd)
	var exit *ssh.ExitError
	var closed *ssh.ExitMissingError
	denied := errors.As(err, &exit) && exit.ExitStatus() == 1
	if len(out) != 0 || !(denied || errors.Is(err, io.EOF) || errors.As(err, &closed)) {
		t.Fatalf("stale connection ran %q: stdout %q, error %v", cmd, out, err)
	}
}

func TestAuthenticatedConnectionCannotActAfterSameKeyReclaimsHandle(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a := s.createNamed(t, s.alice, "returning", "")
	b := s.create(t, s.bob, "")
	old := s.client(t, s.alice, a.ID)
	defer old.Close()
	s.deleteInbox(t, s.alice, a)
	s.createNamed(t, s.alice, a.ID, "")
	file := s.put(t, s.bob, b, "confidential", []byte("new generation only"))
	fresh := s.send(t, s.bob, b, a.ID+" --attach "+file, []byte("new mail"))
	for _, cmd := range []string{"poll", "get " + file, "delete " + fresh.ID, "put stale", "send " + b.ID} {
		requireRevokedExec(t, old, cmd, []byte("stale client"))
	}
	if p := s.poll(t, s.alice, a, ""); len(p.Messages) != 1 || p.Messages[0].ID != fresh.ID {
		t.Fatalf("stale connection altered replacement: %+v", p)
	}
	if got := s.exec(t, s.alice, a.ID, "get "+file, nil, 0); string(got) != "new generation only" {
		t.Fatalf("fresh connection did not receive its own file: %q", got)
	}
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatalf("stale connection sent as replacement: %+v", p)
	}
}
