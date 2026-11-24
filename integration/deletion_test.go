package integration_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

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
	a := s.createNamed(t, s.alice, "Build_bot-2", newIdentity(t))
	b := s.create(t, s.bob)
	pending := s.put(t, s.alice, a, b, "pending", []byte("still usable"))
	file := s.put(t, s.bob, b, a, "received", []byte("private file"))
	r := s.send(t, s.bob, b, a, " --attach "+file, []byte("must not disappear"))

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
	if key := unpack[map[string]string](t, s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 0)); key["public_key"] != a.publicKey() {
		t.Fatal("rejected delete-inbox changed the published age key")
	}
	if p := s.poll(t, s.alice, a, ""); len(p.Messages) != 1 || p.Messages[0].ID != r.ID || string(decrypt(t, a, bodyCipher(t, p.Messages[0].Body))) != "must not disappear" {
		t.Fatalf("rejected delete-inbox changed the mailbox: %+v", p)
	}
	if got := s.exec(t, s.alice, a.ID, "get "+file, nil, 0); string(decrypt(t, a, got)) != "private file" {
		t.Fatal("rejected delete-inbox changed the received file")
	}
	s.send(t, s.alice, a, b, " --attach "+pending, nil)
	s.deleteInbox(t, s.alice, a)
	s.exec(t, s.alice, "spool", "delete-inbox "+a.ID, nil, 1)
	s.requireList(t, s.alice)
	s.requireList(t, s.bob, b)
}

func TestDeleteAndReclaimPreservesOnlyDeliveredCopiesAcrossRestart(t *testing.T) {
	cfg := relay.Config{DataDir: t.TempDir()}
	k := keys(t)
	var pendingBytes, incomingBytes, deliveredBytes []byte
	var a, replacement, peer inbox
	var pending, incomingFile, incomingID, deliveredFile, deliveredID string
	if !t.Run("delete and immediately reclaim", func(t *testing.T) {
		s := start(t, cfg, k)
		a = s.createNamed(t, s.alice, "Reused", newIdentity(t))
		peer = s.create(t, s.bob)
		if lookup := unpack[map[string]string](t, s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 0)); lookup["public_key"] != a.publicKey() {
			t.Fatal("original public key unavailable")
		}
		pendingBytes = seal(t, a, peer, []byte("unpublished private attachment"))
		incomingBytes = seal(t, peer, a, []byte("private received attachment"))
		deliveredBytes = seal(t, a, peer, []byte{'k', 0, 'e', 255, 'p'})
		pending = s.putCipher(t, s.alice, a, peer, "unfinished", pendingBytes)
		incomingFile = s.putCipher(t, s.bob, peer, a, "received", incomingBytes)
		incomingID = s.send(t, s.bob, peer, a, " --attach "+incomingFile, []byte("private inbox history")).ID
		deliveredFile = s.putCipher(t, s.alice, a, peer, "kept.bin", deliveredBytes)
		deliveredID = s.send(t, s.alice, a, peer, " --attach "+deliveredFile, []byte("keep this copy")).ID
		requireDiskPayload(t, cfg.DataDir, pendingBytes, true)
		requireDiskPayload(t, cfg.DataDir, incomingBytes, true)

		s.deleteInbox(t, s.alice, a)
		s.denyLogin(t, a.ID, ssh.PublicKeys(s.alice))
		s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 1)
		s.exec(t, s.bob, peer.ID, sendTo(a), seal(t, peer, a, []byte("before reclaim")), 1)
		replacement = s.createNamed(t, s.bob, a.ID, newIdentity(t))
		if replacement.Address != a.Address {
			t.Fatalf("reclaimed address = %s, want %s", replacement.Address, a.Address)
		}
		requireDiskPayload(t, cfg.DataDir, pendingBytes, false)
		requireDiskPayload(t, cfg.DataDir, incomingBytes, false)
	}) {
		t.FailNow()
	}

	s := start(t, cfg, k)
	s.requireList(t, s.alice)
	s.requireList(t, s.bob, replacement, peer)
	s.denyLogin(t, a.ID, ssh.PublicKeys(s.alice))
	s.exec(t, s.alice, "spool", "delete-inbox "+a.ID, nil, 1)
	if lookup := unpack[map[string]string](t, s.exec(t, s.bob, "spool", "pubkey "+a.Address, nil, 0)); lookup["public_key"] != replacement.publicKey() {
		t.Fatal("reclaimed address retained old age key")
	}
	s.exec(t, s.bob, replacement.ID, "get "+incomingFile, nil, 1)
	s.exec(t, s.bob, replacement.ID, "delete "+incomingID, nil, 1)
	s.exec(t, s.bob, replacement.ID, sendTo(peer)+" --attach "+pending, nil, 1)

	p := s.poll(t, s.bob, peer, "")
	if len(p.Messages) != 1 || p.Next != deliveredID {
		t.Fatalf("old delivery or cursor changed: %+v", p)
	}
	m := p.Messages[0]
	if m.ID != deliveredID || m.From != a.Address || m.To != peer.Address || string(decrypt(t, peer, bodyCipher(t, m.Body))) != "keep this copy" || len(m.Attachments) != 1 || m.Attachments[0] != (attachment{ID: deliveredFile, Filename: "kept.bin", Size: int64(len(deliveredBytes))}) {
		t.Fatalf("old delivery changed: %+v", m)
	}
	if got := s.exec(t, s.bob, peer.ID, "get "+deliveredFile, nil, 0); !bytes.Equal(got, deliveredBytes) {
		t.Fatalf("recipient's delivered file changed: %x", got)
	}
	s.exec(t, s.bob, peer.ID, sendTo(replacement)+" --reply-to "+m.ID, seal(t, peer, replacement, []byte("only for the old owner")), 1)
	s.exec(t, s.bob, peer.ID, sendTo(a), seal(t, peer, a, []byte("stale key lookup")), 1)
	if p := s.poll(t, s.bob, replacement, ""); len(p.Messages) != 0 {
		t.Fatalf("replacement received old mail or a stale reply: %+v", p)
	}
	fresh := s.send(t, s.bob, peer, replacement, "", []byte("for the new owner"))
	if p := s.poll(t, s.bob, replacement, ""); len(p.Messages) != 1 || p.Messages[0].ID != fresh.ID || p.Messages[0].From != peer.Address || p.Messages[0].To != a.Address || string(decrypt(t, replacement, bodyCipher(t, p.Messages[0].Body))) != "for the new owner" {
		t.Fatalf("fresh delivery did not reach replacement: %+v", p)
	}
	s.send(t, s.bob, replacement, peer, " --reply-to "+fresh.ID, []byte("new conversation"))
}

func TestSenderRecallAfterPollAndReclaimReleasesOriginalOwnersQuota(t *testing.T) {
	overhead := envelopeOverhead(t)
	quota := 3*overhead + 8
	dir := t.TempDir()
	s := start(t, relay.Config{DataDir: dir, QuotaBytes: quota}, keys(t))
	a, sibling := s.create(t, s.alice), s.create(t, s.alice)
	b := s.create(t, s.bob)
	file := seal(t, a, b, []byte("12"))
	stage := s.putCipher(t, s.alice, a, b, "recalled", file)
	original := s.send(t, s.alice, a, b, " --attach "+stage, []byte("3456"))
	s.put(t, s.alice, a, b, "discarded", []byte("78"))
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 1 || p.Next != original.ID {
		t.Fatal("delivery missing before recall")
	}
	if got := s.exec(t, s.bob, b.ID, "get "+stage, nil, 0); !bytes.Equal(got, file) {
		t.Fatal("file not downloadable before recall")
	}
	requireDiskPayload(t, dir, file, true)
	s.deleteInbox(t, s.alice, a)
	replacement := s.createNamed(t, s.charlie, a.ID, newIdentity(t))
	// The stage is released, but both delivered envelopes remain Alice's
	// charge. The reclaimed address starts under its new owner's own quota.
	s.exec(t, s.alice, sibling.ID, sendTo(b), seal(t, sibling, b, []byte("123")), 1)
	kept := s.send(t, s.alice, sibling, b, "", []byte("12"))
	other := s.send(t, s.charlie, replacement, b, "", make([]byte, quota-overhead))
	recall := "recall " + original.ID
	s.exec(t, s.bob, "spool", recall, nil, 1)
	s.exec(t, s.charlie, "spool", recall, nil, 1)
	s.exec(t, s.alice, sibling.ID, recall, nil, 2)
	s.exec(t, s.alice, "spool", "recall", nil, 2)
	s.exec(t, s.alice, "spool", "recall 999999", nil, 1)
	out := s.exec(t, s.alice, "spool", recall, nil, 0)
	if got := unpack[map[string]string](t, out); len(got) != 1 || got["recalled"] != original.ID {
		t.Fatalf("wrong recall receipt: %s", out)
	}
	s.exec(t, s.alice, "spool", recall, nil, 1)
	s.exec(t, s.bob, b.ID, "get "+stage, nil, 1)
	requireDiskPayload(t, dir, file, false)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 2 || p.Messages[0].ID != kept.ID || p.Messages[1].ID != other.ID {
		t.Fatal("recall removed unrelated mail or left the recalled message visible")
	}
	s.send(t, s.alice, sibling, b, "", make([]byte, overhead+6)) // reuse all 2*overhead+6 released bytes
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
	a := s.createNamed(t, s.alice, "returning", newIdentity(t))
	b := s.create(t, s.bob)
	intendedForOld := s.put(t, s.bob, b, a, "old generation", []byte("not for its successor"))
	old := s.client(t, s.alice, a.ID)
	defer old.Close()
	s.deleteInbox(t, s.alice, a)
	// Even reusing both the SSH owner and age key cannot revive the stage.
	replacement := s.createNamed(t, s.alice, a.ID, a.identity)
	s.exec(t, s.bob, b.ID, sendTo(replacement)+" --attach "+intendedForOld, nil, 1)
	file := s.put(t, s.bob, b, replacement, "confidential", []byte("new generation only"))
	fresh := s.send(t, s.bob, b, replacement, " --attach "+file, []byte("new mail"))
	cipher := seal(t, replacement, b, []byte("stale client"))
	for _, cmd := range []string{"poll", "get " + file, "delete " + fresh.ID, putTo(b, "stale"), sendTo(b)} {
		requireRevokedExec(t, old, cmd, cipher)
	}
	if p := s.poll(t, s.alice, a, ""); len(p.Messages) != 1 || p.Messages[0].ID != fresh.ID {
		t.Fatalf("stale connection altered replacement: %+v", p)
	}
	if got := s.exec(t, s.alice, replacement.ID, "get "+file, nil, 0); string(decrypt(t, replacement, got)) != "new generation only" {
		t.Fatal("fresh connection did not receive its own file")
	}
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatalf("stale connection sent as replacement: %+v", p)
	}
}
