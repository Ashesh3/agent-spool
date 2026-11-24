package integration_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"spool/internal/relay"
)

func TestEncryptedSSHDelivery(t *testing.T) {
	dir := t.TempDir()
	s := start(t, relay.Config{DataDir: dir}, keys(t))
	alice, bob := s.create(t, s.alice), s.create(t, s.bob)
	key := s.exec(t, s.alice, "spool", "pubkey "+bob.Address, nil, 0)
	if got := unpack[map[string]string](t, key)["public_key"]; got != bob.publicKey() {
		t.Fatalf("recipient discovery returned %q", got)
	}
	text := []byte("**ready** — résumé")
	file := bytes.Repeat([]byte{0, 255, 9, 254}, 22000) // spans age stream chunks
	body, blob := seal(t, alice, bob, text), seal(t, alice, bob, file)
	stage := s.putCipher(t, s.alice, alice, bob, "encrypted.bin", blob)
	msg := s.sendCipher(t, s.alice, alice, bob, " --attach "+stage, body)
	p := s.poll(t, s.bob, bob, "--since 0")
	if len(p.Messages) != 1 || p.Next != msg.ID {
		t.Fatal("missing encrypted delivery")
	}
	m := p.Messages[0]
	if m.From != alice.Address || m.To != bob.Address || len(m.Attachments) != 1 || m.Attachments[0].ID != stage {
		t.Fatal("incorrect encrypted message metadata")
	}
	db := openStoreDB(t, dir)
	var stored []byte
	var storageType string
	if err := db.QueryRow("SELECT typeof(body), body FROM messages WHERE id=?", msg.ID).Scan(&storageType, &stored); err != nil {
		t.Fatal(err)
	}
	if storageType != "blob" || !bytes.Equal(stored, body) || !bytes.Equal(bodyCipher(t, m.Body), body) {
		t.Fatal("persisted or polled ciphertext does not match the original age envelope")
	}
	requireDiskPayload(t, dir, blob, true)
	if got := s.exec(t, s.bob, bob.ID, "get "+stage, nil, 0); !bytes.Equal(got, blob) {
		t.Fatal("download did not return the original ciphertext")
	}
	outsider := newIdentity(t)
	for _, payload := range []struct{ cipher, plain []byte }{{body, text}, {blob, file}} {
		for _, i := range []inbox{alice, bob} {
			if !bytes.Equal(decrypt(t, i, payload.cipher), payload.plain) {
				t.Fatalf("incorrect plaintext for %s", i.ID)
			}
		}
		if _, err := age.Decrypt(bytes.NewReader(payload.cipher), outsider); !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Fatalf("unrelated private key: want no identity match, got %v", err)
		}
	}
}

func TestSSHRejectsNonEncryptedInputAndUnboundKeys(t *testing.T) {
	dir := t.TempDir()
	s := start(t, relay.Config{DataDir: dir}, keys(t))
	id := newIdentity(t)
	for _, cmd := range []string{
		"create", "create named", "create --public-key", "create --public-key not-an-age-key",
		"create --public-key " + id.String(), "create named --public-key " + strings.ToUpper(id.Recipient().String()),
	} {
		s.exec(t, s.alice, "spool", cmd, nil, anyRejection)
	}
	s.requireList(t, s.alice)
	a, b := s.create(t, s.alice), s.create(t, s.bob)
	plain := []byte("not ciphertext")
	cipher := seal(t, a, b, plain)
	stage := s.putCipher(t, s.alice, a, b, "valid stage", cipher)
	for _, invalid := range [][]byte{
		nil, plain, []byte(base64.StdEncoding.EncodeToString(plain)), []byte(base64.StdEncoding.EncodeToString(cipher)),
		[]byte("age-encryption.org/v1\n"), cipher[:len(cipher)-len(plain)-1], seal(t, b, b, plain),
	} {
		s.exec(t, s.alice, a.ID, sendTo(b), invalid, anyRejection)
		s.exec(t, s.alice, a.ID, putTo(b, "invalid"), invalid, anyRejection)
	}
	// A self-send expects one stanza, but a password-only stanza still does
	// not satisfy the registered X25519 recipient contract.
	password, err := age.NewScryptRecipient("not an inbox key")
	if err != nil {
		t.Fatal(err)
	}
	password.SetWorkFactor(4)
	passwordOnly := encryptFor(t, plain, password)
	s.exec(t, s.alice, a.ID, sendTo(a), passwordOnly, anyRejection)
	s.exec(t, s.alice, a.ID, putTo(a, "password"), passwordOnly, anyRejection)
	// Even valid ciphertext must travel under the encrypted-only grammar;
	// flags cannot turn plaintext or base64 text into an encrypted envelope.
	for _, encoding := range []string{"plain", "age"} {
		cmd := sendTo(b) + " --encoding " + encoding
		s.exec(t, s.alice, a.ID, cmd, plain, anyRejection)
		s.exec(t, s.alice, a.ID, cmd, cipher, anyRejection)
	}
	wrong := " --recipient-key " + a.publicKey()
	s.exec(t, s.alice, a.ID, "put "+b.ID+wrong+" misdirected", cipher, anyRejection)
	s.exec(t, s.alice, a.ID, "send "+b.ID+wrong+" --attach "+stage, cipher, anyRejection)
	s.exec(t, s.alice, a.ID, "send "+b.ID, cipher, anyRejection)
	s.exec(t, s.alice, a.ID, "put file", cipher, anyRejection)
	s.exec(t, s.alice, a.ID, sendTo(b)+" --attach "+stage, plain, anyRejection)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatal("invalid send published a message")
	}
	requireSQLInt(t, openStoreDB(t, dir), "SELECT count(*) FROM pending", 1)
	s.send(t, s.alice, a, b, " --attach "+stage, nil)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 1 || *p.Messages[0].Body != "" || len(p.Messages[0].Attachments) != 1 || p.Messages[0].Attachments[0].ID != stage {
		t.Fatal("failed send consumed valid stage or partially published")
	}
}

func TestOneAgeRecipientForSelfDelivery(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	a := s.create(t, s.alice)
	file := s.put(t, s.alice, a, a, "empty file", nil)
	s.send(t, s.alice, a, a, " --attach "+file, []byte("private note"))
	p := s.poll(t, s.alice, a, "")
	if len(p.Messages) != 1 || string(decrypt(t, a, bodyCipher(t, p.Messages[0].Body))) != "private note" {
		t.Fatal("self-addressed message did not decrypt")
	}
	if got := decrypt(t, a, s.exec(t, s.alice, a.ID, "get "+file, nil, 0)); len(got) != 0 {
		t.Fatal("encrypted empty file has nonempty plaintext")
	}
}
