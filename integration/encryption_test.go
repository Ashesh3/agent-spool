package integration_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"filippo.io/age"
	"spool/internal/relay"
)

func TestEncryptedSSHDelivery(t *testing.T) {
	s := start(t, relay.Config{}, keys(t))
	alice := s.create(t, s.alice, "")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bob := s.create(t, s.bob, id.Recipient().String())
	key := s.exec(t, s.alice, "spool", "pubkey "+bob.Address, nil, 0)
	recipient, err := age.ParseX25519Recipient(unpack[map[string]string](t, key)["public_key"])
	if err != nil {
		t.Fatal(err)
	}
	seal := func(data []byte) []byte {
		t.Helper()
		var b bytes.Buffer
		w, err := age.Encrypt(&b, recipient)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	text := []byte("**ready** — résumé")
	file := bytes.Repeat([]byte{0, 255, 9, 254}, 22000) // spans age stream chunks
	stage := s.put(t, s.alice, alice, "encrypted.bin", seal(file))
	msg := s.send(t, s.alice, alice, bob.ID+" --encoding age --attach "+stage, []byte(base64.StdEncoding.EncodeToString(seal(text))))
	p := s.poll(t, s.bob, bob, "--since 0")
	if len(p.Messages) != 1 || p.Next != msg.ID {
		t.Fatal("missing encrypted delivery")
	}
	m := p.Messages[0]
	if m.Encoding != "age" || m.From != alice.Address || len(m.Attachments) != 1 {
		t.Fatal("incorrect encrypted message metadata")
	}
	verify := func(cipher, want []byte) {
		t.Helper()
		r, err := age.Decrypt(bytes.NewReader(cipher), id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("decrypted payload differs (read error: %v)", err)
		}
	}
	cipher, err := base64.StdEncoding.DecodeString(m.Body)
	if err != nil {
		t.Fatal(err)
	}
	verify(cipher, text)
	blob := s.exec(t, s.bob, bob.ID, "get "+m.Attachments[0].ID, nil, 0)
	verify(blob, file)
}
