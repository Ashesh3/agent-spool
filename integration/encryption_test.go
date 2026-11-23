package integration_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"filippo.io/age"
	"spool/internal/relay"
)

func TestEncryptedAPIDelivery(t *testing.T) {
	s := start(t, relay.Config{DataDir: t.TempDir()})
	alice := s.mint(t, gateA, "{}")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bob := s.mint(t, gateB, fmt.Sprintf(`{"public_key":%q}`, id.Recipient().String()))
	key, _ := s.call(t, "GET", bob.path("pubkey"), gateA, "", "", nil, 200)
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
	msgID := upload(t, s, alice, bob, base64.StdEncoding.EncodeToString(seal(text)), "age", seal(file))
	body, _ := s.call(t, "GET", bob.path("messages?since=0"), gateB, bob.Secret, "", nil, 200)
	p := unpack[page](t, body)
	if len(p.Messages) != 1 || p.Next != msgID {
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
	blob, header := s.call(t, "GET", bob.path("attachments/"+m.Attachments[0].ID), gateB, bob.Secret, "", nil, 200)
	if header.Get("X-Spool-Encoding") != "age" {
		t.Fatal("download did not identify encrypted attachment")
	}
	verify(blob, file)
}
