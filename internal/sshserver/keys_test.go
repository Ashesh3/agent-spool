package sshserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAllowlistRejectsRestrictionsInsteadOfGrantingUnrestrictedAccess(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " agent@workstation\r\n"
	allowed, err := ParseAuthorizedKeys([]byte("# approved keys\r\n" + line))
	if err != nil || !allowed[ssh.FingerprintSHA256(key)] {
		t.Fatalf("plain approved key was not loaded: %v", err)
	}
	// OpenSSH can restrict a key to a specific command. Spool does not
	// implement that policy: never accept just the key and ignore its options.
	if keys, err := ParseAuthorizedKeys([]byte(line + `command="restricted-command" ` + line)); err == nil || len(keys) != 0 {
		t.Fatal("invalid allowlist was partially accepted or its restriction was dropped")
	}
}
