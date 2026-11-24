package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostIdentityIsStableAndNeverReplacedOnError(t *testing.T) {
	dir := t.TempDir()
	first, err := loadHostKey(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	next, err := loadHostKey(dir, "")
	if err != nil || ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(next.PublicKey()) {
		t.Fatalf("host identity changed between startups: %v", err)
	}
	path := filepath.Join(dir, "ssh_host_ed25519_key")
	const damaged = "not a private key"
	if err := os.WriteFile(path, []byte(damaged), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostKey(dir, ""); err == nil {
		t.Fatal("startup replaced a damaged host identity")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != damaged {
		t.Fatalf("damaged host key was overwritten: %v", err)
	}
	if _, err := loadHostKey(dir, filepath.Join(dir, "missing-operator-key")); err == nil {
		t.Fatal("missing operator-provisioned key was silently generated")
	}
}
