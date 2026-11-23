package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// The relay holds the data directory lease before calling loadHostKey. A
// missing operator-supplied key is an error, never a reason to rotate trust.
func loadHostKey(dir, configured string) (ssh.Signer, error) {
	path := configured
	if path == "" {
		path = filepath.Join(dir, "ssh_host_ed25519_key")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if configured != "" || !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "spool relay")
	if err != nil {
		return nil, err
	}
	// O_EXCL also prevents overwriting a dangling symlink or a key installed
	// by an administrator during startup. Never replace an unreadable key.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(f, block)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, errors.Join(err, os.Remove(path))
	}
	return ssh.NewSignerFromKey(key)
}
