package sshserver

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ParseAuthorizedKeys accepts plain OpenSSH public keys, not an sshd policy
// file. Never silently skip a malformed line or discard a key restriction.
func ParseAuthorizedKeys(data []byte) (map[string]bool, error) {
	allowed := make(map[string]bool)
	lineNo := 0
	for line := range bytes.Lines(data) {
		lineNo++
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// ParseAuthorizedKey would otherwise ignore everything after a CR.
		if bytes.IndexAny(line, "\r\x00") >= 0 {
			return nil, fmt.Errorf("authorized_keys line %d: invalid character", lineNo)
		}
		key, _, options, _, err := ssh.ParseAuthorizedKey(line)
		i := bytes.IndexAny(line, " \t")
		if err != nil || len(options) != 0 || i < 0 || string(line[:i]) != key.Type() {
			return nil, fmt.Errorf("authorized_keys line %d: expected a plain public key without options", lineNo)
		}
		if _, cert := key.(*ssh.Certificate); cert {
			return nil, fmt.Errorf("authorized_keys line %d: certificates are not supported", lineNo)
		}
		allowed[ssh.FingerprintSHA256(key)] = true
	}
	if len(allowed) == 0 {
		return nil, errors.New("authorized_keys contains no public keys")
	}
	return allowed, nil
}
