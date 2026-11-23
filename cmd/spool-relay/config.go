package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"spool/internal/relay"
	"spool/internal/sshserver"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Old mailbox secrets cannot identify an SSH owner. Only the administrator's
// explicit, allowlisted mapping can transfer ownership of an existing inbox.
func legacyOwners(path string, allowed map[string]bool) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	owners := make(map[string]string)
	for n, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 || !dnsLabel.MatchString(f[0]) || !allowed[f[1]] || owners[f[0]] != "" {
			return nil, fmt.Errorf("invalid ownership mapping on line %d: expected a unique inbox ID and an allowlisted SHA256 fingerprint", n+1)
		}
		owners[f[0]] = f[1]
	}
	return owners, nil
}

type settings struct {
	relay.Config
	listen, hostKeyFile string
	allowed             map[string]bool
}

func loadSettings() (settings, error) {
	var s settings
	s.Host = strings.ToLower(os.Getenv("RELAY_HOST"))
	if len(s.Host) > 253 {
		return s, errors.New("RELAY_HOST is too long")
	}
	for part := range strings.SplitSeq(s.Host, ".") {
		if !dnsLabel.MatchString(part) {
			return s, errors.New("RELAY_HOST must be a hostname, without scheme, port or path")
		}
	}
	keyFile := os.Getenv("AUTHORIZED_KEYS_FILE")
	if keyFile == "" {
		keyFile = "ssh-config/authorized_keys"
	}
	keys, err := os.ReadFile(keyFile)
	if err != nil {
		return s, fmt.Errorf("read authorized keys: %w", err)
	}
	s.allowed, err = sshserver.ParseAuthorizedKeys(keys)
	if err != nil {
		return s, fmt.Errorf("authorized keys: %w", err)
	}
	if path := os.Getenv("LEGACY_OWNERS_FILE"); path != "" {
		s.LegacyOwners, err = legacyOwners(path, s.allowed)
		if err != nil {
			return s, fmt.Errorf("legacy owners: %w", err)
		}
	}
	s.hostKeyFile = os.Getenv("SSH_HOST_KEY_FILE")
	s.listen, s.DataDir = os.Getenv("LISTEN_ADDR"), os.Getenv("DATA_DIR")
	if s.listen == "" {
		s.listen = "127.0.0.1:2222"
	}
	if s.DataDir == "" {
		s.DataDir = "./data"
	}
	for name, target := range map[string]*int64{"MAX_FILE_BYTES": &s.MaxFileBytes, "MAX_MESSAGE_BYTES": &s.MaxMessageBytes, "QUOTA_BYTES": &s.QuotaBytes} {
		if raw, ok := os.LookupEnv(name); ok {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n <= 0 || n > 1<<50 {
				return s, fmt.Errorf("%s must be a positive byte count no larger than 2^50", name)
			}
			*target = n
		}
	}
	if raw, ok := os.LookupEnv("REQUESTS_PER_MINUTE"); ok {
		s.RequestsPerMinute, err = strconv.Atoi(raw)
		if err != nil || s.RequestsPerMinute < 1 {
			return s, errors.New("REQUESTS_PER_MINUTE must be a positive integer")
		}
	}
	return s, nil
}
