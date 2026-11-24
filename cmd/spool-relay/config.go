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
