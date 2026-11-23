package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"spool/internal/relay"
)

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	member   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

func parseMembers(raw string) (map[string]string, error) {
	keys := make(map[string]string)
	seen := make(map[string]bool)
	for entry := range strings.SplitSeq(raw, ",") {
		label, token, ok := strings.Cut(strings.TrimSpace(entry), ":")
		value, prefix := strings.CutPrefix(token, "gk_")
		_, err := hex.DecodeString(value)
		if !ok || !member.MatchString(label) || !prefix || (len(value) != 32 && len(value) != 64) || err != nil {
			return nil, errors.New("ALLOWED_GATE_KEYS requires label:gk_<32 or 64 hex digits> entries")
		}
		if _, exists := keys[label]; exists || seen[token] {
			return nil, errors.New("ALLOWED_GATE_KEYS contains a duplicate label or token")
		}
		keys[label], seen[token] = token, true
	}
	return keys, nil
}

type settings struct {
	relay.Config
	listen, cert, key string
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
	var err error
	s.GateKeys, err = parseMembers(os.Getenv("ALLOWED_GATE_KEYS"))
	if err != nil {
		return s, err
	}
	s.cert, s.key = os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if s.cert == "" || s.key == "" {
		return s, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required; plaintext serving is disabled")
	}
	s.listen, s.DataDir = os.Getenv("LISTEN_ADDR"), os.Getenv("DATA_DIR")
	if s.listen == "" {
		s.listen = "127.0.0.1:8443"
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
