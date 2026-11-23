package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"
)

type profile struct {
	Relay       string `json:"relay"`
	Gate        string `json:"gate_key"`
	Address     string `json:"address"`
	InboxID     string `json:"inbox_id"`
	InboxSecret string `json:"inbox_secret"`
	PrivateKey  string `json:"private_key"`
	Cursor      string `json:"cursor"`

	identity *age.X25519Identity
}

func profilePath() (string, error) {
	if path := os.Getenv("DROPWIRE_CONFIG"); path != "" {
		return filepath.Abs(path)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dropwire", "config.json"), nil
}

func origin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.TrimSuffix(u.EscapedPath(), "/") != "" || u.ForceQuery || u.RawQuery != "" || strings.Contains(s, "#") {
		return "", errors.New("relay must be an HTTPS origin without credentials, a path, query, or fragment")
	}
	return "https://" + strings.ToLower(strings.TrimSuffix(u.Host, ":443")), nil
}

func safeID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 255 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~", c)) {
			return false
		}
	}
	return true
}

func addressParts(s string) (string, string, bool) {
	id, domain, found := strings.Cut(s, "@")
	if !found || !safeID(id) || domain == "" || len(domain) > 255 {
		return "", "", false
	}
	for _, c := range domain {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:[]", c)) {
			return "", "", false
		}
	}
	return id, domain, true
}

func headerToken(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, c := range s {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func lockProfile(path string, create bool) (*os.File, error) {
	dir := filepath.Dir(path)
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("profile not found; run dropwire init first")
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("profile directory must not be writable by group or others; choose a private directory with DROPWIRE_CONFIG")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := exclusiveLock(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("locking profile: %w", err)
	}
	return lock, nil
}

func readProfile(path string) (*profile, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || (runtime.GOOS != "windows" && entry.Mode().Perm()&0077 != 0) {
		return nil, errors.New("profile must be a private regular file (mode 0600 on Unix), not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, entry) || info.Size() > 64<<10 {
		return nil, errors.New("invalid or changed profile")
	}
	var p profile
	if err := decodeJSON(f, 64<<10, &p); err != nil {
		return nil, errors.New("invalid profile JSON")
	}
	p.identity, err = age.ParseX25519Identity(p.PrivateKey)
	relay, relayErr := origin(p.Relay)
	id, _, valid := addressParts(p.Address)
	if err != nil || relayErr != nil || id != p.InboxID || !valid || !headerToken(p.Gate) || !headerToken(p.InboxSecret) || !decimal(p.Cursor, true) {
		return nil, errors.New("invalid credentials or cursor in local profile")
	}
	p.Relay = relay
	return &p, nil
}

// Stage in the destination directory. Nothing becomes visible at the chosen
// name until write, authentication (for downloads), fsync and close succeed.
func atomicWrite(path string, replace bool, write func(io.Writer) error) error {
	f, err := privateTemp(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = write(f); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return publish(f.Name(), path, replace)
}

func saveProfile(path string, p *profile, replace bool) error {
	return atomicWrite(path, replace, func(w io.Writer) error { return json.NewEncoder(w).Encode(p) })
}

func provision(path string, p *profile, o options) (*profile, error) {
	var relayURL string
	var err error
	if o.relay != "" {
		if relayURL, err = origin(o.relay); err != nil {
			return nil, err
		}
	}
	if p != nil {
		if relayURL != "" && relayURL != p.Relay {
			return nil, errors.New("profile already belongs to another relay; select a new DROPWIRE_CONFIG")
		}
		if o.gate != "" && o.gate != p.Gate {
			if !headerToken(o.gate) {
				return nil, usageError("invalid replacement gate key")
			}
			p.Gate = o.gate
			r, err := newRelay(p)
			if err != nil {
				return nil, err
			}
			key, err := r.publicKey(p.InboxID)
			if err != nil {
				return nil, err
			}
			if key.String() != p.identity.Recipient().String() {
				return nil, errors.New("published inbox key does not match this profile; saved credentials unchanged")
			}
			if err := saveProfile(path, p, true); err != nil {
				return nil, fmt.Errorf("saving rotated gate key: %w", err)
			}
		}
		return p, nil
	}
	if relayURL == "" || !headerToken(o.gate) {
		return nil, usageError("init requires --relay and --gate-key, or RELAY_URL and GATE_KEY")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	p = &profile{Relay: relayURL, Gate: o.gate, PrivateKey: identity.String(), identity: identity, Cursor: "0"}
	r, err := newRelay(p)
	if err != nil {
		return nil, err
	}
	payload := map[string]string{"public_key": identity.Recipient().String()}
	if o.label != "" {
		payload["label"] = o.label
	}
	var minted struct {
		Address string `json:"address"`
		ID      string `json:"inbox_id"`
		Secret  string `json:"inbox_secret"`
	}
	if err := r.postJSON("/v1/inboxes", payload, false, &minted); err != nil {
		return nil, err
	}
	id, _, valid := addressParts(minted.Address)
	if !valid || id != minted.ID || !headerToken(minted.Secret) {
		return nil, errors.New("relay returned invalid inbox credentials")
	}
	p.Address, p.InboxID, p.InboxSecret = minted.Address, minted.ID, minted.Secret
	if err := saveProfile(path, p, false); err != nil {
		return nil, fmt.Errorf("saving new inbox credentials: %w", err)
	}
	return p, nil
}
