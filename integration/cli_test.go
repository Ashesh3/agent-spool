package integration_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"dropwire/internal/relay"
)

// Use the real CLI so that credential protection, cursor persistence, native
// path handling, certificate trust and age streams are covered on each OS.
func TestNativeClients(t *testing.T) {
	s := start(t, relay.Config{DataDir: t.TempDir()})
	dir := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	bin := filepath.Join(dir, "dropwire"+ext)
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"+ext), "build", "-o", bin, "./cmd/dropwire")
	build.Dir = ".."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build client: %v: %s", err, b)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	alice, bob := filepath.Join(dir, "a", "config.json"), filepath.Join(dir, "b", "config.json")
	cli := func(profile string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bin, append(args, "--json")...)
		key := gateA
		if profile == bob {
			key = gateB
		}
		cmd.Env = append(os.Environ(), "DROPWIRE_CONFIG="+profile, "DROPWIRE_CA_FILE="+ca, "RELAY_URL="+s.URL, "GATE_KEY="+key)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v: %s", args[0], err, &stderr)
		}
		if !json.Valid(b) {
			t.Fatalf("%s emitted invalid JSON", args[0])
		}
		return b
	}
	aliceAddress := unpack[inbox](t, cli(alice, "init")).Address
	bobAddress := unpack[inbox](t, cli(bob, "init")).Address
	if aliceAddress == "" || aliceAddress == bobAddress || unpack[inbox](t, cli(alice, "init")).Address != aliceAddress || unpack[inbox](t, cli(bob, "whoami")).Address != bobAddress {
		t.Fatal("persistent identities not preserved")
	}
	file := filepath.Join(dir, "binary.dat")
	data := bytes.Repeat([]byte{255, 0, 9, 254}, 22000) // crosses an age STREAM chunk boundary
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	const text = "**ready** — résumé"
	id := unpack[map[string]string](t, cli(alice, "send", bobAddress, "-m", text, "-f", file))["message_id"]
	p := unpack[page](t, cli(bob, "poll"))
	if len(p.Messages) != 1 || p.Next != id {
		t.Fatal("missing encrypted delivery")
	}
	m := p.Messages[0]
	if m.Body != text || m.Encoding != "age" || m.From != aliceAddress || len(m.Attachments) != 1 {
		t.Fatal("wrong decrypted message")
	}
	if len(unpack[page](t, cli(bob, "poll")).Messages) != 0 {
		t.Fatal("normal poll replayed delivered mail")
	}
	if len(unpack[page](t, cli(bob, "poll", "--since", "0")).Messages) != 1 || len(unpack[page](t, cli(bob, "poll")).Messages) != 0 {
		t.Fatal("explicit replay disturbed saved cursor")
	}
	path := filepath.Join(dir, "received.bin")
	cli(bob, "download", m.Attachments[0].ID, "-o", path)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decrypted file differs (read error: %v)", err)
	}
}
