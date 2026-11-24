package integration_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"spool/internal/relay"
)

// Locate an actual blob by its payload, independent of the staging/committed
// directory layout. Checking presence first prevents a vacuous cleanup test.
func requireDiskPayload(t *testing.T, dir string, payload []byte, want bool) {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil || info.Size() != int64(len(payload)) {
			return err
		}
		data, err := os.ReadFile(path)
		if bytes.Equal(data, payload) {
			found = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if found != want {
		t.Fatalf("%d-byte ciphertext blob present on disk = %t, want %t", len(payload), found, want)
	}
}

func TestRestartAndIndependentUploadAndDeliveryClocks(t *testing.T) {
	clock := newClock()
	epoch := clock.now()
	cfg := relay.Config{DataDir: t.TempDir(), Now: clock.now}
	k := keys(t)
	var a, b inbox
	var abandoned, live, blobID, msgID string
	var pending, delivered []byte
	if !t.Run("before restart", func(t *testing.T) {
		s := start(t, cfg, k)
		a, b = s.create(t, s.alice), s.create(t, s.bob)
		pending = seal(t, a, b, []byte("abandoned upload: one hour"))
		delivered = seal(t, a, b, []byte("delivered payload: seven days"))
		abandoned = s.putCipher(t, s.alice, a, b, "abandoned", pending)
		live = s.put(t, s.alice, a, b, "still staged", []byte("recoverable stage"))
		stage := s.putCipher(t, s.alice, a, b, "delivered", delivered)
		r := s.send(t, s.alice, a, b, " --attach "+stage, nil)
		if !r.Expires.Equal(epoch.Add(7 * 24 * time.Hour)) {
			t.Fatalf("wrong receipt expiry: %s", r.Expires)
		}
		p := s.poll(t, s.bob, b, "")
		if len(p.Messages) != 1 || len(p.Messages[0].Attachments) != 1 || p.Next != r.ID {
			t.Fatalf("missing delivered message: %+v", p)
		}
		blobID, msgID = p.Messages[0].Attachments[0].ID, r.ID
		requireDiskPayload(t, cfg.DataDir, pending, true)
		requireDiskPayload(t, cfg.DataDir, delivered, true)
	}) {
		t.FailNow()
	}

	s := start(t, cfg, k)
	s.requireList(t, s.alice, a)
	s.requireList(t, s.bob, b)
	clock.step(time.Hour - time.Second)
	r := s.send(t, s.alice, a, b, " --attach "+live, nil)
	if !r.Expires.Equal(clock.now().Add(7 * 24 * time.Hour)) {
		t.Fatal("retention did not start at send time")
	}
	s.exec(t, s.bob, b.ID, "delete "+r.ID, nil, 0)
	clock.step(time.Second)
	s.exec(t, s.alice, a.ID, sendTo(b)+" --attach "+abandoned, nil, 1)
	if err := s.app.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireDiskPayload(t, cfg.DataDir, pending, false)
	requireDiskPayload(t, cfg.DataDir, delivered, true)

	clock.step(7*24*time.Hour - time.Hour - time.Second)
	if data := s.exec(t, s.bob, b.ID, "get "+blobID, nil, 0); !bytes.Equal(data, delivered) {
		t.Fatal("live download did not survive restart and sweep")
	}
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 1 || p.Next != msgID {
		t.Fatalf("live message lost its cursor: %+v", p)
	}
	clock.step(time.Second)
	if p := s.poll(t, s.bob, b, ""); len(p.Messages) != 0 {
		t.Fatal("expired message visible before sweep")
	}
	s.exec(t, s.bob, b.ID, "get "+blobID, nil, 1)
	s.exec(t, s.alice, "spool", "recall "+msgID, nil, 1)
	if err := s.app.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireDiskPayload(t, cfg.DataDir, delivered, false)
	s.send(t, s.alice, a, b, "", []byte("inbox IDs outlive their mail"))
}
