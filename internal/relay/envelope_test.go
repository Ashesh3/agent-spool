package relay

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func envelopeTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func envelopeTestEncrypt(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	r, err := age.EncryptReader(bytes.NewReader(plaintext), recipients...)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func TestCopyAgeEnvelope(t *testing.T) {
	ids := []*age.X25519Identity{envelopeTestIdentity(t), envelopeTestIdentity(t)}
	keys := []age.Recipient{ids[0].Recipient(), ids[1].Recipient()}
	for _, tc := range []struct{ size, count int }{{0, 1}, {1, 2}, {65536, 1}, {65537, 2}, {2 * 65536, 2}} {
		t.Run(fmt.Sprintf("%d-bytes-%d-recipients", tc.size, tc.count), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte{0xff}, tc.size)
			ciphertext := envelopeTestEncrypt(t, plaintext, keys[:tc.count]...)
			var dst bytes.Buffer
			src := iotest.HalfReader(bytes.NewReader(ciphertext))
			n, err := copyAgeEnvelope(&dst, src, int64(len(ciphertext)), tc.count)
			if err != nil || n != int64(len(ciphertext)) || !bytes.Equal(dst.Bytes(), ciphertext) {
				t.Fatalf("copy did not preserve %d bytes: n=%d, err=%v", len(ciphertext), n, err)
			}
			for _, id := range ids[:tc.count] {
				r, err := age.Decrypt(bytes.NewReader(dst.Bytes()), id)
				if err != nil {
					t.Fatal(err)
				}
				out, err := io.ReadAll(r)
				if err != nil || !bytes.Equal(out, plaintext) {
					t.Fatalf("authenticated decryption returned %d bytes, err=%v", len(out), err)
				}
			}
		})
	}
	for _, src := range []io.Reader{nil, bytes.NewReader(nil)} {
		var dst bytes.Buffer
		if n, err := copyAgeEnvelope(&dst, src, 0, 1); n != 0 || err != nil || dst.Len() != 0 {
			t.Fatalf("empty input: n=%d, err=%v", n, err)
		}
	}
}

func TestCopyAgeEnvelopeRejectsInvalidHeader(t *testing.T) {
	key := envelopeTestIdentity(t).Recipient()
	ciphertext := envelopeTestEncrypt(t, make([]byte, 256), key)
	password, err := age.NewScryptRecipient("test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	password.SetWorkFactor(1)
	var armored bytes.Buffer
	w := armor.NewWriter(&armored)
	if _, err := w.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Each mutation is made on a fresh copy of a genuine canonical header;
	// always include payload so we exercise the header check, not just EOF.
	lines := bytes.SplitN(ciphertext, []byte("\n"), 5)
	replaceLine := func(i int, value []byte) []byte {
		copyLines := append([][]byte(nil), lines...)
		copyLines[i] = value
		return bytes.Join(copyLines, []byte("\n"))
	}
	for _, tc := range []struct {
		name  string
		input []byte
		count int
	}{
		{"plaintext", bytes.Repeat([]byte("private message"), 64), 1},
		{"base64", []byte(base64.StdEncoding.EncodeToString(ciphertext)), 1},
		{"armor", armored.Bytes(), 1},
		{"magic-only", []byte("age-encryption.org/v1\n"), 1},
		{"wrong-version", replaceLine(0, []byte("age-encryption.org/v2")), 1},
		{"one-not-two", ciphertext, 2},
		{"two-not-one", envelopeTestEncrypt(t, nil, key, envelopeTestIdentity(t).Recipient()), 1},
		{"password-only", envelopeTestEncrypt(t, nil, password), 1},
		{"other-stanza", replaceLine(1, bytes.Replace(lines[1], []byte("X25519"), []byte("custom"), 1)), 1},
		{"extra-arg", replaceLine(1, []byte("-> X25519 "+strings.Repeat("A", 41)+" A")), 1},
		{"short-arg", replaceLine(1, []byte("-> X25519 AA")), 1},
		{"bad-arg-bits", replaceLine(1, []byte("-> X25519 "+strings.Repeat("A", 42)+"B")), 1},
		{"short-wrapped-key", replaceLine(2, []byte("AA")), 1},
		{"malformed-wrapped-key", replaceLine(2, bytes.Repeat([]byte{'!'}, 43)), 1},
		{"short-mac", replaceLine(3, []byte("--- AA")), 1},
		{"invalid-recipient-count", ciphertext, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dst bytes.Buffer
			n, err := copyAgeEnvelope(&dst, bytes.NewReader(tc.input), int64(len(tc.input)), tc.count)
			if !errors.Is(err, errInvalidEnvelope) || n != 0 || dst.Len() != 0 {
				t.Fatalf("wanted sanitized request error before writing, got n=%d, err=%v", n, err)
			}
		})
	}
}

func TestCopyAgeEnvelopeRejectsImpossiblePayloadLengths(t *testing.T) {
	ciphertext := envelopeTestEncrypt(t, make([]byte, 2*65536), envelopeTestIdentity(t).Recipient())
	header, err := age.ExtractHeader(bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	// The 16-byte nonce is followed by full 65552-byte ciphertext chunks,
	// except for the final chunk, which still requires an entire 16-byte tag.
	for _, size := range []int{0, 15, 16, 31, 16 + 65552 + 1, 16 + 65552 + 15, 16 + 65552 + 16} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			truncated := ciphertext[:len(header)+size]
			_, err := copyAgeEnvelope(io.Discard, bytes.NewReader(truncated), int64(len(truncated)), 1)
			if !errors.Is(err, errInvalidEnvelope) {
				t.Fatalf("accepted impossible %d-byte payload: %v", size, err)
			}
		})
	}
}

func TestCopyAgeEnvelopeLimit(t *testing.T) {
	ciphertext := envelopeTestEncrypt(t, make([]byte, 1<<17), envelopeTestIdentity(t).Recipient())
	for _, limit := range []int{0, 1, 100, 256, len(ciphertext) - 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			r := bytes.NewReader(ciphertext)
			var dst bytes.Buffer
			n, err := copyAgeEnvelope(&dst, r, int64(limit), 1)
			if !errors.Is(err, errEnvelopeLimit) || n > int64(limit) || dst.Len() > limit || len(ciphertext)-r.Len() != limit+1 {
				t.Fatalf("limit %d: read=%d, wrote=%d, n=%d, err=%v", limit, len(ciphertext)-r.Len(), dst.Len(), n, err)
			}
		})
	}
	// Reject even an arbitrarily long malformed header without draining its line.
	r := bytes.NewReader(make([]byte, 1<<20))
	_, err := copyAgeEnvelope(io.Discard, r, r.Size(), 2)
	if !errors.Is(err, errInvalidEnvelope) || r.Size()-int64(r.Len()) > 512 {
		t.Fatalf("malformed header: consumed %d, err=%v", r.Size()-int64(r.Len()), err)
	}
}

func TestCopyAgeEnvelopeReadError(t *testing.T) {
	ciphertext := envelopeTestEncrypt(t, []byte("test"), envelopeTestIdentity(t).Recipient())
	header, err := age.ExtractHeader(bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	broken := errors.New("broken transport")
	for _, size := range []int{0, len(header) - 1, len(header), len(ciphertext)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			src := iotest.DataErrReader(io.MultiReader(bytes.NewReader(ciphertext[:size]), iotest.ErrReader(broken)))
			_, err := copyAgeEnvelope(io.Discard, src, int64(size), 1)
			if !errors.Is(err, broken) {
				t.Fatalf("lost terminal read error at %d: %v", size, err)
			}
		})
	}
}
