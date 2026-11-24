package relay

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"

	"filippo.io/age"
)

var (
	errEnvelopeLimit   = errors.New("age ciphertext exceeds size limit")
	errInspectedHeader = errors.New("age header inspected without a file key")
)

const errInvalidEnvelope = RequestError("expected a binary age v1 envelope with the required X25519 recipients")

// Each native stanza contains a 32-byte ephemeral public key and a 32-byte
// wrapped file key. Both, like the footer MAC, occupy 43 raw base64 characters.
const (
	ageFieldChars = 43
	ageStanzaSize = len("-> X25519 \n\n") + 2*ageFieldChars
	ageFixedSize  = len("age-encryption.org/v1\n--- \n") + ageFieldChars
	ageNonceSize  = 16
	ageTagSize    = 16
	ageChunkSize  = 64*1024 + ageTagSize // ciphertext, including its tag
)

// age validates the stanza framing, body encoding, and footer MAC encoding and
// length. Stop before decryption: the relay has no identity or file key.
type stanzaInspector int

func (count stanzaInspector) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != int(count) {
		return nil, errInvalidEnvelope
	}
	var ephemeral [32]byte
	for _, s := range stanzas {
		if s.Type != "X25519" || len(s.Args) != 1 || len(s.Args[0]) != ageFieldChars || len(s.Body) != 32 {
			return nil, errInvalidEnvelope
		}
		n, err := base64.RawStdEncoding.Strict().Decode(ephemeral[:], []byte(s.Args[0]))
		if err != nil || n != len(ephemeral) {
			return nil, errInvalidEnvelope
		}
	}
	return nil, errInspectedHeader
}

// Read at most one byte past the budget to distinguish exact fits from excess.
// Remember terminal errors: ReadFull can otherwise drop an error returned with
// the last header byte, and the transport need not return that error again.
type envelopeInput struct {
	r         io.Reader
	remaining int64
	err       error
}

func (in *envelopeInput) Read(p []byte) (int, error) {
	if in.err != nil {
		return 0, in.err
	}
	if int64(len(p)) > in.remaining {
		p = p[:in.remaining+1]
	}
	n, err := in.r.Read(p)
	if int64(n) > in.remaining {
		n, err = int(in.remaining), errEnvelopeLimit
	}
	in.remaining -= int64(n)
	in.err = err
	return n, err
}

// copyAgeEnvelope admits only structurally valid binary age ciphertext. The
// caller must discard dst on error; only a recipient can authenticate the MAC,
// payload tags, or actual key binding. Empty input is distinct from a complete
// encrypted empty file, and is permitted here for attachment-only sends.
func copyAgeEnvelope(dst io.Writer, src io.Reader, limit int64, recipientCount int) (int64, error) {
	if src == nil {
		return 0, nil
	}
	if recipientCount != 1 && recipientCount != 2 {
		return 0, errInvalidEnvelope
	}
	in := &envelopeInput{r: src, remaining: max(0, limit)}
	// The canonical stanza shape makes the header length exact. Give the age
	// parser only this private prefix, so it cannot read ahead into the stream
	// or make the relay buffer attacker-controlled header lengths.
	header := make([]byte, ageFixedSize+recipientCount*ageStanzaSize)
	n, err := io.ReadFull(in, header)
	if in.err != nil && in.err != io.EOF {
		return 0, in.err
	}
	if err == io.EOF && n == 0 {
		return 0, nil
	}
	if err != nil {
		return 0, errInvalidEnvelope
	}
	if _, err := age.DecryptHeader(header, stanzaInspector(recipientCount)); !errors.Is(err, errInspectedHeader) {
		// Parser errors can quote untrusted input, including mistaken plaintext.
		return 0, errInvalidEnvelope
	}

	written, err := bytes.NewReader(header).WriteTo(dst)
	if err != nil {
		return written, err
	}
	payload, err := io.Copy(dst, in)
	written += payload
	if err != nil {
		return written, err
	}
	chunks := payload - ageNonceSize
	tail := chunks % ageChunkSize
	// A full final chunk is valid. A tag-only final chunk is valid only as
	// the single chunk of an encrypted empty file.
	if chunks < ageTagSize || (tail != 0 && tail <= ageTagSize && chunks != ageTagSize) {
		return written, errInvalidEnvelope
	}
	return written, nil
}
