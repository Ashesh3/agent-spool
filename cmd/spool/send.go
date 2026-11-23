package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
)

type receipt struct {
	MessageID string    `json:"message_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type envelope struct {
	To       string `json:"to"`
	From     string `json:"from"`
	Body     string `json:"body"`
	Encoding string `json:"encoding"`
	ReplyTo  string `json:"reply_to,omitempty"`
}

func (r *relay) publicKey(id string) (*age.X25519Recipient, error) {
	resp, err := r.request("GET", "/v1/inboxes/"+id+"/pubkey", "", nil, false)
	if err != nil {
		return nil, fmt.Errorf("fetching inbox public key: %w", err)
	}
	defer resp.Body.Close()
	var pub struct {
		Key string `json:"public_key"`
	}
	if err := decodeJSON(resp.Body, 64<<10, &pub); err != nil {
		return nil, err
	}
	key, err := age.ParseX25519Recipient(pub.Key)
	if err != nil {
		return nil, errors.New("relay supplied no valid age X25519 recipient key")
	}
	return key, nil
}

func (r *relay) send(o options, out io.Writer) error {
	id, host, valid := addressParts(o.address)
	_, ourHost, _ := addressParts(r.Address)
	if !valid || !strings.EqualFold(host, ourHost) {
		return usageError("recipient must be a complete address on this relay")
	}
	if len(o.files) > 16 {
		return usageError("at most 16 attachments are allowed per message")
	}
	if !utf8.ValidString(o.message) {
		return usageError("message must be UTF-8; send binary content with -f")
	}
	key, err := r.publicKey(id)
	if err != nil {
		return err
	}
	e := envelope{To: o.address, From: r.Address, Encoding: "age", ReplyTo: o.replyTo}
	if o.message != "" {
		cipher, err := age.EncryptReader(strings.NewReader(o.message), key)
		if err != nil {
			return err
		}
		var body strings.Builder
		b64 := base64.NewEncoder(base64.StdEncoding, &body)
		if _, err := io.Copy(b64, cipher); err != nil {
			return err
		}
		if err := b64.Close(); err != nil {
			return err
		}
		e.Body = body.String()
	}
	var sent receipt
	if len(o.files) == 0 {
		err = r.postJSON("/v1/messages", &e, true, &sent)
	} else {
		err = r.upload(e, key, o.files, &sent)
	}
	if err != nil {
		return err
	}
	if !decimal(sent.MessageID, false) || sent.ExpiresAt.IsZero() {
		return errors.New("relay returned an invalid message receipt")
	}
	if o.json {
		return json.NewEncoder(out).Encode(sent)
	}
	_, err = fmt.Fprintf(out, "Sent message %s to %s (expires %s)\n", sent.MessageID, o.address, sent.ExpiresAt.Format(time.RFC3339))
	return err
}

func (r *relay) upload(e envelope, key *age.X25519Recipient, paths []string, result *receipt) error {
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		if len(name) > 255 || !utf8.ValidString(name) || strings.ContainsAny(name, `/\`) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return errors.New("attachment has an invalid filename; rename it before sending")
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("each attachment must be a regular file")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		files = append(files, f)
	}
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	done := make(chan error, 1)
	go func() {
		err := writeUpload(mw, e, key, files)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	resp, err := r.request("POST", "/v1/messages", mw.FormDataContentType(), pr, true)
	// On an early HTTP rejection or a TLS/dial failure, release the pipe
	// producer before waiting for it and before closing its source files.
	_ = pr.Close()
	producerErr := <-done
	if resp != nil {
		defer resp.Body.Close()
	}
	if producerErr != nil && !errors.Is(producerErr, io.ErrClosedPipe) {
		return fmt.Errorf("encrypting upload: %w", producerErr)
	}
	if err != nil {
		return err
	}
	if producerErr != nil {
		return errors.New("relay replied before upload completed")
	}
	return decodeJSON(resp.Body, 64<<10, result)
}

func writeUpload(mw *multipart.Writer, e envelope, key *age.X25519Recipient, files []*os.File) error {
	for _, field := range [][2]string{{"to", e.To}, {"from", e.From}, {"encoding", e.Encoding}, {"body", e.Body}} {
		if err := mw.WriteField(field[0], field[1]); err != nil {
			return err
		}
	}
	if e.ReplyTo != "" {
		if err := mw.WriteField("reply_to", e.ReplyTo); err != nil {
			return err
		}
	}
	for _, f := range files {
		part, err := mw.CreateFormFile("files[]", filepath.Base(f.Name()))
		if err != nil {
			return err
		}
		cipher, err := age.EncryptReader(f, key)
		if err != nil {
			return err
		}
		if _, err := io.Copy(part, cipher); err != nil {
			return err
		}
	}
	return mw.Close()
}
