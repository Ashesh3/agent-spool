package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

type attachment struct {
	ID       string `json:"attachment_id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type message struct {
	MessageID       string       `json:"message_id"`
	From            string       `json:"from"`
	To              string       `json:"to"`
	Body            *string      `json:"body"`
	Encoding        string       `json:"encoding"`
	ReplyTo         string       `json:"reply_to,omitempty"`
	CreatedAt       string       `json:"created_at"`
	ExpiresAt       string       `json:"expires_at"`
	Attachments     []attachment `json:"attachments"`
	DecryptionError string       `json:"decryption_error,omitempty"`
}

func (m *message) decrypt(id *age.X25519Identity) {
	m.DecryptionError = ""
	if m.Encoding == "plain" && m.Body != nil {
		return
	}
	if m.Encoding == "age" && m.Body != nil {
		if *m.Body == "" && len(m.Attachments) != 0 {
			return // File-only message; attachments each have their own ciphertext.
		}
		cipher := base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(*m.Body))
		if plaintext, err := age.Decrypt(cipher, id); err == nil {
			var text strings.Builder
			if _, err := io.Copy(&text, plaintext); err == nil && utf8.ValidString(text.String()) {
				v := text.String()
				m.Body = &v
				return
			}
		}
	}
	m.Body = nil
	m.DecryptionError = "invalid encoding, ciphertext, or recipient; body unavailable"
}

func (r *relay) poll(path string, o options, out io.Writer) error {
	since := o.since
	if since == "" {
		since = r.Cursor
	}
	resp, err := r.request("GET", "/v1/inboxes/"+r.InboxID+"/messages?since="+since+"&limit="+strconv.Itoa(o.limit), "", nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msgs, next, err := readPage(resp.Body, since, o.limit, r.profile)
	if err != nil {
		return err
	}
	if err := printPage(out, o.json, msgs, next); err != nil {
		return err
	}
	// Explicit --since is a replay/inspection, not a destructive seek.
	if o.since == "" && next != r.Cursor {
		r.Cursor = next
		if err := saveProfile(path, r.profile, true); err != nil {
			return fmt.Errorf("mail printed but cursor could not be saved: %w", err)
		}
	}
	return nil
}

// Decode each message separately so a legitimate page of JSON-escaped bodies
// does not also require buffering the full raw response. Validate the complete
// page before writing anything or moving the saved cursor.
func readPage(body io.Reader, since string, limit int, p *profile) ([]message, string, error) {
	bounded := &io.LimitedReader{R: body, N: int64(limit)*(7<<20) + 64<<10}
	d := json.NewDecoder(bounded)
	invalid := errors.New("invalid, incomplete, or out-of-order poll response; cursor unchanged")
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, "", invalid
	}
	var msgs []message
	var next string
	last := since
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, "", invalid
		}
		switch t {
		case "messages":
			if t, err := d.Token(); err != nil || t != json.Delim('[') || msgs != nil {
				return nil, "", invalid
			}
			msgs = make([]message, 0, limit)
			for d.More() {
				var m message
				if len(msgs) == limit || d.Decode(&m) != nil || !decimal(m.MessageID, false) || m.To != p.Address || !(len(m.MessageID) > len(last) || len(m.MessageID) == len(last) && m.MessageID > last) {
					return nil, "", invalid
				}
				m.decrypt(p.identity)
				last = m.MessageID
				msgs = append(msgs, m)
			}
			if t, err := d.Token(); err != nil || t != json.Delim(']') {
				return nil, "", invalid
			}
		case "next_cursor":
			if next != "" || d.Decode(&next) != nil || !decimal(next, true) {
				return nil, "", invalid
			}
		default:
			if err := d.Decode(new(json.RawMessage)); err != nil {
				return nil, "", invalid
			}
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') || msgs == nil || next != last || d.Decode(new(json.RawMessage)) != io.EOF || bounded.N == 0 {
		return nil, "", invalid
	}
	return msgs, next, nil
}

func printPage(out io.Writer, asJSON bool, msgs []message, next string) error {
	if asJSON {
		if _, err := io.WriteString(out, `{"messages":[`); err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		for i := range msgs {
			if i > 0 {
				if _, err := io.WriteString(out, ","); err != nil {
					return err
				}
			}
			if err := enc.Encode(&msgs[i]); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(out, "],\"next_cursor\":%q}\n", next)
		return err
	}
	for _, m := range msgs {
		if _, err := fmt.Fprintf(out, "Message %s from %q at %q\n", m.MessageID, m.From, m.CreatedAt); err != nil {
			return err
		}
		if m.ReplyTo != "" {
			if _, err := fmt.Fprintf(out, "  Reply to: %q\n", m.ReplyTo); err != nil {
				return err
			}
		}
		if m.DecryptionError != "" {
			if _, err := fmt.Fprintln(out, "  Decryption error:", m.DecryptionError); err != nil {
				return err
			}
		} else if m.Body != nil && *m.Body != "" {
			if _, err := fmt.Fprintf(out, "  Body: %q\n", *m.Body); err != nil {
				return err
			}
		}
		for _, a := range m.Attachments {
			if _, err := fmt.Fprintf(out, "  Attachment %q: %q (%d bytes stored)\n", a.ID, a.Filename, a.Size); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(out, "%d message(s); next cursor %s\n", len(msgs), next)
	return err
}
