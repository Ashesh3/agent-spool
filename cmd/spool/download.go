package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
)

// Relay-supplied names must be safe as a single basename on all three OSes,
// even when downloaded on Unix and later copied to Windows. In particular,
// never accept NT device names (including extensions), streams or dotfiles.
func safeFilename(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || name[0] == '.' || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") || strings.ContainsAny(name, `<>:"/\|?*`) || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return false
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if suffix, found := strings.CutPrefix(stem, prefix); found && utf8.RuneCountInString(suffix) == 1 && strings.Contains("0123456789¹²³", suffix) {
			return false
		}
	}
	return true
}

func destination(output, disposition string) (string, error) {
	info, err := os.Stat(output)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	isDir := info != nil && info.IsDir() || os.IsPathSeparator(output[len(output)-1])
	if !isDir {
		if !safeFilename(filepath.Base(output)) {
			return "", usageError("choose a safe output filename")
		}
		return filepath.Clean(output), nil
	}
	kind, params, err := mime.ParseMediaType(disposition)
	if err != nil || kind != "attachment" || !safeFilename(params["filename"]) {
		return "", errors.New("missing or unsafe relay filename; use -o with an explicit safe filename")
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return "", err
	}
	return filepath.Join(output, params["filename"]), nil
}

func (r *relay) download(o options, out io.Writer) error {
	resp, err := r.request("GET", "/v1/inboxes/"+r.InboxID+"/attachments/"+o.attachment, "", nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var source io.Reader = resp.Body
	encodings := resp.Header.Values("X-Spool-Encoding")
	if len(encodings) != 1 {
		return errors.New("expected exactly one X-Spool-Encoding header")
	}
	switch encodings[0] {
	case "plain":
	case "age":
		source, err = age.Decrypt(resp.Body, r.identity)
		if err != nil {
			return errors.New("attachment decryption failed; no output published")
		}
	default:
		return errors.New("unknown X-Spool-Encoding; refusing ambiguous attachment")
	}
	path, err := destination(o.output, resp.Header.Get("Content-Disposition"))
	if err != nil {
		return err
	}
	var size int64
	err = atomicWrite(path, false, func(w io.Writer) error {
		var err error
		size, err = io.Copy(w, source)
		if err != nil {
			return errors.New("attachment read, authentication, or write failed; no output published")
		}
		return nil
	})
	if errors.Is(err, os.ErrExist) {
		return errors.New("destination already exists; choose another -o path")
	}
	if err != nil {
		return err
	}
	if o.json {
		return json.NewEncoder(out).Encode(struct {
			ID   string `json:"attachment_id"`
			Path string `json:"path"`
			Size int64  `json:"size"`
		}{o.attachment, path, size})
	}
	_, err = fmt.Fprintf(out, "Downloaded %s to %q (%d bytes)\n", o.attachment, path, size)
	return err
}
