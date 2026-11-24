package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Treat filenames as metadata, never disk paths. Apply the same basename
// rules on every host, including Windows device names and alternate streams.
func safeName(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || strings.ContainsAny(name, `<>:"/\|?*`) ||
		strings.IndexFunc(name, unicode.IsControl) != -1 || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.TrimRight(stem, " ")
	if strings.EqualFold(stem, "CON") || strings.EqualFold(stem, "PRN") ||
		strings.EqualFold(stem, "AUX") || strings.EqualFold(stem, "NUL") ||
		strings.EqualFold(stem, "CONIN$") || strings.EqualFold(stem, "CONOUT$") {
		return false
	}
	if len(stem) > 3 && (strings.EqualFold(stem[:3], "COM") || strings.EqualFold(stem[:3], "LPT")) {
		switch stem[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}

func (r *Relay) Put(ctx context.Context, owner string, id InboxKey, name string, src io.Reader) (Attachment, error) {
	if _, err := ownedHandle(ctx, r.db, owner, id); err != nil {
		return Attachment{}, err
	}
	if !safeName(name) {
		return Attachment{}, RequestError("expected a safe attachment basename of at most 255 UTF-8 bytes")
	}
	if src == nil {
		return Attachment{}, errors.New("no attachment input reader")
	}
	m, err := r.acquireWriter(ctx, owner)
	if err != nil {
		return Attachment{}, err
	}
	defer m.releaseWriter()
	available, err := r.available(ctx, r.db, owner, r.cfg.Now().UnixNano())
	if err != nil {
		return Attachment{}, err
	}
	a := Attachment{ID: "a_" + rand.Text(), Filename: name}
	temp := filepath.Join(r.staging, a.ID)
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Attachment{}, err
	}
	defer func() {
		if err := os.Remove(temp); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("spool relay: removing incomplete upload: %v", err)
		}
	}()
	// Bound even uncommitted disk usage without trusting an input length or
	// holding any SQLite connection or global lock while waiting for stdin.
	limit := min(r.cfg.MaxFileBytes, r.cfg.MaxMessageBytes, available)
	a.Size, err = io.Copy(f, io.LimitReader(src, limit))
	if err == nil && a.Size == limit {
		var one [1]byte
		if n, probeErr := io.ReadFull(src, one[:]); n != 0 {
			if limit == available {
				err = quotaExceeded
			} else {
				err = RequestError("attachment exceeds byte limit")
			}
		} else if !errors.Is(probeErr, io.EOF) {
			err = probeErr
		}
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return Attachment{}, err
	}
	if closeErr != nil {
		return Attachment{}, closeErr
	}
	if err := r.registerUpload(ctx, owner, id, a, temp); err != nil {
		return Attachment{}, err
	}
	return a, nil
}

func (r *Relay) registerUpload(ctx context.Context, owner string, inbox InboxKey, a Attachment, temp string) error {
	r.files.Lock()
	defer r.files.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := ownedHandle(ctx, tx, owner, inbox); err != nil {
		return err
	}
	now := r.cfg.Now()
	available, err := r.available(ctx, tx, owner, now.UnixNano())
	if err != nil {
		return err
	}
	if a.Size > available {
		return quotaExceeded
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO pending(id,inbox,filename,size,expires)
		SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM garbage WHERE id=? UNION ALL SELECT 1 FROM attachments WHERE id=?)`,
		a.ID, inbox, a.Filename, a.Size, now.Add(pendingTTL).UnixNano(), a.ID, a.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("attachment ID collision")
	}
	dest := filepath.Join(r.blobs, a.ID)
	if _, err := os.Lstat(dest); err == nil {
		return errors.New("attachment path collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temp, dest); err != nil {
		return err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Cancellation or a failed sync must not leave uncharged bytes until
		// restart. If the commit outcome is ambiguous, check before unlinking.
		tx.Rollback()
		var live bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM pending WHERE id=?)", a.ID).Scan(&live)
		if err == nil && !live {
			err = os.Remove(dest)
		}
		if err != nil {
			log.Printf("spool relay: cleaning uncommitted upload: %v", err)
		}
	}()
	// Order the directory entry before the SQLite commit. Windows does not
	// support fsync of directory handles. An uncommitted promoted file is
	// unreachable and is reclaimed under the directory lease at startup.
	if runtime.GOOS != "windows" {
		d, err := os.Open(r.blobs)
		if err != nil {
			return err
		}
		err = d.Sync()
		closeErr := d.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	err = tx.Commit()
	committed = err == nil
	return err
}
