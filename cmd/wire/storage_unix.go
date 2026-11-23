//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func privateTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".wire-*") // 0600 from creation
}

func exclusiveLock(f *os.File) error {
	l := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 1}
	for {
		err := unix.FcntlFlock(f.Fd(), unix.F_SETLKW, &l)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func publish(temp, dest string, replace bool) error {
	var err error
	if replace {
		err = os.Rename(temp, dest)
	} else {
		// Unlike a stat followed by rename, link can never clobber dest.
		err = os.Link(temp, dest)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
