package main

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateTemp(dir string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	// Protected DACL, current user only. Set it at creation, before any
	// other process could obtain a handle or any secrets reach disk.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	path := filepath.Join(dir, ".dropwire-"+rand.Text())
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
	}
	// FAT/exFAT may accept CreateFile's security descriptor but discard it.
	var flags uint32
	err = windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0)
	if err != nil || flags&windows.FILE_PERSISTENT_ACLS == 0 {
		windows.CloseHandle(h)
		os.Remove(path)
		return nil, errors.New("private storage requires a filesystem with persistent Windows ACLs")
	}
	return os.NewFile(uintptr(h), path), nil
}

func exclusiveLock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

func publish(temp, dest string, replace bool) error {
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dest)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return &os.LinkError{Op: "publish", Old: temp, New: dest, Err: err}
	}
	return nil
}
