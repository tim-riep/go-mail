//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ceremony

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkKeyDirInfo reports ErrKeyDir unless fi (from Lstat or Fstat) is a
// directory, not a symbolic link, with mode 0700 and owned by the user
// running the ceremony.
func checkKeyDirInfo(fi fs.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrKeyDir, filepath.Base(fi.Name()))
	}
	if fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0o700 {
		return fmt.Errorf("%w: %s has mode %04o, not 0700", ErrKeyDir, filepath.Base(fi.Name()), fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: %s does not belong to this user", ErrKeyDir, filepath.Base(fi.Name()))
	}
	return nil
}

// openKeyDir opens keyDir as an os.Root. The last element of keyDir
// must not be a symbolic link (O_DIRECTORY|O_NOFOLLOW), and the
// directory must pass checkKeyDirInfo. The root is checked to be the
// directory opened without following links, so that a directory swapped
// for a link after the checks of the ceremony is refused (ErrKeyDir).
func openKeyDir(keyDir string) (*os.Root, error) {
	var fd int
	var err error
	for {
		fd, err = syscall.Open(keyDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EMLINK) {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrKeyDir, filepath.Base(keyDir))
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: keyDir, Err: err}
	}
	f := os.NewFile(uintptr(fd), keyDir)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkKeyDirInfo(fi); err != nil {
		return nil, err
	}
	if err := hook("keydir"); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(keyDir)
	if err != nil {
		return nil, err
	}
	ri, err := r.Stat(".")
	if err != nil || !os.SameFile(fi, ri) {
		r.Close()
		return nil, fmt.Errorf("%w: %s was replaced", ErrKeyDir, filepath.Base(keyDir))
	}
	return r, nil
}
