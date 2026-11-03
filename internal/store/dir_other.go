//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package store

import (
	"io/fs"
	"os"
	"syscall"
)

// openDir is OpenDir where syscall has no O_DIRECTORY: the type is
// checked after the open (the PoC runs on Unix).
func openDir(dir string) (*os.File, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := d.Stat(); err != nil || !fi.IsDir() {
		d.Close()
		if err == nil {
			err = &fs.PathError{Op: "open", Path: dir, Err: syscall.ENOTDIR}
		}
		return nil, err
	}
	return d, nil
}
