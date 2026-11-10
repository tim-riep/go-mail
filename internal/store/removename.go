//go:build unix || windows

package store

import (
	"io/fs"
	"syscall"
)

// removeName removes the name path with unlink (DeleteFile on Windows):
// a file, or a symbolic link itself, never a directory (review of task 25
// A, H2: os.Remove falls back to rmdir and removes an empty directory).
func removeName(path string) error {
	if err := syscall.Unlink(path); err != nil {
		return &fs.PathError{Op: "unlink", Path: path, Err: err}
	}
	return nil
}
