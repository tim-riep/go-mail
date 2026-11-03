//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package store

import (
	"os"
	"syscall"
)

// openDir is OpenDir: O_DIRECTORY makes the open refuse anything but a
// directory (ENOTDIR).
func openDir(dir string) (*os.File, error) {
	return os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
}
