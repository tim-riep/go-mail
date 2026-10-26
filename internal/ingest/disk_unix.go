//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ingest

import "syscall"

// diskSpace returns the bytes available to unprivileged users and the
// size of the file system holding path.
func diskSpace(path string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	return uint64(s.Bavail) * uint64(s.Bsize), uint64(s.Blocks) * uint64(s.Bsize), nil
}
