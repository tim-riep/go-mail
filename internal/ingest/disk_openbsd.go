//go:build openbsd

package ingest

import "syscall"

// diskSpace returns the bytes available to unprivileged users and the
// size of the file system holding path (OpenBSD names the fields of
// struct statfs with the prefix f_).
func diskSpace(path string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	// F_bavail is negative while the reserve of the superuser is in use.
	avail := max(s.F_bavail, 0)
	return uint64(avail) * uint64(s.F_bsize), s.F_blocks * uint64(s.F_bsize), nil
}
