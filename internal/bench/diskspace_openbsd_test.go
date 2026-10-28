//go:build openbsd

package bench

import "syscall"

// benchDiskSpace is the space check of ingest on OpenBSD (internal/ingest,
// disk_openbsd.go): struct statfs names its fields with the prefix f_
// (task 20a point 9).
func benchDiskSpace(path string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	// F_bavail is negative while the reserve of the superuser is in use.
	avail := max(s.F_bavail, 0)
	return uint64(avail) * uint64(s.F_bsize), s.F_blocks * uint64(s.F_bsize), nil
}
