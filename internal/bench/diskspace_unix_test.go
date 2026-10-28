//go:build linux || darwin || freebsd || dragonfly

package bench

import "syscall"

// benchDiskSpace is the space check of ingest (internal/ingest,
// diskSpace, disk_unix.go): the bytes available to unprivileged users
// and the size of the file system holding path. OpenBSD names the
// fields differently (diskspace_openbsd_test.go); NetBSD has no
// syscall.Statfs (diskspace_other_test.go, as ingest).
func benchDiskSpace(path string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	// Bavail is signed on the BSDs and negative while the reserve of the
	// superuser is in use.
	avail := max(int64(s.Bavail), 0)
	return uint64(avail) * uint64(s.Bsize), uint64(s.Blocks) * uint64(s.Bsize), nil
}
