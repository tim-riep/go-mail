//go:build linux || darwin || freebsd || dragonfly

package ingest

import "syscall"

// diskSpace returns the bytes available to unprivileged users and the
// size of the file system holding path.
func diskSpace(path string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	// Bavail is signed on the BSDs and negative while the reserve of the
	// superuser is in use: nothing is free for the server then.
	avail := max(int64(s.Bavail), 0)
	return uint64(avail) * uint64(s.Bsize), uint64(s.Blocks) * uint64(s.Bsize), nil
}
