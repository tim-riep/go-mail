//go:build !(linux || darwin || freebsd || openbsd || dragonfly)

package bench

import "errors"

// benchDiskSpace fails as ingest does where the free space is unknown
// (NetBSD, whose syscall package has no Statfs, Windows; internal/ingest,
// disk_other.go).
func benchDiskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("bench: free space unknown on this platform")
}
