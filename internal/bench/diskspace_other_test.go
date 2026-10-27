//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package bench

import "errors"

// benchDiskSpace fails as ingest does where the free space is unknown.
func benchDiskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("bench: free space unknown on this platform")
}
