//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package ingest

import "errors"

func diskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("ingest: free space unknown on this platform")
}
