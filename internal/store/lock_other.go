//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package store

import "errors"

// lockFile is not available on this platform; the PoC runs on Unix.
func lockFile(path string) (func(), error) {
	return nil, errors.New("store: file locks are not supported on this platform")
}

func tryLockFile(path string) (func(), error) { return lockFile(path) }
