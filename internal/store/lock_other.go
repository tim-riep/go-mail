//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package store

import "errors"

var errNoLocks = errors.New("store: file locks are not supported on this platform")

// lockPath is not available on this platform; the PoC runs on Unix.
func lockPath(path string, exclusive, wait bool) (func(), error) { return nil, errNoLocks }

func lockFile(path string) (func(), error)    { return nil, errNoLocks }
func tryLockFile(path string) (func(), error) { return nil, errNoLocks }
func probeLock(path string) error             { return errNoLocks }

// LockPath is not available on this platform; the PoC runs on Unix.
func LockPath(path string) (func(), error) { return nil, errNoLocks }
