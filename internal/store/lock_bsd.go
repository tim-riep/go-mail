//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package store

import "syscall"

// The other Unix systems have process-associated record locks only; see
// lock_unix.go for how the program copes with their semantics.
const (
	cmdSetLk  = syscall.F_SETLK
	cmdSetLkW = syscall.F_SETLKW
	ofdLocks  = false
)
