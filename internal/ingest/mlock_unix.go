//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ingest

import "syscall"

// mlock locks b against swapping (5.3).
func mlock(b []byte) error   { return syscall.Mlock(b) }
func munlock(b []byte) error { return syscall.Munlock(b) }
