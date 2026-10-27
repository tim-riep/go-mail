//go:build !(linux || darwin)

package ingest

import "errors"

// mlock is not in package syscall on this platform (the BSDs among
// others): the ephemeral key cannot be locked against swapping, so the
// queue never spills to work/ (queue.go, 5.3; fail closed). Task 15c
// finding 5: package syscall of Go 1.26 has Mlock only on Linux and
// darwin, not on FreeBSD (only the number SYS_MLOCK); a raw system call
// through it is not built here (strictest reading: no unchecked
// pointer passing for a platform without a test run), and
// golang.org/x/sys must not be imported.
func mlock([]byte) error   { return errors.New("mlock not supported") }
func munlock([]byte) error { return nil }
