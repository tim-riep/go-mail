//go:build linux

package store

// Linux uses open file description locks (fcntl(2)); golang.org/x/sys is
// not imported, so the commands are spelled out. They have the same values
// on every Linux architecture.
const (
	cmdSetLk  = 37 // F_OFD_SETLK
	cmdSetLkW = 38 // F_OFD_SETLKW
	ofdLocks  = true
)
