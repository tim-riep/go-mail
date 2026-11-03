//go:build !unix

package store

// openNoCTTY is O_NOCTTY on Unix (noctty_unix.go); elsewhere an open
// does not assign a controlling terminal, and the flag is not used.
const openNoCTTY = 0
