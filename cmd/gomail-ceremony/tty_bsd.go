//go:build (darwin || freebsd || netbsd || openbsd || dragonfly) && !ceremony_notty

package main

import "syscall"

// Requests that read and write the terminal attributes (termios).
// ioctlSetTermiosFlush (TIOCSETAF) discards the input received and not
// read yet, then sets the attributes.
const (
	ioctlGetTermios      = syscall.TIOCGETA
	ioctlSetTermios      = syscall.TIOCSETA
	ioctlSetTermiosFlush = syscall.TIOCSETAF
)
