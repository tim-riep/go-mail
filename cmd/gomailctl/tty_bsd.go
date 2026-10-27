//go:build darwin || freebsd || netbsd || openbsd || dragonfly

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

// isControllingDevice is the check of Linux (tty_linux.go) that the side
// of sameControlling that is not /dev/tty is the controlling terminal by
// its device number. These systems publish that number to a program only
// through sysctl or /proc layouts of their own, which syscall does not
// read; the check is left out, and sameControlling relies on the pseudo
// terminal masters being no terminal (isPtyMaster) and on TIOCGPGRP.
func isControllingDevice(uint64) bool { return true }
