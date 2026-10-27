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

// isControllingFd is the check of Linux (tty_linux.go) that a descriptor
// of /dev/tty names the controlling terminal of the program by the
// device number of the terminal behind it. TIOCGDEV is Linux only; here
// sameControlling relies on TIOCGPGRP, which these systems answer on a
// terminal only for the session it controls.
func isControllingFd(uintptr) bool { return true }

// isDevTTYNumber is false: the device number of /dev/tty is not fixed
// on these systems, isDevTTY reads it from the file system.
func isDevTTYNumber(uint64) bool { return false }
