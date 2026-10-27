//go:build linux && !ceremony_notty

package main

import "syscall"

// Requests that read and write the terminal attributes (termios).
// ioctlSetTermiosFlush is TCSETSF: it discards the input received and
// not read yet, then sets the attributes. The syscall package does not
// define it; on every Linux architecture it is TCSETS + 2
// (asm-generic/ioctls.h 0x5402/0x5404, mips 0x540e/0x5410, powerpc and
// sparc _IOW numbers 20/22 and 9/11).
const (
	ioctlGetTermios      = syscall.TCGETS
	ioctlSetTermios      = syscall.TCSETS
	ioctlSetTermiosFlush = syscall.TCSETS + 2
)
