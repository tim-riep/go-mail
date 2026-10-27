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

// flushPending discards the input that the terminal fd received and has
// not processed yet (tcflush(fd, TCIFLUSH): TCFLSH empties the buffers
// between the driver and the line discipline as well; TCSETSF empties
// only the line discipline's). Linux hands input on to the line
// discipline in the background: a share typed just before an abort and
// not processed yet when the echo comes back would be echoed then, on
// the screen just cleared (task 15b, found by TestPTYSignalSalvo).
func flushPending(fd uintptr) error {
	for {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlFlush, syscall.TCIFLUSH)
		switch e {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		}
		return e
	}
}
