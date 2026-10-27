//go:build netbsd

package main

import (
	"syscall"
	"unsafe"
)

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1): TIOCPTSNAME (struct ptmget, as ptsname reads it)
// is answered only by the master. The buffer is larger than struct
// ptmget on every architecture; the kernel copies out the size encoded
// in the request.
func isPtyMaster(fd uintptr) bool {
	var ptm [4096]byte
	return ioctl(fd, syscall.TIOCPTSNAME, unsafe.Pointer(&ptm[0])) == nil
}
