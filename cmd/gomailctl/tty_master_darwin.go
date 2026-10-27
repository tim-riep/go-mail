//go:build darwin

package main

import (
	"syscall"
	"unsafe"
)

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1): TIOCPTYGNAME (the name of the slave, 128 bytes,
// as ptsname reads it) is answered only by the master.
func isPtyMaster(fd uintptr) bool {
	var name [128]byte
	return ioctl(fd, syscall.TIOCPTYGNAME, unsafe.Pointer(&name[0])) == nil
}
