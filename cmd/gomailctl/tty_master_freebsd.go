//go:build freebsd

package main

import (
	"syscall"
	"unsafe"
)

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1): TIOCGPTN (the number of the pseudo terminal) is
// answered only by the master (ptsdev_ioctl); the slave, a terminal
// device of devfs, does not know it. FIODGNAME is not used: devfs
// answers it for every device, the slave included.
func isPtyMaster(fd uintptr) bool {
	var n uint32
	return ioctl(fd, syscall.TIOCGPTN, unsafe.Pointer(&n)) == nil
}
