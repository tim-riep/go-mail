//go:build dragonfly

package main

import "syscall"

// isPtyMaster reports whether fd is the master side of a pseudo terminal
// (task 13d finding 1): TIOCISPTMASTER succeeds only on the master of a
// Unix 98 pseudo terminal (/dev/ptmx, as posix_openpt opens it).
// TODO(ask): the masters of the old BSD pseudo terminals (/dev/ptyXX)
// do not answer it; they are not recognized.
func isPtyMaster(fd uintptr) bool {
	return ioctl(fd, syscall.TIOCISPTMASTER, nil) == nil
}
