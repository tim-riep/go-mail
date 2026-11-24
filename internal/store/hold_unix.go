//go:build unix

package store

import (
	"io/fs"
	"os"
	"syscall"
)

// holdFile returns a duplicate of the descriptor of f (dup(2), marked
// close-on-exec under syscall.ForkLock, as os/exec expects of a
// descriptor made without O_CLOEXEC), for written.held: the same open
// file, so that its inode stays in use after f is closed. The name of f
// is never opened again: a FIFO, a device, a socket or a link that
// another process puts under it meanwhile is neither opened nor
// followed, and nothing is removed because such an open failed. Every
// error is an *fs.PathError ("dup <name>: ..."), an error of the
// temporary file for the callers (EMFILE, for example).
func holdFile(f *os.File) (*os.File, error) {
	dupErr := func(err error) error { return &fs.PathError{Op: "dup", Path: f.Name(), Err: underlying(err)} }
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, dupErr(err)
	}
	nfd, derr := -1, error(nil)
	if err := rc.Control(func(fd uintptr) {
		syscall.ForkLock.RLock()
		nfd, derr = syscall.Dup(int(fd))
		if derr == nil {
			syscall.CloseOnExec(nfd)
		}
		syscall.ForkLock.RUnlock()
	}); err != nil {
		return nil, dupErr(err)
	}
	if derr != nil {
		return nil, dupErr(derr)
	}
	return os.NewFile(uintptr(nfd), f.Name()), nil
}
