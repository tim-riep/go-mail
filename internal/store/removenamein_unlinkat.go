//go:build linux || aix

package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// removeNameIn is removeName for the name in the directory that root
// holds: unlinkat(2) relative to a descriptor of that directory, without
// AT_REMOVEDIR, so a file or a symbolic link itself is removed, never a
// directory (os.Root.Remove falls back to rmdir and would remove an
// empty one). syscall has Unlinkat (flags 0) on Linux and AIX only; the
// other systems use removenamein_other.go. Every error names the path
// as removeName does ("unlink <dir>/<name>: ..."), also one of the open
// of the descriptor.
func removeNameIn(root *os.Root, name string) error {
	if err := checkNameIn(root, name); err != nil {
		return err
	}
	unlinkErr := func(err error) error {
		return &fs.PathError{Op: "unlink", Path: filepath.Join(root.Name(), name), Err: underlying(err)}
	}
	d, err := root.Open(".")
	if err != nil {
		return unlinkErr(err)
	}
	defer d.Close()
	rc, err := d.SyscallConn()
	if err != nil {
		return unlinkErr(err)
	}
	var uerr error
	if err := rc.Control(func(fd uintptr) { uerr = syscall.Unlinkat(int(fd), name) }); err != nil {
		return unlinkErr(err)
	}
	if uerr != nil {
		return unlinkErr(uerr)
	}
	return nil
}
