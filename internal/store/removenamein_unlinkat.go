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
	d, err := root.Open(".")
	if err != nil {
		return unlinkErrIn(root, name, err)
	}
	defer d.Close()
	return removeNameInDir(root, d, name)
}

// openDirIn opens the directory that root holds for removeNameInDir, so
// that a caller can open it before it looks at a name it is to remove
// (written.dropTemp): the open is then not in the window between that
// look and the unlink.
func openDirIn(root *os.Root) (*os.File, error) { return root.Open(".") }

// removeNameInDir is removeNameIn with d, a descriptor of the directory
// that root holds which the caller opened before (openDirIn) and
// closes; with d nil it is removeNameIn.
func removeNameInDir(root *os.Root, d *os.File, name string) error {
	if d == nil {
		return removeNameIn(root, name)
	}
	if err := checkNameIn(root, name); err != nil {
		return err
	}
	rc, err := d.SyscallConn()
	if err != nil {
		return unlinkErrIn(root, name, err)
	}
	var uerr error
	if err := rc.Control(func(fd uintptr) { uerr = syscall.Unlinkat(int(fd), name) }); err != nil {
		return unlinkErrIn(root, name, err)
	}
	if uerr != nil {
		return unlinkErrIn(root, name, uerr)
	}
	return nil
}

// unlinkErrIn is err of removeNameIn for name, with the path as
// removeName names it.
func unlinkErrIn(root *os.Root, name string, err error) error {
	return &fs.PathError{Op: "unlink", Path: filepath.Join(root.Name(), name), Err: underlying(err)}
}
