//go:build !linux && !aix

package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// errIsDirIn reports a directory under a name that removeNameIn must
// remove with unlink.
var errIsDirIn = errors.New("is a directory")

// removeNameIn is removeName for the name in the directory that root
// holds, where syscall has no Unlinkat (every system but Linux and AIX,
// removenamein_unlinkat.go; the module does not import golang.org/x/sys).
// Without unlinkat relative to the descriptor an empty directory cannot
// be kept for certain: the name is looked at first (Root.Lstat) and a
// directory is refused, then os.Root.Remove removes the name. It tries
// unlinkat without AT_REMOVEDIR first and falls back to rmdir on an
// error, so the window left is between the Root.Lstat and that
// fallback: a directory that another process puts under the name in it
// is removed if it is empty, as by os.Remove; a full one stays, with the
// error of rmdir. Outside that window an empty directory stays and is an
// error, as on Linux. Nothing outside the directory root holds is
// reached: os.Root.Remove removes a symbolic link itself. The PoC runs
// on Linux. Every error names the path as removeName does ("unlink
// <dir>/<name>: ...").
func removeNameIn(root *os.Root, name string) error {
	if err := checkNameIn(root, name); err != nil {
		return err
	}
	p := filepath.Join(root.Name(), name)
	fi, err := root.Lstat(name)
	if err != nil {
		return &fs.PathError{Op: "unlink", Path: p, Err: underlying(err)}
	}
	if fi.IsDir() {
		return &fs.PathError{Op: "unlink", Path: p, Err: errIsDirIn}
	}
	if err := root.Remove(name); err != nil {
		return &fs.PathError{Op: "unlink", Path: p, Err: underlying(err)}
	}
	return nil
}
