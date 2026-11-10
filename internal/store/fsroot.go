package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// The functions of this file work on a directory held by an os.Root
// instead of a path (backlog 72: gomail-ceremony publish opens
// platform/ of the data directory once and does everything after that
// relative to it). A name is a name in that directory, never a path
// with separators. os.Root follows a symbolic link inside the directory
// and refuses one that leaves it; the callers that must not follow a
// link look at the name with Root.Lstat first and compare it with what
// they opened (os.SameFile), as they do for a path.
//
// The errors are those of the functions on a path (OpenRegular,
// ReadDir, WriteFileAtomic, CreateFileAtomic, SyncDir): os.Root names
// only the name in the directory and its own operation ("openat
// ingest-1.cert", "renameat .tmp-... witnesses.rec"), and a file opened
// through a root opened as "<dir>/." is named "<dir>/./<name>". pathErrIn
// gives every fs.PathError and os.LinkError the path
// filepath.Join(root.Name(), name) and the operation of the os function
// on a path (open, rename, link), as removeNameIn does (review of task
// 26 package B, N2).

// pathOps maps an operation of os.Root to that of the os function on a
// path.
var pathOps = map[string]string{"openat": "open", "renameat": "rename", "linkat": "link"}

// underlying is the error inside an fs.PathError, an os.LinkError or an
// os.SyscallError, for an error that removeNameIn reports with its own
// path; any other error is returned as it is.
func underlying(err error) error {
	var pe *fs.PathError
	var le *os.LinkError
	var se *os.SyscallError
	switch {
	case errors.As(err, &pe):
		return pe.Err
	case errors.As(err, &le):
		return le.Err
	case errors.As(err, &se):
		return se.Err
	}
	return err
}

// pathErrIn is err of an os.Root call for name in the directory root
// holds, or of a file opened through it, with the path of name and the
// operation of the os function on a path: an fs.PathError gets the path
// filepath.Join(root.Name(), name), an os.LinkError the paths of its
// two names, which os.Root reports relative to the directory. Any other
// error is returned as it is.
func pathErrIn(root *os.Root, name string, err error) error {
	var le *os.LinkError
	if errors.As(err, &le) {
		if op, ok := pathOps[le.Op]; ok {
			le.Op = op
		}
		le.Old, le.New = filepath.Join(root.Name(), le.Old), filepath.Join(root.Name(), le.New)
		return err
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		if op, ok := pathOps[pe.Op]; ok {
			pe.Op = op
		}
		pe.Path = filepath.Join(root.Name(), name)
	}
	return err
}

// OpenRegularIn is OpenRegular for the file name in the directory that
// root holds: opened with O_NONBLOCK (and O_NOCTTY on Unix), checked
// with fstat after the open; a FIFO, a device or a directory is
// ErrNotRegular, a missing name ErrNotFound. The messages name the file
// as OpenRegular does ("open <dir>/<name>: ...", pathErrIn).
func OpenRegularIn(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|openNoCTTY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s", ErrNotFound, filepath.Base(name))
		}
		return nil, nil, pathErrIn(root, name, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, pathErrIn(root, name, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("store: %s is %w", filepath.Base(name), ErrNotRegular)
	}
	return f, fi, nil
}

// ReadDirIn is ReadDir for the directory that root holds: its entries
// sorted by name, wherever its path is now. File.ReadDir of a directory
// opened through an os.Root looks at every entry with fstatat(2)
// relative to that descriptor (AT_SYMLINK_NOFOLLOW; os.Root on Unix),
// never by a path, also on a file system that reports no type in the
// listing (DT_UNKNOWN): the type of an entry is that in the directory
// root holds. An entry gone between the listing and its fstatat is left
// out, as by os.ReadDir. The errors name the directory as ReadDir does
// (root.Name() without a trailing "/.", pathErrIn), not the name
// "<dir>/./." of the descriptor.
func ReadDirIn(root *os.Root) ([]fs.DirEntry, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, pathErrIn(root, ".", err)
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	if err != nil {
		err = pathErrIn(root, ".", err)
	}
	return entries, err
}

// writeTempIn writes data to a new temporary file with mode perm in the
// directory that root holds, syncs and closes it, and returns its name;
// on an error it removes the name again. The errors name the temporary
// file as writeTemp does ("open <dir>/.tmp-...: ...", pathErrIn).
func writeTempIn(root *os.Root, data []byte, perm fs.FileMode) (string, error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return "", err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", pathErrIn(root, tmp, err)
	}
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		removeNameIn(root, tmp)
		return "", pathErrIn(root, tmp, err)
	}
	return tmp, nil
}

// ReplaceFileIn is WriteFileAtomicIn without its last step: it writes
// data to a temporary file (mode FilePerm) in the directory that root
// holds, syncs it and renames it to name, but does not sync the
// directory. The caller does that with SyncDirIn. A caller that must act
// once name is replaced, whether or not the sync of the directory
// succeeds, uses it (gomail-ceremony publish reports a replaced
// witnesses.rec: backlog 83). The rename replaces a symbolic link
// itself, never its target; a directory under name is an error. When
// the rename fails, the temporary file is removed again, and name is
// unchanged. A failing rename is "rename <dir>/.tmp-... <dir>/<name>:
// ...", as for WriteFileAtomic.
func ReplaceFileIn(root *os.Root, name string, data []byte) error {
	tmp, err := writeTempIn(root, data, FilePerm)
	if err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		removeNameIn(root, tmp)
		return pathErrIn(root, name, err)
	}
	return nil
}

// WriteFileAtomicIn is WriteFileAtomic for the file name in the
// directory that root holds (backlog 72): temporary file, fsync, rename
// and fsync of the directory all go through root, so the file lands in
// that directory even if its path names another directory by now, or a
// symbolic link.
func WriteFileAtomicIn(root *os.Root, name string, data []byte) error {
	if err := ReplaceFileIn(root, name, data); err != nil {
		return err
	}
	return SyncDirIn(root)
}

// CreateFileAtomicIn is CreateFileAtomic for the file name in the
// directory that root holds (backlog 72): it creates name with data and
// mode FilePerm only if the name is free (ErrExists otherwise, also for
// a symbolic link, a dangling one as well); temporary file, hard link
// to name and fsync of the directory all go through root. A failing
// link is "link <dir>/.tmp-... <dir>/<name>: ...", as for
// CreateFileAtomic.
func CreateFileAtomicIn(root *os.Root, name string, data []byte) error {
	tmp, err := writeTempIn(root, data, FilePerm)
	if err != nil {
		return err
	}
	defer removeNameIn(root, tmp)
	if err := root.Link(tmp, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, filepath.Base(name))
		}
		return pathErrIn(root, name, err)
	}
	if err := removeNameIn(root, tmp); err != nil {
		return err
	}
	return SyncDirIn(root)
}

// SyncDirIn is SyncRoot with the messages of SyncDir: it fsyncs the
// directory that root holds, wherever its path is now, and an error
// names the directory as root.Name() without a trailing "/." ("open
// <dir>: ...", "sync <dir>: ...", pathErrIn), not as "<dir>/./.", the
// name of the descriptor of a root opened as "<dir>/.". SyncRoot is
// unchanged for its other callers.
func SyncDirIn(root *os.Root) error {
	return pathErrIn(root, ".", SyncRoot(root))
}

// RemoveTempReportIn is RemoveTempReport for the directory that root
// holds (backlog 72): listing, unlink and fsync go through root, so
// nothing is removed in another directory that its path names by now,
// or through a symbolic link in its place. The rules are those of
// RemoveTempReport: a temporary file is an entry that is a regular file
// when the directory is listed and whose name starts with ".tmp-"; its
// name is removed with unlink (removeNameIn), never with rmdir, so that
// a directory put under the name meanwhile stays and is an error; a name
// that is gone meanwhile is skipped and not reported.
func RemoveTempReportIn(root *os.Root, removed func(name string)) error {
	entries, err := ReadDirIn(root)
	if err != nil {
		return err
	}
	gone := false
	for _, e := range entries {
		if len(e.Name()) > len(tmpPrefix) && e.Name()[:len(tmpPrefix)] == tmpPrefix && e.Type().IsRegular() {
			if err := removeNameIn(root, e.Name()); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return err
			}
			gone = true
			if removed != nil {
				removed(e.Name())
			}
		}
	}
	if gone {
		return SyncDirIn(root)
	}
	return nil
}

// errNameInRoot reports a name for removeNameIn that is no single name
// in the directory.
var errNameInRoot = errors.New("not a name in the directory")

// checkNameIn refuses a name that is not a single entry of the
// directory: empty, ".", ".." or with a separator.
func checkNameIn(root *os.Root, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, filepath.Separator) {
		return &fs.PathError{Op: "unlink", Path: filepath.Join(root.Name(), name), Err: errNameInRoot}
	}
	return nil
}
