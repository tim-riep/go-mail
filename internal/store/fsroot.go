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

// ErrReplacedMeanwhile reports that a name the functions of this file
// wrote through a temporary file is not that file when they look at it
// again with Root.Lstat (backlog 108, review of task 33 A, H1): after
// the rename or link, name is missing, is not a regular file or is
// another file than the one written (os.SameFile against the fstat of
// the temporary file); or, on an error before, the temporary name is
// missing or is not the file written any more. Another process changed
// the directory meanwhile. Nothing that is not the file written is
// removed: such an entry stays where it is, and the error names it.
var ErrReplacedMeanwhile = errors.New("another process changed the directory meanwhile")

// tempInHook, if set, is called by the functions of this file that
// write through a temporary file, with the root, the temporary name and
// the point: "written" after the data are written and synced, before
// the close; "rename" or "link" before the rename or link to the name;
// "renamed" or "linked" after it, before the name is looked at again.
// Only tests set it (SetTempInHook, in a build with the tag gomail_test
// only, for the tests of gomail-ceremony publish): it stands for
// another process that changes the directory at that point.
var tempInHook func(root *os.Root, tmp, point string)

func callTempInHook(root *os.Root, tmp, point string) {
	if tempInHook != nil {
		tempInHook(root, tmp, point)
	}
}

// written is a temporary file that writeTempIn wrote: its name in the
// directory, the FileInfo of fstat on its descriptor right after the
// open, and held, a second descriptor of the same open file (a
// duplicate, holdFile; never an open of the name), kept until the
// caller is done. held keeps the inode in use after the close, so that
// its number is not given to another file meanwhile: ext4 gives the
// number of an inode freed by an unlink at once to the next file
// created, and a file of another process could then look like the file
// written to os.SameFile (review of task 34 A, M4). Where there is no
// duplicate (Windows, Plan 9, js and wasip1: holdFile), held is nil;
// on Windows a second handle opened without FILE_SHARE_DELETE would
// make the rename fail, and the comparison rests on the file ID of
// NTFS, which carries a sequence number.
type written struct {
	tmp  string
	fi   fs.FileInfo
	held *os.File
}

// release closes held.
func (w *written) release() {
	if w.held != nil {
		w.held.Close()
	}
}

// differs looks at name in the directory that root holds with
// Root.Lstat (never an open: a FIFO or a device under the name is not
// opened) and returns "" if it is the file written, a regular file that
// os.SameFile takes for it, and otherwise what it is instead: "missing",
// "not a regular file", "another file", or that it cannot be looked at,
// with the error of Root.Lstat.
func (w *written) differs(root *os.Root, name string) string {
	fi, err := root.Lstat(name)
	switch {
	case err != nil && errors.Is(err, fs.ErrNotExist):
		return "missing"
	case err != nil:
		return "not to be looked at (" + underlying(err).Error() + ")"
	case !fi.Mode().IsRegular():
		return "not a regular file"
	case !os.SameFile(fi, w.fi):
		return "another file"
	}
	return ""
}

// meanwhileErr is ErrReplacedMeanwhile for name of the directory that
// root holds, which is what instead of the file written (differs);
// step is the step after which it was looked at ("rename", "link"), or
// "" for the temporary name on an error, which stays as it is.
func meanwhileErr(root *os.Root, name, what, step string) error {
	p := filepath.Join(root.Name(), name)
	switch {
	case step != "" && what == "missing":
		return fmt.Errorf("store: after the %s, %s is missing: %w", step, p, ErrReplacedMeanwhile)
	case step != "":
		return fmt.Errorf("store: after the %s, %s is %s, not the file written: %w", step, p, what, ErrReplacedMeanwhile)
	case what == "missing":
		return fmt.Errorf("store: %s is missing: %w", p, ErrReplacedMeanwhile)
	}
	return fmt.Errorf("store: %s is %s, not the file written, and stays: %w", p, what, ErrReplacedMeanwhile)
}

// check returns nil if name is the file written after step (the rename
// or link to it), and ErrReplacedMeanwhile otherwise. The window left
// is between the rename or link and the Root.Lstat of the check:
// another process that changes name in it and puts the file written
// back before the Root.Lstat goes unseen, as does any change after the
// Root.Lstat; what a reader of name finds in that window is not this
// function's to tell.
func (w *written) check(root *os.Root, name, step string) error {
	if what := w.differs(root, name); what != "" {
		return meanwhileErr(root, name, what, step)
	}
	return nil
}

// removeTemp removes the temporary name on an error (cause) if it is
// still the file written (differs) and returns cause; the error of the
// removal is not reported, as before. If the name is anything else, or
// missing, nothing is removed: the entry belongs to another process and
// stays, and the error is cause and ErrReplacedMeanwhile (errors.Is
// holds for both). The window left is between the Root.Lstat of differs
// and the unlink of removeNameIn: an entry that another process puts
// under the temporary name in it is removed (unlink removes a name,
// whatever it is then; no system call removes a name only if it is a
// given inode), a directory never.
func (w *written) removeTemp(root *os.Root, cause error) error {
	if what := w.differs(root, w.tmp); what != "" {
		return fmt.Errorf("%w; %w", cause, meanwhileErr(root, w.tmp, what, ""))
	}
	removeNameIn(root, w.tmp)
	return cause
}

// writeTempIn writes data to a new temporary file with mode perm in the
// directory that root holds, syncs and closes it, and returns it
// (written; the caller releases it). On an error it removes the name
// again where that is possible (not in a directory with chattr +a, for
// example), and only if it is still the file it created
// (written.removeTemp): an entry that another process put under the
// name stays, and the error is ErrReplacedMeanwhile as well. If the
// fstat right after the open fails, the name cannot be compared and
// stays. The errors name the temporary file as writeTemp does ("open
// <dir>/.tmp-...: ...", pathErrIn).
func writeTempIn(root *os.Root, data []byte, perm fs.FileMode) (*written, error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return nil, err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, pathErrIn(root, tmp, err)
	}
	w := &written{tmp: tmp}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, pathErrIn(root, tmp, err)
	}
	w.fi = fi
	w.held, err = holdFile(f)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		callTempInHook(root, tmp, "written")
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		err = w.removeTemp(root, pathErrIn(root, tmp, err))
		w.release()
		return nil, err
	}
	return w, nil
}

// ReplaceFileIn is WriteFileAtomicIn without its last step: it writes
// data to a temporary file (mode FilePerm) in the directory that root
// holds, syncs it and renames it to name, but does not sync the
// directory. The caller does that with SyncDirIn. A caller that must act
// once name is replaced, whether or not the sync of the directory
// succeeds, uses it (gomail-ceremony publish reports a replaced
// witnesses.rec: backlog 83). The rename replaces a symbolic link
// itself, never its target; a directory under name is an error.
//
// After the rename, name is looked at again with Root.Lstat
// (written.check; backlog 108, review of task 33 A, H1): it must be a
// regular file that os.SameFile takes for the temporary file written
// (fstat on its descriptor, whose duplicate held keeps the inode).
// Otherwise the error is ErrReplacedMeanwhile: another process put
// something else under the temporary name before the rename (a
// directory, which renameat(2) puts over a missing name or an empty
// directory, a FIFO, a link, another file), or changed name after it.
// That entry is left under name; nothing is removed. There is no check
// before the rename: the one after it sees every such change up to its
// Root.Lstat (the window left is written.check's).
//
// When the temporary file or the rename fails, the temporary name is
// removed again where that is possible (not in a directory with
// chattr +a, for example: it stays there) and only if it is still the
// file written (written.removeTemp; ErrReplacedMeanwhile otherwise),
// and this function has not replaced name; it does not say that name
// is as it was before, since its error may come from another process
// that changed name or the temporary file meanwhile (a directory put
// under name, for example; backlog 118). A failing rename is "rename
// <dir>/.tmp-... <dir>/<name>: ...", an *os.LinkError, as for
// WriteFileAtomic; the errors of the temporary file name it as
// writeTempIn does, an *fs.PathError (or, for crypto/rand, no path).
// So an ErrReplacedMeanwhile carries an *os.LinkError when the rename
// failed, an *fs.PathError when the temporary file failed, and neither
// when the rename happened and name is not the file written
// (gomail-ceremony publish tells these apart).
func ReplaceFileIn(root *os.Root, name string, data []byte) error {
	w, err := writeTempIn(root, data, FilePerm)
	if err != nil {
		return err
	}
	defer w.release()
	callTempInHook(root, w.tmp, "rename")
	if err := root.Rename(w.tmp, name); err != nil {
		return w.removeTemp(root, pathErrIn(root, name, err))
	}
	callTempInHook(root, w.tmp, "renamed")
	return w.check(root, name, "rename")
}

// WriteFileAtomicIn is WriteFileAtomic for the file name in the
// directory that root holds (backlog 72): temporary file, fsync, rename
// and fsync of the directory all go through root, so the file lands in
// that directory even if its path names another directory by now, or a
// symbolic link. Its errors are those of ReplaceFileIn
// (ErrReplacedMeanwhile included) and of SyncDirIn; the directory is
// not synced after an error of ReplaceFileIn.
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
//
// After the link, name is looked at again as by ReplaceFileIn
// (written.check): a link of something else that another process put
// under the temporary name (link(2) links a FIFO, a socket or a
// symbolic link itself), or a change of name after the link, is
// ErrReplacedMeanwhile, and the entry stays under name. The temporary
// name is removed after the link, and on every error, only if it is
// still the file written (written.removeTemp); otherwise it stays and
// the error is ErrReplacedMeanwhile (errors.Is holds for ErrExists as
// well when the link found name present). An error of the removal
// after a link that succeeded and was checked is returned as before
// (ErrReplacedMeanwhile when the temporary name is gone by then): name
// is the file written then, but the directory is not synced. The
// window of written.removeTemp is on this path also after a link that
// succeeded: between the Root.Lstat of the temporary name and its
// unlink.
func CreateFileAtomicIn(root *os.Root, name string, data []byte) error {
	w, err := writeTempIn(root, data, FilePerm)
	if err != nil {
		return err
	}
	defer w.release()
	callTempInHook(root, w.tmp, "link")
	if err := root.Link(w.tmp, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			err = fmt.Errorf("%w: %s", ErrExists, filepath.Base(name))
		} else {
			err = pathErrIn(root, name, err)
		}
		return w.removeTemp(root, err)
	}
	callTempInHook(root, w.tmp, "linked")
	cerr := w.check(root, name, "link")
	if what := w.differs(root, w.tmp); what != "" {
		if cerr == nil {
			cerr = meanwhileErr(root, w.tmp, what, "")
		}
	} else if err := removeNameIn(root, w.tmp); err != nil && cerr == nil {
		cerr = err
		if errors.Is(err, fs.ErrNotExist) {
			// Gone between the Root.Lstat and the unlink: removed or
			// renamed by another process.
			cerr = meanwhileErr(root, w.tmp, "missing", "")
		}
	}
	if cerr != nil {
		return cerr
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
