package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

var (
	// ErrExists reports that an exclusive create found the target present.
	ErrExists = errors.New("store: file exists")
	// ErrNotFound reports a missing file or directory.
	ErrNotFound = errors.New("store: not found")
	// ErrTooLarge reports a file above the size limit of its kind.
	ErrTooLarge = errors.New("store: file too large")
	// ErrLocked reports a lock held by another process.
	ErrLocked = errors.New("store: in use by another process")
	// ErrNotRegular reports a file that must be a regular file and is
	// not (a FIFO, a device, a directory); OpenRegular, ReadFileLimited.
	ErrNotRegular = errors.New("not a regular file")
)

// tmpPrefix marks temporary files. They are never valid data files; a
// crash may leave them behind and RemoveTemp deletes them.
const tmpPrefix = ".tmp-"

// OpenDir opens the directory dir for reading its entries or for fsync
// with O_DIRECTORY and O_NONBLOCK (task 20b point 5, R41): anything but a
// directory is refused by the open itself (syscall.ENOTDIR), so a FIFO
// in place of the directory is an error at once instead of an open that
// waits for a writer. A symbolic link to a directory is followed, as by
// os.Open. On a platform without O_DIRECTORY the type is checked after
// the open instead (openDir in dir_other.go).
func OpenDir(dir string) (*os.File, error) { return openDir(dir) }

// ReadDir returns the entries of the directory dir sorted by name, as
// os.ReadDir does, but opens dir with OpenDir (task 24 package F, R41):
// a FIFO, or a file, in place of the directory is refused by the open
// itself (syscall.ENOTDIR) instead of an open that could wait for a
// writer. os.ReadDir of the current toolchain opens with O_DIRECTORY on
// Unix as well; ReadDir makes that guarantee part of this package rather
// than a detail of the runtime. The errors are those of os.ReadDir: a
// missing directory is fs.ErrNotExist (not ErrNotFound), and on an error
// while reading, the entries read so far are returned with it.
func ReadDir(dir string) ([]fs.DirEntry, error) {
	d, err := OpenDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, err
}

// OpenRegular opens path for reading (or fsync) if it is a regular file:
// it is opened with O_NONBLOCK and checked with fstat after the open
// (task 20a point 2, task 20b point 5). A FIFO, or a device, put in
// place of a file is refused as not regular (ErrNotRegular), and the
// open, which waits for a writer on a FIFO without O_NONBLOCK, returns
// at once. On Unix the open also has O_NOCTTY (task 20i point 4), so a
// terminal device in place of a file does not become the controlling
// terminal of a process that has none before it is refused. On a
// regular file O_NONBLOCK and O_NOCTTY change nothing. A missing file
// is ErrNotFound.
func OpenRegular(path string) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|openNoCTTY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s", ErrNotFound, filepath.Base(path))
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("store: %s is %w", filepath.Base(path), ErrNotRegular)
	}
	return f, fi, nil
}

// SyncDir fsyncs a directory so that a rename or create in it is durable.
// It opens dir with OpenDir: a FIFO in place of the directory is an error
// at once.
func SyncDir(dir string) error {
	d, err := OpenDir(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// Permissions in the data directory (9.1). Server and client run as
// different operating system users that both belong to the group gomail,
// so files are 0660 and directories 2770: setgid, so that new entries
// inherit the group of the directory. The program never sets the group
// itself; the administrator creates the data directory with group gomail
// and setgid passes it on. The modes are set with Chmod after creating,
// because the umask may clear the group bits. Group access is allowed
// because the data directory holds no private key; key stores and private
// keys live outside it with PrivateFilePerm.
const (
	FilePerm        fs.FileMode = 0o660
	DirPerm         fs.FileMode = fs.ModeSetgid | 0o770
	PrivateFilePerm fs.FileMode = 0o600
)

// modeBits are the bits Chmod sets.
const modeBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// MkdirAll creates dir and its missing parents with mode DirPerm and
// syncs every parent whose entry was created, so the new directories
// survive a crash. Existing directories keep their mode.
func MkdirAll(dir string) error {
	dir = filepath.Clean(dir)
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("store: %s is not a directory", filepath.Base(dir))
		}
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := MkdirAll(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	} else if err := os.Chmod(dir, DirPerm); err != nil {
		return err
	}
	return SyncDir(parent)
}

// chmodDir sets dir to DirPerm unless it has that mode already.
func chmodDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&modeBits == DirPerm {
		return nil
	}
	return os.Chmod(dir, DirPerm)
}

// tempFile creates a new temporary file next to path with mode perm.
func tempFile(path string, perm fs.FileMode) (*os.File, error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return nil, err
	}
	name := filepath.Join(filepath.Dir(path), tmpPrefix+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(name)
		return nil, err
	}
	return f, nil
}

// writeTemp writes data to a new temporary file with mode perm next to
// path, syncs and closes it, and returns its name.
func writeTemp(path string, data []byte, perm fs.FileMode) (string, error) {
	f, err := tempFile(path, perm)
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// WriteFileAtomic replaces path in the data directory with data, mode
// FilePerm: temporary file, fsync, rename, fsync of the directory. The
// directory must exist.
func WriteFileAtomic(path string, data []byte) error { return writeAtomic(path, data, FilePerm) }

// WritePrivateFileAtomic is WriteFileAtomic with mode PrivateFilePerm,
// for files outside the data directory (client directory, keys).
func WritePrivateFileAtomic(path string, data []byte) error {
	return writeAtomic(path, data, PrivateFilePerm)
}

// WritePrivateFileAtomicIn is WritePrivateFileAtomic for the file name
// in the directory that root holds (task 20l point 1): the temporary
// file, its rename to name and the fsync of the directory all go
// through root, so the file lands in that directory even if its path
// names another directory by now. name is a name in that directory.
func WritePrivateFileAtomicIn(root *os.Root, name string, data []byte) error {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = f.Chmod(PrivateFilePerm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		root.Remove(tmp)
		return err
	}
	return SyncRoot(root)
}

// SyncRoot fsyncs the directory that root holds, wherever its path is
// now.
func SyncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// CreateFileAtomic creates path in the data directory with data and mode
// FilePerm only if it does not exist yet (ErrExists otherwise). The file
// appears complete or not at all: it is written to a temporary file and
// hard-linked to its name, which fails if the name is taken.
func CreateFileAtomic(path string, data []byte) error { return createAtomic(path, data, FilePerm) }

// CreatePrivateFileAtomic is CreateFileAtomic with mode PrivateFilePerm,
// for files outside the data directory (private keys of the ceremony).
func CreatePrivateFileAtomic(path string, data []byte) error {
	return createAtomic(path, data, PrivateFilePerm)
}

func createAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, filepath.Base(path))
		}
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// RenameDurable moves src to dst (same file system) and syncs both
// directories.
func RenameDurable(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if err := SyncDir(filepath.Dir(dst)); err != nil {
		return err
	}
	if filepath.Dir(src) != filepath.Dir(dst) {
		return SyncDir(filepath.Dir(src))
	}
	return nil
}

// RemoveDurable removes path and syncs its directory. A missing file is
// not an error.
func RemoveDurable(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// ReadFileLimited reads path if it is a regular file of at most max
// bytes. The size is checked before anything is allocated.
//
// The file is opened with OpenRegular (task 20a point 2): a FIFO, or a
// device, put in place of a file of the data directory (or given as a
// pin or key file) is refused as not regular (ErrNotRegular), and the
// open returns at once; no reader (server, client, ceremony) hangs at
// it. A terminal device does not become the controlling terminal
// (O_NOCTTY of OpenRegular, task 20i point 4).
//
// The buffer is allocated once with the size from Stat plus one byte
// (backlog 105), at most max+1 bytes, so a file that keeps its size is
// read without growing the buffer: about once its size is allocated,
// not twice as with io.ReadAll. The extra byte lets the read see the
// end of the file (or growth) without another allocation. A file that
// grew after Stat is still read to at most max+1 bytes, the buffer
// doubling up to max+1 (see readAtMost), about twice max+1 allocated
// in all; one that shrank is returned with the bytes read. A result
// much smaller than its buffer is copied where the copy keeps the sum
// within twice max+1 (always when the file shrank).
func ReadFileLimited(path string, max int64) ([]byte, error) {
	f, fi, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: %s has %d bytes, at most %d", ErrTooLarge, filepath.Base(path), fi.Size(), max)
	}
	if readLimitedHook != nil {
		readLimitedHook(path)
	}
	// Read at most max+1 bytes: the file may grow after Stat.
	data, err := readAtMost(f, fi.Size(), max+1)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s grew beyond %d bytes", ErrTooLarge, filepath.Base(path), max)
	}
	return data, nil
}

// readLimitedHook, if set, is called by ReadFileLimited with the path
// after the size check and before the read. Only tests set it
// (fs28d_test.go: the file grows or shrinks between Stat and the read);
// it is nil in production. It is a package variable without
// synchronisation: tests that set it must not run in parallel.
var readLimitedHook func(path string)

// readAtMost reads r to its end, but at most limit bytes, as
// io.ReadAll(io.LimitReader(r, limit)) does: the same bytes on success
// and the same error, but with a buffer of size+1 bytes (at most limit)
// allocated before the first read. A read error is returned as is,
// without the bytes read (io.ReadAll returns them; ReadFileLimited
// dropped them before). A limit of zero or less reads nothing and
// returns an empty, non-nil slice (io.LimitReader with N <= 0); a size
// below zero counts as zero.
//
// A size of zero (as Stat shows for files of /proc) starts with
// min(512, limit) bytes, as io.ReadAll does, not with one byte: the
// first read is as large as before backlog 105 (review 28D2, finding
// 1). Only the first read is the same; the later ones are not. For the
// limits of the callers, a file replaced by a link to a special file
// that refuses short reads (/proc/self/pagemap wants a multiple of 8)
// gives the same result as before backlog 105
// (TestReadFileLimitedSpecialLikeOld); for some other limits it does
// not (review 29A, finding 1).
//
// If the buffer is full before the end (the file grew after Stat, or
// Stat showed 0 bytes), it doubles, to at least 512 bytes and at most
// limit; once the doubled size would be above half of limit, it grows
// to limit at once. So no buffer is larger than limit, the buffers of
// one read add up to at most about twice limit (backlog 105, review
// 28D F1), and the byte that shows the end of the file needs no buffer
// of its own.
//
// A result much smaller than its buffer (more than 4 KiB and more than
// half of it unused) is copied, so a caller that keeps it does not keep
// the buffer (review 28D F2), but only while the buffers and the copy
// add up to at most twice limit (review 28D2 R1, review 29A R1):
//   - If the buffer did not grow (the file shrank after Stat), or grew
//     to limit in one step, the copy always fits: such a result holds
//     at most about twice its bytes.
//   - After a doubling the copy is left out where it would raise the
//     sum above twice limit, as in the worst case of review 28D2 R1
//     (the doubling full just below half of limit, then limit, then the
//     end; a copy there made about 2.5 times limit).
//   - A result that is not copied holds less than three times its
//     bytes, and at most limit: its buffer is limit, the buffers before
//     were full and add up to less than twice its bytes, and these with
//     limit and the copy would be above twice limit.
//
// With this growth both bounds (twice limit in all, twice its bytes
// held) cannot be had at once; the one of the allocation wins. Never to
// copy after growth would hold up to four times the bytes (review 29A
// R1), always to copy (28D2) would allocate 2.5 times limit.
func readAtMost(r io.Reader, size, limit int64) ([]byte, error) {
	return readAtMostCap(r, size, limit, math.MaxInt)
}

// readAtMostCap is readAtMost with buffers of at most maxCap bytes
// (math.MaxInt, the range of int; tests pass less). If the buffer is
// full at maxCap bytes before limit, the result is ErrTooLarge with
// the fixed message "the buffer is full at N bytes before the limit"
// (not "more than max": the file may end there): Read never gets an
// empty buffer, which an os.File answers with (0, nil),
// so the loop would not end. Only 386 with a limit of 2 GiB or more
// gets there (none of the callers), and only if a buffer of MaxInt
// bytes could be allocated and filled; mostly an allocation fails
// before, as with io.ReadAll.
func readAtMostCap(r io.Reader, size, limit, maxCap int64) ([]byte, error) {
	if limit <= 0 {
		return []byte{}, nil
	}
	n := max(size, 0)
	if n < limit {
		n++ // the byte that shows the end of the file
	}
	if size <= 0 {
		n = 512 // as io.ReadAll; see readAtMost
	}
	n = min(n, limit)
	if n > maxCap {
		// Only with a limit above the range of int (386 and a limit
		// of 2 GiB or more, none of the callers): start with 512
		// bytes and double.
		n = min(512, maxCap)
	}
	buf := make([]byte, 0, int(n))
	total := n // all buffers of this read, for the bound of the copy
	for int64(len(buf)) < limit {
		if len(buf) == cap(buf) {
			c := max(2*int64(cap(buf)), 512)
			if c > limit/2 {
				c = limit
			}
			c = min(c, maxCap)
			if c <= int64(cap(buf)) {
				return nil, fmt.Errorf("%w: the buffer is full at %d bytes before the limit", ErrTooLarge, cap(buf))
			}
			nb := make([]byte, len(buf), int(c))
			copy(nb, buf)
			buf = nb
			total += c
		}
		room := buf[len(buf):cap(buf)]
		if rest := limit - int64(len(buf)); int64(len(room)) > rest {
			room = room[:rest]
		}
		m, err := r.Read(room)
		buf = buf[:len(buf)+m]
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	// total+len <= 2*limit, written so that it cannot overflow.
	if cap(buf)-len(buf) > 4096 && len(buf) < cap(buf)/2 && total-limit <= limit-int64(len(buf)) {
		buf = slices.Clone(buf) // not nil for an empty buf
	}
	return buf, nil
}

// RemoveTemp deletes temporary files left by an interrupted write in dir.
func RemoveTemp(dir string) error { return RemoveTempReport(dir, nil) }

// RemoveTempReport is RemoveTemp that calls removed, when not nil, with
// the name of every temporary file it removed (gomail-ceremony publish
// names them: review of task 25 A, L2; publish uses RemoveTempReportIn
// since backlog 72). A temporary file is an entry of
// dir that is a regular file when dir is listed and whose name starts
// with ".tmp-". Its name is removed with unlink (removeName), never with
// rmdir: a directory that another process put under the name meanwhile
// is not removed, even when empty, and is an error (review of task 25 A,
// H2). A name that is gone meanwhile is skipped and not reported.
func RemoveTempReport(dir string, removed func(name string)) error {
	entries, err := ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	gone := false
	for _, e := range entries {
		if len(e.Name()) > len(tmpPrefix) && e.Name()[:len(tmpPrefix)] == tmpPrefix && e.Type().IsRegular() {
			if err := removeName(filepath.Join(dir, e.Name())); err != nil {
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
		return SyncDir(dir)
	}
	return nil
}
