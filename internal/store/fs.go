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
)

// tmpPrefix marks temporary files. They are never valid data files; a
// crash may leave them behind and RemoveTemp deletes them.
const tmpPrefix = ".tmp-"

// SyncDir fsyncs a directory so that a rename or create in it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
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
func ReadFileLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, filepath.Base(path))
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("store: %s is not a regular file", filepath.Base(path))
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: %s has %d bytes, at most %d", ErrTooLarge, filepath.Base(path), fi.Size(), max)
	}
	// Read at most max+1 bytes: the file may grow after Stat.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s grew beyond %d bytes", ErrTooLarge, filepath.Base(path), max)
	}
	return data, nil
}

// RemoveTemp deletes temporary files left by an interrupted write in dir.
func RemoveTemp(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	removed := false
	for _, e := range entries {
		if len(e.Name()) > len(tmpPrefix) && e.Name()[:len(tmpPrefix)] == tmpPrefix && e.Type().IsRegular() {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			removed = true
		}
	}
	if removed {
		return SyncDir(dir)
	}
	return nil
}
