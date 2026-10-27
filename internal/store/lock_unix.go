//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// File locks (9.1) are POSIX record locks (fcntl) over the whole file,
// never flock: only record locks are enforced across machines by NFSv4.
//
// On Linux they are open file description locks (F_OFD_SETLK,
// F_OFD_SETLKW, lock_linux.go). They belong to one open file description:
// two descriptors of the same process conflict, and only closing that
// description releases the lock.
//
// The other Unix systems only have process locks (F_SETLK, F_SETLKW) with
// two pitfalls: a process never conflicts with itself, and closing any
// descriptor of the file releases every lock the process holds on it,
// even one taken through another descriptor. Therefore each lock is held
// through exactly one descriptor: a registry in the process serializes
// the locks of one path, a lock file is opened only by the holder of its
// registry entry and closed only on release, and nothing else in the
// program opens lock files. The registry is used on Linux as well.

// lockRegistry holds the lock paths this process holds or is acquiring.
var lockRegistry = struct {
	sync.Mutex
	held map[string]chan struct{} // closed on release
}{held: map[string]chan struct{}{}}

// reserve takes the registry entry of path. Without wait it reports
// ErrLocked if the process holds path already.
func reserve(path string, wait bool) error {
	for {
		lockRegistry.Lock()
		ch, busy := lockRegistry.held[path]
		if !busy {
			lockRegistry.held[path] = make(chan struct{})
			lockRegistry.Unlock()
			return nil
		}
		lockRegistry.Unlock()
		if !wait {
			return ErrLocked
		}
		<-ch
	}
}

// reserved reports whether this process holds the registry entry of path.
func reserved(path string) bool {
	lockRegistry.Lock()
	defer lockRegistry.Unlock()
	_, ok := lockRegistry.held[path]
	return ok
}

func unreserve(path string) {
	lockRegistry.Lock()
	ch := lockRegistry.held[path]
	delete(lockRegistry.held, path)
	lockRegistry.Unlock()
	close(ch)
}

// openLockFile opens path for reading and writing, creating it with mode
// FilePerm if it does not exist.
func openLockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := f.Chmod(FilePerm); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}

// fcntlLock sets (typ F_RDLCK or F_WRLCK) or releases (F_UNLCK) the lock
// over the whole file of f.
func fcntlLock(f *os.File, typ int16, wait bool) error {
	lk := syscall.Flock_t{Type: typ, Whence: io.SeekStart} // Start 0, Len 0: the whole file
	cmd := cmdSetLk
	if wait {
		cmd = cmdSetLkW
	}
	for {
		err := syscall.FcntlFlock(f.Fd(), cmd, &lk)
		if err != syscall.EINTR {
			return err
		}
	}
}

// conflict reports whether a non-blocking lock failed because another
// holder has the file locked.
func conflict(err error) bool { return err == syscall.EAGAIN || err == syscall.EACCES }

// lockPath locks path (created if missing) exclusively or shared. Without
// wait it reports ErrLocked if the lock is held elsewhere. The returned
// function releases the lock; calling it twice is harmless.
func lockPath(path string, exclusive, wait bool) (func(), error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := reserve(path, wait); err != nil {
		return nil, err
	}
	f, err := openLockFile(path)
	if err != nil {
		unreserve(path)
		return nil, err
	}
	typ := int16(syscall.F_RDLCK)
	if exclusive {
		typ = syscall.F_WRLCK
	}
	if err := fcntlLock(f, typ, wait); err != nil {
		f.Close()
		unreserve(path)
		if !wait && conflict(err) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock %s: %w", filepath.Base(path), err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			fcntlLock(f, syscall.F_UNLCK, false)
			f.Close()
			unreserve(path)
		})
	}, nil
}

// lockFile takes an exclusive lock on path and waits for it.
func lockFile(path string) (func(), error) { return lockPath(path, true, true) }

// tryLockFile is lockFile without waiting (ErrLocked).
func tryLockFile(path string) (func(), error) { return lockPath(path, true, false) }

// probeLock tries to take an exclusive lock on the existing file path
// without waiting and releases it at once. It returns nil if the lock was
// free, ErrLocked if someone holds a lock on the file, and fs.ErrNotExist
// if there is no such file.
func probeLock(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if !ofdLocks && reserved(path) {
		// With process locks a second descriptor would neither conflict
		// with this process's own lock nor survive closing; the lock this
		// process holds is in force against every other process.
		return ErrLocked
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := fcntlLock(f, syscall.F_WRLCK, false); err != nil {
		if conflict(err) {
			return ErrLocked
		}
		return fmt.Errorf("store: lock %s: %w", filepath.Base(path), err)
	}
	return fcntlLock(f, syscall.F_UNLCK, false)
}

// LockPath takes the exclusive record lock on path (created with mode
// FilePerm if missing) and waits for it, like LockMailbox. It is the lock
// of the transparency log (translog log/lock): every appender and the
// server when it writes a head hold it. The returned function releases
// the lock; calling it twice is harmless.
func LockPath(path string) (func(), error) { return lockFile(path) }
