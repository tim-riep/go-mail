package ceremony

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// crashHook is called at the injection points of commit and Publish
// with the name of the point; an error it returns is handled like a
// failed write there. Only tests set it.
var crashHook func(point string) error

func hook(point string) error {
	if crashHook != nil {
		return crashHook(point)
	}
	return nil
}

// stagingPrefix names the staging directory of an export next to Out.
const stagingPrefix = ".tmp-ceremony-"

// realPath returns p absolute and cleaned, with the symbolic links of
// its longest existing prefix resolved, so that two paths can be
// compared for containment.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cur, rest := abs, ""
	for {
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// checkDirs resolves out and keyDir (keyDir may be empty: nothing
// private is written) and checks that out is new or an empty directory
// and that neither directory contains the other (ErrOutDir). A keyDir
// whose last element is a symbolic link is ErrKeyDir; links in the
// elements before it are resolved.
func checkDirs(out, keyDir string) (string, string, error) {
	if out == "" {
		return "", "", fmt.Errorf("%w: no export directory", ErrOutDir)
	}
	o, err := realPath(out)
	if err != nil {
		return "", "", err
	}
	var k string
	if keyDir != "" {
		// The last element is looked at before the path is resolved: a
		// link there is refused, not followed (task 10e finding 5).
		if fi, err := os.Lstat(filepath.Clean(keyDir)); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return "", "", fmt.Errorf("%w: %s is a symbolic link", ErrKeyDir, filepath.Base(keyDir))
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		if k, err = realPath(keyDir); err != nil {
			return "", "", err
		}
		if inside(k, o) || inside(o, k) {
			return "", "", fmt.Errorf("%w: export and key directory must be separate", ErrOutDir)
		}
	}
	if err := checkEmpty(o); err != nil {
		return "", "", err
	}
	return o, k, nil
}

// checkEmpty reports whether dir does not exist or is an empty
// directory.
func checkEmpty(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrOutDir, filepath.Base(dir))
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(1)
	f.Close()
	if len(names) > 0 {
		return fmt.Errorf("%w: %s is not empty", ErrOutDir, filepath.Base(dir))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// checkKeyFiles reports ErrKeyDir if keyDir is not a directory of
// mode 0700 owned by the current user (checkKeyDirInfo) or already
// holds one of names. A missing keyDir is fine (commit creates it).
// commit checks the directory again when it opens it.
func checkKeyFiles(keyDir string, names ...string) error {
	if keyDir == "" {
		return fmt.Errorf("%w: no key directory", ErrKeyDir)
	}
	fi, err := os.Lstat(keyDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := checkKeyDirInfo(fi); err != nil {
		return err
	}
	for _, n := range names {
		_, err := os.Lstat(filepath.Join(keyDir, n))
		if err == nil {
			return fmt.Errorf("%w: it already holds %s", ErrKeyDir, n)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// keyFile is a private key to be written to the key directory.
type keyFile struct {
	role uint8
	name string // "admin" or "ingest"
	gen  uint32
	key  ed25519.PrivateKey
}

func (k keyFile) fileName() string { return store.PlatformFileName(k.name, k.gen, "key") }

// commit writes the export directory out with files (paths relative to
// out, "/"-separated) and the private keys ks into keyDir, so that an
// error at any point leaves neither behind: the export is staged in a
// new hidden directory next to out, then keyDir (created with mode 0700
// if missing) is opened as an os.Root without following a link in its
// last element and checked again (mode 0700, own user, ErrKeyDir), the
// keys are created exclusively relative to that root (never by path:
// a directory swapped for a link after the root was opened does not
// redirect them, task 10c finding 2), and the rename of the staging
// directory to out is the commit point (an empty out is replaced).
// Every error before it removes the keys written so far (every key
// whose name was linked, even if a later step of createKeyFile failed,
// task 10d finding 5), keyDir if commit created it, and the staging
// directory.
//
// g (may be nil) brackets all of it: BeginCommit before the first
// write, CommitPoint after the staging directory and the keys are
// written and before the rename (an error rolls back as any error
// before the commit point), EndCommit after the files are complete or
// rolled back, with whether the rename succeeded (task 10c finding 3,
// task 10e finding 2).
func commit(out string, files map[string][]byte, keyDir string, ks []keyFile, g CommitGuard) (err error) {
	committed := false
	if g != nil {
		g.BeginCommit()
		// Registered first, so it runs after every other deferred call
		// (the rollback).
		defer func() { g.EndCommit(committed) }()
	}
	if err := hook("commit"); err != nil {
		return err
	}
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(parent, stagingPrefix+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	defer func() {
		if !committed {
			os.RemoveAll(tmp)
		}
	}()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(tmp, filepath.FromSlash(n))
		if !inside(p, tmp) || p == tmp {
			return fmt.Errorf("%w: invalid export path", ErrOutDir)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := store.CreateFileAtomic(p, files[n]); err != nil {
			return err
		}
		if err := hook("export-file"); err != nil {
			return err
		}
	}
	if err := store.SyncDir(tmp); err != nil {
		return err
	}
	if err := hook("export"); err != nil {
		return err
	}

	if keyDir != "" {
		created := false
		if _, err := os.Lstat(keyDir); errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				return err
			}
			created = true
		}
		// The keys are created relative to the directory opened without
		// following a link and checked again (task 10b finding 3).
		root, err := openKeyDir(keyDir)
		if err != nil {
			if created {
				os.Remove(keyDir)
			}
			return err
		}
		defer root.Close()
		var written []string
		defer func() {
			if committed {
				return
			}
			for _, n := range written {
				root.Remove(n)
			}
			if created {
				os.Remove(keyDir)
			} else if len(written) > 0 {
				syncRoot(root)
			}
		}()
		// Injection point after the directory was opened and checked:
		// from here on the keys go to the opened directory, whatever
		// keyDir names now (task 10c finding 2).
		if err := hook("root"); err != nil {
			return err
		}
		for _, k := range ks {
			data, err := store.EncodePlatformKey(k.role, k.gen, k.key)
			if err != nil {
				return err
			}
			linked, err := createKeyFile(root, k.fileName(), data)
			keys.Wipe(data)
			if linked {
				// Recorded as soon as the name exists, whatever
				// failed after the link: the rollback removes it.
				written = append(written, k.fileName())
			}
			if err != nil {
				return err
			}
			if err := hook("key"); err != nil {
				return err
			}
		}
	}
	if err := hook("keys"); err != nil {
		return err
	}
	// A signal that arrived so far stops the ceremony here: nothing is
	// committed, the deferred calls roll back (task 10e finding 2).
	if g != nil {
		if err := g.CommitPoint(); err != nil {
			return err
		}
	}
	// syscall.Rename, not os.Rename: os.Rename refuses an existing
	// directory as the target, rename(2) replaces an empty one.
	if err := syscall.Rename(tmp, out); err != nil {
		return fmt.Errorf("%w: %s is not new or empty any more", ErrOutDir, filepath.Base(out))
	}
	committed = true
	return store.SyncDir(parent)
}

// createKeyFile creates name in root with data and mode 0600 only if it
// does not exist yet (ErrKeyDir otherwise), as store.CreatePrivateFileAtomic
// does for a path: a temporary file is written, synced and hard-linked to
// its name, which fails if the name is taken. linked reports whether
// name was created, also when an error follows (removing the temporary
// name, syncing the directory): the caller must remove it on rollback.
func createKeyFile(root *os.Root, name string, data []byte) (linked bool, err error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return false, err
	}
	tmp := ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, store.PrivateFilePerm)
	if err != nil {
		return false, err
	}
	defer root.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(store.PrivateFilePerm)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if err := root.Link(tmp, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, fmt.Errorf("%w: it already holds %s", ErrKeyDir, name)
		}
		return false, err
	}
	// Injection point after the link: a failure from here on leaves
	// name behind unless the caller removes it (task 10d finding 5).
	if err := hook("link"); err != nil {
		return true, err
	}
	if err := root.Remove(tmp); err != nil {
		return true, err
	}
	return true, syncRoot(root)
}

// syncRoot fsyncs the directory of root.
func syncRoot(root *os.Root) error {
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
