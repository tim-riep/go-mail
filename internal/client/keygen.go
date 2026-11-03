package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Prompter shows the seed words and asks for three of them (2.2).
type Prompter interface {
	// ShowWords displays the 24 words once.
	ShowWords(words []string) error
	// AskWord asks for the word at position (1-based).
	AskWord(position int) (string, error)
}

// SharePrompter is a Prompter that also shows the Shamir shares of the
// seed (2.2 "Wiederherstellung", gomailctl keygen --shares). The shares
// are shown only through ShowShares and never written to a file.
//
// It stays a separate interface (task 20b point 2): Prompter is all that
// Keygen without shares and RecoveryKeygen, which never splits its seed,
// need, so their callers implement no method that is never called.
// KeygenWithOptions asks for SharePrompter only when opts.Shares is set
// and refuses a Prompter without ShowShares (ErrArgument) before a seed
// exists. The prompter of gomailctl keygen implements it.
type SharePrompter interface {
	Prompter
	// ShowShares displays the shares once: shares[i] are the 30 words of
	// the share with index i+1 (shamir.Share.Words).
	ShowShares(shares [][]string) error
}

// Shares is a split "k-of-n" of the seed: Threshold of Count shares
// rebuild it.
type Shares struct {
	Threshold int
	Count     int
}

// KeygenOptions are the options of KeygenWithOptions.
type KeygenOptions struct {
	// Shares splits the seed additionally into shares (2.2
	// "Wiederherstellung", e.g. 2-of-3); zero means no split. 2 <=
	// Threshold <= Count <= 255 (shamir.Split).
	Shares Shares
}

// ConfirmWords is the number of words asked back (2.2).
const ConfirmWords = 3

// Keygen creates a new user in cfg.Dir (2.2): a seed from crypto/rand,
// shown as 24 words, three of them asked back; only then the root key,
// generation 1 and its certificate are derived, the key store is written
// with passphrase and the seed and root are wiped. The user exists only
// locally until Register.
func Keygen(cfg Config, passphrase []byte, p Prompter) (store.ID, error) {
	return KeygenWithOptions(cfg, passphrase, p, KeygenOptions{})
}

// KeygenWithOptions is Keygen with options. With opts.Shares the seed is
// split with shamir.Split after the words are confirmed, each share is
// shown as 30 words through SharePrompter.ShowShares (p must implement
// it), and the shares are wiped; the platform gets no share (2.2). A
// split that does not rebuild the seed from its first Threshold shares
// stops Keygen before anything is written.
func KeygenWithOptions(cfg Config, passphrase []byte, p Prompter, opts KeygenOptions) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if len(passphrase) == 0 {
		return store.ID{}, fmt.Errorf("client: empty passphrase")
	}
	var sp SharePrompter
	if opts.Shares != (Shares{}) {
		if err := checkShares(opts.Shares); err != nil {
			return store.ID{}, err
		}
		var ok bool
		if sp, ok = p.(SharePrompter); !ok {
			return store.ID{}, fmt.Errorf("%w: the prompter cannot show shares", ErrArgument)
		}
	}
	if _, err := os.Stat(cfg.keystorePath()); err == nil {
		return store.ID{}, ErrRegistered
	}
	seed, err := keys.NewSeed(nil)
	if err != nil {
		return store.ID{}, err
	}
	defer seed.Zero()
	if err := showAndConfirm(seed, p); err != nil {
		return store.ID{}, err
	}
	if sp != nil {
		if err := showShares(seed, opts.Shares, sp); err != nil {
			return store.ID{}, err
		}
	}

	u := keys.DeriveUser(seed)
	defer u.Zero()
	root, err := u.RootKey()
	if err != nil {
		return store.ID{}, err
	}
	defer keys.Wipe(root)
	identity, err := u.IdentityKey(1)
	if err != nil {
		return store.ID{}, err
	}
	unwrap, err := u.UnwrapKey(1)
	if err != nil {
		keys.Wipe(identity)
		return store.ID{}, err
	}
	ks := &keys.Keystore{Generation: 1, Identity: identity, Unwrap: unwrap}
	defer ks.Zero()
	cert, err := keys.NewGenerationCert(root, 1, identity.Public().(ed25519.PublicKey), unwrap.PublicKey(), cfg.Now().UnixMilli())
	if err != nil {
		return store.ID{}, err
	}
	id, err := store.NewID(nil)
	if err != nil {
		return store.ID{}, err
	}
	user := &store.User{ID: id, RootPub: root.Public().(ed25519.PublicKey), Generations: []*keys.GenerationCert{cert}}
	// user.rec is signed by the root here, the only moment the root exists
	// (2.2, 3.7 "user"); Register publishes the signed file.
	if err := user.Sign(root); err != nil {
		return store.ID{}, err
	}
	userData, err := user.Encode()
	if err != nil {
		return store.ID{}, err
	}
	ksData, err := ks.Seal(passphrase, nil)
	if err != nil {
		return store.ID{}, err
	}
	err = writeClientDir(cfg.Dir, "keygen", userData, ksData, &state{UserID: id.String(), Mailboxes: map[string]*mailboxState{}})
	if err != nil {
		return store.ID{}, err
	}
	return id, nil
}

// clientDirFault, if set, is called after every write step of Keygen and
// Restore with the name of the step, prefixed with the kind of the run
// ("keygen-" or "restore-" and "dir", "user", "keystore", "state",
// "locked", "renamed"); an error it returns is handled like a failed
// write of that step. It is nil in production and set only by tests of
// this package.
var clientDirFault func(step string) error

// dirStep ends write step step of a run of kind (keygen, restore) that
// creates a client directory: a simulated crash (crashHook, point
// "<kind>-<step>") stops without cleanup as a killed process would; an
// injected fault (clientDirFault) fails the step.
func dirStep(kind, step string) error {
	if crash(kind + "-" + step) {
		return errCrashed
	}
	if clientDirFault != nil {
		return clientDirFault(kind + "-" + step)
	}
	return nil
}

// writeClientDir creates the client directory dir of a user with
// user.rec userData, the sealed key store ksData and the state st, in
// one step (createClientDir); kind names the run (keygen, restore). The
// files are written through the descriptor of the temporary directory
// (task 20l point 1); the key store as keys.WriteKeystoreFile writes
// it, mode 0600, synced, renamed and the directory synced.
func writeClientDir(dir, kind string, userData, ksData []byte, st *state) error {
	return createClientDir(dir, kind, func(root *os.Root) error {
		if err := store.WritePrivateFileAtomicIn(root, "user.rec", userData); err != nil {
			return err
		}
		if err := dirStep(kind, "user"); err != nil {
			return err
		}
		if err := store.WritePrivateFileAtomicIn(root, "keystore", ksData); err != nil {
			return err
		}
		if err := dirStep(kind, "keystore"); err != nil {
			return err
		}
		data, err := stateData(st)
		if err != nil {
			return err
		}
		if err := store.WritePrivateFileAtomicIn(root, "state.json", data); err != nil {
			return err
		}
		return dirStep(kind, "state")
	})
}

// errDirNotEmpty is the cause of a rename of createClientDir that found
// the client directory not empty.
var errDirNotEmpty = errors.New("client: client directory not empty")

// errInUse is the error of a keygen or restore that lost the client
// directory dir to another client: the rename found it not empty, or a
// concurrent run of the same kind removed the temporary directory of
// this one (removeLeftovers, task 20h point 6) and dir is taken (task
// 20i point 2).
func errInUse(dir string) error {
	return fmt.Errorf("%w: the client directory %s is not empty or in use by another client", store.ErrExists, dir)
}

// errTempReplaced is the error of a keygen or restore whose temporary
// directory was replaced (task 20l point 1): its name, or after the
// rename the client directory, names another directory than the one
// this run made and holds open. Nothing is renamed over or removed then.
var errTempReplaced = errors.New("client: the temporary directory of the client directory was replaced by another directory; its parent must not be writable by other users")

// incompleteMarker is the file that marks the temporary directory of a
// keygen or restore before its rename (task 20h point 4).
const incompleteMarker = ".incomplete"

// createClientDir creates the client directory dir of a user in one step
// (task 20b point 1; Restore since task 20e point 2): write fills a new
// temporary directory .<name>.<kind>-<digits> next to dir (each file
// synced on its own), the temporary directory is synced, renamed to dir
// and the parent of dir is synced. kind is the run, keygen or restore. A
// signal or a failed write at any point leaves either no client
// directory or a complete one with key store, user.rec and state.json,
// so a second run succeeds after an interrupted one, and a complete
// directory is never half overwritten. Before the rename a failure
// removes the temporary directory; a killed process may leave it behind
// next to dir, holding only the sealed key store, the public user.rec and
// state.json, and no client reads it. The first file of the temporary
// directory is the marker .incomplete (task 20h point 4); it is removed,
// and the removal synced, right before the rename, so a client directory
// never holds it. The next run of the same kind for dir that succeeds
// removes a leftover with the marker (removeLeftovers, task 20e point 3).
// A process killed between the removal of the marker and the rename
// leaves a temporary directory without it, which stays.
//
// The temporary directory is held by a descriptor (os.Root) from right
// after os.MkdirTemp on (task 20l point 1, F2 of the attack review of
// task 20i): it must then be an empty directory of this user
// (openTempDir), every file is written, and the marker removed, through
// the descriptor, and the identity of the directory is kept. Someone who
// can write the parent of dir may rename the temporary directory away
// and put another directory, such as the complete client directory of
// another user, at its name. The files still go to the directory this
// run made, wherever it is now, and before the rename (sameDir; before
// lockOnlyDir and again right before the rename) the path is checked to
// name that directory still: another directory there fails the run with
// errTempReplaced, and nothing is renamed over dir or removed. After the
// rename dir is checked the same way, so a directory swapped in between
// that check and the rename is not reported as success. A failure before
// the rename removes the temporary directory only if its path names this
// run's directory, and then only the entries through the descriptor and
// the then empty directory with os.Remove (removeTempDir), so a
// directory swapped in after the check is never emptied. A race between
// the check and the rename is left (the rename is not relative to a
// descriptor); it moves at worst another directory to dir and fails the
// run. The parent of a client directory must not be writable by other
// users.
//
// dir may exist as an empty directory, which the rename replaces, or as
// one that holds only the lock file (lockOnlyDir); a directory with
// other entries is kept and refused (store.ErrExists; Keygen and Restore
// themselves refuse a directory with a key store, user.rec or state.json
// before, ErrRegistered). An Open of the same directory may create its
// lock file again between lockOnlyDir and the rename (L1 of the review of
// task 20b): the rename is tried once more, and a directory that is still
// not empty is refused as "not empty or in use by another client"
// (errInUse), as is a run whose temporary directory a concurrent run of
// the same kind removed (task 20h point 6), if a rename of this run
// found dir not empty or dir is taken once the temporary directory is
// found missing (dirTaken, task 20i point 2); otherwise a missing
// temporary directory fails the run with the error of its step, or of
// the check before the rename, which errors.Is matches with
// fs.ErrNotExist (someone moved or removed it, but dir is not taken). A
// symbolic link as dir is followed, as before: the directory it names
// is created or replaced. A mount point as dir cannot be replaced: the
// rename fails with EBUSY or EXDEV and the run with it.
func createClientDir(dir, kind string, write func(root *os.Root) error) (err error) {
	if fi, lerr := os.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		if dir, err = filepath.EvalSymlinks(dir); err != nil {
			return err
		}
	}
	parent, name := filepath.Dir(dir), filepath.Base(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	prefix := "." + name + "." + kind + "-"
	tmp, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return err
	}
	root, made, err := openTempDir(tmp)
	if err != nil {
		if !errors.Is(err, errTempReplaced) {
			// os.Remove removes only an empty directory.
			os.Remove(tmp)
		}
		return err
	}
	defer root.Close()
	// renamed is set once tmp is dir; notEmpty once a rename found dir
	// not empty.
	renamed, notEmpty := false, false
	defer func() {
		// A simulated crash leaves everything as a killed process would;
		// after the rename tmp is the client directory. A replaced
		// temporary directory is left alone, and so is whatever is at its
		// name.
		if err == nil || errors.Is(err, errCrashed) || renamed || errors.Is(err, errTempReplaced) {
			return
		}
		// A temporary directory that is gone may have been removed by a
		// run of the same kind that succeeded meanwhile (removeLeftovers):
		// whatever step failed on the missing directory, dir is reported
		// as taken (errInUse) only if the rename found it not empty or
		// the look of lockOnlyDir at it finds it taken now (task 20i
		// point 2). Otherwise the error of the step stays, which
		// errors.Is matches with fs.ErrNotExist: the temporary directory
		// was moved or removed by someone else and dir is not taken.
		fi, lerr := os.Lstat(tmp)
		if errors.Is(lerr, os.ErrNotExist) {
			if notEmpty || dirTaken(dir) {
				err = errInUse(dir)
			}
			return
		}
		// Another directory at the name of tmp is not removed (task 20l
		// point 1).
		if lerr == nil && os.SameFile(fi, made) {
			removeTempDir(root, tmp)
		}
	}()
	if err := writeMarker(root); err != nil {
		return err
	}
	// The time of the file system at the start of this run: a temporary
	// directory last changed before it is a leftover of an earlier run.
	start, err := root.Stat(".")
	if err != nil {
		return err
	}
	if err := dirStep(kind, "dir"); err != nil {
		return err
	}
	if err := write(root); err != nil {
		return err
	}
	err = replaceDir(root, made, tmp, dir, kind)
	if errors.Is(err, errDirNotEmpty) {
		notEmpty = true
		err = replaceDir(root, made, tmp, dir, kind)
	}
	if errors.Is(err, errDirNotEmpty) {
		return errInUse(dir)
	}
	if err != nil {
		return err
	}
	renamed = true
	if err := sameDir(dir, made); err != nil {
		// Another directory was swapped in between the check and the
		// rename: it is at dir now, the one of this run elsewhere.
		if !errors.Is(err, errTempReplaced) {
			err = fmt.Errorf("%w: %s after the rename: %w", errTempReplaced, dir, err)
		}
		return err
	}
	if err := dirStep(kind, "renamed"); err != nil {
		return err
	}
	if err := store.SyncDir(parent); err != nil {
		return err
	}
	removeLeftovers(parent, prefix, start.ModTime())
	return nil
}

// openTempDir opens the temporary directory tmp that os.MkdirTemp has
// just made as a root and returns it with the identity of the directory
// (fstat). It must be what MkdirTemp made: an empty directory of the
// user of this process (ownedByMe, where the system has owners of
// files), named by tmp itself (os.Lstat, no symbolic link, os.SameFile
// with the root); anything else, such as another client directory or a
// symbolic link to any directory renamed to its name right after
// MkdirTemp, is errTempReplaced and is not touched.
// The directory gets mode 0700 through the descriptor (MkdirTemp creates
// it with 0700 less the umask).
func openTempDir(tmp string) (*os.Root, fs.FileInfo, error) {
	root, err := os.OpenRoot(tmp)
	if err != nil {
		return nil, nil, err
	}
	fi, err := checkTempDir(root, tmp)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, fi, nil
}

// checkTempDir is the check of openTempDir on the directory root holds.
func checkTempDir(root *os.Root, tmp string) (fs.FileInfo, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || (ownersKnown && !ownedByMe(fi)) {
		return nil, fmt.Errorf("%w: %s is not a directory of this user", errTempReplaced, tmp)
	}
	// os.OpenRoot follows a symbolic link at tmp; the name itself must be
	// the directory root holds, not a link to another one.
	li, err := os.Lstat(tmp)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errTempReplaced, tmp, err)
	}
	if !li.IsDir() || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%w: %s is not the directory opened", errTempReplaced, tmp)
	}
	names, err := d.Readdirnames(1)
	if len(names) > 0 {
		return nil, fmt.Errorf("%w: %s is not empty", errTempReplaced, tmp)
	}
	if err != io.EOF {
		return nil, err
	}
	if err := d.Chmod(0o700); err != nil {
		return nil, err
	}
	return fi, nil
}

// sameDir checks that path names the directory made (os.SameFile with
// os.Lstat of path): a missing path is the error of os.Lstat, which
// errors.Is matches with fs.ErrNotExist, any other file errTempReplaced.
func sameDir(path string, made fs.FileInfo) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(fi, made) {
		return fmt.Errorf("%w: %s", errTempReplaced, path)
	}
	return nil
}

// removeTempDir removes the temporary directory tmp of a failed run,
// whose path createClientDir found naming the directory root holds: the
// entries through root, so only those of that directory, and then tmp
// with os.Remove, which removes only an empty directory. A directory
// renamed to the name of tmp after the check keeps its entries and
// stays. Errors are ignored: the run has failed already, and a leftover
// with the marker is removed by a later run.
func removeTempDir(root *os.Root, tmp string) {
	d, err := root.Open(".")
	if err != nil {
		return
	}
	for {
		names, err := d.Readdirnames(leftoverBatch)
		for _, n := range names {
			root.RemoveAll(n)
		}
		if err != nil {
			break
		}
	}
	d.Close()
	os.Remove(tmp)
}

// writeMarker creates the empty marker .incomplete in the new temporary
// directory that root holds.
func writeMarker(root *os.Root) error {
	f, err := root.OpenFile(incompleteMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// replaceDir renames tmp, the directory that root holds and made
// identifies, to dir under lockOnlyDir; errDirNotEmpty if dir is a
// directory that is not empty. Before lockOnlyDir, and again right
// before the rename, it checks that tmp still names that directory
// (sameDir, task 20l point 1). Before the second check it removes the
// marker through root (gone already on the second try) and syncs the
// directory.
func replaceDir(root *os.Root, made fs.FileInfo, tmp, dir, kind string) error {
	if err := sameDir(tmp, made); err != nil {
		return err
	}
	release, err := lockOnlyDir(dir)
	if err != nil {
		return err
	}
	defer release()
	if err := dirStep(kind, "locked"); err != nil {
		return err
	}
	if err := root.Remove(incompleteMarker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := store.SyncRoot(root); err != nil {
		return err
	}
	if err := sameDir(tmp, made); err != nil {
		return err
	}
	// syscall.Rename, because os.Rename refuses every existing directory
	// as target; rename(2) replaces an empty one and refuses any other.
	if err := syscall.Rename(tmp, dir); err != nil {
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			return errDirNotEmpty
		}
		return &os.LinkError{Op: "rename", Old: tmp, New: dir, Err: err}
	}
	return nil
}

// lockOnlyDir prepares an existing directory dir for the rename of
// createClientDir. Open creates the client directory and its lock file
// before it finds that no user exists (ErrNotRegistered), so a client
// directory that holds only the regular file lock counts as empty: under
// that lock the file is removed and the rename replaces the then empty
// directory; release ends the lock. A directory with any other entry is
// left alone, and the rename refuses it. The directory is opened with
// store.OpenDir (task 20e point 4). The lock is taken by lockClientDir,
// so the file removed is the one locked (task 20h point 5). The content
// of lock is not checked (L2 of the review of task 20b): any regular
// file of that name is taken for the lock file of Open and removed while
// nobody holds a lock on it; that takes write access to the directory,
// which allows removing it anyway.
func lockOnlyDir(dir string) (release func(), err error) {
	release = func() {}
	ents, ok, err := lookAtDir(dir)
	if err != nil || !ok || !onlyLock(ents) {
		return release, err
	}
	lock := filepath.Join(dir, "lock")
	unlock, err := lockClientDir(lock)
	if err != nil {
		return release, err
	}
	if err := os.Remove(lock); err != nil {
		unlock()
		return release, err
	}
	return unlock, nil
}

// lookAtDir reads up to two entries of dir for lockOnlyDir and
// dirTaken; ok is false, and err nil, if dir is missing or not a
// directory (os.Lstat).
func lookAtDir(dir string) (ents []os.DirEntry, ok bool, err error) {
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return nil, false, nil
	}
	d, err := store.OpenDir(dir)
	if err != nil {
		return nil, false, err
	}
	ents, _ = d.ReadDir(2)
	d.Close()
	return ents, true, nil
}

// onlyLock reports whether ents is the regular file lock alone.
func onlyLock(ents []os.DirEntry) bool {
	return len(ents) == 1 && ents[0].Name() == "lock" && ents[0].Type().IsRegular()
}

// dirTaken reports whether dir is a directory that the rename of
// createClientDir would refuse as not empty, as lockOnlyDir sees it: one
// with an entry other than the regular file lock alone. A directory that
// cannot be read counts as not taken (createClientDir then keeps the
// error of its own step).
//
// One case is reported wrongly (F1 of the attack review of task 20i,
// kept in task 20l): someone who can write the parent of dir and renames
// the temporary directory of a run onto a missing dir makes that run
// fail with "not empty or in use by another client" (errInUse), although
// dir then holds the run's own files (written through the descriptor;
// after the lock step without the marker). Nothing is lost: a second run
// refuses the directory with the key store (ErrRegistered).
func dirTaken(dir string) bool {
	ents, ok, err := lookAtDir(dir)
	return err == nil && ok && len(ents) > 0 && !onlyLock(ents)
}

// leftoverBatch is the number of names read from a directory at a time
// (removeLeftovers).
const leftoverBatch = 256

// removeLeftovers removes the temporary directories prefix<digits> in
// parent that a run of the same kind for the same client directory left
// behind when it was killed before its rename (createClientDir; task 20e
// point 3, task 20h points 4 and 7): only names in which the digits of
// os.MkdirTemp follow prefix, only directories (a symbolic link is
// neither followed nor removed), owned by the user of this process
// (ownedByMe), last changed before start, the time of the file system
// when this run made its own, and holding the marker .incomplete as a
// regular file. In such a directory only the files a run writes there
// are removed (leftoverFile), the marker last, and then the directory
// itself, which fails if anything else is left; a directory with another
// entry keeps that entry and its marker. A renamed client directory has
// no marker and stays whole. A run of the same kind that is still under
// way and loses its temporary directory this way fails with
// store.ErrExists, "not empty or in use by another client" (errInUse;
// its client directory is taken by now, unless it was removed again).
// Errors are ignored: this run has succeeded, and what is left is
// removed by a later one.
func removeLeftovers(parent, prefix string, start time.Time) {
	d, err := store.OpenDir(parent)
	if err != nil {
		return
	}
	defer d.Close()
	for {
		names, err := d.Readdirnames(leftoverBatch)
		for _, n := range names {
			if !strings.HasPrefix(n, prefix) || !mkdirTempDigits(n[len(prefix):]) {
				continue
			}
			p := filepath.Join(parent, n)
			fi, err := os.Lstat(p)
			if err != nil || !fi.IsDir() || !ownedByMe(fi) || !fi.ModTime().Before(start) {
				continue
			}
			removeLeftover(p)
		}
		if err != nil {
			return
		}
	}
}

// removeLeftover removes the leftover temporary directory p if it holds
// the marker: the files a run writes there, the marker last and then p.
func removeLeftover(p string) {
	marker := filepath.Join(p, incompleteMarker)
	if fi, err := os.Lstat(marker); err != nil || !fi.Mode().IsRegular() {
		return
	}
	d, err := store.OpenDir(p)
	if err != nil {
		return
	}
	defer d.Close()
	other := false
	for {
		names, err := d.Readdirnames(leftoverBatch)
		for _, n := range names {
			if n == incompleteMarker {
				continue
			}
			f := filepath.Join(p, n)
			if fi, lerr := os.Lstat(f); lerr != nil || fi.IsDir() || !leftoverFile(n) {
				other = true
				continue
			}
			if os.Remove(f) != nil {
				other = true
			}
		}
		if err != nil {
			break
		}
	}
	if other {
		return
	}
	if os.Remove(marker) == nil {
		os.Remove(p)
	}
}

// leftoverFile reports whether name is a file that createClientDir or
// its atomic writers make in a temporary directory: key store, user.rec,
// state.json and the temporary files of store.WritePrivateFileAtomicIn
// (.tmp-<16 hex digits>) and of keys.WriteKeystoreFile, which wrote the
// key store before task 20l (.keystore-<digits>.tmp). The marker is
// handled by removeLeftover.
func leftoverFile(name string) bool {
	switch name {
	case "keystore", "user.rec", "state.json":
		return true
	}
	if h, ok := strings.CutPrefix(name, ".tmp-"); ok {
		if len(h) != 16 {
			return false
		}
		for _, c := range h {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
		return true
	}
	if r, ok := strings.CutPrefix(name, ".keystore-"); ok {
		if n, ok := strings.CutSuffix(r, ".tmp"); ok {
			return mkdirTempDigits(n)
		}
	}
	return false
}

// mkdirTempDigits reports whether s is a random part of os.MkdirTemp and
// os.CreateTemp: one to ten decimal digits (a uint32).
func mkdirTempDigits(s string) bool {
	if len(s) < 1 || len(s) > 10 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// showAndConfirm shows the 24 words of seed through p and asks three
// randomly chosen ones back (2.2); ErrConfirm if one differs.
func showAndConfirm(seed *keys.Seed, p Prompter) error {
	words, err := seed.Words()
	if err != nil {
		return err
	}
	defer func() {
		for i := range words {
			words[i] = ""
		}
	}()
	if err := p.ShowWords(words); err != nil {
		return err
	}
	positions, err := choosePositions(len(words), ConfirmWords)
	if err != nil {
		return err
	}
	for _, pos := range positions {
		got, err := p.AskWord(pos + 1)
		if err != nil {
			return err
		}
		// The answer is normalized like every word input (2.2 "Eingabe
		// von Wörtern", S11) and must then be exactly the word.
		w, err := oneWord(got)
		if err != nil {
			return fmt.Errorf("%w: position %d: %w", ErrConfirm, pos+1, err)
		}
		if subtle.ConstantTimeCompare([]byte(w), []byte(words[pos])) != 1 {
			return ErrConfirm
		}
	}
	return nil
}

// checkShares checks a split k-of-n before any secret exists.
func checkShares(s Shares) error {
	if s.Threshold < 2 || s.Count < s.Threshold || s.Count > 255 {
		return fmt.Errorf("%w: shares %d-of-%d: %w", ErrArgument, s.Threshold, s.Count, shamir.ErrParams)
	}
	return nil
}

// showShares splits seed into s.Count shares of which s.Threshold rebuild
// it (shamir.Split, randomness from crypto/rand), checks that the first
// s.Threshold of them do, shows them as words through p and wipes them.
func showShares(seed *keys.Seed, s Shares, p SharePrompter) error {
	shares, err := shamir.Split(seed[:], s.Threshold, s.Count, nil)
	if err != nil {
		return err
	}
	defer func() {
		for _, sh := range shares {
			sh.Zero()
		}
	}()
	back, err := shamir.Combine(shares[:s.Threshold])
	if err != nil {
		return err
	}
	same := subtle.ConstantTimeCompare(back, seed[:]) == 1
	keys.Wipe(back)
	if !same {
		return fmt.Errorf("client: the shares do not rebuild the seed")
	}
	out := make([][]string, len(shares))
	defer func() {
		for _, w := range out {
			clear(w)
		}
	}()
	for i, sh := range shares {
		out[i] = sh.Words()
	}
	return p.ShowShares(out)
}

// choosePositions draws k distinct positions below n from crypto/rand.
func choosePositions(n, k int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for len(out) < k {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return nil, err
		}
		if p := int(v.Int64()); !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

// Register publishes the user created by Keygen (2.2). The user entry
// of generation 1 is the first entry of the user ID in the log, bound to
// nothing but its own content, so the order is (translog doc.go "Who
// writes", findings 03c-1 and 03d-5): the record is the user.rec that
// Keygen keeps in the client directory (step 1); the invitation is
// consumed (store.ConsumeInvite, a code never registers two users) and
// right after it InviteUsed is set in state.json; the user.rec is
// appended to the log (step 2, Append is idempotent) and its pending
// entry kept in state.json; only then users/<id>/user.rec is written to
// the data directory (step 3, store.EnsureUser) and Registered is set.
// A Register run again after a crash skips ConsumeInvite once InviteUsed
// is set and continues with step 2. ErrDuplicate means that somebody
// else logged the user ID first: Register stops before step 3. The error
// names the whole remedy (task 14b point 10): the client directory holds
// a user that can never be registered and the invitation is used up, so
// the user deletes the client directory, runs keygen again (a new ID
// needs a user.rec signed by the root, which exists only during keygen;
// Keygen refuses a directory with a key store, ErrRegistered, so that it
// never overwrites the keys of a user that may be registered) and
// registers with a new invitation code.
func Register(cfg Config, code store.ID) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if _, err := os.Stat(cfg.statePath()); err != nil {
		return store.ID{}, ErrNotRegistered
	}
	unlock, err := lockClientDir(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return store.ID{}, err
	}
	defer unlock()
	st, err := loadState(cfg.statePath())
	if err != nil {
		return store.ID{}, err
	}
	if st.UserID == "" {
		return store.ID{}, ErrNotRegistered
	}
	if st.Registered {
		return store.ID{}, ErrRegistered
	}
	data, err := store.ReadFileLimited(cfg.userPath(), store.MaxUserFile)
	if err != nil {
		return store.ID{}, ErrNotRegistered
	}
	user, err := store.DecodeUser(data)
	if err != nil {
		return store.ID{}, err
	}
	if len(user.Generations) != 1 {
		return store.ID{}, ErrNotRegistered
	}
	if _, err := os.Lstat(cfg.Store.UserFile(user.ID)); err == nil && !st.InviteUsed {
		return store.ID{}, fmt.Errorf("client: user ID already taken: %w", store.ErrExists)
	}
	if !st.InviteUsed {
		if err := cfg.Store.ConsumeInvite(code); err != nil {
			return store.ID{}, err
		}
		st.InviteUsed = true
		if err := saveState(cfg.statePath(), st); err != nil {
			return store.ID{}, err
		}
	}
	if crash("register-invite") {
		return store.ID{}, errCrashed
	}
	lc, err := openLog(&cfg, st, false)
	if err != nil {
		return store.ID{}, err
	}
	defer lc.close()
	if _, err := lc.appendRecord(translog.KindUser, data); err != nil {
		if errors.Is(err, translog.ErrDuplicate) {
			return store.ID{}, fmt.Errorf("client: the user ID is already taken in the transparency log, so this client directory can never be registered and its invitation code is used up; delete the client directory %s, run keygen again and register with a new invitation code: %w", cfg.Dir, err)
		}
		return store.ID{}, err
	}
	if crash("register-logged") {
		return store.ID{}, errCrashed
	}
	if err := cfg.Store.EnsureUser(user); err != nil {
		if errors.Is(err, store.ErrExists) {
			return store.ID{}, fmt.Errorf("client: user ID already taken: %w", err)
		}
		return store.ID{}, err
	}
	st.Registered = true
	if err := saveState(cfg.statePath(), st); err != nil {
		return store.ID{}, err
	}
	return user.ID, nil
}
