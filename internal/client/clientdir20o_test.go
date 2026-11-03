package client_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 20o (L2 to L5 of the review of the client directories).

// TestIncompleteDirRefused (point 1): Open, Register and DeviceLost
// refuse the temporary directory of an unfinished keygen or restore,
// which holds the marker .incomplete (of any type), with a fixed error,
// and write nothing into it, not even the lock file. The temporary
// directory of a restore holds a state.json with a registered user.
func TestIncompleteDirRefused(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	code, err := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	killed := func(t *testing.T, kind string) string {
		t.Helper()
		dir := filepath.Join(env.Base, kind)
		cfg := env.ClientConfig(dir)
		client.SetCrashHook(t, func(p string) bool { return p == kind+"-state" })
		var err error
		if kind == "keygen" {
			_, err = client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
		} else {
			_, err = client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
		}
		client.SetCrashHook(t, nil)
		if !errors.Is(err, client.ErrCrashed) {
			t.Fatalf("killed %s: %v", kind, err)
		}
		temps := tempDirs(t, dir, kind)
		if len(temps) != 1 {
			t.Fatalf("temporary directories of the killed %s: %v", kind, temps)
		}
		return temps[0]
	}
	check := func(t *testing.T, tmp string) {
		t.Helper()
		before := entries(t, tmp)
		cfg := env.ClientConfig(tmp)
		if c, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrIncompleteDir) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("Open: %v", err)
		}
		if _, err := client.Register(cfg, code); !errors.Is(err, client.ErrIncompleteDir) {
			t.Fatalf("Register: %v", err)
		}
		if _, err := client.DeviceLost(cfg, testenv.Passphrase, u.Words); !errors.Is(err, client.ErrIncompleteDir) {
			t.Fatalf("DeviceLost: %v", err)
		}
		if got := entries(t, tmp); !slices.Equal(got, before) {
			t.Fatalf("temporary directory changed: %v, was %v", got, before)
		}
	}
	for _, kind := range []string{"keygen", "restore"} {
		t.Run(kind, func(t *testing.T) {
			tmp := killed(t, kind)
			if got := strings.Join(entries(t, tmp), " "); got != ".incomplete keystore state.json user.rec" {
				t.Fatalf("temporary directory: %s", got)
			}
			check(t, tmp)
			// A marker that is no regular file is refused as well.
			marker := filepath.Join(tmp, ".incomplete")
			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(marker, 0o700); err != nil {
				t.Fatal(err)
			}
			check(t, tmp)
		})
	}
	// The invitation code was not consumed: a new user registers with it.
	cfg := env.ClientConfig(filepath.Join(env.Base, "bob"))
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(cfg, code); err != nil {
		t.Fatalf("Register with the code offered to the temporary directories: %v", err)
	}
}

// TestLeftoverAllOrNothing (point 1): a successful keygen removes a
// leftover with the marker only if every other entry is a file a run
// writes there; a leftover with any other entry, also one read only after
// the first batch of names, keeps every entry, its key store included.
func TestLeftoverAllOrNothing(t *testing.T) {
	env := testenv.New(t)
	parent := filepath.Join(env.Base, "devices")
	at := func(name string) string { return filepath.Join(parent, name) }
	clean := at(".bob.keygen-55")
	writeFiles(t, clean, ".incomplete", "keystore", "user.rec", "state.json", ".tmp-0123456789abcdef")
	mixed := at(".bob.keygen-56")
	writeFiles(t, mixed, ".incomplete", "keystore", "user.rec", "state.json", "notes")
	withDir := at(".bob.keygen-57")
	writeFiles(t, withDir, ".incomplete", "keystore", "user.rec")
	if err := os.Mkdir(filepath.Join(withDir, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	many := at(".bob.keygen-58")
	names := []string{".incomplete", "keystore", "zz-notes"}
	for i := range 600 {
		names = append(names, fmt.Sprintf(".tmp-%016x", i))
	}
	writeFiles(t, many, names...)
	keep := map[string][]string{}
	for _, p := range []string{mixed, withDir, many} {
		keep[p] = entries(t, p)
	}
	for _, p := range []string{clean, mixed, withDir, many} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := client.Keygen(env.ClientConfig(at("bob")), testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, at("bob"), true)
	if _, err := os.Lstat(clean); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover with only the files of a run: %v %v", err, entries(t, clean))
	}
	for p, want := range keep {
		if got := entries(t, p); !slices.Equal(got, want) {
			t.Fatalf("%s: %d entries, want %d", filepath.Base(p), len(got), len(want))
		}
	}
}

// swapPrompter answers like testenv.Echo and calls swap when it shows
// the words, after Config.check and before the client directory is made.
type swapPrompter struct {
	testenv.Echo
	swap func() error
}

func (p *swapPrompter) ShowWords(w []string) error {
	if err := p.swap(); err != nil {
		return err
	}
	return p.Echo.ShowWords(w)
}

// TestClientDirLinkIntoDataDir (point 3): a client directory named
// through a symbolic link into the data directory, at the directory
// itself or at a parent, is inside it for Config.check (keygen, restore,
// Open, Register, DeviceLost); and keygen and restore check again after
// they resolved a symbolic link at the client directory that was changed
// to point into the data directory after Config.check. Nothing is created
// in the data directory.
func TestClientDirLinkIntoDataDir(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	work := filepath.Join(env.Store.Root, "work")
	inside := filepath.Join(work, "client")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	before := entries(t, work)
	links := filepath.Join(env.Base, "links")
	if err := os.Mkdir(links, 0o700); err != nil {
		t.Fatal(err)
	}
	direct := filepath.Join(links, "direct")
	if err := os.Symlink(inside, direct); err != nil {
		t.Fatal(err)
	}
	toRoot := filepath.Join(links, "root")
	if err := os.Symlink(env.Store.Root, toRoot); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{direct, toRoot, filepath.Join(toRoot, "work", "new"), filepath.Join(toRoot, "missing", "client")} {
		cfg := env.ClientConfig(dir)
		if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("keygen in %s: %v", dir, err)
		}
		if _, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("restore in %s: %v", dir, err)
		}
		if c, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrInsideDataDir) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("open in %s: %v", dir, err)
		}
		if _, err := client.Register(cfg, store.ID{}); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("register in %s: %v", dir, err)
		}
		if _, err := client.DeviceLost(cfg, testenv.Passphrase, u.Words); !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("device lost in %s: %v", dir, err)
		}
	}

	// The link at the client directory points outside at Config.check and
	// into the data directory when keygen or restore makes the directory:
	// keygen swaps it when it shows the words, restore when it opens the
	// client log (SetLogHook), both after Config.check.
	for _, kind := range []string{"keygen", "restore"} {
		outside := filepath.Join(env.Base, "outside-"+kind)
		if err := os.Mkdir(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		swapped := filepath.Join(links, "swapped-"+kind)
		if err := os.Symlink(outside, swapped); err != nil {
			t.Fatal(err)
		}
		swaps := 0
		swap := func() error {
			swaps++
			if err := os.Remove(swapped); err != nil {
				return err
			}
			return os.Symlink(inside, swapped)
		}
		var err error
		if kind == "keygen" {
			_, err = client.Keygen(env.ClientConfig(swapped), testenv.Passphrase, &swapPrompter{swap: swap})
		} else {
			client.SetLogHook(t, func(l translog.Log) translog.Log {
				if swaps == 0 {
					if err := swap(); err != nil {
						t.Error(err)
					}
				}
				return l
			})
			_, err = client.Restore(env.ClientConfig(swapped), client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
			client.SetLogHook(t, nil)
		}
		if swaps != 1 || !errors.Is(err, client.ErrInsideDataDir) {
			t.Fatalf("%s through a link swapped into the data directory (%d swaps): %v", kind, swaps, err)
		}
		if got := entries(t, work); !slices.Equal(got, before) {
			t.Fatalf("data directory work/ after %s: %v, was %v", kind, got, before)
		}
		if got := entries(t, inside); len(got) != 0 {
			t.Fatalf("directory in the data directory after %s: %v", kind, got)
		}
		if got := entries(t, outside); len(got) != 0 {
			t.Fatalf("directory outside after %s: %v", kind, got)
		}
	}
}

// TestNotDurableAfterRename (point 4): a keygen or restore that fails
// after the rename only in the sync of the parent (the injected fault of
// step renamed stands for it) reports errNotDurable with its cause, not
// the text of errTempReplaced; the client directory is complete and
// works. A simulated crash at that step stays errCrashed.
func TestNotDurableAfterRename(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	fault := errors.New("injected fault")
	replaced := client.ErrTempReplaced.Error()
	for _, kind := range []string{"keygen", "restore"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(env.Base, "durable-"+kind)
			cfg := env.ClientConfig(dir)
			client.SetClientDirFault(t, func(s string) error {
				if s == kind+"-renamed" {
					return fault
				}
				return nil
			})
			var err error
			if kind == "keygen" {
				_, err = client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
			} else {
				_, err = client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
			}
			client.SetClientDirFault(t, nil)
			if !errors.Is(err, client.ErrNotDurable) || !errors.Is(err, fault) || errors.Is(err, client.ErrTempReplaced) || strings.Contains(err.Error(), replaced) {
				t.Fatalf("%s with a failed sync after the rename: %v", kind, err)
			}
			if !strings.Contains(err.Error(), dir) {
				t.Fatalf("error does not name the client directory: %v", err)
			}
			checkClientDir(t, dir, true)
			if kind == "keygen" {
				code, err := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Register(cfg, code); err != nil {
					t.Fatal(err)
				}
			}
			c, err := client.Open(cfg, testenv.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		})
	}
	dir := filepath.Join(env.Base, "crashed")
	client.SetCrashHook(t, func(p string) bool { return p == "keygen-renamed" })
	_, err := client.Keygen(env.ClientConfig(dir), testenv.Passphrase, &testenv.Echo{})
	client.SetCrashHook(t, nil)
	if !errors.Is(err, client.ErrCrashed) || errors.Is(err, client.ErrNotDurable) {
		t.Fatalf("keygen killed after the rename: %v", err)
	}
	checkClientDir(t, dir, true)
}

// TestAfterRename (point 4): a lookup of the client directory right
// after the rename that finds another directory or nothing is reported
// with the text of errTempReplaced; any other error of the lookup is
// errNotDurable with its cause.
func TestAfterRename(t *testing.T) {
	const dir = "/clients/alice"
	swapped := fmt.Errorf("%w: %s", client.ErrTempReplaced, dir)
	if err := client.AfterRename(dir, swapped); err != swapped {
		t.Fatalf("another directory at dir: %v", err)
	}
	missing := &fs.PathError{Op: "lstat", Path: dir, Err: syscall.ENOENT}
	if err := client.AfterRename(dir, missing); !errors.Is(err, client.ErrTempReplaced) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, client.ErrNotDurable) {
		t.Fatalf("missing dir: %v", err)
	}
	for _, e := range []syscall.Errno{syscall.EACCES, syscall.EIO, syscall.ENOTDIR, syscall.ELOOP} {
		other := &fs.PathError{Op: "lstat", Path: dir, Err: e}
		err := client.AfterRename(dir, other)
		if !errors.Is(err, client.ErrNotDurable) || !errors.Is(err, e) || errors.Is(err, client.ErrTempReplaced) || strings.Contains(err.Error(), client.ErrTempReplaced.Error()) {
			t.Fatalf("lookup failed with %v: %v", e, err)
		}
	}
}

// TestHeldLockInUse (point 2): keygen and restore on a client directory
// that holds only the lock file while another client holds its lock fail
// like on a directory that is not empty ("not empty or in use by another
// client", store.ErrExists), and errors.Is still matches store.ErrLocked;
// the lock file stays and no temporary directory is left.
func TestHeldLockInUse(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	runs := map[string]func(cfg client.Config) error{
		"keygen": func(cfg client.Config) error {
			_, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
			return err
		},
		"restore": func(cfg client.Config) error {
			_, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
			return err
		},
	}
	for kind, run := range runs {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(env.Base, "held-"+kind)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			unlock, err := store.LockFile(filepath.Join(dir, "lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			err = run(env.ClientConfig(dir))
			if !errors.Is(err, store.ErrLocked) || !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), "is not empty or in use by another client") {
				t.Fatalf("%s beside a held lock: %v", kind, err)
			}
			if got := strings.Join(entries(t, dir), " "); got != "lock" {
				t.Fatalf("client directory: %s", got)
			}
			if temps := tempDirs(t, dir, kind); len(temps) != 0 {
				t.Fatalf("temporary directories left: %v", temps)
			}
		})
	}
}
