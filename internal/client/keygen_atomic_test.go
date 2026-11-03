package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 20b point 1: keygen creates the client directory in one
// step (temporary directory, fsync, rename, fsync of the parent).

// keygenSteps are the write steps of Keygen and Restore in their order
// (dirStep).
var keygenSteps = []string{"dir", "user", "keystore", "state", "locked", "renamed"}

// clientFiles are the files of a complete client directory after keygen.
var clientFiles = []string{"keystore", "user.rec", "state.json"}

// checkClientDir fails unless dir is absent (complete false) or a
// complete client directory with mode 0700 and without the marker
// .incomplete (complete true).
func checkClientDir(t *testing.T, dir string, complete bool) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if !complete {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("client directory after an interrupted keygen: %v", err)
		}
		return
	}
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("client directory: %v %v", fi, err)
	}
	for _, f := range clientFiles {
		if fi, err := os.Lstat(filepath.Join(dir, f)); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: %v", f, err)
		}
	}
	// The marker of the temporary directory is gone (task 20h point 4).
	if _, err := os.Lstat(filepath.Join(dir, ".incomplete")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker in the client directory: %v", err)
	}
}

// keygenTemps returns the temporary directories of keygen next to dir.
func keygenTemps(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+".keygen-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestKeygenAtomic: keygen interrupted after every write step, by a
// failed write (clientDirFault, cleaned up) or by a kill (crash hook, no
// cleanup), leaves either no client directory or a complete one. After
// a failed write nothing is left, not even the temporary directory; a
// kill before the rename leaves at most the temporary directory, which
// no client reads and the next successful keygen removes (task 20e
// point 3). A second keygen then succeeds, or, after the rename,
// refuses the complete directory (ErrRegistered), which registers and
// opens.
func TestKeygenAtomic(t *testing.T) {
	env := testenv.New(t)
	fault := errors.New("injected fault")
	for _, kill := range []bool{false, true} {
		for _, step := range keygenSteps {
			name := "fault-" + step
			if kill {
				name = "kill-" + step
			}
			t.Run(name, func(t *testing.T) {
				dir := filepath.Join(env.Base, name)
				cfg := env.ClientConfig(dir)
				if kill {
					client.SetCrashHook(t, func(p string) bool { return p == "keygen-"+step })
				} else {
					client.SetClientDirFault(t, func(s string) error {
						if s == "keygen-"+step {
							return fault
						}
						return nil
					})
				}
				_, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
				client.SetCrashHook(t, nil)
				client.SetClientDirFault(t, nil)
				want := fault
				if kill {
					want = client.ErrCrashed
				}
				if !errors.Is(err, want) {
					t.Fatalf("keygen interrupted at %s: %v, want %v", step, err, want)
				}
				complete := step == "renamed"
				checkClientDir(t, dir, complete)
				wantTemps := 0
				if kill && !complete {
					wantTemps = 1
				}
				temps := keygenTemps(t, dir)
				if len(temps) != wantTemps {
					t.Fatalf("temporary directories after %s: %v", name, temps)
				}
				// The leftover of the killed run is older than the next
				// run (task 20e point 3), also on a file system with
				// coarse times.
				for _, p := range temps {
					if err := os.Chtimes(p, past, past); err != nil {
						t.Fatal(err)
					}
				}
				id, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
				if complete {
					if !errors.Is(err, client.ErrRegistered) {
						t.Fatalf("second keygen over a complete directory: %v", err)
					}
				} else if err != nil {
					t.Fatalf("second keygen after %s: %v", name, err)
				}
				checkClientDir(t, dir, true)
				if temps := keygenTemps(t, dir); len(temps) != 0 {
					t.Fatalf("temporary directories after the second keygen: %v", temps)
				}
				code, err := env.Store.CreateInvite(0)
				if err != nil {
					t.Fatal(err)
				}
				got, err := client.Register(cfg, code)
				if err != nil {
					t.Fatalf("register after %s: %v", name, err)
				}
				if !complete && got != id {
					t.Fatalf("registered %s, keygen made %s", got, id)
				}
				c, err := client.Open(cfg, testenv.Passphrase)
				if err != nil {
					t.Fatalf("open after %s: %v", name, err)
				}
				c.Close()
			})
		}
	}
}

// TestKeygenExistingDir: keygen replaces an existing empty client
// directory and one that holds only the lock file Open leaves when it
// finds no user, but not while that lock is held; it follows a symbolic
// link as before; a directory with any other entry is refused
// (store.ErrExists) and kept as it was.
func TestKeygenExistingDir(t *testing.T) {
	env := testenv.New(t)
	keygen := func(dir string) error {
		_, err := client.Keygen(env.ClientConfig(dir), testenv.Passphrase, &testenv.Echo{})
		return err
	}

	empty := filepath.Join(env.Base, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := keygen(empty); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, empty, true)

	opened := filepath.Join(env.Base, "opened")
	if _, err := client.Open(env.ClientConfig(opened), testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatalf("open before keygen: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(opened, "lock")); err != nil {
		t.Fatalf("open leaves no lock file: %v", err)
	}
	if err := keygen(opened); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, opened, true)

	held := filepath.Join(env.Base, "held")
	if err := os.Mkdir(held, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := store.LockFile(filepath.Join(held, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := keygen(held); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("keygen beside a held lock: %v", err)
	}
	unlock()
	if _, err := os.Lstat(filepath.Join(held, "lock")); err != nil {
		t.Fatalf("lock file of a held lock removed: %v", err)
	}
	if temps := keygenTemps(t, held); len(temps) != 0 {
		t.Fatalf("temporary directories left: %v", temps)
	}

	target := filepath.Join(env.Base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(env.Base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := keygen(link); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, target, true)
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symbolic link replaced: %v %v", fi, err)
	}

	full := filepath.Join(env.Base, "full")
	if err := os.Mkdir(full, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(full, "notes")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keygen(full); !errors.Is(err, store.ErrExists) {
		t.Fatalf("keygen into a directory with entries: %v", err)
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != "x" {
		t.Fatalf("entry of a refused directory changed: %q %v", b, err)
	}
	for _, f := range clientFiles {
		if _, err := os.Lstat(filepath.Join(full, f)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written into a refused directory", f)
		}
	}
	if temps := keygenTemps(t, full); len(temps) != 0 {
		t.Fatalf("temporary directories left: %v", temps)
	}
}
