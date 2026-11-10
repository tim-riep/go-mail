package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 20e points 2 to 4: Restore creates the client directory
// in one step like keygen, a successful keygen or restore removes the
// temporary directories that earlier runs of its kind left behind, and
// keygen tries the rename once more when an Open of the same directory
// made its lock file again.

// past is a fixed time long before any run of a test (os.Chtimes).
var past = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// tempDirs returns the temporary directories of a run of kind (keygen,
// restore) next to dir.
func tempDirs(t *testing.T, dir, kind string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+"."+kind+"-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestRestoreAtomic: Restore interrupted after every write step, by a
// failed write (cleaned up) or by a kill (crash hook, no cleanup), leaves
// either no client directory or a complete one, as keygen does
// (TestKeygenAtomic). A kill before the rename leaves at most the
// temporary directory, which the next successful Restore removes. A
// second Restore succeeds, or, after the rename, refuses the complete
// directory (ErrRegistered); the client opens.
func TestRestoreAtomic(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	fault := errors.New("injected fault")
	restore := func(cfg client.Config) error {
		_, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
		return err
	}
	for _, kill := range []bool{false, true} {
		for _, step := range keygenSteps {
			name := "fault-" + step
			if kill {
				name = "kill-" + step
			}
			t.Run(name, func(t *testing.T) {
				dir := filepath.Join(env.Base, "restored", name)
				cfg := env.ClientConfig(dir)
				if kill {
					client.SetCrashHook(t, func(p string) bool { return p == "restore-"+step })
				} else {
					client.SetClientDirFault(t, func(s string) error {
						if s == "restore-"+step {
							return fault
						}
						return nil
					})
				}
				err := restore(cfg)
				client.SetCrashHook(t, nil)
				client.SetClientDirFault(t, nil)
				want := fault
				if kill {
					want = client.ErrCrashed
				}
				if !errors.Is(err, want) {
					t.Fatalf("restore interrupted at %s: %v, want %v", step, err, want)
				}
				complete := step == "renamed"
				checkClientDir(t, dir, complete)
				temps := tempDirs(t, dir, "restore")
				wantTemps := 0
				if kill && !complete {
					wantTemps = 1
				}
				if len(temps) != wantTemps {
					t.Fatalf("temporary directories after %s: %v", name, temps)
				}
				for _, p := range temps {
					if err := os.Chtimes(p, past, past); err != nil {
						t.Fatal(err)
					}
				}
				err = restore(cfg)
				if complete {
					if !errors.Is(err, client.ErrRegistered) {
						t.Fatalf("second restore over a complete directory: %v", err)
					}
				} else if err != nil {
					t.Fatalf("second restore after %s: %v", name, err)
				}
				checkClientDir(t, dir, true)
				if temps := tempDirs(t, dir, "restore"); len(temps) != 0 {
					t.Fatalf("temporary directories after the second restore: %v", temps)
				}
				c, err := client.Open(cfg, testenv.Passphrase)
				if err != nil {
					t.Fatalf("open after %s: %v", name, err)
				}
				c.Close()
			})
		}
	}

	// A directory that holds only the lock file of Open is replaced; one
	// with any other entry is refused and kept.
	opened := filepath.Join(env.Base, "restored", "opened")
	if _, err := client.Open(env.ClientConfig(opened), testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
		t.Fatalf("open before restore: %v", err)
	}
	if err := restore(env.ClientConfig(opened)); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, opened, true)
	full := filepath.Join(env.Base, "restored", "full")
	if err := os.MkdirAll(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "notes"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restore(env.ClientConfig(full)); !errors.Is(err, store.ErrExists) {
		t.Fatalf("restore into a directory with entries: %v", err)
	}
	for _, f := range clientFiles {
		if _, err := os.Lstat(filepath.Join(full, f)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written into a refused directory", f)
		}
	}
	if temps := tempDirs(t, full, "restore"); len(temps) != 0 {
		t.Fatalf("temporary directories left: %v", temps)
	}
}

// TestClientDirLeftovers (task 20e point 3; names and marker after task
// 20h points 4 and 7): a successful keygen removes the directories
// .<name>.keygen-<digits> with the marker .incomplete next to its client
// directory that were last changed before its run and belong to the user
// of the process, and nothing else: not a newer one, not a symbolic link (nor what it
// names), not a regular file, not the temporary directory of a restore
// or of another client directory, not one of another user. A successful
// restore removes .<name>.restore-* in the same way and keeps
// .<name>.keygen-*. A failed run removes nothing. The directory of
// another user needs uid 0 with CAP_CHOWN; without it only that part is
// left out (task 26, package 26D, point 3).
func TestClientDirLeftovers(t *testing.T) {
	env := testenv.New(t)
	parent := filepath.Join(env.Base, "devices")
	mkdir := func(p string, at time.Time) {
		t.Helper()
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"keystore", ".incomplete"} {
			if err := os.WriteFile(filepath.Join(p, f), []byte("sealed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(p string, want bool) {
		t.Helper()
		if _, err := os.Lstat(p); (err == nil) != want {
			t.Fatalf("%s: exists %v, want %v", filepath.Base(p), err == nil, want)
		}
	}
	at := func(name string) string { return filepath.Join(parent, name) }

	mkdir(at(".alice.keygen-1001"), past)
	// A time after this run that a 32-bit time_t holds (GOARCH=386).
	mkdir(at(".alice.keygen-1002"), time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC))
	mkdir(at("victim"), past)
	if err := os.Symlink(at("victim"), at(".alice.keygen-1003")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(at(".alice.keygen-1004"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(at(".alice.keygen-1004"), past, past); err != nil {
		t.Fatal(err)
	}
	mkdir(at(".alice.restore-1005"), past)
	mkdir(at(".bob.keygen-1006"), past)
	mkdir(at(".alicex.keygen-1007"), past)
	foreign := os.Geteuid() == 0
	if foreign {
		mkdir(at(".alice.keygen-1008"), past)
		if err := os.Chown(at(".alice.keygen-1008"), 4242, 4242); errors.Is(err, syscall.EPERM) {
			// Root without CAP_CHOWN (setpriv --inh-caps=-all
			// --bounding-set=-all): the directory of another user
			// cannot be made. Only that part is left out (task 26,
			// package 26D, point 3, backlog item 79); the directory, owned
			// by the process itself, is removed again.
			t.Logf("uid 0 without CAP_CHOWN, no directory of another user: %v", err)
			foreign = false
			if err := os.RemoveAll(at(".alice.keygen-1008")); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}

	// A failed keygen removes nothing.
	dir := at("alice")
	cfg := env.ClientConfig(dir)
	fault := errors.New("injected fault")
	client.SetClientDirFault(t, func(s string) error {
		if s == "keygen-state" {
			return fault
		}
		return nil
	})
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, fault) {
		t.Fatalf("keygen with a fault: %v", err)
	}
	client.SetClientDirFault(t, nil)
	exists(at(".alice.keygen-1001"), true)

	echo := &testenv.Echo{}
	if _, err := client.Keygen(cfg, testenv.Passphrase, echo); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, dir, true)
	exists(at(".alice.keygen-1001"), false)
	exists(at(".alice.keygen-1002"), true)
	exists(at(".alice.keygen-1003"), true)
	exists(filepath.Join(at("victim"), "keystore"), true)
	exists(at(".alice.keygen-1004"), true)
	exists(at(".alice.restore-1005"), true)
	exists(at(".bob.keygen-1006"), true)
	exists(at(".alicex.keygen-1007"), true)
	if foreign {
		exists(filepath.Join(at(".alice.keygen-1008"), "keystore"), true)
	}
	code, err := env.Store.CreateInvite(env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(cfg, code); err != nil {
		t.Fatal(err)
	}

	rdir := at("alice2")
	mkdir(at(".alice2.restore-2001"), past)
	mkdir(at(".alice2.keygen-2002"), past)
	if _, err := client.Restore(env.ClientConfig(rdir), client.RestoreOptions{Words: echo.Words()}, testenv.Passphrase); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, rdir, true)
	exists(at(".alice2.restore-2001"), false)
	exists(at(".alice2.keygen-2002"), true)
	exists(at(".alice.restore-1005"), true)
}

// TestKeygenOpenRace (task 20e point 4, L1 of the review of task 20b):
// an Open of the same directory makes its lock file again after
// lockOnlyDir removed it, before the rename (fault hook at "locked").
// Once: keygen tries the rename again and succeeds. Every time: keygen
// refuses with store.ErrExists, "not empty or in use by another client",
// after two tries, and leaves no temporary directory.
func TestKeygenOpenRace(t *testing.T) {
	env := testenv.New(t)
	for _, always := range []bool{false, true} {
		name := "once"
		if always {
			name = "always"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(env.Base, name)
			cfg := env.ClientConfig(dir)
			if _, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, client.ErrNotRegistered) {
				t.Fatalf("open before keygen: %v", err)
			}
			calls := 0
			client.SetClientDirFault(t, func(s string) error {
				if s != "keygen-locked" {
					return nil
				}
				calls++
				if calls == 1 || always {
					return os.WriteFile(filepath.Join(dir, "lock"), nil, 0o600)
				}
				return nil
			})
			_, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
			client.SetClientDirFault(t, nil)
			if calls != 2 {
				t.Fatalf("rename tried %d times", calls)
			}
			if temps := keygenTemps(t, dir); len(temps) != 0 {
				t.Fatalf("temporary directories left: %v", temps)
			}
			if !always {
				if err != nil {
					t.Fatalf("keygen after one lock file made again: %v", err)
				}
				checkClientDir(t, dir, true)
				return
			}
			if !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), "not empty or in use by another client") {
				t.Fatalf("keygen while the lock file is made again: %v", err)
			}
			for _, f := range clientFiles {
				if _, err := os.Lstat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s written into a directory in use", f)
				}
			}
		})
	}
}
