package client_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 20l point 1 (F2 of the attack review of task 20i): the
// temporary directory of a keygen or restore is held by a descriptor and
// checked by its identity. Someone who can write the parent of the
// client directory is simulated by renames in the test process; another
// user with write access to a parent without the sticky bit can do the
// same renames there.

// clientDirRuns are a keygen and a restore of u into the client
// directory of cfg.
func clientDirRuns(u *testenv.User) map[string]func(cfg client.Config) error {
	return map[string]func(cfg client.Config) error{
		"keygen": func(cfg client.Config) error {
			_, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{})
			return err
		},
		"restore": func(cfg client.Config) error {
			_, err := client.Restore(cfg, client.RestoreOptions{Words: u.Words}, testenv.Passphrase)
			return err
		},
	}
}

// dirSnapshot is the content of the files in a directory.
type dirSnapshot map[string][]byte

// snapshot reads the regular files of dir.
func snapshot(t *testing.T, dir string) dirSnapshot {
	t.Helper()
	s := dirSnapshot{}
	for _, n := range entries(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		s[n] = b
	}
	return s
}

// checkSnapshot fails unless dir holds exactly the files of want.
func checkSnapshot(t *testing.T, dir string, want dirSnapshot) {
	t.Helper()
	got := snapshot(t, dir)
	if len(got) != len(want) {
		t.Fatalf("%s holds %v, want %d files", dir, entries(t, dir), len(want))
	}
	for n, b := range want {
		if !bytes.Equal(got[n], b) {
			t.Fatalf("%s: %s changed", dir, n)
		}
	}
}

// swapInVictim moves the only temporary directory of a run of kind for
// dir to stolen and renames the client directory victim to its name; it
// returns that name.
func swapInVictim(t *testing.T, dir, kind, stolen, victim string) string {
	t.Helper()
	temps := tempDirs(t, dir, kind)
	if len(temps) != 1 {
		t.Fatalf("temporary directories: %v", temps)
	}
	if err := os.Rename(temps[0], stolen); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(victim, temps[0]); err != nil {
		t.Fatal(err)
	}
	return temps[0]
}

// TestTempDirSwappedForClientDir (TestAttack20iVictimDirSwappedOntoTemp
// of the attack review of task 20i): right after the marker, the
// temporary directory of a keygen or restore is moved away and the
// complete client directory of another user is renamed to its name.
// Before task 20l the run wrote its user.rec, key store and state.json
// into that directory, replacing the other user's sealed key store,
// renamed it to its own client directory and reported success. Now the
// files go to the directory the run made, wherever it is, and the run
// fails with ErrTempReplaced before the rename; the other user's
// directory keeps every file and stays where it was put, and the run's
// client directory is not created.
func TestTempDirSwappedForClientDir(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	for kind, run := range clientDirRuns(u) {
		t.Run(kind, func(t *testing.T) {
			victim := env.NewUser("victim-" + kind).Dir
			before := snapshot(t, victim)
			dir := filepath.Join(env.Base, "clients", "swapped-"+kind)
			stolen := filepath.Join(env.Base, "stolen-"+kind)
			var at string
			client.SetClientDirFault(t, func(s string) error {
				if s == kind+"-dir" {
					at = swapInVictim(t, dir, kind, stolen, victim)
				}
				return nil
			})
			err := run(env.ClientConfig(dir))
			client.SetClientDirFault(t, nil)
			if at == "" {
				t.Fatal("step dir not reached")
			}
			if !errors.Is(err, client.ErrTempReplaced) {
				t.Fatalf("run with a replaced temporary directory: %v", err)
			}
			checkClientDir(t, dir, false)
			checkSnapshot(t, at, before)
			// The run's own files are in the directory it made.
			for _, f := range clientFiles {
				if _, err := os.Stat(filepath.Join(stolen, f)); err != nil {
					t.Fatalf("moved temporary directory: %v", err)
				}
			}
		})
	}
}

// TestTempDirSwappedNotRemoved (TestAttack20iVictimDirRemovedAsTemp):
// as TestTempDirSwappedForClientDir, but the next write step fails.
// Before task 20l the cleanup removed the temporary directory by its
// name (os.RemoveAll), that is the other user's whole client directory.
// Now the run fails with the error of its step and removes nothing: the
// name of its temporary directory names another directory, and its own
// directory, moved away, keeps its marker and files.
func TestTempDirSwappedNotRemoved(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	fault := errors.New("disk full")
	for kind, run := range clientDirRuns(u) {
		t.Run(kind, func(t *testing.T) {
			victim := env.NewUser("victim-" + kind).Dir
			before := snapshot(t, victim)
			dir := filepath.Join(env.Base, "clients", "failed-"+kind)
			stolen := filepath.Join(env.Base, "stolen-"+kind)
			var at string
			client.SetClientDirFault(t, func(s string) error {
				switch s {
				case kind + "-dir":
					at = swapInVictim(t, dir, kind, stolen, victim)
				case kind + "-user":
					return fault
				}
				return nil
			})
			err := run(env.ClientConfig(dir))
			client.SetClientDirFault(t, nil)
			if !errors.Is(err, fault) {
				t.Fatalf("run: %v", err)
			}
			if at == "" {
				t.Fatal("step dir not reached")
			}
			checkClientDir(t, dir, false)
			checkSnapshot(t, at, before)
			// The run's own directory, moved away, is not cleaned up
			// either: it keeps the marker and the file written before
			// the failed step.
			got := entries(t, stolen)
			want := []string{".incomplete", "user.rec"}
			if !slices.Equal(got, want) {
				t.Fatalf("moved temporary directory: %v, want %v", got, want)
			}
		})
	}
}

// TestTempDirSwappedBeforeRename (TestAttack20iGarbageSwappedBeforeRename):
// after the lock before the rename, the finished temporary directory is
// moved away and a directory with a file of someone else's is put at
// its name. Before task 20l the run renamed that directory to its client
// directory and reported success, its key store elsewhere. Now the check
// right before the rename fails the run with ErrTempReplaced: the client
// directory is not created, the other directory stays as it is, and the
// moved directory holds the run's files.
func TestTempDirSwappedBeforeRename(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	for kind, run := range clientDirRuns(u) {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(env.Base, "clients", "junk-"+kind)
			moved := filepath.Join(env.Base, "moved-"+kind)
			var at string
			client.SetClientDirFault(t, func(s string) error {
				if s != kind+"-locked" {
					return nil
				}
				temps := tempDirs(t, dir, kind)
				if len(temps) != 1 {
					t.Fatalf("temporary directories: %v", temps)
				}
				if err := os.Rename(temps[0], moved); err != nil {
					t.Fatal(err)
				}
				writeFiles(t, temps[0], "junk")
				at = temps[0]
				return nil
			})
			err := run(env.ClientConfig(dir))
			client.SetClientDirFault(t, nil)
			if at == "" {
				t.Fatal("step locked not reached")
			}
			if !errors.Is(err, client.ErrTempReplaced) {
				t.Fatalf("run with a replaced temporary directory: %v", err)
			}
			checkClientDir(t, dir, false)
			checkSnapshot(t, at, dirSnapshot{"junk": []byte("junk")})
			got := entries(t, moved)
			want := slices.Sorted(slices.Values(clientFiles))
			if !slices.Equal(got, want) {
				t.Fatalf("moved temporary directory: %v, want %v", got, want)
			}
		})
	}
}

// TestOpenTempDirRefuses: the check of the new temporary directory
// (openTempDir) takes only an empty directory of this user and gives it
// mode 0700; another client directory, or a symbolic link to one or to
// an empty directory of this user, put at its name right after
// os.MkdirTemp is ErrTempReplaced and left alone.
func TestOpenTempDirRefuses(t *testing.T) {
	base := t.TempDir()
	empty := filepath.Join(base, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenTempDir(empty); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if fi, err := os.Stat(empty); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("empty directory after the check: %v %v", fi, err)
	}
	full := filepath.Join(base, "full")
	writeFiles(t, full, clientFiles...)
	if err := os.Chmod(full, 0o750); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, full)
	link := filepath.Join(base, "link")
	if err := os.Symlink(full, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{full, link} {
		if err := client.OpenTempDir(p); !errors.Is(err, client.ErrTempReplaced) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	checkSnapshot(t, full, before)
	if fi, err := os.Stat(full); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("directory after the check: %v %v", fi, err)
	}
	// A link to an empty directory of this user passes every check on
	// the directory itself; the name must not be a link.
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	emptyLink := filepath.Join(base, "empty-link")
	if err := os.Symlink(target, emptyLink); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenTempDir(emptyLink); !errors.Is(err, client.ErrTempReplaced) {
		t.Fatalf("%s: %v", emptyLink, err)
	}
	checkSnapshot(t, target, dirSnapshot{})
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("link target after the check: %v %v", fi, err)
	}
	if err := client.OpenTempDir(filepath.Join(base, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
}
