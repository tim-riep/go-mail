package client_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 20h points 4 to 7: leftovers of keygen and restore are
// removed only with the marker .incomplete and only file by file, only
// with the digits of os.MkdirTemp after the prefix; Open makes sure that
// it locks the lock file the client directory holds; a run whose
// temporary directory a concurrent run removed reports store.ErrExists.

// writeFiles writes the files names (content: the name) into dir.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// entries returns the sorted names in dir, or nil if dir is missing.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestLeftoverNeedsMarker (points 4 and 7, F1 of the attack review of
// task 20e): a successful keygen removes the temporary directory that a
// killed keygen for the same client directory left behind (marker, key
// store, user.rec, state.json and the temporary files of the atomic
// writers), and nothing else: not a complete client directory renamed to
// a name of that pattern (no marker), not a leftover with the marker and
// an unknown entry (which stays whole since task 20o point 1), not a
// directory whose marker is no regular file, not a name with anything but
// the digits of os.MkdirTemp after the prefix.
func TestLeftoverNeedsMarker(t *testing.T) {
	env := testenv.New(t)
	parent := filepath.Join(env.Base, "devices")
	at := func(name string) string { return filepath.Join(parent, name) }
	old := func(p string) {
		t.Helper()
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}

	// A complete client directory, renamed into the pattern of alice's
	// temporary directories.
	if _, err := client.Keygen(env.ClientConfig(at("real")), testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	renamed := at(".alice.keygen-4242")
	if err := os.Rename(at("real"), renamed); err != nil {
		t.Fatal(err)
	}
	old(renamed)
	keep := map[string][]byte{}
	for _, f := range clientFiles {
		data, err := os.ReadFile(filepath.Join(renamed, f))
		if err != nil {
			t.Fatal(err)
		}
		keep[f] = data
	}

	// The leftover of a keygen killed after state.json, with temporary
	// files of the atomic writers added.
	dir := at("alice")
	cfg := env.ClientConfig(dir)
	client.SetCrashHook(t, func(p string) bool { return p == "keygen-state" })
	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); !errors.Is(err, client.ErrCrashed) {
		t.Fatalf("killed keygen: %v", err)
	}
	client.SetCrashHook(t, nil)
	var killed string
	for _, p := range keygenTemps(t, dir) {
		if p != renamed {
			killed = p
		}
	}
	if killed == "" {
		t.Fatal("no leftover of the killed keygen")
	}
	if got := strings.Join(entries(t, killed), " "); got != ".incomplete keystore state.json user.rec" {
		t.Fatalf("leftover of the killed keygen: %s", got)
	}
	writeFiles(t, killed, ".tmp-0123456789abcdef", ".keystore-123456.tmp")
	old(killed)

	// Leftovers with the marker and an unknown entry, with a marker that
	// is a directory, and names outside the pattern.
	unknown := at(".alice.keygen-77")
	writeFiles(t, unknown, ".incomplete", "keystore", "notes", ".tmp-short", ".keystore-x.tmp")
	if err := os.Mkdir(filepath.Join(unknown, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	old(unknown)
	dirMarker := at(".alice.keygen-78")
	writeFiles(t, dirMarker, "keystore")
	if err := os.Mkdir(filepath.Join(dirMarker, ".incomplete"), 0o700); err != nil {
		t.Fatal(err)
	}
	old(dirMarker)
	outside := []string{".alice.keygen-old", ".alice.keygen-12345678901", ".alice.keygen-12.bak", ".alice.keygen-", ".alice.keygen--1", ".alice.keygen-+1"}
	for _, n := range outside {
		writeFiles(t, at(n), ".incomplete", "keystore")
		old(at(n))
	}

	if _, err := client.Keygen(cfg, testenv.Passphrase, &testenv.Echo{}); err != nil {
		t.Fatal(err)
	}
	checkClientDir(t, dir, true)
	if _, err := os.Lstat(killed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover of the killed keygen: %v %v", err, entries(t, killed))
	}
	if got := strings.Join(entries(t, renamed), " "); got != "keystore state.json user.rec" {
		t.Fatalf("renamed client directory: %s", got)
	}
	for f, data := range keep {
		if got, err := os.ReadFile(filepath.Join(renamed, f)); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s of the renamed client directory changed: %v", f, err)
		}
	}
	if got := strings.Join(entries(t, unknown), " "); got != ".incomplete .keystore-x.tmp .tmp-short keystore notes state.json" {
		t.Fatalf("leftover with unknown entries: %s", got)
	}
	if got := strings.Join(entries(t, dirMarker), " "); got != ".incomplete keystore" {
		t.Fatalf("leftover with a directory as marker: %s", got)
	}
	for _, n := range outside {
		if got := strings.Join(entries(t, at(n)), " "); got != ".incomplete keystore" {
			t.Fatalf("%s: %s", n, got)
		}
	}
}

// TestRunLosesTempDir (point 6, F3 of the attack review of task 20e): a
// keygen or restore whose temporary directory a concurrent run of the
// same kind for the same client directory removed (it succeeded and
// found the directory older than itself) fails with store.ErrExists and
// the message "not empty or in use by another client", not with the
// ENOENT of its next step, after a write and after the lock before the
// rename; the client directory of the other run stays complete.
func TestRunLosesTempDir(t *testing.T) {
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
		for _, step := range []string{"user", "locked"} {
			t.Run(kind+"-"+step, func(t *testing.T) {
				dir := filepath.Join(env.Base, kind+"-"+step)
				cfg := env.ClientConfig(dir)
				inner, calls := false, 0
				var innerErr error
				client.SetClientDirFault(t, func(s string) error {
					if inner || s != kind+"-"+step {
						return nil
					}
					calls++
					temps := tempDirs(t, dir, kind)
					if len(temps) != 1 {
						t.Errorf("temporary directories at %s: %v", s, temps)
						return nil
					}
					if err := os.Chtimes(temps[0], past, past); err != nil {
						t.Error(err)
					}
					inner = true
					innerErr = run(cfg)
					inner = false
					return nil
				})
				err := run(cfg)
				client.SetClientDirFault(t, nil)
				if calls != 1 || innerErr != nil {
					t.Fatalf("concurrent run: %d calls, %v", calls, innerErr)
				}
				if !errors.Is(err, store.ErrExists) || errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "not empty or in use by another client") {
					t.Fatalf("run that lost its temporary directory: %v", err)
				}
				checkClientDir(t, dir, true)
				if temps := tempDirs(t, dir, kind); len(temps) != 0 {
					t.Fatalf("temporary directories left: %v", temps)
				}
			})
		}
	}
}

// lockProbeEnv names the lock file that TestHelperProbeClientDirLock
// tries to lock.
const lockProbeEnv = "GOMAIL_CLIENT_LOCK_PROBE"

// TestHelperProbeClientDirLock is not a test: started by
// probeInOtherProcess as a second process, it tries to lock the file
// named by lockProbeEnv like Open (store.LockFile) and prints the result.
func TestHelperProbeClientDirLock(t *testing.T) {
	path := os.Getenv(lockProbeEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	unlock, err := store.LockFile(path)
	switch {
	case err == nil:
		unlock()
		os.Stdout.WriteString("probe: free\n")
	case errors.Is(err, store.ErrLocked):
		os.Stdout.WriteString("probe: locked\n")
	default:
		os.Stdout.WriteString("probe: error " + err.Error() + "\n")
	}
}

// probeInOtherProcess returns "free" or "locked": what another process
// finds when it tries to take the lock of the client directory dir.
func probeInOtherProcess(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProbeClientDirLock$", "-test.count=1")
	cmd.Env = append(os.Environ(), lockProbeEnv+"="+filepath.Join(dir, "lock"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v %s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if r, ok := strings.CutPrefix(l, "probe: "); ok {
			return r
		}
	}
	t.Fatalf("probe: %s", out)
	return ""
}

// TestOpenLockFileReplaced (point 5, F2 of the attack review of task
// 20e): the lock file of the client directory is removed, or replaced by
// another file, after Open locked it and before Open compared it (as a
// concurrent keygen's lockOnlyDir does between the open and the lock of
// a slower Open). Open takes the lock again and holds it on the file the
// directory names: another process cannot lock it while the client is
// open, and can once it is closed. A file that changes in every attempt
// ends Open with store.ErrLocked after client.LockAttempts attempts.
func TestOpenLockFileReplaced(t *testing.T) {
	env := testenv.New(t)
	u := env.NewUser("alice")
	u.Client.Close()
	cfg := env.ClientConfig(u.Dir)
	lock := filepath.Join(u.Dir, "lock")
	change := map[string]func(){
		"removed": func() {
			if err := os.Remove(lock); err != nil {
				t.Error(err)
			}
		},
		"replaced": func() {
			if err := os.Remove(lock); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Error(err)
			}
		},
	}
	for name, fn := range change {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			client.SetDirLockHook(t, func(attempt int) {
				attempts = attempt
				if attempt == 1 {
					fn()
				}
			})
			c, err := client.Open(cfg, testenv.Passphrase)
			client.SetDirLockHook(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := probeInOtherProcess(t, u.Dir)
			c.Close()
			if got != "locked" {
				t.Fatalf("another process finds the lock of an open client %s", got)
			}
			if attempts < 2 {
				t.Fatalf("lock taken in %d attempts", attempts)
			}
			if got := probeInOtherProcess(t, u.Dir); got != "free" {
				t.Fatalf("another process finds the lock of a closed client %s", got)
			}
		})
	}

	attempts := 0
	client.SetDirLockHook(t, func(attempt int) {
		attempts = attempt
		change["replaced"]()
	})
	if c, err := client.Open(cfg, testenv.Passphrase); !errors.Is(err, store.ErrLocked) {
		if err == nil {
			c.Close()
		}
		t.Fatalf("open while the lock file changes every time: %v", err)
	}
	client.SetDirLockHook(t, nil)
	if attempts != client.LockAttempts {
		t.Fatalf("%d attempts, want %d", attempts, client.LockAttempts)
	}
	if got := probeInOtherProcess(t, u.Dir); got != "free" {
		t.Fatalf("lock held after a failed open: %s", got)
	}
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
