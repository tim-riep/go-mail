package client_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// TestTempDirMovedAway (task 20i point 2, finding low of the attack
// review of task 20h): someone who can write only the parent moves the
// temporary directory of a keygen or restore away, after the first file
// (step user) or after the lock of the target (step locked). The run
// fails; it reports the client directory as "not empty or in use by
// another client" (store.ErrExists) only if the directory is taken,
// here by another entry. A missing target, or one that holds only the
// lock file of Open, is not taken: the run fails with the error of its
// step, which errors.Is matches with fs.ErrNotExist, and nothing is
// created. TestRunLosesTempDir covers the taken directory of a
// concurrent run that succeeded.
func TestTempDirMovedAway(t *testing.T) {
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
	// The target before the run: entries and whether it is taken.
	targets := []struct {
		name  string
		files []string // nil: no directory
		taken bool
	}{
		{"missing", nil, false},
		{"lock-only", []string{"lock"}, false},
		{"taken", []string{"other"}, true},
	}
	for kind, run := range runs {
		for _, step := range []string{"user", "locked"} {
			for _, tg := range targets {
				t.Run(kind+"-"+step+"-"+tg.name, func(t *testing.T) {
					dir := filepath.Join(env.Base, kind+"-"+step+"-"+tg.name)
					if tg.files != nil {
						writeFiles(t, dir, tg.files...)
					}
					moved := filepath.Join(env.Base, "moved-"+kind+"-"+step+"-"+tg.name)
					calls := 0
					client.SetClientDirFault(t, func(s string) error {
						if s != kind+"-"+step {
							return nil
						}
						calls++
						temps := tempDirs(t, dir, kind)
						if len(temps) != 1 {
							t.Errorf("temporary directories at %s: %v", s, temps)
							return nil
						}
						if err := os.Rename(temps[0], moved); err != nil {
							t.Error(err)
						}
						return nil
					})
					err := run(env.ClientConfig(dir))
					client.SetClientDirFault(t, nil)
					if calls != 1 {
						t.Fatalf("step %s reached %d times", step, calls)
					}
					inUse := err != nil && errors.Is(err, store.ErrExists) && strings.Contains(err.Error(), "not empty or in use by another client")
					if tg.taken {
						if !inUse {
							t.Fatalf("run without temporary directory, target taken: %v", err)
						}
					} else if inUse || errors.Is(err, store.ErrExists) || !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("run without temporary directory, target not taken: %v", err)
					}
					// The target is not replaced; with the lock-only target
					// the lock file may be gone (lockOnlyDir at step locked).
					got := entries(t, dir)
					switch {
					case tg.files == nil && got != nil:
						t.Fatalf("client directory created: %v", got)
					case tg.taken && (len(got) != 1 || got[0] != "other"):
						t.Fatalf("taken client directory changed: %v", got)
					case tg.name == "lock-only" && len(got) > 1:
						t.Fatalf("lock-only client directory changed: %v", got)
					}
					if temps := tempDirs(t, dir, kind); len(temps) != 0 {
						t.Fatalf("temporary directories left: %v", temps)
					}
					if _, err := os.Stat(filepath.Join(moved, "user.rec")); err != nil {
						t.Fatalf("moved temporary directory: %v", err)
					}
				})
			}
		}
	}
}
