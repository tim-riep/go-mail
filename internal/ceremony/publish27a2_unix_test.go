//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of the follow-up 27A2 of task 27 package 27A: each branch that
// makes publish say "wrote to" before the log (review of task 27 A, F1
// of the first, N3 of the second review), and an admin public key
// listed as no regular file that is one when it is read (C4, X2).

// TestPublishWroteBeforeLog: every way publish writes into platform/,
// each alone, then platform/ is moved away right before the log (hook
// "publish-log"). The message says "wrote to" in each case, and the
// directory publish opened differs from before in exactly the name
// written: witnesses.rec written from the pin (store.ReplaceFileIn), a
// foreign admin-1.pub healed and a symbolic link under ingest-1.cert
// replaced (store.WriteFileAtomicIn), a missing admin-1.pub made
// (store.CreateFileAtomicIn). Nothing is logged. (Nothing written is
// TestPublishPlatformGoneBeforeLog.)
func TestPublishWroteBeforeLog(t *testing.T) {
	for _, c := range []struct {
		name, file string
		prepare    func(t *testing.T, f *fixture, st *store.Store)
	}{
		{"witnesses-written", WitnessesFile, func(t *testing.T, f *fixture, st *store.Store) {
			if err := os.Remove(st.Path("platform", WitnessesFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"pub-healed", "admin-1.pub", func(t *testing.T, f *fixture, st *store.Store) {
			if err := os.WriteFile(st.Path("platform", "admin-1.pub"), bytes.Repeat([]byte{9}, 32), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"link-replaced", "ingest-1.cert", func(t *testing.T, f *fixture, st *store.Store) {
			p := st.Path("platform", "ingest-1.cert")
			target := filepath.Join(f.base, "outside-ingest-1.cert")
			if err := os.WriteFile(target, mustReadFile(t, p), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"created", "admin-1.pub", func(t *testing.T, f *fixture, st *store.Store) {
			if err := os.Remove(st.Path("platform", "admin-1.pub")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.base, "out")
			st := newData(t, filepath.Join(f.base, "data"))
			lg := newLog(t)
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg}); err != nil {
				t.Fatal(err)
			}
			c.prepare(t, f, st)
			plat := st.Path("platform")
			moved := filepath.Join(f.base, "moved")
			before := dirSnapshot(t, plat)
			var serr error
			hit := false
			crashHook = func(p string) error {
				if p != "publish-log" || hit {
					return nil
				}
				hit = true
				serr = os.Rename(plat, moved)
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			logged := len(lg.names)
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg})
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("move: %v %v", serr, hit)
			}
			if !errors.Is(err, errPlatformReplaced) || err.Error() != replacedBeforeLog(plat) || len(lg.names) != logged {
				t.Fatalf("logged %q: %v", lg.names[logged:], err)
			}
			// Exactly the one name differs in the directory publish opened.
			was, now := strings.Split(before, "\n"), strings.Split(dirSnapshot(t, moved), "\n")
			var changed []string
			for _, ls := range [][2][]string{{now, was}, {was, now}} {
				for _, l := range ls[0] {
					if l == "" || slices.Contains(ls[1], l) {
						continue
					}
					if n := strings.Fields(l)[0]; !slices.Contains(changed, n) {
						changed = append(changed, n)
					}
				}
			}
			if len(changed) != 1 || changed[0] != c.file {
				t.Fatalf("changed in the opened directory: %q", changed)
			}
			fi, lerr := os.Lstat(filepath.Join(moved, c.file))
			if lerr != nil || !fi.Mode().IsRegular() {
				t.Fatalf("%s: %v %v", c.file, fi, lerr)
			}
			if c.file != WitnessesFile && !bytes.Equal(mustReadFile(t, filepath.Join(moved, c.file)), mustReadFile(t, filepath.Join(out, "platform", c.file))) {
				t.Fatalf("%s is not the export's", c.file)
			}
		})
	}
}

// TestPublishPubListedNonRegular: admin-3.pub, a name the export does
// not hold, is a directory when checkDataPlatform lists platform/ and a
// regular file with other content by the time it reads that entry
// (replaced at the hook "check-open admin-1.cert", which comes before it
// in the listing). As for a regular admin-<g>.pub from the start, its
// content is not the business of that check: publish goes on and
// leaves it as it is. (A directory there when it is read is
// TestPublishNonRegularBeforeName.)
func TestPublishPubListedNonRegular(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "admin-3.pub")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{7}, 32)
	var serr error
	hit := false
	crashHook = func(pt string) error {
		if pt != "check-open admin-1.cert" || hit {
			return nil
		}
		hit = true
		if serr = os.Remove(p); serr == nil {
			serr = os.WriteFile(p, other, 0o644)
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if serr != nil || !hit {
		t.Fatalf("swap: %v %v", serr, hit)
	}
	if err != nil {
		t.Fatalf("admin-3.pub a regular file by the time it is read: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, p), other) {
		t.Fatal("admin-3.pub changed")
	}
}
