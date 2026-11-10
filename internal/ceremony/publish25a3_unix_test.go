//go:build unix

package ceremony

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 25 package 25A, rework 25A3 (reviews of 25A2): the
// mutants that survived the specification review (S1, S2, S4, S12, S14,
// S16).

// TestPublishWitnessesLinkCallbackOnlyForLinks (review of task 25 A2,
// S12): WitnessesLinkReplaced is called neither when publish writes
// witnesses.rec for the first time nor when it replaces a regular
// working copy with other witnesses (WitnessesReplaced is, once).
func TestPublishWitnessesLinkCallbackOnlyForLinks(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "out")
	st := newData(t, filepath.Join(f.base, "data"))
	p := st.Path("platform", WitnessesFile)
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("new data directory with %s: %v", WitnessesFile, err)
	}
	var links []string
	replaced := 0
	opts := PublishOptions{From: out, Data: st, Pin: f.res.Pin,
		WitnessesReplaced:     func(_, _ *witness.Witnesses) { replaced++ },
		WitnessesLinkReplaced: func(link string, _ *witness.Witnesses) { links = append(links, link) }}
	if err := Publish(opts); err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 || replaced != 0 {
		t.Fatalf("first write of %s: link callback %q, replaced %d", WitnessesFile, links, replaced)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("%s not written: %v %v", WitnessesFile, fi, err)
	}

	// A regular working copy with other witnesses, replaced on purpose.
	other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, other, 0o644); err != nil {
		t.Fatal(err)
	}
	opts.ReplaceWitnesses = true
	if err := Publish(opts); err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 || replaced != 1 {
		t.Fatalf("regular %s replaced: link callback %q, replaced %d", WitnessesFile, links, replaced)
	}
}

// TestPublishHardLinkedGarbageChecked (after TestZZHardLinkGarbageChecked
// of the specification review of 25A2, S14): a hard link admin-9.cert in
// data/platform/, a name the export does not have, to a file outside
// that does not decode, is checked by checkDataPlatform as every regular
// file of platform/ is, whatever its other names: refused, nothing
// written.
func TestPublishHardLinkedGarbageChecked(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	outside := filepath.Join(f.base, "outside")
	if err := os.WriteFile(outside, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, st.Path("platform", "admin-9.cert")); err != nil {
		t.Skip(err)
	}
	before := platformSnapshot(t, st)
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if err == nil || !strings.HasPrefix(err.Error(), "platform/admin-9.cert: ") {
		t.Fatalf("hard-linked garbage admin-9.cert: %v", err)
	}
	if platformSnapshot(t, st) != before {
		t.Fatal("written before the refusal")
	}
}

// TestPublishTmpReportedAfterRemoval (review of task 25 A2, S1 and S2):
// TempRemoved names a ".tmp-" file once it is removed, not before, and
// does not name one that is gone before publish removes it (here: removed
// by another process while publish reports the first one).
func TestPublishTmpReportedAfterRemoval(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	first, second := ".tmp-1111111111111111", ".tmp-2222222222222222"
	for _, n := range []string{first, second} {
		if err := os.WriteFile(st.Path("platform", n), []byte("rest"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var removed []string
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) {
		removed = append(removed, n)
		if _, err := os.Lstat(st.Path("platform", n)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s named before it was removed: %v", n, err)
		}
		if n == first {
			if err := os.Remove(st.Path("platform", second)); err != nil {
				t.Error(err)
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, " ") != first {
		t.Fatalf("TempRemoved: %q", removed)
	}
}

// TestPublishPlatformMissing (review of task 25 A2, S4 and H6): a data
// directory without platform/ is refused before anything is removed or
// written, with the error of os.Lstat in the context of platform/, and
// not as a symbolic link.
func TestPublishPlatformMissing(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	if err := os.RemoveAll(st.Path("platform")); err != nil {
		t.Fatal(err)
	}
	called := false
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(string) { called = true }})
	if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, errPlatformLink) ||
		!strings.HasPrefix(err.Error(), "ceremony: looking at platform/: ") || called {
		t.Fatalf("missing platform/: %v %v", err, called)
	}
	if _, err := os.Lstat(st.Path("platform")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("platform/ created: %v", err)
	}
}

// TestPublishEntryGoneWhileRead (review of task 25 A2, S16): an entry
// removed while publish reads it (before the second os.Lstat) is
// errChanged, like one replaced then, not a failure of os.Lstat.
func TestPublishEntryGoneWhileRead(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	serr := swapAt(t, "publish-recheck", "ingest-1.cert", func() error { return os.Remove(p) })
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if *serr != nil {
		t.Fatal(*serr)
	}
	if !errors.Is(err, errChanged) || !strings.Contains(err.Error(), p+" was replaced while it was read; ") {
		t.Fatalf("entry gone while read: %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("entry written again: %v", err)
	}
}
