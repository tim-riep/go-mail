//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 26 package 26B: publish opens platform/ of the data
// directory once and works relative to it (backlog 72), and reports a
// replaced witnesses.rec also when only the fsync of platform/ fails
// afterwards (backlog 83).

// copyFlat copies the regular files of dir into a new directory to.
func copyFlat(t *testing.T, dir, to string) {
	t.Helper()
	if err := os.Mkdir(to, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := os.WriteFile(filepath.Join(to, e.Name()), mustReadFile(t, filepath.Join(dir, e.Name())), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// dirSnapshot describes the entries of dir and the content of its
// regular files.
func dirSnapshot(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range ents {
		fmt.Fprintf(&b, "%s %v", e.Name(), e.Type())
		if e.Type().IsRegular() {
			fmt.Fprintf(&b, " %x", mustReadFile(t, filepath.Join(dir, e.Name())))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// TestPublishPlatformReplacedBeforeOpen (backlog 72): platform/ is a
// directory when publish looks at it (checkPlatformDir) and is replaced
// before publish opens it (hook "publish-platform"): by a symbolic link
// to a copy outside, or by another directory, each with a ".tmp-" file
// of its own and without ingest-1.cert, which publish would write.
// Publish refuses before it removes or writes anything, naming
// platform/; neither the copy nor the moved directory changes. A FIFO
// in place of platform/ is syscall.ENOTDIR at once (no open that waits
// for a writer), with the message of a platform/ that is no directory.
// A symbolic link to the very directory publish looked at (moved
// outside) is refused as well (review of task 26 package B, N1: the path
// must lead to the opened directory without a link), and nothing in that
// directory changes.
func TestPublishPlatformReplacedBeforeOpen(t *testing.T) {
	for _, kind := range []string{"link-to-copy", "other-dir", "fifo", "link-to-same"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			plat := st.Path("platform")
			if err := os.Remove(filepath.Join(plat, "ingest-1.cert")); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(f.base, "moved")
			other := filepath.Join(f.base, "other")
			var snapMoved, snapOther string
			serr := error(nil)
			hit := false
			crashHook = func(p string) error {
				if p != "publish-platform" || hit {
					return nil
				}
				hit = true
				if err := os.Rename(plat, moved); err != nil {
					return err
				}
				switch kind {
				case "link-to-copy", "other-dir":
					copyFlat(t, moved, other)
					if err := os.WriteFile(filepath.Join(other, ".tmp-foreign"), []byte("foreign"), 0o644); err != nil {
						return err
					}
					snapOther = dirSnapshot(t, other)
					if kind == "other-dir" {
						serr = os.Rename(other, plat)
						other = plat
					} else {
						serr = os.Symlink(other, plat)
					}
				case "fifo":
					serr = syscall.Mkfifo(plat, 0o644)
				case "link-to-same":
					serr = os.Symlink(moved, plat)
				}
				snapMoved = dirSnapshot(t, moved)
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			if err := os.WriteFile(filepath.Join(plat, ".tmp-own"), []byte("own"), 0o644); err != nil {
				t.Fatal(err)
			}
			var removed []string
			done := make(chan error, 1)
			go func() {
				done <- Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) { removed = append(removed, n) }})
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("publish hangs")
			}
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("swap: %v %v", serr, hit)
			}
			switch kind {
			case "link-to-copy", "other-dir", "link-to-same":
				if !errors.Is(err, errPlatformReplaced) || errors.Is(err, errPlatformLink) || err.Error() != replacedBeforeOpen(plat) {
					t.Fatalf("platform/ replaced before the open: %v", err)
				}
				if removed != nil {
					t.Fatalf("TempRemoved: %q", removed)
				}
				if kind != "link-to-same" {
					if got := dirSnapshot(t, other); got != snapOther {
						t.Fatalf("the replacement changed:\n%s", got)
					}
				}
				if got := dirSnapshot(t, moved); got != snapMoved {
					t.Fatalf("the directory looked at changed:\n%s", got)
				}
			case "fifo":
				if !errors.Is(err, syscall.ENOTDIR) || err.Error() != "ceremony: removing temporary files of platform/: open "+plat+": not a directory" {
					t.Fatalf("FIFO in place of platform/: %v", err)
				}
				if got := dirSnapshot(t, moved); got != snapMoved || removed != nil {
					t.Fatalf("the directory looked at changed: %q\n%s", removed, got)
				}
			}
		})
	}
}

// replacedBeforeOpen is the message of errPlatformReplaced when publish
// refuses platform/ at its open.
func replacedBeforeOpen(plat string) string {
	return "ceremony: platform/ of the data directory was replaced during publish: " + plat +
		" is no longer the directory publish looked at; nothing removed or written: another process writes the data directory: stop it, look at platform/ and run the same publish again"
}

// replacedBeforeLog is the message of errPlatformReplaced when publish
// refuses before the log.
func replacedBeforeLog(plat string) string {
	return "ceremony: platform/ of the data directory was replaced during publish: " + plat +
		" is no longer the directory publish opened and wrote to; nothing logged: another process writes the data directory: stop it, look at platform/ and run the same publish again"
}

// TestPublishPlatformCheckedAfterOpen (review of task 26 package B, N1):
// platform/ is the directory publish looked at when it is opened, and
// is replaced right after the open, before publish looks at the path
// again (hook "publish-platform-opened"): by a symbolic link to the
// opened directory (moved outside), by another directory with the same
// files, or not at all (moved away). That stands for a reused inode
// number, which lets the first os.SameFile pass for a directory that is
// not platform/ (TestRev26BInodeReuse of the review): publish refuses
// before it removes or writes anything, and nothing changes in the
// opened directory or in the replacement. With the same directory back
// in its place, the same publish succeeds.
func TestPublishPlatformCheckedAfterOpen(t *testing.T) {
	for _, kind := range []string{"link-to-opened", "other-dir", "gone"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			plat := st.Path("platform")
			if err := os.Remove(filepath.Join(plat, "ingest-1.cert")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(plat, ".tmp-own"), []byte("own"), 0o644); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(f.base, "moved")
			var snapMoved, snapPlat string
			var serr error
			hit := false
			crashHook = func(p string) error {
				if p != "publish-platform-opened" || hit {
					return nil
				}
				hit = true
				if serr = os.Rename(plat, moved); serr != nil {
					return nil
				}
				switch kind {
				case "link-to-opened":
					serr = os.Symlink(moved, plat)
				case "other-dir":
					copyFlat(t, moved, plat)
					snapPlat = dirSnapshot(t, plat)
				}
				snapMoved = dirSnapshot(t, moved)
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			var removed []string
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) { removed = append(removed, n) }})
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("swap: %v %v", serr, hit)
			}
			if !errors.Is(err, errPlatformReplaced) || err.Error() != replacedBeforeOpen(plat) {
				t.Fatalf("platform/ replaced after the open: %v", err)
			}
			if removed != nil {
				t.Fatalf("TempRemoved: %q", removed)
			}
			if got := dirSnapshot(t, moved); got != snapMoved {
				t.Fatalf("the opened directory changed:\n%s", got)
			}
			if kind == "other-dir" {
				if got := dirSnapshot(t, plat); got != snapPlat {
					t.Fatalf("the replacement changed:\n%s", got)
				}
				if err := os.RemoveAll(plat); err != nil {
					t.Fatal(err)
				}
			} else if kind == "link-to-opened" {
				if err := os.Remove(plat); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(moved, plat); err != nil {
				t.Fatal(err)
			}
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
				t.Fatalf("the same publish again: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(plat, "ingest-1.cert")); err != nil {
				t.Fatalf("ingest-1.cert not written: %v", err)
			}
		})
	}
}

// TestPublishPlatformSwappedAfterOpen (backlog 72): once publish has
// opened platform/, a swap of platform/ for a symbolic link to a copy
// outside (the decoy: with ingest-1.cert and witnesses.rec missing,
// which publish writes, ".tmp-" files and a garbage admin-9.cert of its
// own), or for a regular
// file, does not change where publish lists, reads, removes and writes:
// the temporary files are removed and ingest-1.cert and witnesses.rec
// are written in the directory publish opened (moved away by the swap);
// nothing is written, removed or read where the path platform/ leads
// now (a listing of the decoy would refuse its admin-9.cert). Before the
// log publish refuses, because platform/ is no longer the directory it
// wrote to (review of task 26 package B, H2); with that directory back
// in its place, the same publish succeeds. The swap happens when the
// first temporary file was
// removed (TempRemoved), at the hook of the first entry
// checkDataPlatform reads, or at the second os.Lstat of an entry of the
// export (the swap of review of task 25 A, which made that os.Lstat
// fail with syscall.ENOTDIR before).
func TestPublishPlatformSwappedAfterOpen(t *testing.T) {
	for _, c := range []struct{ point, kind string }{
		{"temp-removed", "link"},
		{"temp-removed", "file"},
		{"check-open admin-1.cert", "link"},
		{"check-open admin-1.cert", "file"},
		{"publish-recheck admin-1.cert", "link"},
		{"publish-recheck admin-1.cert", "file"},
	} {
		t.Run(c.point+"/"+c.kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			plat := st.Path("platform")
			want := mustReadFile(t, filepath.Join(plat, "ingest-1.cert"))
			wantW := mustReadFile(t, filepath.Join(plat, WitnessesFile))
			for _, n := range []string{"ingest-1.cert", WitnessesFile} {
				if err := os.Remove(filepath.Join(plat, n)); err != nil {
					t.Fatal(err)
				}
			}
			for _, n := range []string{".tmp-a", ".tmp-b"} {
				if err := os.WriteFile(filepath.Join(plat, n), []byte(n), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			moved := filepath.Join(f.base, "moved")
			decoy := filepath.Join(f.base, "decoy")
			var snapDecoy string
			hit := false
			var serr error
			swap := func(p string) {
				if p != c.point || hit {
					return
				}
				hit = true
				if serr = os.Rename(plat, moved); serr != nil {
					return
				}
				if c.kind == "link" {
					copyFlat(t, moved, decoy)
					for _, n := range []string{".tmp-a", ".tmp-decoy", "admin-9.cert"} {
						if serr = os.WriteFile(filepath.Join(decoy, n), []byte("decoy"), 0o644); serr != nil {
							return
						}
					}
					snapDecoy = dirSnapshot(t, decoy)
					serr = os.Symlink(decoy, plat)
				} else {
					serr = os.WriteFile(plat, nil, 0o644)
				}
			}
			crashHook = func(p string) error { swap(p); return nil }
			t.Cleanup(func() { crashHook = nil })
			var removed []string
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) {
				removed = append(removed, n)
				swap("temp-removed")
			}})
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("swap: %v %v", serr, hit)
			}
			if !errors.Is(err, errPlatformReplaced) || err.Error() != replacedBeforeLog(plat) {
				t.Fatalf("publish after the swap: %v", err)
			}
			if strings.Join(removed, " ") != ".tmp-a .tmp-b" {
				t.Fatalf("TempRemoved: %q", removed)
			}
			if b, rerr := os.ReadFile(filepath.Join(moved, "ingest-1.cert")); rerr != nil || !bytes.Equal(b, want) {
				t.Fatalf("ingest-1.cert not written into the directory publish opened: %v", rerr)
			}
			if b, rerr := os.ReadFile(filepath.Join(moved, WitnessesFile)); rerr != nil || !bytes.Equal(b, wantW) {
				t.Fatalf("witnesses.rec not written into the directory publish opened: %v", rerr)
			}
			for _, n := range []string{".tmp-a", ".tmp-b"} {
				if _, lerr := os.Lstat(filepath.Join(moved, n)); !errors.Is(lerr, os.ErrNotExist) {
					t.Fatalf("%s left in the directory publish opened: %v", n, lerr)
				}
			}
			if c.kind == "link" {
				if got := dirSnapshot(t, decoy); got != snapDecoy {
					t.Fatalf("written or removed through the link:\n%s", got)
				}
			} else if fi, lerr := os.Lstat(plat); lerr != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
				t.Fatalf("the file in place of platform/ changed: %v %v", fi, lerr)
			}
			if err := os.Remove(plat); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, plat); err != nil {
				t.Fatal(err)
			}
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
				t.Fatalf("the same publish again: %v", err)
			}
		})
	}
}

// TestPublishNoLogAfterSwap (review of task 26 package B, H2): publish
// into a new data directory, so that every file of the export is
// written and then logged. Right before the log (hook "publish-log")
// platform/ is moved away and replaced by a symbolic link to it, or by
// a copy of it. Publish refuses before anything is logged, with the
// message of errPlatformReplaced. The same publish again then logs
// every file: on the copy (the files are there, equal), and on the
// directory publish wrote, back in its place after the link is removed
// (with the link left in place, checkPlatformDir refuses).
func TestPublishNoLogAfterSwap(t *testing.T) {
	for _, kind := range []string{"link", "copy"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.base, "out")
			st := newData(t, filepath.Join(f.base, "data"))
			plat := st.Path("platform")
			moved := filepath.Join(f.base, "moved")
			lg := newLog(t)
			var serr error
			hit := false
			crashHook = func(p string) error {
				if p != "publish-log" || hit {
					return nil
				}
				hit = true
				if serr = os.Rename(plat, moved); serr != nil {
					return nil
				}
				if kind == "link" {
					serr = os.Symlink(moved, plat)
				} else {
					copyFlat(t, moved, plat)
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg})
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("swap: %v %v", serr, hit)
			}
			if !errors.Is(err, errPlatformReplaced) || err.Error() != replacedBeforeLog(plat) || len(lg.names) != 0 {
				t.Fatalf("logged %q: %v", lg.names, err)
			}
			if _, err := os.Lstat(filepath.Join(moved, "ingest-1.cert")); err != nil {
				t.Fatalf("ingest-1.cert not written into the opened directory: %v", err)
			}
			if kind == "link" {
				if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg}); !errors.Is(err, errPlatformLink) || len(lg.names) != 0 {
					t.Fatalf("again with the link: logged %q: %v", lg.names, err)
				}
				if err := os.Remove(plat); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(moved, plat); err != nil {
					t.Fatal(err)
				}
			}
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg}); err != nil {
				t.Fatalf("the same publish again: %v", err)
			}
			if _, ok := lg.logged["ingest-1.cert"]; !ok {
				t.Fatalf("not logged on the repeat: %q", lg.names)
			}
		})
	}
}

// TestPublishWitnessesSyncFails (backlog 83): witnesses.rec, a working
// copy with other witnesses or a symbolic link, is replaced with
// ReplaceWitnesses, and only the fsync of platform/ after the rename
// fails (hook "publish-sync witnesses.rec"). The callback is called once
// all the same, after the rename (it reads the pin's working copy), and
// Publish returns the error of the fsync afterwards, before the log.
func TestPublishWitnessesSyncFails(t *testing.T) {
	for _, kind := range []string{"regular", "symbolic"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.base, "out")
			st := newData(t, filepath.Join(f.base, "data"))
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", WitnessesFile)
			want := mustReadFile(t, p)
			other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if kind == "regular" {
				if err := os.WriteFile(p, other, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				outside := filepath.Join(f.base, "outside-w")
				if err := os.WriteFile(outside, other, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, p); err != nil {
					t.Fatal(err)
				}
			}
			eio := fmt.Errorf("fsync of platform/: %w", syscall.EIO)
			synced, logged := false, false
			crashHook = func(point string) error {
				switch point {
				case "publish-sync " + WitnessesFile:
					synced = true
					return eio
				case "publish-log":
					logged = true
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			calls := 0
			replaced := func() {
				calls++
				if !synced {
					t.Error("callback before the fsync of platform/")
				}
				if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || !bytes.Equal(mustReadFile(t, p), want) {
					t.Errorf("callback before witnesses.rec was replaced: %v %v", fi, err)
				}
			}
			opts := PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true}
			if kind == "regular" {
				opts.WitnessesReplaced = func(before, after *witness.Witnesses) {
					if before.Min != 1 || len(before.List) != 1 || after.Min != f.res.Pin.MinWitnesses {
						t.Errorf("before %+v after %+v", before, after)
					}
					replaced()
				}
				opts.WitnessesLinkReplaced = func(string, *witness.Witnesses) { t.Error("link callback for a regular file") }
			} else {
				opts.WitnessesReplaced = func(_, _ *witness.Witnesses) { t.Error("WitnessesReplaced for a link") }
				opts.WitnessesLinkReplaced = func(link string, _ *witness.Witnesses) {
					if link != linkSymbolic {
						t.Errorf("link %q", link)
					}
					replaced()
				}
			}
			err = Publish(opts)
			if err != eio || calls != 1 || logged {
				t.Fatalf("err %v, calls %d, log reached %v", err, calls, logged)
			}
		})
	}
}
