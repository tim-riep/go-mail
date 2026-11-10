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

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 24 package A, rework A2 (reviews of A): a FIFO or a
// directory under a name of the export is refused before writing; a
// hard link counts as a link; a link written meanwhile is refused; a
// link over a valid entry with other content names the remedy; a file
// equal to the export's over a valid entry with other content is
// refused before writing.

// otherAdmin2 publishes admin-2 in the published fixture and returns a
// second export of admin-2.cert with other content (same key, later
// time), whose name the log now holds with the first.
func otherAdmin2(t *testing.T, f *fixture, st *store.Store) (exp, expB string, a2B []byte) {
	t.Helper()
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	exp = writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
	if err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	id1, _ := f.platform(t).IdentityKey(1)
	c, err := keys.NewPlatformCert(id1, 1, keys.RoleAdmin, 2, a2pub, testNow.Add(time.Second).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	a2B, _ = c.Encode()
	expB = writeExport(t, filepath.Join(f.base, "expA2b"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2B})
	return exp, expB, a2B
}

// TestPublishNonRegularUnderName: a FIFO or a directory directly under
// the logged ingest-1.cert is refused with store.ErrNotRegular before
// anything is written (admin-1.pub, foreign under a free name and
// replaced first otherwise, stays), and it stays in place.
func TestPublishNonRegularUnderName(t *testing.T) {
	for _, kind := range []string{"fifo", "dir"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			foreign := bytes.Repeat([]byte{9}, 32)
			if err := os.WriteFile(st.Path("platform", "admin-1.pub"), foreign, 0o644); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", "ingest-1.cert")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			before := listDir(t, st.Path("platform"))
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			if !errors.Is(err, store.ErrNotRegular) {
				t.Fatalf("%s under ingest-1.cert: %v", kind, err)
			}
			if fi, lerr := os.Lstat(p); lerr != nil || fi.Mode().IsRegular() {
				t.Fatalf("replaced: %v %v", fi, lerr)
			}
			if fmt.Sprint(listDir(t, st.Path("platform"))) != fmt.Sprint(before) ||
				!bytes.Equal(mustReadFile(t, st.Path("platform", "admin-1.pub")), foreign) {
				t.Fatal("written before the refusal")
			}
		})
	}
}

// TestPublishMeanwhileLink: admin-2.cert is missing when publish
// compares; after admin-2.pub is written (hook publish-file) a symbolic
// or hard link to a file outside with the export's content appears as
// admin-2.cert. Publish refuses it as a link written meanwhile, logs
// nothing and leaves the link.
func TestPublishMeanwhileLink(t *testing.T) {
	for _, kind := range []string{"symbolic", "hard"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
			exp := writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
			target := filepath.Join(f.base, "outside-admin-2.cert")
			if err := os.WriteFile(target, a2, 0o644); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", "admin-2.cert")
			planted := false
			crashHook = func(point string) error {
				if point == "publish-file" && !planted {
					planted = true
					link := os.Symlink
					if kind == "hard" {
						link = os.Link
					}
					if err := link(target, p); err != nil {
						return err
					}
				}
				return nil
			}
			defer func() { crashHook = nil }()
			err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin})
			crashHook = nil
			if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) ||
				!strings.Contains(err.Error(), "is a "+kind+" link") || !strings.Contains(err.Error(), "(written meanwhile); nothing logged") {
				t.Fatalf("%s link written meanwhile: %v", kind, err)
			}
			if es := lookupCert(t, st, f.res.Pin, "admin-2.cert"); len(es) != 0 {
				t.Fatalf("logged: %+v", es)
			}
			a, _ := os.Lstat(p)
			b, _ := os.Stat(target)
			if kind == "symbolic" && !isLink(t, p) || kind == "hard" && !os.SameFile(a, b) {
				t.Fatal("link replaced")
			}
		})
	}
}

// TestPublishHardLinkUnderName: a hard link under the logged
// ingest-1.cert to a file outside data/platform/ with the logged content
// is not taken for the export's file: publish replaces the name itself,
// and changing the outside file afterwards no longer changes what
// server and clients read. The outside file keeps its content.
func TestPublishHardLinkUnderName(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	want := mustReadFile(t, p)
	target := filepath.Join(f.base, "outside")
	if err := os.WriteFile(target, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, p); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	a, _ := os.Lstat(p)
	b, _ := os.Stat(target)
	if os.SameFile(a, b) {
		t.Fatal("hard link kept")
	}
	regularExport(t, st, out, "ingest-1.cert")
	if !bytes.Equal(mustReadFile(t, target), want) {
		t.Fatal("outside file written")
	}
	if err := os.WriteFile(target, bytes.Repeat([]byte{1}, len(want)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, p), want) {
		t.Fatal("platform/ingest-1.cert changed with the outside file")
	}
}

// TestPublishCrashTempNotHardLink: a temporary file of store that a
// crash of CreateFileAtomic left as the second name of admin-2.pub is no
// foreign name: publish of the same export goes on as before.
func TestPublishCrashTempNotHardLink(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	exp := writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
	p := st.Path("platform", "admin-2.pub")
	if err := os.WriteFile(p, a2pub, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, st.Path("platform", ".tmp-0011223344556677")); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	regularExport(t, st, exp, "admin-2.pub", "admin-2.cert")
}

// TestPublishLinkOverValidEntry: a symbolic or hard link as admin-2.cert,
// whose name the log holds with other content than the export's, is
// refused before anything is written, and the message names the remedy:
// the export that holds the logged file, or a reissue under the next
// generation for a thief's entry. That export then replaces the link.
func TestPublishLinkOverValidEntry(t *testing.T) {
	for _, kind := range []string{"symbolic", "hard"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			exp, expB, a2B := otherAdmin2(t, f, st)
			target := filepath.Join(f.base, "outside")
			if err := os.WriteFile(target, a2B, 0o644); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", "admin-2.cert")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			link := os.Symlink
			if kind == "hard" {
				link = os.Link
			}
			if err := link(target, p); err != nil {
				t.Skip(err)
			}
			before := platformSnapshot(t, st)
			err := Publish(PublishOptions{From: expB, Data: st, Pin: f.res.Pin})
			if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) {
				t.Fatalf("%s link over a valid entry: %v", kind, err)
			}
			for _, s := range []string{"is a " + kind + " link", "a valid entry is never replaced",
				"publish the export that holds the logged admin-2.cert", "next generation (RUNBOOK 7.3)"} {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("message without %q: %v", s, err)
				}
			}
			if platformSnapshot(t, st) != before {
				t.Fatal("written before the refusal")
			}
			if err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin}); err != nil {
				t.Fatalf("the export of the logged file: %v", err)
			}
			regularExport(t, st, exp, "admin-2.cert", "admin-2.pub")
			if !bytes.Equal(mustReadFile(t, target), a2B) {
				t.Fatal("outside file written")
			}
		})
	}
}

// TestPublishSameOverValidEntry (review of 24 A, F4): admin-2.cert of the
// data directory is the export's, but the log holds admin-2.cert with
// other content. Publish refuses before anything is written (the
// missing admin-2.pub stays missing), not only when logging.
func TestPublishSameOverValidEntry(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	_, expB, a2B := otherAdmin2(t, f, st)
	if err := os.WriteFile(st.Path("platform", "admin-2.cert"), a2B, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removePlatformFile(st, "admin-2.pub"); err != nil {
		t.Fatal(err)
	}
	before := platformSnapshot(t, st)
	err := Publish(PublishOptions{From: expB, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) ||
		!strings.Contains(err.Error(), "is the same as") || !strings.Contains(err.Error(), "a valid entry is never replaced") {
		t.Fatalf("same file over a valid entry: %v", err)
	}
	if platformSnapshot(t, st) != before {
		t.Fatal("written before the refusal")
	}
}

// platformSnapshot describes the entries of data/platform/ without following
// links: name, type and content of regular files.
func platformSnapshot(t *testing.T, st *store.Store) string {
	t.Helper()
	var b strings.Builder
	for _, n := range listDir(t, st.Path("platform")) {
		p := st.Path("platform", n)
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %v", n, fi.Mode().Type())
		if fi.Mode().IsRegular() {
			fmt.Fprintf(&b, " %x", mustReadFile(t, p))
		}
		b.WriteString("\n")
	}
	return b.String()
}
