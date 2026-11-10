//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 25 package 25A (reviews of task 24 A and A2): an entry
// replaced while publish reads it is refused (F3); a ".tmp-" name hides
// no hard link (N1); a missing name over a valid entry with other
// content is refused before writing (N3); a link as witnesses.rec is
// treated as under the other names of the export.

// swapAt sets crashHook so that swap runs once, at the hook point
// "<point> <name>" of readEntry, and returns the error swap gave.
func swapAt(t *testing.T, point, name string, swap func() error) *error {
	t.Helper()
	var serr error
	done := false
	crashHook = func(p string) error {
		if p == point+" "+name && !done {
			done = true
			serr = swap()
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	return &serr
}

// replaceBy puts a symbolic link to target, or a regular file with
// content data when target is "", under path, by rename (atomically, as
// an attacker would).
func replaceBy(path, target string, data []byte) error {
	tmp := path + ".new"
	var err error
	if target != "" {
		err = os.Symlink(target, tmp)
	} else {
		err = os.WriteFile(tmp, data, 0o644)
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TestPublishEntrySwapped (review of task 24 A, F3): the logged
// ingest-1.cert is a regular file with the export's content when publish
// looks at it (os.Lstat), and is replaced before publish opens it, or
// while publish reads it, by a symbolic link to a file outside with the
// same content, by a symbolic link to the same file (whose other name
// lies outside) or by another regular file with the same content.
// Publish refuses with errChanged instead of taking it for the export's
// file, writes nothing and logs nothing, and the entry stays as the
// swap left it.
func TestPublishEntrySwapped(t *testing.T) {
	for _, point := range []string{"publish-open", "publish-recheck"} {
		for _, kind := range []string{"symlink-outside", "symlink-same-file", "regular"} {
			t.Run(point+"/"+kind, func(t *testing.T) {
				f := newFixture(t)
				st, _ := f.published(t, "data")
				out := filepath.Join(f.base, "out")
				p := st.Path("platform", "ingest-1.cert")
				want := mustReadFile(t, p)
				outside := filepath.Join(f.base, "outside")
				var after string
				serr := swapAt(t, point, "ingest-1.cert", func() error {
					var err error
					switch kind {
					case "symlink-outside":
						if err = os.WriteFile(outside, want, 0o644); err == nil {
							err = replaceBy(p, outside, nil)
						}
					case "symlink-same-file":
						if err = os.Link(p, outside); err == nil {
							err = replaceBy(p, outside, nil)
						}
					default:
						err = replaceBy(p, "", want)
					}
					if err != nil {
						return err
					}
					after = platformSnapshot(t, st)
					return nil
				})
				err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
				crashHook = nil
				if *serr != nil {
					t.Fatalf("swap: %v", *serr)
				}
				if after == "" {
					t.Fatal("hook not reached")
				}
				if !errors.Is(err, errChanged) || !strings.Contains(err.Error(), p) {
					t.Fatalf("%s at %s: %v", kind, point, err)
				}
				if platformSnapshot(t, st) != after {
					t.Fatal("written after the swap")
				}
				if es := lookupCert(t, st, f.res.Pin, "ingest-1.cert"); len(es) != 1 || !bytes.Equal(es[0].Content, want) {
					t.Fatalf("log changed: %+v", es)
				}
				if strings.HasPrefix(kind, "symlink") != isLink(t, p) {
					t.Fatal("entry changed after the swap")
				}
			})
		}
	}
}

// TestPublishEntryGone (F3): an entry removed between os.Lstat and the
// open is errChanged, not a missing name that publish writes.
func TestPublishEntryGone(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	serr := swapAt(t, "publish-open", "ingest-1.cert", func() error { return os.Remove(p) })
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if *serr != nil {
		t.Fatal(*serr)
	}
	if !errors.Is(err, errChanged) {
		t.Fatalf("entry gone before the open: %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written: %v", err)
	}
}

// TestPublishTmpNameHidesNoHardLink (review of task 24 A2, N1, after
// TestRevTmpNameHidesHardLink): the logged ingest-1.cert whose other
// name is a ".tmp-" name in platform/ (a crash leaves such a name, an
// attacker can make one) does not stay a file with two names: publish
// removes the temporary name under the server lock first, so writing
// that name afterwards no longer changes platform/ingest-1.cert. With a
// third name outside, the file is a hard link and replaced.
func TestPublishTmpNameHidesNoHardLink(t *testing.T) {
	for _, outsideToo := range []bool{false, true} {
		name := "tmp-only"
		if outsideToo {
			name = "tmp-and-outside"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", "ingest-1.cert")
			want := mustReadFile(t, p)
			tmp := st.Path("platform", ".tmp-a1b2c3d4e5f60718")
			if err := os.Link(p, tmp); err != nil {
				t.Skip(err)
			}
			outside := filepath.Join(f.base, "outside")
			if outsideToo {
				if err := os.Link(p, outside); err != nil {
					t.Fatal(err)
				}
			}
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
				t.Fatalf("publish: %v", err)
			}
			if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary name kept: %v", err)
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || nlink(fi) != 1 {
				t.Fatalf("platform/ingest-1.cert: %v %v", fi, err)
			}
			regularExport(t, st, out, "ingest-1.cert")
			if err := os.WriteFile(tmp, bytes.Repeat([]byte{1}, len(want)), 0o644); err != nil {
				t.Fatal(err)
			}
			if outsideToo {
				if err := os.WriteFile(outside, bytes.Repeat([]byte{2}, len(want)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(mustReadFile(t, p), want) {
				t.Fatal("platform/ingest-1.cert changed with another name")
			}
		})
	}
}

// TestPublishMissingOverValidEntry (review of task 24 A2, N3, after
// TestRevMissingOverValidEntry): admin-2.cert and admin-2.pub are
// missing in data/platform/, and the log holds admin-2.cert with other
// content than the export's. Publish refuses before anything is written
// (RUNBOOK 7.3 "Liegt keine der beiden Dateien dort"), not only when
// logging, and the retry is refused the same way.
func TestPublishMissingOverValidEntry(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	_, expB, _ := otherAdmin2(t, f, st)
	for _, n := range []string{"admin-2.cert", "admin-2.pub"} {
		if err := removePlatformFile(st, n); err != nil {
			t.Fatal(err)
		}
	}
	logged := lookupCert(t, st, f.res.Pin, "admin-2.cert")
	before := platformSnapshot(t, st)
	for run := 1; run <= 2; run++ {
		err := Publish(PublishOptions{From: expB, Data: st, Pin: f.res.Pin})
		if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) {
			t.Fatalf("run %d: missing name over a valid entry: %v", run, err)
		}
		for _, s := range []string{"admin-2.cert is missing", "a valid entry is never replaced; nothing written",
			"publish the export that holds the logged admin-2.cert", "next generation (RUNBOOK 7.3)"} {
			if !strings.Contains(err.Error(), s) {
				t.Fatalf("run %d: message without %q: %v", run, s, err)
			}
		}
		if platformSnapshot(t, st) != before {
			t.Fatalf("run %d: written before the refusal", run)
		}
		if es := lookupCert(t, st, f.res.Pin, "admin-2.cert"); len(es) != 1 || !bytes.Equal(es[0].Content, logged[0].Content) {
			t.Fatalf("run %d: log changed: %+v", run, es)
		}
	}
}

// TestPublishWitnessesLink (after TestRev24AWitnessesLink):
// platform/witnesses.rec, a file of the export (Init writes it), as a
// symbolic or hard link to a file outside with the pin's witnesses is
// never taken for them, as under the other names of the export: without
// ReplaceWitnesses publish refuses before anything is written and
// names the link; with it, publish replaces the link itself by a
// regular file with the pin's witnesses, and the outside file keeps its
// content.
func TestPublishWitnessesLink(t *testing.T) {
	for _, kind := range []string{"symbolic", "hard"} {
		for _, replace := range []bool{false, true} {
			name := kind
			if replace {
				name += "/replace"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				st, _ := f.published(t, "data")
				out := filepath.Join(f.base, "out")
				if _, err := os.Stat(filepath.Join(out, "platform", WitnessesFile)); err != nil {
					t.Fatalf("export without %s: %v", WitnessesFile, err)
				}
				p := st.Path("platform", WitnessesFile)
				want := mustReadFile(t, p)
				outside := filepath.Join(f.base, "outside-w")
				if err := os.WriteFile(outside, want, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hard" {
					link = os.Link
				}
				if err := link(outside, p); err != nil {
					t.Skip(err)
				}
				before := platformSnapshot(t, st)
				called := false
				var linkKind string
				var after *witness.Witnesses
				err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: replace,
					WitnessesReplaced: func(_, _ *witness.Witnesses) { called = true },
					WitnessesLinkReplaced: func(link string, w *witness.Witnesses) {
						if linkKind != "" {
							t.Error("WitnessesLinkReplaced called twice")
						}
						linkKind, after = link, w
					}})
				if !replace {
					if !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), p+" is a "+kind+" link") ||
						!strings.Contains(err.Error(), "nothing written") || !strings.Contains(err.Error(), "--replace-witnesses") {
						t.Fatalf("%s link as witnesses.rec: %v", kind, err)
					}
					if platformSnapshot(t, st) != before {
						t.Fatal("written before the refusal")
					}
					if linkKind != "" {
						t.Fatal("WitnessesLinkReplaced called without a replacement")
					}
					return
				}
				if err != nil {
					t.Fatalf("publish --replace-witnesses: %v", err)
				}
				if called {
					t.Fatal("WitnessesReplaced called for a link, whose content is not read")
				}
				// Review of task 25 A, H4: the replaced link is reported,
				// with the pin's witnesses and quorum.
				if linkKind != "a "+kind+" link" || after == nil ||
					!sameWitnesses(after.List, after.Min, pinWitnesses(f.res.Pin), f.res.Pin.MinWitnesses) {
					t.Fatalf("WitnessesLinkReplaced: %q %+v", linkKind, after)
				}
				fi, err := os.Lstat(p)
				if err != nil || !fi.Mode().IsRegular() || nlink(fi) != 1 || !bytes.Equal(mustReadFile(t, p), want) {
					t.Fatalf("witnesses.rec after publish: %v %v", fi, err)
				}
				if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(mustReadFile(t, p), want) {
					t.Fatal("witnesses.rec changed with the outside file")
				}
			})
		}
	}
}

// Tests of task 25 package 25A, rework 25A2 (reviews of 25A): the cases
// of the specification review that the tests above left open, platform/
// as a symbolic link (L1), the temporary files publish removes and names
// (L2, H1), a succession relogged from data/platform/ that is a link
// (H5), and the messages.

// TestPublishServerLockKeepsTmp (after TestRv25LockedKeepsTmp): with the
// server lock held, publish refuses with ErrServer and removes no
// ".tmp-" file: the running server may be writing it.
func TestPublishServerLockKeepsTmp(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	tmp := st.Path("platform", ".tmp-9999999999999999")
	if err := os.WriteFile(tmp, []byte("server writes"), 0o644); err != nil {
		t.Fatal(err)
	}
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var removed []string
	err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) { removed = append(removed, n) }})
	if !errors.Is(err, ErrServer) {
		t.Fatalf("publish under a held server lock: %v", err)
	}
	if _, err := os.Lstat(tmp); err != nil || removed != nil {
		t.Fatalf(".tmp- removed without the server lock: %v %q", err, removed)
	}
}

// TestPublishSuccMissingOverValidEntry (after
// TestRv25SuccMissingOverValidEntry; review of task 24 A2, N3, for a
// succession): identity-2.succ is missing in data/platform/ and the log
// holds identity-2.succ with other content (another valid_from) than the
// export's. Publish refuses before anything is written, with the remedy
// for a succession, also when the name is a symbolic link (linkErr), and
// the export with the logged succession heals the name.
func TestPublishSuccMissingOverValidEntry(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	pin2 := f.pinN(t, 2)
	pub2, s2 := f.succ(t, 2)
	exp := writeExport(t, filepath.Join(f.base, "s2"), map[string][]byte{"identity-2.pub": pub2, "identity-2.succ": s2})
	if err := Publish(PublishOptions{From: exp, Data: st, Pin: pin2}); err != nil {
		t.Fatal(err)
	}
	id1, _ := f.platform(t).IdentityKey(1)
	sb, err := keys.NewPlatformSuccession(id1, 2, pub2, testNow.Add(time.Second).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	s2B, _ := sb.Encode()
	if bytes.Equal(s2B, s2) {
		t.Fatal("same content")
	}
	expB := writeExport(t, filepath.Join(f.base, "s2b"), map[string][]byte{"identity-2.pub": pub2, "identity-2.succ": s2B})
	if err := removePlatformFile(st, "identity-2.succ"); err != nil {
		t.Fatal(err)
	}
	before := platformSnapshot(t, st)
	err = Publish(PublishOptions{From: expB, Data: st, Pin: pin2})
	if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), "identity-2.succ is missing") ||
		!strings.HasSuffix(err.Error(), "; nothing written: publish the export that holds the logged succession identity-2.succ or, "+succThiefHint) ||
		strings.Contains(err.Error(), "reissue") {
		t.Fatalf("missing succession over a valid entry: %v", err)
	}
	if platformSnapshot(t, st) != before {
		t.Fatal("written before the refusal")
	}
	// The same name as a symbolic link to a file outside with the logged
	// succession: linkErr, with the remedy for a succession as well.
	p := st.Path("platform", "identity-2.succ")
	outside := filepath.Join(f.base, "outside-identity-2.succ")
	if err := os.WriteFile(outside, s2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	before = platformSnapshot(t, st)
	err = Publish(PublishOptions{From: expB, Data: st, Pin: pin2})
	if !errors.Is(err, store.ErrExists) || !strings.Contains(err.Error(), p+" is a symbolic link") ||
		!strings.HasSuffix(err.Error(), "; nothing written: look at the link; publish the export that holds the logged succession identity-2.succ, which replaces the link, or, "+succThiefHint) ||
		strings.Contains(err.Error(), "reissue") {
		t.Fatalf("succession as a link over a valid entry: %v", err)
	}
	if platformSnapshot(t, st) != before {
		t.Fatal("written before the refusal")
	}
	if err := Publish(PublishOptions{From: exp, Data: st, Pin: pin2}); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || !bytes.Equal(mustReadFile(t, p), s2) {
		t.Fatalf("not healed: %v %v", fi, err)
	}
	if !bytes.Equal(mustReadFile(t, outside), s2) {
		t.Fatal("outside file changed")
	}
}

// TestPublishMissingLoggedSameHealed (after TestRv25MissingSameHealed):
// a missing certificate and public key whose valid entry is the export's
// file are written back, and nothing is logged again.
func TestPublishMissingLoggedSameHealed(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	want := mustReadFile(t, p)
	for _, n := range []string{"ingest-1.cert", "ingest-1.pub"} {
		if err := removePlatformFile(st, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatalf("heal of a missing name: %v", err)
	}
	if !bytes.Equal(mustReadFile(t, p), want) {
		t.Fatal("not healed")
	}
	if es := lookupCert(t, st, f.res.Pin, "ingest-1.cert"); len(es) != 1 {
		t.Fatalf("log: %d", len(es))
	}
}

// TestPublishTmpLinkDuringPublish (after TestRv25TmpLinkAfterRemove;
// review of task 24 A2, N1): a ".tmp-" hard link to the logged
// ingest-1.cert made after the temporary files were removed (by an
// attacker, not a crash) counts as another name: the entry is replaced,
// and the ".tmp-" name no longer changes it.
func TestPublishTmpLinkDuringPublish(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	want := mustReadFile(t, p)
	tmp := st.Path("platform", ".tmp-feedfacefeedface")
	serr := swapAt(t, "publish-open", "ingest-1.cert", func() error { return os.Link(p, tmp) })
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if *serr != nil {
		t.Skip(*serr)
	}
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	a, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.Lstat(tmp); err != nil || os.SameFile(a, b) {
		t.Fatalf(".tmp- name made during publish hides a hard link: %v", err)
	}
	if err := os.WriteFile(tmp, bytes.Repeat([]byte{1}, len(want)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, p), want) {
		t.Fatal("changed with the .tmp- name")
	}
}

// TestPublishCrashTmpUnfreeableName (after TestRv25CrashTempUnfreeable;
// review of task 24 A2, N1, and of 25 A, L2): a ".tmp-" name that a
// crash left as a second name of identity-1.pub (a name freeName never
// frees) or of witnesses.rec (a crash of gomail-server init) does not
// make the retry refuse a hard link: it is removed first, and
// TempRemoved names it.
func TestPublishCrashTmpUnfreeableName(t *testing.T) {
	for _, n := range []string{"identity-1.pub", WitnessesFile} {
		t.Run(n, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", n)
			const tmp = ".tmp-0102030405060708"
			if err := os.Link(p, st.Path("platform", tmp)); err != nil {
				t.Skip(err)
			}
			var removed []string
			if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) { removed = append(removed, n) }}); err != nil {
				t.Fatalf("retry after a crash: %v", err)
			}
			fi, err := os.Lstat(p)
			if err != nil || nlink(fi) != 1 {
				t.Fatalf("%s: %v %v", n, fi, err)
			}
			if strings.Join(removed, " ") != tmp {
				t.Fatalf("TempRemoved: %q", removed)
			}
		})
	}
}

// TestPublishTmpRemovedBeforeRefusal (review of task 25 A, L2 and H1):
// the temporary files are removed and named also when publish refuses
// afterwards (here checkDataPlatform, for a certificate that does not
// decode); a failure to remove them names platform/.
func TestPublishTmpRemovedBeforeRefusal(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	for _, n := range []string{".tmp-1111111111111111", ".tmp-2222222222222222"} {
		if err := os.WriteFile(st.Path("platform", n), []byte("rest"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(st.Path("platform", "admin-9.cert"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	var removed []string
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(n string) { removed = append(removed, n) }})
	if err == nil || !strings.Contains(err.Error(), "platform/admin-9.cert") {
		t.Fatalf("garbage certificate: %v", err)
	}
	if strings.Join(removed, " ") != ".tmp-1111111111111111 .tmp-2222222222222222" {
		t.Fatalf("TempRemoved: %q", removed)
	}
	for _, n := range []string{".tmp-1111111111111111", ".tmp-2222222222222222"} {
		if _, err := os.Lstat(st.Path("platform", n)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s kept: %v", n, err)
		}
	}

	// platform/ that cannot be listed (a regular file in its place).
	plat := st.Path("platform")
	if err := os.Rename(plat, plat+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plat, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if err == nil || !strings.HasPrefix(err.Error(), "ceremony: removing temporary files of platform/: ") || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("platform/ not a directory: %v", err)
	}
}

// TestPublishPlatformIsLink (after TestRev25APlatformIsLink; review of
// task 25 A, L1): platform/ of the data directory is a symbolic link to a
// directory outside it with a ".tmp-" file of its own. Publish refuses
// before it removes or writes anything, naming the link; the outside
// directory is unchanged.
func TestPublishPlatformIsLink(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	elsewhere := filepath.Join(f.base, "elsewhere")
	if err := os.Rename(st.Path("platform"), elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, st.Path("platform")); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(elsewhere, ".tmp-foreignfile")
	if err := os.WriteFile(foreign, []byte("someone else's"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Something to write: ingest-1.cert is missing, its entry logged.
	if err := os.Remove(filepath.Join(elsewhere, "ingest-1.cert")); err != nil {
		t.Fatal(err)
	}
	before := fmt.Sprint(listDir(t, elsewhere))
	called := false
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(string) { called = true }})
	// Review of task 25 A2, H3: the message names the target of the link
	// and says "nothing removed or written" once.
	if !errors.Is(err, errPlatformLink) ||
		!strings.Contains(err.Error(), st.Path("platform")+" points to "+strconv.Quote(elsewhere)+"; nothing removed or written: ") ||
		strings.Count(err.Error(), "nothing") != 1 {
		t.Fatalf("platform/ as a symbolic link: %v", err)
	}
	if _, ferr := os.Lstat(foreign); ferr != nil || called {
		t.Fatalf("outside .tmp- file removed: %v %v", ferr, called)
	}
	if got := fmt.Sprint(listDir(t, elsewhere)); got != before {
		t.Fatalf("written outside: %s", got)
	}
}

// TestPublishRecheckError (review of task 25 A): when the second os.Lstat
// of an entry fails other than with a missing name, the message names
// that error and does not claim the entry was replaced.
func TestPublishRecheckError(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	plat := st.Path("platform")
	p := st.Path("platform", "ingest-1.cert")
	serr := swapAt(t, "publish-recheck", "ingest-1.cert", func() error {
		if err := os.Rename(plat, plat+".moved"); err != nil {
			return err
		}
		return os.WriteFile(plat, nil, 0o644)
	})
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if *serr != nil {
		t.Fatal(*serr)
	}
	if !errors.Is(err, syscall.ENOTDIR) || errors.Is(err, errChanged) || strings.Contains(err.Error(), "replaced") ||
		!strings.Contains(err.Error(), "ceremony: looking at "+p+" again after reading it: ") {
		t.Fatalf("second lstat fails: %v", err)
	}
}

// TestPublishCheckEntrySwapped (review of task 25 A, H5, for
// checkDataPlatform): the logged ingest-1.cert, a regular file when
// platform/ is listed, is replaced by a symbolic link to a file outside
// with the same content, or removed: after the listing, before
// checkDataPlatform looks at it (at the hook of admin-1.cert, which
// comes before it), before it opens it or while it reads it.
// checkDataPlatform does not read through the link and refuses with
// errChanged; nothing is written.
func TestPublishCheckEntrySwapped(t *testing.T) {
	// how is what the message says (review of task 25 A2, H4: a swap
	// before checkDataPlatform looks at the entry happened after the
	// listing).
	for _, c := range []struct{ point, at, kind, how string }{
		{"check-open", "ingest-1.cert", "symlink", " was replaced before it was opened; "},
		{"check-recheck", "ingest-1.cert", "symlink", " was replaced while it was read; "},
		{"check-open", "ingest-1.cert", "gone", " is gone; "},
		{"check-open", "admin-1.cert", "symlink", " was replaced by a symbolic link after platform/ was listed; "},
		{"check-open", "admin-1.cert", "gone", " was removed after platform/ was listed; "},
	} {
		t.Run(c.point+"/"+c.at+"/"+c.kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", "ingest-1.cert")
			want := mustReadFile(t, p)
			outside := filepath.Join(f.base, "outside")
			var after string
			serr := swapAt(t, c.point, c.at, func() error {
				var err error
				if c.kind == "gone" {
					err = os.Remove(p)
				} else if err = os.WriteFile(outside, want, 0o644); err == nil {
					err = replaceBy(p, outside, nil)
				}
				after = platformSnapshot(t, st)
				return err
			})
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			crashHook = nil
			if *serr != nil {
				t.Fatal(*serr)
			}
			if after == "" {
				t.Fatal("hook not reached")
			}
			if !errors.Is(err, errChanged) || !strings.Contains(err.Error(), p+c.how) {
				t.Fatalf("%s at %s: %v", c.kind, c.point, err)
			}
			if platformSnapshot(t, st) != after {
				t.Fatal("written after the swap")
			}
		})
	}
}

// TestPublishRelogLink (after TestRev25ARelogLink; review of task 25 A,
// H5): data/platform/identity-2.succ, neither logged nor in the export,
// which needs it for identity-2.pub, is a symbolic or hard link to a file
// outside with the valid succession. Publish does not log it through the
// link: it refuses before anything is written or logged, naming the
// link.
func TestPublishRelogLink(t *testing.T) {
	for _, kind := range []string{"symbolic", "hard"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			pin2 := f.pinN(t, 2)
			s2pub, s2 := f.succ(t, 2)
			exp := writeExport(t, filepath.Join(f.base, "exp"), map[string][]byte{"identity-2.pub": s2pub})
			outside := filepath.Join(f.base, "outside-succ")
			if err := os.WriteFile(outside, s2, 0o644); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", "identity-2.succ")
			link := os.Symlink
			if kind == "hard" {
				link = os.Link
			}
			if err := link(outside, p); err != nil {
				t.Skip(err)
			}
			before := platformSnapshot(t, st)
			err := Publish(PublishOptions{From: exp, Data: st, Pin: pin2})
			if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), p+" is a "+kind+" link, never logged through it") ||
				!strings.Contains(err.Error(), "nothing written: look at the link and remove it by hand") {
				t.Fatalf("succession as a %s link: %v", kind, err)
			}
			if platformSnapshot(t, st) != before {
				t.Fatal("written before the refusal")
			}
			if es := lookupCert(t, st, pin2, "identity-2.succ"); len(es) != 0 {
				t.Fatalf("logged through the link: %+v", es)
			}
			if !bytes.Equal(mustReadFile(t, outside), s2) {
				t.Fatal("outside file changed")
			}
		})
	}
}

// TestPublishRelogThroughSymlinkChain (after TestRv25RelogThroughSymlink):
// the succession identity-2.succ that the export of generation 3 needs
// as the predecessor of identity-3.succ is a symbolic link in
// data/platform/ to a file outside with the valid succession: refused,
// nothing logged, and the link stays.
func TestPublishRelogThroughSymlinkChain(t *testing.T) {
	c := newChain(t)
	target := filepath.Join(c.f.base, "outside-identity-2.succ")
	if err := os.WriteFile(target, c.file(t, c.out2, "identity-2.succ"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := c.st.Path("platform", "identity-2.succ")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := c.st.WritePlatformFile("identity-2.pub", c.file(t, c.out2, "identity-2.pub")); err != nil {
		t.Fatal(err)
	}
	err := Publish(PublishOptions{From: c.out3, Data: c.st, Pin: c.res3.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), p+" is a symbolic link, never logged through it") {
		t.Fatalf("relog through a symbolic link: %v", err)
	}
	for _, n := range []string{"identity-2.succ", "identity-3.succ"} {
		if i := c.logIndex(t, c.res3.Pin, n); i != -1 {
			t.Fatalf("%s logged at %d", n, i)
		}
	}
	if !isLink(t, p) {
		t.Fatal("link changed")
	}
}
