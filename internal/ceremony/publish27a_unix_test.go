//go:build unix

package ceremony

import (
	"bytes"
	"errors"
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
)

// Tests of task 27 package 27A: the parts of backlog 40 that need no
// decision (a predecessor certificate in data/platform/ alone, a second
// genuine succession of a generation, entries of platform/ that are no
// regular files) and the gaps of backlog 86 (platform/ missing before
// the log, the message when publish wrote nothing).

// loggedPlatform returns the valid entries of the operator log of st
// under pin with the platform file name.
func loggedPlatform(t *testing.T, st *store.Store, pin *store.PlatformPin, name string) []translog.Entry {
	t.Helper()
	l, err := OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	es, err := l.Lookup(translog.KindPlatform, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// TestPublishPredecessorOnlyInPlatform (backlog 40, first part):
// ingest-2.cert and ingest-2.pub lie in data/platform/ without a log
// entry (a crash between the files and the log). The export of
// ingest-3 needs ingest-2.cert as its predecessor, which Append requires
// as a valid entry of the log: publish refuses before anything is
// written, and logs nothing; a file in data/platform/ alone does not
// count (the remedy that accepts nothing new, not a relog of the
// certificate). Publishing the export of ingest-2 first logs it, and
// then the export of ingest-3 goes in.
func TestPublishPredecessorOnlyInPlatform(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	i2pub, i2 := f.cert(t, 1, keys.RoleIngest, 2)
	i3pub, i3 := f.cert(t, 1, keys.RoleIngest, 3)
	for n, b := range map[string][]byte{"ingest-2.pub": i2pub, "ingest-2.cert": i2} {
		if err := st.WritePlatformFile(n, b); err != nil {
			t.Fatal(err)
		}
	}
	exp2 := writeExport(t, filepath.Join(f.base, "exp2"), map[string][]byte{"ingest-2.pub": i2pub, "ingest-2.cert": i2})
	exp3 := writeExport(t, filepath.Join(f.base, "exp3"), map[string][]byte{"ingest-3.pub": i3pub, "ingest-3.cert": i3})
	before := platformSnapshot(t, st)
	err := Publish(PublishOptions{From: exp3, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) ||
		err.Error() != "translog: an entry this one depends on is not in the log yet: ingest-3.cert needs ingest-2.cert, which is neither in the export nor a valid entry of the log: publish the export of ingest generation 2 first" {
		t.Fatalf("predecessor in data/platform/ alone: %v", err)
	}
	if platformSnapshot(t, st) != before {
		t.Fatal("written before the refusal")
	}
	for _, n := range []string{"ingest-2.cert", "ingest-3.cert"} {
		if es := loggedPlatform(t, st, f.res.Pin, n); len(es) != 0 {
			t.Fatalf("%s logged", n)
		}
	}
	for _, exp := range []string{exp2, exp3} {
		if err := Publish(PublishOptions{From: exp, Data: st, Pin: f.res.Pin}); err != nil {
			t.Fatalf("%s: %v", exp, err)
		}
	}
	for n, b := range map[string][]byte{"ingest-2.cert": i2, "ingest-3.cert": i3} {
		if es := loggedPlatform(t, st, f.res.Pin, n); len(es) != 1 || !bytes.Equal(es[0].Content, b) {
			t.Fatalf("%s not logged: %v", n, es)
		}
	}
}

// TestPublishSecondSuccession (backlog 40, second part): the log holds
// the genuine identity-2.succ, and the export holds a second genuine
// succession to the same key of generation 2 (signed by generation 1,
// another valid_from). Whatever data/platform/ holds under the name (the
// logged succession, or the second one with identity-2.pub missing),
// publish refuses before anything is written, with the duplicate log
// key and the remedy for a succession; the log keeps the first one only.
// (The name missing in data/platform/ is TestPublishSuccMissingOverValidEntry.)
func TestPublishSecondSuccession(t *testing.T) {
	for _, state := range []string{"logged", "second"} {
		t.Run(state, func(t *testing.T) {
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
			p := st.Path("platform", "identity-2.succ")
			want := p + " with other content than " + filepath.Join(expB, "platform", "identity-2.succ") + " of the export, and identity-2.succ is a valid entry of the log under this pin with other content than the export's: a valid entry is never replaced"
			if state == "second" {
				if err := os.WriteFile(p, s2B, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := removePlatformFile(st, "identity-2.pub"); err != nil {
					t.Fatal(err)
				}
				want = p + " is the same as " + filepath.Join(expB, "platform", "identity-2.succ") + ", and identity-2.succ is a valid entry of the log under this pin with other content than " +
					filepath.Join(expB, "platform", "identity-2.succ") + " of the export: a valid entry is never replaced; nothing written: publish the export that holds the logged succession identity-2.succ or, " + succThiefHint
			}
			before := platformSnapshot(t, st)
			err = Publish(PublishOptions{From: expB, Data: st, Pin: pin2})
			if !errors.Is(err, store.ErrExists) || !errors.Is(err, translog.ErrDuplicate) || !strings.Contains(err.Error(), want) {
				t.Fatalf("second succession of generation 2: %v", err)
			}
			if platformSnapshot(t, st) != before {
				t.Fatal("written before the refusal")
			}
			if es := loggedPlatform(t, st, pin2, "identity-2.succ"); len(es) != 1 || !bytes.Equal(es[0].Content, s2) {
				t.Fatalf("log: %v", es)
			}
		})
	}
}

// notRegularMsg is the refusal of an entry of platform/ at path p under
// a name of section 4 that is neither a regular file nor a symbolic link
// (review of task 27 A, N1).
func notRegularMsg(p string) string {
	return "ceremony: " + p + " is not a regular file (a FIFO, a device, a directory or a socket) under a name of section 4: publish never reads or replaces such an entry; nothing written or logged: look at the entry, remove it by hand and run the same publish again"
}

// unknownGenNotRegularMsg is the refusal of such an entry under the
// name of an identity generation g above the pin's generation pinGen
// (review of task 27 A, H3).
func unknownGenNotRegularMsg(p string, g, pinGen int) string {
	return "translog: data directory contradicts the log: " + p + " names identity generation " + strconv.Itoa(g) + ", the pin knows 1 to " + strconv.Itoa(pinGen) +
		", and is not a regular file (a FIFO, a device, a directory or a socket): no pin makes it a file of platform/ (Q10 point 5); nothing written or logged: look at the entry, remove it by hand and run the same publish again"
}

// TestPublishNonRegularBeforeName (backlog 40, third part): entries of
// data/platform/ under names of section 4 that are no regular files and
// no names of the export. An identity key or succession of a generation
// the pin does not know is refused by its name, as the start check of
// gomail-server refuses it, whether it is a symbolic link, a FIFO or a
// directory; for one that is no symbolic link the message asks to
// remove it by hand, not to install a new pin (review of task 27 A,
// H3). A FIFO or a directory under any other name of section 4 (also the
// public key of an admin or ingest generation) is store.ErrNotRegular,
// as readExport refuses it in the export, with its path, "nothing
// written or logged" and the remedy (review of task 27 A, N1). Nothing
// is written. A symbolic link under a name of a known generation stays
// unread, as before (readEntry judges links under the names of the
// export, RUNBOOK 7.3).
func TestPublishNonRegularBeforeName(t *testing.T) {
	unknown := func(n string, g int) func(st *store.Store) string {
		return func(st *store.Store) string { return unknownGenNotRegularMsg(st.Path("platform", n), g, 1) }
	}
	notRegular := func(n string) func(st *store.Store) string {
		return func(st *store.Store) string { return notRegularMsg(st.Path("platform", n)) }
	}
	for _, c := range []struct {
		name, kind string
		want       []error
		msg        func(st *store.Store) string
	}{
		{"identity-2.pub", "symbolic", []error{translog.ErrMismatch}, func(*store.Store) string {
			return "translog: data directory contradicts the log: platform/identity-2.pub names identity generation 2, the pin knows 1 to 1; install the new pin (on the server as well) before publish (Q10 point 5)"
		}},
		{"identity-2.succ", "fifo", []error{translog.ErrMismatch, store.ErrNotRegular}, unknown("identity-2.succ", 2)},
		{"identity-3.succ", "dir", []error{translog.ErrMismatch, store.ErrNotRegular}, unknown("identity-3.succ", 3)},
		{"admin-3.cert", "fifo", []error{store.ErrNotRegular}, notRegular("admin-3.cert")},
		{"ingest-3.cert", "dir", []error{store.ErrNotRegular}, notRegular("ingest-3.cert")},
		{"identity-1.succ", "fifo", []error{store.ErrNotRegular}, notRegular("identity-1.succ")},
		{"admin-3.pub", "dir", []error{store.ErrNotRegular}, notRegular("admin-3.pub")},
		{"ingest-2.pub", "fifo", []error{store.ErrNotRegular}, notRegular("ingest-2.pub")},
		{"ingest-3.cert", "symbolic", nil, nil},
	} {
		t.Run(c.name+"-"+c.kind, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			// A foreign admin-1.pub under a free name: publish would replace
			// it first, so it shows whether anything was written.
			foreign := bytes.Repeat([]byte{9}, 32)
			if err := os.WriteFile(st.Path("platform", "admin-1.pub"), foreign, 0o644); err != nil {
				t.Fatal(err)
			}
			p := st.Path("platform", c.name)
			var err error
			switch c.kind {
			case "symbolic":
				target := filepath.Join(f.base, "outside-"+c.name)
				if err = os.WriteFile(target, []byte("outside"), 0o644); err == nil {
					err = os.Symlink(target, p)
				}
			case "fifo":
				err = syscall.Mkfifo(p, 0o600)
			case "dir":
				err = os.Mkdir(p, 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := platformSnapshot(t, st)
			err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			if c.want == nil {
				if err != nil {
					t.Fatalf("symbolic link under a name of a known generation: %v", err)
				}
				if !bytes.Equal(mustReadFile(t, st.Path("platform", "admin-1.pub")), mustReadFile(t, filepath.Join(out, "platform", "admin-1.pub"))) {
					t.Fatal("admin-1.pub not healed")
				}
				return
			}
			if err == nil || err.Error() != c.msg(st) {
				t.Fatalf("%s as %s: %v", c.name, c.kind, err)
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("%s as %s: not %v: %v", c.name, c.kind, w, err)
				}
			}
			if platformSnapshot(t, st) != before {
				t.Fatal("written before the refusal")
			}
		})
	}
}

// TestPublishPlatformGoneBeforeLog (backlog 86, X4 of the review of the
// specification of 26B2): platform/ is moved away right before the log
// (hook "publish-log"), so that its path leads nowhere. Publish refuses
// before anything is logged (errPlatformReplaced). The message says
// "wrote to" only when publish wrote a file: into a new data directory
// it wrote the export's files; into the data directory the export was
// published to before it wrote nothing. With platform/ back in its
// place, the same publish logs every file.
func TestPublishPlatformGoneBeforeLog(t *testing.T) {
	for _, c := range []struct {
		name string
		want func(plat string) string
	}{
		{"written", replacedBeforeLog},
		{"nothing-written", func(plat string) string {
			return "ceremony: platform/ of the data directory was replaced during publish: " + plat +
				" is no longer the directory publish opened; nothing written or logged: another process writes the data directory: stop it, look at platform/ and run the same publish again"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.base, "out")
			st := newData(t, filepath.Join(f.base, "data"))
			lg := newLog(t)
			if c.name == "nothing-written" {
				if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg}); err != nil {
					t.Fatal(err)
				}
				lg = newLog(t)
			}
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
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg})
			crashHook = nil
			if serr != nil || !hit {
				t.Fatalf("move: %v %v", serr, hit)
			}
			if !errors.Is(err, errPlatformReplaced) || err.Error() != c.want(plat) || len(lg.names) != 0 {
				t.Fatalf("logged %q: %v", lg.names, err)
			}
			if _, err := os.Lstat(plat); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("platform/ made again: %v", err)
			}
			after := dirSnapshot(t, moved)
			if c.name == "nothing-written" && after != before {
				t.Fatalf("written: %s", after)
			}
			if c.name == "written" {
				if _, err := os.Lstat(filepath.Join(moved, "ingest-1.cert")); err != nil {
					t.Fatalf("ingest-1.cert not written into the opened directory: %v", err)
				}
			}
			if err := os.Rename(moved, plat); err != nil {
				t.Fatal(err)
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
