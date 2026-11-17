//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 28 package 28A: store.ErrNotRegular of readEntry in
// runPublish with path and remedy (backlog 94), the line before
// witnesses.rec is replaced (backlog 85), and "written meanwhile" with
// the export's content (backlog 95, mutant A11/W4).

// notRegularReadMsg is the refusal of platform/<name> (path p) that was
// no regular file when readEntry looked at it in runPublish (backlog
// 94); why is written in the branch "written meanwhile", "" otherwise.
func notRegularReadMsg(p, why string) string {
	done := "nothing written or logged"
	if why != "" {
		done = "nothing logged, other files of the export may be written already"
	}
	return "ceremony: " + p + " is not a regular file (a FIFO, a device, a directory or a socket)" + why +
		": publish never reads or replaces such an entry; " + done + ": look at the entry, remove it by hand and run the same publish again"
}

// TestPublishNotRegularWrapped (backlog 94): every call of readEntry in
// runPublish that finds an entry that is no regular file (here a FIFO)
// refuses with the path of the entry and the remedy, and
// errors.Is(err, store.ErrNotRegular) holds:
//
//   - witnesses.rec, without and with ReplaceWitnesses (checkDataPlatform
//     does not look at it);
//   - ingest-1.cert in the comparison with the export, made a FIFO after
//     checkDataPlatform read it (hook "publish-open witnesses.rec");
//   - admin-2.cert in freeName, which reads the certificate of a public
//     key that differs (admin-2.cert missing when compared, a FIFO by the
//     time freeName reads it: hook "publish-recheck admin-2.pub");
//   - identity-2.succ that succChain.need would relog, made a FIFO after
//     checkDataPlatform checked it;
//   - admin-2.cert written meanwhile, a FIFO that appears after
//     admin-2.pub was written (hook "publish-file"): the message says
//     that other files may be written already, and admin-2.pub is.
//
// Nothing is logged in any case; before the writes nothing is written
// either (the FIFO is the only change).
func TestPublishNotRegularWrapped(t *testing.T) {
	for _, c := range []string{"witnesses", "witnesses-replace", "compare", "freename", "relog", "meanwhile"} {
		t.Run(c, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			from := filepath.Join(f.base, "out")
			pin := f.res.Pin
			name, at, why := WitnessesFile, "", ""
			a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
			switch c {
			case "compare":
				name, at = "ingest-1.cert", "publish-open "+WitnessesFile
			case "freename":
				from = writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
				if err := os.WriteFile(st.Path("platform", "admin-2.pub"), bytes.Repeat([]byte{9}, 32), 0o644); err != nil {
					t.Fatal(err)
				}
				name, at = "admin-2.cert", "publish-recheck admin-2.pub"
			case "relog":
				pin = f.pinN(t, 2)
				s2pub, s2 := f.succ(t, 2)
				from = writeExport(t, filepath.Join(f.base, "exp"), map[string][]byte{"identity-2.pub": s2pub})
				if err := os.WriteFile(st.Path("platform", "identity-2.succ"), s2, 0o644); err != nil {
					t.Fatal(err)
				}
				name, at = "identity-2.succ", "publish-open "+WitnessesFile
			case "meanwhile":
				from = writeExport(t, filepath.Join(f.base, "expA2"), map[string][]byte{"admin-2.pub": a2pub, "admin-2.cert": a2})
				name, at, why = "admin-2.cert", "publish-file", written
			}
			p := st.Path("platform", name)
			fifo := func() error {
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				return syscall.Mkfifo(p, 0o644)
			}
			if at == "" {
				if err := fifo(); err != nil {
					t.Fatal(err)
				}
			}
			var serr error
			hit := false
			crashHook = func(pt string) error {
				if pt != at || hit {
					return nil
				}
				hit = true
				serr = fifo()
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			logged := len(loggedPlatform(t, st, pin, "admin-2.cert")) + len(loggedPlatform(t, st, pin, "identity-2.succ"))
			before := platformSnapshot(t, st)
			err := Publish(PublishOptions{From: from, Data: st, Pin: pin, ReplaceWitnesses: c == "witnesses-replace"})
			crashHook = nil
			if serr != nil || at != "" && !hit {
				t.Fatalf("swap: %v %v", serr, hit)
			}
			if !errors.Is(err, store.ErrNotRegular) || errors.Is(err, errChanged) || err.Error() != notRegularReadMsg(p, why) {
				t.Fatalf("FIFO as %s: %v", name, err)
			}
			if n := len(loggedPlatform(t, st, pin, "admin-2.cert")) + len(loggedPlatform(t, st, pin, "identity-2.succ")); n != logged {
				t.Fatal("logged after the refusal")
			}
			// What changed in platform/: the FIFO, and in the branch
			// "written meanwhile" admin-2.pub, written before.
			set := map[string]string{}
			if at != "" {
				set[name] = name + " p---------"
			}
			if c == "meanwhile" {
				set["admin-2.pub"] = fmt.Sprintf("admin-2.pub ---------- %x", a2pub)
			}
			if now, want := platformSnapshot(t, st), snapshotWith(before, set); now != want {
				t.Fatalf("platform/ after the refusal:\n%s\nwant\n%s", now, want)
			}
			if c == "meanwhile" && !bytes.Equal(mustReadFile(t, st.Path("platform", "admin-2.pub")), a2pub) {
				t.Fatal("admin-2.pub not written before")
			}
		})
	}
}

// snapshotWith is the platformSnapshot before with the lines of the
// names in set replaced or added (set maps a name to its line).
func snapshotWith(before string, set map[string]string) string {
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSuffix(before, "\n"), "\n") {
		if l != "" {
			lines[strings.Fields(l)[0]] = l
		}
	}
	for n, l := range set {
		lines[n] = l
	}
	names := slices.Sorted(maps.Keys(lines))
	var b strings.Builder
	for _, n := range names {
		b.WriteString(lines[n] + "\n")
	}
	return b.String()
}

// TestPublishMeanwhileSameContent (backlog 95, mutant A11/W4 of the
// reviews of task 27 A): admin-1.pub is missing when publish compares,
// and another process writes it with the export's content before publish
// creates it (hook "publish-recheck ingest-1.pub", the last name of the
// export compared). The branch "written meanwhile" finds the export's
// content and goes on, without counting the name as written by publish:
// with platform/ moved away right before the log (hook "publish-log")
// the message says "nothing written or logged", and the moved directory
// holds exactly what the other process wrote.
func TestPublishMeanwhileSameContent(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "out")
	st := newData(t, filepath.Join(f.base, "data"))
	lg := newLog(t)
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg}); err != nil {
		t.Fatal(err)
	}
	p := st.Path("platform", "admin-1.pub")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	want := mustReadFile(t, filepath.Join(out, "platform", "admin-1.pub"))
	plat, moved := st.Path("platform"), filepath.Join(f.base, "moved")
	var werr, merr error
	wroteMeanwhile, movedAway := false, false
	crashHook = func(pt string) error {
		switch {
		case pt == "publish-recheck ingest-1.pub" && !wroteMeanwhile:
			wroteMeanwhile = true
			werr = os.WriteFile(p, want, 0o644)
		case pt == "publish-log" && !movedAway:
			movedAway = true
			merr = os.Rename(plat, moved)
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	logged := len(lg.names)
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, Log: lg})
	crashHook = nil
	if werr != nil || merr != nil || !wroteMeanwhile || !movedAway {
		t.Fatalf("hooks: %v %v %v %v", werr, merr, wroteMeanwhile, movedAway)
	}
	if !errors.Is(err, errPlatformReplaced) || err.Error() != "ceremony: platform/ of the data directory was replaced during publish: "+plat+
		" is no longer the directory publish opened; nothing written or logged: another process writes the data directory: stop it, look at platform/ and run the same publish again" {
		t.Fatalf("written meanwhile with the export's content: %v", err)
	}
	if len(lg.names) != logged {
		t.Fatalf("logged %q", lg.names[logged:])
	}
	if !bytes.Equal(mustReadFile(t, filepath.Join(moved, "admin-1.pub")), want) {
		t.Fatal("admin-1.pub is not what the other process wrote")
	}
}

// replacingChild is the environment variable that makes
// TestPublishWitnessesAnnouncedBeforeKill the child process: its value
// is "<data directory>|<export>".
const replacingChild = "GOMAIL_TEST_28A_REPLACING_CHILD"

// replacingLine is the line the callbacks of the child of
// TestPublishWitnessesAnnouncedBeforeKill print for WitnessesReplacing.
func replacingLine(before *witness.Witnesses, link string, after *witness.Witnesses) string {
	b := "-"
	if before != nil {
		b = fmt.Sprint(before.Min, len(before.List))
	}
	return fmt.Sprintf("replacing %s %q %d %d\n", b, link, after.Min, len(after.List))
}

// TestPublishWitnessesAnnouncedBeforeKill (backlog 85): with
// ReplaceWitnesses, WitnessesReplacing is called before the rename of
// witnesses.rec (the working copy there is still the old one, and the
// arguments are the old witnesses or the kind of link, and the pin's),
// and before WitnessesReplaced or WitnessesLinkReplaced, which come
// after the rename. A child process that prints its line on standard
// output and kills itself with SIGKILL right after the rename (hook
// "publish-sync witnesses.rec", before the other callbacks) has printed
// that line alone, and witnesses.rec is replaced: the replacement is
// reported without a new option. The working copy is a regular file
// with other witnesses, a symbolic link or a hard link (review of task
// 28 A, F2; mutant N7: the hard link left out); the file a link names
// stays as it was. With the pin's witnesses already there, and when
// witnesses.rec is written for the first time (missing), no callback
// comes.
func TestPublishWitnessesAnnouncedBeforeKill(t *testing.T) {
	if v := os.Getenv(replacingChild); v != "" {
		data, from, _ := strings.Cut(v, "|")
		st, err := store.Open(data)
		if err != nil {
			os.Exit(3)
		}
		pin, err := ReadPin(filepath.Join(from, "identity-1.pin"))
		if err != nil {
			os.Exit(3)
		}
		crashHook = func(pt string) error {
			if pt == "publish-sync "+WitnessesFile {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		}
		err = Publish(PublishOptions{From: from, Data: st, Pin: pin, ReplaceWitnesses: true,
			WitnessesReplacing: func(before *witness.Witnesses, link string, after *witness.Witnesses) {
				fmt.Fprint(os.Stdout, replacingLine(before, link, after))
			},
			WitnessesReplaced:     func(_, _ *witness.Witnesses) { fmt.Fprintln(os.Stdout, "replaced") },
			WitnessesLinkReplaced: func(string, *witness.Witnesses) { fmt.Fprintln(os.Stdout, "link replaced") }})
		fmt.Fprintln(os.Stdout, "returned", err)
		os.Exit(4)
	}
	for _, c := range []struct {
		kind, line string
		calls      []string
	}{
		{"regular", "replacing 1 1 \"\" 2 3\n", []string{"replacing 1 1 \"\" 2 3\n:old", "replaced:new"}},
		{"symbolic", "replacing - \"a symbolic link\" 2 3\n", []string{"replacing - \"a symbolic link\" 2 3\n:link", "link replaced:new"}},
		{"hard", "replacing - \"a hard link\" 2 3\n", []string{"replacing - \"a hard link\" 2 3\n:old", "link replaced:new"}},
		{"same", "", nil},
		{"missing", "", nil},
	} {
		t.Run(c.kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.base, "out")
			other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			// prepare publishes the export into a new data directory name
			// and puts the working copy of the case in place.
			prepare := func(name string) (*store.Store, string, []byte) {
				st, _ := f.published(t, name)
				p := st.Path("platform", WitnessesFile)
				pinW := mustReadFile(t, p)
				switch c.kind {
				case "regular":
					if err := os.WriteFile(p, other, 0o644); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
				case "symbolic", "hard":
					outside := filepath.Join(f.base, "outside-w-"+name)
					if err := os.WriteFile(outside, other, 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
					link := os.Symlink
					if c.kind == "hard" {
						link = os.Link
					}
					if err := link(outside, p); err != nil {
						t.Fatal(err)
					}
				}
				return st, p, pinW
			}
			// In this process: the order of the callbacks and what
			// witnesses.rec is when each comes.
			st, p, pinW := prepare("data")
			look := func() string {
				if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
					return "link"
				}
				if bytes.Equal(mustReadFile(t, p), pinW) {
					return "new"
				}
				return "old"
			}
			var calls []string
			err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true,
				WitnessesReplacing: func(before *witness.Witnesses, link string, after *witness.Witnesses) {
					calls = append(calls, replacingLine(before, link, after)+":"+look())
				},
				WitnessesReplaced:     func(_, _ *witness.Witnesses) { calls = append(calls, "replaced:"+look()) },
				WitnessesLinkReplaced: func(string, *witness.Witnesses) { calls = append(calls, "link replaced:"+look()) }})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(calls, c.calls) {
				t.Fatalf("callbacks %q, want %q", calls, c.calls)
			}
			if c.kind == "same" || c.kind == "missing" {
				if !bytes.Equal(mustReadFile(t, p), pinW) {
					t.Fatal("witnesses.rec is not the pin's")
				}
				return
			}
			// In a child killed right after the rename.
			st, p, pinW = prepare("data-child")
			cmd := exec.Command(os.Args[0], "-test.run=^TestPublishWitnessesAnnouncedBeforeKill$", "-test.count=1")
			cmd.Env = append(os.Environ(), replacingChild+"="+st.Root+"|"+out)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child: %v %q %q", err, stdout.String(), stderr.String())
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("child not killed: %v %q %q", err, stdout.String(), stderr.String())
			}
			if got := stdout.String(); got != c.line {
				t.Fatalf("child's output %q, want %q", got, c.line)
			}
			if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || !bytes.Equal(mustReadFile(t, p), pinW) {
				t.Fatalf("witnesses.rec not replaced by the child: %v %v", fi, err)
			}
			if c.kind != "regular" {
				for _, n := range []string{"data", "data-child"} {
					if !bytes.Equal(mustReadFile(t, filepath.Join(f.base, "outside-w-"+n)), other) {
						t.Fatalf("the file the link named changed (%s)", n)
					}
				}
			}
		})
	}
}

// TestListDir (backlog 95): listDir shows a directory that shows nothing
// below it, empty or without permissions, as "<path>/", so that
// platformSnapshot sees a directory under a name of platform/; a
// directory with entries shows through their paths, and symbolic links
// are not followed.
func TestListDir(t *testing.T) {
	d := t.TempDir()
	for _, m := range []struct {
		p    string
		mode os.FileMode
	}{{"empty", 0o755}, {"none", 0}, {"full", 0o755}, {"full/sub", 0o755}, {"full/sub/deep", 0o755}} {
		if err := os.Mkdir(filepath.Join(d, m.p), m.mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(d, "none"), 0o700) })
	if err := os.WriteFile(filepath.Join(d, "full", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("empty", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(listDir(t, d)); got != "[empty/ full/f full/sub/deep/ link none/]" {
		t.Fatalf("listDir: %s", got)
	}
}
