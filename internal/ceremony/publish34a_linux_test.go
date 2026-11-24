//go:build linux && gomail_test

package ceremony

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 34 package A (review of task 33 A, H1; review of task
// 34 A, N2): another process changes the temporary file of a file
// publish writes into platform/ (store.SetTempInHook, only with the tag
// gomail_test, stands for it). publish refuses with the path, what is
// there and the remedy, logs nothing and calls no callback "replaced";
// the foreign entry stays.

// afterMsg is the error of store for name after the rename or link.
func afterMsg(step, p, what string) string {
	return "store: after the " + step + ", " + p + " is " + what + ", not the file written: " + store.ErrReplacedMeanwhile.Error()
}

// tempSwap sets the hook of store for the test: at the first call with
// point, change is called with the path of the temporary file.
func tempSwap(t *testing.T, point string, change func(tmp string) error) *bool {
	t.Helper()
	done := new(bool)
	restore := store.SetTempInHook(func(root *os.Root, tmp, pt string) {
		if pt != point || *done {
			return
		}
		*done = true
		if err := change(filepath.Join(root.Name(), tmp)); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	return done
}

// toDir moves the temporary file away and puts a directory with a file
// in it under its name.
func toDir(tmp string) error {
	if err := os.Rename(tmp, tmp+"-away"); err != nil {
		return err
	}
	return os.Mkdir(tmp, 0o755)
}

// publishWithin runs Publish and fails the test if it does not return
// within a minute (an open of a FIFO would wait for a writer).
func publishWithin(t *testing.T, opts PublishOptions) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Publish(opts) }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Minute):
		t.Fatal("publish hangs")
		return nil
	}
}

// replaceWitnessesSetup publishes the fixture and puts a working copy
// with other witnesses under witnesses.rec, so that a publish with
// ReplaceWitnesses announces the replacement.
func replaceWitnessesSetup(t *testing.T, f *fixture) (*store.Store, string) {
	t.Helper()
	st, _ := f.published(t, "data")
	other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	p := st.Path("platform", WitnessesFile)
	if err := os.WriteFile(p, other, 0o660); err != nil {
		t.Fatal(err)
	}
	return st, p
}

// logHook records whether publish reaches its log.
func logHook(t *testing.T) *bool {
	logged := new(bool)
	crashHook = func(pt string) error {
		if pt == "publish-log" {
			*logged = true
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	return logged
}

// TestPublishWitnessesTempDirMissingName (review of task 33 A, H1): the
// first publish writes witnesses.rec (missing, nothing announced);
// another process puts a directory under the temporary file before the
// rename, which renameat(2) puts over the missing name. Before, publish
// reported success with a directory under witnesses.rec; now it
// refuses with the path and the remedy, and the directory stays.
func TestPublishWitnessesTempDirMissingName(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	p := st.Path("platform", WitnessesFile)
	done := tempSwap(t, "rename", toDir)
	logged := logHook(t)
	err := publishWithin(t, PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin})
	if !*done || *logged || !errors.Is(err, store.ErrReplacedMeanwhile) {
		t.Fatalf("swap %v, logged %v, err %v", *done, *logged, err)
	}
	if want := meanwhileMsg(p, afterMsg("rename", p, "not a regular file")); err.Error() != want {
		t.Fatalf("message\n%q, want\n%q", err.Error(), want)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
		t.Fatalf("witnesses.rec: %v %v", fi, err)
	}
}

// TestPublishWitnessesReplacedMeanwhile (review of task 34 A, N2): with
// ReplaceWitnesses, after the line of WitnessesReplacing, another
// process changes the temporary file or witnesses.rec. publish calls no
// callback "replaced", logs nothing, says what holds for witnesses.rec
// ("is not the file publish wrote" when the rename happened, "was not
// replaced" when it failed) and names the other process; the foreign
// entry stays, and nothing hangs.
func TestPublishWitnessesReplacedMeanwhile(t *testing.T) {
	for _, c := range []struct {
		name, point string
		change      func(p, tmp string) error
		// state is the state of witnesses.rec, what the error of store
		// (nil: another file under witnesses.rec), kind the type of the
		// foreign entry.
		state string
		what  func(p, tmp string) string
		kind  fs.FileMode
	}{
		{"dir-name-missing", "rename", func(p, tmp string) error {
			if err := os.Remove(p); err != nil {
				return err
			}
			return toDir(tmp)
		}, stateNotWritten, func(p, _ string) string { return afterMsg("rename", p, "not a regular file") }, fs.ModeDir},
		{"dir-name-emptydir", "rename", func(p, tmp string) error {
			if err := os.Remove(p); err != nil {
				return err
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				return err
			}
			return toDir(tmp)
			// The check of os.Root.Rename refuses a directory under the
			// new name (EEXIST); renameat(2) would put the directory over
			// an empty one only in the window after that check.
		}, stateNotReplaced, func(p, tmp string) string {
			return "rename " + tmp + " " + p + ": file exists; store: " + tmp + " is not a regular file, not the file written, and stays: " + store.ErrReplacedMeanwhile.Error()
		}, fs.ModeDir},
		{"fifo-before-close", "written", func(_, tmp string) error {
			if err := os.Rename(tmp, tmp+"-away"); err != nil {
				return err
			}
			return syscall.Mkfifo(tmp, 0o644)
		}, stateNotWritten, func(p, _ string) string { return afterMsg("rename", p, "not a regular file") }, fs.ModeNamedPipe},
		{"other-after-rename", "renamed", func(p, _ string) error {
			if err := os.WriteFile(p+"-other", []byte("x"), 0o660); err != nil {
				return err
			}
			return os.Rename(p+"-other", p)
		}, stateNotWritten, nil, 0},
		{"dir-name-file", "rename", func(_, tmp string) error {
			if err := toDir(tmp); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(tmp, "x"), nil, 0o644)
		}, stateNotReplaced, func(p, tmp string) string {
			return "rename " + tmp + " " + p + ": not a directory; store: " + tmp + " is not a regular file, not the file written, and stays: " + store.ErrReplacedMeanwhile.Error()
		}, fs.ModeDir},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			st, p := replaceWitnessesSetup(t, f)
			var tmpPath string
			done := tempSwap(t, c.point, func(tmp string) error {
				tmpPath = tmp
				return c.change(p, tmp)
			})
			logged := logHook(t)
			calls, announced := 0, 0
			err := publishWithin(t, PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin, ReplaceWitnesses: true,
				WitnessesReplacing:    func(*witness.Witnesses, string, *witness.Witnesses) { announced++ },
				WitnessesReplaced:     func(_, _ *witness.Witnesses) { calls++ },
				WitnessesLinkReplaced: func(string, *witness.Witnesses) { calls++ }})
			if !*done || *logged || calls != 0 || announced != 1 || !errors.Is(err, store.ErrReplacedMeanwhile) {
				t.Fatalf("swap %v, logged %v, calls %d, announced %d, err %v", *done, *logged, calls, announced, err)
			}
			what := afterMsg("rename", p, "another file")
			if c.what != nil {
				what = c.what(p, tmpPath)
			}
			if want := replaceMeanwhileMsg(p, what, c.state); err.Error() != want {
				t.Fatalf("message\n%q, want\n%q", err.Error(), want)
			}
			if strings.Contains(err.Error(), "was not replaced") != (c.state == stateNotReplaced) {
				t.Fatalf("state: %v", err)
			}
			at := p
			if c.state == stateNotReplaced {
				at = tmpPath
			}
			fi, lerr := os.Lstat(at)
			if lerr != nil || fi.Mode().Type() != c.kind {
				t.Fatalf("the foreign entry under %s: %v %v", at, fi, lerr)
			}
		})
	}
}

// TestPublishExportFileReplacedMeanwhile: the export's files are
// written with store.CreateFileAtomicIn (a missing name) and
// store.WriteFileAtomicIn (a hard link replaced, freeName); another
// process puts a FIFO or a directory under the temporary file. publish
// refuses with writeErr, logs nothing, and the foreign entry stays.
func TestPublishExportFileReplacedMeanwhile(t *testing.T) {
	t.Run("create-fifo", func(t *testing.T) {
		f := newFixture(t)
		st := newData(t, filepath.Join(f.base, "data"))
		var tmpPath string
		done := tempSwap(t, "link", func(tmp string) error {
			tmpPath = tmp
			if err := os.Rename(tmp, tmp+"-away"); err != nil {
				return err
			}
			return syscall.Mkfifo(tmp, 0o644)
		})
		logged := logHook(t)
		err := publishWithin(t, PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin})
		if !*done || *logged || !errors.Is(err, store.ErrReplacedMeanwhile) {
			t.Fatalf("swap %v, logged %v, err %v", *done, *logged, err)
		}
		msg := err.Error()
		i := strings.Index(msg, ": store: after the link, ")
		if i < 0 || !strings.HasPrefix(msg, "ceremony: writing ") {
			t.Fatalf("message %q", msg)
		}
		p := msg[len("ceremony: writing "):i]
		if want := meanwhileMsg(p, afterMsg("link", p, "not a regular file")); msg != want {
			t.Fatalf("message\n%q, want\n%q", msg, want)
		}
		for _, at := range []string{p, tmpPath} {
			if fi, err := os.Lstat(at); err != nil || fi.Mode().Type() != fs.ModeNamedPipe {
				t.Fatalf("the FIFO under %s: %v %v", at, fi, err)
			}
		}
	})
	t.Run("create-exists-fifo", func(t *testing.T) {
		// The name taken meanwhile by the export's file itself and a
		// FIFO under the temporary name: the link finds the name
		// (store.ErrExists), but the temporary name is not the file
		// written, so publish refuses instead of taking the name for
		// the export's file (writeErr before the check of ErrExists).
		f := newFixture(t)
		st := newData(t, filepath.Join(f.base, "data"))
		exp := filepath.Join(f.base, "out", "platform")
		var p string
		done := tempSwap(t, "link", func(tmp string) error {
			b, err := os.ReadFile(tmp)
			if err != nil {
				return err
			}
			ents, err := os.ReadDir(exp)
			if err != nil {
				return err
			}
			for _, e := range ents {
				if eb, err := os.ReadFile(filepath.Join(exp, e.Name())); err == nil && string(eb) == string(b) {
					p = st.Path("platform", e.Name())
				}
			}
			if p == "" {
				return errors.New("no export file with the content of the temporary file")
			}
			if err := os.WriteFile(p, b, 0o660); err != nil {
				return err
			}
			if err := os.Rename(tmp, tmp+"-away"); err != nil {
				return err
			}
			return syscall.Mkfifo(tmp, 0o644)
		})
		logged := logHook(t)
		err := publishWithin(t, PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin})
		if !*done || *logged || !errors.Is(err, store.ErrReplacedMeanwhile) || !errors.Is(err, store.ErrExists) {
			t.Fatalf("swap %v, logged %v, err %v", *done, *logged, err)
		}
		if !strings.HasPrefix(err.Error(), "ceremony: writing "+p+": store: file exists: "+filepath.Base(p)+"; store: ") {
			t.Fatalf("message %q", err.Error())
		}
	})
	t.Run("replace-dir", func(t *testing.T) {
		f := newFixture(t)
		st, _ := f.published(t, "data")
		p := st.Path("platform", "admin-1.cert")
		if err := os.Link(p, filepath.Join(f.base, "second-name")); err != nil {
			t.Skip(err)
		}
		done := tempSwap(t, "rename", toDir)
		logged := logHook(t)
		err := publishWithin(t, PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin})
		if !*done || *logged || !errors.Is(err, store.ErrReplacedMeanwhile) {
			t.Fatalf("swap %v, logged %v, err %v", *done, *logged, err)
		}
		// A directory is not put over a file: the rename fails, the
		// directory stays under the temporary name, and admin-1.cert is
		// the hard link it was.
		var le *os.LinkError
		if !errors.As(err, &le) {
			t.Fatalf("no *os.LinkError: %v", err)
		}
		if want := meanwhileMsg(p, "rename "+le.Old+" "+p+": not a directory; store: "+le.Old+
			" is not a regular file, not the file written, and stays: "+store.ErrReplacedMeanwhile.Error()); err.Error() != want {
			t.Fatalf("message\n%q, want\n%q", err.Error(), want)
		}
		if fi, err := os.Lstat(le.Old); err != nil || !fi.IsDir() {
			t.Fatalf("the directory under %s: %v %v", le.Old, fi, err)
		}
	})
}
