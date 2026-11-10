//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 25 package 25A, rework 25A4 (reviews of 25A3): the order
// of the witnesses.rec callbacks (N1) and the quoted link target of
// platform/ (H1).

// TestPublishWitnessesCallbackBeforeLog (after TestZZReplacedCallbackOrder
// of the specification review of 25A3, N1): WitnessesReplaced, for a
// regular working copy with other witnesses, and WitnessesLinkReplaced,
// for a symbolic link as witnesses.rec, are called after witnesses.rec
// was replaced by the pin's working copy (the callback reads it) and
// before the log entries are appended: here the crash hook fails publish
// at "publish-log", and each callback was called once all the same.
func TestPublishWitnessesCallbackBeforeLog(t *testing.T) {
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
			if kind == "regular" {
				if err := os.WriteFile(p, other, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				outside := filepath.Join(f.base, "outside-w")
				if err := os.WriteFile(outside, other, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, p); err != nil {
					t.Fatal(err)
				}
			}
			boom := errors.New("boom")
			logged := false
			crashHook = func(point string) error {
				if point == "publish-log" {
					logged = true
					return boom
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			calls := 0
			// replaced checks, in a callback, that witnesses.rec is the
			// pin's working copy already, a regular file, and that the
			// log has not been reached yet.
			replaced := func() {
				calls++
				fi, err := os.Lstat(p)
				if err != nil {
					t.Errorf("callback: %v", err)
					return
				}
				if !fi.Mode().IsRegular() {
					t.Errorf("callback before witnesses.rec was replaced: mode %v", fi.Mode())
					return
				}
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
					t.Errorf("callback before witnesses.rec was replaced: %v", err)
				}
				if logged {
					t.Error("callback after the log was reached")
				}
			}
			opts := PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true}
			if kind == "regular" {
				opts.WitnessesReplaced = func(_, _ *witness.Witnesses) { replaced() }
				opts.WitnessesLinkReplaced = func(string, *witness.Witnesses) { t.Error("link callback for a regular file") }
			} else {
				opts.WitnessesReplaced = func(_, _ *witness.Witnesses) { t.Error("WitnessesReplaced for a link") }
				opts.WitnessesLinkReplaced = func(string, *witness.Witnesses) { replaced() }
			}
			err = Publish(opts)
			if !errors.Is(err, boom) || calls != 1 || !logged {
				t.Fatalf("err %v, calls %d, log reached %v", err, calls, logged)
			}
			// witnesses.rec stays replaced after the failure.
			if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || !bytes.Equal(mustReadFile(t, p), want) {
				t.Fatalf("witnesses.rec after the failure: %v %v", fi, err)
			}
		})
	}
}

// TestPublishPlatformLinkTargetQuoted (review of task 25 A3, H1): the
// message for platform/ as a symbolic link quotes its target, which
// someone else chose: a newline and an escape sequence there come out
// escaped (strconv.Quote), never raw.
func TestPublishPlatformLinkTargetQuoted(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	elsewhere := filepath.Join(f.base, "else\nwhere\x1b[31m")
	if err := os.Rename(st.Path("platform"), elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, st.Path("platform")); err != nil {
		t.Fatal(err)
	}
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, errPlatformLink) ||
		!strings.Contains(err.Error(), st.Path("platform")+" points to "+strconv.Quote(elsewhere)+"; nothing removed or written: ") {
		t.Fatalf("platform/ as a link with control characters in its target: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Fatalf("control character in the message: %q", err.Error())
	}
}
