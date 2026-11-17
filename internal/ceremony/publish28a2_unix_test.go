//go:build unix

package ceremony

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// replaceFailedMsg is the error of publish when the replacement of
// witnesses.rec (path p) fails after its line (review of task 28 A, F3),
// with the error cause of store.ReplaceFileIn.
func replaceFailedMsg(p, cause string) string {
	return "ceremony: replacing " + p + ": " + cause + "; " + p +
		" is unchanged and nothing is logged (files of the export may be written already): run the same publish again"
}

// TestPublishReplacingAfterExportFiles (review of task 28 A, F4; mutant
// N15: the line before the export's files): with ReplaceWitnesses and a
// working copy with other witnesses, admin-1.pub missing, the line of
// WitnessesReplacing comes after publish wrote the export's files
// (admin-1.pub is there when it comes) and before witnesses.rec is
// replaced. When writing the export's files fails (the hook
// "publish-file" after admin-1.pub stands for that), no line comes,
// witnesses.rec is unchanged and nothing is logged.
func TestPublishReplacingAfterExportFiles(t *testing.T) {
	for _, c := range []string{"order", "loop-fails"} {
		t.Run(c, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p := st.Path("platform", WitnessesFile)
			pinW := mustReadFile(t, p)
			other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, other, 0o644); err != nil {
				t.Fatal(err)
			}
			a1 := st.Path("platform", "admin-1.pub")
			if err := os.Remove(a1); err != nil {
				t.Fatal(err)
			}
			wantA1 := mustReadFile(t, filepath.Join(out, "platform", "admin-1.pub"))
			loopErr := errors.New("writing the export's files fails in the test")
			hit, logReached := false, false
			crashHook = func(pt string) error {
				switch {
				case pt == "publish-log":
					logReached = true
				case pt == "publish-file" && !hit:
					hit = true
					if c == "loop-fails" {
						return loopErr
					}
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			var calls []string
			err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true,
				WitnessesReplacing: func(*witness.Witnesses, string, *witness.Witnesses) {
					a1now, _ := os.ReadFile(a1)
					wnow, _ := os.ReadFile(p)
					calls = append(calls, "replacing", "admin-1.pub written "+boolText(bytes.Equal(a1now, wantA1)),
						"witnesses.rec old "+boolText(bytes.Equal(wnow, other)))
				},
				WitnessesReplaced: func(_, _ *witness.Witnesses) { calls = append(calls, "replaced") }})
			crashHook = nil
			if !hit {
				t.Fatal("hook publish-file not reached")
			}
			if c == "order" {
				want := []string{"replacing", "admin-1.pub written yes", "witnesses.rec old yes", "replaced"}
				if err != nil || !slices.Equal(calls, want) || !logReached {
					t.Fatalf("callbacks %q, want %q: %v", calls, want, err)
				}
				if !bytes.Equal(mustReadFile(t, p), pinW) {
					t.Fatal("witnesses.rec not replaced")
				}
				return
			}
			if !errors.Is(err, loopErr) || len(calls) != 0 || logReached {
				t.Fatalf("writing the export failed: callbacks %q, log reached %v: %v", calls, logReached, err)
			}
			if !bytes.Equal(mustReadFile(t, p), other) {
				t.Fatal("witnesses.rec changed")
			}
		})
	}
}

// boolText is "yes" or "no".
func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
