//go:build unix

package ceremony

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestReplaceFailedErrMeanwhile (task 34 package A, review of task 34
// A, N2): store.ErrReplacedMeanwhile gets the remedy that names the
// other process, in each of the three states: "is unchanged" when the
// temporary file failed (an *fs.PathError), "was not replaced" when
// the rename failed (an *os.LinkError), and "is not the file publish
// wrote" when the rename happened (neither); never "was not replaced"
// after a rename. errors.Is holds for the cause. writeErr completes
// store.ErrReplacedMeanwhile only and returns every other error as it
// is.
func TestReplaceFailedErrMeanwhile(t *testing.T) {
	st := newData(t, filepath.Join(t.TempDir(), "data"))
	p := st.Path("platform", WitnessesFile)
	tmp := st.Path("platform", ".tmp-0123456789abcdef")
	stays := fmt.Errorf("store: %s is not a regular file, not the file written, and stays: %w", tmp, store.ErrReplacedMeanwhile)
	for _, c := range []struct {
		name  string
		err   error
		state string
	}{
		{"temp", fmt.Errorf("%w; %w", &fs.PathError{Op: "write", Path: tmp, Err: syscall.EFBIG}, stays), stateUnchanged},
		{"rename", fmt.Errorf("%w; %w", &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.ENOTDIR}, stays), stateNotReplaced},
		{"after", fmt.Errorf("store: after the rename, %s is not a regular file, not the file written: %w", p, store.ErrReplacedMeanwhile), stateNotWritten},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := replaceFailedErr(st, c.err)
			if got, want := err.Error(), replaceMeanwhileMsg(p, c.err.Error(), c.state); got != want {
				t.Fatalf("message\n%q, want\n%q", got, want)
			}
			if !errors.Is(err, c.err) || !errors.Is(err, store.ErrReplacedMeanwhile) {
				t.Fatalf("errors.Is lost the cause: %v", err)
			}
			if got, want := writeErr(st, WitnessesFile, c.err).Error(), meanwhileMsg(p, c.err.Error()); got != want {
				t.Fatalf("writeErr\n%q, want\n%q", got, want)
			}
		})
	}
	other := &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.EXDEV}
	if err := writeErr(st, WitnessesFile, other); err != error(other) {
		t.Fatalf("writeErr changed %v", err)
	}
}

// meanwhileMsg is the message of writeErr.
func meanwhileMsg(p, cause string) string {
	return "ceremony: writing " + p + ": " + cause + "; nothing is logged (files of the export may be written already): " +
		"another process writes platform/ during publish: stop it, look at platform/ and run the same publish again"
}

// replaceMeanwhileMsg is the message of replaceFailedErr for
// store.ErrReplacedMeanwhile.
func replaceMeanwhileMsg(p, cause, state string) string {
	return "ceremony: replacing " + p + ": " + cause + "; " + p + " " + state +
		" and nothing is logged (files of the export may be written already): " +
		"another process writes platform/ during publish: stop it, look at platform/ and run the same publish again"
}

// stateNotWritten is the state of witnesses.rec in replaceMeanwhileMsg
// after a rename that happened.
const stateNotWritten = "is not the file publish wrote"
