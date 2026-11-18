//go:build unix

package ceremony

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReplaceFailedErrState (task 29 C point 1; review of task 28 A2, H4
// and H2): the error of a failed replacement of witnesses.rec after its
// line says "was not replaced" exactly when the rename failed because a
// directory stands under the name now (EEXIST of the check of os.Root,
// EISDIR of renameat(2) for a directory put there after that check;
// another process put it there), and "is unchanged" for every other
// error of store.ReplaceFileIn: of the temporary file (an EEXIST of its
// open with O_EXCL as well, a *fs.PathError) and of a rename that left
// the name as it was. errors.Is and errors.As hold for the cause. The
// EISDIR case cannot be brought about through os.Root in a test (the
// window between its check and renameat(2)), so the errors are made
// here.
func TestReplaceFailedErrState(t *testing.T) {
	st := newData(t, filepath.Join(t.TempDir(), "data"))
	p := st.Path("platform", WitnessesFile)
	tmp := st.Path("platform", ".tmp-0123456789abcdef")
	for _, c := range []struct {
		name  string
		err   error
		state string
	}{
		{"open-emfile", &fs.PathError{Op: "open", Path: tmp, Err: syscall.EMFILE}, stateUnchanged},
		{"open-eexist", &fs.PathError{Op: "open", Path: tmp, Err: syscall.EEXIST}, stateUnchanged},
		{"write-efbig", &fs.PathError{Op: "write", Path: tmp, Err: syscall.EFBIG}, stateUnchanged},
		{"rename-eexist", &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.EEXIST}, stateNotReplaced},
		{"rename-eisdir", &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.EISDIR}, stateNotReplaced},
		{"rename-eperm", &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.EPERM}, stateUnchanged},
		{"rename-enoent", &os.LinkError{Op: "rename", Old: tmp, New: p, Err: syscall.ENOENT}, stateUnchanged},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := replaceFailedErr(st, c.err)
			if got, want := err.Error(), replaceFailedMsg(p, c.err.Error(), c.state); got != want {
				t.Fatalf("message\n%q, want\n%q", got, want)
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("errors.Is lost the cause: %v", err)
			}
			var le *os.LinkError
			if _, isLink := c.err.(*os.LinkError); errors.As(err, &le) != isLink {
				t.Fatalf("errors.As *os.LinkError: %v", err)
			}
		})
	}
}
