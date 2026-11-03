//go:build unix

package translog

import (
	"os"
	"testing"
)

// TestFIFONewestHeadSize (task 20e point 5, R41): a FIFO in place of
// heads/ makes newestHeadSize fail at once (ErrConsistency) instead of an
// open that waits for a writer; a missing heads/ is still no head, and a
// directory is read as before.
func TestFIFONewestHeadSize(t *testing.T) {
	f := &files{root: t.TempDir()}
	if n, err := f.newestHeadSize(); err != nil || n != 0 {
		t.Fatalf("missing heads/: %d %v", n, err)
	}
	heads := f.path(HeadsDir)
	mkfifo(t, heads)
	fifoNoHang(t, "newestHeadSize", heads, ErrConsistency, func() error {
		_, err := f.newestHeadSize()
		return err
	})
	if err := os.Remove(heads); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(heads, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"3.sig", "12.sig", "x.sig", "7.tmp"} {
		if err := os.WriteFile(f.path(HeadsDir+"/"+name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.newestHeadSize(); err != nil || n != 12 {
		t.Fatalf("heads/: %d %v", n, err)
	}
}
