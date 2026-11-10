//go:build unix

package translog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestFIFOPlatformCandidates (task 24 package F, R41): a FIFO in place of
// platform/ makes candidates return at once with the certificates of the
// state only (none here) instead of an open that waits for a writer;
// candidates lists platform/ with store.ReadDir and ignores an error, as
// before. The list of entries/ in create follows store.MkdirAll, which
// refuses a FIFO there already (TestFIFOInLogDirectory covers the rest
// of log/).
func TestFIFOPlatformCandidates(t *testing.T) {
	st, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	platform := st.Path("platform")
	if err := os.RemoveAll(platform); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, platform)
	l := &fileLog{st: st}
	fifoNoHang(t, "candidates", platform, nil, func() error {
		if c := l.candidates(&state{}); len(c) != 0 {
			t.Errorf("candidates: %d, want none", len(c))
		}
		return nil
	})
}
