//go:build unix

package ceremony

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of the rework 26B2 of task 26 package B (reviews of 26B):
// messages with paths (N2), an entry replaced by a symbolic link that
// got the freed inode number (N3), and the gaps the review of the
// specification found (N2: a failing rename of witnesses.rec, an entry
// that cannot be opened).

// TestPublishWitnessesRenameFailsNoCallback (review of the
// specification of task 26 package B, proposal): witnesses.rec, a
// working copy with other witnesses, is replaced by a directory after
// it was read (hook "publish-open admin-1.cert"), so the rename of the
// new witnesses.rec fails. No callback is called (witnesses.rec was not
// replaced), the error of the rename is returned with the paths of both
// names (review N2: as at 3ea40f0), no temporary file is left, and the
// log is not reached.
func TestPublishWitnessesRenameFailsNoCallback(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(f.base, "out")
	st := newData(t, filepath.Join(f.base, "data"))
	if err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	plat := st.Path("platform")
	p := filepath.Join(plat, WitnessesFile)
	other, err := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, other, 0o644); err != nil {
		t.Fatal(err)
	}
	logged := false
	done := false
	crashHook = func(pt string) error {
		switch pt {
		case "publish-open admin-1.cert":
			if !done {
				done = true
				if err := os.Remove(p); err != nil {
					return err
				}
				if err := os.Mkdir(p, 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(p, "x"), nil, 0o644)
			}
		case "publish-log":
			logged = true
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	calls := 0
	err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, ReplaceWitnesses: true,
		WitnessesReplaced:     func(_, _ *witness.Witnesses) { calls++ },
		WitnessesLinkReplaced: func(string, *witness.Witnesses) { calls++ }})
	crashHook = nil
	if !done || calls != 0 || logged || !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("swap %v, calls %d, logged %v, err %v", done, calls, logged, err)
	}
	var le *os.LinkError
	if !errors.As(err, &le) || le.Op != "rename" || filepath.Dir(le.Old) != plat || !strings.HasPrefix(filepath.Base(le.Old), ".tmp-") || le.New != p ||
		err.Error() != "rename "+le.Old+" "+p+": file exists" {
		t.Fatalf("message: %v", err)
	}
	ents, err := os.ReadDir(plat)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("left %s", e.Name())
		}
	}
}

// TestPublishEntryOpenDenied (review of the specification of task 26
// package B, proposal): an entry that cannot be opened (no read
// permission) is that error, never reported as replaced, and the
// message names its path as at 3ea40f0 ("open <platform>/ingest-1.cert:
// permission denied", review N2), not the name alone ("openat
// ingest-1.cert"). Without CAP_DAC_OVERRIDE only.
func TestPublishEntryOpenDenied(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	if fh, err := os.Open(p); err == nil {
		fh.Close()
		t.Skip("privileged: the file opens all the same")
	}
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, errChanged) || err.Error() != "open "+p+": permission denied" {
		t.Fatalf("open denied: %v", err)
	}
}

// TestPublishEntryReplacedByLinkOutside (review of task 26 package B,
// N3): right before publish opens ingest-1.cert (hook "check-open
// ingest-1.cert"), the file is removed and a symbolic link to a file
// outside platform/ put in its place. os.Root refuses to follow it, and
// the link often gets the inode number the removal freed, so that
// os.SameFile with the os.Lstat before took it for the same entry. It is
// "replaced before it was opened" in every run, and nothing outside is
// read. The runs repeat until the inode number was reused a few times
// (it is on tmpfs and ext4 as a rule); how often is logged.
func TestPublishEntryReplacedByLinkOutside(t *testing.T) {
	const runs, wantReused = 40, 3
	reused := 0
	for i := 0; i < runs && reused < wantReused; i++ {
		f := newFixture(t)
		st, _ := f.published(t, "data")
		out := filepath.Join(f.base, "out")
		p := st.Path("platform", "ingest-1.cert")
		outside := filepath.Join(f.base, "outside.cert")
		if err := os.WriteFile(outside, mustReadFile(t, p), 0o644); err != nil {
			t.Fatal(err)
		}
		var oldIno, newIno uint64
		var serr error
		hit := false
		crashHook = func(pt string) error {
			if pt != "check-open ingest-1.cert" || hit {
				return nil
			}
			hit = true
			var sb syscall.Stat_t
			if serr = syscall.Lstat(p, &sb); serr != nil {
				return nil
			}
			oldIno = uint64(sb.Ino)
			if serr = os.Remove(p); serr != nil {
				return nil
			}
			if serr = os.Symlink(outside, p); serr != nil {
				return nil
			}
			if serr = syscall.Lstat(p, &sb); serr == nil {
				newIno = uint64(sb.Ino)
			}
			return nil
		}
		err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
		crashHook = nil
		if serr != nil || !hit {
			t.Fatalf("swap: %v %v", serr, hit)
		}
		if oldIno == newIno {
			reused++
		}
		if !errors.Is(err, errChanged) || err.Error() != "ceremony: an entry of platform/ changed while publish read it: "+p+" was replaced before it was opened; another process writes platform/ during publish: stop it, look at the entry and run the same publish again" {
			t.Fatalf("run %d (inode number reused: %v): %v", i, oldIno == newIno, err)
		}
	}
	t.Logf("inode number reused by the link in %d runs", reused)
}

// TestPublishPlatformRemovedAfterOpen (review of task 26 package B,
// H1): platform/ is removed with everything in it once publish has
// opened it and removed the first temporary file (TempRemoved). The
// listing of checkDataPlatform fails then (getdents(2) of a removed
// directory, on Linux), and the message says "ceremony:" and names
// platform/ by its path, without "/./." (the name of the descriptor of
// the root). Nothing is written.
func TestPublishPlatformRemovedAfterOpen(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("getdents(2) of a removed directory fails with ENOENT on Linux")
	}
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	plat := st.Path("platform")
	if err := os.WriteFile(filepath.Join(plat, ".tmp-own"), []byte("own"), 0o644); err != nil {
		t.Fatal(err)
	}
	var serr error
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin, TempRemoved: func(string) { serr = os.RemoveAll(plat) }})
	if serr != nil {
		t.Fatal(serr)
	}
	if !errors.Is(err, fs.ErrNotExist) || err.Error() != "ceremony: listing platform/: readdirent "+plat+": no such file or directory" {
		t.Fatalf("platform/ removed after the open: %v", err)
	}
	if _, err := os.Lstat(plat); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("platform/ written again: %v", err)
	}
}
