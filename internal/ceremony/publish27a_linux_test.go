//go:build linux

package ceremony

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestPublishEntryReplacedBySocket (backlog 86, X6 of the review of the
// specification of 26B2): right before publish opens ingest-1.cert
// (hook "check-open ingest-1.cert"), a socket is renamed over it. The
// open fails (ENXIO), with an error that is neither "missing" nor "no
// regular file", and the socket is no symbolic link: only os.SameFile
// with what os.Lstat saw before tells that the entry was replaced, and
// publish says so instead of returning the error of the open. The
// socket is made under another name first and renamed over the file, so
// that it never gets the inode number of the file (which is still in use
// when the socket is made).
func TestPublishEntryReplacedBySocket(t *testing.T) {
	f := newFixture(t)
	st, _ := f.published(t, "data")
	out := filepath.Join(f.base, "out")
	p := st.Path("platform", "ingest-1.cert")
	sock := st.Path("platform", "sock")
	var serr error
	hit := false
	crashHook = func(pt string) error {
		if pt != "check-open ingest-1.cert" || hit {
			return nil
		}
		hit = true
		if serr = syscall.Mknod(sock, syscall.S_IFSOCK|0o644, 0); serr == nil {
			serr = os.Rename(sock, p)
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	crashHook = nil
	if serr != nil || !hit {
		t.Fatalf("swap: %v %v", serr, hit)
	}
	if fi, lerr := os.Lstat(p); lerr != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no socket in place: %v %v", fi, lerr)
	}
	if !errors.Is(err, errChanged) || err.Error() != "ceremony: an entry of platform/ changed while publish read it: "+p+" was replaced before it was opened; another process writes platform/ during publish: stop it, look at the entry and run the same publish again" {
		t.Fatalf("socket in place of ingest-1.cert: %v", err)
	}
	// The socket from the start is refused by its kind before any open
	// (store.ErrNotRegular, no ENXIO; review of task 27 A, N2), never
	// "replaced".
	err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
	if errors.Is(err, errChanged) || errors.Is(err, syscall.ENXIO) || !errors.Is(err, store.ErrNotRegular) || err.Error() != notRegularMsg(p) {
		t.Fatalf("socket under ingest-1.cert: %v", err)
	}
}

// TestPublishNonRegularKinds (review of task 27 A, N1, N2, F3 and F4):
// a socket, character devices (that of /dev/null and that of /dev/tty,
// whose open fails with ENXIO without a controlling terminal), a block
// device, a directory without permissions, a FIFO with a writer waiting
// for a reader and an empty directory, each under a name of section 4
// that the export does not hold (admin-3.pub, ingest-2.pub,
// identity-1.succ), under one it holds (ingest-1.cert) and under
// witnesses.rec. Each is store.ErrNotRegular by the kind os.Lstat shows,
// never opened (the writer of the FIFO still waits), never ENXIO or
// EACCES; under a name of section 4 with the path of the entry,
// "nothing written or logged" and the remedy. Nothing is written or
// logged. readEntry refuses each the same way, also called directly.
// Devices need CAP_MKNOD; without it their cases are skipped.
func TestPublishNonRegularKinds(t *testing.T) {
	kinds := []struct {
		name string
		make func(p string) error
	}{
		{"socket", func(p string) error { return syscall.Mknod(p, syscall.S_IFSOCK|0o644, 0) }},
		{"chr-null", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, int(1<<8|3)) }},
		{"chr-tty", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, int(5<<8|0)) }},
		{"blk-loop", func(p string) error { return syscall.Mknod(p, syscall.S_IFBLK|0o600, int(7<<8|0)) }},
		{"dir-000", func(p string) error { return os.Mkdir(p, 0) }},
		{"dir", func(p string) error { return os.Mkdir(p, 0o755) }},
		{"fifo-writer", func(p string) error { return syscall.Mkfifo(p, 0o644) }},
	}
	for _, name := range []string{"admin-3.pub", "ingest-2.pub", "identity-1.succ", "ingest-1.cert", WitnessesFile} {
		for _, k := range kinds {
			t.Run(name+"-"+k.name, func(t *testing.T) {
				f := newFixture(t)
				st, _ := f.published(t, "data")
				out := filepath.Join(f.base, "out")
				p := st.Path("platform", name)
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if err := k.make(p); err != nil {
					if errors.Is(err, syscall.EPERM) {
						t.Skipf("%s: %v", k.name, err)
					}
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(p, 0o700) })
				var opened chan struct{}
				if k.name == "fifo-writer" {
					opened = make(chan struct{})
					go func() {
						// Blocks until a reader opens the FIFO.
						if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
							close(opened)
							w.Close()
						}
					}()
					time.Sleep(50 * time.Millisecond)
				}
				before := platformSnapshot(t, st)
				logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
				err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
				if opened != nil {
					select {
					case <-opened:
						t.Error("publish opened the FIFO")
					case <-time.After(50 * time.Millisecond):
					}
					// Let the writer go.
					if r, oerr := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); oerr == nil {
						select {
						case <-opened:
						case <-time.After(5 * time.Second):
							t.Error("the writer of the FIFO did not get its open")
						}
						r.Close()
					}
				}
				want := notRegularMsg(p)
				if name == WitnessesFile {
					want = "store: " + WitnessesFile + " is not a regular file"
				}
				if !errors.Is(err, store.ErrNotRegular) || errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.EACCES) || err.Error() != want {
					t.Fatalf("%s as %s: %v", name, k.name, err)
				}
				if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
					t.Fatal("written or logged before the refusal")
				}
				if k.name == "fifo-writer" {
					return
				}
				pd, _, err := openPlatformDir(st)
				if err != nil {
					t.Fatal(err)
				}
				defer pd.Close()
				b, link, err := readEntry(st, pd, name)
				if b != nil || link != "" || !errors.Is(err, store.ErrNotRegular) || err.Error() != "store: "+name+" is not a regular file" {
					t.Fatalf("readEntry of %s as %s: %q %q %v", name, k.name, b, link, err)
				}
			})
		}
	}
}
