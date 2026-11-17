//go:build linux

package ceremony

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 28 package 28A on Linux: a regular file replaced right
// after os.Lstat (backlog 93), and a device that os.Lstat shows is never
// opened, checked with inotify and without root (backlog 95).

// swapKinds are the entries a regular file is replaced by, or that lie
// under a name from the start: mknod of a character or block device
// needs CAP_MKNOD, except for the device 0:0 (a whiteout, which Linux
// lets anyone make since 5.8 and which has no driver: an open fails with
// ENXIO).
var swapKinds = []struct {
	name string
	make func(p string) error
}{
	{"fifo", func(p string) error { return syscall.Mkfifo(p, 0o644) }},
	{"dir", func(p string) error { return os.Mkdir(p, 0o755) }},
	{"dir-000", func(p string) error { return os.Mkdir(p, 0) }},
	{"socket", func(p string) error { return syscall.Mknod(p, syscall.S_IFSOCK|0o644, 0) }},
	{"chr-null", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, int(1<<8|3)) }},
	{"chr-tty", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, int(5<<8|0)) }},
	{"blk-loop", func(p string) error { return syscall.Mknod(p, syscall.S_IFBLK|0o600, int(7<<8|0)) }},
	{"chr-0-0", func(p string) error { return syscall.Mknod(p, syscall.S_IFCHR|0o644, 0) }},
}

// TestPublishEntrySwappedAfterLstat (backlog 93; mutants Y7/A15 of the
// reviews of task 27 A): a regular file that os.Lstat saw is replaced
// right before publish opens it (hook "<at>-open <name>") by a FIFO, a
// directory (also one without permissions), a socket, devices with and
// without a driver: in checkDataPlatform (ingest-1.cert), in the
// comparison with the export (ingest-1.cert) and for witnesses.rec.
// Each is errChanged, "was replaced before it was opened", never
// store.ErrNotRegular with "remove it by hand", which is for an entry
// that os.Lstat showed as no regular file. Nothing is written or
// logged: with the file put back, platform/ is as before.
func TestPublishEntrySwappedAfterLstat(t *testing.T) {
	for _, at := range []string{"check-open ingest-1.cert", "publish-open ingest-1.cert", "publish-open " + WitnessesFile} {
		for _, k := range swapKinds {
			t.Run(at+"-"+k.name, func(t *testing.T) {
				f := newFixture(t)
				st, _ := f.published(t, "data")
				out := filepath.Join(f.base, "out")
				_, name, _ := strings.Cut(at, " ")
				p, aside := st.Path("platform", name), filepath.Join(f.base, "aside")
				// Can this kind be made here at all?
				probe := filepath.Join(f.base, "probe")
				if err := k.make(probe); err != nil {
					if errors.Is(err, syscall.EPERM) {
						t.Skipf("%s: %v", k.name, err)
					}
					t.Fatal(err)
				}
				before := platformSnapshot(t, st)
				logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
				var serr error
				hit := false
				crashHook = func(pt string) error {
					if pt != at || hit {
						return nil
					}
					hit = true
					// The file stays elsewhere, so the new entry never gets
					// its inode number.
					if serr = os.Rename(p, aside); serr == nil {
						serr = k.make(p)
					}
					return nil
				}
				t.Cleanup(func() { crashHook = nil; os.Chmod(p, 0o700) })
				err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
				crashHook = nil
				if serr != nil || !hit {
					t.Fatalf("swap: %v %v", serr, hit)
				}
				want := "ceremony: an entry of platform/ changed while publish read it: " + p +
					" was replaced before it was opened; another process writes platform/ during publish: stop it, look at the entry and run the same publish again"
				if !errors.Is(err, errChanged) || errors.Is(err, store.ErrNotRegular) || err.Error() != want {
					t.Fatalf("%s replaced by %s: %v", name, k.name, err)
				}
				os.Chmod(p, 0o700)
				if err := os.RemoveAll(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(aside, p); err != nil {
					t.Fatal(err)
				}
				if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
					t.Fatal("written or logged before the refusal")
				}
			})
		}
	}
}

// inotifyOpens returns how often each name was opened in the directory
// watched by the inotify descriptor fd (IN_OPEN, IN_NONBLOCK) since the
// last call.
func inotifyOpens(t *testing.T, fd int) map[string]int {
	t.Helper()
	n := map[string]int{}
	buf := make([]byte, 1<<16)
	for {
		k, err := syscall.Read(fd, buf)
		if errors.Is(err, syscall.EAGAIN) || k == 0 {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		for b := buf[:k]; len(b) >= syscall.SizeofInotifyEvent; {
			mask := binary.NativeEndian.Uint32(b[4:])
			l := int(binary.NativeEndian.Uint32(b[12:]))
			name := b[syscall.SizeofInotifyEvent : syscall.SizeofInotifyEvent+l]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			if mask&syscall.IN_OPEN != 0 {
				n[string(name)]++
			}
			b = b[syscall.SizeofInotifyEvent+l:]
		}
	}
}

// TestPublishDeviceAtLstatNeverOpened (backlog 95; mutant Y1 of the
// review of task 27 A2, which survived without root): a device that
// os.Lstat already shows under ingest-1.cert (checkDataPlatform),
// admin-3.pub (a name of section 4 the export does not hold) or
// witnesses.rec (readEntry) is refused as store.ErrNotRegular and never
// opened. inotify (IN_OPEN on platform/) shows that no open reached it,
// while it shows the opens of the regular files publish reads and the
// test's own open of the device afterwards. The device 0:0 needs no
// CAP_MKNOD (Linux 5.8 and later) and no root; an open of it fails with
// ENXIO, which the refusal must not be. With CAP_MKNOD the device of
// /dev/null (1:3) and a block device (7:0) are checked as well; without
// it their cases are skipped, as is everything where the system refuses
// inotify or even the device 0:0.
func TestPublishDeviceAtLstatNeverOpened(t *testing.T) {
	devs := []struct {
		name string
		mode uint32
		dev  int
	}{
		{"chr-0-0", syscall.S_IFCHR | 0o644, 0},
		{"chr-null", syscall.S_IFCHR | 0o644, 1<<8 | 3},
		{"blk-loop", syscall.S_IFBLK | 0o600, 7<<8 | 0},
	}
	for _, name := range []string{"ingest-1.cert", "admin-3.pub", WitnessesFile} {
		for _, d := range devs {
			t.Run(name+"-"+d.name, func(t *testing.T) {
				f := newFixture(t)
				st, _ := f.published(t, "data")
				out := filepath.Join(f.base, "out")
				p := st.Path("platform", name)
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if err := syscall.Mknod(p, d.mode, d.dev); err != nil {
					if errors.Is(err, syscall.EPERM) {
						t.Skipf("mknod %s: %v (CAP_MKNOD, or Linux before 5.8 for 0:0)", d.name, err)
					}
					t.Fatal(err)
				}
				fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
				if err != nil {
					t.Skipf("inotify: %v", err)
				}
				defer syscall.Close(fd)
				if _, err := syscall.InotifyAddWatch(fd, st.Path("platform"), syscall.IN_OPEN); err != nil {
					t.Skipf("inotify watch: %v", err)
				}
				before := platformSnapshot(t, st)
				err = Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
				opens := inotifyOpens(t, fd)
				want := notRegularMsg(p)
				if name == WitnessesFile {
					want = notRegularReadMsg(p, "")
				}
				if !errors.Is(err, store.ErrNotRegular) || errors.Is(err, syscall.ENXIO) || errors.Is(err, errChanged) || err.Error() != want {
					t.Fatalf("%s as %s: %v", name, d.name, err)
				}
				if opens[name] != 0 {
					t.Fatalf("publish opened the device under %s %d times", name, opens[name])
				}
				// The watch sees the opens of publish: the regular files it
				// read before the refusal (checkDataPlatform reads
				// admin-1.cert first; before witnesses.rec it reads
				// ingest-1.cert as well).
				if opens["admin-1.cert"] == 0 {
					t.Fatalf("inotify saw no open of admin-1.cert: %v", opens)
				}
				// And it sees an open of the device itself, where the device
				// has a driver; 0:0 has none, its open fails with ENXIO.
				dev, oerr := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
				if oerr == nil {
					dev.Close()
					if inotifyOpens(t, fd)[name] == 0 {
						t.Fatalf("inotify did not see the open of %s", d.name)
					}
				} else if d.name == "chr-0-0" && !errors.Is(oerr, syscall.ENXIO) {
					t.Fatalf("open of the device 0:0: %v", oerr)
				}
				if platformSnapshot(t, st) != before {
					t.Fatal("written before the refusal")
				}
			})
		}
	}
}

// TestPublishEntryGoneAfterFailedOpen (backlog 93): ingest-1.cert is
// replaced by a socket right before publish opens it (the open fails with
// ENXIO), and right after the failed open (hook "check-failed
// ingest-1.cert") the socket is removed: the entry is gone, errChanged
// "is gone", not the error of the open. If the file is put back instead
// (the same file under the name again), nothing tells that the open hit
// another entry: publish refuses with the error of the open (ENXIO),
// neither errChanged nor store.ErrNotRegular, and writes or logs nothing
// (the window left).
func TestPublishEntryGoneAfterFailedOpen(t *testing.T) {
	for _, c := range []string{"gone", "back"} {
		t.Run(c, func(t *testing.T) {
			f := newFixture(t)
			st, _ := f.published(t, "data")
			out := filepath.Join(f.base, "out")
			p, aside := st.Path("platform", "ingest-1.cert"), filepath.Join(f.base, "aside")
			before := platformSnapshot(t, st)
			logged := len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert"))
			var serr error
			var hits []string
			crashHook = func(pt string) error {
				switch {
				case pt == "check-open ingest-1.cert" && len(hits) == 0:
					hits = append(hits, pt)
					if serr = os.Rename(p, aside); serr == nil {
						serr = syscall.Mknod(p, syscall.S_IFSOCK|0o644, 0)
					}
				case pt == "check-failed ingest-1.cert" && len(hits) == 1:
					hits = append(hits, pt)
					if serr = os.Remove(p); serr == nil && c == "back" {
						serr = os.Rename(aside, p)
					}
				}
				return nil
			}
			t.Cleanup(func() { crashHook = nil })
			err := Publish(PublishOptions{From: out, Data: st, Pin: f.res.Pin})
			crashHook = nil
			if serr != nil || len(hits) != 2 {
				t.Fatalf("swap: %v %v", serr, hits)
			}
			if c == "gone" {
				want := "ceremony: an entry of platform/ changed while publish read it: " + p +
					" is gone; another process writes platform/ during publish: stop it, look at the entry and run the same publish again"
				if !errors.Is(err, errChanged) || err.Error() != want {
					t.Fatalf("socket gone after the failed open: %v", err)
				}
				if err := os.Rename(aside, p); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, syscall.ENXIO) || errors.Is(err, errChanged) || errors.Is(err, store.ErrNotRegular) {
				t.Fatalf("file back after the failed open: %v", err)
			}
			if platformSnapshot(t, st) != before || len(loggedPlatform(t, st, f.res.Pin, "ingest-1.cert")) != logged {
				t.Fatal("written or logged before the refusal")
			}
		})
	}
}
