//go:build linux

package client_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// fanotify(7), as package syscall has no wrappers for it.
const (
	fanCloexec      = 0x1
	fanNonblock     = 0x2
	fanClassContent = 0x4
	fanMarkAdd      = 0x1
	fanAccessPerm   = 0x20000
	fanAllow        = 0x1
	fanEventSize    = 24 // struct fanotify_event_metadata
	atFDCWD         = -100
)

// grower makes a file one byte longer before it is first read.
type grower struct {
	events *os.File   // the fanotify group, nonblocking
	done   chan error // the outcome of the append, once
}

// errNoFanotify: the system has no fanotify permission events for this
// process (no CAP_SYS_ADMIN, or a kernel without
// CONFIG_FANOTIFY_ACCESS_PERMISSIONS).
var errNoFanotify = errors.New("no fanotify permission events here")

// growOnRead puts a sparse regular file of store.MaxMailFile bytes at
// path and makes it one byte longer within the first read(2) of it, after
// the reader's fstat and before the read gets any byte: a fanotify
// permission event (FAN_ACCESS_PERM) holds that read until the byte is
// appended through the event's file descriptor and the read is allowed.
// So the reader always sees the file grow beyond the size its fstat gave;
// there is no race with the reader, whatever the load and GOMAXPROCS. The
// group allows every later read unchanged; close ends it.
func growOnRead(path string) (*grower, error) {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	err = fh.Truncate(store.MaxMailFile)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, fanCloexec|fanNonblock|fanClassContent,
		uintptr(syscall.O_WRONLY|syscall.O_APPEND|syscall.O_LARGEFILE|syscall.O_CLOEXEC), 0)
	if errno != 0 {
		return nil, fmt.Errorf("%w: fanotify_init: %v", errNoFanotify, errno)
	}
	if err := fanotifyMark(int(fd), path, fanAccessPerm); err != nil {
		syscall.Close(int(fd))
		return nil, fmt.Errorf("%w: fanotify_mark: %v", errNoFanotify, err)
	}
	g := &grower{events: os.NewFile(fd, "fanotify"), done: make(chan error, 1)}
	go g.serve()
	return g, nil
}

// fanotifyMark adds mask to the marks of group fd on path. On a 32-bit
// system the 64-bit mask takes two arguments, in the order of its bytes
// in memory.
func fanotifyMark(fd int, path string, mask uint64) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	at := atFDCWD
	var errno syscall.Errno
	if unsafe.Sizeof(uintptr(0)) == 8 {
		_, _, errno = syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(fd), fanMarkAdd, uintptr(mask),
			uintptr(at), uintptr(unsafe.Pointer(p)), 0)
	} else {
		lo, hi := uintptr(uint32(mask)), uintptr(uint32(mask>>32))
		if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
			lo, hi = hi, lo
		}
		_, _, errno = syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(fd), fanMarkAdd, lo, hi,
			uintptr(at), uintptr(unsafe.Pointer(p)))
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// serve answers the permission events of g: the first one after the byte
// is appended, every one with FAN_ALLOW. It ends when g is closed.
func (g *grower) serve() {
	buf := make([]byte, 4096)
	first := true
	for {
		n, err := g.events.Read(buf)
		if err != nil {
			if first {
				g.done <- err
			}
			return
		}
		for b := buf[:n]; len(b) >= fanEventSize; {
			size := binary.NativeEndian.Uint32(b)
			fd := int32(binary.NativeEndian.Uint32(b[16:]))
			if size < fanEventSize || int(size) > len(b) {
				break
			}
			b = b[size:]
			if fd < 0 {
				continue // overflow: no read is held
			}
			var werr error
			if first {
				_, werr = syscall.Write(int(fd), []byte{0})
			}
			syscall.Close(int(fd))
			resp := make([]byte, 8) // struct fanotify_response
			binary.NativeEndian.PutUint32(resp, uint32(fd))
			binary.NativeEndian.PutUint32(resp[4:], fanAllow)
			if _, err := g.events.Write(resp); werr == nil {
				werr = err
			}
			if first {
				first = false
				g.done <- werr
			}
		}
	}
}

// close ends the group: a read held meanwhile is allowed by the kernel.
func (g *grower) close() { g.events.Close() }

// wait waits for g to append its byte, then ends the group.
func (g *grower) wait(t *testing.T) {
	t.Helper()
	defer g.close()
	select {
	case err := <-g.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the file was not read")
	}
}

// TestUnprocessedMailGrewBeyond: a mail file that grows beyond
// store.MaxMailFile while it is read, after fstat gave a size within the
// limit (the branch "grew beyond" of store.ReadFileLimited), is a verdict
// like one whose size fstat gives above the limit: Search takes the terms
// of the metadata, Index indexes the entry with them and deletes the
// marker, each with one warning "Format ungültig" (task 28, Nr. 107). The
// branch is reached without a change of package store: the mail file is
// replaced since the listing by a sparse file of store.MaxMailFile bytes
// that grows by one byte within the first read of it (growOnRead, a
// fanotify permission event that holds the read). The append does not
// race the reader (review 28C, F1: an append after the read, on inotify
// IN_ACCESS, came too late once store read the whole file with one
// read(2)), so every stage reaches the branch. Without fanotify
// permission events (they need CAP_SYS_ADMIN) the test is skipped with
// the reason.
func TestUnprocessedMailGrewBeyond(t *testing.T) {
	dir := t.TempDir()
	// The mechanism, read without package store and like it (open,
	// fstat, one read of up to the limit plus one byte): the file grows
	// within the read.
	g, err := growOnRead(filepath.Join(dir, "probe"))
	if errors.Is(err, errNoFanotify) {
		t.Skipf("the file cannot be made to grow within a read here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(dir, "probe"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fh.Stat()
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.ReadFull(fh, make([]byte, store.MaxMailFile+2))
	fh.Close()
	if err != io.ErrUnexpectedEOF {
		g.close()
		t.Fatal(err)
	}
	if fi.Size() != store.MaxMailFile || n != store.MaxMailFile+1 {
		// No permission event held the read (a file system without
		// them, for example).
		g.close()
		t.Skipf("the file did not grow within a read here: fstat %d, read %d", fi.Size(), n)
	}
	g.wait(t)
	// The branch of store.ReadFileLimited this test is about.
	path := filepath.Join(dir, "file")
	if g, err = growOnRead(path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFileLimited(path, store.MaxMailFile); !errors.Is(err, store.ErrTooLarge) || !strings.Contains(err.Error(), "grew beyond") {
		g.close()
		t.Fatalf("ReadFileLimited: %v, want the branch \"grew beyond\"", err)
	}
	g.wait(t)
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	m := mailBySubject(t, f, "longto")
	path = f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID)
	f.u.Client.Close()
	armed := false
	g = nil
	t.Cleanup(func() {
		if g != nil {
			g.close()
		}
	})
	client.SetLogHook(t, func(l translog.Log) translog.Log {
		return &vanishLog{Log: l, path: path, armed: &armed, then: func(path string) {
			if g, err = growOnRead(path); err != nil {
				t.Error(err)
			}
		}}
	})
	c, err := client.Open(f.env.ClientConfig(f.u.Dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	restore := func() {
		t.Helper()
		if armed || g == nil {
			t.Fatal("the mail file was not replaced since the listing")
		}
		g.wait(t)
		g = nil
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".away", path); err != nil {
			t.Fatal(err)
		}
	}
	want := "WARNUNG: Suchbegriffe der Mail " + m.ID.String() + " nur aus ihren Metadaten: Format ungültig."
	warnings := func(stage string, n int) {
		t.Helper()
		if w := f.env.Warnings.Take(); len(w) != n || n == 1 && w[0] != want {
			t.Fatalf("%s: warnings %q", stage, w)
		}
	}
	armed = true
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "" {
		t.Fatalf("search: %q", got)
	}
	restore()
	warnings("search", 1)
	armed = true
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	restore()
	warnings("index", 1)
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("marker left")
	}
	for _, tc := range []struct{ q, want string }{
		{"to:addr000@recipients.example", "longto"},
		{"to:addr139@recipients.example", ""},
	} {
		if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
			t.Fatalf("%s after index: %q, want %q", tc.q, got, tc.want)
		}
	}
	warnings("end", 0)
}
