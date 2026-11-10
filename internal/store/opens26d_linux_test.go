package store

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"
)

// watchOpens (task 26, package 26D, point 2, backlog item 69) watches
// dir with inotify for IN_OPEN and IN_CLOSE and returns a function that
// gives, for each entry of dir, the number of opens and of closes since
// the last call. The kernel queues the events at every open and close
// of the file, whichever code path opens it: a read through
// ReadPlatformFile, which platformReadHook sees, and a read past it
// (ReadFileLimited, OpenRegular, os.Open) alike. The events of a call
// that has returned are in the queue, so the counts are complete when
// they are taken after the call.
//
// The kernel merges an event with the last one still queued when both
// are the same (inotify(7)): two opens of the same file with no other
// event of dir between them count once, and so do two closes. Counting
// the closes as well finds a second open that the first one hides. Two
// reads one after the other in one goroutine count two opens, since the
// close of the first lies between them; a descriptor held open while
// the file is read again closes after other events of dir (the close of
// the second read, the files platformReadHook writes, the read of the
// .pub) and counts a second close.
//
// The events do not show a descriptor that is never closed: a second
// open whose descriptor stays open after the call (leaked, or kept for
// a later read) leaves one open and one close in the queue when its
// open merges with the first one. heldFDs, taken after the call, finds
// every descriptor of the file that the process still holds (task 27,
// package 27D, backlog item 84). What stays hidden then is a second
// open whose descriptors are all closed again when the call returns and
// that either overlaps the first concurrently, from a second goroutine,
// so that their opens and their closes each meet in the queue with
// nothing between, or goes through another name of the file outside
// dir (a hard link elsewhere), of which the watch of dir hears nothing.
//
// On Linux the test needs inotify: it fails if inotify cannot be set
// up, and never passes on platformReadHook alone.
func watchOpens(t *testing.T, dir string) func() (opened, closed map[string]int) {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		t.Fatalf("inotify: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if _, err := syscall.InotifyAddWatch(fd, dir, syscall.IN_OPEN|syscall.IN_CLOSE); err != nil {
		t.Fatalf("inotify watch: %v", err)
	}
	buf := make([]byte, 64*1024)
	return func() (opened, closed map[string]int) {
		t.Helper()
		opened, closed = map[string]int{}, map[string]int{}
		for {
			m, err := syscall.Read(fd, buf)
			if errors.Is(err, syscall.EAGAIN) {
				return opened, closed
			}
			if err != nil {
				t.Fatalf("inotify read: %v", err)
			}
			for b := buf[:m]; len(b) > 0; {
				if len(b) < syscall.SizeofInotifyEvent {
					t.Fatalf("inotify: short event of %d bytes", len(b))
				}
				mask := binary.NativeEndian.Uint32(b[4:8])
				l := int(binary.NativeEndian.Uint32(b[12:16]))
				if len(b) < syscall.SizeofInotifyEvent+l {
					t.Fatalf("inotify: event name of %d bytes in %d", l, len(b))
				}
				if mask&syscall.IN_Q_OVERFLOW != 0 {
					t.Fatal("inotify: queue overflow, events lost")
				}
				name := b[syscall.SizeofInotifyEvent : syscall.SizeofInotifyEvent+l]
				for len(name) > 0 && name[len(name)-1] == 0 {
					name = name[:len(name)-1]
				}
				if len(name) > 0 {
					if mask&syscall.IN_OPEN != 0 {
						opened[string(name)]++
					}
					if mask&syscall.IN_CLOSE != 0 {
						closed[string(name)]++
					}
				}
				b = b[syscall.SizeofInotifyEvent+l:]
			}
		}
	}
}

// heldFDs (task 27, package 27D, point 1, backlog item 84) lists the
// descriptors in /proc/self/fd that refer to one of files, compared by
// device and inode (os.SameFile), so that a descriptor of a file that
// has since been replaced or removed counts as well. Each entry is the
// descriptor number and its link target. A descriptor that closes
// between the listing and its stat is skipped (the listing's own one
// among them); any other error fails the test.
func heldFDs(t *testing.T, files ...os.FileInfo) []string {
	t.Helper()
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatalf("descriptors: %v", err)
	}
	fds, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		t.Fatalf("descriptors: %v", err)
	}
	var held []string
	for _, fd := range fds {
		p := "/proc/self/fd/" + fd
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("descriptor %s: %v", fd, err)
		}
		for _, f := range files {
			if os.SameFile(fi, f) {
				target, _ := os.Readlink(p)
				held = append(held, fd+" -> "+target)
				break
			}
		}
	}
	return held
}
