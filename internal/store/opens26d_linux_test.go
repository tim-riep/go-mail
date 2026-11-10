package store

import (
	"encoding/binary"
	"errors"
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
// .pub) and counts a second close. What stays hidden are only opens
// that overlap concurrently, from a second goroutine, so that their
// opens and their closes each meet in the queue with nothing between.
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
