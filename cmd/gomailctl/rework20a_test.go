package main

import (
	"runtime"
	"testing"
)

// TestSameDeviceDevpts (task 20a point 4): two terminals with the same
// device number (st_rdev) whose nodes lie in different file systems
// (st_dev), as /dev/pts/3 of two instances of devpts, are not the same
// terminal; the same number in the same file system is. The stat values
// are made up: a second instance of devpts needs a mount.
func TestSameDeviceDevpts(t *testing.T) {
	pts := termID{rdev: 136<<8 | 3, dev: 25}
	if !sameDevice(pts, pts) {
		t.Fatal("one pseudo terminal is not the same terminal")
	}
	other := termID{rdev: pts.rdev, dev: 26}
	if sameDevice(pts, other) || sameDevice(other, pts) {
		t.Fatal("the same pts number in two instances of devpts counts as one terminal")
	}
	if sameDevice(pts, termID{rdev: 136<<8 | 4, dev: 25}) {
		t.Fatal("two pts numbers count as one terminal")
	}
	if tty := (termID{rdev: 5 << 8, dev: 5}); runtime.GOOS == "linux" && sameDevice(tty, tty) {
		t.Fatal("/dev/tty counts as the same terminal by its device number")
	}
}
