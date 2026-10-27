//go:build (linux || darwin || freebsd || netbsd || openbsd || dragonfly) && !ceremony_notty

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckStderrReadOnly (task 15m point 3): a standard error that is
// open, but not for writing, is errStderrReadOnly, a kind of
// errStderrClosed (usage error, exit code 2): a regular file, a terminal
// or /dev/null opened read-only, the read end of a pipe. Opened for
// writing, the same files pass. Before task 15m only the kind of file
// was checked, and the prompts failed unseen.
func TestCheckStderrReadOnly(t *testing.T) {
	base := t.TempDir()
	name := filepath.Join(base, "err")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	open := func(name string, flag int) *os.File {
		t.Helper()
		f, err := os.OpenFile(name, flag, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cases := []struct {
		name string
		f    *os.File
		want error
	}{
		{"file read-only", open(name, os.O_RDONLY), errStderrReadOnly},
		{"file write-only", open(name, os.O_WRONLY), nil},
		{"file read-write", open(name, os.O_RDWR), nil},
		{"/dev/null read-only", open(os.DevNull, os.O_RDONLY), errStderrClosed},
		{"read end of a pipe", r, errStderrReadOnly},
		{"write end of a pipe", w, nil},
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		t.Cleanup(func() { tty.Close() })
		cases = append(cases, struct {
			name string
			f    *os.File
			want error
		}{"terminal read-only", tty, errStderrReadOnly})
	}
	for _, tc := range cases {
		err := newEnv(nil, nil, tc.f).checkStderr()
		if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if tc.want != nil && !errors.Is(err, errStderrClosed) {
			t.Fatalf("%s: %v is no errStderrClosed (exit code 2)", tc.name, err)
		}
	}
}
