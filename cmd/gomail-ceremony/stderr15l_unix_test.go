//go:build (linux || darwin || freebsd || netbsd || openbsd || dragonfly) && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Tests of task 15l point 2 with the stand-in terminals: standard error
// must be a terminal, a pipe or a regular file.

// TestCheckStderr: /dev/null (what the runtime puts in the slot of a
// descriptor 2 closed at the start) is errStderrClosed, a socket and a
// device that is no terminal are errStderrKind; a regular file, a pipe
// and a stand-in of the tests pass.
func TestCheckStderr(t *testing.T) {
	base := t.TempDir()
	open := func(name string, flag int) *os.File {
		t.Helper()
		f, err := os.OpenFile(name, flag, 0o600)
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
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	sock := os.NewFile(uintptr(fds[0]), "socket")
	defer sock.Close()
	defer syscall.Close(fds[1])
	for _, tc := range []struct {
		name string
		w    io.Writer
		want error
	}{
		{"/dev/null", open(os.DevNull, os.O_WRONLY), errStderrClosed},
		{"/dev/null read-write", open(os.DevNull, os.O_RDWR), errStderrClosed},
		{"/dev/zero", open("/dev/zero", os.O_WRONLY), errStderrKind},
		{"socket", sock, errStderrKind},
		{"regular file", open(filepath.Join(base, "err"), os.O_WRONLY|os.O_CREATE), nil},
		{"pipe", w, nil},
		{"stand-in", &bytes.Buffer{}, nil},
	} {
		e := newEnv(nil, nil, tc.w)
		err := e.checkStderr()
		if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if err != nil && (!strings.Contains(err.Error(), "Eingabeaufforderungen wären nicht zu sehen") ||
			!strings.Contains(err.Error(), "nichts angezeigt, gelesen oder geschrieben")) {
			t.Fatalf("%s: %q", tc.name, err)
		}
	}
}

// TestStderrNull: every command that shows or reads shares refuses a
// standard error on /dev/null with a usage error (exit code 2) before
// the terminal check: before anything is shown, read or written, the
// terminal untouched (no flow control, no echo switched), also when
// standard input is no terminal (the terminal check would give exit
// code 1). publish, which shows and reads no share, is not concerned.
func TestStderrNull(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	pinPath := filepath.Join(out, "identity-1.pin")
	answers := strings.Repeat("\n", 20) + tt.shares[1] + "\n" + tt.shares[2] + "\n"
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	o2 := filepath.Join(base, "o2")
	for _, args := range [][]string{
		{"init", "--shares", "3-of-5", "--out", o2, "--keys", filepath.Join(base, "k2"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
		{"reshare", "--pin", pinPath, "--shares", "2-of-3"},
		{"ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", o2, "--keys", filepath.Join(base, "keys"), "--valid-from", "2026-11-01T00:00:00Z"},
		{"succeed", "--pin", pinPath, "--out", o2, "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
	} {
		for _, noTerm := range []bool{false, true} {
			term := newTTY()
			term.inNoTerminal = noTerm
			term.in.WriteString(answers)
			if code := run(args, ttyIn{term}, ttyOut{term}, null); code != exitUsage {
				t.Fatalf("%s (stdin no terminal %v): exit code %d", args[0], noTerm, code)
			}
			if term.out.Len() != 0 || term.msgs.Len() != 0 || term.reads != 0 || term.echoOff || term.flowOff {
				t.Fatalf("%s: stdout %q, messages %q, %d reads, echo off %v, flow control off %v",
					args[0], term.out.String(), term.msgs.String(), term.reads, term.echoOff, term.flowOff)
			}
		}
	}
	for _, d := range []string{o2, filepath.Join(base, "k2")} {
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s written", d)
		}
	}
	var stdout bytes.Buffer
	if code := run([]string{"publish", "--from", out, "--data", filepath.Join(base, "nodata"), "--pin", pinPath}, nil, &stdout, null); code != exitFail {
		t.Fatalf("publish: exit code %d", code)
	}
}
