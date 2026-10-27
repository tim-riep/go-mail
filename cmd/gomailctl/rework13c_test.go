package main

import (
	"bufio"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// endlessLines reads as an endless run of line, counting the lines
// read; it ends after 1<<16 lines, so that a reader that does not stop
// at the limit fails the test instead of hanging it.
type endlessLines struct {
	line string
	n    int
}

func (e *endlessLines) Read(p []byte) (int, error) {
	k := 0
	for k+len(e.line) <= len(p) {
		if e.n >= 1<<16 {
			if k == 0 {
				return 0, io.EOF
			}
			break
		}
		k += copy(p[k:], e.line)
		e.n++
	}
	return k, nil
}

// TestWordLinesBound (task 13c finding 3, B10): readWords reads at most
// maxWordLines lines for one seed or share; an endless run of empty
// lines ends with "zu viele Zeilen" instead of a loop. 24 words with
// empty lines in between are accepted up to that bound.
func TestWordLinesBound(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words
	for _, tc := range []struct {
		args []string
		line string
	}{
		{[]string{"device", "lost"}, "\n"},
		{[]string{"restore"}, "\r\n"},
		{[]string{"restore", "--shares", "2"}, " \n"},
	} {
		dir := alice.Dir
		if tc.args[0] == "restore" {
			dir = filepath.Join(c.env.Base, "clients", "lines")
		}
		in := &endlessLines{line: tc.line}
		r := c.exec(dir, in, nil, tc.args...)
		if r.code != 1 || !strings.Contains(r.errOut, "zu viele Zeilen (höchstens 64) nach 0 von") {
			t.Fatalf("%v: %+v", tc.args, r)
		}
		// Not more than the bound and the read buffer.
		if in.n > maxWordLines+4096/len(tc.line) {
			t.Fatalf("%v: %d lines read", tc.args, in.n)
		}
		if n := strings.Count(r.errOut, "(0 von "); n != maxWordLines {
			t.Fatalf("%v: %d progress lines", tc.args, n)
		}
		if exists(filepath.Join(c.env.Base, "clients", "lines")) {
			t.Fatal("client directory")
		}
	}

	// readWords itself: the error is errManyLines; the words read so far
	// are counted, never shown.
	e := &env{stderr: io.Discard}
	e.stdin = bufio.NewReader(strings.NewReader(strings.Join(ws[:3], " ") + strings.Repeat("\n", 100)))
	if _, err := e.readWords(nil, "Seed", 24); !errors.Is(err, errManyLines) || !strings.Contains(err.Error(), "nach 3 von 24") || strings.Contains(err.Error(), ws[0]) {
		t.Fatalf("readWords: %v", err)
	}

	// One word per line with 40 empty lines between them: 64 lines in
	// all are accepted, one empty line more is refused.
	lines := func(blank int) string {
		var b strings.Builder
		for i, w := range ws {
			b.WriteString(w + "\n")
			if i == 0 {
				b.WriteString(strings.Repeat("\n", blank))
			}
		}
		return b.String()
	}
	r := c.must(1, alice.Dir, lines(maxWordLines-len(ws)+1), "device", "lost")
	if !strings.Contains(r.errOut, "zu viele Zeilen") {
		t.Fatalf("65 lines: %q", r.errOut)
	}
	noneIn(t, "65 lines", r.errOut, ws[0]+" ", " "+ws[1])
	if r = c.must(0, alice.Dir, lines(maxWordLines-len(ws)), "device", "lost"); !strings.Contains(r.out, "Neue Generation 2") {
		t.Fatalf("64 lines: %+v", r)
	}
}
