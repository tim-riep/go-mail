package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/testenv"
)

// testEnvKeygenPipeName is the switch of a test build
// (keygen_pipe_tagged.go); the tests of the rules unset it.
const testEnvKeygenPipeName = "GOMAILCTL_TEST_KEYGEN_PIPE"

// Tests of task 13b with stand-in terminals (keyboard, tty); the same
// rules on a real pseudo terminal are in pty_linux_test.go.

// TestKeygenTerminalRules (finding 1, A1): keygen refuses before it
// shows, reads or writes anything unless standard output is a terminal
// and standard input a terminal whose echo can be switched off.
func TestKeygenTerminalRules(t *testing.T) {
	c := newCLI(t)
	t.Setenv(testEnvKeygenPipeName, "")
	os.Unsetenv(testEnvKeygenPipeName)
	// The passphrase too would be read from the keyboard.
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	file, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for i, tc := range []struct {
		out  interface{ Write([]byte) (int, error) }
		in   func(kb *keyboard) any
		want string
	}{
		{&syncBuf{}, nil, "Standardausgabe ist keins"},
		{file, nil, "Standardausgabe ist keins"},
		{&tty{}, func(*keyboard) any { return strings.NewReader("pw\npw\n\n") }, "Standardeingabe ist keins"},
		{&tty{}, func(kb *keyboard) any { kb.echoFail = true; return kb }, "Echo"},
	} {
		for _, split := range [][]string{nil, {"--shares", "2-of-3"}} {
			dir := filepath.Join(c.env.Base, "clients", "rules")
			kb := &keyboard{err: &syncBuf{}, answer: func(string) (string, bool) { return "", true }}
			var in any = kb
			if tc.in != nil {
				in = tc.in(kb)
			}
			r := in.(interface{ Read([]byte) (int, error) })
			e := &env{stdin: bufio.NewReader(r), in: r, stdout: tc.out, stderr: kb.err, now: c.env.Clock.Now}
			args := append(append([]string{"keygen"}, split...), "--data", c.env.Store.Path(""), "--dir", dir, "--platform", c.pin, "--insecure-no-log")
			code := e.run(args)
			var shown string
			if s, ok := tc.out.(interface{ String() string }); ok {
				shown = s.String()
			}
			if fi, _ := file.Stat(); fi.Size() != 0 {
				t.Fatal("bytes in the file")
			}
			if code != 1 || shown != "" || kb.answered() != 0 || !strings.Contains(kb.err.String(), tc.want) || exists(dir) {
				t.Fatalf("case %d %v: exit %d, shown %q, %d lines read, %q", i, split, code, shown, kb.answered(), kb.err.String())
			}
		}
	}
}

// TestKeygenSeedScreen (finding 1): keygen without --shares clears the
// screen, shows the seed, discards input typed ahead before its
// confirmation, clears it, asks three words with the echo off and
// clears and closes the screen before the key store is written.
func TestKeygenSeedScreen(t *testing.T) {
	c := newCLI(t)
	t.Setenv(testEnvKeygenPipeName, "")
	os.Unsetenv(testEnvKeygenPipeName)
	dir := filepath.Join(c.env.Base, "clients", "seed")
	out := &tty{}
	kb := &keyboard{err: &syncBuf{}, out: out}
	kb.answer = keygenKeys(t, out, true, false)
	var clears []bool
	out.onClear = func() { clears = append(clears, exists(filepath.Join(dir, "keystore"))) }
	r := c.keygenRun(dir, out, kb)
	if r.code != 0 {
		t.Fatalf("keygen: %+v", r)
	}
	screens := strings.Split(r.out, clearScreen)
	if len(screens) != 4 || screens[0] != "" || !strings.HasPrefix(screens[1], "Ihr Seed") || screens[2] != "" ||
		!strings.HasPrefix(screens[3], "Benutzer ") {
		t.Fatalf("screens %q", screens)
	}
	for i, ks := range clears {
		if ks {
			t.Fatalf("clear %d with the key store written", i)
		}
	}
	if len(kb.lines) != 4 || kb.hidden[0] || !kb.hidden[1] || !kb.hidden[2] || !kb.hidden[3] {
		t.Fatalf("answers %d, echo off %v", len(kb.lines), kb.hidden)
	}
	// The seed is confirmed only after a flush with the seed on the screen.
	seedEnd := strings.Index(r.out, "Ihr Seed")
	if kb.events[0].kind != 'F' || kb.events[0].outLen <= seedEnd || kb.events[1].kind != 'R' {
		t.Fatalf("events %+v", kb.events)
	}
	seed := seedOf(t, r.out)
	noneIn(t, "stderr", r.errOut, strings.Join(seed[:4], " "))
	for i, l := range kb.lines[1:] {
		if !strings.Contains(strings.Join(seed, " "), l) || strings.Contains(r.errOut, l+"\n") {
			t.Fatalf("answer %d", i)
		}
	}
	if !exists(filepath.Join(dir, "keystore")) {
		t.Fatal("no key store")
	}
	// The same directory again: refused by the client before a seed is
	// shown.
	out = &tty{}
	kb = &keyboard{err: &syncBuf{}, answer: keygenKeys(t, out, true, false)}
	if r = c.keygenRun(dir, out, kb); r.code != 1 || strings.Contains(r.out, "Seed") || !strings.Contains(r.errOut, "already has a user") {
		t.Fatalf("second keygen: %+v", r)
	}
}

// TestWordInputTerminal (finding 2): device lost and restore read words
// typed on a terminal with the echo off and clear the screen afterwards;
// with standard output redirected or on another terminal they refuse
// before the passphrase or any word is read.
func TestWordInputTerminal(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	words := func(prompt string) (string, bool) {
		switch {
		case strings.HasSuffix(prompt, "Passphrase: ") || strings.HasSuffix(prompt, "wiederholen: "):
			return "correct horse battery staple", true
		case strings.Contains(prompt, "Seed eingeben"):
			return strings.Join(ws[:12], " "), true
		case strings.Contains(prompt, "(12 von 24"):
			return strings.Join(ws[12:], " "), true
		}
		return "", false
	}
	runWith := func(dir string, out interface{ Write([]byte) (int, error) }, kb *keyboard, args ...string) int {
		args = append(args, "--data", c.env.Store.Path(""), "--dir", dir, "--platform", c.pin, "--insecure-no-log")
		e := &env{stdin: bufio.NewReader(kb), in: kb, stdout: out, stderr: kb.err, now: c.env.Clock.Now}
		return e.run(args)
	}
	dev := filepath.Join(c.env.Base, "clients", "dev")
	for _, args := range [][]string{{"device", "lost"}, {"restore"}, {"restore", "--shares", "2"}} {
		for i, tc := range []struct {
			out  interface{ Write([]byte) (int, error) }
			id   uint64
			fail bool
			want string
		}{
			{&syncBuf{}, 0, false, "dasselbe Terminal"},
			{&tty{}, 7, false, "dasselbe Terminal"},
			{&tty{}, 0, true, "Echo"},
		} {
			kb := &keyboard{err: &syncBuf{}, answer: words, id: tc.id, echoFail: tc.fail}
			dir := dev
			if args[0] == "device" {
				dir = alice.Dir
			}
			code := runWith(dir, tc.out, kb, args...)
			// With a failing echo the passphrase is read first (the
			// screen opens after it); nothing else.
			read := kb.answered()
			if code != 1 || !strings.Contains(kb.err.String(), tc.want) || (!tc.fail && read != 0) || read > 2 ||
				strings.Contains(kb.err.String(), "eingeben") || exists(dev) {
				t.Fatalf("%v case %d: exit %d, %d lines read, %q", args, i, code, read, kb.err.String())
			}
		}
	}

	// device lost on the terminal: every word line with the echo off,
	// the screen cleared after them.
	out := &tty{}
	kb := &keyboard{err: &syncBuf{}, answer: words}
	if code := runWith(alice.Dir, out, kb, "device", "lost"); code != 0 {
		t.Fatalf("device lost: exit %d, %s", code, kb.err.String())
	}
	if len(kb.lines) != 3 || kb.hidden[0] || !kb.hidden[1] || !kb.hidden[2] || kb.echoOff ||
		!strings.Contains(out.String(), clearScreen+"Neue Generation 2") {
		t.Fatalf("device lost: echo off %v, %q", kb.hidden, out.String())
	}

	// restore --shares 2 on the terminal: each share typed with the echo
	// off and cleared; wrong shares fail after the clear.
	out = &tty{}
	kb = &keyboard{err: &syncBuf{}, answer: func(prompt string) (string, bool) {
		if strings.Contains(prompt, "Anteil ") {
			return strings.Join(ws[:15], " ") + " " + strings.Join(ws[:15], " "), true
		}
		return words(prompt)
	}}
	if code := runWith(dev, out, kb, "restore", "--shares", "2"); code != 1 {
		t.Fatalf("restore with wrong shares: exit %d", code)
	}
	if len(kb.lines) != 4 || !kb.hidden[2] || !kb.hidden[3] || strings.Count(out.String(), clearScreen) < 3 || !strings.HasSuffix(out.String(), clearScreen) {
		t.Fatalf("restore --shares: echo off %v, %q", kb.hidden, out.String())
	}
	if exists(filepath.Join(dev, "keystore")) {
		t.Fatal("key store after wrong shares")
	}
}

// endless reads as a run of 'a' without a line end, counting the bytes
// read; it ends after 1 MiB, so that a reader that does not stop at the
// limit fails the test instead of hanging it.
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	if e.n >= 1<<20 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'a'
	}
	e.n += len(p)
	return len(p), nil
}

// TestPassphraseBound (finding 5, A11): a passphrase line from standard
// input is at most 4096 bytes; an endless input without a line end is
// refused after the first 4096 bytes.
func TestPassphraseBound(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	mbx := c.mailbox(alice, "info@brownbear.example")
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	in := &endless{}
	start := time.Now()
	r := c.exec(alice.Dir, in, nil, "search", mbx.String(), "from:x")
	if r.code != 1 || !strings.Contains(r.errOut, "Zeile zu lang") || in.n > 4096 || time.Since(start) > 30*time.Second {
		t.Fatalf("endless passphrase: %+v, %d bytes read", r, in.n)
	}
	r = c.do(alice.Dir, strings.Repeat("x", 4097)+"\n", "search", mbx.String(), "from:x")
	if r.code != 1 || !strings.Contains(r.errOut, "Zeile zu lang") {
		t.Fatalf("long passphrase: %+v", r)
	}
	// The passphrase as the last line without a line end still counts.
	c.must(0, alice.Dir, string(testenv.Passphrase), "search", mbx.String(), "from:x")
	c.must(0, alice.Dir, string(testenv.Passphrase)+"\r\n", "search", mbx.String(), "from:x")
}

// TestSubjectControls (finding 6, A13): a subject with C1 controls (the
// single-character CSI and OSC), bidirectional overrides and isolates
// and an escape sequence reaches list and search without them.
func TestSubjectControls(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	mbx := c.mailbox(alice, "info@brownbear.example")
	subj := "Angebot \u009b31mROT\u009b0m \u009d0;evil\u009c ‮TSET‬ ⁦iso⁩ \x1b[2J \t tab"
	c.deliver("s@x.example", "info@brownbear.example", "From: s@x.example\r\nSubject: "+subj+"\r\n\r\nText\r\n")
	c.env.Clock.Advance(time.Hour)
	for _, args := range [][]string{{"list", mbx.String()}, {"search", mbx.String(), "from:s@x.example"}} {
		r := c.must(0, alice.Dir, "", args...)
		if !strings.Contains(r.out, "Angebot  31mROT 0m  0;evil   TSET   iso   [2J") {
			t.Fatalf("%v: %q", args[0], r.out)
		}
		for _, bad := range []string{"\u009b", "\u009d", "\u009c", "‮", "‬", "⁦", "⁩", "\x1b"} {
			if strings.Contains(r.out, bad) {
				t.Fatalf("%v: %q in %q", args[0], bad, r.out)
			}
		}
	}
}
