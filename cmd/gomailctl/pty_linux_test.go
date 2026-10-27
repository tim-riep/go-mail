//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The tests in this file drive gomailctl (this test binary re-executed
// with runMainEnv, see TestMain) on a pseudo terminal from /dev/ptmx, as
// a user would (task 13b). The master side records everything the
// terminal shows (the transcript), including the echo of typed input
// while the echo is on. The program runs in a session of its own with
// the pseudo terminal as its controlling terminal, so that Ctrl-C typed
// on the master raises SIGINT in it.

// ptyRec is a pseudo terminal whose output is recorded.
type ptyRec struct {
	master, slave *os.File
	out           syncBuf
	lflag0        uint32 // the local modes before the program ran
	iflag0        uint32 // the input modes before the program ran
}

func newPtyRec(t *testing.T) *ptyRec {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		m.Close()
		t.Skip("TIOCGPTN:", err)
	}
	var unlock int32
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		m.Close()
		t.Skip("TIOCSPTLCK:", err)
	}
	s, err := os.OpenFile("/dev/pts/"+itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skip("pty slave:", err)
	}
	p := &ptyRec{master: m, slave: s}
	t.Cleanup(func() { s.Close(); m.Close() })
	go func() {
		b := make([]byte, 4096)
		for {
			k, err := m.Read(b)
			if k > 0 {
				p.out.Write(b[:k])
			}
			if err != nil {
				return
			}
		}
	}()
	p.lflag0, p.iflag0 = p.lflag(t), iflag(t, s)
	return p
}

func (p *ptyRec) lflag(t *testing.T) uint32 {
	t.Helper()
	var tio syscall.Termios
	if err := ioctl(p.slave.Fd(), ioctlGetTermios, unsafe.Pointer(&tio)); err != nil {
		t.Fatal(err)
	}
	return tio.Lflag
}

// wait waits until the transcript from offset from matches re and
// returns the offset just behind the match and the submatches.
func (p *ptyRec) wait(t *testing.T, from int, re string) (int, []string) {
	t.Helper()
	r := regexp.MustCompile(re)
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		s := p.out.String()
		if from > len(s) {
			continue
		}
		if m := r.FindStringSubmatchIndex(s[from:]); m != nil {
			var subs []string
			for i := 0; i+1 < len(m); i += 2 {
				if m[i] >= 0 {
					subs = append(subs, s[from+m[i]:from+m[i+1]])
				}
			}
			return from + m[1], subs
		}
	}
	t.Fatalf("timeout waiting for %q; transcript:\n%q", re, p.out.String())
	return 0, nil
}

func (p *ptyRec) typeIn(t *testing.T, s string) {
	t.Helper()
	if _, err := p.master.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

// restored fails unless the terminal has its modes from before the
// program ran (echo and flow control restored).
func (p *ptyRec) restored(t *testing.T) {
	t.Helper()
	if l, i := p.lflag(t), iflag(t, p.slave); l != p.lflag0 || i != p.iflag0 {
		t.Fatalf("terminal not restored: lflag %#x (was %#x), iflag %#x (was %#x)", l, p.lflag0, i, p.iflag0)
	}
}

// echoOff reports whether the echo of the terminal is off.
func (p *ptyRec) echoOff(t *testing.T) bool { return p.lflag(t)&syscall.ECHO == 0 }

// child is gomailctl started from this test binary.
type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	code int
}

// start runs gomailctl with args and the common options for client
// directory dir; ctty makes stdin (a pseudo terminal) its controlling
// terminal. env is added to the environment of the test, without the
// switch of the test build (keygen_pipe_tagged.go).
func (c *cli) start(t *testing.T, dir string, stdin, stdout, stderr *os.File, ctty bool, env []string, args ...string) *child {
	t.Helper()
	cmd := exec.Command(os.Args[0], c.args(dir, args)...)
	cmd.Env = childEnv(env)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if ctty {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	return startChild(t, cmd)
}

// args appends the common options for client directory dir to args.
func (c *cli) args(dir string, args []string) []string {
	return append(args, "--data", c.env.Store.Path(""), "--dir", dir, "--platform", c.pin, "--insecure-no-log")
}

// childEnv is the environment of gomailctl started from this test
// binary: that of the test with env added, without the switch of the
// test build.
func childEnv(env []string) []string {
	var r []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOMAILCTL_TEST_KEYGEN_PIPE=") {
			r = append(r, v)
		}
	}
	return append(append(r, runMainEnv+"=1"), env...)
}

// startChild starts cmd and ends it with the test.
func startChild(t *testing.T, cmd *exec.Cmd) *child {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ch := &child{cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		ch.code = cmd.ProcessState.ExitCode()
		close(ch.done)
	}()
	t.Cleanup(func() {
		select {
		case <-ch.done:
		default:
			cmd.Process.Kill()
			<-ch.done
		}
	})
	return ch
}

// exit waits for the end of the program and returns its exit code.
func (ch *child) exit(t *testing.T) int {
	t.Helper()
	select {
	case <-ch.done:
	case <-time.After(60 * time.Second):
		ch.cmd.Process.Kill()
		t.Fatal("gomailctl does not end")
	}
	return ch.code
}

// running fails if the program ended.
func (ch *child) running(t *testing.T) {
	t.Helper()
	select {
	case <-ch.done:
		t.Fatalf("gomailctl ended with exit code %d", ch.code)
	default:
	}
}

// keygenOnPty starts keygen with args on a new pseudo terminal as
// standard input, output and error, and waits for the seed.
func (c *cli) keygenOnPty(t *testing.T, name string, args ...string) (p *ptyRec, ch *child, dir string, seed []string, pos int) {
	t.Helper()
	p = newPtyRec(t)
	dir = filepath.Join(c.env.Base, "clients", name)
	ch = c.start(t, dir, p.slave, p.slave, p.slave, true, nil, append([]string{"keygen"}, args...)...)
	pos, _ = p.wait(t, 0, `Seed notiert\? Eingabetaste löscht den Bildschirm: $`)
	s := p.out.String()
	// The screen was cleared before the seed appeared.
	if i := strings.Index(s, "Ihr Seed"); i < 0 || !strings.Contains(s[:i], clearScreen) {
		t.Fatalf("no clear before the seed: %q", s)
	}
	seed = seedOf(t, s)
	if iflag(t, p.slave)&flowFlags != 0 {
		t.Fatal("flow control on while the seed is shown")
	}
	return p, ch, dir, seed, pos
}

// answerWords confirms the seed and answers the three word questions:
// the echo must be off at every question, and the typed word must not
// appear on the terminal.
func (p *ptyRec) answerWords(t *testing.T, seed []string, pos int) int {
	t.Helper()
	p.typeIn(t, "\n")
	for i := 0; i < 3; i++ {
		var m []string
		pos, m = p.wait(t, pos, `Wort Nr\. (\d+): $`)
		if !p.echoOff(t) {
			t.Fatalf("echo on at word question %d", i+1)
		}
		n, _ := strconv.Atoi(m[1])
		p.typeIn(t, seed[n-1]+"\n")
	}
	return pos
}

// noWordsAfter fails if the transcript s shows words of ws: two of them
// in a row (as typed or shown, in any case), a numbered word ("7.
// word"), or an answer to a word question ("Wort Nr. 7: word").
func noWordsAfter(t *testing.T, what, s string, ws []string) {
	t.Helper()
	low := strings.ToLower(s)
	for i := 0; i+1 < len(ws); i++ {
		if regexp.MustCompile(`\b` + ws[i] + `\s+` + ws[i+1] + `\b`).MatchString(low) {
			t.Fatalf("%s: words %d and %d in %q", what, i+1, i+2, s)
		}
	}
	for _, m := range numberedRe.FindAllStringSubmatch(s, -1) {
		for _, w := range ws {
			if strings.EqualFold(m[2], w) {
				t.Fatalf("%s: numbered word in %q", what, s)
			}
		}
	}
	for _, m := range regexp.MustCompile(`Wort Nr\. (\d+): ([^\r\n]*)`).FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		if n >= 1 && n <= len(ws) && strings.Contains(strings.ToLower(m[2]), ws[n-1]) {
			t.Fatalf("%s: answer to word %d echoed: %q", what, n, s)
		}
	}
}

// TestPtyKeygen (task 13b finding 1, A2): keygen on a terminal clears
// the screen before the seed and after it is noted, reads the three
// words with the echo off (they never appear in the transcript), clears
// again before the key store is written, and restores the terminal.
func TestPtyKeygen(t *testing.T) {
	c := newCLI(t)
	p, ch, dir, seed, pos := c.keygenOnPty(t, "pty")
	if exists(dir) {
		t.Fatal("client directory before the words were confirmed")
	}
	seedEnd := pos
	p.answerWords(t, seed, pos)
	if code := ch.exit(t); code != 0 {
		t.Fatalf("exit %d\n%q", code, p.out.String())
	}
	p.wait(t, seedEnd, `angelegt \(noch nicht registriert\)`)
	s := p.out.String()
	// Everything after the seed: the words typed never appear (echo
	// off), and the seed is gone behind a clear.
	after := s[seedEnd:]
	if !strings.HasPrefix(after, "\r\n"+clearScreen) && !strings.HasPrefix(after, clearScreen) {
		t.Fatalf("seed not cleared after its confirmation: %q", after)
	}
	noWordsAfter(t, "after the seed", after, seed)
	tail := s[strings.LastIndex(s, clearScreen)+len(clearScreen):]
	if !strings.HasPrefix(tail, "Benutzer ") {
		t.Fatalf("after the last clear: %q", tail)
	}
	p.restored(t)
	if !exists(filepath.Join(dir, "keystore")) {
		t.Fatal("no key store")
	}
}

// TestPtyKeygenAbort (task 13b finding 1 and 4): Ctrl-C at a word
// question, SIGABRT and SIGTERM while a share is on the screen, and
// Ctrl-Z while the seed is shown: the echo and the flow control are
// restored, the screen is cleared, exit code 130 without a stack trace,
// and nothing is written.
func TestPtyKeygenAbort(t *testing.T) {
	c := newCLI(t)
	for _, tc := range []struct {
		name  string
		split bool
		at    string // seed, word, share
		send  func(p *ptyRec, ch *child)
	}{
		{"ctrl-c at a word", false, "word", func(p *ptyRec, _ *child) { p.master.Write([]byte{3}) }},
		{"ctrl-z at the seed", false, "seed", func(p *ptyRec, _ *child) { p.master.Write([]byte{26}) }},
		{"ctrl-backslash at a word", true, "word", func(p *ptyRec, _ *child) { p.master.Write([]byte{28}) }},
		{"sigabrt at a share", true, "share", func(_ *ptyRec, ch *child) { ch.cmd.Process.Signal(syscall.SIGABRT) }},
		{"sigterm at a share", true, "share", func(_ *ptyRec, ch *child) { ch.cmd.Process.Signal(syscall.SIGTERM) }},
		{"sigsegv at a share", true, "share", func(_ *ptyRec, ch *child) { ch.cmd.Process.Signal(syscall.SIGSEGV) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.split {
				args = []string{"--shares", "2-of-3"}
			}
			p, ch, dir, seed, pos := c.keygenOnPty(t, strings.Fields(tc.name)[0]+strconv.Itoa(len(tc.name)), args...)
			mark := strings.Index(p.out.String(), "Ihr Seed")
			switch tc.at {
			case "word":
				p.typeIn(t, "\n")
				pos, _ = p.wait(t, pos, `Wort Nr\. \d+: $`)
				if !p.echoOff(t) {
					t.Fatal("echo on at the word question")
				}
			case "share":
				pos = p.answerWords(t, seed, pos)
				pos, _ = p.wait(t, pos, `Inhaber von Anteil 1 von 3 an den Bildschirm, dann Eingabetaste: $`)
				p.typeIn(t, "\n")
				pos, _ = p.wait(t, pos, `Anteil notiert\? Eingabetaste löscht den Bildschirm: $`)
				mark = strings.Index(p.out.String(), "Anteil 1 von 3 (30")
			}
			tc.send(p, ch)
			if code := ch.exit(t); code != 130 {
				t.Fatalf("exit %d\n%q", code, p.out.String())
			}
			p.wait(t, mark, `abgebrochen`)
			s := p.out.String()
			if !strings.Contains(s[mark:], clearScreen) || strings.Contains(s, "goroutine ") {
				t.Fatalf("after the abort: %q", s[mark:])
			}
			p.restored(t)
			if exists(dir) {
				t.Fatal("client directory after the abort")
			}
		})
	}
}

// TestPtyDoubleEnterAtHolder (task 13b finding 3, A4): two Enters typed
// at once to call holder 1 show share 1, but the second does not
// confirm it: it stays on the screen until an Enter typed after it
// appeared; then the screen is cleared and holder 2 is called.
func TestPtyDoubleEnterAtHolder(t *testing.T) {
	c := newCLI(t)
	p, ch, dir, seed, pos := c.keygenOnPty(t, "double", "--shares", "2-of-2")
	pos = p.answerWords(t, seed, pos)
	pos, _ = p.wait(t, pos, `Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: $`)
	p.typeIn(t, "\n\n")
	pos, _ = p.wait(t, pos, `Anteil notiert\? Eingabetaste löscht den Bildschirm: $`)
	share := strings.Index(p.out.String(), "Anteil 1 von 2 (30")
	if share < 0 {
		t.Fatal("share 1 not shown")
	}
	time.Sleep(time.Second)
	ch.running(t)
	if s := p.out.String()[share:]; strings.Contains(s, clearScreen) || strings.Contains(s, "Inhaber von Anteil 2") {
		t.Fatalf("share 1 confirmed by the Enter typed ahead: %q", s)
	}
	p.typeIn(t, "\n")
	pos, _ = p.wait(t, pos, regexp.QuoteMeta(clearScreen)+`(?s).*Inhaber von Anteil 2 von 2 an den Bildschirm, dann Eingabetaste: $`)
	p.typeIn(t, "\n")
	pos, _ = p.wait(t, pos, `Anteil notiert\? Eingabetaste löscht den Bildschirm: $`)
	p.typeIn(t, "\n")
	if code := ch.exit(t); code != 0 {
		t.Fatalf("exit %d\n%q", code, p.out.String())
	}
	p.wait(t, pos, `restore --shares 2`)
	s := p.out.String()
	shares := numbered(s[share:])
	if len(shares) != 30 {
		t.Fatalf("%d words of share 1", len(shares))
	}
	noWordsAfter(t, "after the last clear", s[strings.LastIndex(s, clearScreen):], append(seed, shares...))
	p.restored(t)
	if !exists(filepath.Join(dir, "keystore")) {
		t.Fatal("no key store")
	}
}

// TestPtyKeygenNoTerminal (task 13b finding 1, A1): keygen with standard
// output in a file, a pipe or /dev/null, or with standard input from a
// pipe, ends with exit code 1 before anything is shown, read or
// written: no byte on standard output, no client directory, no word
// question.
func TestPtyKeygenNoTerminal(t *testing.T) {
	c := newCLI(t)
	p := newPtyRec(t)
	for _, kind := range []string{"file", "pipe", "devnull", "stdin-pipe", "file-shares"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(c.env.Base, "clients", "nt-"+kind)
			stdin, stdout := p.slave, p.slave
			var r *os.File
			var path string
			var err error
			switch kind {
			case "file", "file-shares":
				path = filepath.Join(t.TempDir(), "out")
				stdout, err = os.Create(path)
			case "pipe":
				r, stdout, err = os.Pipe()
			case "devnull":
				stdout, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			case "stdin-pipe":
				var w *os.File
				stdin, w, err = os.Pipe()
				if err == nil {
					defer w.Close()
					defer stdin.Close()
					w.Write([]byte("abandon\nabandon\nabandon\n"))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"keygen"}
			if kind == "file-shares" {
				args = append(args, "--shares", "2-of-3")
			}
			from := len(p.out.String())
			ch := c.start(t, dir, stdin, stdout, p.slave, false, nil, args...)
			if stdout != p.slave {
				stdout.Close()
			}
			if code := ch.exit(t); code != 1 {
				t.Fatalf("exit %d", code)
			}
			var got []byte
			switch {
			case r != nil:
				got, _ = readAll(r)
			case path != "":
				got, _ = os.ReadFile(path)
			}
			if len(got) != 0 {
				t.Fatalf("%d bytes on standard output", len(got))
			}
			if exists(dir) {
				t.Fatal("client directory")
			}
			s := p.out.String()[from:]
			if strings.Contains(s, "Wort Nr") || strings.Contains(s, "Ihr Seed") || !strings.Contains(s, "nur") {
				t.Fatalf("terminal: %q", s)
			}
		})
	}
}

func readAll(f *os.File) ([]byte, error) {
	defer f.Close()
	var b bytes.Buffer
	_, err := b.ReadFrom(f)
	return b.Bytes(), err
}

// TestPtyWordsStdoutRedirected (task 13b finding 2, A9): device lost and
// restore with standard input on a terminal and standard output in a
// pipe end with exit code 1 before they ask anything: no passphrase
// prompt, no word prompt, nothing read, no client directory.
func TestPtyWordsStdoutRedirected(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	for _, tc := range []struct {
		args []string
		dir  string
	}{
		{[]string{"device", "lost"}, alice.Dir},
		{[]string{"restore"}, filepath.Join(c.env.Base, "clients", "a9")},
		{[]string{"restore", "--shares", "2"}, filepath.Join(c.env.Base, "clients", "a9s")},
	} {
		p := newPtyRec(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(alice.Dir, "keystore"))
		ch := c.start(t, tc.dir, p.slave, w, p.slave, true, nil, tc.args...)
		w.Close()
		p.typeIn(t, strings.Join(alice.Words, " ")+"\n")
		if code := ch.exit(t); code != 1 {
			t.Fatalf("%v: exit %d\n%q", tc.args, code, p.out.String())
		}
		got, _ := readAll(r)
		time.Sleep(100 * time.Millisecond)
		s := p.out.String()
		if len(got) != 0 || strings.Contains(s, "Passphrase") || strings.Contains(s, "eingeben") || !strings.Contains(s, "dasselbe Terminal") {
			t.Fatalf("%v: stdout %q, terminal %q", tc.args, got, s)
		}
		// What was typed was not read: it is still in the input of the
		// terminal (its echo is in the transcript, as the terminal shows
		// it, the program never got it).
		if tc.dir != alice.Dir && exists(tc.dir) {
			t.Fatalf("%v: client directory", tc.args)
		}
		if after, _ := os.ReadFile(filepath.Join(alice.Dir, "keystore")); !bytes.Equal(before, after) {
			t.Fatal("key store changed")
		}
	}
	u, _, err := c.env.Store.ReadUser(alice.ID)
	if err != nil || u.Current().Gen != 1 {
		t.Fatalf("generation changed: %v", err)
	}
}

// TestPtyWordsEchoOff (task 13b finding 2, TestVerifyWordsEchoNoClear
// reversed): device lost with standard input and output on the same
// terminal reads the 24 words over two lines with the echo off: they
// never appear in the transcript, the screen is cleared afterwards, the
// terminal is restored. restore with Ctrl-C in the middle of the words
// clears the screen, ends with exit code 130 and writes nothing.
func TestPtyWordsEchoOff(t *testing.T) {
	c := newCLI(t)
	alice := c.user("alice")
	ws := alice.Words

	p := newPtyRec(t)
	ch := c.start(t, alice.Dir, p.slave, p.slave, p.slave, true, nil, "device", "lost")
	pos, _ := p.wait(t, 0, `Seed eingeben \(24 Wörter, auch über mehrere Zeilen, ohne Anzeige\):\r?\n`)
	if !p.echoOff(t) {
		t.Fatal("echo on while the seed is typed")
	}
	p.typeIn(t, strings.Join(ws[:12], " ")+"\n")
	p.wait(t, pos, `\(12 von 24 Wörtern\)`)
	p.typeIn(t, strings.ToUpper(strings.Join(ws[12:], "  "))+"\n")
	if code := ch.exit(t); code != 0 {
		t.Fatalf("device lost: exit %d\n%q", code, p.out.String())
	}
	p.wait(t, pos, `Neue Generation 2`)
	s := p.out.String()
	noWordsAfter(t, "device lost", strings.ToLower(s), ws)
	if i := strings.Index(s[pos:], "Neue Generation 2"); !strings.Contains(s[pos:pos+i], clearScreen) {
		t.Fatalf("no clear after the words: %q", s[pos:])
	}
	p.restored(t)

	// restore: Ctrl-C after the first line.
	p = newPtyRec(t)
	dir := filepath.Join(c.env.Base, "clients", "restore-int")
	ch = c.start(t, dir, p.slave, p.slave, p.slave, true, nil, "restore")
	pos, _ = p.wait(t, 0, `Seed eingeben`)
	p.typeIn(t, strings.Join(ws[:12], " ")+"\n")
	pos, _ = p.wait(t, pos, `\(12 von 24 Wörtern\)`)
	p.typeIn(t, strings.Join(ws[12:15], " ")+"\x03")
	if code := ch.exit(t); code != 130 {
		t.Fatalf("restore with Ctrl-C: exit %d\n%q", code, p.out.String())
	}
	p.wait(t, pos, `abgebrochen`)
	s = p.out.String()
	if !strings.Contains(s[pos:], clearScreen) {
		t.Fatalf("no clear after Ctrl-C: %q", s[pos:])
	}
	noWordsAfter(t, "restore", s, ws)
	p.restored(t)
	if exists(filepath.Join(dir, "keystore")) {
		t.Fatal("key store after Ctrl-C")
	}
}

// TestAbortSignals: the abort signals are those of gomail-ceremony
// (task 13b finding 4).
func TestAbortSignals(t *testing.T) {
	want := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGABRT,
		syscall.SIGILL, syscall.SIGTRAP, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGSEGV, syscall.SIGSYS}
	if fmt.Sprint(abortSignals) != fmt.Sprint(want) {
		t.Fatalf("abortSignals %v", abortSignals)
	}
}
