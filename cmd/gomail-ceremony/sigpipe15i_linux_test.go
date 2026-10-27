//go:build linux && !ceremony_notty

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
)

// Tests of task 15i on a pseudo terminal (pty_linux_test.go): standard
// error of the program in a pipe whose reader goes away (finding of
// task 13c). Without SIGPIPE taken in the runtime ends the program at
// its next prompt with SIGPIPE, past the abort path: a share left on
// the screen, the flow control off.

// errPipe is the read side of the pipe on standard error of a program
// started on p (p.stderr is its write side).
type errPipe struct {
	t   *testing.T
	r   *os.File
	buf []byte
	pos int
}

func newErrPipe(t *testing.T, p *pty) *errPipe {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	p.stderr = w
	return &errPipe{t: t, r: r}
}

// next reads standard error until re matches behind pos and moves pos
// behind the match; it returns the submatches.
func (e *errPipe) next(re *regexp.Regexp) []string {
	e.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	b := make([]byte, 4096)
	for {
		if m := re.FindSubmatchIndex(e.buf[e.pos:]); m != nil {
			sub := make([]string, len(m)/2)
			for i := range sub {
				if m[2*i] >= 0 {
					sub[i] = string(e.buf[e.pos+m[2*i] : e.pos+m[2*i+1]])
				}
			}
			e.pos += m[1]
			return sub
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("timeout; stderr so far %q", e.buf)
		}
		e.r.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := e.r.Read(b)
		e.buf = append(e.buf, b[:n]...)
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			e.t.Fatalf("stderr: %v; so far %q", err, e.buf)
		}
	}
}

// gone closes the read side: every later write of the program to
// standard error fails with EPIPE (and raises SIGPIPE).
func (e *errPipe) gone() { e.r.Close() }

var (
	reHolder = regexp.MustCompile(`Inhaber von Anteil (\d+) von \d+ an den Bildschirm, dann Eingabetaste: `)
	reNoted  = regexp.MustCompile(`Anteil notiert\? Eingabetaste löscht den Bildschirm: `)
	reAsk    = regexp.MustCompile(`Anteil Nr\. (\d+) eingeben[^\n]*\n`)
	reCount  = regexp.MustCompile(`\(12 von 30 Wörtern\)\n`)
	reShare  = regexp.MustCompile(`Anteil (\d+)/\d+: ([a-z ]+)\r\n`)
)

// holder answers the call of holder i on standard error with Enter and
// records the share shown on the screen.
func (p *pty) holder(e *errPipe, i int) {
	p.t.Helper()
	if m := e.next(reHolder); m[1] != fmt.Sprint(i) {
		p.t.Fatalf("holder %s called, want %d", m[1], i)
	}
	p.confirm()
	p.recordShare()
}

// recordShare waits for the next share line on the screen and records
// it.
func (p *pty) recordShare() {
	p.t.Helper()
	m := p.next(reShare)
	if m == nil {
		p.t.Fatalf("no share shown: %q", p.output())
	}
	var k int
	fmt.Sscan(m[1], &k)
	p.shown[k] = strings.TrimSpace(m[2])
	p.shownAt = append(p.shownAt, p.pos)
}

// typeLine types line n (0 or 1: words 1-12, words 13-30) of share i,
// with the echo off.
func (p *pty) typeLine(i, n int) {
	p.t.Helper()
	p.quietInput()
	ws := strings.Fields(p.shown[i])
	line := strings.ToUpper(strings.Join(ws[:12], " "))
	if n == 1 {
		line = strings.Join(ws[12:], " ")
	}
	p.typed = append(p.typed, typing{off: len(p.output()), lines: []string{line}})
	p.send(line + "\n")
}

// exitOf waits for the program and returns its exit code; it fails if a
// signal ended the program.
func (p *pty) exitOf() int {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(60 * time.Second):
		p.t.Fatalf("program does not exit: %q", p.output())
	}
	time.Sleep(100 * time.Millisecond) // the rest of the output
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		if ws := ee.Sys().(syscall.WaitStatus); ws.Signaled() {
			p.t.Fatalf("ended by %v; screen %q", ws.Signal(), p.output())
		}
		return ee.ExitCode()
	}
	if p.err != nil {
		p.t.Fatal(p.err)
	}
	return 0
}

// TestPTYStderrClosed (task 15i): init 2-of-2 on a pseudo terminal with
// standard error in a pipe whose reader goes away before the program
// starts, once holder 1 is called, once holder 2 is called, and while a
// share is typed back. The program is never ended by SIGPIPE: the
// prompt that fails (the call of holder 1, "Anteil notiert?", the count
// of the words typed) takes the abort path at once: exit code 130, no
// share on the screen at the end, the words typed not echoed, the
// terminal (echo, flow control) restored, nothing written, and behind
// the last clear the reason and "abgebrochen" on standard output.
func TestPTYStderrClosed(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, tc := range []struct {
		name  string
		drive func(p *pty, e *errPipe)
	}{
		{"before start", nil},
		{"holder 1", func(p *pty, e *errPipe) {
			e.next(reHolder)
			e.gone()
			p.confirm()
			p.recordShare()
		}},
		{"holder 2", func(p *pty, e *errPipe) {
			p.holder(e, 1)
			e.next(reNoted)
			p.confirm()
			e.next(reHolder)
			e.gone()
			p.confirm()
			p.recordShare()
		}},
		{"share input", func(p *pty, e *errPipe) {
			for i := 1; i <= 2; i++ {
				p.holder(e, i)
				e.next(reNoted)
				p.confirm()
			}
			var k int
			fmt.Sscan(e.next(reAsk)[1], &k)
			e.gone()
			p.typeLine(k, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			p := openPTY(t)
			e := newErrPipe(t, p)
			if tc.drive == nil {
				e.gone()
			}
			out, kd := p.startInit(base, w1)
			p.stderr.Close()
			if tc.drive != nil {
				tc.drive(p, e)
			}
			if code := p.exitOf(); code != exitAbort {
				t.Fatalf("exit code %d; screen %q", code, p.output())
			}
			screen := p.checkShares(1)
			// What the screen showed is complete: the share lines read by
			// holder are all there are.
			if n := len(reShare.FindAllString(screen, -1)); n != len(p.shown) {
				t.Fatalf("%d share lines, %d recorded", n, len(p.shown))
			}
			tail := screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):]
			want := strings.ReplaceAll(lostTail, "\n", "\r\n")
			if tail != want {
				t.Fatalf("behind the last clear %q, want %q", tail, want)
			}
			for _, s := range stackTrace {
				if strings.Contains(screen, s) {
					t.Fatalf("%q on the terminal: %q", s, screen)
				}
			}
			for _, d := range []string{out, kd} {
				if exists(d) {
					t.Fatalf("%s written", d)
				}
			}
			if staging, _ := filepath.Glob(filepath.Join(base, ".tmp-ceremony-*")); len(staging) != 0 {
				t.Fatalf("staging left %v", staging)
			}
		})
	}
}

// TestPTYStderrClosedAfterInput (task 15i): standard error loses its
// reader after the last words of the ceremony are counted; a SIGINT
// after the commit point (hook commit-sig at "end") makes the program
// report the late signal on standard error after close. That write
// fails with EPIPE and does not end the program: the ceremony is
// complete, exit code 0, the export and the keys complete, the results
// on the screen behind the last clear, the terminal restored.
func TestPTYStderrClosedAfterInput(t *testing.T) {
	w1 := witnessArg(t, "w1")
	base := t.TempDir()
	p := openPTY(t)
	p.env = []string{hookEnv + "=commit-sig", sigEnv + "=" + fmt.Sprint(int(syscall.SIGINT)), atEnv + "=end"}
	e := newErrPipe(t, p)
	out, kd := p.startInit(base, w1)
	p.stderr.Close()
	for i := 1; i <= 2; i++ {
		p.holder(e, i)
		e.next(reNoted)
		p.confirm()
	}
	for n := 0; n < 2; n++ {
		var k int
		fmt.Sscan(e.next(reAsk)[1], &k)
		p.typeLine(k, 0)
		e.next(reCount)
		if n == 1 {
			e.gone()
		}
		p.typeLine(k, 1)
	}
	if code := p.exitOf(); code != 0 {
		t.Fatalf("exit code %d; screen %q", code, p.output())
	}
	screen := p.checkShares(len(p.shown) + len(p.typed)/2 + 1)
	tail := screen[strings.LastIndex(screen, clearScreen):]
	if !strings.Contains(tail, "Exportverzeichnis:") || strings.Contains(screen, "abgebrochen") {
		t.Fatalf("behind the last clear %q", tail)
	}
	keys, _ := os.ReadDir(kd)
	exported, _ := os.ReadDir(filepath.Join(out, "platform"))
	if len(keys) != 2 || len(exported) != 6 {
		t.Fatalf("keys %v, export %v", keys, exported)
	}
	if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
		t.Fatal(err)
	}
}
