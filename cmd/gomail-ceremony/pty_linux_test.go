//go:build linux && !ceremony_notty

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/tim-riep/go-mail/internal/ceremony"
)

// The tests in this file drive the program (this test binary re-executed
// as gomail-ceremony, see TestMain) on a pseudo terminal from /dev/ptmx,
// as the operator and the holders would (task 10b finding 1d). The
// master side records everything the terminal shows, including the echo
// of typed input when the echo is on.

const runMainEnv = "GOMAIL_CEREMONY_TEST_RUN_MAIN"

// hookEnv names a test hook for the program re-executed (childHooks);
// spoilEnv the export directory that the hook "commit-sig-spoil" fills
// so that commit has to roll back; sigEnv the number of the signal and
// atEnv the commitHook point ("begin", "point" or "end") of the hooks
// "commit-sig" and "commit-sig-spoil".
const (
	hookEnv  = "GOMAIL_CEREMONY_TEST_HOOK"
	spoilEnv = "GOMAIL_CEREMONY_TEST_SPOIL"
	sigEnv   = "GOMAIL_CEREMONY_TEST_SIG"
	atEnv    = "GOMAIL_CEREMONY_TEST_AT"
)

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		childHooks(os.Getenv(hookEnv))
		main()
	}
	os.Exit(m.Run())
}

// childHooks sets the hooks of the program re-executed by a test:
//
//	commit-sig        the signal sigEnv to itself at the commitHook point
//	                  atEnv (BeginCommit, CommitPoint before the rename,
//	                  EndCommit after it), taken in before commit goes on
//	commit-sig-spoil  the same, and then the export directory is filled
//	                  so that commit rolls back
//	probe-int         SIGINT to itself while openTerm has the echo off
//	close-int         a signal handed to the signal handling while close
//	                  holds t.mu (as TestCloseSignal)
func childHooks(name string) {
	switch name {
	case "":
	case "commit-sig", "commit-sig-spoil":
		sig, err := strconv.Atoi(os.Getenv(sigEnv))
		if err != nil {
			fmt.Fprintln(os.Stderr, "no signal for", name)
			os.Exit(3)
		}
		point := os.Getenv(atEnv)
		commitHook = func(t *term, at string, _ bool) {
			if at != point {
				return
			}
			syscall.Kill(os.Getpid(), syscall.Signal(sig))
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				t.mu.Lock()
				p := t.pending || t.late
				t.mu.Unlock()
				if p {
					break
				}
			}
			if out := os.Getenv(spoilEnv); name == "commit-sig-spoil" && out != "" {
				os.MkdirAll(out, 0o700)
				os.WriteFile(filepath.Join(out, "x"), nil, 0o600)
			}
		}
	case "probe-int":
		probeHook = func(*term) {
			syscall.Kill(os.Getpid(), syscall.SIGINT)
			time.Sleep(10 * time.Second) // the signal ends the program
		}
	case "close-int":
		closeHook = func(t *term) {
			t.sig <- os.Interrupt
			for len(t.sig) != 0 {
				runtime.Gosched()
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown test hook", name)
		os.Exit(3)
	}
}

// pty is a pseudo terminal with a running program on its slave side.
type pty struct {
	t      *testing.T
	master *os.File
	slave  *os.File // kept open by the test to read the terminal attributes
	lflag0 uint32   // the local modes of the terminal before the program ran
	iflag0 uint32   // the input modes of the terminal before the program ran
	env    []string // added to the environment of the program

	mu  sync.Mutex
	out []byte // everything the terminal showed
	eof chan struct{}

	cmd    *exec.Cmd
	exited chan struct{}
	err    error // of cmd.Wait

	pos   int      // how far the output has been answered
	typed []typing // the shares typed, in order
	shown map[int]string

	shownAt []int // output offsets just behind every share line shown
	sentAt  []int // output offsets at which input was sent
}

// typing is a share typed at output offset off.
type typing struct {
	off   int
	lines []string
}

func openPTY(t *testing.T) *pty {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pseudo terminal:", err)
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
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skip("pts:", err)
	}
	p := &pty{t: t, master: m, slave: s, eof: make(chan struct{}), exited: make(chan struct{}), shown: map[int]string{}}
	p.lflag0 = p.lflag()
	if p.lflag0&quiet != quiet {
		t.Fatalf("new terminal with local modes %#x", p.lflag0)
	}
	p.iflag0 = p.iflag()
	if p.iflag0&syscall.IXON == 0 {
		t.Fatalf("new terminal with input modes %#x", p.iflag0)
	}
	go func() {
		defer close(p.eof)
		buf := make([]byte, 4096)
		for {
			n, err := m.Read(buf)
			p.mu.Lock()
			p.out = append(p.out, buf[:n]...)
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			p.cmd.Process.Kill()
			<-p.exited
		}
		s.Close()
		m.Close()
	})
	return p
}

// start runs the program with stdin, stdout and stderr on the slave as
// its controlling terminal; stdin and stdout go to the given files
// instead when they are not nil.
func (p *pty) start(stdin, stdout *os.File, args ...string) {
	p.t.Helper()
	p.startBin(os.Args[0], stdin, stdout, args...)
}

// startBin is start with the program bin.
func (p *pty) startBin(bin string, stdin, stdout *os.File, args ...string) {
	p.t.Helper()
	cmd := exec.Command(bin, args...)
	// Without GOTRACEBACK the program's own traceback level applies.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOTRACEBACK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(append(cmd.Env, runMainEnv+"=1"), p.env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.slave, p.slave, p.slave
	if stdin != nil {
		cmd.Stdin = stdin
	}
	if stdout != nil {
		cmd.Stdout = stdout
	}
	// The controlling terminal is taken from stderr, which is always
	// the slave.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 2}
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.cmd = cmd
	go func() {
		p.err = cmd.Wait()
		close(p.exited)
	}()
}

func (p *pty) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.out)
}

func (p *pty) send(s string) {
	p.t.Helper()
	p.sentAt = append(p.sentAt, len(p.output()))
	if _, err := p.master.Write([]byte(s)); err != nil {
		p.t.Fatal(err)
	}
}

// lflag returns the local modes of the terminal.
func (p *pty) lflag() uint32 { return p.termios().Lflag }

// iflag returns the input modes of the terminal.
func (p *pty) iflag() uint32 { return p.termios().Iflag }

func (p *pty) termios() syscall.Termios {
	p.t.Helper()
	var t syscall.Termios
	if err := sysIoctl(p.slave.Fd(), syscall.TCGETS, unsafe.Pointer(&t)); err != nil {
		p.t.Fatal(err)
	}
	return t
}

// setIflag sets the input modes of the terminal before the program runs.
func (p *pty) setIflag(set uint32) {
	p.t.Helper()
	t := p.termios()
	t.Iflag |= set
	if err := sysIoctl(p.slave.Fd(), syscall.TCSETS, unsafe.Pointer(&t)); err != nil {
		p.t.Fatal(err)
	}
	p.iflag0 = p.iflag()
}

// echo reports whether the terminal echoes input, and whether it is in
// canonical mode.
func (p *pty) echo() (echo, icanon bool) {
	p.t.Helper()
	l := p.lflag()
	return l&syscall.ECHO != 0, l&syscall.ICANON != 0
}

// pendingInput returns the number of bytes received by the terminal and
// not read, complete lines or not: canonical mode is switched off for
// the count (a partial line counts only then) and on again.
func (p *pty) pendingInput() int {
	p.t.Helper()
	var old syscall.Termios
	if err := sysIoctl(p.slave.Fd(), syscall.TCGETS, unsafe.Pointer(&old)); err != nil {
		p.t.Fatal(err)
	}
	raw := old
	raw.Lflag &^= syscall.ICANON
	if err := sysIoctl(p.slave.Fd(), syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		p.t.Fatal(err)
	}
	defer sysIoctl(p.slave.Fd(), syscall.TCSETS, unsafe.Pointer(&old))
	var n int32
	if err := sysIoctl(p.slave.Fd(), syscall.TIOCINQ, unsafe.Pointer(&n)); err != nil {
		p.t.Fatal(err)
	}
	return int(n)
}

// quiet are the local modes that must be clear while a share is typed,
// flow the input modes that must be clear while the program shows or
// reads shares (spelled out here, not taken from quietFlags and
// flowFlags).
const (
	quiet = syscall.ECHO | syscall.ISIG | syscall.IEXTEN
	flow  = syscall.IXON | syscall.IXOFF | syscall.IXANY
)

// quietInput checks the local modes while a share is asked: no echo, no
// signals from control characters, no extended input processing, and
// still canonical mode (task 10b finding 1, task 10d finding 1a); and no
// flow control (task 10e finding 1).
func (p *pty) quietInput() {
	p.t.Helper()
	if l := p.lflag(); l&quiet != 0 || l&syscall.ICANON == 0 {
		p.t.Fatalf("share asked with echo %v, isig %v, iexten %v, canonical mode %v",
			l&syscall.ECHO != 0, l&syscall.ISIG != 0, l&syscall.IEXTEN != 0, l&syscall.ICANON != 0)
	}
	p.noFlow()
}

// noFlow checks that the terminal has no software flow control.
func (p *pty) noFlow() {
	p.t.Helper()
	if i := p.iflag(); i&flow != 0 {
		p.t.Fatalf("flow control on: ixon %v, ixoff %v, ixany %v", i&syscall.IXON != 0, i&syscall.IXOFF != 0, i&syscall.IXANY != 0)
	}
}

// restored checks that the terminal has its local and input modes of
// before the program again.
func (p *pty) restored() {
	p.t.Helper()
	if l := p.lflag(); l != p.lflag0 {
		p.t.Fatalf("local modes %#x after the program, %#x before", l, p.lflag0)
	}
	if i := p.iflag(); i != p.iflag0 {
		p.t.Fatalf("input modes %#x after the program, %#x before", i, p.iflag0)
	}
}

// next waits for the next match of re after pos and moves pos behind
// it; it returns nil when the program exited without one.
func (p *pty) next(re *regexp.Regexp) []string {
	p.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		out := p.output()
		if m := re.FindStringSubmatchIndex(out[p.pos:]); m != nil {
			sub := make([]string, len(m)/2)
			for i := range sub {
				if m[2*i] >= 0 {
					sub[i] = out[p.pos+m[2*i] : p.pos+m[2*i+1]]
				}
			}
			p.pos += m[1]
			return sub
		}
		select {
		case <-p.exited:
			// Read what the program wrote before it exited.
			time.Sleep(50 * time.Millisecond)
			if re.MatchString(p.output()[p.pos:]) {
				continue
			}
			return nil
		default:
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("timeout; output so far:\n%q", out[max(0, len(out)-2000):])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wait waits for the program to exit and for its output; it returns the
// exit code.
func (p *pty) wait() int {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(60 * time.Second):
		p.t.Fatal("program does not exit")
	}
	// The slave of the test stays open; give the reader a moment.
	time.Sleep(100 * time.Millisecond)
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode()
	}
	if p.err != nil {
		p.t.Fatal(p.err)
	}
	return 0
}

var ptyPrompt = regexp.MustCompile(`Inhaber von Anteil \d+ von \d+|Anteil notiert\?|Anteil Nr\. (\d+) eingeben[^\n]*\n|Anteil eingeben[^\n]*\n|Anteil (\d+)/\d+: ([a-z ]+)\r\n`)

// converse answers the prompts of the program until it exits: Enter for
// the holders, the share asked for (typed in upper case over two lines)
// in the trial reconstruction, and the shares of queue for "Anteil
// eingeben". While a share is typed, the echo must be off and canonical
// mode on.
func (p *pty) converse(queue []string) {
	p.t.Helper()
	for {
		m := p.next(ptyPrompt)
		if m == nil {
			return
		}
		var share string
		switch {
		case strings.HasPrefix(m[0], "Inhaber"), strings.HasPrefix(m[0], "Anteil notiert"):
			p.send("\n")
			continue
		case m[3] != "":
			var i int
			fmt.Sscan(m[2], &i)
			p.shown[i] = strings.TrimSpace(m[3])
			p.shownAt = append(p.shownAt, p.pos)
			continue
		case m[1] != "":
			var i int
			fmt.Sscan(m[1], &i)
			share = p.shown[i]
		default:
			if len(queue) == 0 {
				p.t.Fatal("no share left to type")
			}
			share, queue = queue[0], queue[1:]
		}
		p.quietInput()
		ws := strings.Fields(share)
		lines := []string{strings.ToUpper(strings.Join(ws[:12], " ")), strings.Join(ws[12:], " ")}
		p.typed = append(p.typed, typing{off: len(p.output()), lines: lines})
		p.send(lines[0] + "\n" + lines[1] + "\n")
	}
}

// check checks the screen after the program exited (task 10b finding
// 1d): no typed word was echoed, every share is cleared before the next
// holder is called and before the end, at least shown + typed + 1
// clears, and the terminal modes (echo, signals) are restored.
func (p *pty) check(extra ...string) string {
	p.t.Helper()
	out := p.checkShares(len(p.shown)+len(p.typed)+1, extra...)
	p.checkConfirm(out)
	return out
}

// checkShares is check without the confirmations, with at least
// minClears clears.
func (p *pty) checkShares(minClears int, extra ...string) string {
	p.t.Helper()
	out := p.output()
	for _, ty := range p.typed {
		for _, l := range ty.lines {
			ws := strings.Fields(l)
			for i := 0; i+2 <= len(ws); i++ {
				if pair := ws[i] + " " + ws[i+1]; strings.Contains(out[ty.off:], pair) {
					p.t.Fatalf("typed words %q echoed", pair)
				}
			}
		}
	}
	var shares []string
	for _, s := range p.shown {
		shares = append(shares, s)
	}
	for _, ty := range p.typed {
		shares = append(shares, strings.Join(ty.lines, " "))
	}
	checkScreen(p.t, out, append(shares, extra...), minClears)
	if echo, icanon := p.echo(); !echo || !icanon {
		p.t.Fatal("echo not restored")
	}
	p.restored()
	return out
}

// checkConfirm checks that between every share line shown and the next
// clear the holder was asked exactly once whether the share is noted
// and exactly one input was sent (task 10c finding 5).
func (p *pty) checkConfirm(out string) {
	p.t.Helper()
	if len(p.shownAt) != len(p.shown) {
		p.t.Fatalf("%d share lines, %d shares", len(p.shownAt), len(p.shown))
	}
	for n, s := range p.shownAt {
		c := strings.Index(out[s:], clearScreen)
		if c < 0 {
			p.t.Fatalf("share line %d never cleared", n+1)
		}
		sent := 0
		for _, off := range p.sentAt {
			if off >= s && off < s+c {
				sent++
			}
		}
		if k := strings.Count(out[s:s+c], "Anteil notiert?"); k != 1 || sent != 1 {
			t := out[s : s+c]
			p.t.Fatalf("share line %d: %d confirmation prompts and %d inputs before the clear: %q", n+1, k, sent, t)
		}
	}
}

func TestPTY(t *testing.T) {
	base := t.TempDir()
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	w1 := witnessArg(t, "w1")

	// init 3-of-5: five shares shown, three typed back.
	p := openPTY(t)
	p.start(nil, nil, "init", "--shares", "3-of-5", "--out", out, "--keys", kd, "--origin", "go-mail.test/log", "--witness", w1, "--min-witnesses", "1")
	p.converse(nil)
	if code := p.wait(); code != 0 {
		t.Fatalf("init: %d\n%s", code, p.output())
	}
	if len(p.shown) != 5 || len(p.typed) != 3 {
		t.Fatalf("%d shown, %d typed", len(p.shown), len(p.typed))
	}
	screen := p.check()
	last := strings.LastIndex(screen, clearScreen)
	if !strings.Contains(screen[last:], "Exportverzeichnis:") || !strings.Contains(screen[last:], "Probe-Rekonstruktion erfolgreich") {
		t.Fatalf("results not after the last clear: %q", screen[last:])
	}
	t.Logf("init: %d shares shown, %d typed, %d clears, final screen %q", len(p.shown), len(p.typed),
		strings.Count(screen, clearScreen), screen[last+len(clearScreen):])
	shares := p.shown
	pinPath := filepath.Join(out, "identity-1.pin")

	// reshare 3-of-5 with three old shares: the old ones are never on
	// the screen when the first new holder comes.
	p = openPTY(t)
	p.start(nil, nil, "reshare", "--pin", pinPath, "--shares", "3-of-5")
	p.converse([]string{shares[2], shares[5], shares[1]})
	if code := p.wait(); code != 0 {
		t.Fatalf("reshare: %d\n%s", code, p.output())
	}
	if len(p.shown) != 5 || len(p.typed) != 3+3 {
		t.Fatalf("%d shown, %d typed", len(p.shown), len(p.typed))
	}
	screen = p.check(shares[1], shares[2], shares[3], shares[4], shares[5])
	t.Logf("reshare: %d shares shown, %d typed, %d clears", len(p.shown), len(p.typed), strings.Count(screen, clearScreen))

	// ingest-rotate: three shares typed, with one refused attempt.
	validFrom := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	p = openPTY(t)
	p.start(nil, nil, "ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", filepath.Join(base, "rot"), "--keys", kd, "--valid-from", validFrom)
	bad := strings.Fields(shares[4])
	bad[0], bad[1] = bad[1], bad[0]
	p.converse([]string{shares[4], strings.Join(bad, " "), shares[4], shares[3]})
	if code := p.wait(); code == 0 {
		// shares[4] twice: the duplicate is refused by the ceremony.
		t.Fatal("duplicate share accepted")
	}
	p.check()
	p = openPTY(t)
	p.start(nil, nil, "ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", filepath.Join(base, "rot"), "--keys", kd, "--valid-from", validFrom)
	p.converse([]string{shares[4], strings.Join(bad, " "), shares[1], shares[3]})
	if code := p.wait(); code != 0 {
		t.Fatalf("ingest-rotate: %d\n%s", code, p.output())
	}
	screen = p.check()
	if !strings.Contains(screen, "Prüfsumme") {
		t.Fatal("refused attempt not reported")
	}
	t.Logf("ingest-rotate: %d typed, %d clears", len(p.typed), strings.Count(screen, clearScreen))

	// succeed: three shares typed with the echo off.
	p = openPTY(t)
	p.start(nil, nil, "succeed", "--pin", pinPath, "--out", filepath.Join(base, "succ"), "--origin", "go-mail.test/log", "--witness", w1, "--min-witnesses", "1")
	p.converse([]string{shares[2], shares[5], shares[4]})
	if code := p.wait(); code != 0 {
		t.Fatalf("succeed: %d\n%s", code, p.output())
	}
	screen = p.check()
	if len(p.typed) != 3 || !strings.Contains(screen, "identity-2.pin") {
		t.Fatalf("succeed: %d typed", len(p.typed))
	}
	t.Logf("succeed: %d typed, %d clears", len(p.typed), strings.Count(screen, clearScreen))
}

// TestPTYInterrupt: Ctrl-C while a share is typed restores the echo,
// clears the screen and ends the program. The terminal raises no signal
// then (ISIG cleared, task 10d finding 1a): Ctrl-C reaches the program
// with the line, when Enter is pressed.
func TestPTYInterrupt(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	p := openPTY(t)
	p.start(nil, nil, "init", "--shares", "2-of-2", "--out", filepath.Join(base, "out"), "--keys", filepath.Join(base, "keys"),
		"--origin", "o", "--witness", w1, "--min-witnesses", "1")
	// Both shares shown, then Ctrl-C in the middle of the first one typed
	// back.
	for {
		m := p.next(ptyPrompt)
		if m == nil {
			t.Fatalf("exited early:\n%s", p.output())
		}
		if m[3] != "" {
			var i int
			fmt.Sscan(m[2], &i)
			p.shown[i] = strings.TrimSpace(m[3])
			p.shownAt = append(p.shownAt, p.pos)
			continue
		}
		if m[1] != "" {
			break
		}
		p.send("\n")
	}
	p.quietInput()
	ws := strings.Fields(p.shown[1])
	p.typed = append(p.typed, typing{off: len(p.output()), lines: []string{strings.Join(ws[:12], " ")}})
	p.send(strings.Join(ws[:12], " ") + "\n")
	p.next(regexp.MustCompile(`\(12 von 30 Wörtern\)`))
	p.send("\x03") // VINTR
	time.Sleep(200 * time.Millisecond)
	select {
	case <-p.exited:
		t.Fatal("Ctrl-C raised a signal while a share is typed")
	default:
	}
	p.send("\n")
	if code := p.wait(); code != 130 {
		t.Fatalf("exit code %d\n%s", code, p.output())
	}
	screen := p.check()
	if !strings.HasSuffix(strings.TrimSpace(screen), "abgebrochen") || !strings.Contains(screen, "Abbruchtaste") {
		t.Fatalf("end of screen %q", screen[max(0, len(screen)-200):])
	}
	if _, err := os.Lstat(filepath.Join(base, "out")); err == nil {
		t.Fatal("export written")
	}
}

// shareCommands returns the four commands that show or read shares, for
// the pin pinPath, writing below base.
func shareCommands(base, pinPath, w1 string) [][]string {
	validFrom := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return [][]string{
		{"init", "--shares", "3-of-5", "--out", filepath.Join(base, "o2"), "--keys", filepath.Join(base, "k2"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
		{"reshare", "--pin", pinPath, "--shares", "3-of-5"},
		{"ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", filepath.Join(base, "o2"), "--keys", filepath.Join(base, "k2"), "--valid-from", validFrom},
		{"succeed", "--pin", pinPath, "--out", filepath.Join(base, "o2"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
	}
}

// refusedAlone waits for the program to end by itself (nobody answers)
// and checks that it refused with errNoTerminal and showed nothing: no
// prompt, no share, no clear.
func (p *pty) refusedAlone(what string) {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		p.t.Errorf("%s waits for input instead of refusing", what)
	}
	code := p.wait()
	out := p.output()
	if code != 1 || !strings.Contains(out, "nur auf einem Terminal") || strings.Contains(out, clearScreen) {
		p.t.Fatalf("%s: %d, terminal %q", what, code, out)
	}
	for _, s := range []string{"Inhaber", "Anteil Nr.", "Anteil eingeben", "Anteil notiert", "Anteil 1/"} {
		if strings.Contains(out, s) {
			p.t.Fatalf("%s: %q on the terminal", what, s)
		}
	}
}

// TestPTYPipe: every command that shows or reads shares refuses without
// showing, reading or writing anything when stdout is a pipe (stdin and
// stderr on the terminal), and when stdin is a pipe or a file (stdout
// and stderr on the terminal) (task 10b finding 1c, task 10c finding 1).
func TestPTYPipe(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	pinPath := filepath.Join(out, "identity-1.pin")
	answers := strings.Repeat("\n", 20) + tt.shares[1] + "\n" + tt.shares[2] + "\n"
	inPath := filepath.Join(base, "stdin")
	if err := os.WriteFile(inPath, []byte(answers), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range shareCommands(base, pinPath, w1) {
		// stdout a pipe.
		p := openPTY(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		p.start(nil, w, args...)
		w.Close()
		pipe := make(chan []byte)
		go func() {
			b, _ := io.ReadAll(r)
			pipe <- b
		}()
		p.refusedAlone(args[0] + " with stdout a pipe")
		if piped := <-pipe; len(piped) != 0 {
			t.Fatalf("%s: pipe %q", args[0], piped)
		}
		r.Close()

		// stdin a pipe.
		p = openPTY(t)
		r, w, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.WriteString(answers)
		w.Close()
		p.start(r, nil, args...)
		p.refusedAlone(args[0] + " with stdin a pipe")
		left, _ := io.ReadAll(r)
		r.Close()
		if string(left) != answers {
			t.Fatalf("%s: stdin pipe read", args[0])
		}

		// stdin a file.
		p = openPTY(t)
		f, err := os.Open(inPath)
		if err != nil {
			t.Fatal(err)
		}
		p.start(f, nil, args...)
		p.refusedAlone(args[0] + " with stdin a file")
		off, err := f.Seek(0, io.SeekCurrent)
		f.Close()
		if err != nil || off != 0 {
			t.Fatalf("%s: stdin file read up to %d", args[0], off)
		}
	}
	for _, d := range []string{"o2", "k2"} {
		if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
			t.Fatalf("%s written", d)
		}
	}
}

// TestNoTTYBuild: the program built with tty_other.go on Linux (build
// tag ceremony_notty: no terminal control, isTerminalFd always false),
// run with stdin, stdout and stderr on a real terminal, refuses all four
// commands that show or read shares (task 10c finding 1).
func TestNoTTYBuild(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the variant:", err)
	}
	base := t.TempDir()
	bin := filepath.Join(base, "gomail-ceremony-notty")
	build := exec.Command(goBin, "build", "-tags", "ceremony_notty", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	for _, args := range shareCommands(base, filepath.Join(out, "identity-1.pin"), w1) {
		p := openPTY(t)
		p.startBin(bin, nil, nil, args...)
		p.refusedAlone(args[0] + " without terminal control")
		if echo, icanon := p.echo(); !echo || !icanon {
			t.Fatalf("%s: terminal changed", args[0])
		}
		t.Logf("%s refused: %q", args[0], strings.TrimSpace(p.output()))
	}
	for _, d := range []string{"o2", "k2"} {
		if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
			t.Fatalf("%s written", d)
		}
	}
	// The normal build of the same commands on the same terminal does
	// ask (TestPTY); here a control: the publish command, which needs no
	// terminal, still works its way to its own error.
	p := openPTY(t)
	p.startBin(bin, nil, nil, "publish", "--from", out, "--data", filepath.Join(base, "nodata"), "--pin", filepath.Join(out, "identity-1.pin"))
	if code := p.wait(); code != 1 || strings.Contains(p.output(), "nur auf einem Terminal") {
		t.Fatalf("publish: %d %q", code, p.output())
	}
}

// startInit starts init 2-of-2 below base; it returns the export and
// the key directory.
func (p *pty) startInit(base, w1 string) (out, kd string) {
	p.t.Helper()
	out, kd = filepath.Join(base, "out"), filepath.Join(base, "keys")
	p.start(nil, nil, "init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
	return out, kd
}

// driveTo answers the prompts as converse does until a share is shown
// and its holder is asked whether it is noted (stop "display"), or until
// a share is asked back (stop "input"; it returns the index asked for).
func (p *pty) driveTo(stop string) int {
	p.t.Helper()
	for {
		m := p.next(ptyPrompt)
		if m == nil {
			p.t.Fatalf("exited early:\n%s", p.output())
		}
		switch {
		case m[3] != "":
			var i int
			fmt.Sscan(m[2], &i)
			p.shown[i] = strings.TrimSpace(m[3])
			p.shownAt = append(p.shownAt, p.pos)
			continue
		case m[1] != "":
			if stop != "input" {
				p.t.Fatalf("share asked before %s", stop)
			}
			var i int
			fmt.Sscan(m[1], &i)
			return i
		case stop == "display" && strings.HasPrefix(m[0], "Anteil notiert"):
			return 0
		}
		p.send("\n")
	}
}

// stackTrace are traces of a stack dump of the Go runtime (not words
// of the word list: "panic" is one).
var stackTrace = []string{"goroutine ", "SIGQUIT", "SIGTSTP", "SIGABRT", "PC=", "panic:", "[signal"}

// checkAbort checks a program ended by a signal or an abort key: exit
// code 130, the terminal modes restored, every share cleared, behind the
// last clear only the message (with the abort key named if inBand), and
// no stack trace on the terminal.
func (p *pty) checkAbort(inBand bool) string {
	p.t.Helper()
	if code := p.wait(); code != exitAbort {
		p.t.Fatalf("exit code %d\n%q", code, p.output())
	}
	screen := p.checkShares(1)
	tail := screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):]
	want := "gomail-ceremony: abgebrochen\r\n"
	if inBand {
		want = "gomail-ceremony: " + errAborted.Error() + "\r\n" + want
	}
	if tail != want {
		p.t.Fatalf("behind the last clear %q, want %q", tail, want)
	}
	for _, s := range stackTrace {
		if strings.Contains(screen, s) {
			p.t.Fatalf("%q on the terminal: %q", s, screen)
		}
	}
	return screen
}

// TestPTYSignals: SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGTSTP, sent to
// the program (task 10e finding 3: each while a share is shown and while
// one is typed) or raised by the terminal from Ctrl-\ and Ctrl-Z, end
// the ceremony through the abort path: the
// echo and the other terminal modes restored, the screen cleared, no
// stack trace, exit code 130, nothing written; the program is never
// stopped (task 10d finding 1). While a share is typed the terminal
// raises no signal (ISIG cleared): Ctrl-\ and Ctrl-Z reach the program
// as input and end it the same way, naming the abort key. The signals
// after which the runtime would print a stack trace take the same way.
// Words typed but not sent yet (no Enter) when the ceremony is aborted
// are discarded with the restore of the echo, not left in the input
// queue of the terminal, where they would be echoed or read by the
// shell.
func TestPTYSignals(t *testing.T) {
	w1 := witnessArg(t, "w1")
	kill := func(sig syscall.Signal) func(*pty) {
		return func(p *pty) {
			if err := p.cmd.Process.Signal(sig); err != nil {
				p.t.Fatal(err)
			}
		}
	}
	key := func(k string) func(*pty) { return func(p *pty) { p.send(k) } }
	for _, c := range []struct {
		name   string
		stop   string // "display" or "input"
		act    func(*pty)
		inBand bool // the program reads the abort key itself
	}{
		{"SIGQUIT shown", "display", kill(syscall.SIGQUIT), false},
		{"Ctrl-backslash shown", "display", key("\x1c"), false},
		{"SIGTSTP shown", "display", kill(syscall.SIGTSTP), false},
		{"Ctrl-Z shown", "display", key("\x1a"), false},
		{"SIGQUIT typed", "input", kill(syscall.SIGQUIT), false},
		{"Ctrl-backslash typed", "input", key("\x1c\n"), true},
		{"SIGTSTP typed", "input", kill(syscall.SIGTSTP), false},
		{"Ctrl-Z typed", "input", key("\x1a\n"), true},
		{"SIGINT typed", "input", kill(syscall.SIGINT), false},
		{"SIGINT shown", "display", kill(syscall.SIGINT), false},
		{"SIGTERM shown", "display", kill(syscall.SIGTERM), false},
		{"SIGTERM typed", "input", kill(syscall.SIGTERM), false},
		{"SIGHUP shown", "display", kill(syscall.SIGHUP), false},
		{"SIGHUP typed", "input", kill(syscall.SIGHUP), false},
		// Signals after which the runtime would print a stack trace
		// (task 10d finding 1c).
		{"SIGABRT shown", "display", kill(syscall.SIGABRT), false},
		{"SIGABRT typed", "input", kill(syscall.SIGABRT), false},
		{"SIGILL shown", "display", kill(syscall.SIGILL), false},
		{"SIGTRAP shown", "display", kill(syscall.SIGTRAP), false},
		{"SIGBUS shown", "display", kill(syscall.SIGBUS), false},
		{"SIGFPE shown", "display", kill(syscall.SIGFPE), false},
		{"SIGSEGV shown", "display", kill(syscall.SIGSEGV), false},
		{"SIGSYS shown", "display", kill(syscall.SIGSYS), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			p := openPTY(t)
			out, kd := p.startInit(base, w1)
			if want := p.driveTo(c.stop); c.stop == "input" {
				p.quietInput()
				ws := strings.Fields(p.shown[want])
				p.typed = append(p.typed, typing{off: len(p.output()), lines: []string{strings.Join(ws[:12], " ")}})
				p.send(strings.Join(ws[:12], " ") + "\n")
				p.next(regexp.MustCompile(`\(12 von 30 Wörtern\)`))
				// Three more words, not sent yet.
				last := &p.typed[len(p.typed)-1]
				last.lines = append(last.lines, strings.Join(ws[12:15], " "))
				p.send(strings.Join(ws[12:15], " "))
				time.Sleep(50 * time.Millisecond)
			}
			c.act(p)
			screen := p.checkAbort(c.inBand)
			if n := p.pendingInput(); n != 0 {
				t.Fatalf("%d bytes typed left in the input queue", n)
			}
			for _, d := range []string{out, kd} {
				if _, err := os.Lstat(d); err == nil {
					t.Fatalf("%s written", d)
				}
			}
			t.Logf("echo before %v, after %v; behind the last clear %q", c.stop != "input", p.lflag()&syscall.ECHO != 0,
				screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):])
		})
	}
}

// TestPTYQuitInCommit: SIGQUIT, SIGTERM or SIGHUP while the ceremony
// writes its files (task 10d finding 1, task 10e findings 2 and 3).
// Before the commit point (at BeginCommit, also with the export
// directory taken meanwhile, or at CommitPoint just before the rename)
// the files are rolled back: no staging directory, no key, no export,
// "abgebrochen" and exit code 130. After the rename (at EndCommit) the
// ceremony is complete: the results and the note that a signal was
// ignored after the last clear, exit code 0. In every case the terminal
// is restored and no stack trace is shown.
func TestPTYQuitInCommit(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, sig := range []syscall.Signal{syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP} {
		for _, c := range []struct {
			at       string
			spoil    bool
			complete bool
		}{
			{"begin", false, false},
			{"begin", true, false},
			{"point", false, false},
			{"end", false, true},
		} {
			name := fmt.Sprintf("%v at %s", sig, c.at)
			if c.spoil {
				name += ", out taken"
			}
			t.Run(name, func(t *testing.T) {
				base := t.TempDir()
				p := openPTY(t)
				hook := "commit-sig"
				if c.spoil {
					hook = "commit-sig-spoil"
				}
				p.env = []string{hookEnv + "=" + hook, sigEnv + "=" + strconv.Itoa(int(sig)), atEnv + "=" + c.at,
					spoilEnv + "=" + filepath.Join(base, "out")}
				out, kd := p.startInit(base, w1)
				p.converse(nil)
				var screen string
				if c.complete {
					if code := p.wait(); code != 0 {
						t.Fatalf("exit code %d\n%q", code, p.output())
					}
					screen = p.check()
					tail := screen[strings.LastIndex(screen, clearScreen):]
					if !strings.Contains(tail, "abgeschlossen; ein Abbruchsignal kam nach dem Commit-Punkt an und wurde ignoriert") ||
						!strings.Contains(tail, "Exportverzeichnis:") || !strings.Contains(tail, "Ingest-Schlüssel:") || strings.Contains(screen, "abgebrochen") {
						t.Fatalf("behind the last clear %q", tail)
					}
					for _, s := range stackTrace {
						if strings.Contains(screen, s) {
							t.Fatalf("%q on the terminal", s)
						}
					}
				} else {
					screen = p.checkAbort(false)
				}
				if staging, _ := filepath.Glob(filepath.Join(base, ".tmp-ceremony-*")); len(staging) != 0 {
					t.Fatalf("staging left %v", staging)
				}
				keys, _ := os.ReadDir(kd)
				exported, _ := os.ReadDir(filepath.Join(out, "platform"))
				if c.complete {
					if len(keys) != 2 || len(exported) != 6 {
						t.Fatalf("keys %v, export %v", keys, exported)
					}
					if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
						t.Fatal(err)
					}
				} else if _, err := os.Lstat(kd); err == nil || len(exported) != 0 {
					t.Fatalf("keys %v, export %v", keys, exported)
				}
				t.Logf("%d keys, %d export files; behind the last clear %q", len(keys), len(exported),
					screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):])
			})
		}
	}
}

// TestPTYFlowControl: from the first prompt to the end the terminal has
// no software flow control (task 10e finding 1). Ctrl-S (XOFF) typed
// while a share is shown or typed is input like any other: it stops
// nothing, and SIGINT afterwards ends the program within 2 s with exit
// code 130, the screen cleared and the terminal modes as before (IXON,
// IXOFF and IXANY set again). An XOFF typed before the program started
// stops its output only until the program clears IXON. The terminal
// has IXON, IXOFF and IXANY set before.
func TestPTYFlowControl(t *testing.T) {
	w1 := witnessArg(t, "w1")
	for _, c := range []struct {
		name  string
		stop  string // "display" or "input"
		ahead bool   // XOFF before the program starts, not at stop
	}{
		{"XOFF shown", "display", false},
		{"XOFF typed", "input", false},
		{"XOFF before the start", "display", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			p := openPTY(t)
			// Should the terminal stay stopped (the program does not
			// clear IXON), Ctrl-Q lets the killed program exit when the
			// test ends.
			t.Cleanup(func() { p.master.Write([]byte("\x11")) })
			p.setIflag(flow)
			if c.ahead {
				// The terminal stops its output: a byte written to it
				// does not arrive (it does once the program cleared IXON).
				p.send("\x13")
				time.Sleep(50 * time.Millisecond)
				go p.slave.Write([]byte("."))
				time.Sleep(100 * time.Millisecond)
				if o := p.output(); o != "" {
					t.Fatalf("output not stopped: %q", o)
				}
			}
			out, kd := p.startInit(base, w1)
			want := p.driveTo(c.stop)
			p.noFlow()
			if c.stop == "input" {
				p.quietInput()
				ws := strings.Fields(p.shown[want])
				p.typed = append(p.typed, typing{off: len(p.output()), lines: []string{strings.Join(ws[:12], " ")}})
				p.send(strings.Join(ws[:12], " ") + "\n")
				p.next(regexp.MustCompile(`\(12 von 30 Wörtern\)`))
			}
			if !c.ahead {
				p.send("\x13")
			}
			time.Sleep(100 * time.Millisecond)
			sent := time.Now()
			if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.exited:
			case <-time.After(2 * time.Second):
				t.Fatalf("no exit within 2 s after SIGINT; terminal stopped by XOFF? output tail %q", p.output()[max(0, len(p.output())-200):])
			}
			took := time.Since(sent)
			screen := p.checkAbort(false)
			if n := p.pendingInput(); n != 0 {
				t.Fatalf("%d bytes left in the input queue", n)
			}
			for _, d := range []string{out, kd} {
				if _, err := os.Lstat(d); err == nil {
					t.Fatalf("%s written", d)
				}
			}
			t.Logf("exit 130 %v after SIGINT; input modes before %#x, after %#x; %d clears; behind the last clear %q",
				took.Round(time.Millisecond), p.iflag0, p.iflag(), strings.Count(screen, clearScreen),
				screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):])
		})
	}
}

// TestPTYDoubleEnter: Enter typed twice when the holder of share 1 is
// asked whether it is noted does not call the holder of share 2 too:
// the input typed ahead is discarded before the prompt, and share 2 is
// shown only after its holder pressed Enter (task 10e finding 4).
func TestPTYDoubleEnter(t *testing.T) {
	w1 := witnessArg(t, "w1")
	base := t.TempDir()
	p := openPTY(t)
	out, _ := p.startInit(base, w1)
	p.driveTo("display")
	p.send("\n\n")
	if p.next(regexp.MustCompile(`Inhaber von Anteil 2 von 2 an den Bildschirm, dann Eingabetaste: `)) == nil {
		t.Fatalf("holder 2 not called; output %q", p.output())
	}
	time.Sleep(300 * time.Millisecond)
	if after := p.output()[p.pos:]; strings.Contains(after, "Anteil 2/2") {
		t.Fatalf("share 2 shown without its holder: %q", after)
	}
	if n := p.pendingInput(); n != 0 {
		t.Fatalf("%d bytes typed ahead left", n)
	}
	p.send("\n") // holder 2
	p.converse(nil)
	if code := p.wait(); code != 0 {
		t.Fatalf("exit code %d\n%q", code, p.output())
	}
	p.check()
	if len(p.shown) != 2 {
		t.Fatalf("%d shares shown", len(p.shown))
	}
	if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
		t.Fatal(err)
	}
}

// TestPTYProbeSignal: a signal while openTerm tries the echo of stdin
// (between switching it off and restoring it) is handled already: the
// echo is restored, the program ends with exit code 130 (task 10d
// finding 3).
func TestPTYProbeSignal(t *testing.T) {
	w1 := witnessArg(t, "w1")
	base := t.TempDir()
	p := openPTY(t)
	p.env = []string{hookEnv + "=probe-int"}
	out, kd := p.startInit(base, w1)
	if code := p.wait(); code != exitAbort {
		t.Fatalf("exit code %d\n%q", code, p.output())
	}
	p.restored()
	screen := p.output()
	if !strings.HasSuffix(screen, "gomail-ceremony: abgebrochen\r\n") || strings.Contains(screen, "Zeremonie") {
		t.Fatalf("%q", screen)
	}
	for _, d := range []string{out, kd} {
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s written", d)
		}
	}
}

// TestPTYCloseSignal: a signal handed to the signal handling while the
// command closes its term after a complete ceremony: exit code 0, the
// results after the last clear (task 10d finding 4).
func TestPTYCloseSignal(t *testing.T) {
	w1 := witnessArg(t, "w1")
	base := t.TempDir()
	p := openPTY(t)
	p.env = []string{hookEnv + "=close-int"}
	out, _ := p.startInit(base, w1)
	p.converse(nil)
	if code := p.wait(); code != 0 {
		t.Fatalf("exit code %d\n%q", code, p.output())
	}
	screen := p.check()
	tail := screen[strings.LastIndex(screen, clearScreen):]
	if !strings.Contains(tail, "Exportverzeichnis:") || strings.Contains(screen, "abgebrochen") {
		t.Fatalf("behind the last clear %q", tail)
	}
	if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
		t.Fatal(err)
	}
}

// TestEchoReadBack: a terminal that takes the request to switch the echo
// off without an error but keeps ECHO set (a TCSETS that clears ECHO
// swallowed by the stand-in ioctl) is found by reading the attributes
// back: openTerm and
// every command that shows or reads shares refuse it with errNoTerminal,
// before anything is shown, read or written (task 10d finding 2).
func TestEchoReadBack(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	p := openPTY(t)
	var mu sync.Mutex
	sets := 0
	ioctl = func(fd, req uintptr, arg unsafe.Pointer) error {
		if req == ioctlSetTermios && (*syscall.Termios)(arg).Lflag&syscall.ECHO == 0 {
			mu.Lock()
			sets++
			mu.Unlock()
			return nil
		}
		return sysIoctl(fd, req, arg)
	}
	defer func() { ioctl = sysIoctl }()
	e := newEnv(p.slave, p.slave, io.Discard)
	if err := e.checkTerminal(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.openTerm(); !errors.Is(err, errNoTerminal) || !strings.Contains(err.Error(), errEchoStays.Error()) || e.t != nil {
		t.Fatalf("openTerm: %v", err)
	}
	for _, args := range shareCommands(base, filepath.Join(out, "identity-1.pin"), w1) {
		errb := &lockedBuffer{}
		ret := make(chan int, 1)
		go func() { ret <- run(args, p.slave, p.slave, errb) }()
		select {
		case code := <-ret:
			msg := errb.String()
			if code != exitFail || !strings.Contains(msg, "nur auf einem Terminal") || !strings.Contains(msg, errEchoStays.Error()) ||
				!strings.Contains(msg, "nichts angezeigt, gelesen oder geschrieben") {
				t.Fatalf("%s: %d %q", args[0], code, msg)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: not refused, it waits for input; terminal %q", args[0], p.output())
		}
	}
	mu.Lock()
	n := sets
	mu.Unlock()
	if n == 0 {
		t.Fatal("ECHO never cleared")
	}
	p.restored()
	time.Sleep(100 * time.Millisecond)
	if screen := p.output(); screen != "" {
		t.Fatalf("on the terminal: %q", screen)
	}
	for _, d := range []string{"o2", "k2"} {
		if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
			t.Fatalf("%s written", d)
		}
	}
	t.Logf("%d swallowed TCSETS, all four commands refused", n)
}
