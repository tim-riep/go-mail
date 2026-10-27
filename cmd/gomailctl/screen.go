package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/tim-riep/go-mail/internal/words"
)

// The screen of shares and seed words (2.2 "Wiederherstellung", task 13,
// task 13b), after gomail-ceremony: the seed and the shares are shown
// only on a terminal, one holder at a time, and the screen is cleared
// (with its scroll-back buffer) before the seed is shown, after the seed
// once it is noted, after every share once its holder confirmed with
// input typed after the share appeared, at the end and on every error;
// while a share or the seed may be on the screen or words are typed,
// the software flow control of the terminal is off and the abort
// signals restore the terminal and clear the screen before the program
// ends (exit code 130). Shares and words never reach a file, a log or an
// error message: messages name positions and share numbers only.
//
// Word input (task 13b finding 2) follows standard input: from a
// terminal, the echo is off while words are typed (ECHO cleared and read
// back), standard output must be the same terminal, and that screen is
// cleared afterwards; a terminal on standard input with standard output
// redirected or on another terminal is refused before anything is read
// (checkWordInput: there is no window to clear, and refusing is simpler
// than clearing a terminal over /dev/tty). From a file or a pipe (a
// script) the words are accepted: the line discipline of a terminal
// echoes nothing there. keygen reads its three words only from a
// terminal (keygenPre). The same terminal may be named through
// /dev/tty (task 13c finding 2, sameTerminal); two descriptors of
// /dev/tty count as one terminal only when both are the controlling
// terminal of the program (task 13e point 1). The master side of a
// pseudo terminal is never a terminal of the user (task 13d finding 1,
// isTerminalFd): on standard input or output it refuses keygen, device
// lost and restore before anything is shown or read (errPtyMaster).
//
// A write error on standard output or standard error never ends the
// program (task 13c finding 1, task 13d finding 2): the prompts go to
// standard error, and a pipe there without a reader would make the
// runtime end the program with SIGPIPE at the next prompt, with the seed
// or a share on the screen, the echo or the flow control off; after the
// screen is closed, it would end a restore or a device lost that has
// written everything with exit code 141 at its last warning. main
// therefore takes SIGPIPE over for the whole run (relayBrokenPipe), to
// a channel that is never read and never stopped: the write fails with
// EPIPE, which the messages ignore, the next prompt is tried and the
// input is read as before, every path of the screen still ends through
// close or abort (screen cleared, terminal restored), and the exit code
// is that of the command. A command whose standard output is a pipe
// closed early (gomailctl list | head) runs to its end instead of dying
// with SIGPIPE. Taking SIGPIPE over only while the screen is open (task
// 13c) left the window after close open. The alternative, SIGPIPE among
// abortSignals, was not taken: once SIGPIPE is relayed to a channel, the
// runtime relays it for a broken pipe or connection on any descriptor,
// so a lost connection elsewhere in the process would abort the
// command, and a closed standard error alone would end a run whose user
// still sees the screen and can finish it or abort it with Ctrl-C.
// signal.Ignore is not used either: an ignored SIGPIPE is inherited by
// the programs a command might start, a relayed one is not.

// clearScreen clears the screen and the scroll-back buffer and moves
// the cursor home.
const clearScreen = "\033[2J\033[3J\033[H"

// errNoTerminal refuses to show the seed or shares when standard output
// is not a terminal (a file or a pipe would put them on disk).
var errNoTerminal = errors.New("Seed und Anteile erscheinen nur auf einem Terminal: die Standardausgabe ist keins (umgeleitet in eine Datei oder Pipe); es wurde nichts angezeigt")

// errNoTerminalIn refuses keygen when standard input is not a terminal
// whose echo can be switched off: the three words are typed only there.
var errNoTerminalIn = errors.New("keygen liest die Kontrollwörter nur ohne Echo von einem Terminal: die Standardeingabe ist keins (eine Datei oder Pipe); es wurde nichts angezeigt")

// errWordsNoScreen refuses word input from a terminal when standard
// output is not that terminal: the screen with the input could not be
// cleared.
var errWordsNoScreen = errors.New("Wörter von einem Terminal nur, wenn die Standardausgabe dasselbe Terminal ist (nicht umgeleitet); es wurde nichts gelesen")

// errPtyMaster refuses keygen, device lost and restore when standard
// input or standard output is the master side of a pseudo terminal
// (task 13d finding 1): written there, the seed would become the input
// of the program on the other side, and read from there, the words
// would be the output of that program.
var errPtyMaster = errors.New("Standardeingabe oder Standardausgabe ist die Gegenseite (Master) eines Pseudoterminals, kein Terminal des Benutzers; es wurde nichts angezeigt oder gelesen")

// errNoEchoControl refuses word input from a terminal whose echo cannot
// be switched off.
var errNoEchoControl = errors.New("das Echo der Standardeingabe lässt sich nicht abschalten; es wurde nichts gelesen")

// errNoInput reports the end of the input.
var errNoInput = errors.New("keine Eingabe")

// errLongLine reports an input line longer than the read buffer.
var errLongLine = errors.New("Zeile zu lang")

// maxWordLines bounds the lines that readWords reads for one seed or
// share (task 13c finding 3): 30 words, one per line, with room for
// empty lines, but not an endless run of them.
const maxWordLines = 64

// errManyLines reports more than maxWordLines lines for one seed or
// share.
var errManyLines = errors.New("zu viele Zeilen")

// terminalStandIn is implemented only by the stand-in terminals of the
// tests of this package; the command itself passes *os.File.
type terminalStandIn interface{ terminal() bool }

// echoStandIn is a stand-in terminal for standard input whose echo the
// command switches and whose input it discards; ttyID names the
// terminal (sameTerminal). Only the tests of this package implement it.
type echoStandIn interface {
	terminalStandIn
	disableEcho() (func() error, error)
	flushInput() error
	ttyID() uint64
}

// isTerminal reports whether v is a terminal: an *os.File whose terminal
// attributes can be read.
func isTerminal(v any) bool {
	switch f := v.(type) {
	case *os.File:
		return isTerminalFd(f.Fd())
	case terminalStandIn:
		return f.terminal()
	}
	return false
}

// ptyMasterOf reports whether v is the master side of a pseudo terminal
// (isPtyMaster); stand-ins never are.
func ptyMasterOf(v any) bool {
	f, ok := v.(*os.File)
	return ok && isPtyMaster(f.Fd())
}

// terminalOf returns the identity of the terminal v (terminalID; a
// stand-in names its own, 0 by default).
func terminalOf(v any) (uint64, bool) {
	switch f := v.(type) {
	case *os.File:
		return terminalID(f.Fd())
	case interface {
		terminalStandIn
		ttyID() uint64
	}:
		return f.ttyID(), f.terminal()
	case terminalStandIn:
		return 0, f.terminal()
	}
	return 0, false
}

// sameTerminal reports whether a and b are the same terminal: the same
// device other than /dev/tty, or, for two files, both the controlling
// terminal of the program (task 13c finding 2: /dev/tty is a device of
// its own, 5:0 on Linux, and names the controlling terminal;
// sameControlling). Two descriptors of /dev/tty have the same device
// even when they were opened in different sessions and name different
// terminals (task 13e point 1): they pass only through sameControlling.
func sameTerminal(a, b any) bool {
	x, ok1 := terminalOf(a)
	y, ok2 := terminalOf(b)
	if !ok1 || !ok2 {
		return false
	}
	if x == y && !isDevTTY(x) {
		return true
	}
	fa, ok1 := a.(*os.File)
	fb, ok2 := b.(*os.File)
	return ok1 && ok2 && sameControlling(fa.Fd(), fb.Fd())
}

// control are the switches of the terminal on standard input.
type control struct {
	echo  func() (func() error, error) // ECHO (disableEcho)
	flush func() error                 // discards the input not read yet (flushInput)
}

// echoControl returns the switches of standard input v, or nil if v is
// not a terminal.
func echoControl(v any) *control {
	switch f := v.(type) {
	case *os.File:
		fd := f.Fd()
		if !isTerminalFd(fd) {
			return nil
		}
		return &control{
			echo:  func() (func() error, error) { return disableEcho(fd) },
			flush: func() error { return flushInput(fd) },
		}
	case echoStandIn:
		if !f.terminal() {
			return nil
		}
		return &control{echo: f.disableEcho, flush: f.flushInput}
	}
	return nil
}

// checkWordInput is the first step of device lost and restore (task 13b
// finding 2), before the passphrase or any word is read: the master side
// of a pseudo terminal on standard input or output is refused
// (errPtyMaster, task 13d finding 1); from a terminal on standard input,
// standard output must be the same terminal and the echo must be
// switchable. A file or a pipe on standard input passes.
func (e *env) checkWordInput() error {
	if ptyMasterOf(e.in) || ptyMasterOf(e.stdout) {
		return errPtyMaster
	}
	if !isTerminal(e.in) {
		return nil
	}
	if echoControl(e.in) == nil {
		return errNoEchoControl
	}
	if !isTerminal(e.stdout) || !sameTerminal(e.in, e.stdout) {
		return errWordsNoScreen
	}
	return nil
}

// exit ends the program on the abort path; tests replace it.
var exit = os.Exit

// screen is standard output while a share or seed words may be on it,
// with the echo switch of standard input (ctl, nil if standard input is
// no terminal).
type screen struct {
	e           *env
	ctl         *control
	mu          sync.Mutex   // held while writing; the abort path never releases it
	flowRestore func() error // set while the flow control is off
	echoRestore func() error // set while the echo is off
	sig         chan os.Signal
	done        chan struct{}
	closed      bool
}

// openScreen starts the screen handling: standard output must be a
// terminal (errNoTerminal); the abort signals are handled first, then
// the flow control of standard output is switched off. SIGPIPE is taken
// over by main for the whole run (relayBrokenPipe).
func (e *env) openScreen() (*screen, error) {
	if !isTerminal(e.stdout) {
		return nil, errNoTerminal
	}
	s := &screen{e: e, ctl: echoControl(e.in), sig: make(chan os.Signal, 1), done: make(chan struct{})}
	if isTerminal(e.in) && s.ctl == nil {
		return nil, errNoEchoControl
	}
	signal.Notify(s.sig, abortSignals...)
	go s.watch()
	var err error
	if f, ok := e.stdout.(*os.File); ok {
		s.mu.Lock()
		s.flowRestore, err = disableFlow(f.Fd())
		s.mu.Unlock()
		if err != nil {
			err = fmt.Errorf("die Flusssteuerung des Terminals lässt sich nicht abschalten: %w", err)
		}
	}
	if err == nil && s.ctl != nil {
		// The echo is switched off once and restored at once, before
		// anything is shown: a terminal whose echo stays on is refused
		// here, not after the seed appeared.
		if err = s.echoOff(); err == nil {
			s.echoOn()
		}
	}
	if err != nil {
		// Nothing was shown: the terminal is restored and the signal
		// handling ends without a clear of the screen.
		s.mu.Lock()
		if s.flowRestore != nil {
			s.flowRestore()
			s.flowRestore = nil
		}
		s.closed = true
		signal.Stop(s.sig)
		close(s.done)
		s.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// wordScreen is openScreen when standard output is a terminal and nil
// otherwise (checkWordInput made sure that standard input is then no
// terminal); the methods of screen accept nil.
func (e *env) wordScreen() (*screen, error) {
	if err := e.checkWordInput(); err != nil {
		return nil, err
	}
	if !isTerminal(e.stdout) {
		return nil, nil
	}
	return e.openScreen()
}

func (s *screen) watch() {
	select {
	case <-s.sig:
		s.abort()
	case <-s.done:
	}
}

// abort restores the echo, clears the screen, restores the flow control
// and ends the program with exit code 130. It takes the lock and never
// releases it, so that nothing is written to the screen after the clear.
// A closed standard error does not end the program before its exit code
// (relayBrokenPipe).
// A signal that arrives while close runs is ignored: the screen is
// cleared and restored already (as in gomail-ceremony).
func (s *screen) abort() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if s.echoRestore != nil {
		s.echoRestore()
		s.echoRestore = nil
	}
	fmt.Fprint(s.e.stdout, clearScreen)
	if s.flowRestore != nil {
		s.flowRestore()
		s.flowRestore = nil
	}
	fmt.Fprintln(s.e.stderr, "gomailctl: abgebrochen, der Bildschirm wurde gelöscht")
	exit(130)
}

// show writes text to the screen.
func (s *screen) show(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprint(s.e.stdout, text)
}

// wipe clears the screen.
func (s *screen) wipe() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprint(s.e.stdout, clearScreen)
}

// echoOff switches the echo of standard input off until echoOn; without
// a terminal on standard input it fails closed (errNoEchoControl).
func (s *screen) echoOff() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.echoRestore != nil {
		return nil
	}
	if s.ctl == nil {
		return errNoEchoControl
	}
	restore, err := s.ctl.echo()
	if err != nil {
		return fmt.Errorf("das Echo des Terminals lässt sich nicht abschalten: %w", err)
	}
	s.echoRestore = restore
	return nil
}

// echoOn restores the echo switched off by echoOff; the input typed and
// not read yet is discarded with it.
func (s *screen) echoOn() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.echoRestore != nil {
		s.echoRestore()
		s.echoRestore = nil
	}
}

// close restores the echo, clears the screen, restores the flow control
// and stops the handling of the abort signals; SIGPIPE stays taken over
// (relayBrokenPipe).
func (s *screen) close() {
	if s == nil {
		return
	}
	s.echoOn()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	fmt.Fprint(s.e.stdout, clearScreen)
	if s.flowRestore != nil {
		s.flowRestore()
		s.flowRestore = nil
	}
	signal.Stop(s.sig)
	close(s.done)
}

// relayBrokenPipe takes SIGPIPE over for the rest of the program (task
// 13d finding 2; see the comment at the top of this file): it is relayed
// to a channel that is never read and never stopped, so that a write to
// a pipe without a reader fails with EPIPE on every descriptor, standard
// output and standard error included, instead of ending the program.
// The signal package drops a signal for a full channel; nothing blocks.
// main calls it first.
func relayBrokenPipe() {
	if len(brokenPipe) > 0 {
		// Notify without signals would relay every signal.
		signal.Notify(make(chan os.Signal, 1), brokenPipe...)
	}
}

// readSecret reads one line of at most the size of the read buffer of
// stdin (4096 bytes) without the line terminator. The line points into
// the read buffer; the caller overwrites it. A longer line is refused
// (errLongLine) as soon as the buffer is full, with the buffer
// overwritten; the rest of it is not read (every caller ends then), so
// an endless input without a line end costs neither memory nor time
// (task 13b finding 5).
func (e *env) readSecret() ([]byte, error) {
	line, err := e.stdin.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		clear(line)
		return nil, errLongLine
	}
	if err != nil && len(line) == 0 {
		return nil, errNoInput
	}
	n := len(line)
	for n > 0 && (line[n-1] == '\n' || line[n-1] == '\r') {
		n--
	}
	return line[:n], nil
}

// confirm reads a line that holds no secret (a confirmation with Enter).
func (e *env) confirm() error {
	line, err := e.readSecret()
	clear(line)
	return err
}

// flushTyped discards input typed ahead when standard input is a
// terminal, on the terminal and in the read buffer: an Enter typed twice
// does not answer the next prompt too, and an Enter typed before a share
// appeared does not confirm it. Input from a pipe is kept.
func (e *env) flushTyped() error {
	ctl := echoControl(e.in)
	if ctl == nil {
		return nil
	}
	if err := ctl.flush(); err != nil {
		return fmt.Errorf("die Eingabe des Terminals lässt sich nicht verwerfen: %w", err)
	}
	b, _ := e.stdin.Peek(e.stdin.Buffered())
	clear(b)
	_, err := e.stdin.Discard(len(b))
	return err
}

// countFields counts the words of b as strings.Fields would split them,
// stopping after limit+1, without allocating.
func countFields(b []byte, limit int) int {
	n, in := 0, false
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if unicode.IsSpace(r) {
			in = false
			continue
		}
		if !in {
			in = true
			if n++; n > limit {
				break
			}
		}
	}
	return n
}

// readWords reads want words (a seed 24, a share 30) typed on one or
// more lines, normalized with words.Normalize (2.2 "Eingabe von
// Wörtern", S11) and checked against the word list (words.Check). More
// words than wanted are refused before they are normalized. Errors name
// positions and counts, never words; every line is overwritten in the
// read buffer once it is converted. At most maxWordLines lines are read
// (errManyLines; task 13c finding 3), so that an endless run of empty
// lines ends. From a terminal (s with the echo switch of standard input)
// the echo is off for all lines and the screen is cleared afterwards,
// also on errors.
func (e *env) readWords(s *screen, what string, want int) ([]string, error) {
	hidden := s != nil && s.ctl != nil
	if hidden {
		defer s.wipe()
		if err := s.echoOff(); err != nil {
			return nil, err
		}
		defer s.echoOn()
		fmt.Fprintf(e.stderr, "%s eingeben (%d Wörter, auch über mehrere Zeilen, ohne Anzeige):\n", what, want)
	} else {
		fmt.Fprintf(e.stderr, "%s eingeben (%d Wörter, auch über mehrere Zeilen):\n", what, want)
	}
	var ws []string
	for lines := 0; len(ws) < want; lines++ {
		if lines == maxWordLines {
			return nil, fmt.Errorf("%s: %w (höchstens %d) nach %d von %d Wörtern", what, errManyLines, maxWordLines, len(ws), want)
		}
		line, err := e.readSecret()
		if err != nil {
			return nil, fmt.Errorf("%s: %w nach %d von %d Wörtern", what, err, len(ws), want)
		}
		if countFields(line, want) > want-len(ws) {
			clear(line)
			return nil, fmt.Errorf("%s: mehr als %d Wörter", what, want)
		}
		lw, err := words.Normalize(string(line))
		clear(line)
		if err != nil {
			// A line of the read buffer is below words.MaxInput, but
			// NFKD can split one typed word into many (a compatibility
			// character becomes a space and a combining mark): more
			// than words.MaxTokens are refused (words.ErrTooLong, task
			// 15b point 5).
			return nil, fmt.Errorf("%s: %w nach %d von %d Wörtern", what, err, len(ws), want)
		}
		ws = append(ws, lw...)
		if len(ws) < want {
			fmt.Fprintf(e.stderr, "(%d von %d Wörtern)\n", len(ws), want)
		}
	}
	if len(ws) != want {
		return nil, fmt.Errorf("%s: %d statt %d Wörter nach der Normalisierung", what, len(ws), want)
	}
	if err := words.Check(ws); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return ws, nil
}
