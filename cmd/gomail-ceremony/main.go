// Command gomail-ceremony is the offline tool for the platform root
// (2.3, 9.2):
//
//	gomail-ceremony init --shares 3-of-5 --out <export> --keys <keydir> --origin <origin>
//	                     --witness <name>=<vkey> [--witness ...] --min-witnesses <k>
//	gomail-ceremony ingest-rotate --pin <pin> --gen <n> --out <export> --keys <keydir> --valid-from <RFC3339>
//	gomail-ceremony reshare --pin <pin> --shares <k-of-n>
//	gomail-ceremony succeed --pin <pin> --out <export> [--origin <origin>]
//	                        [--witness <name>=<vkey> ...] [--min-witnesses <k>]
//	gomail-ceremony publish --from <export> --data <datadir> --pin <pin> [--replace-witnesses]
//	gomail-ceremony init --dev --data <datadir> --keys <keydir>   (test build only)
//
// The real ceremony runs on a computer without network (package
// ceremony, api.go). Shares are written to standard output only, one line
// per share with its index and 30 words, one holder at a time, and never
// into a file. Shares are typed on standard input with the echo off.
//
// Terminal rule (task 10c finding 1): every command that shows or reads
// shares (init, reshare, ingest-rotate, succeed) requires, before its
// first prompt, that standard output is a terminal and that standard
// input is a terminal whose attributes can be read and whose echo can
// be switched off (ECHO cleared and read back). Otherwise it refuses
// with a message, before anything is shown, read or written; there is
// no flag around it. Standard input from a file or a pipe is refused
// (a share must never be on disk), and so is every system where this
// program cannot switch the echo with syscall (tty_other.go: all four
// commands refuse there).
//
// The input is normalized (2.2 "Eingabe von Wörtern", package words)
// and checked before the ceremony uses it, and a share is asked again
// up to three times. Messages name word positions, never words. The
// screen is cleared after every share typed, after every share shown
// once its holder confirmed, at the end of every command and on every
// error (type term), on standard error as well when that is another
// terminal (task 15b point 6). From the first prompt to the end of the
// command the terminal has no software flow control (IXON, IXOFF, IXANY
// cleared), and neither has standard output when it is another terminal
// (task 15b point 0b): Ctrl-S cannot stop the output, so that no share
// stays on the screen with the program stuck (task 10e finding 1); a
// write to the screen that blocks all the same holds up neither the
// signal handling nor the end of the program (abortWait). Input typed
// ahead is discarded before every holder is called. SIGINT, SIGTERM,
// SIGHUP, SIGQUIT and SIGTSTP restore the terminal, clear the screen and
// end the program with exit code 130; while the files are written they
// are deferred: a signal before the commit point (the rename of the
// export) rolls the files back and then ends the program with exit
// code 130, a signal after it is ignored, and the ceremony reports its
// results, that a signal was ignored, and exit code 0 (task 10e
// finding 2). Once a command has ended its screen handling (close), the
// signals stay taken in and are discarded until the program exits: a
// complete ceremony always reports its results with exit code 0 (task
// 15b point 0a). A ceremony is never suspended: SIGTSTP
// (Ctrl-Z) ends it like Ctrl-C (task 10d finding 1d). While a share is
// typed, the terminal raises no signals (ISIG cleared with ECHO), and
// Ctrl-C, Ctrl-\ or Ctrl-Z in the input end the program the same way
// once the line is sent (Enter). SIGSTOP and SIGKILL cannot be caught:
// a ceremony stopped with SIGSTOP keeps the echo off until it continues,
// one killed with SIGKILL leaves it off (reset the terminal with
// "stty sane"). SIGABRT, SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV and
// SIGSYS sent with kill take the same way, so that no stack trace of the
// runtime appears on the screen (abortSignals).
//
// The pin (identity-<gen>.pin) carries the origin of the log, the
// witnesses with their quorum and the identity list 1..gen (fields 4 to
// 6 and 8). init takes them from its flags; succeed takes them from the
// pin given with --pin: --origin may be given only as a check (it never
// changes), --witness and --min-witnesses change witnesses and quorum
// on purpose. succeed --compromised is locked (task 15f point 1, Q19): a
// usage error with exit code 2 before anything is shown, read or
// written, until the revocation of a platform generation is specified
// (ceremony.ErrCompromised). init shows the clock of the computer before
// the first prompt, and succeed when it signs a succession: it gives
// valid_from of what they sign (RUNBOOK).
//
// Targets: Linux, macOS and the BSDs control the terminal (tty_unix.go);
// on the other systems the program builds, but the four commands refuse
// (tty_other.go). plan9 and js/wasm are not supported and the program
// does not build there: package ceremony needs syscall.Rename, which
// plan9 lacks, and this command syscall.SIGHUP, which js/wasm lacks
// (task 10e finding 6).
//
// publish runs online on the server machine while the server is
// stopped (it holds the server lock locks/server) and copies an export
// into the data directory and the operator log (ceremony.Publish); the
// server is then started with the pin given to publish. A
// platform/witnesses.rec of the data directory that differs from the
// pin is refused; --replace-witnesses replaces it by the pin's (task 15f
// point 2) and names the old and the new quorum and witnesses. The pin
// file is not signed: with --replace-witnesses the witnesses the server
// trusts rest on its authenticity alone, the operator's trust anchor as
// for the start of gomail-server (task 15g point 4).
//
// init --dev is the development ceremony for tests (root without Shamir
// in an insecure file); it exists only in a build with the tag
// gomail_dev (dev_dev.go), the production program refuses --dev as an
// unknown flag.
//
// Additions to 9.2 (proposed by task 03, flags by task 10): the commands
// succeed and publish, and the flags --out, --keys, --origin, --witness,
// --min-witnesses, --pin, --gen, --valid-from, --compromised (locked),
// --from, --data and --replace-witnesses of the real ceremony.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
	"github.com/tim-riep/go-mail/internal/words"
)

func main() {
	// Task 10d finding 1c: no stack trace on the terminal. The runtime
	// does not let SetTraceback go below the level of GOTRACEBACK (by
	// default "single"), and it prints the full trace of a fatal signal
	// whatever the level; so this call alone keeps no trace off the
	// screen. What does: while a term is open, every signal after which
	// the runtime would print one is handled (abortSignals, tty_unix.go).
	debug.SetTraceback("none")
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// now is the clock of every ceremony (00-vorgaben: time only through
// an injectable interface); tests replace it.
var now = time.Now

const usage = `Aufruf:
  gomail-ceremony init --shares 3-of-5 --out <export> --keys <schlüssel> --origin <origin>
                       --witness <name>=<verifier-zeile> [--witness ...] --min-witnesses <k>
  gomail-ceremony ingest-rotate --pin <pin> --gen <n> --out <export> --keys <schlüssel>
                       --valid-from <RFC3339>
  gomail-ceremony reshare --pin <pin> --shares <k-of-n>
  gomail-ceremony succeed --pin <pin> --out <export> [--origin <origin>]
                       [--witness <name>=<verifier-zeile> ...] [--min-witnesses <k>]
  gomail-ceremony publish --from <export> --data <datenverzeichnis> --pin <pin>
                       [--replace-witnesses]

init, ingest-rotate, reshare und succeed laufen auf einem Rechner ohne Netzwerk.
Die Anteile erscheinen nur auf diesem Bildschirm, nie in einer Datei:
Standardeingabe und Standardausgabe müssen ein Terminal sein, dessen Echo sich
abschalten lässt (keine Umleitung, keine Pipe). --valid-from liegt nicht in der
Vergangenheit. succeed übernimmt Origin, Zeugen und Quorum aus dem Pin;
--witness und --min-witnesses ändern sie ausdrücklich. publish läuft auf dem
Server, solange er angehalten ist, und trägt ein Exportverzeichnis in
Datenverzeichnis und Log ein; danach startet der Server mit diesem Pin.
--replace-witnesses ersetzt platform/witnesses.rec durch Zeugen und Quorum des
Pins (nach succeed --witness/--min-witnesses). Die Pin-Datei ist nicht
signiert: mit --replace-witnesses hängen die Zeugen, denen der Server traut,
allein an ihrer Echtheit (Vertrauensanker des Betreibers, wie beim Serverstart).
--pin ist der Pin der aktuellen Identität (identity-<gen>.pin), bei publish
nach einer Nachfolge der neue.
succeed --compromised ist noch nicht verfügbar (Q19).
`

// exitUsage and exitFail are the exit codes for wrong arguments and a
// failed ceremony.
const (
	exitUsage = 2
	exitFail  = 1
)

// exitAbort is the exit code of a ceremony ended by a signal or by an
// abort key typed into a share (128 + SIGINT, as a shell reports Ctrl-C).
const exitAbort = 130

type env struct {
	in             io.Reader // stdin as passed, for the terminal check
	src            io.Reader // stdin as read: in behind abortReader
	stdin          *bufio.Reader
	stdout, stderr io.Writer
	t              *term // set by the commands that show or read shares
}

func newEnv(stdin io.Reader, stdout, stderr io.Writer) *env {
	src := abortReader{stdin}
	return &env{in: stdin, src: src, stdin: bufio.NewReaderSize(src, maxLine), stdout: stdout, stderr: stderr}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := newEnv(stdin, stdout, stderr)
	if len(args) == 0 {
		fmt.Fprint(stderr, usage+devUsage)
		return exitUsage
	}
	switch args[0] {
	case "init":
		return e.init(args[1:])
	case "ingest-rotate":
		return e.rotate(args[1:])
	case "reshare":
		return e.reshare(args[1:])
	case "succeed":
		return e.succeed(args[1:])
	case "publish":
		return e.publish(args[1:])
	}
	fmt.Fprint(stderr, usage+devUsage)
	return exitUsage
}

// fail reports err; in a command that shows or reads shares it clears
// the screen and restores the terminal first. An abort key typed into a
// share (errAborted) ends the program as a signal does, with exitAbort.
func (e *env) fail(err error) int {
	if e.t != nil {
		e.t.wipe()
		e.t.close()
	}
	if errors.Is(err, errAborted) {
		fmt.Fprintln(e.stderr, "gomail-ceremony:", errAborted)
		fmt.Fprintln(e.stderr, "gomail-ceremony: abgebrochen")
		return exitAbort
	}
	fmt.Fprintln(e.stderr, "gomail-ceremony:", err)
	return exitFail
}

func (e *env) usage(msg string) int {
	if msg != "" {
		fmt.Fprintln(e.stderr, "gomail-ceremony:", msg)
	}
	fmt.Fprint(e.stderr, usage+devUsage)
	return exitUsage
}

func (e *env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) bool {
	return fs.Parse(args) == nil && fs.NArg() == 0
}

// ----------------------------------------------------------- witnesses

// maxVerifierKey bounds a --witness value before it is decoded.
const maxVerifierKey = 256

// witnessFlag collects --witness <name>=<verifier key line>.
type witnessFlag []witness.Key

func (w *witnessFlag) String() string { return "" }

func (w *witnessFlag) Set(s string) error {
	k, err := parseWitness(s)
	if err != nil {
		return err
	}
	*w = append(*w, k)
	return nil
}

// parseWitness parses "<name>=<name>+<hash>+<base64>": the name and the
// note verifier key line printed by "gomail-witness keygen". The name
// must be the one in the key line, the key an Ed25519 key, and the hash
// the one note derives from name and key.
func parseWitness(s string) (witness.Key, error) {
	if len(s) > maxVerifierKey {
		return witness.Key{}, errors.New("Zeuge: Angabe zu lang")
	}
	name, vkey, ok := strings.Cut(s, "=")
	if !ok {
		return witness.Key{}, errors.New("Zeuge: erwartet <name>=<verifier-zeile>")
	}
	if err := witness.CheckName(name); err != nil {
		return witness.Key{}, err
	}
	parts := strings.SplitN(vkey, "+", 3) // base64 may contain "+"
	if len(parts) != 3 || parts[0] != name {
		return witness.Key{}, errors.New("Zeuge: die Verifier-Zeile gehört nicht zu diesem Namen")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize || raw[0] != 1 {
		return witness.Key{}, errors.New("Zeuge: kein Ed25519-Schlüssel")
	}
	pub := ed25519.PublicKey(bytes.Clone(raw[1:]))
	if want, err := note.NewEd25519VerifierKey(name, pub); err != nil || want != vkey {
		return witness.Key{}, errors.New("Zeuge: Prüfsumme der Verifier-Zeile stimmt nicht")
	}
	return witness.Key{Name: name, Pub: pub}, nil
}

// --------------------------------------------------------------- terminal

// maxLine bounds one line of input (a share is 30 words of at most 8
// letters; typed with generous white space it stays far below). It is
// also the size of the read buffer of stdin.
const maxLine = 4096

// maxAttempts is how often a share is asked before the ceremony stops.
const maxAttempts = 3

var errNoInput = errors.New("keine Eingabe")

// errAborted reports an abort key in the input (abortReader).
var errAborted = errors.New("Abbruchtaste (Strg-C, Strg-\\ oder Strg-Z) in der Eingabe")

// abortBytes are the characters with which a terminal in its default
// settings raises SIGINT (VINTR, Ctrl-C), SIGQUIT (VQUIT, Ctrl-\) and
// SIGTSTP (VSUSP, Ctrl-Z). While a share is typed ISIG is cleared and
// the terminal passes them on as input (task 10d finding 1a); they end
// the program as the signals would. Other control characters are input
// like any other and fail the word check.
const abortBytes = "\x03\x1c\x1a"

// abortReader is stdin as the command reads it: a chunk that holds one
// of abortBytes is overwritten and reported as errAborted instead.
type abortReader struct{ r io.Reader }

func (a abortReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if bytes.ContainsAny(p[:n], abortBytes) {
		clear(p[:n])
		return 0, errAborted
	}
	return n, err
}

// readSlice reads one line of at most maxLine bytes; a longer line is
// discarded (and its bytes in the read buffer overwritten) and refused.
// The line returned points into the read buffer and is valid until the
// next read; the caller may overwrite it. An abort key in the input is
// errAborted, with the line read so far overwritten.
func (e *env) readSlice() ([]byte, error) {
	line, err := e.stdin.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			clear(line)
			line, err = e.stdin.ReadSlice('\n')
		}
		clear(line)
		if errors.Is(err, errAborted) {
			return nil, errAborted
		}
		return nil, errors.New("Zeile zu lang")
	}
	if errors.Is(err, errAborted) {
		clear(line)
		return nil, errAborted
	}
	if err != nil && len(line) == 0 {
		return nil, errNoInput
	}
	return line, nil
}

// readLine reads one line that holds no secret (a confirmation).
func (e *env) readLine() (string, error) {
	line, err := e.readSlice()
	return string(line), err
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// scrubInput overwrites the whole read buffer of stdin with zeros
// (task 10c finding 6): the reader is reset onto zeros, the buffer is
// filled completely from it, and the reader is reset onto stdin again.
// Input typed ahead and not read yet is dropped with it. The line
// bytes are overwritten by readWords already; what Go does not let us
// overwrite are the strings made from them (the line converted for
// words.Normalize, the words, and the copies the ceremony makes):
// strings are immutable and stay in memory until the garbage collector
// reuses it.
func (e *env) scrubInput() {
	e.stdin.Reset(zeros{})
	e.stdin.Peek(maxLine)
	e.stdin.Reset(e.src)
}

// clearScreen clears the screen and the scroll-back buffer and moves
// the cursor home.
const clearScreen = "\033[2J\033[3J\033[H"

// errNoTerminal refuses a command that shows or reads shares when
// standard input or standard output is not a terminal, or when the echo
// of standard input cannot be switched off (task 10b finding 1c, task
// 10c finding 1); there is no way around it.
var errNoTerminal = errors.New("Anteile erscheinen und werden eingegeben nur auf einem Terminal")

// noTerminalEnd ends every refusal with errNoTerminal.
const noTerminalEnd = "; Abbruch, es wurde nichts angezeigt, gelesen oder geschrieben"

// terminalStandIn is implemented only by the stand-in terminals of the
// tests of this package; the command itself passes *os.File.
type terminalStandIn interface{ terminal() bool }

// echoStandIn is a stand-in terminal for stdin whose echo and flow
// control the command switches and whose input it discards; only the
// tests of this package implement it.
type echoStandIn interface {
	terminalStandIn
	disableEcho() (func() error, error)
	disableFlow() (func() error, error)
	flushInput() error
}

// isTerminal reports whether v is a terminal: an *os.File whose terminal
// attributes can be read (ioctl TCGETS, TIOCGETA on BSD).
func isTerminal(v any) bool {
	switch f := v.(type) {
	case *os.File:
		return isTerminalFd(f.Fd())
	case terminalStandIn:
		return f.terminal()
	}
	return false
}

// echoSwitch switches modes of a terminal off (the echo, the flow
// control) and returns the function that restores them.
type echoSwitch func() (restore func() error, err error)

// control are the switches of the terminal stdin, and the flow control
// of stdout when that is another terminal.
type control struct {
	echo  echoSwitch   // ECHO, ISIG, IEXTEN (disableEcho)
	flow  echoSwitch   // IXON, IXOFF, IXANY (disableFlow)
	flush func() error // discards the input not read yet (flushInput)
	// outFlow clears IXON, IXOFF and IXANY of stdout (disableFlowOut)
	// when stdout is a terminal other than stdin (task 15b point 0b);
	// nil when it is the same terminal (flow covers it) or a stand-in.
	outFlow echoSwitch
}

// echoControl returns the switches of stdin v, or nil if v is not a
// terminal.
func echoControl(v any) *control {
	switch f := v.(type) {
	case *os.File:
		fd := f.Fd()
		if !isTerminalFd(fd) {
			return nil
		}
		return &control{
			echo:  func() (func() error, error) { return disableEcho(fd) },
			flow:  func() (func() error, error) { return disableFlow(fd) },
			flush: func() error { return flushInput(fd) },
		}
	case echoStandIn:
		if !f.terminal() {
			return nil
		}
		return &control{echo: f.disableEcho, flow: f.disableFlow, flush: f.flushInput}
	}
	return nil
}

// outFlowControl returns the switch of the flow control of stdout out
// when out is a terminal other than stdin in (task 15b point 0b): an
// XOFF typed on that terminal would stop every write to the screen, the
// clear of a share and the abort path included. On the same terminal
// (the same device, sameTerminal) the switch of stdin covers it, and a
// stand-in terminal of the tests has none.
func outFlowControl(in, out any) echoSwitch {
	o, ok := out.(*os.File)
	if !ok {
		return nil
	}
	fd := o.Fd()
	if !isTerminalFd(fd) {
		return nil
	}
	if i, ok := in.(*os.File); ok && sameTerminal(i.Fd(), fd) {
		return nil
	}
	return func() (func() error, error) { return disableFlowOut(fd) }
}

// checkTerminal is the first step of every command that shows or reads
// shares (init, reshare, ingest-rotate, succeed; task 10c finding 1):
// standard output must be a terminal, and standard input a terminal
// whose attributes can be read. Otherwise errNoTerminal, before
// anything is shown, read or written. A file or a pipe on standard
// input is refused as well: a share must never be on disk. Whether the
// echo can be switched off is tried by openTerm, once the signals are
// handled.
func (e *env) checkTerminal() error {
	if !isTerminal(e.stdout) {
		return fmt.Errorf("%w: die Standardausgabe ist keins (umgeleitet in eine Datei oder Pipe)%s", errNoTerminal, noTerminalEnd)
	}
	if echoControl(e.in) == nil {
		return fmt.Errorf("%w: die Standardeingabe ist keins (eine Datei oder Pipe; Anteile dürfen nie auf der Platte liegen)%s",
			errNoTerminal, noTerminalEnd)
	}
	return nil
}

// openTerm starts the screen handling of a command that shows or reads
// shares, after checkTerminal and before the first prompt: first the
// signals are handled (newTerm), then the flow control of stdin is
// switched off until close (flowFlags cleared and read back, task 10e
// finding 1), and that of stdout when it is another terminal (task 15b
// point 0b), then the echo is switched off (quietFlags cleared and read
// back) and restored at once, so that a signal in between restores it
// too (task 10d finding 3). If that fails, the signal handling ends
// again, the flow control is restored, and the command is refused with
// errNoTerminal, before anything is shown, read or written (the screen
// is not cleared either).
func (e *env) openTerm() (*term, error) {
	t := e.newTerm()
	t.mu.Lock()
	var err error
	if t.ctl == nil {
		err = errNoTerminal
	} else if t.flowRestore, err = t.ctl.flow(); err == nil {
		if t.ctl.outFlow != nil {
			if t.outFlowRestore, err = t.ctl.outFlow(); err != nil {
				err = fmt.Errorf("Flusssteuerung der Standardausgabe: %w", err)
			}
		}
		if err == nil {
			t.restore, err = t.ctl.echo()
		}
	}
	t.mu.Unlock()
	if err == nil {
		if probeHook != nil {
			probeHook(t)
		}
		t.mu.Lock()
		err = t.restore()
		t.restore = nil
		t.mu.Unlock()
	}
	if err != nil {
		t.close()
		e.t = nil
		return nil, fmt.Errorf("%w: Echo oder Flusssteuerung der Standardeingabe lassen sich nicht abschalten (%v)%s", errNoTerminal, err, noTerminalEnd)
	}
	return t, nil
}

// exit ends the program after a signal; tests replace it.
var exit = os.Exit

// commitHook is called by BeginCommit once signals are deferred (at
// "begin"), by CommitPoint before it looks for a signal (at "point":
// before the rename) and by EndCommit before it takes t.mu (at "end":
// after the rename if committed); probeHook by openTerm while the echo
// is off, and closeHook by close once the term is closed and before the
// signal handling stops; only tests set them.
var (
	commitHook func(t *term, at string, committed bool)
	probeHook  func(*term)
	closeHook  func(*term)
)

// term is the Prompter of the command line: shares on stdout, prompts
// on stderr, input on stdin.
//
// The screen (task 10b finding 1, task 10c, task 10d, task 10e, task
// 15b point 0): checkTerminal and openTerm made sure that stdin and
// stdout are terminals. From openTerm to close the terminal has no
// software flow control (IXON, IXOFF and IXANY cleared, restored by
// close and, after the clear, by the abort path), so that no Ctrl-S
// stops the output and with it the clear of a share on the screen;
// when stdout is another terminal than stdin, its flow control is
// cleared and restored as well (task 15b point 0b). Unread input is
// discarded before every holder is called (Handover), so that an Enter
// typed ahead does not call the next holder. While a
// share is typed, the terminal does not echo it and raises no signals
// (ECHO, ISIG and IEXTEN cleared, restored afterwards, on errors and on
// the abortSignals; an abort key in the input is errAborted). The
// screen is cleared after every share typed, accepted or refused, after
// every share shown once its holder confirmed, at the end of the
// command and on every error path, whatever was shown; results are
// written after the last clear.
//
// Writes of the term to the screen (stdout), the share lines and the
// clears, hold t.out, never t.mu (task 15b point 0b: a write that
// blocks, because the terminal takes no output, must not block the
// signal handling, which takes t.mu). The abort path marks the term
// dead first, so that no share line is written after it, then takes
// t.out and never releases it, clears the screen and exits; a write
// that blocks keeps it waiting at most abortWait per step, and the
// program ends all the same (a write still blocked then is never
// completed). So no share appears after the clear of the abort path
// (task 10c finding 4). While the ceremony writes its files (commit) a
// signal only sets a flag (task 10c finding 3). A signal that arrived
// before the commit point (CommitPoint, just before the rename of the
// export) rolls the files back and ends the program with exit code 130
// once they are; a signal after the commit point is ignored: the
// ceremony is complete, it reports its results and that a signal was
// ignored, with exit code 0 (task 10e finding 2). From close on every
// abortSignal is taken in and discarded until the program exits (the
// notification stays, see close: with the default disposition back, a
// SIGINT between close and the exit would kill a ceremony that is
// complete, and a SIGTSTP would stop it; task 15b point 0a); a signal
// that the handler took in while close ran is discarded as well (task
// 10d finding 4).
type term struct {
	e     *env
	shown bool // a share is on the screen

	ctl *control // of stdin; nil only if checkTerminal was skipped

	out chan struct{} // held while the term writes to the screen
	// errTerm: stderr is a terminal other than stdout; every clear of
	// the screen goes there too (task 15b point 6).
	errTerm bool
	dead    atomic.Bool // the abort path runs: nothing more on the screen

	mu             sync.Mutex
	restore        func() error // set while echo is off
	flowRestore    func() error // set while the flow control of stdin is off
	outFlowRestore func() error // set while the flow control of stdout is off
	deferred       bool         // signals are deferred (commit)
	pending        bool         // a signal arrived while deferred, before the commit point
	committed      bool         // the commit point is passed
	late           bool         // a signal arrived after the commit point
	sig            chan os.Signal
	done           chan struct{}
	closed         bool
}

// newTerm starts the signal handling of a term (openTerm); e.fail and
// t.finish end it.
func (e *env) newTerm() *term {
	t := &term{e: e, ctl: echoControl(e.in), out: make(chan struct{}, 1), sig: make(chan os.Signal, 1), done: make(chan struct{})}
	if t.ctl != nil {
		t.ctl.outFlow = outFlowControl(e.in, e.stdout)
	}
	t.errTerm = otherTerminal(e.stdout, e.stderr)
	signal.Notify(t.sig, abortSignals...)
	go func() {
		for {
			select {
			case <-t.done:
				return
			case <-t.sig:
				t.mu.Lock()
				if t.closed {
					// The command finished while the signal was on its
					// way (task 10d finding 4).
					t.mu.Unlock()
					return
				}
				if t.committed {
					// After the commit point (task 10e finding 2).
					t.late = true
					t.mu.Unlock()
					continue
				}
				if t.deferred {
					t.pending = true
					t.mu.Unlock()
					continue
				}
				t.abort()
				return
			}
		}
	}()
	e.t = t
	return t
}

// abortWait bounds every step of the abort path that waits for a write
// to a terminal (task 15b point 0b): a write that does not return
// within it does not keep the program from ending.
const abortWait = 400 * time.Millisecond

// bounded runs f and waits for it at most abortWait.
func bounded(f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	timer := time.NewTimer(abortWait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// abort ends the program after a signal. t.mu is held and is never
// released. The term is marked dead before anything else, and t.out is
// taken and never released: no share line can be written after the
// clear (task 10c finding 4). The echo is restored first, then the
// screen is cleared while the flow control is still off, then the flow
// control is restored (stdout before stdin): the order in which a
// command ends (finish, close; task 15b point 0c). A write that blocks
// holds up neither the signal handling nor the end of the program
// (task 15b point 0b): t.out is waited for at most abortWait, and so is
// each write (bounded); the clear is written even when t.out could not
// be taken, and the terminal orders it behind the write that blocks.
// Before the echo comes back, the input not read yet is discarded
// (flushInput): a share typed just before the signal would otherwise be
// echoed once the echo is on, after the clear.
func (t *term) abort() {
	t.dead.Store(true)
	if t.ctl != nil {
		t.ctl.flush()
	}
	if t.restore != nil {
		t.restore()
		t.restore = nil
	}
	timer := time.NewTimer(abortWait)
	select {
	case t.out <- struct{}{}:
	case <-timer.C:
	}
	timer.Stop()
	bounded(t.clear)
	t.restoreFlow()
	bounded(func() { fmt.Fprintln(t.e.stderr, "gomail-ceremony: abgebrochen") })
	exit(exitAbort)
}

// restoreFlow restores the flow control of stdout and then of stdin,
// the reverse order of openTerm (on one terminal reached through two
// devices the attributes of before openTerm come back last). t.mu is
// held.
func (t *term) restoreFlow() {
	if t.outFlowRestore != nil {
		t.outFlowRestore()
		t.outFlowRestore = nil
	}
	if t.flowRestore != nil {
		t.flowRestore()
		t.flowRestore = nil
	}
}

// errDead refuses a share line once the abort path runs.
var errDead = errors.New("Bildschirm nach dem Abbruch gesperrt")

// display is the Display of the ceremony: every share line is written
// while t.out is held, and none once the abort path runs (task 10c
// finding 4, task 15b point 0b).
type display struct{ t *term }

func (d display) Write(p []byte) (int, error) {
	d.t.out <- struct{}{}
	defer func() { <-d.t.out }()
	if d.t.dead.Load() {
		return 0, errDead
	}
	return d.t.e.stdout.Write(p)
}

// BeginCommit implements ceremony.CommitGuard: from now on a signal
// only sets a flag.
func (t *term) BeginCommit() {
	t.mu.Lock()
	t.deferred = true
	t.mu.Unlock()
	if commitHook != nil {
		commitHook(t, "begin", false)
	}
}

// errSignalled refuses the commit point after a signal.
var errSignalled = errors.New("Abbruchsignal vor dem Commit-Punkt")

// CommitPoint implements ceremony.CommitGuard: a signal that arrived
// since BeginCommit refuses the commit point, and the ceremony rolls the
// files back; otherwise the commit point is passed, and from now on a
// signal is ignored (task 10e finding 2).
func (t *term) CommitPoint() error {
	if commitHook != nil {
		commitHook(t, "point", false)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending {
		return errSignalled
	}
	t.committed = true
	return nil
}

// EndCommit implements ceremony.CommitGuard: the files are complete
// (committed) or rolled back. Rolled back after a signal, the program
// ends now with exit code 130. Complete, the ceremony goes on to report
// its results; a signal that arrived after the commit point is reported
// then (task 10e finding 2).
func (t *term) EndCommit(committed bool) {
	if commitHook != nil {
		commitHook(t, "end", committed)
	}
	t.mu.Lock()
	t.deferred = false
	if !committed {
		t.committed = false
		if t.pending || t.late {
			t.abort()
			return
		}
	} else if t.pending {
		// Only if the ceremony did not ask CommitPoint: the files are
		// complete, the signal came too late to stop them.
		t.pending = false
		t.late = true
	}
	t.mu.Unlock()
}

// lateSignal reports whether a signal arrived after the commit point.
func (t *term) lateSignal() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.late
}

// clear writes clearScreen to stdout, and to stderr when that is
// another terminal (errTerm): the prompts and messages are there, and,
// when stdin is that terminal, the echo of anything typed while the echo
// is on (task 15b point 6). stderr comes first, so that a stdout that
// blocks does not keep it from being cleared. t.out is held.
func (t *term) clear() {
	if t.errTerm {
		fmt.Fprint(t.e.stderr, clearScreen)
	}
	fmt.Fprint(t.e.stdout, clearScreen)
}

// otherTerminal reports whether errw (stderr) is a terminal and another
// one than out (stdout). The stand-in terminals of the tests are not.
func otherTerminal(out, errw any) bool {
	ef, ok := errw.(*os.File)
	if !ok || !isTerminalFd(ef.Fd()) {
		return false
	}
	of, ok := out.(*os.File)
	return !ok || !sameTerminal(of.Fd(), ef.Fd())
}

// wipe clears the screen, with t.out held; not once the abort path
// runs, which clears the screen itself.
func (t *term) wipe() {
	t.out <- struct{}{}
	defer func() { <-t.out }()
	if !t.dead.Load() {
		t.clear()
	}
}

// echoOff switches the echo of the terminal off until echoOn. Without
// an echo switch it fails closed.
func (t *term) echoOff() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore != nil {
		return nil
	}
	if t.ctl == nil {
		return errNoTerminal
	}
	restore, err := t.ctl.echo()
	if err != nil {
		return fmt.Errorf("Echo des Terminals lässt sich nicht abschalten: %w", err)
	}
	t.restore = restore
	return nil
}

// echoOn restores the terminal attributes saved by echoOff.
func (t *term) echoOn() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore != nil {
		t.restore()
		t.restore = nil
	}
}

// close restores the terminal (echo, then flow control) and ends the
// handler of the signals, but not their notification: until the program
// exits, every abortSignal is taken in and discarded (os/signal drops a
// signal for a channel that is full), whatever the command reports
// (task 15b point 0a). The command is finished, complete or failed, and
// a signal can change its outcome no more. The notification is not
// stopped: with the default disposition back (signal.Stop) a SIGINT,
// SIGTERM or SIGHUP before the exit would kill the program (the shell
// reports it aborted, the export complete), a SIGTSTP stop it and a
// SIGQUIT print a stack trace. signal.Ignore is no way out either: the
// runtime takes a signal off the notification before it marks it
// ignored, and a signal taken in between gets its default action
// (TestPTYSignalSalvo found it).
func (t *term) close() {
	t.echoOn()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.restoreFlow()
	if !t.closed {
		t.closed = true
		if closeHook != nil {
			closeHook(t)
		}
		close(t.done)
	}
}

// settle waits until the holder of a share on the screen confirms, and
// clears the screen in any case.
func (t *term) settle() error {
	var err error
	if t.shown {
		t.shown = false
		fmt.Fprint(t.e.stderr, "Anteil notiert? Eingabetaste löscht den Bildschirm: ")
		_, err = t.e.readLine()
	}
	t.wipe()
	return err
}

// finish ends the command: after success the last share shown is
// confirmed, after an error it is not; the screen is cleared in both
// cases. After success, a signal that arrived after the commit point is
// reported, after the last clear (task 10e finding 2).
func (t *term) finish(err error) error {
	if err == nil {
		err = t.settle()
	} else {
		t.wipe()
	}
	t.close()
	if err == nil && t.lateSignal() {
		fmt.Fprintln(t.e.stderr, "gomail-ceremony: abgeschlossen; ein Abbruchsignal kam nach dem Commit-Punkt an und wurde ignoriert")
	}
	return err
}

// Handover calls the holder of share i. Input typed ahead and not read
// yet is discarded first, on the terminal and in the read buffer (task
// 10e finding 4): an Enter typed twice at "Anteil notiert?" does not
// answer this prompt too, and share i is shown only once its holder
// confirmed.
func (t *term) Handover(i, n int) error {
	if err := t.settle(); err != nil {
		return err
	}
	if t.ctl == nil {
		return errNoTerminal
	}
	if err := t.ctl.flush(); err != nil {
		return fmt.Errorf("Eingabe des Terminals lässt sich nicht verwerfen: %w", err)
	}
	t.e.scrubInput()
	fmt.Fprintf(t.e.stderr, "Inhaber von Anteil %d von %d an den Bildschirm, dann Eingabetaste: ", i, n)
	if _, err := t.e.readLine(); err != nil {
		return err
	}
	t.shown = true
	return nil
}

func (t *term) AskShare(want int) ([]string, error) {
	if err := t.settle(); err != nil {
		return nil, err
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ws, err := t.readWords(want)
		if err != nil {
			return nil, err
		}
		if msg := checkShare(ws, want); msg != "" {
			fmt.Fprintln(t.e.stderr, msg)
			continue
		}
		return ws, nil
	}
	return nil, fmt.Errorf("%w: %d Fehlversuche", ceremony.ErrShares, maxAttempts)
}

// readWords reads the words of one share with the echo off (and ISIG
// and IEXTEN, echoOff) and clears the screen afterwards, also on
// errors. Every line is overwritten in the read buffer once it is
// converted, and the whole read buffer is overwritten with zeros
// afterwards (scrubInput). An abort key in the input is errAborted.
func (t *term) readWords(want int) ([]string, error) {
	defer t.wipe()
	defer t.e.scrubInput()
	if err := t.echoOff(); err != nil {
		return nil, err
	}
	defer t.echoOn()
	if want > 0 {
		fmt.Fprintf(t.e.stderr, "Anteil Nr. %d eingeben (30 Wörter, auch über mehrere Zeilen, ohne Anzeige; %s):\n", want, abortHint)
	} else {
		fmt.Fprintf(t.e.stderr, "Anteil eingeben (30 Wörter, auch über mehrere Zeilen, ohne Anzeige; %s):\n", abortHint)
	}
	var ws []string
	for len(ws) < shamir.ShareWords {
		line, err := t.e.readSlice()
		if err != nil {
			return nil, err
		}
		lw, err := words.Normalize(string(line))
		clear(line)
		if err != nil {
			// Unreachable: a line is at most maxLine bytes, below
			// words.MaxInput; refused all the same.
			return nil, err
		}
		ws = append(ws, lw...)
		if len(ws) < shamir.ShareWords {
			fmt.Fprintf(t.e.stderr, "(%d von %d Wörtern)\n", len(ws), shamir.ShareWords)
		}
	}
	return ws, nil
}

// abortHint tells how to abort while a share is typed: the abort keys
// raise no signal then and reach the program with the line.
const abortHint = "Abbruch mit Strg-C und Eingabetaste"

// checkShare returns why ws is not share want (0: any), or "". It names
// positions and indices, never words.
func checkShare(ws []string, want int) string {
	if len(ws) != shamir.ShareWords {
		return fmt.Sprintf("Ein Anteil hat genau %d Wörter, eingegeben wurden %d.", shamir.ShareWords, len(ws))
	}
	for i, w := range ws {
		if words.Check([]string{w}) != nil {
			return fmt.Sprintf("Wort Nr. %d steht nicht in der Wortliste (Abkürzungen gelten nicht).", i+1)
		}
	}
	s, err := shamir.ShareFromWords(ws)
	if err != nil {
		return "Die Prüfsumme des Anteils stimmt nicht; bitte Wort für Wort vergleichen."
	}
	idx := int(s.Index)
	s.Zero()
	if want > 0 && idx != want {
		return fmt.Sprintf("Das ist Anteil %d, verlangt ist Anteil %d.", idx, want)
	}
	return ""
}

// ---------------------------------------------------------------- commands

func readPin(path string) (*store.PlatformPin, error) {
	if path == "" {
		return nil, errors.New("--pin fehlt")
	}
	pin, err := ceremony.ReadPin(path)
	if err != nil {
		return nil, err
	}
	if pin.Dev {
		return nil, fmt.Errorf("%w: Pin einer Entwicklungszeremonie", ceremony.ErrIdentity)
	}
	return pin, nil
}

func (e *env) unlockOptions(pin *store.PlatformPin, t *term) ceremony.UnlockOptions {
	return ceremony.UnlockOptions{IdentityGen: pin.Gen, IdentityPub: pin.Pub, Prompter: t, Now: now}
}

func (e *env) init(args []string) int {
	fs := e.flags("init")
	dev := devFlags(fs) // only in a test build (tag gomail_dev)
	sharesArg := fs.String("shares", "", "Aufteilung k-of-n, etwa 3-of-5")
	out := fs.String("out", "", "Exportverzeichnis, neu oder leer")
	keyDir := fs.String("keys", "", "Verzeichnis für private Schlüssel, getrennt vom Export")
	origin := fs.String("origin", "", "Origin des Transparenzlogs")
	var ws witnessFlag
	fs.Var(&ws, "witness", "Zeuge <name>=<verifier-zeile> (mehrfach)")
	minW := fs.Int("min-witnesses", 0, "nötige Zeugensignaturen")
	if !parse(fs, args) {
		return e.usage("")
	}
	realSet := *sharesArg != "" || *out != "" || *origin != "" || len(ws) > 0 || *minW != 0
	if code, ok := dev.run(e, *keyDir, realSet); ok {
		return code
	}
	if *sharesArg == "" || *out == "" || *keyDir == "" || *origin == "" || len(ws) == 0 || *minW == 0 {
		return e.usage("--shares, --out, --keys, --origin, --witness und --min-witnesses sind nötig")
	}
	sh, err := ceremony.ParseShares(*sharesArg)
	if err != nil {
		return e.usage(err.Error())
	}
	if err := e.checkTerminal(); err != nil {
		return e.fail(err)
	}
	t, err := e.openTerm()
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stderr, "Zeremonie %s: Die Anteile erscheinen nacheinander nur auf diesem Bildschirm.\n", sh)
	e.clockHint("Zertifikate")
	res, err := ceremony.Init(ceremony.InitOptions{
		Out: *out, KeyDir: *keyDir, Shares: sh, Origin: *origin, Witnesses: ws, MinWitnesses: *minW,
		Display: display{t}, Prompter: t, Now: now,
	})
	if err := t.finish(err); err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, "Zeremonie abgeschlossen, Probe-Rekonstruktion erfolgreich.")
	fmt.Fprintf(e.stdout, "Exportverzeichnis:   %s  (gomail-ceremony publish --from ... auf dem Server)\n", res.Out)
	fmt.Fprintf(e.stdout, "Pin für Clients:     %s\n", filepath.Join(res.Out, "identity-1.pin"))
	fmt.Fprintf(e.stdout, "Admin-Schlüssel:     %s  (zum Administrator)\n", filepath.Join(res.KeyDir, "admin-1.key"))
	fmt.Fprintf(e.stdout, "Ingest-Schlüssel:    %s  (zum Server)\n", filepath.Join(res.KeyDir, "ingest-1.key"))
	fmt.Fprintln(e.stdout, "Rechner jetzt ausschalten (2.3 Schritt 5).")
	return 0
}

// clockHint shows the clock of the ceremony computer before the first
// prompt (RUNBOOK, task 15b point 6): it gives valid_from of what the
// ceremony signs (what), and a wrong clock is set before the ceremony,
// not after.
func (e *env) clockHint(what string) {
	fmt.Fprintf(e.stderr, "Uhr dieses Rechners: %s; sie bestimmt valid_from der %s. "+
		"Geht sie falsch, jetzt mit Strg-C abbrechen, die Uhr stellen und neu beginnen.\n",
		now().UTC().Format(time.RFC3339), what)
}

func (e *env) rotate(args []string) int {
	fs := e.flags("ingest-rotate")
	pinPath := fs.String("pin", "", "Pin der aktuellen Identität")
	genArg := fs.String("gen", "", "neue Ingest-Generation (höchste vorhandene + 1)")
	out := fs.String("out", "", "Exportverzeichnis, neu oder leer")
	keyDir := fs.String("keys", "", "Verzeichnis für den privaten Ingest-Schlüssel")
	validArg := fs.String("valid-from", "", "Umschaltzeitpunkt (RFC 3339, nicht in der Vergangenheit), ab dem der Server den neuen Schlüssel benutzt")
	if !parse(fs, args) || *pinPath == "" || *genArg == "" || *out == "" || *keyDir == "" || *validArg == "" {
		return e.usage("")
	}
	gen, err := strconv.ParseUint(*genArg, 10, 32)
	if err != nil {
		return e.usage("--gen: keine Generation")
	}
	validFrom, err := time.Parse(time.RFC3339, *validArg)
	if err != nil {
		return e.usage("--valid-from: kein Zeitpunkt nach RFC 3339")
	}
	if err := e.checkTerminal(); err != nil {
		return e.fail(err)
	}
	pin, err := readPin(*pinPath)
	if err != nil {
		return e.fail(err)
	}
	t, err := e.openTerm()
	if err != nil {
		return e.fail(err)
	}
	res, err := ceremony.IngestRotate(ceremony.RotateOptions{
		UnlockOptions: e.unlockOptions(pin, t), Out: *out, KeyDir: *keyDir, Gen: uint32(gen), ValidFrom: validFrom,
	})
	if err := t.finish(err); err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Ingest-Generation %d erzeugt, gültig ab %s.\n", res.Gen, validFrom.UTC().Format(time.RFC3339))
	fmt.Fprintf(e.stdout, "Exportverzeichnis:   %s  (gomail-ceremony publish vor dem Umschalten)\n", *out)
	fmt.Fprintf(e.stdout, "Ingest-Schlüssel:    %s\n", filepath.Join(*keyDir, store.PlatformFileName("ingest", res.Gen, "key")))
	fmt.Fprintln(e.stdout, "Die Zeugen brauchen den neuen Log-Schlüssel (--log-key).")
	return 0
}

func (e *env) reshare(args []string) int {
	fs := e.flags("reshare")
	pinPath := fs.String("pin", "", "Pin der aktuellen Identität")
	sharesArg := fs.String("shares", "", "neue Aufteilung k-of-n")
	if !parse(fs, args) || *pinPath == "" || *sharesArg == "" {
		return e.usage("")
	}
	sh, err := ceremony.ParseShares(*sharesArg)
	if err != nil {
		return e.usage(err.Error())
	}
	if err := e.checkTerminal(); err != nil {
		return e.fail(err)
	}
	pin, err := readPin(*pinPath)
	if err != nil {
		return e.fail(err)
	}
	t, err := e.openTerm()
	if err != nil {
		return e.fail(err)
	}
	err = ceremony.Reshare(ceremony.ReshareOptions{UnlockOptions: e.unlockOptions(pin, t), Shares: sh, Display: display{t}})
	if err := t.finish(err); err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Neue Aufteilung %s erzeugt und geprüft.\n", sh)
	fmt.Fprintln(e.stdout, "Die alten Anteile bleiben gültig und lassen sich nicht widerrufen: Inhaber vernichten sie.")
	return 0
}

func (e *env) succeed(args []string) int {
	fs := e.flags("succeed")
	pinPath := fs.String("pin", "", "Pin der aktuellen Identität")
	out := fs.String("out", "", "Exportverzeichnis, neu oder leer")
	origin := fs.String("origin", "", "Origin des Transparenzlogs (nur zur Kontrolle: er ändert sich nie)")
	var ws witnessFlag
	fs.Var(&ws, "witness", "Zeuge <name>=<verifier-zeile> (mehrfach; nur für eine ausdrückliche Änderung, sonst die des Pins)")
	minW := fs.Int("min-witnesses", 0, "nötige Zeugensignaturen (nur für eine ausdrückliche Änderung, sonst die des Pins)")
	compromised := fs.Bool("compromised", false, "gesperrt: noch nicht verfügbar (Q19)")
	if !parse(fs, args) {
		return e.usage("")
	}
	if *compromised {
		// TODO(Q19): locked (task 15f point 1) before anything is shown,
		// read or written, the terminal check included.
		return e.usage(errCompromised)
	}
	if *pinPath == "" || *out == "" || *minW < 0 {
		return e.usage("")
	}
	if err := e.checkTerminal(); err != nil {
		return e.fail(err)
	}
	pin, err := readPin(*pinPath)
	if err != nil {
		return e.fail(err)
	}
	if *origin != "" && *origin != pin.Origin {
		return e.fail(fmt.Errorf("%w: --origin weicht vom Origin des Pins ab; der Origin eines Logs ändert sich nie", ceremony.ErrOptions))
	}
	t, err := e.openTerm()
	if err != nil {
		return e.fail(err)
	}
	// The clock gives valid_from of the succession; it is shown only when
	// a succession is signed (task 15f point 4): after a compromise
	// (locked above, Q19) none would be.
	if !*compromised {
		e.clockHint("Nachfolge")
	}
	res, err := ceremony.Succeed(ceremony.SucceedOptions{
		UnlockOptions: e.unlockOptions(pin, t), Out: *out, Pin: pin,
		Origin: *origin, Witnesses: ws, MinWitnesses: *minW,
	})
	if err := t.finish(err); err != nil {
		return e.fail(err)
	}
	fmt.Fprintf(e.stdout, "Identitätsgeneration %d erzeugt.\n", res.Pin.Gen)
	fmt.Fprintf(e.stdout, "Exportverzeichnis:   %s\n", res.Out)
	fmt.Fprintf(e.stdout, "Neuer Pin:           %s  (Client-Update und gomail-server --pin, vor publish)\n", filepath.Join(res.Out, store.PlatformFileName("identity", res.Pin.Gen, "pin")))
	return 0
}

func (e *env) publish(args []string) int {
	fs := e.flags("publish")
	from := fs.String("from", "", "Exportverzeichnis einer Zeremonie")
	data := fs.String("data", "", "Datenverzeichnis des Servers")
	pinPath := fs.String("pin", "", "Pin, mit dem der Server läuft (nach einer Nachfolge der neue)")
	replaceW := fs.Bool("replace-witnesses", false, "platform/witnesses.rec durch Zeugen und Quorum des Pins ersetzen")
	if !parse(fs, args) || *from == "" || *data == "" || *pinPath == "" {
		return e.usage("")
	}
	pin, err := readPin(*pinPath)
	if err != nil {
		return e.fail(err)
	}
	st, err := store.Open(*data)
	if err != nil {
		return e.fail(err)
	}
	var replaced string
	opts := ceremony.PublishOptions{From: *from, Data: st, Pin: pin, ReplaceWitnesses: *replaceW,
		WitnessesReplaced: func(before, after *witness.Witnesses) {
			replaced = fmt.Sprintf("platform/witnesses.rec ersetzt: bisher Quorum %d von %d (%s), jetzt Quorum %d von %d (%s) wie im Pin.\n",
				before.Min, len(before.List), witnessNames(before.List), after.Min, len(after.List), witnessNames(after.List))
		}}
	if err := ceremony.Publish(opts); err != nil {
		if errors.Is(err, store.ErrLocked) {
			return e.fail(fmt.Errorf("der Server läuft (Serversperre locks/server, 9.1): erst anhalten, dann veröffentlichen: %w", err))
		}
		return e.fail(err)
	}
	fmt.Fprint(e.stdout, replaced)
	fmt.Fprintf(e.stdout, "%s in %s veröffentlicht und ins Log eingetragen.\n", *from, *data)
	fmt.Fprintf(e.stdout, "Den Server jetzt mit diesem Pin starten: gomail-server serve --pin %s ...\n", *pinPath)
	return 0
}

// errCompromised is the fixed text of the refusal of succeed
// --compromised (task 15f point 1, ceremony.ErrCompromised).
const errCompromised = "succeed --compromised: noch nicht verfügbar: Widerruf einer Plattformgeneration ist nicht festgelegt (Q19)"

// witnessNames returns the names of ws, comma separated (names are
// checked by witness.CheckName; no secret).
func witnessNames(ws []witness.Key) string {
	names := make([]string, 0, len(ws))
	for _, w := range ws {
		names = append(names, w.Name)
	}
	return strings.Join(names, ", ")
}
