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
// terminal (task 15b point 6); standard output, which shows the shares,
// is cleared first (task 15l). From the first prompt to the end of the
// command the terminal has no software flow control (IXON, IXOFF, IXANY
// cleared), and neither has standard output nor standard error when it
// is another terminal (task 15b point 0b, task 15l): Ctrl-S cannot stop
// the output, so that no share stays on the screen with the program
// stuck (task 10e finding 1); a write to the screen that blocks all the
// same holds up neither the signal handling nor the end of the program
// (abortWait, abortTotal: the abort path waits for no write longer and
// ends within 2 s, and none of its requests to a terminal waits, task
// 15m point 1). Before every clear the output of the terminal runs
// again, should another program have stopped it (TCOOFF) or Scroll
// Lock on the Linux console; when a write does not get through all the
// same, the abort path discards the output not yet sent, so that a
// terminal whose output is full takes the clear (task 15m point 2).
// Before the commit no write keeps a share on the screen with the
// program stuck longer than outputGrace (2 s) and the abort path after
// it (task 15n finding 2): every share line, every clear, and every
// prompt while a share is on the screen, restarts the output of its
// terminal first and again every millisecond as long as it does not
// return; one that fails (any write error, a part written included) or
// does not get through within outputGrace ends the ceremony through the
// abort path (screen cleared, exit code 130), and the next holder is
// never called while the clear of a share is not written completely
// (task 15n finding 1). Before every clear and every share line
// O_NONBLOCK is cleared on standard output and standard error: another
// program that shares their open file description can set it, and a
// clear would then fail at once on a terminal that takes nothing. The
// abort path counts every failed write of a clear as one that does not
// return in time: it discards the output not yet sent, restarts the
// output and writes the clear again, until its time is up. The last
// limit stays as before: a terminal that never takes output again (one
// whose output another program stops again and again, faster than it
// is restarted, until the end) never shows the clear, and after exit
// code 130 nothing tries again. The last step of the abort path
// restarts the output of stdout and stderr once more with a single
// request and no stop before it (TCOON, TIOCSTART), after every
// goroutine of the program that restarts the output (TCOOFF, then
// TCOON) has ended: no terminal is left stopped at the exit (task 20a
// point 3).
//
// A confirmation (Enter when a holder is called, Enter when a holder
// noted the share) counts only when it arrives at least confirmDelay (1
// s) after its prompt was written completely (task 15n finding 3):
// what arrives before is discarded, from the terminal and from the read
// buffer, and the prompt is asked again with the note "Eingabe zu früh,
// bitte erneut bestätigen". So an Enter typed twice, also with up to
// confirmDelay between the two, never answers the next prompt: it
// neither calls the next holder nor clears a share before its holder
// saw it. SIGINT, SIGTERM,
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
// The prompts go to standard error, which need not be a terminal; but
// it must be a terminal, a pipe or a regular file, open for writing
// (task 15l, task 15m point 3). Before the
// terminal check, before anything is shown, read or written, the four
// commands refuse with a usage error (exit code 2) a standard error that
// is closed: the runtime puts /dev/null in place of a descriptor 2 that
// is closed when the program starts, and every prompt would vanish
// there, with the ceremony waiting at a prompt nobody sees and a share
// on the screen. /dev/null itself (its device, or the file a fresh open
// of /dev/null gives) is refused the same way, and so is a descriptor
// not open for writing (opened read-only, the read end of a pipe,
// O_PATH) and every other kind of file (a socket, a device that is no
// terminal). Whether a pipe still has a reader is not visible before a
// write; one without a reader is handled as follows (task 15i). From the
// first step of the program until it exits, SIGPIPE and SIGXFSZ are
// taken in on a channel nobody reads (brokenPipe, task 15m point 4), so
// that a pipe on standard error whose reader is gone, or a socket
// without a peer, never ends the program by a signal, neither past the
// abort path (the runtime would end it with SIGPIPE at the next prompt,
// a share on the screen and the flow control off) nor before its exit
// code (a usage error, a refusal). A write error on standard error is
// ignored, with one exception: when a prompt fails before the files
// are written (commit), with EPIPE or any other error (EFBIG of a file at
// RLIMIT_FSIZE, EIO, ENOSPC, ...; task 15m point 3), or does not get
// through within outputGrace while a share is on the screen (task 15n
// finding 2), nobody can see it or maybe any prompt after it, and the
// ceremony ends through the abort path at once, before it waits for an
// answer and before another share is shown (screen cleared, terminal
// restored, nothing written, exit code 130; "abgebrochen" then goes to
// standard output). After the
// commit point the ceremony is complete and ends with its results as
// documented above.
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
abschalten lässt (keine Umleitung, keine Pipe); die Standardfehlerausgabe mit
den Eingabeaufforderungen ist ein Terminal, eine Pipe oder eine Datei, zum
Schreiben geöffnet. --valid-from liegt nicht in der Vergangenheit. succeed übernimmt
Origin, Zeugen und Quorum aus dem Pin; --witness und --min-witnesses ändern sie
ausdrücklich. publish läuft auf dem Server, solange er angehalten ist, und
trägt ein Exportverzeichnis in Datenverzeichnis und Log ein; danach startet der
Server mit diesem Pin.
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

// lostOutput takes in brokenPipe (SIGPIPE, SIGXFSZ) from the first step
// of run until the program exits (task 15i, task 15m point 4); nobody
// reads it, and os/signal drops a signal for a channel that is full. It
// is never stopped, for the reason close gives for the abortSignals.
var (
	lostOutput     = make(chan os.Signal, 1)
	lostOutputOnce sync.Once
)

// catchLostOutput starts lostOutput, once per program. Before task 15m
// it started with openTerm: a usage error, a refusal or a failure
// written before (usage, refuse, fail) to a standard error that is a
// pipe without a reader or a socket without a peer ended the program by
// SIGPIPE instead of its exit code 2 or 1.
func catchLostOutput() {
	lostOutputOnce.Do(func() {
		if len(brokenPipe) > 0 {
			// Notify without signals would relay every signal.
			signal.Notify(lostOutput, brokenPipe...)
		}
	})
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	catchLostOutput() // first: task 15m point 4
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

// pendingStandIn is a stand-in terminal for stdin that reports the input
// it holds and the command has not read (control.pending); only the
// tests of this package implement it.
type pendingStandIn interface {
	inputPending() (int, error)
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
	// pending reports how many bytes of input the terminal received and
	// the program has not read (inputPending; task 15n finding 3); nil
	// for a stand-in without pendingStandIn.
	pending func() (int, error)
	// outFlow clears IXON, IXOFF and IXANY of stdout (disableFlowOut)
	// when stdout is a terminal other than stdin (task 15b point 0b);
	// nil when it is the same terminal (flow covers it) or a stand-in.
	outFlow echoSwitch
	// errFlow clears IXON, IXOFF and IXANY of stderr (disableFlowOut)
	// when stderr is a terminal other than stdin and stdout (task 15l
	// point 1); nil when it is one of them or not a terminal.
	errFlow echoSwitch
}

// outputWake returns the function that lets the output of the terminal
// w run again (wakeOutput, task 15m point 2), with the output not yet
// sent discarded when its argument is true; nil when w is no terminal
// (*os.File) or a stand-in of the tests.
func outputWake(w any) func(discard bool) error {
	f, ok := w.(*os.File)
	if !ok {
		return nil
	}
	fd := f.Fd()
	if !isTerminalFd(fd) {
		return nil
	}
	return func(discard bool) error { return wakeOutput(fd, discard) }
}

// outputResume returns the function that restarts the output of the
// terminal w with a single request, without stopping it first
// (resumeOutput: TCOON on Linux, TIOCSTART on the BSDs and macOS; task
// 20a point 3); nil when w is no terminal (*os.File) or a stand-in of
// the tests.
func outputResume(w any) func() error {
	f, ok := w.(*os.File)
	if !ok {
		return nil
	}
	fd := f.Fd()
	if !isTerminalFd(fd) {
		return nil
	}
	return func() error { return resumeOutput(fd) }
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
			echo:    func() (func() error, error) { return disableEcho(fd) },
			flow:    func() (func() error, error) { return disableFlow(fd) },
			flush:   func() error { return flushInput(fd) },
			pending: func() (int, error) { return inputPending(fd) },
		}
	case echoStandIn:
		if !f.terminal() {
			return nil
		}
		c := &control{echo: f.disableEcho, flow: f.disableFlow, flush: f.flushInput}
		if p, ok := f.(pendingStandIn); ok {
			c.pending = p.inputPending
		}
		return c
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

// errFlowControl returns the switch of the flow control of stderr errw
// when errw is a terminal other than stdin in and stdout out (task 15l
// point 1): an XOFF typed on that terminal would stop every prompt and
// the clear of stderr, and with them the clear of a share in the abort
// path. On the terminal of stdin or stdout their switch covers it.
func errFlowControl(in, out, errw any) echoSwitch {
	ef, ok := errw.(*os.File)
	if !ok {
		return nil
	}
	fd := ef.Fd()
	if !isTerminalFd(fd) {
		return nil
	}
	for _, v := range []any{in, out} {
		if f, ok := v.(*os.File); ok && sameTerminal(f.Fd(), fd) {
			return nil
		}
	}
	return func() (func() error, error) { return disableFlowOut(fd) }
}

// errStderrClosed and errStderrKind refuse, with a usage error (exit
// code 2), a command that shows or reads shares when standard error is
// closed, is not open for writing (errStderrReadOnly, task 15m point 3)
// or is no terminal, pipe or regular file (task 15l point 2;
// checkStderr).
var (
	errStderrClosed = errors.New("die Standardfehlerausgabe ist geschlossen")
	errStderrKind   = errors.New("die Standardfehlerausgabe ist weder Terminal noch Pipe noch Datei")
	// errStderrReadOnly: standard error is open, but not for writing
	// (task 15m point 3, writable); every prompt would fail.
	errStderrReadOnly = fmt.Errorf("%w (nicht zum Schreiben geöffnet)", errStderrClosed)
)

// checkStderr is the first step of checkTerminal (task 15l point 2):
// standard error must be a terminal, a pipe or a regular file, open for
// writing (stderrFile). A descriptor 2 that is closed when the program
// starts is /dev/null to the program (the runtime opens it in that
// slot), and the prompts would go nowhere: errStderrClosed, as for
// /dev/null itself and for a descriptor not open for writing
// (errStderrReadOnly: O_RDONLY, O_PATH, the read end of a pipe; task 15m
// point 3); errStderrKind for every other kind of file. A stand-in of the tests
// (not an *os.File) passes.
func (e *env) checkStderr() error {
	f, ok := e.stderr.(*os.File)
	if !ok {
		return nil
	}
	if err := stderrFile(f.Fd()); err != nil {
		return fmt.Errorf("%w: die Eingabeaufforderungen wären nicht zu sehen%s", err, noTerminalEnd)
	}
	return nil
}

// refuse ends a command that checkTerminal refused: a standard error
// that is closed or of the wrong kind is a usage error (exit code 2),
// every other refusal errNoTerminal (exit code 1, fail).
func (e *env) refuse(err error) int {
	if errors.Is(err, errStderrClosed) || errors.Is(err, errStderrKind) {
		return e.usage(err.Error())
	}
	return e.fail(err)
}

// checkTerminal is the first step of every command that shows or reads
// shares (init, reshare, ingest-rotate, succeed; task 10c finding 1):
// standard error must be usable (checkStderr, first: task 15l point 2),
// standard output must be a terminal, and standard input a terminal
// whose attributes can be read. Otherwise errStderrClosed or
// errStderrKind (refuse: exit code 2) or errNoTerminal, before anything
// is shown, read or written. A file or a pipe on standard input is
// refused as well: a share must never be on disk. Whether the echo can
// be switched off is tried by openTerm, once the signals are handled.
func (e *env) checkTerminal() error {
	if err := e.checkStderr(); err != nil {
		return err
	}
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
// finding 1), and that of stdout and of stderr when they are other
// terminals (task 15b point 0b, task 15l point 1), then the echo is
// switched off (quietFlags cleared and read back) and restored at once,
// so that a signal in between restores it too (task 10d finding 3). If that fails, the signal handling ends
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
		if err == nil && t.ctl.errFlow != nil {
			if t.errFlowRestore, err = t.ctl.errFlow(); err != nil {
				err = fmt.Errorf("Flusssteuerung der Standardfehlerausgabe: %w", err)
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
// cleared and restored as well (task 15b point 0b), and so is that of
// stderr when it is a third terminal (task 15l point 1). A confirmation
// counts only when it arrives confirmDelay after its prompt (confirm,
// task 15n finding 3); what arrives before is discarded, so that an
// Enter typed ahead or twice does not call the next holder. While a
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
// (task 10c finding 4). Before the commit the writes of the command to
// the screen and the prompts while a share is on it are bounded as well
// (push, outputGrace; task 15n): one that fails or does not get through
// takes the abort path (screenLost, promptLost). While the ceremony
// writes its files (commit) a signal only sets a flag (task 10c finding 3). A signal that arrived
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
//
// The prompts and messages of the term go to stderr (prompt), which
// may be a pipe (task 15i): SIGPIPE is taken in on lostOutput, a channel
// nobody reads, from the start of run until the program exits; it is
// never stopped, for the reason close gives for the abortSignals. A
// write error on stderr is ignored, except on a prompt before the commit
// (promptLost, whatever the error: task 15m point 3), which takes the
// abort path.
type term struct {
	e     *env
	shown bool // a share is on the screen

	ctl *control // of stdin; nil only if checkTerminal was skipped

	out chan struct{} // held while the term writes to the screen
	// errTerm: stderr is a terminal other than stdout; every clear of
	// the screen goes there too (task 15b point 6).
	errTerm bool
	// outWake and errWake let the output of stdout and of stderr run
	// again before a clear (outputWake, task 15m point 2) and before a
	// prompt while a share is on the screen (task 15n finding 2); nil
	// when that is no terminal and for a stand-in of the tests. errWake
	// is set whenever stderr is a terminal, also the one of stdout.
	outWake, errWake func(discard bool) error
	// outResume and errResume restart the output of stdout and of
	// stderr with a single request and no stop before it (outputResume,
	// TCOON, TIOCSTART), the last step of the abort path (task 20a point
	// 3); nil as outWake and errWake are.
	outResume, errResume func() error
	dead                 atomic.Bool // the abort path runs: nothing more on the screen
	// wakeMu guards wakeOff and wakeStops: the stop functions of the
	// goroutines of waking that run for this term (t.waking), which the
	// abort path ends before its last step (stopWaking, task 20a point
	// 3), also one that a write of the command started and still waits
	// for (push). Once wakeOff is set, t.waking starts none.
	wakeMu    sync.Mutex
	wakeOff   bool
	wakeN     int
	wakeStops map[int]func()
	// visible: a share line was written to stdout, completely or in part,
	// and no clear of stdout after it was written completely yet (task
	// 15n finding 1). Set and cleared while t.out is held.
	visible atomic.Bool
	// stallEnd is the deadline of the share line last written (display),
	// which the prompt after it shares (prompt, task 15n finding 2): from
	// the share line to the prompt that asks whether it is noted the
	// ceremony waits for nobody, and the two writes together get
	// outputGrace. Zero once that prompt took it, or after a clear. Read
	// and written while t.out is held.
	stallEnd time.Time

	mu             sync.Mutex
	restore        func() error // set while echo is off
	flowRestore    func() error // set while the flow control of stdin is off
	outFlowRestore func() error // set while the flow control of stdout is off
	errFlowRestore func() error // set while the flow control of stderr is off
	deferred       bool         // signals are deferred (commit)
	pending        bool         // a signal arrived while deferred, before the commit point
	committed      bool         // the commit point is passed
	late           bool         // a signal arrived after the commit point
	lost           bool         // a prompt failed (promptLost)
	blocked        bool         // a clear or a share line failed (screenLost)
	sig            chan os.Signal
	done           chan struct{}
	closed         bool
}

// newTerm starts the signal handling of a term (openTerm); e.fail and
// t.finish end it.
func (e *env) newTerm() *term {
	t := &term{e: e, ctl: echoControl(e.in), out: make(chan struct{}, 1), sig: make(chan os.Signal, 1),
		done: make(chan struct{})}
	if t.ctl != nil {
		t.ctl.outFlow = outFlowControl(e.in, e.stdout)
		t.ctl.errFlow = errFlowControl(e.in, e.stdout, e.stderr)
	}
	t.errTerm = otherTerminal(e.stdout, e.stderr)
	t.outWake = outputWake(e.stdout)
	t.errWake = outputWake(e.stderr)
	t.outResume = outputResume(e.stdout)
	t.errResume = outputResume(e.stderr)
	// Task 15i: a write to a pipe without a reader on stderr fails with
	// EPIPE instead of ending the program; run started that already
	// (task 15m point 4), this covers a term opened without run (tests).
	catchLostOutput()
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

// abortWait bounds every step of the abort path that may wait (task 15b
// point 0b, task 15l point 1, task 15m point 1): a write or a request
// that does not return within it does not keep the program from ending.
// The steps are the restart of the output of stdout and stderr, the
// wait for t.out (a prompt, a share line or a clear of the command that
// blocks), the clear of stdout and of stderr (each with its retry),
// each restore of the terminal modes and the last line; each one is
// bounded on its own, so that a descriptor that blocks holds up none of
// the others.
const abortWait = 400 * time.Millisecond

// abortTotal bounds the abort path as a whole (task 15m point 1: it ends
// within 2 s): a step that begins with less than abortWait left waits
// only for the rest, but at least abortFloor, so that the steps that do
// not wait (the restore of the terminal modes, none of whose requests
// waits) still run when the steps before them used up the time. With
// every step at its limit the program ends abortTotal plus a few times
// abortFloor after the abort path began.
const (
	abortTotal = 1500 * time.Millisecond
	abortFloor = 20 * time.Millisecond
)

// abortDrain is how long the abort path waits for t.out once the output
// runs again (abort, step 2) before it takes the output as full and
// discards what was written and not yet sent: a write that does not
// finish that soon on a terminal that runs is held up by a full output
// buffer (or by a terminal slower than a share line in that time, whose
// output is better dropped as well).
const abortDrain = 100 * time.Millisecond

// outputGrace bounds, before the commit, every write of the command to
// the screen (a share line, a clear) and every prompt while a share is
// on the screen (task 15n finding 2): one that does not return within it
// ends the ceremony through the abort path, so that no share stays on
// the screen with the program stuck longer than outputGrace and the
// abort path (abortTotal) together. 2 s: what the ceremony writes at a
// time is a few hundred bytes at most (a share line of 30 words, a
// prompt, a clear), which every terminal of a ceremony computer that
// works takes in far less (a local console or terminal window in
// microseconds, a serial line at 9600 baud in about 0.3 s, so that even
// such a line has six times the time it needs); much longer would keep
// a share on a screen that another program stops (TCOOFF, Scroll Lock)
// or fills, much shorter would end a ceremony on a terminal that is
// only slow for a moment.
const outputGrace = 2 * time.Second

// wakeEvery is how often the output of a terminal is restarted while a
// write to it does not return (push, clearBounded; task 15n finding 2):
// a program that stops the output again and again (TCOOFF in a loop)
// races each restart, and a blocked write gets through only when it runs
// between a restart and the next stop; a thousand chances a second give
// it room. Each restart is two requests that wait for nothing.
const wakeEvery = time.Millisecond

// confirmWait is confirmDelay of the program (task 15n finding 3): an
// Enter typed twice by a human comes within a few tenths of a second,
// a holder who reads a prompt and then confirms takes longer than a
// second. confirmDelay is a variable only so that tests can shorten it;
// they never set it to 0.
const confirmWait = time.Second

var confirmDelay = confirmWait

// abortClock is the deadline of one run of the abort path.
type abortClock struct{ end time.Time }

func newAbortClock() abortClock { return abortClock{end: time.Now().Add(abortTotal)} }

// wait returns how long the next step may take.
func (c abortClock) wait() time.Duration {
	return max(abortFloor, min(abortWait, time.Until(c.end)))
}

// rest returns the time left to the abort path, at least abortFloor: the
// clear of stdout may use all of it (task 15n finding 1), the steps
// after it still run for abortFloor each.
func (c abortClock) rest() time.Duration {
	return max(abortFloor, time.Until(c.end))
}

// bounded runs f and waits for it at most c.wait(); it reports whether f
// returned in time. A step that did not is left running and ends with
// the program.
func (c abortClock) bounded(f func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	timer := time.NewTimer(c.wait())
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// take takes the token ch (t.out), waiting at most c.wait(), and at most
// limit when that is shorter and not 0; it reports whether it got it.
func (c abortClock) take(ch chan struct{}, limit time.Duration) bool {
	wait := c.wait()
	if limit > 0 {
		wait = min(wait, limit)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ch <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// abort ends the program after a signal, or after a lost prompt
// (promptLost). t.mu is held and is never released. The term is marked
// dead before anything else, and t.out is taken and never released: no
// share line can be written after the clear (task 10c finding 4). Every
// step is bounded (abortClock: abortWait each, abortTotal in all), and
// none of the requests to the terminals waits (task 15m point 1): the
// modes are set with TCSETS (TIOCSETA), the input is discarded with
// TCFLSH (TIOCFLUSH), the output restarted with TCXONC (TIOCSTART);
// TCSETSF, as before task 15m, waited for the write lock of the terminal
// as long as a prompt was blocked in a write to it, and the program
// hung with a share on the screen. The order:
//
//  1. The output of stdout, and of stderr when that is another
//     terminal, runs again (wakeOutput, task 15m point 2): a terminal
//     stopped by TCOOFF, by an XOFF or by Scroll Lock on the Linux
//     console takes the clear again, and a write of the command blocked
//     there returns.
//  2. t.out is taken, while the output of both terminals is restarted
//     every wakeEvery (task 15n finding 2: a program that stops it
//     again and again). If it is not free within abortDrain, a write is
//     held up by a full output buffer: what was written to stdout and
//     stderr and not yet sent is discarded (TCOFLUSH, TIOCFLUSH), the
//     output restarted again, and t.out waited for once more.
//  3. stdout is cleared, the terminal that shows the shares, before
//     every step on stdin (task 15m point 1, task 15l point 1), with
//     the time left to the abort path (rest); then stderr when it is
//     another terminal (wait). O_NONBLOCK is cleared before each write
//     (task 15n finding 1). A clear that fails (any error: EAGAIN when
//     O_NONBLOCK was set again, a part written included) or does not
//     return within abortDrain counts as one that did not get through:
//     the output not yet sent to that terminal is discarded (a terminal
//     that filled up), the output restarted and the clear written
//     again, until the time is up (clearBounded). If none gets through,
//     the clear may never be shown: the last limit is a terminal that
//     never takes output again (a pseudo terminal whose master side is
//     never read again, one stopped again and again until the end); a
//     share already shown there stays where it is shown, and after the
//     exit nothing tries again.
//  4. The input not read yet is discarded, the echo is restored and the
//     input is discarded again (restoreInput): a share typed just before
//     the signal is not echoed once the echo is on.
//  5. The flow control is restored (stderr, stdout, stdin) after the
//     clears, the order in which a command ends (finish, close; task
//     15b point 0c).
//  6. The last line goes to stderr, or to stdout after the clear when
//     stderr takes nothing (task 15i; it holds no secret), with the
//     reason first when a prompt was lost (promptLost) or a write to
//     the screen did not get through (screenLost).
//  7. Every goroutine of waking of the term has ended (stopWaking),
//     also one that a write of the command, still blocked, started
//     (push), and none starts any more; then the output of stdout, and
//     of stderr when that is a terminal, is restarted once more with a
//     single request and no stop before it (resume, task 20a point 3):
//     no terminal is left stopped at the exit, also not by a restart of
//     the steps before (TCOOFF, TCOON).
//
// The output not yet sent is discarded only when a write does not get
// through (steps 2 and 3): unconditionally, it would also drop a share
// line written just before the signal on a terminal that takes output,
// which the clear removes anyway, and the holder would not see what
// was shown when the ceremony ended.
func (t *term) abort() {
	t.dead.Store(true)
	c := newAbortClock()
	t.unblock()
	t.wake(c, false)
	if !t.takeWaking(c, abortDrain) {
		t.wake(c, true)
		t.takeWaking(c, 0)
	}
	t.clearBounded(c.rest(), t.clearOut, t.outWake)
	if t.errTerm {
		t.clearBounded(c.wait(), t.clearErr, t.errWake)
	}
	restore := t.restore
	t.restore = nil
	c.bounded(func() {
		if t.ctl != nil {
			t.ctl.flush()
		}
		if restore != nil {
			restore()
		}
	})
	for _, r := range t.flowRestores() {
		c.bounded(func() { r() })
	}
	c.bounded(func() {
		msg := "gomail-ceremony: abgebrochen\n"
		switch {
		case t.lost:
			msg = "gomail-ceremony: " + errPromptLost.Error() + "\n" + msg
		case t.blocked:
			msg = "gomail-ceremony: " + errScreenLost.Error() + "\n" + msg
		}
		if _, err := io.WriteString(t.e.stderr, msg); err != nil {
			io.WriteString(t.e.stdout, msg)
		}
	})
	c.bounded(t.stopWaking)
	t.resume(c)
	exit(exitAbort)
}

// resume is the last step of the abort path (task 20a point 3): the
// output of stdout and of stderr is restarted once more, each with a
// single request that stops nothing before it (outResume, errResume:
// TCOON, TIOCSTART), within one bounded step. Every restart before it
// (wakeOutput: on Linux TCOOFF, then TCOON) stops the output for a
// moment; the goroutines of waking that send them have ended when their
// stop returned, so that no TCOOFF of the program comes after this step
// and no terminal is left stopped at the exit, also when it was stopped
// by a TCOOFF in the meantime. Should a write of the program still be
// blocked on a terminal (a prompt, the last line), it may go on once the
// output runs; the clear came before it.
func (t *term) resume(c abortClock) {
	c.bounded(func() {
		for _, r := range []func() error{t.outResume, t.errResume} {
			if r != nil {
				r()
			}
		}
	})
}

// wake lets the output of stdout and of stderr (when that is a
// terminal; on the terminal of stdout twice, which does no harm) run
// again, the output not yet sent discarded first with discard; each
// request bounded (abort, steps 1 and 2).
func (t *term) wake(c abortClock, discard bool) {
	for _, w := range []func(bool) error{t.outWake, t.errWake} {
		if w != nil {
			c.bounded(func() { w(discard) })
		}
	}
}

// takeWaking takes t.out as c.take does, while the output of stdout and
// stderr is restarted every wakeEvery (waking): the write that holds
// t.out may be one that a program stops again and again (abort, step
// 2; task 15n finding 2).
func (t *term) takeWaking(c abortClock, limit time.Duration) bool {
	stop := t.waking(t.outWake, t.errWake)
	defer stop()
	return c.take(t.out, limit)
}

// clearBounded writes a clear (clearOut, clearErr) within limit and
// reports whether one was written completely (abort, step 3; task 15n
// finding 1). Every attempt clears O_NONBLOCK (unblock) and restarts the
// output of the terminal first (wake; nil for a stand-in and for a
// stderr that is no terminal), and the output is restarted every
// wakeEvery while the attempt does not return (waking). An attempt that
// fails, whatever the error, or that does not return within abortDrain
// counts as one that did not get through: the next attempt discards the
// output not yet sent to that terminal first and writes the whole clear
// again, until limit; an earlier attempt still blocked is left behind
// (its rest, once the terminal takes it, comes before the newer clear,
// as the terminal lets one write after the other). Without wake there
// is nothing to discard: the attempt is waited for until limit, and
// only one that failed is repeated. A step that is left running ends
// with the program.
func (t *term) clearBounded(limit time.Duration, write func() error, wake func(bool) error) bool {
	end := time.Now().Add(limit)
	stop := t.waking(wake)
	defer stop()
	discard := false
	for {
		t.unblock()
		done := make(chan error, 1)
		go func(discard bool) {
			if wake != nil {
				wake(discard)
			}
			done <- write()
		}(discard)
		wait := time.Until(end)
		if wake != nil {
			wait = min(wait, abortDrain)
		}
		timer := time.NewTimer(max(wait, 0))
		select {
		case err := <-done:
			timer.Stop()
			if err == nil {
				return true
			}
			// Not at once again: a write that fails at once (EBADF, an
			// O_NONBLOCK set again and again) is not repeated in a
			// busy loop.
			if left := time.Until(end); left > 0 {
				time.Sleep(min(wakeEvery, left))
			}
		case <-timer.C:
		}
		if !time.Now().Before(end) {
			return false
		}
		discard = true
	}
}

// waking restarts the output of the terminals of wakes (nil entries are
// skipped) every wakeEvery, in a goroutine of its own, until the
// function it returns is called (task 15n finding 2). That function
// returns only once the goroutine has ended (task 20a point 3): a
// restart is TCOOFF and TCOON on Linux, and a goroutine still running
// could stop the output after the last step of the abort path (resume)
// and leave it stopped at the exit. None of the requests waits, so the
// wait for the goroutine is at most one round of them.
func waking(wakes ...func(bool) error) (stop func()) {
	var ws []func(bool) error
	for _, w := range wakes {
		if w != nil {
			ws = append(ws, w)
		}
	}
	if len(ws) == 0 {
		return func() {}
	}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(wakeEvery)
		defer tick.Stop()
		for {
			select {
			case <-quit:
				return
			case <-tick.C:
				for _, w := range ws {
					w(false)
				}
			}
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}

// waking is waking for the term t: its goroutine is ended by the stop
// function returned or by stopWaking, whichever comes first (task 20a
// point 3). After stopWaking it starts none and returns a stop that does
// nothing: the abort path, which called it, ends the program.
func (t *term) waking(wakes ...func(bool) error) (stop func()) {
	t.wakeMu.Lock()
	defer t.wakeMu.Unlock()
	if t.wakeOff {
		return func() {}
	}
	s := sync.OnceFunc(waking(wakes...))
	if t.wakeStops == nil {
		t.wakeStops = make(map[int]func())
	}
	id := t.wakeN
	t.wakeN++
	t.wakeStops[id] = s
	return func() {
		s()
		t.wakeMu.Lock()
		delete(t.wakeStops, id)
		t.wakeMu.Unlock()
	}
}

// stopWaking ends every goroutine of waking that runs for t and returns
// once they have ended; t.waking starts none after it (abort, step 7;
// task 20a point 3). A write of the command that is still blocked (push)
// keeps its goroutine of waking running until its outputGrace is up,
// longer than the abort path takes: without stopWaking that goroutine
// could stop the output (TCOOFF) after the last step of the abort path
// and leave the terminal stopped at the exit.
func (t *term) stopWaking() {
	t.wakeMu.Lock()
	t.wakeOff = true
	stops := t.wakeStops
	t.wakeStops = nil
	t.wakeMu.Unlock()
	for _, s := range stops {
		s()
	}
}

// unblock clears O_NONBLOCK on the open file descriptions of stdout and
// stderr when it is set (blockingOutput; task 15n finding 1); it is
// called before every clear and every share line, in the abort path
// before every attempt of a clear. A stand-in of the tests has none.
//
// Clearing it changes the open file description, which the program
// shares with whoever handed it the terminal (the shell, a job of that
// shell in the background). That is done on purpose: the flag is no
// state of the program's own, it comes only from another program, and
// with it a clear fails at once (EAGAIN) on a terminal that takes
// nothing for a moment, and a share stays on the screen; a ceremony
// owns its terminal while it runs (it switches the echo and the flow
// control of the same terminal for everybody as well). A program that
// relies on O_NONBLOCK on a terminal sets it on each use (an interactive
// shell clears it itself before it reads); it is not restored at the
// end, which would hand the terminal back in the state another program
// left to keep a clear off the screen.
func (t *term) unblock() {
	for _, w := range []io.Writer{t.e.stdout, t.e.stderr} {
		if f, ok := w.(*os.File); ok {
			blockingOutput(f.Fd())
		}
	}
}

// errOutputStuck reports a write that did not return within
// outputGrace (push).
var errOutputStuck = errors.New("Ausgabe hängt")

// push runs write, with t.out held by the caller, and waits for it
// until deadline (outputGrace after the write began, or after the share
// line before it: stallEnd), while the output of the terminals of wakes
// is restarted every wakeEvery (waking; task 15n finding 2). It returns
// the error of write, or errOutputStuck when write did not return in
// time. push releases t.out once write has returned: at once, or, when
// it did not return in time, from the goroutine that runs it (never, if
// it never returns; the abort path does not wait for it longer than
// abortDrain and abortWait).
func (t *term) push(deadline time.Time, write func() error, wakes ...func(bool) error) error {
	done := make(chan error, 1)
	go func() { done <- write() }()
	stop := t.waking(wakes...)
	defer stop()
	grace := time.NewTimer(max(time.Until(deadline), 0))
	defer grace.Stop()
	select {
	case err := <-done:
		<-t.out
		return err
	case <-grace.C:
		go func() {
			<-done
			<-t.out
		}()
		return errOutputStuck
	}
}

// errPromptLost names why the abort path ran after promptLost.
var errPromptLost = errors.New("die Standardfehlerausgabe nimmt nichts mehr an (Schreibfehler, etwa Pipe ohne Leser): Eingabeaufforderungen wären nicht zu sehen")

// errScreenLost names why the abort path ran after screenLost.
var errScreenLost = errors.New("der Bildschirm nimmt nichts mehr an (Schreibfehler oder angehaltene Ausgabe): kein Anteil darf stehen bleiben")

// prompt writes a prompt or a message of the term to stderr (task 15i).
// A write error before the commit takes the abort path at once
// (promptLost), whatever the error (task 15m point 3: EPIPE of a pipe
// without a reader, EFBIG of a file at RLIMIT_FSIZE, EIO, ENOSPC, EBADF,
// ...): nobody sees this prompt, and maybe no later one; waiting for an
// answer would leave a share on the screen with nobody asked to note it,
// or call a holder nobody saw called. After the commit a write error is
// ignored (promptLost). Every write of the term to stderr between
// openTerm and finish goes through prompt. It holds t.out, as the writes
// to the screen do, and writes nothing once the abort path runs: no
// prompt appears behind the clear and the last line of the abort path
// (a prompt written while the abort path waits for t.out comes before
// the clear).
//
// While a share is on the screen (visible) a prompt follows the rule of
// the clears (task 15n finding 2): the output of the terminal of stderr
// is restarted, the prompt written, and the output restarted again every
// wakeEvery while it does not return (push); one that does not get
// through within outputGrace (counted, for the prompt right after a
// share line, from the start of the share line: stallEnd) is lost as one
// that fails: the abort path
// clears stdout first and ends the program (promptLost), before an
// answer is waited for that nobody was asked for. Without a share on
// the screen a prompt that blocks keeps the ceremony waiting as before;
// a signal ends it then.
func (t *term) prompt(format string, args ...any) {
	t.out <- struct{}{}
	if t.dead.Load() {
		<-t.out
		return
	}
	msg := fmt.Sprintf(format, args...)
	var err error
	if t.visible.Load() {
		deadline := time.Now().Add(outputGrace)
		if !t.stallEnd.IsZero() {
			if t.stallEnd.Before(deadline) {
				deadline = t.stallEnd
			}
			t.stallEnd = time.Time{}
		}
		err = t.push(deadline, func() error {
			if t.errWake != nil {
				t.errWake(false)
			}
			_, err := io.WriteString(t.e.stderr, msg)
			return err
		}, t.errWake)
	} else {
		_, err = io.WriteString(t.e.stderr, msg)
		<-t.out
	}
	if err != nil {
		t.promptLost()
	}
}

// promptLost ends the ceremony through the abort path after a prompt
// failed: before the commit, the screen is cleared, the terminal
// restored, nothing is written, exit code 130. It does not return then.
// Once the files are written (deferred) or the ceremony is complete
// (committed, closed) a lost prompt changes nothing: no share is shown
// or asked any more, and the ceremony ends as documented.
func (t *term) promptLost() {
	t.mu.Lock()
	if t.closed || t.deferred || t.committed {
		t.mu.Unlock()
		return
	}
	t.lost = true
	t.abort()
}

// screenLost ends the ceremony through the abort path after a clear or a
// share line failed or did not get through within outputGrace (task 15n
// findings 1 and 2), as promptLost does: before the commit, the abort
// path clears the screen with discarding, restores the terminal, writes
// nothing and exits with code 130; it does not return then. A share line
// written in part counts as shown. Once the files are written or the
// command is closed it changes nothing: no share is on the screen then.
func (t *term) screenLost() {
	t.mu.Lock()
	if t.closed || t.deferred || t.committed {
		t.mu.Unlock()
		return
	}
	t.blocked = true
	t.abort()
}

// flowRestores returns the restores of the flow control that are still
// due, of stderr, of stdout and then of stdin, the reverse order of
// openTerm (on one terminal reached through two devices the attributes
// of before openTerm come back last), and clears them. t.mu is held.
func (t *term) flowRestores() []func() error {
	var rs []func() error
	for _, p := range []*func() error{&t.errFlowRestore, &t.outFlowRestore, &t.flowRestore} {
		if *p != nil {
			rs = append(rs, *p)
			*p = nil
		}
	}
	return rs
}

// restoreFlow restores the flow control of stderr, of stdout and then of
// stdin (flowRestores). t.mu is held.
func (t *term) restoreFlow() {
	for _, r := range t.flowRestores() {
		r()
	}
}

// errDead refuses a share line once the abort path runs.
var errDead = errors.New("Bildschirm nach dem Abbruch gesperrt")

// display is the Display of the ceremony: every share line is written
// while t.out is held, and none once the abort path runs (task 10c
// finding 4, task 15b point 0b). A share line is written as a clear is
// (task 15n findings 1 and 2): O_NONBLOCK cleared, the output of stdout
// restarted, the line written and the output restarted every wakeEvery
// while it does not return (push). From the moment it is written it
// counts as shown (visible), also when only a part gets through; one
// that fails, whatever the error, or does not get through within
// outputGrace ends the ceremony through the abort path (screenLost),
// which clears it.
type display struct{ t *term }

func (d display) Write(p []byte) (int, error) {
	t := d.t
	t.out <- struct{}{}
	if t.dead.Load() {
		<-t.out
		return 0, errDead
	}
	t.unblock()
	t.visible.Store(true)
	t.stallEnd = time.Now().Add(outputGrace)
	var n int
	err := t.push(t.stallEnd, func() error {
		if t.outWake != nil {
			t.outWake(false)
		}
		var err error
		n, err = t.e.stdout.Write(p)
		return err
	}, t.outWake)
	if err != nil {
		t.screenLost()
		if errors.Is(err, errOutputStuck) {
			return 0, err // n is still the write's own
		}
		return n, err
	}
	return n, nil
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

// clear writes clearScreen to stdout, and then to stderr when that is
// another terminal (errTerm): the prompts and messages are there, and,
// when stdin is that terminal, the echo of anything typed while the echo
// is on (task 15b point 6). stdout comes first (task 15l point 1): it is
// the terminal that shows the shares, and a stderr that blocks must not
// keep a share on the screen. t.out is held. It returns the first write
// error, a part written included (task 15n finding 1); once the clear
// of stdout is written completely no share is on the screen (visible
// cleared). The command (wipe) runs it bounded and waits for both
// writes, so that no share line overtakes a clear; the abort path writes
// each one bounded (abort).
//
// Before the clears O_NONBLOCK is cleared on stdout and stderr (unblock,
// task 15n finding 1), and before each one the output of that terminal
// runs again (outWake, errWake without discarding; task 15m point 2): a
// terminal stopped by TCOOFF, by an XOFF or by Scroll Lock on the Linux
// console would keep the clear, and with it the command, waiting with a
// share on the screen, also after the commit point, when a signal no
// longer ends the program.
func (t *term) clear() error {
	t.unblock()
	if t.outWake != nil {
		t.outWake(false)
	}
	if err := t.clearOut(); err != nil {
		return err
	}
	t.visible.Store(false)
	if t.errTerm {
		if t.errWake != nil {
			t.errWake(false)
		}
		return t.clearErr()
	}
	return nil
}

// clearOut writes clearScreen to stdout; every write error is returned,
// also after a part was written (task 15n finding 1).
func (t *term) clearOut() error {
	_, err := io.WriteString(t.e.stdout, clearScreen)
	return err
}

// clearErr writes clearScreen to stderr, as clearOut does.
func (t *term) clearErr() error {
	_, err := io.WriteString(t.e.stderr, clearScreen)
	return err
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
//
// Before the commit the clear is bounded (push, task 15n findings 1 and
// 2): the output of stdout and stderr is restarted every wakeEvery while
// it does not return, and a clear that fails (any write error, a part
// written included) or does not get through within outputGrace ends the
// ceremony through the abort path (screenLost), which discards the
// output not yet sent and clears again: wipe returns only once the clear
// of a share is written completely, and the next holder is never called
// before. Once the files are written or the command closed, no share is
// on the screen any more: the clear is waited for as before, and an
// error changes nothing.
func (t *term) wipe() {
	// Only the command itself moves on to the commit or closes, the
	// goroutine that calls wipe: normal is asked before t.out is taken,
	// so that wipe never waits for t.mu while it holds t.out.
	normal := t.normal()
	t.out <- struct{}{}
	if t.dead.Load() {
		<-t.out
		return
	}
	if !normal {
		t.clear()
		<-t.out
		return
	}
	var wakes []func(bool) error
	if t.errTerm {
		wakes = append(wakes, t.errWake)
	}
	t.stallEnd = time.Time{}
	if err := t.push(time.Now().Add(outputGrace), t.clear, append(wakes, t.outWake)...); err != nil {
		t.screenLost()
	}
}

// normal reports whether the command runs before its commit and is not
// closed: a write that fails or blocks then takes the abort path.
func (t *term) normal() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closed && !t.deferred && !t.committed
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

// close restores the terminal (echo, then flow control; none of the
// requests waits, task 15m point 1) and ends the
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
// (TestPTYSignalSalvo found it). SIGPIPE stays taken in as well
// (lostOutput, task 15i): a message on a stderr without a reader after close (the
// results of a complete ceremony, a late signal, an error) is lost, but
// does not end the program before its exit code.
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

// settle waits until the holder of a share on the screen confirms
// (confirm), and clears the screen in any case.
func (t *term) settle() error {
	var err error
	if t.shown {
		t.shown = false
		err = t.confirm("Anteil notiert? Eingabetaste löscht den Bildschirm: ")
	}
	t.wipe()
	return err
}

// earlyHint goes before a prompt asked again because input arrived
// before confirmDelay had passed (confirm); it shows no share.
const earlyHint = "Eingabe zu früh, bitte erneut bestätigen.\n"

// confirm asks with the prompt format and args for a confirmation (an
// Enter) and reads it (task 15n finding 3), for every prompt that calls
// a holder before a share is shown (Handover) or that clears a share
// once its holder noted it (settle). An input counts only when it
// arrives at least confirmDelay after the prompt was written completely:
// confirm waits confirmDelay after the prompt, then looks whether input
// arrived meanwhile (on the terminal, pending, and in the read buffer),
// then discards all of it, on the terminal (flushInput, which waits for
// nothing, task 15m point 1) and in the read buffer (scrubInput), and
// only then reads. When input had arrived, the prompt is asked once more
// with earlyHint before it, and the wait begins again. So an Enter typed
// twice, the second up to confirmDelay after the first, answers neither
// this prompt nor the next: it is discarded, and the holder is asked
// again (task 10e finding 4 discarded the input typed ahead only before
// the prompt, and a second Enter more than a few tenths of a millisecond
// after the first answered the prompt for the next holder).
//
// What arrives in the short time between the look and the discard is
// discarded without the hint, and a line not yet complete is not seen
// by the look (the terminal counts complete lines in canonical mode)
// but discarded all the same: either way nothing is taken as a
// confirmation that came too early, and the holder presses Enter again.
func (t *term) confirm(format string, args ...any) error {
	if t.ctl == nil {
		return errNoTerminal
	}
	hint := ""
	for {
		t.prompt(hint+format, args...)
		time.Sleep(confirmDelay)
		early := t.e.stdin.Buffered() > 0
		if t.ctl.pending != nil {
			n, err := t.ctl.pending()
			if err != nil {
				return fmt.Errorf("Eingabe des Terminals lässt sich nicht prüfen: %w", err)
			}
			early = early || n > 0
		}
		if err := t.ctl.flush(); err != nil {
			return fmt.Errorf("Eingabe des Terminals lässt sich nicht verwerfen: %w", err)
		}
		t.e.scrubInput()
		if !early {
			break
		}
		hint = earlyHint
	}
	_, err := t.e.readLine()
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

// Handover calls the holder of share i. Only an Enter that arrives
// confirmDelay after the prompt counts (confirm, task 15n finding 3);
// what arrived before, typed ahead or a second Enter at "Anteil
// notiert?", is discarded on the terminal and in the read buffer (task
// 10e finding 4) and does not answer this prompt, and share i is shown
// only once its holder confirmed.
func (t *term) Handover(i, n int) error {
	if err := t.settle(); err != nil {
		return err
	}
	if err := t.confirm("Inhaber von Anteil %d von %d an den Bildschirm, dann Eingabetaste: ", i, n); err != nil {
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
			t.prompt("%s\n", msg)
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
		t.prompt("Anteil Nr. %d eingeben (30 Wörter, auch über mehrere Zeilen, ohne Anzeige; %s):\n", want, abortHint)
	} else {
		t.prompt("Anteil eingeben (30 Wörter, auch über mehrere Zeilen, ohne Anzeige; %s):\n", abortHint)
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
			t.prompt("(%d von %d Wörtern)\n", len(ws), shamir.ShareWords)
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
		return e.refuse(err)
	}
	t, err := e.openTerm()
	if err != nil {
		return e.fail(err)
	}
	t.prompt("Zeremonie %s: Die Anteile erscheinen nacheinander nur auf diesem Bildschirm.\n", sh)
	t.clockHint("Zertifikate")
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
func (t *term) clockHint(what string) {
	t.prompt("Uhr dieses Rechners: %s; sie bestimmt valid_from der %s. "+
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
		return e.refuse(err)
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
		return e.refuse(err)
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
		return e.refuse(err)
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
		t.clockHint("Nachfolge")
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
