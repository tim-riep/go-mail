package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// tty plays the operator and the share holders: it answers every prompt
// the tool writes to stderr, from the shares the tool showed on stdout.
type tty struct {
	shares  map[int]string // index -> line of words as shown
	queue   []string       // input lines for "Anteil eingeben"
	answer  func(want int) string
	in      bytes.Buffer
	out     bytes.Buffer // everything on stdout
	msgs    bytes.Buffer // everything on stderr
	screen  bytes.Buffer // stdout, stderr and the input of stdin, in order
	clears  int
	prompts int
	typed   []string // every share line read from stdin

	// stdin as a stand-in terminal (task 10c finding 1)
	inNoTerminal bool  // stdin is not a terminal
	echoFails    error // the echo cannot be switched off
	echoOff      bool  // the echo is off
	flowOff      bool  // the flow control is off
	flushes      int   // input discarded (flushInput)
	echoed       int   // share lines read while the echo was on
	reads        int   // reads from stdin

	// events in order (task 10c finding 5): "share" (a share line on
	// stdout), "clear", "confirm" (the prompt "Anteil notiert?"),
	// "prompt" (another prompt) and "input" (a read from stdin).
	events []string
}

type ttyOut struct{ *tty }
type ttyErr struct{ *tty }
type ttyIn struct{ *tty }

func newTTY() *tty { return &tty{shares: map[int]string{}} }

// terminal makes stdout a stand-in terminal (isTerminal).
func (t ttyOut) terminal() bool { return true }

// terminal and disableEcho make stdin a stand-in terminal whose echo
// the command switches (echoStandIn). Whatever the echo, the stand-in
// records the input on the screen (as a terminal that echoes locally
// would), so that the clearing of typed shares stays checked; a share
// line read while the echo is on is counted in echoed.
func (t ttyIn) terminal() bool { return !t.inNoTerminal }

func (t ttyIn) disableEcho() (func() error, error) {
	if t.echoFails != nil {
		return nil, t.echoFails
	}
	t.echoOff = true
	return func() error {
		t.echoOff = false
		return nil
	}, nil
}

// disableFlow and flushInput complete the stand-in terminal: the flow
// control is recorded, the input not read yet is discarded.
func (t ttyIn) disableFlow() (func() error, error) {
	t.flowOff = true
	return func() error {
		t.flowOff = false
		t.events = append(t.events, "flow-restore")
		return nil
	}, nil
}

func (t ttyIn) flushInput() error {
	t.flushes++
	t.in.Reset()
	return nil
}

func (t ttyOut) Write(p []byte) (int, error) {
	t.out.Write(p)
	t.screen.Write(p)
	s := string(p)
	if strings.Contains(s, "\033[2J") {
		t.clears++
		t.events = append(t.events, "clear")
	}
	var i, n int
	if head, rest, ok := strings.Cut(strings.TrimSuffix(s, "\n"), ": "); ok {
		if _, err := fmt.Sscanf(head, "Anteil %d/%d", &i, &n); err == nil {
			t.shares[i] = rest
			t.events = append(t.events, "share")
		}
	}
	return len(p), nil
}

func (t ttyErr) Write(p []byte) (int, error) {
	t.msgs.Write(p)
	t.screen.Write(p)
	s := string(p)
	var want int
	switch {
	case strings.HasPrefix(s, "Anteil notiert?"):
		t.events = append(t.events, "confirm")
	case strings.HasPrefix(s, "Inhaber von Anteil"), strings.HasPrefix(s, "Anteil Nr."), strings.HasPrefix(s, "Anteil eingeben"):
		t.events = append(t.events, "prompt")
	}
	switch {
	case strings.HasPrefix(s, "Inhaber von Anteil"), strings.HasPrefix(s, "Anteil notiert?"):
		t.prompts++
		t.in.WriteString("\n")
	case strings.HasPrefix(s, "Anteil Nr."):
		fmt.Sscanf(s, "Anteil Nr. %d", &want)
		if t.answer != nil {
			t.in.WriteString(t.answer(want))
			break
		}
		// Typed sloppily: upper case and split over two lines.
		ws := strings.Fields(t.shares[want])
		t.in.WriteString("  " + strings.ToUpper(strings.Join(ws[:12], "  ")) + "\n\t" + strings.Join(ws[12:], " ") + "\r\n")
	case strings.HasPrefix(s, "Anteil eingeben"):
		if t.answer != nil {
			t.in.WriteString(t.answer(0))
			break
		}
		if len(t.queue) > 0 {
			t.in.WriteString(t.queue[0] + "\n")
			t.queue = t.queue[1:]
		}
	}
	return len(p), nil
}

// Read echoes what it returns, as a terminal in cooked mode with echo
// does.
func (t ttyIn) Read(p []byte) (int, error) {
	t.reads++
	if t.in.Len() == 0 {
		return 0, io.EOF
	}
	n, err := t.in.Read(p)
	t.screen.Write(p[:n])
	t.events = append(t.events, "input")
	for _, line := range strings.Split(string(p[:n]), "\n") {
		if len(strings.Fields(line)) >= 3 {
			t.typed = append(t.typed, line)
			if !t.echoOff {
				t.echoed++
			}
		}
	}
	return n, err
}

// checkConfirm checks the events of a run (task 10c finding 5): every
// share line shown is followed, before the next clear, by exactly one
// prompt "Anteil notiert?" and then one input, and by nothing else; and
// no share line was read while the echo was on.
func (t *tty) checkConfirm(tb testing.TB) {
	tb.Helper()
	if t.echoed != 0 {
		tb.Fatalf("%d share lines read with the echo on", t.echoed)
	}
	shares := 0
	for i, ev := range t.events {
		if ev != "share" {
			continue
		}
		shares++
		j := i + 1
		for j < len(t.events) && t.events[j] != "clear" {
			j++
		}
		if j == len(t.events) {
			tb.Fatalf("share %d never cleared: %v", shares, t.events[i:])
		}
		if got := strings.Join(t.events[i+1:j], " "); got != "confirm input" {
			tb.Fatalf("share %d: between the share and the clear %q, want \"confirm input\"", shares, got)
		}
	}
	if shares != len(t.shares) {
		tb.Fatalf("%d share events, %d shares", shares, len(t.shares))
	}
}

// fixClock sets the clock of the program to 2026-10-01 for the test.
func fixClock(tb testing.TB) {
	now = func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }
	tb.Cleanup(func() { now = time.Now })
}

// holderPrompts are the prompts that call a holder to the screen.
var holderPrompts = []string{"Inhaber von Anteil", "Anteil Nr.", "Anteil eingeben"}

// checkScreen checks a transcript of the screen (what was written and
// echoed, in order, task 10b finding 1): every occurrence of a share
// (its first and last three words, as shown or as typed in upper case)
// is cleared before any holder is called to the screen again and before
// the command ends, and the screen was cleared at least minClears times.
func checkScreen(t *testing.T, screen string, shares []string, minClears int) {
	t.Helper()
	if n := strings.Count(screen, clearScreen); n < minClears {
		t.Fatalf("%d clears, want at least %d", n, minClears)
	}
	for _, sh := range shares {
		ws := strings.Fields(sh)
		if len(ws) < 6 {
			t.Fatalf("not a share: %q", sh)
		}
		head, tail := strings.Join(ws[:3], " "), strings.Join(ws[len(ws)-3:], " ")
		for _, probe := range []string{head, strings.ToUpper(head), tail, strings.ToUpper(tail)} {
			for off := 0; ; {
				i := strings.Index(screen[off:], probe)
				if i < 0 {
					break
				}
				i += off
				c := strings.Index(screen[i:], clearScreen)
				if c < 0 {
					t.Fatalf("share %q... still on the screen at the end", head)
				}
				for _, p := range holderPrompts {
					if strings.Contains(screen[i:i+c], p) {
						t.Fatalf("share %q... on the screen when %q is asked", head, p)
					}
				}
				off = i + 1
			}
		}
	}
}

// shareLines returns the share lines of m.
func shareLines(m map[int]string) []string {
	var l []string
	for _, s := range m {
		l = append(l, s)
	}
	return l
}

// run runs the command in this process. After close the abort signals
// stay taken in and discarded (task 15b point 0a); the test process gets
// their default back afterwards.
func (t *tty) run(args ...string) int {
	defer signal.Reset(abortSignals...)
	return run(args, ttyIn{t}, ttyOut{t}, ttyErr{t})
}

func witnessArg(t *testing.T, name string) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return name + "=" + vkey
}

// filesHold reports whether a file under dir contains s.
func filesHold(t *testing.T, dir, s string) bool {
	t.Helper()
	found := false
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(s)) {
				found = true
			}
		}
		return nil
	})
	return found
}

func TestCeremony(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	w1 := witnessArg(t, "w1")
	tt := newTTY()
	if code := tt.run("init", "--shares", "3-of-5", "--out", out, "--keys", kd, "--origin", "go-mail.test/log",
		"--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatalf("init: %d\n%s", code, tt.msgs.String())
	}
	// Five shares shown and three typed: at least nine clears, and none
	// of them stays on the screen.
	if len(tt.shares) != 5 || tt.clears < 5+3+1 || len(tt.typed) < 3 {
		t.Fatalf("%d shares, %d clears, %d typed", len(tt.shares), tt.clears, len(tt.typed))
	}
	checkScreen(t, tt.screen.String(), shareLines(tt.shares), 5+3+1)
	tt.checkConfirm(t)
	if i, j := strings.LastIndex(tt.out.String(), clearScreen), strings.Index(tt.out.String(), "Exportverzeichnis:"); j < i {
		t.Fatal("results before the last clear")
	}
	for i, line := range tt.shares {
		if len(strings.Fields(line)) != 30 {
			t.Fatalf("share %d has %d words", i, len(strings.Fields(line)))
		}
		// Never in a file, and never in a message.
		if filesHold(t, base, line) || filesHold(t, base, strings.Fields(line)[0]+" "+strings.Fields(line)[1]) ||
			strings.Contains(tt.msgs.String(), strings.Fields(line)[0]+" "+strings.Fields(line)[1]) {
			t.Fatalf("share %d leaked", i)
		}
	}
	if !strings.Contains(tt.out.String(), "Probe-Rekonstruktion erfolgreich") {
		t.Fatal(tt.out.String())
	}
	pinPath := filepath.Join(out, "identity-1.pin")
	pin, err := ceremony.ReadPin(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	shares := tt.shares

	// ingest-rotate with three holders.
	rot := filepath.Join(base, "rot")
	tt = newTTY()
	tt.queue = []string{shares[5], strings.ToUpper(shares[1]), shares[3]}
	if code := tt.run("ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", rot, "--keys", kd, "--valid-from", "2026-11-01T00:00:00Z"); code != 0 {
		t.Fatalf("ingest-rotate: %d\n%s", code, tt.msgs.String())
	}
	checkScreen(t, tt.screen.String(), shareLines(shares), 3+1)
	tt.checkConfirm(t)
	data, _ := os.ReadFile(filepath.Join(rot, "platform", "ingest-2.cert"))
	cert, err := keys.DecodePlatformCert(data)
	if err != nil || cert.Verify(pin.Pub) != nil || cert.ValidFrom != 1_793_491_200_000 {
		t.Fatalf("certificate: %v", err)
	}

	// reshare 2-of-3; the new shares rebuild the same root (checked by
	// succeed below, which unlocks with two of them).
	tt = newTTY()
	tt.queue = []string{shares[2], shares[4], shares[5]}
	if code := tt.run("reshare", "--pin", pinPath, "--shares", "2-of-3"); code != 0 {
		t.Fatalf("reshare: %d\n%s", code, tt.msgs.String())
	}
	if len(tt.shares) != 3 || !strings.Contains(tt.out.String(), "nicht widerrufen") {
		t.Fatal("reshare output")
	}
	// Three old shares typed, three new shown, two typed back.
	checkScreen(t, tt.screen.String(), append(shareLines(shares), shareLines(tt.shares)...), 3+3+2+1)
	tt.checkConfirm(t)
	newShares := tt.shares

	// succeed takes origin, witnesses and quorum from the pin; --origin
	// is only a check and must not differ.
	succ := filepath.Join(base, "succ")
	tt = newTTY()
	tt.queue = []string{newShares[3], newShares[1]}
	if code := tt.run("succeed", "--pin", pinPath, "--out", succ, "--origin", "another.test/log"); code != 1 ||
		!strings.Contains(tt.msgs.String(), "Origin") || len(tt.typed) != 0 {
		t.Fatalf("succeed with another origin: %d\n%s", code, tt.msgs.String())
	}
	tt = newTTY()
	tt.queue = []string{newShares[3], newShares[1]}
	if code := tt.run("succeed", "--pin", pinPath, "--out", succ); code != 0 {
		t.Fatalf("succeed: %d\n%s", code, tt.msgs.String())
	}
	checkScreen(t, tt.screen.String(), shareLines(newShares), 2+1)
	tt.checkConfirm(t)
	if !strings.Contains(tt.msgs.String(), "Uhr dieses Rechners: 2026-10-01T12:00:00Z") {
		t.Fatalf("no clock before the first prompt: %q", tt.msgs.String())
	}
	data, _ = os.ReadFile(filepath.Join(succ, "platform", "identity-2.succ"))
	s, err := keys.DecodePlatformSuccession(data)
	if err != nil || s.Verify(pin.Pub, 1) != nil {
		t.Fatal("succession")
	}
	pin2Path := filepath.Join(succ, "identity-2.pin")
	pin2, err := ceremony.ReadPin(pin2Path)
	if err != nil {
		t.Fatal(err)
	}
	if pin2.Gen != 2 || !pin2.Pub.Equal(s.Pub) || pin2.Origin != pin.Origin || pin2.MinWitnesses != pin.MinWitnesses ||
		len(pin2.Witnesses) != 1 || pin2.Witnesses[0].Name != "w1" || !pin2.Witnesses[0].Pub.Equal(pin.Witnesses[0].Pub) ||
		len(pin2.Identities) != 2 || !pin2.Identities[0].Pub.Equal(pin.Pub) || !pin2.Identities[1].Pub.Equal(s.Pub) {
		t.Fatalf("pin 2 %+v", pin2)
	}

	// publish into the operator log of the data directory: init and
	// ingest-rotate with pin 1; the succession needs pin 2 (Q10 point 5).
	dataDir := filepath.Join(base, "data")
	if _, err := store.Init(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, from := range []string{out, rot} {
		tt = newTTY()
		if code := tt.run("publish", "--from", from, "--data", dataDir, "--pin", pinPath); code != 0 {
			t.Fatalf("publish %s: %d\n%s", from, code, tt.msgs.String())
		}
		if !strings.Contains(tt.out.String(), "Server jetzt mit diesem Pin starten") {
			t.Fatalf("publish: %q", tt.out.String())
		}
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pinPath); code != 1 || !strings.Contains(tt.msgs.String(), "install the new pin") {
		t.Fatalf("succession with the old pin: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path); code != 0 {
		t.Fatalf("publish %s: %d\n%s", succ, code, tt.msgs.String())
	}
	if got := logNames(t, dataDir, pin2); fmt.Sprint(got) != "[admin-1.cert ingest-1.cert ingest-2.cert identity-2.succ]" {
		t.Fatalf("log %v", got)
	}
	// From now on platform/ names generation 2: the old pin is refused.
	tt = newTTY()
	if tt.run("publish", "--from", out, "--data", dataDir, "--pin", pinPath) != 1 {
		t.Fatal("publish with the old pin after the succession")
	}
	// While a server holds the server lock, publish refuses.
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", pin2Path); code != 1 || !strings.Contains(tt.msgs.String(), "Server läuft") {
		t.Fatalf("publish beside a server: %d %s", code, tt.msgs.String())
	}
	release()
	tt = newTTY()
	if tt.run("publish", "--from", out, "--data", filepath.Join(base, "nodata"), "--pin", pinPath) != 1 {
		t.Fatal("publish without data directory")
	}
}

// logNames returns the subjects of the entries of the operator log of
// the data directory dir, in log order.
func logNames(t *testing.T, dir string, pin *store.PlatformPin) []string {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ceremony.OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := int64(0); ; i++ {
		e, err := l.Entry(i)
		if errors.Is(err, translog.ErrNotInLog) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, string(e.Key.Subject))
	}
}

func TestShareInput(t *testing.T) {
	base := t.TempDir()
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	w1 := witnessArg(t, "w1")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-3", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	pinPath := filepath.Join(out, "identity-1.pin")

	// Mistakes are reported by position and asked again.
	ws := strings.Fields(shares[1])
	abbrev := append([]string(nil), ws...)
	abbrev[6] = "zzzzz"
	swapped := append([]string(nil), ws...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if swapped[0] == swapped[1] {
		swapped[2], swapped[3] = swapped[3], swapped[2]
	}
	attempts := []string{strings.Join(ws[:29], " ") + " " + strings.Join(ws, " "), strings.Join(abbrev, " "), strings.Join(swapped, " ")}
	tt = newTTY()
	n := 0
	tt.answer = func(int) string {
		n++
		if n <= len(attempts) {
			return attempts[n-1] + "\n"
		}
		return ""
	}
	if code := tt.run("reshare", "--pin", pinPath, "--shares", "2-of-3"); code != 1 {
		t.Fatal("three failed attempts")
	}
	msgs := tt.msgs.String()
	for _, m := range []string{"genau 30 Wörter, eingegeben wurden 59", "Wort Nr. 7 steht nicht", "Prüfsumme"} {
		if !strings.Contains(msgs, m) {
			t.Fatalf("message %q missing in %s", m, msgs)
		}
	}
	if strings.Contains(msgs, "zzzzz") || strings.Contains(msgs, ws[0]+" "+ws[1]) {
		t.Fatal("words in messages")
	}
	// Refused input is cleared from the screen, also when the command
	// fails.
	checkScreen(t, tt.screen.String(), shareLines(shares), 3+1)
	if !strings.HasSuffix(strings.TrimRight(tt.screen.String(), "\n"), "Fehlversuche") {
		t.Fatalf("error not after the last clear: %q", tt.screen.String()[max(0, tt.screen.Len()-200):])
	}
	// The wrong share index is asked again; then the right one works.
	tt = newTTY()
	n = 0
	tt.answer = func(want int) string {
		n++
		switch {
		case want == 0 && n == 1:
			return shares[1] + "\n"
		case want == 0:
			return shares[3] + "\n"
		case n == 3:
			return tt.shares[want%3+1] + "\n"
		}
		return tt.shares[want] + "\n"
	}
	if code := tt.run("reshare", "--pin", pinPath, "--shares", "2-of-3"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	if !strings.Contains(tt.msgs.String(), "verlangt ist Anteil") {
		t.Fatal("wrong index not reported")
	}
	checkScreen(t, tt.screen.String(), append(shareLines(shares), shareLines(tt.shares)...), 2+3+3+1)
	// A line that is too long, and input that ends.
	tt = newTTY()
	tt.queue = []string{strings.Repeat("abandon ", maxLine/8+1)}
	if tt.run("reshare", "--pin", pinPath, "--shares", "2-of-3") != 1 || !strings.Contains(tt.msgs.String(), "Zeile zu lang") {
		t.Fatal("long line")
	}
	tt = newTTY()
	if tt.run("reshare", "--pin", pinPath, "--shares", "2-of-3") != 1 || !strings.Contains(tt.msgs.String(), "keine Eingabe") {
		t.Fatal("end of input")
	}
	// Shares that do not belong to the pin.
	other := filepath.Join(base, "o2")
	tt = newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", other, "--keys", filepath.Join(base, "k2"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	tt2 := newTTY()
	tt2.queue = []string{shares[1], shares[2]}
	if tt2.run("reshare", "--pin", filepath.Join(other, "identity-1.pin"), "--shares", "2-of-3") != 1 ||
		!strings.Contains(tt2.msgs.String(), "do not belong") {
		t.Fatal(tt2.msgs.String())
	}
}

func TestUsage(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	_, vkey2, _ := note.GenerateKey(rand.Reader, "w2")
	devPin := filepath.Join(base, "dev.pin")
	b, _ := (&store.PlatformPin{Gen: 1, Pub: make([]byte, 32), Dev: true}).Encode()
	os.WriteFile(devPin, b, 0o600)
	o, k := filepath.Join(base, "o"), filepath.Join(base, "k")
	initArgs := []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", w1, "--min-witnesses", "1"}
	for _, c := range []struct {
		code int
		args []string
	}{
		{2, []string{"init"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", w1}},
		{2, append(append([]string(nil), initArgs...), "--data", "d")},
		{2, append(append([]string(nil), initArgs[:2]...), "1-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", w1, "--min-witnesses", "1")},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", "w1=" + vkey2, "--min-witnesses", "1"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", "w1", "--min-witnesses", "1"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", strings.Repeat("x", 300), "--min-witnesses", "1"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", "w1=w1+00000000+AAAA", "--min-witnesses", "1"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", "w1=" + strings.Replace(strings.TrimPrefix(w1, "w1="), "+", "+0", 1), "--min-witnesses", "1"}},
		{2, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", "a b=x", "--min-witnesses", "1"}},
		{1, []string{"init", "--shares", "3-of-5", "--out", o, "--keys", k, "--origin", "o", "--witness", w1, "--min-witnesses", "2"}},
		{2, []string{"ingest-rotate", "--pin", devPin}},
		{2, []string{"ingest-rotate", "--pin", devPin, "--gen", "x", "--out", o, "--keys", k, "--valid-from", "2026-11-01T00:00:00Z"}},
		{2, []string{"ingest-rotate", "--pin", devPin, "--gen", "2", "--out", o, "--keys", k, "--valid-from", "morgen"}},
		{1, []string{"ingest-rotate", "--pin", devPin, "--gen", "2", "--out", o, "--keys", k, "--valid-from", "2026-11-01T00:00:00Z"}},
		{1, []string{"ingest-rotate", "--pin", filepath.Join(base, "missing"), "--gen", "2", "--out", o, "--keys", k, "--valid-from", "2026-11-01T00:00:00Z"}},
		{2, []string{"reshare", "--pin", devPin}},
		{2, []string{"reshare", "--pin", devPin, "--shares", "5-of-3"}},
		{1, []string{"reshare", "--pin", devPin, "--shares", "2-of-3"}},
		{2, []string{"succeed", "--pin", devPin}},
		{1, []string{"succeed", "--pin", devPin, "--out", o}},
		{1, []string{"succeed", "--pin", devPin, "--out", o, "--origin", "o", "--witness", w1, "--min-witnesses", "1"}},
		{2, []string{"succeed", "--pin", devPin, "--out", o, "--compromised"}},
		{2, []string{"publish", "--from", o, "--replace-witnesses"}},
		{2, []string{"publish", "--from", o}},
		{1, []string{"publish", "--from", o, "--data", base, "--pin", devPin}},
		{2, []string{"bogus"}},
	} {
		tt := newTTY()
		if got := tt.run(c.args...); got != c.code {
			t.Fatalf("%v: %d, want %d\n%s", c.args, got, c.code, tt.msgs.String())
		}
	}
	if _, err := os.Stat(o); err == nil {
		t.Fatal("export written by a refused command")
	}
}

// TestNoTerminal: every command that shows or reads shares (init,
// reshare, ingest-rotate, succeed) refuses when standard output is not
// a terminal (a pipe, a file, a buffer), when standard input is not a
// terminal (a pipe, a file, a reader) while standard output is one, and
// when the echo of standard input cannot be switched off; before
// anything is shown, read or written (task 10b finding 1c, task 10c
// finding 1).
func TestNoTerminal(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	// A real ceremony for a pin.
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	pinPath := filepath.Join(out, "identity-1.pin")
	shares := tt.shares
	answers := strings.Repeat("\n", 20) + shares[1] + "\n" + shares[2] + "\n"
	inPath := filepath.Join(base, "stdin")
	if err := os.WriteFile(inPath, []byte(answers), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile, err := os.Create(filepath.Join(base, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	o2 := filepath.Join(base, "o2")
	for _, args := range [][]string{
		{"init", "--shares", "3-of-5", "--out", o2, "--keys", filepath.Join(base, "k2"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
		{"reshare", "--pin", pinPath, "--shares", "2-of-3"},
		{"ingest-rotate", "--pin", pinPath, "--gen", "2", "--out", o2, "--keys", filepath.Join(base, "keys"), "--valid-from", "2026-11-01T00:00:00Z"},
		{"succeed", "--pin", pinPath, "--out", o2, "--origin", "o", "--witness", w1, "--min-witnesses", "1"},
	} {
		refused := func(what string, code int, msgs string) {
			t.Helper()
			if code != 1 || !strings.Contains(msgs, "nur auf einem Terminal") || !strings.Contains(msgs, "nichts angezeigt, gelesen oder geschrieben") {
				t.Fatalf("%s, %s: %d %q", args[0], what, code, msgs)
			}
			for _, p := range []string{"Inhaber", "Anteil Nr.", "Anteil eingeben", "Anteil notiert", "Zeremonie"} {
				if strings.Contains(msgs, p) {
					t.Fatalf("%s, %s: prompt %q", args[0], what, p)
				}
			}
		}
		// stdout a pipe, a file or a buffer; stdin a terminal.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		in := newTTY()
		in.in.WriteString(answers)
		var errb bytes.Buffer
		code := run(args, ttyIn{in}, w, &errb)
		w.Close()
		piped, _ := io.ReadAll(r)
		r.Close()
		refused("stdout a pipe", code, errb.String())
		if len(piped) != 0 || in.reads != 0 {
			t.Fatalf("%s with a pipe: %q, %d reads", args[0], piped, in.reads)
		}
		errb.Reset()
		refused("stdout a file", run(args, ttyIn{in}, outFile, &errb), errb.String())
		errb.Reset()
		var buf bytes.Buffer
		refused("stdout a buffer", run(args, ttyIn{in}, &buf, &errb), errb.String())
		if buf.Len() != 0 || in.reads != 0 {
			t.Fatalf("%s with a buffer: %q, %d reads", args[0], buf.String(), in.reads)
		}

		// stdout a terminal; stdin a pipe, a file, a reader, a terminal
		// that is none, and a terminal whose echo cannot be switched off.
		term := newTTY()
		r, w, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.WriteString(answers)
		w.Close()
		code = run(args, r, ttyOut{term}, ttyErr{term})
		left, _ := io.ReadAll(r)
		r.Close()
		refused("stdin a pipe", code, term.msgs.String())
		if string(left) != answers {
			t.Fatalf("%s: stdin pipe read", args[0])
		}
		term.msgs.Reset()
		f, err := os.Open(inPath)
		if err != nil {
			t.Fatal(err)
		}
		code = run(args, f, ttyOut{term}, ttyErr{term})
		off, _ := f.Seek(0, io.SeekCurrent)
		f.Close()
		refused("stdin a file", code, term.msgs.String())
		if off != 0 {
			t.Fatalf("%s: stdin file read", args[0])
		}
		term.msgs.Reset()
		sr := strings.NewReader(answers)
		refused("stdin a reader", run(args, sr, ttyOut{term}, ttyErr{term}), term.msgs.String())
		if sr.Len() != len(answers) {
			t.Fatalf("%s: stdin reader read", args[0])
		}
		term.msgs.Reset()
		term.inNoTerminal = true
		term.in.WriteString(answers)
		refused("stdin not a terminal", term.run(args...), term.msgs.String())
		term.msgs.Reset()
		term.inNoTerminal = false
		term.echoFails = errors.New("ECHO bleibt gesetzt")
		refused("echo not switchable", term.run(args...), term.msgs.String())
		if !strings.Contains(term.msgs.String(), "Echo oder Flusssteuerung der Standardeingabe lassen sich nicht abschalten") {
			t.Fatalf("%s: %q", args[0], term.msgs.String())
		}
		if term.out.Len() != 0 || term.reads != 0 || term.echoOff || term.flowOff {
			t.Fatalf("%s: stdout %q, %d reads, echo off %v, flow control off %v", args[0], term.out.String(), term.reads, term.echoOff, term.flowOff)
		}
	}
	if fi, _ := outFile.Stat(); fi.Size() != 0 {
		t.Fatal("output in the file")
	}
	for _, d := range []string{o2, filepath.Join(base, "k2")} {
		if _, err := os.Lstat(d); err == nil {
			t.Fatalf("%s written", d)
		}
	}
	if names, _ := os.ReadDir(filepath.Join(base, "keys")); len(names) != 2 {
		t.Fatalf("keys %v", names)
	}
}

// TestValidFromPast: ingest-rotate refuses --valid-from before the
// clock of the ceremony before a share is asked (task 10c finding 7).
func TestValidFromPast(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	rot := filepath.Join(base, "rot")
	for _, vf := range []string{"2026-09-30T23:59:59Z", "2020-01-01T00:00:00Z", "2026-10-01T11:59:59Z"} {
		tt = newTTY()
		tt.queue = []string{shares[1], shares[2]}
		code := tt.run("ingest-rotate", "--pin", filepath.Join(out, "identity-1.pin"), "--gen", "2", "--out", rot, "--keys", kd, "--valid-from", vf)
		if code != 1 || !strings.Contains(tt.msgs.String(), "before the current time") || len(tt.typed) != 0 {
			t.Fatalf("%s: %d %q", vf, code, tt.msgs.String())
		}
	}
	if _, err := os.Lstat(rot); err == nil {
		t.Fatal("export written")
	}
	// The current time itself and later are fine.
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("ingest-rotate", "--pin", filepath.Join(out, "identity-1.pin"), "--gen", "2", "--out", rot, "--keys", kd,
		"--valid-from", "2026-10-01T12:00:00Z"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
}

// lockedBuffer is a terminal stand-in for stdout that several
// goroutines write to.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) terminal() bool { return true }

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// stubExit replaces exit: the code goes to the channel returned, and
// the calling goroutine ends (as the process would).
func stubExit(tb testing.TB) chan int {
	codes := make(chan int, 1)
	exit = func(code int) {
		codes <- code
		runtime.Goexit()
	}
	tb.Cleanup(func() { exit = os.Exit })
	return codes
}

// TestSignalDisplayRace: a signal while shares are being shown; no
// share line is written after the last clear (task 10c finding 4). The
// display keeps writing share lines in a loop, the signal arrives at a
// random moment; exit does not end the process here, so a display that
// does not hold t.mu would go on writing after the clear.
func TestSignalDisplayRace(t *testing.T) {
	const share = "abandon ability able about above absent absorb abstract absurd abuse"
	for i := 0; i < 50; i++ {
		scr := &lockedBuffer{}
		in := newTTY()
		e := newEnv(ttyIn{in}, scr, io.Discard)
		codes := stubExit(t)
		tm := e.newTerm()
		d := display{tm}
		stop := make(chan struct{})
		go func() {
			for n := 1; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				fmt.Fprintf(d, "Anteil %d/5: %s\n", n%5+1, share)
			}
		}()
		for !strings.Contains(scr.String(), "Anteil") {
			runtime.Gosched()
		}
		time.Sleep(time.Duration(i%5) * 100 * time.Microsecond)
		tm.sig <- os.Interrupt
		if code := <-codes; code != 130 {
			t.Fatalf("exit code %d", code)
		}
		// A display that goes on after the clear would show here.
		time.Sleep(5 * time.Millisecond)
		close(stop)
		got := scr.String()
		last := strings.LastIndex(got, clearScreen)
		if last < 0 || strings.Contains(got[last:], "Anteil") || strings.Contains(got[last:], "abandon") {
			t.Fatalf("run %d: share after the last clear: %q", i, got[max(0, last-100):min(len(got), last+300)])
		}
		signal.Stop(tm.sig)
	}
}

// TestSignalDuringCommit: a signal while the ceremony writes its files
// is deferred (task 10c finding 3). Before the commit point (at
// BeginCommit, or at CommitPoint just before the rename) the files are
// rolled back and the program ends with exit code 130; after the rename
// the ceremony is complete: it reports its results after the last clear
// and that a signal was ignored, with exit code 0; after a rename that
// failed it ends with exit code 130 (task 10e finding 2).
func TestSignalDuringCommit(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	defer func() { commitHook = nil }()
	for _, c := range []struct {
		name     string
		sigAt    string // commitHook point of the signal
		spoilAt  string // commitHook point at which out is taken ("": never)
		complete bool   // the export is complete, exit code 0
	}{
		{"at BeginCommit", "begin", "", false},
		{"at BeginCommit, out taken", "begin", "begin", false},
		{"before the rename", "point", "", false},
		{"after the rename", "end", "", true},
		{"after a failed rename", "end", "point", false},
	} {
		dir := filepath.Join(base, c.sigAt+c.spoilAt)
		out, kd := filepath.Join(dir, "out"), filepath.Join(dir, "keys")
		codes := stubExit(t)
		var tm *term
		commitHook = func(t *term, at string, committed bool) {
			if at == c.spoilAt {
				// out is not empty any more: the rename fails, commit
				// rolls back.
				os.MkdirAll(out, 0o700)
				os.WriteFile(filepath.Join(out, "x"), nil, 0o600)
			}
			if at != c.sigAt {
				return
			}
			tm = t
			t.sig <- os.Interrupt
			for {
				t.mu.Lock()
				p := t.pending || t.late
				t.mu.Unlock()
				if p {
					break
				}
				runtime.Gosched()
			}
		}
		tt := newTTY()
		ret := make(chan int, 1)
		go func() {
			ret <- tt.run("init", "--shares", "2-of-3", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		}()
		select {
		case code := <-codes:
			if c.complete || code != 130 {
				t.Fatalf("%s: exit %d\n%s", c.name, code, tt.msgs.String())
			}
		case code := <-ret:
			if !c.complete || code != 0 {
				t.Fatalf("%s: returned %d\n%s", c.name, code, tt.msgs.String())
			}
		}
		signal.Stop(tm.sig)
		staging, _ := filepath.Glob(filepath.Join(dir, ".tmp-ceremony-*"))
		keys, _ := os.ReadDir(kd)
		if len(staging) != 0 {
			t.Fatalf("%s: staging left %v", c.name, staging)
		}
		exported, _ := os.ReadDir(filepath.Join(out, "platform"))
		screen := tt.screen.String()
		tail := screen[strings.LastIndex(screen, clearScreen)+len(clearScreen):]
		if c.complete {
			if len(keys) != 2 || len(exported) != 6 {
				t.Fatalf("%s: keys %v, export %v", c.name, keys, exported)
			}
			if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(tail, "abgeschlossen; ein Abbruchsignal kam nach dem Commit-Punkt an und wurde ignoriert") ||
				!strings.Contains(tail, "Exportverzeichnis:") || !strings.Contains(tail, "Admin-Schlüssel:") || strings.Contains(screen, "abgebrochen") {
				t.Fatalf("%s: behind the last clear %q", c.name, tail)
			}
		} else {
			if _, err := os.Lstat(kd); err == nil || len(exported) != 0 {
				t.Fatalf("%s: keys %v, export %v", c.name, keys, exported)
			}
			if tail != "gomail-ceremony: abgebrochen\n" || strings.Contains(screen, "Commit-Punkt") {
				t.Fatalf("%s: behind the last clear %q", c.name, tail)
			}
		}
	}
}

// recordingReader serves chunks and keeps the buffer the bufio.Reader
// passed to its first Read (the whole read buffer); at every later Read
// it records whether the buffer still held a non-zero byte.
type recordingReader struct {
	chunks [][]byte
	buf    []byte
	dirty  []bool
}

// terminal and disableEcho make it a stand-in terminal for stdin.
func (r *recordingReader) terminal() bool { return true }

func (r *recordingReader) disableEcho() (func() error, error) {
	return func() error { return nil }, nil
}

func (r *recordingReader) disableFlow() (func() error, error) {
	return func() error { return nil }, nil
}

func (r *recordingReader) flushInput() error { return nil }

func (r *recordingReader) Read(p []byte) (int, error) {
	if r.buf == nil {
		r.buf = p[:cap(p)]
	} else {
		r.dirty = append(r.dirty, bytes.ContainsFunc(r.buf, func(c rune) bool { return c != 0 }))
	}
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

// TestScrubInput: a share typed over two lines is overwritten in the
// read buffer line by line, and the whole buffer is overwritten with
// zeros afterwards, with the input typed ahead (task 10c finding 6).
func TestScrubInput(t *testing.T) {
	ws := strings.Fields(strings.Repeat("abandon ability able ", 10))
	r := &recordingReader{chunks: [][]byte{
		[]byte(strings.Join(ws[:12], " ") + "\n"),
		[]byte(strings.Join(ws[12:], " ") + "\nahead typed\n"),
	}}
	e := newEnv(r, &lockedBuffer{}, io.Discard)
	tm := e.newTerm()
	defer tm.close()
	got, err := tm.readWords(0)
	if err != nil || len(got) != 30 {
		t.Fatal(got, err)
	}
	if len(r.buf) != maxLine {
		t.Fatalf("buffer of %d bytes", len(r.buf))
	}
	// At the second read the first line is overwritten already.
	if len(r.dirty) != 1 || r.dirty[0] {
		t.Fatalf("first line not overwritten: %v", r.dirty)
	}
	if bytes.ContainsFunc(r.buf, func(c rune) bool { return c != 0 }) {
		t.Fatalf("read buffer not overwritten: %q", bytes.Trim(r.buf, "\x00"))
	}
	// stdin is read again afterwards.
	r.chunks = [][]byte{[]byte("\n")}
	if _, err := e.readLine(); err != nil {
		t.Fatal(err)
	}
}

// TestSucceedCompromised: succeed --compromised is locked (task 15f
// point 1, Q19 stopping point 2): a usage error with exit code 2 and the
// fixed text, before the terminal is checked, a share is asked or the
// clock is shown; nothing is written, with or without the other flags.
func TestSucceedCompromised(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1, w2, w3 := witnessArg(t, "w1"), witnessArg(t, "w2"), witnessArg(t, "w3")
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	pin1 := filepath.Join(out, "identity-1.pin")
	succ := filepath.Join(base, "succ")
	const fixed = "noch nicht verfügbar: Widerruf einer Plattformgeneration ist nicht festgelegt (Q19)"
	for _, args := range [][]string{
		{"succeed", "--pin", pin1, "--out", succ, "--compromised"},
		{"succeed", "--pin", pin1, "--out", succ, "--witness", w1, "--witness", w2, "--witness", w3, "--min-witnesses", "2", "--compromised"},
		{"succeed", "--compromised"},
		{"succeed", "--compromised", "--pin", filepath.Join(base, "missing"), "--out", succ},
	} {
		tt = newTTY()
		tt.queue = []string{shares[1], shares[2]}
		code := tt.run(args...)
		if code != exitUsage || !strings.Contains(tt.msgs.String(), fixed) {
			t.Fatalf("%v: %d %s", args, code, tt.msgs.String())
		}
		if len(tt.typed) != 0 || tt.reads != 0 || tt.prompts != 0 || tt.echoOff || tt.flowOff || tt.out.Len() != 0 ||
			strings.Contains(tt.msgs.String(), "Uhr dieses Rechners") {
			t.Fatalf("%v: the terminal was used: %q", args, tt.screen.String())
		}
		if _, err := os.Stat(succ); err == nil {
			t.Fatalf("%v: export written", args)
		}
	}
	// Without the stand-in terminal it is the same usage error.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"succeed", "--pin", pin1, "--out", succ, "--compromised"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage ||
		!strings.Contains(stderr.String(), fixed) {
		t.Fatalf("plain run: %d %s", code, stderr.String())
	}
	// The library refuses it too (ceremony.ErrCompromised), before any
	// share is asked.
	pin, err := ceremony.ReadPin(pin1)
	if err != nil {
		t.Fatal(err)
	}
	p := &countingPrompter{}
	if _, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 1, IdentityPub: pin.Pub, Prompter: p},
		Out: succ, Pin: pin, Compromised: true}); !errors.Is(err, ceremony.ErrCompromised) {
		t.Fatalf("library: %v", err)
	}
	if _, err := os.Stat(succ); err == nil || p.calls != 0 {
		t.Fatal("library: export written or share asked")
	}
}

// countingPrompter counts the calls of a ceremony and gives no share.
type countingPrompter struct{ calls int }

func (p *countingPrompter) Handover(int, int) error { p.calls++; return nil }

func (p *countingPrompter) AskShare(int) ([]string, error) {
	p.calls++
	return nil, errNoInput
}

// TestPublishReplaceWitnesses (task 15f points 2 and 4): a regular
// succession that changes the witnesses on purpose (succeed --witness
// --min-witnesses) shows the clock before the first prompt; publish with
// the new pin refuses the data directory's witnesses.rec of pin 1
// without --replace-witnesses (nothing written or logged) and replaces
// it with the flag, naming the old and the new quorum and witnesses.
// Publishing again with the flag changes nothing.
func TestPublishReplaceWitnesses(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1, w2, w3 := witnessArg(t, "w1"), witnessArg(t, "w2"), witnessArg(t, "w3")
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	pin1Path := filepath.Join(out, "identity-1.pin")
	dataDir := filepath.Join(base, "data")
	if _, err := store.Init(dataDir); err != nil {
		t.Fatal(err)
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", pin1Path); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	before := mustRead(t, filepath.Join(dataDir, "platform", "witnesses.rec"))

	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	succ := filepath.Join(base, "succ")
	if code := tt.run("succeed", "--pin", pin1Path, "--out", succ, "--witness", w1, "--witness", w2,
		"--witness", w3, "--min-witnesses", "2"); code != 0 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	// Point 4: a succession is signed, so the clock is shown, before the
	// first prompt.
	msgs := tt.msgs.String()
	if i, j := strings.Index(msgs, "Uhr dieses Rechners: 2026-10-01T12:00:00Z"), strings.Index(msgs, "Anteil eingeben"); i < 0 || j >= 0 && j < i {
		t.Fatalf("no clock before the first prompt: %q", msgs)
	}
	if got := listFiles(t, succ); got != "[identity-2.pin platform/identity-2.pub platform/identity-2.succ]" {
		t.Fatalf("export %s", got)
	}
	pin2Path := filepath.Join(succ, "identity-2.pin")
	pin2, err := ceremony.ReadPin(pin2Path)
	if err != nil || pin2.MinWitnesses != 2 || len(pin2.Witnesses) != 3 || pin2.Origin != "o" {
		t.Fatalf("pin 2 %+v %v", pin2, err)
	}

	// Without the flag: refused, nothing written or logged.
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "witnesses.rec differs") || !strings.Contains(tt.msgs.String(), "--replace-witnesses") {
		t.Fatalf("publish with other witnesses: %d %s", code, tt.msgs.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "platform", "identity-2.succ")); err == nil {
		t.Fatal("succession copied")
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dataDir, "platform", "witnesses.rec")), before) {
		t.Fatal("witnesses.rec replaced without the flag")
	}
	// With the flag: replaced, and the message names both.
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path, "--replace-witnesses"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	if o := tt.out.String(); !strings.Contains(o, "bisher Quorum 1 von 1 (w1), jetzt Quorum 2 von 3 (w1, w2, w3)") {
		t.Fatalf("message %q", o)
	}
	w, err := witness.DecodeWitnesses(mustRead(t, filepath.Join(dataDir, "platform", "witnesses.rec")))
	if err != nil || w.Min != 2 || len(w.List) != 3 {
		t.Fatalf("witnesses.rec %+v %v", w, err)
	}
	for i, k := range w.List {
		if k.Name != pin2.Witnesses[i].Name || !k.Pub.Equal(pin2.Witnesses[i].Pub) {
			t.Fatalf("witness %d is not the pin's", i)
		}
	}
	if got := logNames(t, dataDir, pin2); fmt.Sprint(got) != "[admin-1.cert ingest-1.cert identity-2.succ]" {
		t.Fatalf("log %v", got)
	}
	// Again with the flag: nothing to replace, no message.
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path, "--replace-witnesses"); code != 0 ||
		strings.Contains(tt.out.String(), "ersetzt") {
		t.Fatalf("again: %d %s %s", code, tt.out.String(), tt.msgs.String())
	}
	// The old pin knows no generation 2: the flag does not help it.
	tt = newTTY()
	if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", pin1Path, "--replace-witnesses"); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "install the new pin") {
		t.Fatalf("old pin with the flag: %d %s", code, tt.msgs.String())
	}
	if w, _ := witness.DecodeWitnesses(mustRead(t, filepath.Join(dataDir, "platform", "witnesses.rec"))); w == nil || w.Min != 2 {
		t.Fatal("witnesses.rec replaced by the old pin")
	}
}

// listFiles returns the regular files below dir, relative and sorted.
func listFiles(t *testing.T, dir string) string {
	t.Helper()
	var l []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			l = append(l, filepath.ToSlash(rel))
		}
		return nil
	})
	return fmt.Sprint(l)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEchoOffFailsClosed: a term whose stdin has no echo switch (only
// possible if checkTerminal were skipped) refuses to read a share
// instead of reading it with the echo on (task 10c finding 1).
func TestEchoOffFailsClosed(t *testing.T) {
	sr := strings.NewReader(strings.Repeat("abandon ", 30) + "\n")
	e := newEnv(sr, &lockedBuffer{}, io.Discard)
	tm := e.newTerm()
	defer tm.close()
	if _, err := tm.AskShare(0); !errors.Is(err, errNoTerminal) {
		t.Fatal(err)
	}
	if sr.Len() != len(strings.Repeat("abandon ", 30))+1 {
		t.Fatalf("stdin read: %d left", sr.Len())
	}
}

// TestAbortKeys: Ctrl-C, Ctrl-\ or Ctrl-Z typed into a share (the
// terminal passes them on as input while ISIG is cleared) end the
// ceremony as the signals would: echo restored, screen cleared, exit
// code 130, nothing written (task 10d finding 1).
func TestAbortKeys(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	for _, key := range []string{"\x03", "\x1c", "\x1a"} {
		out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
		tt := newTTY()
		tt.answer = func(want int) string {
			ws := strings.Fields(tt.shares[want])
			return strings.Join(ws[:12], " ") + "\n" + key + "\n"
		}
		code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		msgs := tt.msgs.String()
		if code != exitAbort || !strings.Contains(msgs, "Abbruchtaste") || !strings.HasSuffix(strings.TrimSpace(msgs), "abgebrochen") {
			t.Fatalf("%q: %d %q", key, code, msgs)
		}
		if tt.echoOff || !strings.HasSuffix(tt.out.String(), clearScreen) {
			t.Fatalf("%q: echo off %v, screen %q", key, tt.echoOff, tt.out.String())
		}
		checkScreen(t, tt.screen.String(), append(shareLines(tt.shares), tt.typed...), len(tt.shares)+1)
		for _, d := range []string{out, kd} {
			if _, err := os.Lstat(d); err == nil {
				t.Fatalf("%q: %s written", key, d)
			}
		}
	}
}

// TestCloseSignal: a signal that the signal handling takes in while the
// command closes its term (the ceremony is complete) neither ends the
// program nor reports it aborted; the results are shown (task 10d
// finding 4). closeHook delivers the signal while close holds t.mu and
// waits until the handler has taken it.
func TestCloseSignal(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	codes := stubExit(t)
	delivered := 0
	closeHook = func(tm *term) {
		tm.sig <- os.Interrupt
		for len(tm.sig) != 0 {
			runtime.Gosched()
		}
		delivered++
	}
	defer func() { closeHook = nil }()
	tt := newTTY()
	out := filepath.Join(base, "out")
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	if delivered != 1 {
		t.Fatalf("%d signals delivered in close", delivered)
	}
	// A handler that ignores closed ends the program as soon as close
	// lets go of t.mu.
	select {
	case code := <-codes:
		t.Fatalf("exit %d after the ceremony completed", code)
	case <-time.After(300 * time.Millisecond):
	}
	screen := tt.out.String()
	last := strings.LastIndex(screen, clearScreen)
	if last < 0 || !strings.Contains(screen[last:], "Exportverzeichnis:") || strings.Contains(tt.msgs.String(), "abgebrochen") {
		t.Fatalf("results: %q, messages %q", screen[max(0, last):], tt.msgs.String())
	}
	if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
		t.Fatal(err)
	}
}

// TestAbortOrder: the abort path clears the screen before it restores
// the flow control, in the order in which a command ends (finish
// clears, close restores; task 15b point 0c): while the clear is
// written, an XOFF typed on the terminal cannot stop it.
func TestAbortOrder(t *testing.T) {
	const share = "abandon ability able about above absent absorb abstract absurd abuse"
	codes := stubExit(t)
	in := newTTY()
	e := newEnv(ttyIn{in}, ttyOut{in}, ttyErr{in})
	tm, err := e.openTerm()
	if err != nil {
		t.Fatal(err)
	}
	defer signal.Stop(tm.sig)
	in.events = nil
	fmt.Fprintf(display{tm}, "Anteil 1/2: %s\n", share)
	tm.sig <- os.Interrupt
	if code := <-codes; code != exitAbort {
		t.Fatalf("exit code %d", code)
	}
	if got := strings.Join(in.events, " "); got != "share clear flow-restore" {
		t.Fatalf("events %q, want \"share clear flow-restore\"", got)
	}
	if in.flowOff || in.echoOff {
		t.Fatalf("flow control off %v, echo off %v", in.flowOff, in.echoOff)
	}
}
