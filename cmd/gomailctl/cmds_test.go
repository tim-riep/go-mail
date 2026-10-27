package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// syncBuf is an output that tests read while a command writes it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// tty is a stand-in terminal for standard output (terminalStandIn);
// onClear, if set, runs before every clear of the screen is written.
type tty struct {
	syncBuf
	onClear func()
}

func (*tty) terminal() bool { return true }

func (t *tty) Write(p []byte) (int, error) {
	if t.onClear != nil && bytes.Contains(p, []byte(clearScreen)) {
		t.onClear()
	}
	return t.syncBuf.Write(p)
}

// keyboard is a stand-in terminal on standard input (echoStandIn): it
// answers every prompt on standard error once the command wrote it, with
// answer(prompt) (ok false: the input ends), and records whether the
// echo was off when a line was read.
type keyboard struct {
	err      *syncBuf
	answer   func(prompt string) (line string, ok bool)
	id       uint64 // ttyID
	echoFail bool   // the echo cannot be switched off
	out      *tty   // if set, events record its length

	mu       sync.Mutex
	events   []kbEvent
	pos      int
	echoOff  bool
	lines    []string // the lines read
	hidden   []bool   // the echo was off when lines[i] was read
	flushes  int
	prompts  []string // the prompts answered
	echoUsed int      // how often the echo was switched off
}

func (k *keyboard) Read(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.err.String()
	prompt := s[k.pos:]
	k.pos = len(s)
	line, ok := k.answer(prompt)
	if !ok {
		return 0, io.EOF
	}
	k.lines = append(k.lines, line)
	k.hidden = append(k.hidden, k.echoOff)
	k.prompts = append(k.prompts, prompt)
	k.event('R', prompt)
	return copy(p, line+"\n"), nil
}

// kbEvent is a read ('R', answering prompt) or a flush ('F') of the
// keyboard, with the length of the screen output at that time.
type kbEvent struct {
	kind   byte
	outLen int
	prompt string
}

func (k *keyboard) event(kind byte, prompt string) {
	n := 0
	if k.out != nil {
		n = len(k.out.String())
	}
	k.events = append(k.events, kbEvent{kind, n, prompt})
}

func (*keyboard) terminal() bool  { return true }
func (k *keyboard) ttyID() uint64 { return k.id }

func (k *keyboard) disableEcho() (func() error, error) {
	if k.echoFail {
		return nil, errors.New("ECHO stays set")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.echoOff = true
	k.echoUsed++
	return func() error {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.echoOff = false
		return nil
	}, nil
}

func (k *keyboard) flushInput() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.flushes++
	k.event('F', "")
	return nil
}

// answered returns the number of lines read.
func (k *keyboard) answered() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.lines)
}

// lineSet answers prompts that end in one of the keys of m with its
// value.
func lineSet(m map[string]string) func(string) (string, bool) {
	return func(prompt string) (string, bool) {
		for k, v := range m {
			if strings.HasSuffix(prompt, k) {
				return v, true
			}
		}
		return "", false
	}
}

// cli runs gomailctl commands in-process against a test platform, beside
// the lock of a "running server" held by the test (9.1).
type cli struct {
	t   *testing.T
	env *testenv.Env
	in  *ingest.Ingest
	pin string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	env := testenv.New(t)
	// The ingest backend holds the server lock (9.1) until Close.
	in, err := ingest.New(ingest.Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
		DiskSpace: func(string) (uint64, uint64, error) { return 1, 2, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	t.Setenv("GOMAILCTL_PASSPHRASE", string(testenv.Passphrase))
	// The pin of the development ceremony, accepted by a test build
	// (devpin_tagged.go, task 14).
	t.Setenv("GOMAIL_TEST_DEV_IDENTITY", "1")
	return &cli{t: t, env: env, in: in, pin: filepath.Join(env.KeyDir, ceremony.PinFile)}
}

// beforeRefresh is the head publication of the test platform before
// every Refresh of the client log (testenv AutoHeads, task 14), for the
// in-process gomailctl (env.beforeRefresh).
func (c *cli) beforeRefresh() func() { return c.env.ClientConfig("").BeforeRefresh }

// user creates a registered user; its in-process client is closed so
// that gomailctl can open the client directory.
func (c *cli) user(name string) *testenv.User {
	c.t.Helper()
	u := c.env.NewUser(name)
	u.Client.Close()
	return u
}

// mailbox creates a mailbox of u with address addr.
func (c *cli) mailbox(u *testenv.User, addr string) store.ID {
	c.t.Helper()
	c.env.Reopen(u)
	defer u.Client.Close()
	return c.env.Mailbox(u, "Büro", addr)
}

// deliver delivers a mail to addr.
func (c *cli) deliver(from, addr, msg string) {
	c.t.Helper()
	d, err := c.in.Begin(smtpd.Session{ID: "t"}, from, []string{addr})
	if err != nil {
		c.t.Fatal(err)
	}
	d.Write([]byte(msg))
	if err := d.Commit(); err != nil {
		c.t.Fatal(err)
	}
}

// result is the outcome of one command.
type result struct {
	code        int
	out, errOut string
}

// exec runs gomailctl with the common options for client directory dir
// (none if dir is empty), stdin as standard input and stdout as standard
// output (a fresh buffer if nil).
func (c *cli) exec(dir string, stdin io.Reader, stdout io.Writer, args ...string) result {
	c.t.Helper()
	if dir != "" {
		args = append(args, "--data", c.env.Store.Path(""), "--dir", dir, "--pin", c.pin)
	}
	if stdout == nil {
		stdout = &syncBuf{}
	}
	var errb syncBuf
	e := &env{stdin: bufio.NewReader(stdin), in: stdin, stdout: stdout, stderr: &errb, now: c.env.Clock.Now, beforeRefresh: c.beforeRefresh()}
	code := e.run(args)
	var out string
	if s, ok := stdout.(interface{ String() string }); ok {
		out = s.String()
	}
	return result{code: code, out: out, errOut: errb.String()}
}

// do runs a command with stdin text.
func (c *cli) do(dir, stdin string, args ...string) result {
	c.t.Helper()
	return c.exec(dir, strings.NewReader(stdin), nil, args...)
}

// must runs a command that must exit with code want.
func (c *cli) must(want int, dir, stdin string, args ...string) result {
	c.t.Helper()
	r := c.do(dir, stdin, args...)
	if r.code != want {
		c.t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, r.code, want, r.out, r.errOut)
	}
	return r
}

// noneIn fails if any of secrets occurs in s.
func noneIn(t *testing.T, what, s string, secrets ...string) {
	t.Helper()
	for _, x := range secrets {
		if x != "" && strings.Contains(s, x) {
			t.Fatalf("%s contains %q:\n%s", what, x, s)
		}
	}
}

// noFileHolds fails if a file under dir holds one of secrets.
func noFileHolds(t *testing.T, dir string, secrets ...string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds a secret", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestShareRevokeSearchFlag: two users, end to end over the command line
// (2.5, 6.3, 7): bob cannot read alice's mailbox until she shares it
// with him from epoch 1; then he lists and searches it; alice sets and
// clears flags; revoke takes his access away; a past period; an
// incomplete share exits with code 3. No output holds plaintext but the
// subject shown by list and search.
func TestShareRevokeSearchFlag(t *testing.T) {
	c := newCLI(t)
	alice, bob, carol := c.user("alice"), c.user("bob"), c.user("carol")
	mbx := c.mailbox(alice, "info@brownbear.example")
	const subject, body = "Rechnung 4711", "Kennwort Nordlicht"
	c.deliver("rechnung@lieferant.example", "info@brownbear.example",
		"From: Rechnung <rechnung@lieferant.example>\r\nTo: info@brownbear.example\r\nSubject: "+subject+"\r\n\r\n"+body+"\r\n")
	c.env.Clock.Advance(time.Hour)
	secret := []string{"lieferant", "brownbear", "Nordlicht"}
	var all []result
	keep := func(r result) result { all = append(all, r); return r }
	m, b, cl := mbx.String(), bob.ID.String(), carol.ID.String()

	// Without a share bob reads nothing.
	if r := keep(c.do(bob.Dir, "", "list", m)); r.code == 0 || strings.Contains(r.out, subject) {
		t.Fatalf("bob lists without a share: %+v", r)
	}
	r := keep(c.must(0, alice.Dir, "", "mailbox", "share", m, b, "--from", "1"))
	if !strings.Contains(r.out, "Verpackt für "+b+": Epochen 1.") || !strings.Contains(r.out, "Mitglied von "+m) {
		t.Fatalf("share: %q", r.out)
	}
	r = c.must(0, bob.Dir, "", "list", m)
	if !strings.Contains(r.out, subject) {
		t.Fatalf("bob lists after the share: %q", r.out)
	}
	noneIn(t, "list", r.out, secret...)
	mailID := strings.Fields(r.out)[0]
	if r = c.must(0, bob.Dir, "", "list", m, "--folder", "INBOX"); !strings.Contains(r.out, subject) {
		t.Fatalf("list --folder: %q", r.out)
	}
	keep(c.must(1, bob.Dir, "", "list", m, "--folder", "Archiv"))

	// search: mail ID, time of receipt, folder, subject.
	for _, dir := range []string{bob.Dir, alice.Dir} {
		r = c.must(0, dir, "", "search", m, "from:Rechnung@Lieferant.example")
		want := mailID + "  2026-10-26 10:00  INBOX  " + subject + "\n"
		if r.out != want {
			t.Fatalf("search: %q, want %q", r.out, want)
		}
		keep(result{errOut: r.errOut})
	}
	// After sync the mail is found in the index segment.
	keep(c.must(0, alice.Dir, "", "sync"))
	if r = c.must(0, alice.Dir, "", "search", m, "has:attachment"); r.out != "" {
		t.Fatalf("search without hit: %q", r.out)
	}
	if r = c.must(0, alice.Dir, "", "search", m, "fromdomain:lieferant.example", "--since", "2026-10"); !strings.Contains(r.out, mailID) {
		t.Fatalf("search --since: %q", r.out)
	}
	if r = c.must(0, alice.Dir, "", "search", "--since", "2026-11", m, "fromdomain:lieferant.example"); r.out != "" {
		t.Fatalf("search --since a later month: %q", r.out)
	}
	// A term the client does not accept: exit 1, and the term is in no
	// message.
	r = keep(c.must(1, alice.Dir, "", "search", m, "Nordlicht"))
	noneIn(t, "search error", r.errOut, "Nordlicht")

	// flag: alice is a member of the mail's epoch.
	r = keep(c.must(0, alice.Dir, "", "flag", m, mailID, "--set", "seen, flagged"))
	if r.out != "Flags von "+mailID+": flagged, seen (Version 2)\n" {
		t.Fatalf("flag --set: %q", r.out)
	}
	r = keep(c.must(0, alice.Dir, "", "flag", m, mailID, "--clear", "seen,flagged", "--set", "answered"))
	if r.out != "Flags von "+mailID+": answered (Version 3)\n" {
		t.Fatalf("flag --clear: %q", r.out)
	}
	r = keep(c.must(0, alice.Dir, "", "flag", m, mailID, "--clear", "answered"))
	if r.out != "Flags von "+mailID+": keine (Version 4)\n" {
		t.Fatalf("flag, none left: %q", r.out)
	}
	keep(c.must(1, alice.Dir, "", "flag", m, mailID, "--set", "bogus"))
	// bob is no member of epoch 1: he may not change its metadata.
	keep(c.must(1, bob.Dir, "", "flag", m, mailID, "--set", "seen"))
	// bob still reads the mail signed by alice.
	if r = c.must(0, bob.Dir, "", "read", m, mailID); !strings.Contains(r.out, body) {
		t.Fatal("bob reads the flagged mail")
	}

	// revoke: bob loses access; alice cannot revoke herself.
	r = keep(c.must(0, alice.Dir, "", "mailbox", "revoke", m, b))
	if !strings.Contains(r.out, "entzogen") || !strings.Contains(r.out, "gelöscht wurde nichts") {
		t.Fatalf("revoke: %q", r.out)
	}
	if r = keep(c.do(bob.Dir, "", "list", m)); strings.Contains(r.out, subject) {
		t.Fatalf("bob lists after the revocation: %q", r.out)
	}
	keep(c.must(1, alice.Dir, "", "mailbox", "revoke", m, alice.ID.String()))

	// A past period: bob reads epoch 1 again, without being a member.
	r = keep(c.must(0, alice.Dir, "", "mailbox", "share", m, b, "--to", "1"))
	if !strings.Contains(r.out, "Epochen 1.") || !strings.Contains(r.out, "Epochen 1 bis 1 (kein Mitglied)") {
		t.Fatalf("share --to: %q", r.out)
	}
	if r = c.must(0, bob.Dir, "", "read", m, mailID); !strings.Contains(r.out, body) {
		t.Fatal("bob reads the past period")
	}
	keep(c.must(1, alice.Dir, "", "mailbox", "share", m, b, "--from", "1", "--to", "99"))

	// An incomplete share: alice's own wrap of epoch 1 is gone, so carol
	// gets every epoch but that one (client.ErrPartial, exit code 3).
	if err := os.Remove(c.env.Store.WrapFile(mbx, 1, alice.ID)); err != nil {
		t.Fatal(err)
	}
	r = keep(c.must(exitPartial, alice.Dir, "", "mailbox", "share", m, cl, "--from", "1"))
	if !strings.Contains(r.out, "Verpackt für "+cl+": Epochen ") || !strings.Contains(r.errOut, "not every requested epoch") {
		t.Fatalf("partial share: %+v", r)
	}

	for _, r := range all {
		noneIn(t, "output", r.out+r.errOut, append(secret, subject, "4711")...)
	}
}

// seedOf returns the 24 seed words shown by keygen: the screen that
// starts with "Ihr Seed", up to the next clear.
func seedOf(t *testing.T, out string) []string {
	t.Helper()
	_, seg, ok := strings.Cut(out, "Ihr Seed")
	if !ok {
		t.Fatalf("no seed in %q", out)
	}
	seg, _, _ = strings.Cut(seg, clearScreen)
	ws := numbered(seg)
	if len(ws) != 24 {
		t.Fatalf("%d seed words in %q", len(ws), seg)
	}
	return ws
}

var numberedRe = regexp.MustCompile(`(\d+)\. +(\S+)`)

// numbered returns the numbered words of text in their order.
func numbered(text string) []string {
	var ws []string
	for _, m := range numberedRe.FindAllStringSubmatch(text, -1) {
		n, _ := strconv.Atoi(m[1])
		if n == len(ws)+1 {
			ws = append(ws, m[2])
		}
	}
	return ws
}

var wordPromptRe = regexp.MustCompile(`Wort Nr\. (\d+): $`)

// keygenKeys answers the prompts of keygen: the word questions from the
// seed words on out, the confirmation of the seed (seed) and of the
// holders and shares (holders) with Enter.
func keygenKeys(t *testing.T, out *tty, seed, holders bool) func(string) (string, bool) {
	return func(prompt string) (string, bool) {
		switch {
		case wordPromptRe.MatchString(prompt):
			n, _ := strconv.Atoi(wordPromptRe.FindStringSubmatch(prompt)[1])
			return seedOf(t, out.String())[n-1], true
		case seed && strings.HasSuffix(prompt, "Seed notiert? Eingabetaste löscht den Bildschirm: "):
			return "", true
		case holders && (strings.HasSuffix(prompt, "dann Eingabetaste: ") || strings.HasSuffix(prompt, "Anteil notiert? Eingabetaste löscht den Bildschirm: ")):
			return "", true
		}
		return "", false
	}
}

// keygenRun runs keygen with args on the stand-in terminals out and kb.
func (c *cli) keygenRun(dir string, out *tty, kb *keyboard, args ...string) result {
	c.t.Helper()
	args = append(append([]string{"keygen"}, args...), "--data", c.env.Store.Path(""), "--dir", dir, "--pin", c.pin)
	e := &env{stdin: bufio.NewReader(kb), in: kb, stdout: out, stderr: kb.err, now: c.env.Clock.Now, beforeRefresh: c.beforeRefresh()}
	code := e.run(args)
	return result{code: code, out: out.String(), errOut: kb.err.String()}
}

// TestKeygenSharesRestore: keygen --shares shows every share once, only
// on a terminal, and clears the screen after each (2.2
// "Wiederherstellung"); restore sets up the user on a new device from
// two of the three shares or from the 24 words. No share and no seed
// word reaches a file or a message.
func TestKeygenSharesRestore(t *testing.T) {
	c := newCLI(t)
	dir := filepath.Join(c.env.Base, "clients", "carol")

	// Not a terminal: refused before anything is shown or written.
	r := c.must(1, dir, "", "keygen", "--shares", "2-of-3")
	if !strings.Contains(r.errOut, "nur auf einem Terminal") || r.out != "" {
		t.Fatalf("keygen --shares without a terminal: %+v", r)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("client directory created")
	}
	for _, bad := range []string{"1-of-3", "3-of-2", "2-of-256", "2of3", "x"} {
		c.must(2, dir, "", "keygen", "--shares", bad)
	}

	// The input ends before the first holder confirms: no share is shown
	// and nothing is written, and the screen is cleared.
	out := &tty{}
	kb := &keyboard{err: &syncBuf{}}
	kb.answer = keygenKeys(t, out, true, false)
	if r := c.keygenRun(dir, out, kb, "--shares", "2-of-3"); r.code != 1 ||
		!strings.HasSuffix(out.String(), clearScreen) || strings.Contains(out.String(), "Anteil 1") {
		t.Fatalf("keygen --shares without confirmation: exit %d\n%q", r.code, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "keystore")); !os.IsNotExist(err) {
		t.Fatal("key store written without the shares shown")
	}

	out = &tty{}
	kb = &keyboard{err: &syncBuf{}, out: out}
	kb.answer = keygenKeys(t, out, true, true)
	keystoreAt := map[int]bool{} // clears of the screen: was the key store there?
	out.onClear = func() { keystoreAt[len(out.String())] = exists(filepath.Join(dir, "keystore")) }
	r = c.keygenRun(dir, out, kb, "--shares", "2-of-3")
	errb := kb.err
	if r.code != 0 {
		t.Fatalf("keygen --shares: exit %d\n%s", r.code, errb.String())
	}
	// The seed confirmed, three words, two answers per holder; the words
	// typed with the echo off, the confirmations with the echo on.
	if len(kb.lines) != 1+3+2*3 {
		t.Fatalf("%d answers", len(kb.lines))
	}
	for i, h := range kb.hidden {
		if word := wordPromptRe.MatchString(kb.prompts[i]); h != word {
			t.Fatalf("answer %d to %q: echo off %v", i, kb.prompts[i], h)
		}
	}
	screens := strings.Split(out.String(), clearScreen)
	seed := seedOf(t, out.String())
	var shares [][]string
	for _, s := range screens[1:] {
		if strings.HasPrefix(s, "Anteil ") {
			if want := "Anteil " + strconv.Itoa(len(shares)+1) + " von 3 (30 Wörter)"; !strings.HasPrefix(s, want) {
				t.Fatalf("screen %q", s)
			}
			ws := numbered(s)
			if len(ws) != 30 {
				t.Fatalf("share with %d words", len(ws))
			}
			shares = append(shares, ws)
		} else if s != "" && !strings.HasPrefix(s, "Benutzer ") && !strings.HasPrefix(s, "Ihr Seed") {
			t.Fatalf("unexpected screen %q", s)
		}
	}
	// The screen is cleared before the seed and after it; each share on a
	// screen of its own, cleared before the next one and at the end,
	// before the key store is written and the final message shown.
	if len(shares) != 3 || len(screens) != 8 || screens[0] != "" || !strings.HasPrefix(screens[1], "Ihr Seed") || screens[2] != "" ||
		screens[6] != "" || !strings.HasPrefix(screens[7], "Benutzer ") {
		t.Fatalf("%d shares on %d screens: %q", len(shares), len(screens), screens)
	}
	if !strings.Contains(screens[7], "restore --shares 2") {
		t.Fatalf("final message %q", screens[7])
	}
	for at, ks := range keystoreAt {
		if ks {
			t.Fatalf("screen cleared at %d with the key store written", at)
		}
	}
	if !exists(filepath.Join(dir, "keystore")) {
		t.Fatal("no key store")
	}
	// Task 13b finding 3: every "Anteil notiert?" is answered only after
	// input typed ahead was discarded with the share on the screen.
	k := 0
	for i, ev := range kb.events {
		if ev.kind != 'R' || !strings.HasSuffix(ev.prompt, "Anteil notiert? Eingabetaste löscht den Bildschirm: ") {
			continue
		}
		k++
		shareEnd := strings.Index(out.String(), "Anteil "+strconv.Itoa(k)+" von 3 (30")
		if i == 0 || kb.events[i-1].kind != 'F' || kb.events[i-1].outLen <= shareEnd {
			t.Fatalf("share %d confirmed without a flush after it appeared: %+v", k, kb.events[:i+1])
		}
	}
	if k != 3 {
		t.Fatalf("%d shares confirmed", k)
	}
	join := func(ws []string) string { return strings.Join(ws[:6], " ") }
	secrets := []string{join(seed), join(shares[0]), join(shares[1]), join(shares[2])}
	noneIn(t, "stderr", errb.String(), secrets...)

	// Register carol; then restore on two new devices.
	code2, err := c.env.Store.CreateInvite(c.env.Clock.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	r = c.must(0, dir, "", "register", "--invite", code2.String())
	carol := strings.TrimSpace(strings.TrimPrefix(r.out, "Registriert:"))

	// Shares 1 and 3, typed with odd spacing and case over several lines.
	in := strings.ToUpper(strings.Join(shares[0][:10], "  ")) + "\n" + strings.Join(shares[0][10:], "\t") + "\n" +
		strings.Join(shares[2], " ") + "\n"
	dev2 := filepath.Join(c.env.Base, "clients", "carol2")
	r = c.must(0, dev2, in, "restore", "--shares", "2")
	if r.out != "Benutzer "+carol+" auf diesem Gerät wiederhergestellt.\n" || !strings.Contains(r.errOut, "Noch kein bestätigter Zustand") {
		t.Fatalf("restore --shares: %+v", r)
	}
	noneIn(t, "restore", r.out+r.errOut, secrets...)
	c.must(0, dev2, "", "sync")
	// The same directory again: it holds a user.
	c.must(1, dev2, in, "restore", "--shares", "2")

	// From the 24 words, on a terminal: the typed words are cleared.
	dev3 := filepath.Join(c.env.Base, "clients", "carol3")
	t3 := &tty{}
	r = c.exec(dev3, strings.NewReader(strings.Join(seed, "\n")+"\n"), t3, "restore")
	if r.code != 0 || !strings.HasSuffix(t3.String(), clearScreen+"Benutzer "+carol+" auf diesem Gerät wiederhergestellt.\n") {
		t.Fatalf("restore from words: %+v", r)
	}

	// Errors name positions and counts, never words.
	dev4 := filepath.Join(c.env.Base, "clients", "carol4")
	swapped := append([]string(nil), shares[1]...)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	bad := []struct{ in, want string }{
		{strings.Join(shares[0], " ") + "\n" + strings.Join(swapped, " ") + "\n", "share 2"},
		{strings.Join(shares[0], " ") + "\n", "Anteil 2 von 2: keine Eingabe nach 0 von 30 Wörtern"},
		{strings.Join(shares[0], " ") + " " + shares[1][0] + "\n", "Anteil 1 von 2: mehr als 30 Wörter"},
		{strings.Join(shares[0][:7], " ") + " zzzz " + strings.Join(shares[0][8:], " ") + "\n", "word 8"},
		{strings.Repeat("a", 5000) + "\n", "Zeile zu lang"},
		{strings.Join(shares[0], " ") + "\n" + strings.Join(shares[0], " ") + "\n", "duplicate"},
	}
	for i, b := range bad {
		r = c.must(1, dev4, b.in, "restore", "--shares", "2")
		if !strings.Contains(r.errOut, b.want) {
			t.Fatalf("case %d: %q, want %q", i, r.errOut, b.want)
		}
		noneIn(t, "restore error", r.errOut, append(secrets, "zzzz", shares[0][0], shares[1][0])...)
	}
	if _, err := os.Stat(filepath.Join(dev4, "keystore")); !os.IsNotExist(err) {
		t.Fatal("key store written for a failed restore")
	}
	for _, args := range [][]string{{"restore", "--shares", "1"}, {"restore", "--shares", "x"}, {"restore", "y"}} {
		c.must(2, dev4, "", args...)
	}

	// Neither shares nor seed words are in any file.
	noFileHolds(t, c.env.Base, secrets...)
}

// TestDeviceLost: device lost over the command line with the seed words
// (2.2 "Generationen"): a new generation, the mailbox still readable;
// typed words are normalized and cleared from a terminal; wrong input is
// refused with positions only.
func TestDeviceLost(t *testing.T) {
	c := newCLI(t)
	alice, bob := c.user("alice"), c.user("bob")
	mbx := c.mailbox(alice, "info@brownbear.example")
	c.deliver("s@x.example", "info@brownbear.example", "Subject: Angebot 17\r\n\r\nText\r\n")
	c.env.Clock.Advance(time.Hour)
	words := alice.Words
	secret := []string{strings.Join(words[:6], " "), strings.Join(bob.Words[:6], " ")}

	bad := []struct{ in, want string }{
		{strings.Join(words[:23], " ") + "\n", "nach 23 von 24 Wörtern"},
		{strings.Join(words, " ") + " " + words[0] + "\n", "mehr als 24 Wörter"},
		{strings.Join(words[:4], " ") + " abandonx " + strings.Join(words[5:], " ") + "\n", "word 5"},
		{strings.Join(bob.Words, " ") + "\n", "seed does not belong"},
	}
	for i, b := range bad {
		r := c.must(1, alice.Dir, b.in, "device", "lost")
		if !strings.Contains(r.errOut, b.want) {
			t.Fatalf("case %d: %q, want %q", i, r.errOut, b.want)
		}
		noneIn(t, "device lost error", r.out+r.errOut, append(secret, "abandonx", words[0])...)
	}

	// The words in capitals with tabs, over three lines, on a terminal.
	in := strings.ToUpper(strings.Join(words[:8], "\t")) + "\n " + strings.Join(words[8:16], "   ") + "\r\n" + strings.Join(words[16:], " ") + "\n"
	out := &tty{}
	r := c.exec(alice.Dir, strings.NewReader(in), out, "device", "lost")
	if r.code != 0 || !strings.Contains(out.String(), clearScreen+"Neue Generation 2;") {
		t.Fatalf("device lost: %+v\n%s", r, out.String())
	}
	noneIn(t, "device lost", out.String()+r.errOut, secret...)
	user, _, err := c.env.Store.ReadUser(alice.ID)
	if err != nil || user.Current().Gen != 2 {
		t.Fatalf("generation after device lost: %v", err)
	}
	if r = c.must(0, alice.Dir, "", "list", mbx.String()); !strings.Contains(r.out, "Angebot 17") {
		t.Fatalf("list after device lost: %q", r.out)
	}
	// Without the passphrase nothing happens.
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	c.must(1, alice.Dir, "", "device", "lost")
	noFileHolds(t, c.env.Base, secret...)
}

// TestUsageTask13: usage errors of the commands of task 13 exit with 2
// before the data directory is touched; a search term never appears in
// a message.
func TestUsageTask13(t *testing.T) {
	id1, _ := store.NewID(nil)
	id2, _ := store.NewID(nil)
	a, b := id1.String(), id2.String()
	for _, args := range [][]string{
		{"device"}, {"device", "found"}, {"device", "lost", "x"}, {"mailbox", "share", a}, {"mailbox", "share", "bad", b},
		{"mailbox", "share", a, b, "--from", "0"}, {"mailbox", "share", a, b, "--from", "3", "--to", "2"},
		{"mailbox", "share", a, b, "--to", "x"}, {"mailbox", "share", a, b, "--delegate"}, {"mailbox", "revoke", a},
		{"mailbox", "revoke", a, "bad"}, {"mailbox", "rotate", a}, {"search", a}, {"search", a, "from:x", "--since", "2026"},
		{"search", "bad", "from:x"}, {"flag", a, b}, {"flag", a, b, "--set", "seen,,draft"}, {"flag", a, "--set", "seen"},
		{"keygen", "extra"}, {"recovery", "keygen"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d\n%s", args, code, errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"search", a, "-Nordlicht"}, strings.NewReader(""), &out, &errb); code != 2 || strings.Contains(errb.String(), "Nordlicht") {
		t.Fatalf("search term in a usage error: %d %s", code, errb.String())
	}
	// Valid usage, but no server lock: exit 1 from the configuration.
	if code := run([]string{"search", a, "from:x"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("search without --data: exit %d", code)
	}
	if code := run([]string{"device", "lost"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("device lost without --data: exit %d", code)
	}
}
