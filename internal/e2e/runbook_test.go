package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// rbPassphrase is the passphrase of the key stores of TestRunbook (a
// test value, through the environment as RUNBOOK 3.2 allows).
const rbPassphrase = "GOMAILCTL_PASSPHRASE=runbook test passphrase"

// rbKeygenPipe is the keygen switch of a test build (RUNBOOK 9): seed
// words on standard output, the three words from standard input.
const rbKeygenPipe = "GOMAILCTL_TEST_KEYGEN_PIPE=1"

// runbook is the state of TestRunbook: the programs of a production
// build with the tag gomail_test only (prodTags: the free space and head
// gap switches of gomail-server and the keygen pipe of gomailctl, no
// development ceremony), the directories, and the running server and
// witness.
type runbook struct {
	t     *testing.T
	start time.Time
	bin   string
	dir   string
	data  string
	keys  string // private admin and ingest keys of the ceremony
	admin string
	// ingestKey is the key the server runs with, pin the pin of the
	// server; origin and witnessKey those of the ceremony.
	ingestKey, pin, origin, witnessKey string
	// logKeys are the verifier lines of the log keys the witness gets
	// (RUNBOOK 6: both generations during an ingest rotation).
	logKeys     []string
	srv         *serverProc
	servers     []*serverProc // every server started, for the check of their logs
	stopWitness func()
	section     string // the RUNBOOK section of the current step
}

// refuseLimit bounds every call of TestRunbook that expects a refusal: a
// regression that lets the program run (a server that starts) is killed
// and reported with its step instead of hanging until the test timeout.
const refuseLimit = 30 * time.Second

// rbUser is a user of TestRunbook with its client directory and pin.
type rbUser struct {
	name, dir, pin, id string
	words              []string // the seed, shown by keygen of the test build
}

// step logs the RUNBOOK section a step of the test follows.
func (r *runbook) step(section, what string) {
	r.t.Helper()
	r.section = section
	r.t.Logf("RUNBOOK %s: %s (%.1f s)", section, what, time.Since(r.start).Seconds())
}

// env is the environment of every program: that of the test without
// any GOMAIL* variable, plus the free space and head gap switches of the
// test build (testMinFree, testHeadGap), the passphrase and extra.
func (r *runbook) env(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOMAIL") {
			env = append(env, kv)
		}
	}
	return append(append(env, testMinFree, testHeadGap, rbPassphrase), extra...)
}

// exec runs a program with stdin and returns its exit code, standard
// output and standard error.
func (r *runbook) exec(stdin, name string, args ...string) (int, string, string) {
	r.t.Helper()
	return r.execCtx(context.Background(), stdin, name, args...)
}

// refuse runs a program that is expected to refuse, at most for
// refuseLimit. On the deadline the process is killed and the test fails
// with the RUNBOOK section of the step.
func (r *runbook) refuse(stdin, name string, args ...string) (int, string, string) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), refuseLimit)
	defer cancel()
	code, out, errb := r.execCtx(ctx, stdin, name, args...)
	if ctx.Err() != nil {
		r.t.Fatalf("RUNBOOK %s: %s %v expected to refuse, still running after %v (killed)\n%s", r.section, name, args, refuseLimit, errb)
	}
	return code, out, errb
}

// execCtx is exec with a context: the process is killed when ctx ends.
func (r *runbook) execCtx(ctx context.Context, stdin, name string, args ...string) (int, string, string) {
	r.t.Helper()
	cmd := exec.CommandContext(ctx, filepath.Join(r.bin, name), args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = r.env()
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		r.t.Fatalf("%s %v: %v", name, args, err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errb.String()
}

// run runs a program that must succeed and returns its output.
func (r *runbook) run(stdin, name string, args ...string) string {
	r.t.Helper()
	code, out, errb := r.exec(stdin, name, args...)
	if code != 0 {
		r.t.Fatalf("%s %v: exit %d\n%s", name, args, code, errb)
	}
	return out
}

// args are the common options of gomailctl for u.
func (r *runbook) args(u *rbUser, cmd ...string) []string {
	return append(cmd, "--data", r.data, "--dir", u.dir, "--pin", u.pin)
}

// ctl runs gomailctl for u until it succeeds, at most for a minute, and
// returns standard output and standard error of that run: a command
// after an own log entry needs a head cosigned by the witness that
// covers it (RUNBOOK 3.4), which the test build signs at most every
// second (testHeadGap).
func (r *runbook) ctl(u *rbUser, stdin string, cmd ...string) (string, string) {
	r.t.Helper()
	var errb string
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		code, out, e := r.exec(stdin, "gomailctl", r.args(u, cmd...)...)
		if code == 0 {
			return out, e
		}
		errb = e
	}
	r.t.Fatalf("gomailctl %v (%s): no success within a minute\n%s", cmd, u.name, errb)
	return "", ""
}

// listUntil runs "gomailctl list" for u until the output holds every
// one of want, at most for a minute, and returns the last output and
// standard error.
func (r *runbook) listUntil(u *rbUser, mbx string, want ...string) (string, string) {
	r.t.Helper()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(250 * time.Millisecond) {
		out, errb := r.ctl(u, "", "list", mbx)
		all := true
		for _, w := range want {
			all = all && strings.Contains(out, w)
		}
		if all {
			return out, errb
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("list %s (%s): %v missing\n%s\n%s", mbx, u.name, want, out, errb)
		}
	}
}

// mailID returns the ID of the line of a list or search output that
// holds subject.
func (r *runbook) mailID(out, subject string) string {
	r.t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, subject) {
			return strings.Fields(line)[0]
		}
	}
	r.t.Fatalf("no line with %q in\n%s", subject, out)
	return ""
}

// keygen runs "gomailctl keygen" for u in the pipe mode of the test
// build (RUNBOOK 9: a production build shows the seed only on a
// terminal), keeps the 24 words shown and answers the three questions.
func (r *runbook) keygen(u *rbUser) {
	t := r.t
	t.Helper()
	kg := exec.Command(filepath.Join(r.bin, "gomailctl"), r.args(u, "keygen")...)
	kg.Env = r.env(rbKeygenPipe)
	stdin, _ := kg.StdinPipe()
	stdout, _ := kg.StdoutPipe()
	stderr, _ := kg.StderrPipe()
	if err := kg.Start(); err != nil {
		t.Fatal(err)
	}
	words := make([]string, 24)
	sc := bufio.NewScanner(stdout)
	wordRe := regexp.MustCompile(`(\d+)\. (\S+)`)
	for n := 0; n < 24 && sc.Scan(); {
		for _, m := range wordRe.FindAllStringSubmatch(sc.Text(), -1) {
			i, _ := strconv.Atoi(m[1])
			if i >= 1 && i <= 24 && words[i-1] == "" {
				words[i-1] = m[2]
				n++
			}
		}
	}
	er := bufio.NewReader(stderr)
	promptRe := regexp.MustCompile(`Wort Nr\. (\d+):$`)
	for i := 0; i < 3; i++ {
		prompt, err := er.ReadString(':')
		if err != nil {
			t.Fatal(err)
		}
		m := promptRe.FindStringSubmatch(prompt)
		if m == nil {
			t.Fatalf("prompt %q", prompt)
		}
		n, _ := strconv.Atoi(m[1])
		io.WriteString(stdin, words[n-1]+"\n")
	}
	var rest bytes.Buffer
	go io.Copy(io.Discard, er)
	io.Copy(&rest, stdout)
	if err := kg.Wait(); err != nil {
		t.Fatalf("keygen %s: %v", u.name, err)
	}
	if !strings.Contains(rest.String(), "angelegt (noch nicht registriert)") {
		t.Fatalf("keygen %s: %q", u.name, rest.String())
	}
	u.words = words
}

// startServer starts "gomail-server serve" with the ingest key and pin
// of r (RUNBOOK 1.6) and returns once both listeners are up.
func (r *runbook) startServer(extra ...string) {
	r.t.Helper()
	r.srv = startServerProc(r.t, r.bin, r.env(), append(r.serveArgs(), extra...))
	r.servers = append(r.servers, r.srv)
}

func (r *runbook) serveArgs() []string {
	return []string{"serve", "--data", r.data, "--listen", "127.0.0.1:0", "--ingest-key", r.ingestKey, "--pin", r.pin, "--log-listen", "127.0.0.1:0"}
}

// startWitness starts gomail-witness against the log side of the running
// server (RUNBOOK 1.7) with the log keys of r and the state directory
// of the witness, which survives every restart.
func (r *runbook) startWitness() {
	r.t.Helper()
	args := []string{"serve", "--log", "http://" + r.srv.log}
	for _, k := range r.logKeys {
		args = append(args, "--log-key", k)
	}
	args = append(args, "--origin", r.origin, "--key", r.witnessKey, "--state", filepath.Join(r.dir, "witness-state"), "--interval", "1s")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(r.bin, "gomail-witness"), args...)
	cmd.Env = r.env()
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	var once sync.Once
	r.stopWitness = func() {
		once.Do(func() {
			cmd.Process.Signal(os.Interrupt)
			cmd.Wait()
			cancel()
		})
	}
	r.t.Cleanup(r.stopWitness)
}

// stop stops witness and server.
func (r *runbook) stop() {
	r.stopWitness()
	r.srv.stop()
}

// logKey is the verifier line of the log key of ingest generation gen,
// as RUNBOOK 1.7 forms it from platform/ingest-<gen>.pub with sha256sum
// and base64; the test checks the shell lines against the note package
// when sh, sha256sum and base64 are there.
func (r *runbook) logKey(gen uint32) string {
	r.t.Helper()
	pubFile := filepath.Join(r.data, "platform", store.PlatformFileName("ingest", gen, "pub"))
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		r.t.Fatal(err)
	}
	want, err := note.NewEd25519VerifierKey(translog.LogSignerName, ed25519.PublicKey(pub))
	if err != nil {
		r.t.Fatal(err)
	}
	for _, tool := range []string{"sh", "sha256sum", "base64", "cut", "tr"} {
		if _, err := exec.LookPath(tool); err != nil {
			return want
		}
	}
	script := `pub=$1
h=$({ printf 'gomail-log\n\001'; cat "$pub"; } | sha256sum | cut -c1-8)
k=$({ printf '\001'; cat "$pub"; } | base64 | tr -d '\n')
echo "gomail-log+$h+$k"`
	out, err := exec.Command("sh", "-c", script, "sh", pubFile).Output()
	if err != nil || strings.TrimSpace(string(out)) != want {
		r.t.Fatalf("RUNBOOK 1.7: shell lines give %q (%v), want %q", out, err, want)
	}
	return want
}

// startServerProc starts gomail-server with args and env and returns once
// both listeners are up; it is stopped at the end of the test.
func startServerProc(t *testing.T, bin string, env, args []string) *serverProc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &serverProc{cmd: exec.CommandContext(ctx, filepath.Join(bin, "gomail-server"), args...)}
	s.cmd.Env = env
	stderr, _ := s.cmd.StderrPipe()
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.stop)
	addrs := make(chan [2]string, 2)
	go func() {
		sc := bufio.NewScanner(stderr)
		re := regexp.MustCompile(`msg="(smtp|log) listening" addr=(127\.0\.0\.1:\d+)`)
		for sc.Scan() {
			s.mu.Lock()
			s.logs.WriteString(sc.Text() + "\n")
			s.mu.Unlock()
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				addrs <- [2]string{m[1], m[2]}
			}
		}
	}()
	deadline := time.After(30 * time.Second)
	for s.smtp == "" || s.log == "" {
		select {
		case a := <-addrs:
			if a[0] == "smtp" {
				s.smtp = a[1]
			} else {
				s.log = a[1]
			}
		case <-deadline:
			t.Fatalf("server did not start:\n%s", s.Logs())
		}
	}
	return s
}

// mail sends a mail with subject to info@brownbear.example over SMTP.
func mail(addr, subject string) error {
	return smtp.SendMail(addr, nil, "rechnung@lieferant.example", []string{"info@brownbear.example"},
		[]byte("From: Lieferant <rechnung@lieferant.example>\r\nTo: info@brownbear.example\r\nSubject: "+subject+"\r\n\r\nHallo.\r\n"))
}

// staleIngest delivers one mail the way a server that still holds the
// key of ingest generation gen would (RUNBOOK 6): package ingest with
// that key and the clock at, in this process, on the data directory of a
// stopped server. The log of the data directory does not hold the
// certificate of the next generation yet, so ingest signs.
func staleIngest(t *testing.T, data, pinFile, keyFile string, at time.Time, subject string) {
	t.Helper()
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := ceremony.ReadPin(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := ceremony.PinIdentities(pin)
	if err != nil {
		t.Fatal(err)
	}
	tl, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin})
	if err != nil {
		t.Fatal(err)
	}
	key, gen, err := ceremony.ReadKey(keyFile, store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	in, err := ingest.New(ingest.Config{Store: st, Log: tl, IngestKey: key, IngestGen: gen, Now: func() time.Time { return at },
		Logger: logger, MinFree: 0.000001})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := in.Recover(); err != nil {
		t.Fatal(err)
	}
	in.Start()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtpd.NewServer(smtpd.Config{Hostname: "stale.test", Logger: logger}, in)
	go srv.Serve(ln)
	defer srv.Close()
	if err := mail(ln.Addr().String(), subject); err != nil {
		t.Fatal(err)
	}
}

// TestRunbook follows docs/RUNBOOK.md step by step with the programs of
// a production build (prodTags: tag gomail_test only, for the free space
// and head gap switches of gomail-server and the keygen pipe of
// gomailctl; no development ceremony). Every step logs the RUNBOOK
// section it follows ("RUNBOOK <section>: ..."). The ceremonies run
// through the seams of package ceremony (Display, Prompter), not on a
// terminal: the terminal rules of gomail-ceremony are tested in
// cmd/gomail-ceremony. Two mails of RUNBOOK 6 come from package ingest
// in this process (staleIngest), as a server that kept ingest key 1
// would sign them; they cover the rule that gomailctl refuses metadata
// of ingest generation 1 from valid_from of ingest-2.cert on (task 14c).
// Every call that expects a refusal runs at most refuseLimit (task 19b);
// the revocation is checked with inspect as RUNBOOK 4.7 says.
func TestRunbook(t *testing.T) {
	dir := t.TempDir()
	r := &runbook{t: t, start: time.Now(), bin: prodPrograms(t), dir: dir, data: filepath.Join(dir, "data"), keys: filepath.Join(dir, "keys")}
	r.admin, r.ingestKey = filepath.Join(r.keys, "admin-1.key"), filepath.Join(r.keys, "ingest-1.key")
	r.step("0.2", "Programme gebaut (Produktionsbuild, nur Tag gomail_test): keine Entwicklungszeremonie")
	if code, _, _ := r.refuse("", "gomail-ceremony", "init", "--dev", "--data", filepath.Join(dir, "dev-data"), "--keys", filepath.Join(dir, "dev-keys")); code != 2 {
		t.Fatalf("init --dev in a production build: exit %d", code)
	}

	// 1.1 The witness key.
	r.step("1.1", "Zeugenschlüssel (gomail-witness keygen)")
	r.witnessKey, r.origin = filepath.Join(dir, "witness", "witness.key"), "runbook.go-mail.test/log"
	if err := os.Mkdir(filepath.Dir(r.witnessKey), 0o700); err != nil {
		t.Fatal(err)
	}
	vkey := strings.TrimSpace(r.run("", "gomail-witness", "keygen", "--name", "runbook-witness", "--key", r.witnessKey))
	if fi, err := os.Stat(r.witnessKey); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("witness key: %v %v", fi, err)
	}
	raw, err := base64.StdEncoding.DecodeString(vkeyData(vkey))
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		t.Fatalf("witness key %q: %v", vkey, err)
	}
	wk := witness.Key{Name: "runbook-witness", Pub: ed25519.PublicKey(raw[1:])}

	// 1.2 The ceremony, offline. The program refuses without a terminal
	// (2: the terminal rules); the ceremony itself runs through the seams.
	r.step("1.2", "Zeremonie: ohne Terminal verweigert")
	export := filepath.Join(dir, "export")
	code, _, e := r.refuse("", "gomail-ceremony", "init", "--shares", "3-of-5", "--out", export, "--keys", r.keys, "--origin", r.origin,
		"--witness", "runbook-witness="+vkey, "--min-witnesses", "1")
	if code == 0 || !strings.Contains(e, "Terminal") {
		t.Fatalf("ceremony without a terminal: exit %d %s", code, e)
	}
	for _, p := range []string{export, r.keys} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s written by a refused ceremony", p)
		}
	}
	r.step("1.2", "Zeremonie init 3-of-5 mit Probe-Rekonstruktion (Testseams)")
	sp := &sharePrompter{shown: map[int][]string{}}
	res, err := ceremony.Init(ceremony.InitOptions{Out: export, KeyDir: r.keys, Shares: ceremony.Shares{Threshold: 3, Count: 5},
		Origin: r.origin, Witnesses: []witness.Key{wk}, MinWitnesses: 1, Display: sp, Prompter: sp})
	if err != nil {
		t.Fatal(err)
	}
	if len(sp.shown) != 5 {
		t.Fatalf("%d shares shown, want 5", len(sp.shown))
	}
	// The trial reconstruction asked for three distinct shares of the
	// five by index (AskShare(want > 0)).
	probed := map[int]bool{}
	for _, i := range sp.asked {
		if i < 1 || i > 5 || probed[i] {
			t.Fatalf("trial reconstruction asked for shares %v, want three distinct of 1 to 5", sp.asked)
		}
		probed[i] = true
	}
	if len(probed) != 3 {
		t.Fatalf("trial reconstruction asked for shares %v, want three", sp.asked)
	}
	shares := sp.shown
	pin1 := filepath.Join(export, "identity-1.pin")
	for _, k := range []string{"admin-1.key", "ingest-1.key"} {
		if fi, err := os.Stat(filepath.Join(r.keys, k)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", k, fi, err)
		}
	}

	// 1.3 Distribution: the pin outside the data directory; nothing
	// private in the export.
	r.step("1.3", "Export ohne private Schlüssel, Pin außerhalb des Datenverzeichnisses")
	if keysIn(t, export) != nil {
		t.Fatalf("private keys in the export: %v", keysIn(t, export))
	}
	r.pin = pin1

	// 1.4 The data directory.
	r.step("1.4", "Datenverzeichnis anlegen (gomail-server init)")
	if out := r.run("", "gomail-server", "init", "--data", r.data, "--pin", r.pin, "--witnesses", filepath.Join(export, "platform", ceremony.WitnessesFile)); !strings.Contains(out, "gomail-ceremony publish") {
		t.Fatalf("init: %q", out)
	}
	if code, _, _ := r.refuse("", "gomail-server", r.serveArgs()...); code != 1 {
		t.Fatalf("server before publish: exit %d", code)
	}

	// 1.5 publish.
	r.step("1.5", "Veröffentlichen (gomail-ceremony publish)")
	if out := r.run("", "gomail-ceremony", "publish", "--from", export, "--data", r.data, "--pin", r.pin); !strings.Contains(out, "Server jetzt mit diesem Pin starten") {
		t.Fatalf("publish: %q", out)
	}

	// 1.6 The server (before the witness: the witness needs the log
	// address). Without a client, --require-client-lock refuses.
	r.step("1.6", "Server: --require-client-lock ohne Client verweigert")
	if code, _, e := r.refuse("", "gomail-server", append(r.serveArgs(), "--require-client-lock")...); code != 1 || !strings.Contains(e, "Testsperre") {
		t.Fatalf("serve --require-client-lock without a client: exit %d %s", code, e)
	}
	r.step("1.6", "Server mit --pin und --log-listen")
	r.startServer()
	if code, _, e := r.refuse("", "gomail-server", r.serveArgs()...); code != 1 || !strings.Contains(e, "Serversperre") {
		t.Fatalf("second server: exit %d %s", code, e)
	}

	// 1.7 The witness, with the log key formed as the RUNBOOK says.
	r.step("1.7", "Zeuge mit dem Prüfschlüssel des Logs")
	r.logKeys = []string{r.logKey(1)}
	r.startWitness()

	// 3. Users: invitation, keygen, registration.
	alice := &rbUser{name: "alice", dir: filepath.Join(dir, "alice"), pin: pin1}
	bob := &rbUser{name: "bob", dir: filepath.Join(dir, "bob"), pin: pin1}
	carol := &rbUser{name: "carol", dir: filepath.Join(dir, "carol"), pin: pin1}
	r.step("3.2", "keygen ohne Terminal verweigert (Produktionsregel)")
	if code, _, e := r.refuse("", "gomailctl", r.args(alice, "keygen")...); code != 1 || !strings.Contains(e, "Terminal") {
		t.Fatalf("keygen without a terminal: exit %d %s", code, e)
	}
	if _, err := os.Lstat(filepath.Join(alice.dir, "keystore")); err == nil {
		t.Fatal("key store written by a refused keygen")
	}
	if code, _, e := r.refuse("", "gomailctl", r.args(alice, "sync", "--insecure-no-log")...); code != 2 || !strings.Contains(e, "insecure-no-log") {
		t.Fatalf("gomailctl --insecure-no-log: exit %d %s", code, e)
	}
	used := ""
	for _, u := range []*rbUser{alice, bob, carol} {
		r.step("3.1", "Einladung für "+u.name)
		invite := strings.TrimSpace(r.run("", "gomail-server", "invite", "create", "--data", r.data))
		r.step("3.2", "keygen für "+u.name+" (Testbuild: Seed über eine Pipe)")
		r.keygen(u)
		r.step("3.4", "Registrieren: "+u.name)
		if used != "" {
			if code, _, e := r.refuse("", "gomailctl", r.args(u, "register", "--invite", used)...); code != 1 || !strings.Contains(e, "invitation") {
				t.Fatalf("registration with a used code: exit %d %s", code, e)
			}
		}
		out := r.run("", "gomailctl", r.args(u, "register", "--invite", invite)...)
		u.id = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "Registriert:"))
		if _, err := os.Stat(filepath.Join(r.data, "users", u.id, "user.rec")); err != nil {
			t.Fatal(err)
		}
		used = invite
	}

	// 4. The mailbox of alice, address, mail, list, read, search, flag.
	r.step("4.1", "Postfach anlegen (alice)")
	mbxOut, _ := r.ctl(alice, "", "mailbox", "create", "Büro")
	mbx := strings.TrimSpace(mbxOut)
	if _, err := store.ParseID(mbx); err != nil {
		t.Fatalf("mailbox create: %q", mbxOut)
	}
	r.step("4.2", "Adresse zuordnen (address add)")
	r.run("", "gomail-server", "address", "add", "info@brownbear.example", "--mailbox", mbx, "--data", r.data, "--admin-key", r.admin, "--pin", r.pin)
	r.step("4.3", "Mail einliefern (SMTP)")
	if err := mail(r.srv.smtp, "Rechnung 4711"); err != nil {
		t.Fatal(err)
	}
	if err := smtp.SendMail(r.srv.smtp, nil, "vorstand@brownbear.example", []string{"info@brownbear.example"}, []byte(rbSecretMail)); err != nil {
		t.Fatal(err)
	}
	if err := smtp.SendMail(r.srv.smtp, nil, "x@example.net", []string{"nobody@brownbear.example"}, []byte("Subject: x\r\n\r\nx\r\n")); smtpCode(err) != 550 {
		t.Fatalf("unknown address: %v", err)
	}
	r.step("4.4", "Auflisten (ohne Absender) und lesen")
	list, _ := r.listUntil(alice, mbx, "Rechnung 4711")
	if strings.Contains(list, "lieferant") {
		t.Fatalf("list shows the sender: %q", list)
	}
	mail1 := r.mailID(list, "Rechnung 4711")
	content, _ := r.ctl(alice, "", "read", mbx, mail1)
	if !strings.HasPrefix(content, "Received: ") || !strings.Contains(content, "Subject: Rechnung 4711\r\n") {
		t.Fatalf("read: %q", content)
	}
	// The mail with the secret word arrived as sent: the checks at the end
	// look for its text in the data directory and the server logs.
	list, _ = r.listUntil(alice, mbx, rbSecretSubject)
	if content, _ := r.ctl(alice, "", "read", mbx, r.mailID(list, rbSecretSubject)); !strings.HasSuffix(content, rbSecretMail) {
		t.Fatalf("read of the secret mail: %q", content)
	}
	if out, _ := r.ctl(alice, "", "list", mbx, "--folder", "INBOX"); !strings.Contains(out, mail1) {
		t.Fatalf("list --folder INBOX: %q", out)
	}
	r.step("4.5", "Suchen")
	if out, _ := r.ctl(alice, "", "search", mbx, "from:rechnung@lieferant.example"); !strings.Contains(out, mail1) || !strings.Contains(out, "INBOX") {
		t.Fatalf("search: %q", out)
	}
	if out, _ := r.ctl(alice, "", "search", mbx, "from:niemand@lieferant.example", "--since", time.Now().UTC().Format("2006-01")); strings.TrimSpace(out) != "" {
		t.Fatalf("search without a hit: %q", out)
	}
	r.step("4.6", "Flags setzen und entfernen")
	if out, _ := r.ctl(alice, "", "flag", mbx, mail1, "--set", "seen,flagged"); !strings.Contains(out, "flagged, seen (Version 2)") {
		t.Fatalf("flag --set: %q", out)
	}
	if out, _ := r.ctl(alice, "", "flag", mbx, mail1, "--clear", "flagged"); !strings.Contains(out, "seen (Version 3)") {
		t.Fatalf("flag --clear: %q", out)
	}
	r.step("4.9", "inspect")
	if out := r.run("", "gomailctl", "inspect", filepath.Join(r.data, "mailboxes", mbx, "epochs", "1", "epoch.rec")); !strings.Contains(out, `"_type": "gomail/v1/rec/epoch"`) {
		t.Fatalf("inspect: %q", out)
	}

	// 4.7 Sharing: bob from epoch 1 on, carol from the new epoch on;
	// then carol's access is revoked.
	r.step("4.7", "Teilen mit bob ab Epoche 1 (--from 1)")
	if out, _ := r.ctl(alice, "", "mailbox", "share", mbx, bob.id, "--from", "1"); !strings.Contains(out, "Mitglied") {
		t.Fatalf("share bob: %q", out)
	}
	r.listUntil(bob, mbx, "Rechnung 4711")
	if out, _ := r.ctl(bob, "", "search", mbx, "from:rechnung@lieferant.example"); !strings.Contains(out, mail1) {
		t.Fatalf("search by bob: %q", out)
	}
	r.step("4.7", "Teilen mit carol ab der neuen Epoche")
	r.ctl(alice, "", "mailbox", "share", mbx, carol.id)
	if out, _ := r.ctl(carol, "", "list", mbx); strings.Contains(out, "Rechnung 4711") {
		t.Fatalf("carol reads a mail before her epoch: %q", out)
	}
	if err := mail(r.srv.smtp, "Angebot Carol"); err != nil {
		t.Fatal(err)
	}
	out, _ := r.listUntil(carol, mbx, "Angebot Carol")
	carolEpoch := r.mailEpoch(mbx, r.mailID(out, "Angebot Carol"))
	if ms := r.epochMembers(r.epoch(mbx, carolEpoch)); !ms[carol.id] {
		t.Fatalf("carol is no member of epoch %d of her mail: %v", carolEpoch, ms)
	}
	r.step("4.7", "Zugriff von carol entziehen")
	revokeStart := time.Now()
	if out, _ := r.ctl(alice, "", "mailbox", "revoke", mbx, carol.id); !strings.Contains(out, "entzogen") {
		t.Fatalf("revoke: %q", out)
	}
	revokeEnd := time.Now()
	if err := mail(r.srv.smtp, "Nach dem Entzug"); err != nil {
		t.Fatal(err)
	}
	out, _ = r.listUntil(alice, mbx, "Nach dem Entzug")
	r.listUntil(bob, mbx, "Nach dem Entzug")
	// RUNBOOK 4.7: revoke began a new epoch at once, it is in the log and
	// carol is no member of it; the mail after the revocation is in it
	// (gomailctl inspect of the mail file and of the epoch.rec).
	r.step("4.7", "neue Epoche ohne carol, im Log, Mail nach dem Entzug darin (inspect)")
	revEpoch := r.mailEpoch(mbx, r.mailID(out, "Nach dem Entzug"))
	if revEpoch <= carolEpoch {
		t.Fatalf("mail after the revocation in epoch %d, carol's mail in epoch %d: no new epoch", revEpoch, carolEpoch)
	}
	ep := r.epoch(mbx, revEpoch)
	if reason, _ := ep["reason"].(float64); reason != float64(store.ReasonMemberRemoved) {
		t.Fatalf("epoch %d: reason %v, want %d (member removed)", revEpoch, ep["reason"], store.ReasonMemberRemoved)
	}
	if begin, _ := ep["begin"].(float64); int64(begin) < revokeStart.UnixMilli() || int64(begin) > revokeEnd.UnixMilli() {
		t.Fatalf("epoch %d begins at %v, not during the revocation [%d, %d]", revEpoch, ep["begin"], revokeStart.UnixMilli(), revokeEnd.UnixMilli())
	}
	if ms := r.epochMembers(ep); ms[carol.id] || !ms[alice.id] || !ms[bob.id] {
		t.Fatalf("members of epoch %d after the revocation of carol: %v", revEpoch, ms)
	}
	r.inLog(r.epochFile(mbx, revEpoch))
	if _, err := os.Lstat(filepath.Join(r.data, "mailboxes", mbx, "epochs", strconv.FormatUint(uint64(revEpoch), 10), "members", carol.id+".wrap")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wrap of carol for epoch %d: %v", revEpoch, err)
	}
	// Revoked, carol has no wrap of the current epoch any more: list
	// fails (exit 1) and shows nothing.
	if code, out, e := r.refuse("", "gomailctl", r.args(carol, "list", mbx)...); code != 1 || out != "" || !strings.Contains(e, "epoch keys not available") {
		t.Fatalf("carol after the revocation: exit %d %q %s", code, out, e)
	}
	r.step("4.8", "sync")
	for _, u := range []*rbUser{alice, bob} {
		if out, _ := r.ctl(u, "", "sync"); !strings.Contains(out, "Epochenvorrat aktuell") {
			t.Fatalf("sync %s: %q", u.name, out)
		}
	}
	r.step("4.10", "Exit-Codes: 2 Aufruffehler, 1 Fehler")
	if code, _, _ := r.refuse("", "gomailctl", r.args(alice, "search", mbx)...); code != 2 {
		t.Fatalf("search without a term: exit %d", code)
	}
	if code, _, _ := r.refuse("", "gomailctl", r.args(alice, "flag", mbx, mail1, "--set", "seen,unbekannt")...); code != 1 {
		t.Fatalf("flag with an unknown name: exit %d", code)
	}

	// 5. Device lost: bob, with the seed; a new generation, alice wraps
	// the mailbox for it on her next sync.
	r.step("5.1", "device lost (bob): neue Generation")
	if out, _ := r.ctl(bob, strings.Join(bob.words, " ")+"\n", "device", "lost"); !strings.Contains(out, "Neue Generation 2") {
		t.Fatalf("device lost: %q", out)
	}
	r.step("5.1", "sync der anderen Mitglieder verpackt neu; bob liest wieder")
	r.ctl(alice, "", "sync")
	if err := mail(r.srv.smtp, "Nach dem Geräteverlust"); err != nil {
		t.Fatal(err)
	}
	r.listUntil(bob, mbx, "Rechnung 4711", "Nach dem Geräteverlust")
	r.step("5.2", "restore aus Wörtern auf einem neuen Gerät (bob)")
	bob2 := &rbUser{name: "bob (neues Gerät)", dir: filepath.Join(dir, "bob-neu"), pin: pin1}
	if out, _ := r.ctl(bob2, strings.Join(bob.words, " ")+"\n", "restore"); !strings.Contains(out, bob.id) {
		t.Fatalf("restore: %q", out)
	}
	r.listUntil(bob2, mbx, "Rechnung 4711", "Nach dem Geräteverlust")
	// keygen --shares shows the shares only on a terminal (tested on a
	// pseudo terminal in cmd/gomailctl); here they are split from the
	// seed of alice the way keygen splits it (shamir.Split, 2-of-3).
	r.step("5.3", "restore aus 2 von 3 Anteilen auf einem neuen Gerät (alice)")
	seed, err := keys.SeedFromWords(alice.words)
	if err != nil {
		t.Fatal(err)
	}
	split, err := shamir.Split(seed[:], 2, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	alice2 := &rbUser{name: "alice (neues Gerät)", dir: filepath.Join(dir, "alice-neu"), pin: pin1}
	typed := strings.Join(split[2].Words(), " ") + "\n" + strings.Join(split[0].Words(), " ") + "\n"
	if out, _ := r.ctl(alice2, typed, "restore", "--shares", "2"); !strings.Contains(out, alice.id) {
		t.Fatalf("restore --shares: %q", out)
	}
	r.listUntil(alice2, mbx, "Rechnung 4711", "Nach dem Geräteverlust")

	// 6. Ingest rotation under identity 1. Before the switch, a server
	// that still holds ingest key 1 signs a mail before valid_from and
	// one after it; after the switch gomailctl shows the first and
	// refuses the second (task 14c: metadata of ingest generation 1 after
	// valid_from of ingest-2.cert).
	r.step("6", "ingest-rotate (Testseams), valid_from in wenigen Sekunden")
	validFrom := time.Now().Add(12 * time.Second).Truncate(time.Second)
	rot := filepath.Join(dir, "export-rotate")
	if _, err := ceremony.IngestRotate(ceremony.RotateOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 1, IdentityPub: res.IdentityPub,
		Prompter: holders(shares, 2, 4, 5)}, Out: rot, KeyDir: r.keys, Gen: 2, ValidFrom: validFrom}); err != nil {
		t.Fatal(err)
	}
	r.stop()
	staleIngest(t, r.data, r.pin, r.ingestKey, validFrom.Add(-time.Second), "Ingest 1 vor dem Umschalten")
	staleIngest(t, r.data, r.pin, r.ingestKey, validFrom.Add(time.Second), "Ingest 1 nach dem Umschalten")
	r.step("6", "publish der Rotation vor dem Umschalten")
	r.run("", "gomail-ceremony", "publish", "--from", rot, "--data", r.data, "--pin", r.pin)
	time.Sleep(time.Until(validFrom.Add(1500 * time.Millisecond)))
	r.step("6", "nach valid_from: Server mit ingest-1.key verweigert, startet mit ingest-2.key")
	if code, _, e := r.refuse("", "gomail-server", r.serveArgs()...); code != 1 || !strings.Contains(e, "superseded") {
		t.Fatalf("server with ingest key 1 after valid_from: exit %d %s", code, e)
	}
	r.ingestKey = filepath.Join(r.keys, "ingest-2.key")
	r.startServer()
	r.logKeys = append(r.logKeys, r.logKey(2))
	r.startWitness()
	if err := mail(r.srv.smtp, "Nach der Rotation"); err != nil {
		t.Fatal(err)
	}
	r.step("6", "gomailctl lehnt Metadaten der Ingest-Generation 1 nach valid_from ab")
	list, warn := r.listUntil(alice, mbx, "Nach der Rotation", "Ingest 1 vor dem Umschalten", "Rechnung 4711")
	if strings.Contains(list, "Ingest 1 nach dem Umschalten") {
		t.Fatalf("list shows metadata of ingest generation 1 after valid_from:\n%s", list)
	}
	// The same path before valid_from is shown: the refusal is the end of
	// generation 1 at valid_from (until), nothing else.
	if n := strings.Count(warn, "wird nicht verarbeitet: Plattformzertifikat oder Annahmeschlüssel nicht gültig"); n != 1 {
		t.Fatalf("%d warnings for the refused mail, want 1:\n%s", n, warn)
	}

	// 7. Succession of the platform identity 1 to 2.
	r.step("7.3", "succeed --compromised gesperrt (Q19)")
	if code, _, e := r.refuse("", "gomail-ceremony", "succeed", "--pin", pin1, "--out", filepath.Join(dir, "export-c"), "--compromised"); code != 2 || !strings.Contains(e, "Q19") {
		t.Fatalf("succeed --compromised: exit %d %s", code, e)
	}
	r.step("7.1", "succeed (Testseams)")
	out2 := filepath.Join(dir, "export-2")
	if _, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 1, IdentityPub: res.IdentityPub,
		Prompter: holders(shares, 5, 1, 3)}, Out: out2, Pin: res.Pin}); err != nil {
		t.Fatal(err)
	}
	pin2 := filepath.Join(out2, "identity-2.pin")
	r.step("7.1", "publish verweigert neben dem laufenden Server")
	if code, _, e := r.refuse("", "gomail-ceremony", "publish", "--from", out2, "--data", r.data, "--pin", pin2); code != 1 || !strings.Contains(e, "Server läuft") {
		t.Fatalf("publish beside the server: exit %d %s", code, e)
	}
	r.stop()
	r.step("7.1", "publish mit dem neuen Pin, Server mit altem Pin verweigert, mit neuem startet")
	r.run("", "gomail-ceremony", "publish", "--from", out2, "--data", r.data, "--pin", pin2)
	if code, _, e := r.refuse("", "gomail-server", r.serveArgs()...); code != 1 || !strings.Contains(e, "kennt nur 1 bis 1") {
		t.Fatalf("server with pin 1 after the succession: exit %d %s", code, e)
	}
	r.pin = pin2
	r.startServer()
	r.startWitness()
	if err := mail(r.srv.smtp, "Nach der Nachfolge"); err != nil {
		t.Fatal(err)
	}
	r.step("7.1", "Clients mit neuem Pin (alice) und mit altem Pin (bob)")
	alice.pin = pin2
	r.listUntil(alice, mbx, "Nach der Nachfolge", "Rechnung 4711")
	r.listUntil(bob, mbx, "Nach der Nachfolge", "Rechnung 4711")

	// 8. Faults: log repair on a stopped server; the client refuses
	// without a server.
	r.step("8.2", "log repair bei angehaltenem Server")
	if code, _, e := r.refuse("", "gomail-server", "log", "repair", "--data", r.data, "--pin", r.pin); code != 1 || !strings.Contains(e, "Server-Sperre") {
		t.Fatalf("log repair beside the server: exit %d %s", code, e)
	}
	r.stop()
	if out := r.run("", "gomail-server", "log", "repair", "--data", r.data, "--pin", r.pin); !strings.Contains(out, "0 verwaiste Einträge gemeldet, 0 verworfen") {
		t.Fatalf("log repair: %q", out)
	}
	if code, _, e := r.refuse("", "gomailctl", r.args(alice, "list", mbx)...); code != 1 || !strings.Contains(e, "Testsperre") {
		t.Fatalf("client without a server: exit %d %s", code, e)
	}

	// Throughout: no private key and no plaintext in the data directory,
	// no plaintext and no address in the server log.
	r.step("1.3", "keine privaten Schlüssel und kein Klartext im Datenverzeichnis")
	if ks := keysIn(t, r.data); ks != nil {
		t.Fatalf("private keys in the data directory: %v", ks)
	}
	// Subjects, the text of the mails and the secret word, and the
	// senders; the recipient address only for the server logs (it is in
	// the logged address assignment by design, 4.2).
	plain := []string{"Rechnung 4711", "Angebot Carol", "Nach dem Entzug", "Nach dem Geräteverlust", "Nach der Rotation", "Nach der Nachfolge",
		"Ingest 1 vor dem Umschalten", "Ingest 1 nach dem Umschalten", rbSecretSubject, "Nordlicht", rbSecretText, rbSecretWord, "Hallo",
		"lieferant", "vorstand"}
	if hits := filesContaining(t, r.data, plain...); hits != nil {
		t.Fatalf("plaintext in the data directory: %v", hits)
	}
	for i, srv := range r.servers {
		logs := srv.Logs()
		if !strings.Contains(logs, "listening") {
			t.Fatalf("log of server %d not captured: %q", i+1, logs)
		}
		for _, s := range append(plain, "brownbear") {
			if strings.Contains(logs, s) {
				t.Fatalf("log of server %d contains %q", i+1, s)
			}
		}
	}
	if logs := r.servers[0].Logs(); !strings.Contains(logs, "status=250") {
		t.Fatalf("log of server 1 shows no delivery:\n%s", logs)
	}
	if d := time.Since(r.start); d > 5*time.Minute {
		t.Errorf("TestRunbook took %v, more than 5 minutes", d)
	}
	r.step("-", "fertig")
}

// rbSecretMail is a mail with a secret word in its body (RUNBOOK 1.3:
// no plaintext in the data directory, none in the server log).
const (
	rbSecretSubject = "Geheimprojekt Nordlicht"
	rbSecretText    = "Der Termin bleibt intern."
	rbSecretWord    = "Polarfuchs-Morgenrot"
	rbSecretMail    = "From: Vorstand <vorstand@brownbear.example>\r\nTo: info@brownbear.example\r\nSubject: " + rbSecretSubject +
		"\r\n\r\n" + rbSecretText + "\r\nKennwort: " + rbSecretWord + "\r\n"
)

// inspect runs "gomailctl inspect" on path (RUNBOOK 4.9) and decodes its
// JSON.
func (r *runbook) inspect(path string) map[string]any {
	r.t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(r.run("", "gomailctl", "inspect", path)), &v); err != nil {
		r.t.Fatalf("inspect %s: %v", path, err)
	}
	return v
}

// mailEpoch returns the epoch of the header of the mail file of id in
// mbx, as inspect shows it.
func (r *runbook) mailEpoch(mbx, id string) uint32 {
	r.t.Helper()
	files, _ := filepath.Glob(filepath.Join(r.data, "mailboxes", mbx, "mail", "*", id+".gml"))
	if len(files) != 1 {
		r.t.Fatalf("mail %s: files %v", id, files)
	}
	h, _ := r.inspect(files[0])["header"].(map[string]any)
	n, ok := h["epoch"].(float64)
	if !ok || n < 1 {
		r.t.Fatalf("mail %s: header %v", id, h)
	}
	return uint32(n)
}

func (r *runbook) epochFile(mbx string, n uint32) string {
	return filepath.Join(r.data, "mailboxes", mbx, "epochs", strconv.FormatUint(uint64(n), 10), "epoch.rec")
}

// epoch returns epoch.rec of epoch n of mbx as inspect shows it.
func (r *runbook) epoch(mbx string, n uint32) map[string]any {
	r.t.Helper()
	return r.inspect(r.epochFile(mbx, n))
}

// epochMembers returns the IDs of the members of an epoch shown by
// inspect.
func (r *runbook) epochMembers(e map[string]any) map[string]bool {
	r.t.Helper()
	list, ok := e["members"].([]any)
	if !ok || len(list) == 0 {
		r.t.Fatalf("epoch without members: %v", e)
	}
	ms := map[string]bool{}
	for _, m := range list {
		mm, _ := m.(map[string]any)
		id, _ := mm["id"].(string)
		ms[id] = true
	}
	return ms
}

// inLog checks that the record at path is in the log of the data
// directory (an entry holds its bytes unchanged, translog doc.go) and
// that a head cosigned by the witness covers that entry.
func (r *runbook) inLog(path string) {
	r.t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(r.data, "log", "entries"))
	if err != nil {
		r.t.Fatal(err)
	}
	index := int64(-1)
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), ".rec")
		i, err := strconv.ParseInt(n, 10, 64)
		if !ok || err != nil {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(r.data, "log", "entries", e.Name())); err == nil && bytes.Contains(b, want) {
			index = i
			break
		}
	}
	if index < 0 {
		r.t.Fatalf("%s is in no entry of the log", path)
	}
	heads, _ := filepath.Glob(filepath.Join(r.data, "log", "heads", "*.sig"))
	for _, h := range heads {
		if size, err := strconv.ParseInt(strings.TrimSuffix(filepath.Base(h), ".sig"), 10, 64); err == nil && size > index {
			return
		}
	}
	r.t.Fatalf("%s: entry %d covered by no head of the log (%v)", path, index, heads)
}

// keysIn returns the files below root whose name ends in .key.
func keysIn(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".key") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// filesContaining returns the files below root that hold one of texts.
func filesContaining(t *testing.T, root string, texts ...string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, s := range texts {
			if bytes.Contains(b, []byte(s)) {
				found = append(found, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}
