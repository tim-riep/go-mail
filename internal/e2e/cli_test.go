package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
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

	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// binDir holds the programs built once for all tests of the package.
var (
	binOnce sync.Once
	binDir  string
	binErr  error
)

func TestMain(m *testing.M) {
	// The test binary doubles as the client log helper of
	// scripts/two-host-test.sh (twohost_test.go).
	if os.Getenv(helperEnv) == helperLogAppend {
		os.Exit(logAppendMain(os.Args[1:], os.Stdout, os.Stderr))
	}
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// testMinFree is the free-space fraction the server programs of these
// tests require (GOMAIL_TEST_MIN_FREE, read only by a build with the tag
// gomail_test, task 15c finding 7): the tests must not fail on the free
// space of the host (452 below the 10 % of 5.1).
const testMinFree = "GOMAIL_TEST_MIN_FREE=0.000001"

// programs builds the four programs once, with the tag gomail_test (the
// hidden test switch of gomail-server, cmd/gomail-server/
// testconfig_tagged.go), and returns their directory.
func programs(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the programs")
	}
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gomail-e2e-bin-")
		if err != nil {
			binErr = err
			return
		}
		binDir = dir
		build := exec.Command("go", "build", "-tags", "gomail_test", "-o", dir+string(os.PathSeparator), "github.com/tim-riep/go-mail/cmd/...")
		build.Env = os.Environ()
		if out, err := build.CombinedOutput(); err != nil {
			binErr = errors.New(err.Error() + "\n" + string(out))
		}
	})
	if binErr != nil {
		t.Fatalf("build: %v", binErr)
	}
	return binDir
}

// platform is a development platform made with the ceremony program.
type platform struct {
	t                     *testing.T
	bin, dir, data, keys  string
	pin, ingestKey, admin string
}

func newPlatform(t *testing.T) *platform {
	t.Helper()
	dir := t.TempDir()
	p := &platform{t: t, bin: programs(t), dir: dir, data: filepath.Join(dir, "data"), keys: filepath.Join(dir, "keys")}
	p.pin, p.ingestKey, p.admin = filepath.Join(p.keys, "identity-1.pin"), filepath.Join(p.keys, "ingest-1.key"), filepath.Join(p.keys, "admin-1.key")
	// TODO(task-15b): the ceremony program still needs --insecure-no-log;
	// InitDev writes the certificates into the log of the data directory.
	p.run("", "gomail-ceremony", "init", "--dev", "--data", p.data, "--keys", p.keys, "--insecure-no-log")
	return p
}

// exec runs a program and returns its exit code, standard output and
// standard error.
func (p *platform) exec(stdin, name string, args ...string) (int, string, string) {
	p.t.Helper()
	cmd := exec.Command(filepath.Join(p.bin, name), args...)
	cmd.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple", testMinFree)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		p.t.Fatalf("%s %v: %v", name, args, err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errb.String()
}

// run runs a program that must succeed and returns its output.
func (p *platform) run(stdin, name string, args ...string) string {
	p.t.Helper()
	code, out, errb := p.exec(stdin, name, args...)
	if code != 0 {
		p.t.Fatalf("%s %v: exit %d\n%s", name, args, code, errb)
	}
	return out
}

func (p *platform) serveArgs() []string {
	return []string{"serve", "--data", p.data, "--listen", "127.0.0.1:0", "--ingest-key", p.ingestKey, "--pin", p.pin, "--log-listen", "127.0.0.1:0"}
}

// serverProc is a running gomail-server.
type serverProc struct {
	cmd       *exec.Cmd
	smtp, log string
	mu        sync.Mutex
	logs      bytes.Buffer
}

func (s *serverProc) Logs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logs.String()
}

// stop ends the server with SIGINT and waits for it.
func (s *serverProc) stop() {
	s.cmd.Process.Signal(os.Interrupt)
	s.cmd.Wait()
}

// startServerProgram starts gomail-server and returns once both
// listeners are up.
func (p *platform) startServer() *serverProc {
	p.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p.t.Cleanup(cancel)
	s := &serverProc{cmd: exec.CommandContext(ctx, filepath.Join(p.bin, "gomail-server"), p.serveArgs()...)}
	s.cmd.Env = append(os.Environ(), testMinFree)
	stderr, _ := s.cmd.StderrPipe()
	if err := s.cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(s.stop)
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
			p.t.Fatalf("server did not start:\n%s", s.Logs())
		}
	}
	return s
}

// startWitness starts gomail-witness with the development witness key of
// the ceremony against the log side of s.
func (p *platform) startWitness(s *serverProc) {
	p.t.Helper()
	ipub, err := os.ReadFile(filepath.Join(p.data, "platform", "ingest-1.pub"))
	if err != nil {
		p.t.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(translog.LogSignerName, ed25519.PublicKey(ipub))
	if err != nil {
		p.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(p.bin, "gomail-witness"), "serve", "--log", "http://"+s.log, "--log-key", vkey,
		"--origin", "gomail-dev", "--key", filepath.Join(p.keys, "witness-dev.key"), "--state", filepath.Join(p.dir, "witness-state"),
		"--interval", "1s")
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
		cancel()
	})
}

// logAsClient appends records to the operator log of the data directory
// as the client will do itself. TODO(task-14): gomailctl appends user,
// epochs and the signer's user.rec to the log; until then it runs with
// --insecure-no-log, and the test logs what it wrote.
func (p *platform) logAsClient(kind translog.Kind, files ...string) {
	p.t.Helper()
	if _, err := appendAsClient(p.data, p.pin, kind, files...); err != nil {
		p.t.Fatal(err)
	}
}

// TestRunbook builds the programs and runs the steps of docs/RUNBOOK.md:
// ceremony, server with the transparency log and a witness, keygen,
// invite, register, mailbox, address, mail via SMTP, list, read,
// inspect, sync.
func TestRunbook(t *testing.T) {
	p := newPlatform(t)
	data, keys, alice := p.data, p.keys, filepath.Join(p.dir, "alice")
	run := p.run
	common := []string{"--data", data, "--dir", alice, "--platform", p.pin, "--insecure-no-log"}

	// 2. Server, only with the log; then the witness.
	if code, _, _ := p.exec("", "gomail-server", "serve", "--data", data, "--ingest-key", p.ingestKey); code != 2 {
		t.Fatalf("server without --pin: exit %d", code)
	}
	srv := p.startServer()
	p.startWitness(srv)

	// 3. keygen: answer the three questions from the words shown.
	kg := exec.Command(filepath.Join(p.bin, "gomailctl"), append([]string{"keygen"}, common...)...)
	kg.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple")
	stdin, _ := kg.StdinPipe()
	stdout, _ := kg.StdoutPipe()
	stderr, _ := kg.StderrPipe()
	if err := kg.Start(); err != nil {
		t.Fatal(err)
	}
	words := map[int]string{}
	sc := bufio.NewScanner(stdout)
	wordRe := regexp.MustCompile(`(\d+)\. (\S+)`)
	for sc.Scan() && len(words) < 24 {
		for _, m := range wordRe.FindAllStringSubmatch(sc.Text(), -1) {
			n, _ := strconv.Atoi(m[1])
			words[n] = m[2]
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
		io.WriteString(stdin, words[n]+"\n")
	}
	go io.Copy(io.Discard, stdout)
	go io.Copy(io.Discard, er)
	if err := kg.Wait(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 4. Invitation and registration.
	code := strings.TrimSpace(run("", "gomail-server", "invite", "create", "--data", data))
	reg := run("", "gomailctl", append([]string{"register", "--invite", code}, common...)...)
	userID := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reg), "Registriert:"))
	p.logAsClient(translog.KindUser, filepath.Join(data, "users", userID, "user.rec"))

	// 5. Mailbox and address.
	mbx := strings.TrimSpace(run("", "gomailctl", append([]string{"mailbox", "create", "Büro"}, common...)...))
	epochs, _ := filepath.Glob(filepath.Join(data, "mailboxes", mbx, "epochs", "*", "epoch.rec"))
	if len(epochs) == 0 {
		t.Fatal("no epochs")
	}
	for n := 1; n <= len(epochs); n++ {
		p.logAsClient(translog.KindEpoch, filepath.Join(data, "mailboxes", mbx, "epochs", strconv.Itoa(n), "epoch.rec"))
	}
	if c, _, _ := p.exec("", "gomail-server", "address", "add", "info@brownbear.example", "--mailbox", mbx, "--data", data,
		"--admin-key", p.admin, "--insecure-no-log"); c != 2 {
		t.Fatalf("address add with --insecure-no-log: exit %d", c)
	}
	run("", "gomail-server", "address", "add", "info@brownbear.example", "--mailbox", mbx, "--data", data,
		"--admin-key", p.admin, "--pin", p.pin)

	// 6. A mail via SMTP.
	msg := "From: rechnung@lieferant.example\r\nTo: info@brownbear.example\r\nSubject: Rechnung 4711\r\n\r\nHallo.\r\n"
	if err := smtp.SendMail(srv.smtp, nil, "rechnung@lieferant.example", []string{"info@brownbear.example"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	// A second mail with a known secret phrase in header and body.
	secret := "Subject: Geheimprojekt Nordlicht\r\nFrom: vorstand@brownbear.example\r\nTo: info@brownbear.example\r\n\r\nKennwort: Nordlicht-2026\r\n"
	if err := smtp.SendMail(srv.smtp, nil, "vorstand@brownbear.example", []string{"info@brownbear.example"}, []byte(secret)); err != nil {
		t.Fatal(err)
	}

	// 7. list, read, inspect, sync.
	list := run("", "gomailctl", append([]string{"list", mbx}, common...)...)
	if !strings.Contains(list, "Rechnung 4711") {
		t.Fatalf("list: %q", list)
	}
	var mailID string
	for _, line := range strings.Split(list, "\n") {
		if strings.Contains(line, "Rechnung 4711") {
			mailID = strings.Fields(line)[0]
		}
	}
	content := run("", "gomailctl", append([]string{"read", mbx, mailID}, common...)...)
	if !strings.HasSuffix(content, msg) || !strings.HasPrefix(content, "Received: ") {
		t.Fatalf("read: %q", content)
	}
	run("", "gomailctl", append([]string{"list", mbx, "--folder", "INBOX"}, common...)...)
	insp := run("", "gomailctl", "inspect", filepath.Join(data, "mailboxes", mbx, "epochs", "1", "epoch.rec"))
	if !strings.Contains(insp, `"_type": "gomail/v1/rec/epoch"`) {
		t.Fatalf("inspect: %q", insp)
	}
	run("", "gomailctl", append([]string{"sync"}, common...)...)

	// The witness cosigned a head of the server: heads/<n>.sig.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if hs, _ := filepath.Glob(filepath.Join(data, "log", "heads", "*.sig")); len(hs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no head published:\n%s", srv.Logs())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The server log holds no content and no addresses.
	srv.stop()
	logs := srv.Logs()
	for _, s := range []string{"Rechnung", "lieferant", "brownbear", "Hallo", "Nordlicht", "vorstand"} {
		if strings.Contains(logs, s) {
			t.Fatalf("server log contains %q", s)
		}
	}
	if !strings.Contains(logs, "status=250") || !strings.Contains(logs, "head published") {
		t.Fatalf("server log: %s", logs)
	}
	// Without a running server the client refuses (9.1, Testsperre).
	if c, _, e := p.exec("", "gomailctl", append([]string{"list", mbx}, common...)...); c != 1 || !strings.Contains(e, "Testsperre") {
		t.Fatalf("client without a server: exit %d %s", c, e)
	}
	// GOMAIL_E2E_KEEP=<dir> keeps a copy of the data directory (only the
	// data directory: no keys, no client) for an independent review.
	if keep := os.Getenv("GOMAIL_E2E_KEEP"); keep != "" {
		if out, err := exec.Command("cp", "-a", data, keep).CombinedOutput(); err != nil {
			t.Fatalf("keep: %v %s", err, out)
		}
	}
	_ = keys
}

// TestProgramsRefuse: the start checks of task 15 with the built
// programs (built with the tag gomail_test, see programs). --insecure-no-log is no switch of gomail-server any more
// (usage error), a pin without witness quorum keeps the server from
// starting, a second server on the data directory does not start, and a
// client without an effective server lock refuses.
func TestProgramsRefuse(t *testing.T) {
	p := newPlatform(t)
	args := p.serveArgs()
	if code, _, e := p.exec("", "gomail-server", append(args, "--insecure-no-log")...); code != 2 || !strings.Contains(e, "insecure-no-log") {
		t.Fatalf("serve --insecure-no-log: exit %d %s", code, e)
	}
	if code, _, _ := p.exec("", "gomail-server", "serve", "--data", p.data, "--ingest-key", p.ingestKey, "--insecure-no-log"); code != 2 {
		t.Fatalf("serve --insecure-no-log without pin: exit %d", code)
	}

	// A pin whose quorum violates 2*min > n (1 of 2).
	pin, err := store.ReadPlatformPin(p.pin)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _ := ed25519.GenerateKey(nil)
	ws := []*rec.Record{
		rec.New(store.WitnessSchema).SetString(1, pin.Witnesses[0].Name).SetBytes(2, pin.Witnesses[0].Pub),
		rec.New(store.WitnessSchema).SetString(1, "second-witness").SetBytes(2, second),
	}
	ids := []*rec.Record{rec.New(store.PlatformIdentitySchema).SetU32(1, 1).SetBytes(2, pin.Identities[0].Pub)}
	bad, err := rec.New(store.PlatformPinSchema).SetU32(1, 1).SetBytes(2, pin.Pub).SetU8(3, 1).SetString(4, pin.Origin).
		SetList(5, ws).SetU32(6, 1).SetList(8, ids).Encode()
	if err != nil {
		t.Fatal(err)
	}
	badPin := filepath.Join(p.dir, "bad.pin")
	if err := os.WriteFile(badPin, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	badArgs := append([]string(nil), args...)
	for i := range badArgs {
		if badArgs[i] == p.pin {
			badArgs[i] = badPin
		}
	}
	if code, _, e := p.exec("", "gomail-server", badArgs...); code != 1 || !strings.Contains(e, "Pin") {
		t.Fatalf("pin without quorum: exit %d %s", code, e)
	}

	// A client without a running server.
	common := []string{"--data", p.data, "--dir", filepath.Join(p.dir, "c"), "--platform", p.pin, "--insecure-no-log"}
	if code, _, e := p.exec("", "gomailctl", append([]string{"sync"}, common...)...); code != 1 || !strings.Contains(e, "Testsperre") {
		t.Fatalf("client without a server: exit %d %s", code, e)
	}

	// The hidden test switch (task 15c finding 7) is read by the test
	// build: a value outside (0, 1) stops the start (fail closed).
	sw := exec.Command(filepath.Join(p.bin, "gomail-server"), args...)
	sw.Env = append(os.Environ(), "GOMAIL_TEST_MIN_FREE=2")
	if out, err := sw.CombinedOutput(); sw.ProcessState == nil || sw.ProcessState.ExitCode() != 1 || !strings.Contains(string(out), "GOMAIL_TEST_MIN_FREE") {
		t.Fatalf("serve with GOMAIL_TEST_MIN_FREE=2: %v %s", err, out)
	}

	// A second server beside a running one.
	srv := p.startServer()
	if code, _, e := p.exec("", "gomail-server", args...); code != 1 || !strings.Contains(e, "Serversperre") {
		t.Fatalf("second server: exit %d %s", code, e)
	}
	// Beside the running server the client passes the lock check (and
	// fails for the missing user).
	if code, _, e := p.exec("", "gomailctl", append([]string{"sync"}, common...)...); code != 1 || strings.Contains(e, "Testsperre") {
		t.Fatalf("client beside the server: exit %d %s", code, e)
	}
	srv.stop()
}
