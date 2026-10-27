package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
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
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	if prodDir != "" {
		os.RemoveAll(prodDir)
	}
	os.Exit(code)
}

// testMinFree is the free-space fraction the server programs of these
// tests require (GOMAIL_TEST_MIN_FREE, read only by a build with the tag
// gomail_test, task 15c finding 7): the tests must not fail on the free
// space of the host (452 below the 10 % of 5.1).
const testMinFree = "GOMAIL_TEST_MIN_FREE=0.000001"

// testHeadGap lets the server of a test build sign a head at most every
// second while the log grows (GOMAIL_TEST_HEAD_GAP, task 14) instead of
// once a minute, and testDevIdentity lets gomailctl of a test build
// accept the development pin of the ceremony (GOMAIL_TEST_DEV_IDENTITY,
// client.Config.AllowDevIdentity).
const (
	testHeadGap     = "GOMAIL_TEST_HEAD_GAP=1s"
	testDevIdentity = "GOMAIL_TEST_DEV_IDENTITY=1"
)

// buildTags are the tags of the programs of these tests: gomail_test,
// the hidden test switch of gomail-server (cmd/gomail-server/
// testconfig_tagged.go), and gomail_dev, the development ceremony
// "gomail-ceremony init --dev" (task 15b point 4).
const buildTags = "gomail_dev,gomail_test"

// programs builds the four programs once, with buildTags, and returns
// their directory.
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
		build := exec.Command("go", "build", "-tags", buildTags, "-o", dir+string(os.PathSeparator), "github.com/tim-riep/go-mail/cmd/...")
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
	// witnessKey and origin are the note signer key file of the pinned
	// witness and the log origin; empty, those of the development
	// ceremony (keys/witness-dev.key, gomail-dev).
	witnessKey, origin string
}

func newPlatform(t *testing.T) *platform {
	t.Helper()
	dir := t.TempDir()
	p := &platform{t: t, bin: programs(t), dir: dir, data: filepath.Join(dir, "data"), keys: filepath.Join(dir, "keys")}
	p.pin, p.ingestKey, p.admin = filepath.Join(p.keys, "identity-1.pin"), filepath.Join(p.keys, "ingest-1.key"), filepath.Join(p.keys, "admin-1.key")
	// InitDev writes the certificates into the log of the data directory;
	// gomail-ceremony has no --insecure-no-log any more (task 15b).
	p.run("", "gomail-ceremony", "init", "--dev", "--data", p.data, "--keys", p.keys)
	return p
}

// exec runs a program and returns its exit code, standard output and
// standard error.
func (p *platform) exec(stdin, name string, args ...string) (int, string, string) {
	p.t.Helper()
	cmd := exec.Command(filepath.Join(p.bin, name), args...)
	cmd.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple", testMinFree, testHeadGap, testDevIdentity)
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

// startServer starts gomail-server with serveArgs and returns once both
// listeners are up (startServerProc).
func (p *platform) startServer() *serverProc {
	p.t.Helper()
	return startServerProc(p.t, p.bin, append(os.Environ(), testMinFree, testHeadGap), p.serveArgs())
}

// startWitness starts gomail-witness with the witness key of the
// platform (that of the development ceremony unless witnessKey is set)
// against the log side of s, which signs with ingest generation 1.
func (p *platform) startWitness(s *serverProc) {
	p.t.Helper()
	p.startWitnessGen(s, 1)
}

// startWitnessGen is startWitness for a log side that signs with ingest
// generation gen; it returns the function that stops the witness (it
// stops at the end of the test in any case).
func (p *platform) startWitnessGen(s *serverProc, gen uint32) (stop func()) {
	p.t.Helper()
	ipub, err := os.ReadFile(filepath.Join(p.data, "platform", store.PlatformFileName("ingest", gen, "pub")))
	if err != nil {
		p.t.Fatal(err)
	}
	wkey, origin := filepath.Join(p.keys, "witness-dev.key"), "gomail-dev"
	if p.witnessKey != "" {
		wkey, origin = p.witnessKey, p.origin
	}
	vkey, err := note.NewEd25519VerifierKey(translog.LogSignerName, ed25519.PublicKey(ipub))
	if err != nil {
		p.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(p.bin, "gomail-witness"), "serve", "--log", "http://"+s.log, "--log-key", vkey,
		"--origin", origin, "--key", wkey, "--state", filepath.Join(p.dir, "witness-state"),
		"--interval", "1s")
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cmd.Process.Signal(os.Interrupt)
			cmd.Wait()
			cancel()
		})
	}
	p.t.Cleanup(stop)
	return stop
}

// runLogged runs a gomailctl command until it succeeds, at most for a
// minute: it needs a head with the witness's cosignature that covers the
// newest log entries (task 14), which the server signs at most every
// second while the log grows (testHeadGap) and the witness cosigns
// within a second. It returns the output of the successful run.
func (p *platform) runLogged(stdin, name string, args ...string) string {
	p.t.Helper()
	var errb string
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		code, out, e := p.exec(stdin, name, args...)
		if code == 0 {
			return out
		}
		errb = e
	}
	p.t.Fatalf("%s %v: no success within a minute\n%s", name, args, errb)
	return ""
}

// keygen runs "gomailctl keygen" with the arguments common and answers
// the three questions from the words shown. A production gomailctl
// shows the seed only on a terminal and reads the words only from one
// (task 13b, tested on a pseudo terminal in cmd/gomailctl); the test
// build runs on pipes with GOMAILCTL_TEST_KEYGEN_PIPE=1 and accepts the
// development pin with GOMAIL_TEST_DEV_IDENTITY=1 (task 14).
func (p *platform) keygen(common []string) {
	t := p.t
	t.Helper()
	kg := exec.Command(filepath.Join(p.bin, "gomailctl"), append([]string{"keygen"}, common...)...)
	kg.Env = append(os.Environ(), "GOMAILCTL_PASSPHRASE=correct horse battery staple", "GOMAILCTL_TEST_KEYGEN_PIPE=1", testDevIdentity)
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
	common := []string{"--data", p.data, "--dir", filepath.Join(p.dir, "c"), "--pin", p.pin}
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
