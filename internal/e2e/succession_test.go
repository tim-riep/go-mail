package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// sharePrompter is the Prompter and the Display of the ceremonies of
// these tests (the seams of task 10c: ceremony.Prompter and
// InitOptions.Display; the command line asks the same on a terminal,
// cmd/gomail-ceremony): it keeps the shares shown and gives back the
// share asked for by index, and the next one of queue for any share.
// asked records the indices asked for (the trial reconstruction).
type sharePrompter struct {
	shown map[int][]string
	queue [][]string
	asked []int
}

func (p *sharePrompter) Handover(int, int) error { return nil }

func (p *sharePrompter) AskShare(want int) ([]string, error) {
	if want > 0 {
		p.asked = append(p.asked, want)
		return p.shown[want], nil
	}
	if len(p.queue) == 0 {
		return nil, errors.New("no share left")
	}
	s := p.queue[0]
	p.queue = p.queue[1:]
	return s, nil
}

// Write takes a share line "Anteil <i>/<n>: <words>" of the Display.
func (p *sharePrompter) Write(b []byte) (int, error) {
	var i, n int
	if head, rest, ok := strings.Cut(strings.TrimSuffix(string(b), "\n"), ": "); ok {
		if _, err := fmt.Sscanf(head, "Anteil %d/%d", &i, &n); err == nil {
			p.shown[i] = strings.Fields(rest)
		}
	}
	return len(b), nil
}

// holders returns a prompter that types the shares idx of shown.
func holders(shown map[int][]string, idx ...int) *sharePrompter {
	p := &sharePrompter{shown: map[int][]string{}}
	for _, i := range idx {
		p.queue = append(p.queue, shown[i])
	}
	return p
}

// userMailbox registers a user with gomailctl (common: its arguments),
// which logs the user and the epochs itself (task 14), creates a mailbox
// (repeated until a head cosigned by the witness covers the user entry,
// runLogged) and assigns addr to it with "address add"; it returns the
// mailbox ID. A witness must run.
func (p *platform) userMailbox(common []string, addr string) string {
	t := p.t
	t.Helper()
	p.keygen(common)
	code := strings.TrimSpace(p.run("", "gomail-server", "invite", "create", "--data", p.data))
	p.run("", "gomailctl", append([]string{"register", "--invite", code}, common...)...)
	mbx := strings.TrimSpace(p.runLogged("", "gomailctl", append([]string{"mailbox", "create", "Büro"}, common...)...))
	epochs, _ := filepath.Glob(filepath.Join(p.data, "mailboxes", mbx, "epochs", "*", "epoch.rec"))
	if len(epochs) == 0 {
		t.Fatal("no epochs")
	}
	p.run("", "gomail-server", "address", "add", addr, "--mailbox", mbx, "--data", p.data, "--admin-key", p.admin, "--pin", p.pin)
	return mbx
}

// listUntil runs "gomailctl list mbx" until its output contains every
// one of want, at most for a minute (a head cosigned by the witness must
// cover the address assignment and the epochs, task 14), and returns the
// last output.
func (p *platform) listUntil(mbx string, common []string, want ...string) string {
	p.t.Helper()
	var list string
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(250 * time.Millisecond) {
		list = p.runLogged("", "gomailctl", append([]string{"list", mbx}, common...)...)
		all := true
		for _, w := range want {
			all = all && strings.Contains(list, w)
		}
		if all || time.Now().After(deadline) {
			return list
		}
	}
}

// clientLog opens the log of the data directory as a client with the
// identity list of pin will (task 14): a client log with a Verifier of
// the pinned witnesses, audit index in dir.
func clientLog(t *testing.T, data, dir string, pin *store.PlatformPin) (translog.Log, *translog.Verifier) {
	t.Helper()
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := ceremony.PinIdentities(pin)
	if err != nil {
		t.Fatal(err)
	}
	var wvs []note.Verifier
	for _, w := range pin.Witnesses {
		wv, err := translog.NewWitnessVerifier(w.Name, w.Pub)
		if err != nil {
			t.Fatal(err)
		}
		wvs = append(wvs, wv)
	}
	v := &translog.Verifier{Origin: pin.Origin, Witnesses: wvs, MinWitnesses: pin.MinWitnesses, Identity: ids[len(ids)-1], Identities: ids}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := translog.Open(translog.Options{Store: st, Verifier: v, IndexFile: filepath.Join(dir, "index.json"), Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return l, v
}

// refreshUntil refreshes the client log l until check succeeds (a head
// cosigned by the witness covers what check looks for), at most 60 s.
func refreshUntil(t *testing.T, l translog.Log, logs func() string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, rerr := l.Refresh(time.Now())
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not in the log of a cosigned head: %v (refresh: %v); server log:\n%s", err, rerr, logs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestSuccessionEndToEnd (task 15b): the real ceremony with the built
// programs on a platform of its own (no development ceremony).
//
//  1. init 3-of-5 (package ceremony through the seams of task 10c),
//     "gomail-ceremony publish", gomail-server with pin 1, a mail;
//  2. a regular succession (succeed) of identity 1 to 2: publish refuses
//     while the server runs and with pin 1 (Q10 point 5), goes through
//     with pin 2; the server refuses to start with pin 1
//     (translog.ErrMismatch: platform/ names generation 2) and starts
//     with pin 2; a second mail; a client log with pin 1 accepts the
//     succession from the log (CheckPlatform on identity-2.succ after a
//     head cosigned by the witness);
//  3. succeed --compromised of identity 2 is refused (task 15f point 1,
//     Q19): "gomail-ceremony succeed --compromised" is a usage error
//     (exit code 2) with the fixed text, ceremony.Succeed returns
//     ceremony.ErrCompromised; nothing is written. TODO(Q19): a mark
//     "compromised" with which the predecessor identity is invalid from
//     the log entry of the succession on has no record (ceremony.Succeed);
//     until it has, the compromise case stays locked;
//  4. instead a regular succession of identity 2 to 3 that replaces the
//     witness on purpose (task 15f point 2: publish without
//     --replace-witnesses refuses, with it witnesses.rec becomes the
//     pin's, and the server starts with pin 3 without the warning about
//     witnesses.rec), and a new ingest generation 2 under identity 3,
//     published with pin 3: from valid_from of ingest-2.cert on, once it
//     is logged, the old ingest key signs nothing validly: the server
//     refuses to start with it (ingest.ErrSuperseded), and a client log
//     with pin 3 (heads cosigned by the new witness) ends generation 1 at
//     that valid_from (LogKey.Until) and accepts the new certificate
//     issued by identity 3. This step checks the end of generation 1 on
//     a client log of its own (clientLog); the rule for metadata signed
//     by ingest generation 1 after that time (translog doc.go "Platform
//     generations") in the client log of gomailctl is covered by
//     TestRunbook (RUNBOOK 6).
func TestSuccessionEndToEnd(t *testing.T) {
	bin := programs(t)
	dir := t.TempDir()
	// The pinned witness, quorum 1 of 1.
	skey, vkey, err := note.GenerateKey(rand.Reader, "e2e-witness")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(vkeyData(vkey))
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		t.Fatal("witness key", err)
	}
	wk := witness.Key{Name: "e2e-witness", Pub: ed25519.PublicKey(raw[1:])}
	wkeyFile := filepath.Join(dir, "witness.key")
	if err := store.CreatePrivateFileAtomic(wkeyFile, []byte(skey+"\n")); err != nil {
		t.Fatal(err)
	}
	const origin = "e2e.go-mail.test/log"
	keysDir := filepath.Join(dir, "keys")

	// 1. init, publish, server, mail.
	out1 := filepath.Join(dir, "out1")
	sp := &sharePrompter{shown: map[int][]string{}}
	res1, err := ceremony.Init(ceremony.InitOptions{Out: out1, KeyDir: keysDir, Shares: ceremony.Shares{Threshold: 3, Count: 5},
		Origin: origin, Witnesses: []witness.Key{wk}, MinWitnesses: 1, Display: sp, Prompter: sp})
	if err != nil {
		t.Fatal(err)
	}
	shares := sp.shown
	data := filepath.Join(dir, "data")
	if _, err := store.Init(data); err != nil {
		t.Fatal(err)
	}
	pin1 := filepath.Join(out1, "identity-1.pin")
	p := &platform{t: t, bin: bin, dir: dir, data: data, keys: keysDir, pin: pin1, ingestKey: filepath.Join(keysDir, "ingest-1.key"),
		admin: filepath.Join(keysDir, "admin-1.key"), witnessKey: wkeyFile, origin: origin}
	if out := p.run("", "gomail-ceremony", "publish", "--from", out1, "--data", data, "--pin", pin1); !strings.Contains(out, "Server jetzt mit diesem Pin starten") {
		t.Fatalf("publish: %q", out)
	}
	srv := p.startServer()
	// gomailctl works only with heads cosigned by the witness (task 14):
	// the witness runs from the start.
	stopWitness := p.startWitnessGen(srv, 1)
	common := []string{"--data", data, "--dir", filepath.Join(dir, "alice"), "--pin", pin1}
	mbx := p.userMailbox(common, "info@brownbear.example")
	mail := func(s *serverProc, subject string) error {
		return smtp.SendMail(s.smtp, nil, "a@lieferant.example", []string{"info@brownbear.example"},
			[]byte("From: a@lieferant.example\r\nTo: info@brownbear.example\r\nSubject: "+subject+"\r\n\r\nx\r\n"))
	}
	if err := mail(srv, "vor der Nachfolge"); err != nil {
		t.Fatal(err)
	}

	// 2. Regular succession of identity 1 to 2.
	out2 := filepath.Join(dir, "out2")
	if _, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 1, IdentityPub: res1.IdentityPub,
		Prompter: holders(shares, 5, 1, 3)}, Out: out2, Pin: res1.Pin}); err != nil {
		t.Fatal(err)
	}
	pin2 := filepath.Join(out2, "identity-2.pin")
	if code, _, e := p.exec("", "gomail-ceremony", "publish", "--from", out2, "--data", data, "--pin", pin2); code != 1 || !strings.Contains(e, "Server läuft") {
		t.Fatalf("publish beside the server: %d %s", code, e)
	}
	stopWitness()
	srv.stop()
	if code, _, e := p.exec("", "gomail-ceremony", "publish", "--from", out2, "--data", data, "--pin", pin1); code != 1 || !strings.Contains(e, "install the new pin") {
		t.Fatalf("publish of the succession with pin 1: %d %s", code, e)
	}
	p.run("", "gomail-ceremony", "publish", "--from", out2, "--data", data, "--pin", pin2)
	if code, _, e := p.exec("", "gomail-server", p.serveArgs()...); code != 1 || !strings.Contains(e, "kennt nur 1 bis 1") {
		t.Fatalf("server with pin 1 after the succession: %d %s", code, e)
	}
	p.pin = pin2
	srv = p.startServer()
	stopWitness = p.startWitnessGen(srv, 1)
	if err := mail(srv, "nach der Nachfolge"); err != nil {
		t.Fatal(err)
	}
	if list := p.listUntil(mbx, common, "vor der Nachfolge", "nach der Nachfolge"); !strings.Contains(list, "vor der Nachfolge") || !strings.Contains(list, "nach der Nachfolge") {
		t.Fatalf("list: %q", list)
	}
	succData, err := os.ReadFile(filepath.Join(data, "platform", "identity-2.succ"))
	if err != nil {
		t.Fatal(err)
	}
	cl1, _ := clientLog(t, data, filepath.Join(dir, "client1"), res1.Pin)
	refreshUntil(t, cl1, srv.Logs, func() error { return cl1.CheckPlatform("identity-2.succ", succData) })
	stopWitness()
	srv.stop()

	// 3. A compromise of identity 2 is refused (Q19), by the program and
	// by the library; nothing is written.
	pin2p, err := ceremony.ReadPin(pin2)
	if err != nil {
		t.Fatal(err)
	}
	out3c := filepath.Join(dir, "out3c")
	if code, _, e := p.exec("", "gomail-ceremony", "succeed", "--pin", pin2, "--out", out3c, "--compromised"); code != 2 ||
		!strings.Contains(e, "noch nicht verfügbar: Widerruf einer Plattformgeneration ist nicht festgelegt (Q19)") {
		t.Fatalf("succeed --compromised: %d %s", code, e)
	}
	if _, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 2, IdentityPub: pin2p.Pub,
		Prompter: holders(shares, 2, 4, 1)}, Out: out3c, Pin: pin2p, Compromised: true}); !errors.Is(err, ceremony.ErrCompromised) {
		t.Fatalf("ceremony.Succeed with Compromised: %v", err)
	}
	if _, err := os.Stat(out3c); err == nil {
		t.Fatal("export of a compromise written")
	}

	// 4. A regular succession of identity 2 to 3 that replaces the
	// witness, a new ingest generation under identity 3, valid from
	// shortly after now.
	skey2, vkey2, err := note.GenerateKey(rand.Reader, "e2e-witness-2")
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := base64.StdEncoding.DecodeString(vkeyData(vkey2))
	if err != nil || len(raw2) != 1+ed25519.PublicKeySize {
		t.Fatal("witness key 2", err)
	}
	wk2 := witness.Key{Name: "e2e-witness-2", Pub: ed25519.PublicKey(raw2[1:])}
	wkeyFile2 := filepath.Join(dir, "witness-2.key")
	if err := store.CreatePrivateFileAtomic(wkeyFile2, []byte(skey2+"\n")); err != nil {
		t.Fatal(err)
	}
	out3 := filepath.Join(dir, "out3")
	res3, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 2, IdentityPub: pin2p.Pub,
		Prompter: holders(shares, 2, 4, 1)}, Out: out3, Pin: pin2p, Witnesses: []witness.Key{wk2}, MinWitnesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	pin3 := filepath.Join(out3, "identity-3.pin")
	validFrom := time.Now().Add(3 * time.Second).Truncate(time.Second)
	rot := filepath.Join(dir, "rot")
	if _, err := ceremony.IngestRotate(ceremony.RotateOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 3, IdentityPub: res3.IdentityPub,
		Prompter: holders(shares, 3, 5, 2)}, Out: rot, KeyDir: keysDir, Gen: 2, ValidFrom: validFrom}); err != nil {
		t.Fatal(err)
	}
	wrecPath := filepath.Join(data, "platform", "witnesses.rec")
	wrecBefore, err := os.ReadFile(wrecPath)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, e := p.exec("", "gomail-ceremony", "publish", "--from", out3, "--data", data, "--pin", pin3); code != 1 ||
		!strings.Contains(e, "witnesses.rec differs") || !strings.Contains(e, "--replace-witnesses") {
		t.Fatalf("publish with another witness: %d %s", code, e)
	}
	if now, _ := os.ReadFile(wrecPath); string(now) != string(wrecBefore) {
		t.Fatal("witnesses.rec replaced without --replace-witnesses")
	}
	if _, err := os.Stat(filepath.Join(data, "platform", "identity-3.succ")); err == nil {
		t.Fatal("succession copied by a refused publish")
	}
	if out := p.run("", "gomail-ceremony", "publish", "--from", out3, "--data", data, "--pin", pin3, "--replace-witnesses"); !strings.Contains(out,
		"bisher Quorum 1 von 1 (e2e-witness), jetzt Quorum 1 von 1 (e2e-witness-2)") {
		t.Fatalf("publish --replace-witnesses: %q", out)
	}
	p.run("", "gomail-ceremony", "publish", "--from", rot, "--data", data, "--pin", pin3)
	time.Sleep(time.Until(validFrom) + 200*time.Millisecond)
	p.pin = pin3
	if code, _, e := p.exec("", "gomail-server", p.serveArgs()...); code != 1 || !strings.Contains(e, "superseded") {
		t.Fatalf("server with ingest key 1 after valid_from of ingest-2.cert: %d %s", code, e)
	}
	p.ingestKey = filepath.Join(keysDir, "ingest-2.key")
	srv = p.startServer()
	// witnesses.rec is the pin's: no warning at the start.
	if logs := srv.Logs(); strings.Contains(logs, "witnesses.rec differs") {
		t.Fatalf("server warns about witnesses.rec after --replace-witnesses:\n%s", logs)
	}
	// The new witness, with a state of its own.
	p.witnessKey, p.dir = wkeyFile2, filepath.Join(dir, "witness-2")
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p.startWitnessGen(srv, 2)
	if err := mail(srv, "nach der Kompromittierung"); err != nil {
		t.Fatal(err)
	}
	cert2, err := os.ReadFile(filepath.Join(data, "platform", "ingest-2.cert"))
	if err != nil {
		t.Fatal(err)
	}
	cl3, v3 := clientLog(t, data, filepath.Join(dir, "client3"), res3.Pin)
	refreshUntil(t, cl3, srv.Logs, func() error { return cl3.CheckPlatform("ingest-2.cert", cert2) })
	var until int64 = -1
	for _, k := range v3.LogKeys {
		if k.Gen == 1 && k.Logged {
			until = k.Until
		}
	}
	if until != validFrom.UnixMilli() {
		t.Fatalf("ingest generation 1 ends at %d, want %d (valid_from of ingest-2.cert)", until, validFrom.UnixMilli())
	}
	srv.stop()
}

// vkeyData returns the key part of a note verifier key
// <name>+<hash>+<base64>.
func vkeyData(vkey string) string {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}
