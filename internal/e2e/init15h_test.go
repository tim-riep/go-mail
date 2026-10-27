package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// prodTags are the tags of the programs of TestInitProduction: only
// gomail_test (the free space switch of gomail-server), without
// gomail_dev, so the programs are those of a production build as far as
// the development ceremony goes (task 15h).
const prodTags = "gomail_test"

var (
	prodOnce sync.Once
	prodDir  string
	prodErr  error
)

// prodPrograms builds the programs once with prodTags and returns their
// directory (removed by TestMain).
func prodPrograms(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the programs")
	}
	prodOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gomail-e2e-prod-")
		if err != nil {
			prodErr = err
			return
		}
		prodDir = dir
		build := exec.Command("go", "build", "-tags", prodTags, "-o", dir+string(os.PathSeparator), "github.com/tim-riep/go-mail/cmd/...")
		build.Env = os.Environ()
		if out, err := build.CombinedOutput(); err != nil {
			prodErr = errors.New(err.Error() + "\n" + string(out))
		}
	})
	if prodErr != nil {
		t.Fatalf("build: %v", prodErr)
	}
	return prodDir
}

// TestInitProduction (task 15h, SPEC-ISSUES S80): the first installation
// with the programs of a production build (tag gomail_test only, no
// gomail_dev), in the order of RUNBOOK "Erstinstallation":
//
//  1. the build has no development ceremony (init --dev: usage error);
//  2. witness key (gomail-witness keygen), the real ceremony 3-of-5
//     through the seams of task 10c (package ceremony);
//  3. "gomail-server init" refuses a development pin and creates the
//     empty data directory from the pin and the export's witnesses.rec
//     (rights 2770/0660, nothing but platform/witnesses.rec);
//  4. "gomail-ceremony publish"; serve, address add and log repair
//     refuse the development pin (exit status 2, task 15k); the server
//     with the pin, the witness;
//  5. a user, a mailbox, an address, a mail over SMTP, list, and a head
//     cosigned by the witness.
func TestInitProduction(t *testing.T) {
	bin := prodPrograms(t)
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	p := &platform{t: t, bin: bin, dir: dir, data: filepath.Join(dir, "data"), keys: keysDir,
		ingestKey: filepath.Join(keysDir, "ingest-1.key"), admin: filepath.Join(keysDir, "admin-1.key")}

	// 1. No development ceremony in this build.
	if code, _, _ := p.exec("", "gomail-ceremony", "init", "--dev", "--data", filepath.Join(dir, "dev-data"), "--keys", filepath.Join(dir, "dev-keys")); code != 2 {
		t.Fatalf("init --dev in a production build: exit %d", code)
	}

	// 2. Witness key and the real ceremony.
	p.witnessKey, p.origin = filepath.Join(dir, "witness.key"), "e2e-init.go-mail.test/log"
	vkey := strings.TrimSpace(p.run("", "gomail-witness", "keygen", "--name", "e2e-witness", "--key", p.witnessKey))
	raw, err := base64.StdEncoding.DecodeString(vkeyData(vkey))
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		t.Fatalf("witness key %q: %v", vkey, err)
	}
	out := filepath.Join(dir, "out")
	sp := &sharePrompter{shown: map[int][]string{}}
	res, err := ceremony.Init(ceremony.InitOptions{Out: out, KeyDir: keysDir, Shares: ceremony.Shares{Threshold: 3, Count: 5},
		Origin: p.origin, Witnesses: []witness.Key{{Name: "e2e-witness", Pub: ed25519.PublicKey(raw[1:])}}, MinWitnesses: 1,
		Display: sp, Prompter: sp})
	if err != nil {
		t.Fatal(err)
	}
	p.pin = filepath.Join(out, "identity-1.pin")

	// 3. gomail-server init: a development pin is refused, the pin of the
	// ceremony creates the data directory.
	devPin := *res.Pin
	devPin.Dev = true
	db, err := devPin.Encode()
	if err != nil {
		t.Fatal(err)
	}
	devFile := filepath.Join(dir, "dev.pin")
	if err := os.WriteFile(devFile, db, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := p.exec("", "gomail-server", "init", "--data", p.data, "--pin", devFile); code != 2 || !strings.Contains(e, "Entwicklungs-Pin") {
		t.Fatalf("init with a development pin: exit %d %s", code, e)
	}
	if _, err := os.Lstat(p.data); err == nil {
		t.Fatal("data directory created with a development pin")
	}
	// Before init, publish finds no data directory.
	if code, _, _ := p.exec("", "gomail-ceremony", "publish", "--from", out, "--data", p.data, "--pin", p.pin); code != 1 {
		t.Fatalf("publish without a data directory: exit %d", code)
	}
	if _, err := os.Lstat(p.data); err == nil {
		t.Fatal("publish created the data directory")
	}
	wrecFile := filepath.Join(out, "platform", ceremony.WitnessesFile)
	if o := p.run("", "gomail-server", "init", "--data", p.data, "--pin", p.pin, "--witnesses", wrecFile); !strings.Contains(o, "gomail-ceremony publish") {
		t.Fatalf("init: %q", o)
	}
	fi, err := os.Stat(p.data)
	if err != nil || fi.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != store.DirPerm {
		t.Fatalf("data directory: %v %v", fi, err)
	}
	plat, err := os.ReadDir(filepath.Join(p.data, "platform"))
	if err != nil || len(plat) != 1 || plat[0].Name() != ceremony.WitnessesFile {
		t.Fatalf("platform/ after init: %v %v", plat, err)
	}
	for _, d := range []string{"log", "locks"} {
		if ents, err := os.ReadDir(filepath.Join(p.data, d)); err != nil || len(ents) != 0 {
			t.Fatalf("%s/ after init: %v %v", d, ents, err)
		}
	}
	want, err := os.ReadFile(wrecFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(p.data, "platform", ceremony.WitnessesFile)); err != nil || string(got) != string(want) {
		t.Fatalf("witnesses.rec: %v", err)
	}
	if code, _, e := p.exec("", "gomail-server", "init", "--data", p.data, "--pin", p.pin); code != 2 || !strings.Contains(e, "nicht leer") {
		t.Fatalf("second init: exit %d %s", code, e)
	}
	// Without the certificates the server does not start.
	if code, _, _ := p.exec("", "gomail-server", p.serveArgs()...); code != 1 {
		t.Fatalf("server before publish: exit %d", code)
	}

	// 4. publish, server, witness.
	if o := p.run("", "gomail-ceremony", "publish", "--from", out, "--data", p.data, "--pin", p.pin); !strings.Contains(o, "Server jetzt mit diesem Pin starten") {
		t.Fatalf("publish: %q", o)
	}
	// The production build refuses the development pin in every server
	// command with exit status 2, before any lock or log (task 15k
	// finding 1).
	mbxID, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	before := dirState(t, p.data)
	for _, args := range [][]string{
		{"serve", "--data", p.data, "--listen", "127.0.0.1:0", "--ingest-key", p.ingestKey, "--pin", devFile, "--log-listen", "127.0.0.1:0"},
		{"address", "add", "info@brownbear.example", "--mailbox", mbxID.String(), "--data", p.data, "--admin-key", p.admin, "--pin", devFile},
		{"log", "repair", "--data", p.data, "--pin", devFile},
	} {
		if code, _, e := p.exec("", "gomail-server", args...); code != 2 || !strings.Contains(e, "Entwicklungs-Pin") || !strings.Contains(e, "Produktionsbuild") {
			t.Fatalf("%s %s with a development pin: exit %d %s", args[0], args[1], code, e)
		}
	}
	if after := dirState(t, p.data); after != before {
		t.Fatalf("data directory changed by the refused commands:\n%s\n---\n%s", before, after)
	}
	srv := p.startServer()
	p.startWitness(srv)

	// 5. User, mailbox, address, mail, list, a cosigned head.
	common := []string{"--data", p.data, "--dir", filepath.Join(dir, "alice"), "--pin", p.pin}
	mbx := p.userMailbox(common, "info@brownbear.example")
	msg := "From: a@lieferant.example\r\nTo: info@brownbear.example\r\nSubject: Erstinstallation\r\n\r\nx\r\n"
	if err := smtp.SendMail(srv.smtp, nil, "a@lieferant.example", []string{"info@brownbear.example"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	if list := p.listUntil(mbx, common, "Erstinstallation"); !strings.Contains(list, "Erstinstallation") {
		t.Fatalf("list: %q", list)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if hs, _ := filepath.Glob(filepath.Join(p.data, "log", "heads", "*.sig")); len(hs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no head published:\n%s", srv.Logs())
		}
		time.Sleep(100 * time.Millisecond)
	}
	srv.stop()
	if logs := srv.Logs(); strings.Contains(logs, "development pin") || !strings.Contains(logs, "status=250") {
		t.Fatalf("server log: %s", logs)
	}
}

// dirState lists every entry below root with its mode, size and
// modification time.
func dirState(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %v %d %d\n", path, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
