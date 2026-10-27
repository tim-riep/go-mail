package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

// logSetup is a development platform whose certificates are in the
// operator log, with witnesses.rec, and a mailbox.
type logSetup struct {
	dir, data, keys, pin string
	st                   *store.Store
	p                    *store.PlatformPin
	mbx                  store.ID
}

func newLogSetup(t *testing.T) *logSetup {
	t.Helper()
	dir := t.TempDir()
	s := &logSetup{dir: dir, data: filepath.Join(dir, "data"), keys: filepath.Join(dir, "keys")}
	// InitDev logs the certificates and writes witnesses.rec (task 15).
	res, err := ceremony.InitDev(s.data, s.keys, time.Now().Add(-time.Hour), nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.p, s.pin = res.Pin, filepath.Join(s.keys, ceremony.PinFile)
	if s.st, err = store.Open(s.data); err != nil {
		t.Fatal(err)
	}
	if s.mbx, err = store.NewID(nil); err != nil {
		t.Fatal(err)
	}
	inbox, _ := store.NewID(nil)
	if err := s.st.WriteMailbox(&store.Mailbox{ID: s.mbx, Epoch: 1, Inbox: inbox}); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *logSetup) operator(t *testing.T) translog.Operator {
	t.Helper()
	l, err := translog.Open(translog.Options{Store: s.st, Identities: []translog.Identity{{Gen: 1, Pub: s.p.Pub}}, Origin: s.p.Origin})
	if err != nil {
		t.Fatal(err)
	}
	return l.(translog.Operator)
}

func (s *logSetup) treeSize(t *testing.T) int64 {
	t.Helper()
	// The newest committed entry: Entry succeeds below the size.
	op := s.operator(t)
	n := int64(0)
	for ; ; n++ {
		if _, err := op.Entry(n); err != nil {
			return n
		}
	}
}

// TestAddressAddLogged: "address add" appends the signed assignment to
// the operator log before addresses.json changes.
func TestAddressAddLogged(t *testing.T) {
	s := newLogSetup(t)
	var out, errb bytes.Buffer
	ctx := context.Background()
	adminKey := filepath.Join(s.keys, ceremony.AdminKeyFile)
	base := []string{"address", "add", "Info@Example.org", "--mailbox", s.mbx.String(), "--data", s.data, "--admin-key", adminKey}
	// --insecure-no-log is no switch any more (task 15), and --pin is
	// required.
	if code := run(ctx, append(append([]string(nil), base...), "--pin", s.pin, "--insecure-no-log"), &out, &errb, nil); code != 2 {
		t.Fatalf("--pin with --insecure-no-log: %d", code)
	}
	if code := run(ctx, append(append([]string(nil), base...), "--insecure-no-log"), &out, &errb, nil); code != 2 {
		t.Fatalf("--insecure-no-log: %d", code)
	}
	if code := run(ctx, base, &out, &errb, nil); code != 2 {
		t.Fatalf("without --pin: %d", code)
	}
	inside := filepath.Join(s.data, "identity-1.pin")
	data, _ := os.ReadFile(s.pin)
	if err := store.WriteFileAtomic(inside, data); err != nil {
		t.Fatal(err)
	}
	if code := run(ctx, append(append([]string(nil), base...), "--pin", inside), &out, &errb, nil); code != 2 {
		t.Fatalf("pin in the data directory: %d", code)
	}
	if code := run(ctx, append(append([]string(nil), base...), "--pin", filepath.Join(s.dir, "none.pin")), &out, &errb, nil); code != 1 {
		t.Fatalf("missing pin: %d", code)
	}
	if code := run(ctx, append(append([]string(nil), base...), "--pin", s.pin), &out, &errb, nil); code != 0 {
		t.Fatalf("address add: %d %s", code, errb.String())
	}
	es, err := s.operator(t).Lookup(translog.KindAddress, []byte("info@example.org"))
	if err != nil || len(es) != 1 {
		t.Fatalf("not logged: %v %d", err, len(es))
	}
	aj, err := os.ReadFile(s.st.AddressesFile())
	if err != nil || !bytes.Contains(aj, []byte(s.mbx.String())) {
		t.Fatal("addresses.json not changed")
	}
	// The log refuses an assignment it cannot accept (no logged admin
	// certificate), and addresses.json stays unchanged.
	s2 := newLogSetup(t)
	if err := os.RemoveAll(filepath.Join(s2.data, "log")); err != nil {
		t.Fatal(err)
	}
	b2 := []string{"address", "add", "x@example.org", "--mailbox", s2.mbx.String(), "--data", s2.data,
		"--admin-key", filepath.Join(s2.keys, ceremony.AdminKeyFile), "--pin", s2.pin}
	if code := run(ctx, b2, &out, &errb, nil); code != 1 {
		t.Fatalf("assignment without a logged admin certificate: %d", code)
	}
	if aj, err := os.ReadFile(s2.st.AddressesFile()); err == nil && bytes.Contains(aj, []byte(s2.mbx.String())) {
		t.Fatal("addresses.json changed although the log refused")
	}
}

// TestServeLog: serve with --pin signs heads, the development witness
// cosigns them over HTTP and heads/<n>.sig appears.
func TestServeLog(t *testing.T) {
	s := newLogSetup(t)
	var out, errb bytes.Buffer
	ctx := context.Background()
	ingestKey := filepath.Join(s.keys, ceremony.IngestKeyFile)
	base := []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", ingestKey}
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no log":              {nil, 2},
		"no-log switch":       {[]string{"--insecure-no-log"}, 2},
		"pin and no-log":      {[]string{"--pin", s.pin, "--log-listen", "127.0.0.1:0", "--insecure-no-log"}, 2},
		"pin without listen":  {[]string{"--pin", s.pin}, 2},
		"listen without pin":  {[]string{"--log-listen", "127.0.0.1:0"}, 2},
		"public log address":  {[]string{"--pin", s.pin, "--log-listen", "0.0.0.0:0"}, 1},
		"long head interval":  {[]string{"--pin", s.pin, "--log-listen", "127.0.0.1:0", "--head-interval", "2h"}, 1},
		"missing pin":         {[]string{"--pin", filepath.Join(s.dir, "none"), "--log-listen", "127.0.0.1:0"}, 1},
		"bad listen with pin": {[]string{"--pin", s.pin, "--log-listen", "nohost"}, 1},
	} {
		if code := run(ctx, append(append([]string(nil), base...), tc.args...), &out, &errb, nil); code != tc.code {
			t.Fatalf("%s: %d %s", name, code, errb.String())
		}
	}
	// Without witnesses.rec the server does not start.
	wrec := s.st.Path("platform", "witnesses.rec")
	saved, _ := os.ReadFile(wrec)
	if err := os.Remove(wrec); err != nil {
		t.Fatal(err)
	}
	if code := run(ctx, append(append([]string(nil), base...), "--pin", s.pin, "--log-listen", "127.0.0.1:0"), &out, &errb, nil); code != 1 {
		t.Fatalf("without witnesses.rec: %d", code)
	}
	if err := store.WriteFileAtomic(wrec, saved); err != nil {
		t.Fatal(err)
	}

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	addrs := make(chan string, 1)
	done := make(chan int, 1)
	var sout, serr lockedBuffer
	go func() {
		done <- run(ctx2, append(append([]string(nil), base...), "--pin", s.pin, "--log-listen", "127.0.0.1:0"), &sout, &serr,
			func(_, log string) { addrs <- log })
	}()
	var logAddr string
	select {
	case logAddr = <-addrs:
	case code := <-done:
		t.Fatalf("serve ended: %d", code)
	}
	ipub, err := os.ReadFile(s.st.Path("platform", "ingest-1.pub"))
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(translog.LogSignerName, ed25519.PublicKey(ipub))
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.New(witness.Config{Log: "http://" + logAddr, LogKeys: []string{vkey}, Origin: s.p.Origin,
		KeyFile: filepath.Join(s.keys, ceremony.WitnessKeyFile), StateDir: filepath.Join(s.dir, "witness-state")})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	head := filepath.Join(s.data, "log", "heads", "2.sig")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := w.Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
		if _, err := os.Stat(head); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no head published")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve: %d %s", code, serr.String())
	}
	logs := serr.String()
	if !strings.Contains(logs, "head published") || !strings.Contains(logs, "development pin") {
		t.Fatalf("log lines: %s", logs)
	}
	if strings.Contains(logs, "info@") {
		t.Fatal("address in the log")
	}
}

// TestWitnessesDiffer: a witnesses.rec that differs from the pin is used
// as the working copy, with a warning.
func TestWitnessesDiffer(t *testing.T) {
	s := newLogSetup(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ws := witness.Witnesses{Min: 1, List: []witness.Key{{Name: "other-witness", Pub: other}}}
	wr, err := ws.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(s.st.Path("platform", "witnesses.rec"), wr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errb bytes.Buffer
	code := run(ctx, []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", filepath.Join(s.keys, ceremony.IngestKeyFile),
		"--pin", s.pin, "--log-listen", "127.0.0.1:0"}, &out, &errb, func(string, string) { cancel() })
	if code != 0 || !strings.Contains(errb.String(), "witnesses.rec differs from the pin") {
		t.Fatalf("%d %s", code, errb.String())
	}
}

// TestLogRepair: "log repair" restores a damaged tree.rec.
func TestLogRepair(t *testing.T) {
	s := newLogSetup(t)
	var out, errb bytes.Buffer
	ctx := context.Background()
	for _, args := range [][]string{{"log"}, {"log", "repair"}, {"log", "fix", "--data", s.data, "--pin", s.pin}, {"log", "repair", "--data", s.data}} {
		if run(ctx, args, &out, &errb, nil) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	tree := filepath.Join(s.data, "log", "tree.rec")
	want, err := os.ReadFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tree); err != nil {
		t.Fatal(err)
	}
	if code := run(ctx, []string{"log", "repair", "--data", s.data, "--pin", s.pin}, &out, &errb, nil); code != 0 {
		t.Fatalf("repair: %d %s", code, errb.String())
	}
	if got, _ := os.ReadFile(tree); !bytes.Equal(got, want) {
		t.Fatal("tree.rec not restored")
	}
	if s.treeSize(t) != 2 {
		t.Fatal("size")
	}
	// Not while a server holds the server lock.
	release, err := s.st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	if code := run(ctx, []string{"log", "repair", "--data", s.data, "--pin", s.pin}, &out, &errb, nil); code != 1 {
		t.Fatalf("repair beside a server: %d", code)
	}
	release()
	for _, args := range [][]string{
		{"log", "repair", "--data", filepath.Join(s.dir, "none"), "--pin", s.pin},
		{"log", "repair", "--data", s.data, "--pin", filepath.Join(s.dir, "none")},
	} {
		if run(ctx, args, &out, &errb, nil) != 1 {
			t.Fatalf("%v", args)
		}
	}
	// A head beyond the entries: refused.
	if err := store.WriteFileAtomic(filepath.Join(s.data, "log", "heads", "9.sig"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if run(ctx, []string{"log", "repair", "--data", s.data, "--pin", s.pin}, &out, &errb, nil) != 1 {
		t.Fatal("head beyond the entries")
	}
}
