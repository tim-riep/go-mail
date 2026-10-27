package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

func TestCheckListen(t *testing.T) {
	for _, a := range []string{"127.0.0.1:2525", "[::1]:25", "localhost:2525"} {
		if checkListen(a, false) != nil {
			t.Fatalf("%s refused", a)
		}
	}
	for _, a := range []string{":2525", "0.0.0.0:2525", "192.0.2.1:25", "nohost"} {
		if checkListen(a, false) == nil {
			t.Fatalf("%s accepted without --isolated-test-network", a)
		}
	}
	if checkListen("192.0.2.1:25", true) != nil {
		t.Fatal("isolated test network")
	}
}

func TestCommands(t *testing.T) {
	s := newLogSetup(t)
	data, keys, dir := s.data, s.keys, s.dir
	var out, errb bytes.Buffer
	ctx := context.Background()
	for _, args := range [][]string{nil, {"x"}, {"serve"}, {"invite"}, {"invite", "create"}, {"address", "add", "a@b"}, {"serve", "--data", data, "--ingest-key", "k", "extra"}} {
		if run(ctx, args, &out, &errb, nil) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	ingestKey := filepath.Join(keys, ceremony.IngestKeyFile)
	adminKey := filepath.Join(keys, ceremony.AdminKeyFile)
	logArgs := []string{"--pin", s.pin, "--log-listen", "127.0.0.1:0"}
	serve := func(args ...string) []string { return append(append([]string{"serve"}, args...), logArgs...) }
	// serve refuses without the log (usage), with --insecure-no-log
	// (no such switch, task 15), on a public address, with the admin key
	// as ingest key, and with a key inside the data dir.
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", ingestKey}, &out, &errb, nil) != 2 {
		t.Fatal("serve without --pin")
	}
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", ingestKey, "--insecure-no-log"}, &out, &errb, nil) != 2 {
		t.Fatal("serve with --insecure-no-log")
	}
	if run(ctx, serve("--data", data, "--ingest-key", ingestKey, "--listen", "0.0.0.0:0"), &out, &errb, nil) != 1 {
		t.Fatal("serve on all interfaces")
	}
	if run(ctx, serve("--data", data, "--ingest-key", adminKey, "--listen", "127.0.0.1:0"), &out, &errb, nil) != 1 {
		t.Fatal("admin key as ingest key")
	}
	inside := filepath.Join(data, "ingest.key")
	store.WriteFileAtomic(inside, []byte("x"))
	if run(ctx, serve("--data", data, "--ingest-key", inside, "--listen", "127.0.0.1:0"), &out, &errb, nil) != 1 {
		t.Fatal("key in the data directory")
	}
	if run(ctx, serve("--data", filepath.Join(dir, "none"), "--ingest-key", ingestKey, "--listen", "127.0.0.1:0"), &out, &errb, nil) != 1 {
		t.Fatal("missing data directory")
	}
	// serve starts and stops with the context.
	ctx2, cancel := context.WithCancel(ctx)
	done := make(chan int)
	go func() {
		done <- run(ctx2, serve("--data", data, "--listen", "127.0.0.1:0", "--ingest-key", ingestKey), &out, &errb, func(string, string) { cancel() })
	}()
	if code := <-done; code != 0 {
		t.Fatalf("serve: %d %s", code, errb.String())
	}
	// invite create prints a code.
	out.Reset()
	if run(ctx, []string{"invite", "create", "--data", data}, &out, &errb, nil) != 0 {
		t.Fatal(errb.String())
	}
	if _, err := store.ParseID(strings.TrimSpace(out.String())); err != nil {
		t.Fatal("invite code")
	}
	if run(ctx, []string{"invite", "create", "--data", filepath.Join(dir, "none")}, &out, &errb, nil) != 1 {
		t.Fatal("invite without data directory")
	}
	// address add needs --pin, an existing mailbox, a valid address and
	// the admin key.
	base := []string{"address", "add", "info@example.org", "--data", data, "--admin-key", adminKey}
	if run(ctx, base, &out, &errb, nil) != 2 {
		t.Fatal("address without mailbox flag")
	}
	withMbx := append(append([]string(nil), base...), "--mailbox", (store.ID{1}).String())
	if run(ctx, withMbx, &out, &errb, nil) != 2 {
		t.Fatal("address without --pin")
	}
	if run(ctx, append(withMbx, "--insecure-no-log"), &out, &errb, nil) != 2 {
		t.Fatal("address with --insecure-no-log")
	}
	if run(ctx, append(withMbx, "--pin", s.pin), &out, &errb, nil) != 1 {
		t.Fatal("address for a missing mailbox")
	}
	bad := []string{"address", "add", "x", "--data", data, "--admin-key", adminKey, "--mailbox", "bad", "--pin", s.pin}
	if run(ctx, bad, &out, &errb, nil) != 1 {
		t.Fatal("bad mailbox id")
	}
}

// serveArgs are the arguments of a server on s.
func (s *logSetup) serveArgs() []string {
	return []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", filepath.Join(s.keys, ceremony.IngestKeyFile),
		"--pin", s.pin, "--log-listen", "127.0.0.1:0"}
}

// start runs a server on s until the test ends and returns once it
// listens.
func (s *logSetup) start(t *testing.T) *bytes.Buffer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan int, 1)
	var out, errb bytes.Buffer
	go func() {
		done <- run(ctx, s.serveArgs(), &out, &errb, func(string, string) { close(ready) })
	}()
	select {
	case <-ready:
	case code := <-done:
		t.Fatalf("serve ended: %d %s", code, errb.String())
	}
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &errb
}

// startFails runs a server on s and requires exit status 1 with want in
// its output.
func (s *logSetup) startFails(t *testing.T, name, want string) {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(context.Background(), s.serveArgs(), &out, &errb, func(string, string) { t.Fatalf("%s: server started", name) }); code != 1 ||
		!strings.Contains(errb.String(), want) {
		t.Fatalf("%s: %d %s", name, code, errb.String())
	}
}

// TestSecondServer: the server holds locks/server exclusively (9.1, D70);
// a second server on the same data directory does not start, and the
// first one's start test of the locks passed.
func TestSecondServer(t *testing.T) {
	s := newLogSetup(t)
	logs := s.start(t)
	s.startFails(t, "second server", "Serversperre")
	if err := s.st.CheckPeerLock(store.RoleServer); err != nil {
		t.Fatalf("server lock not in force: %v", err)
	}
	_ = logs
}

// TestStartPlatformPin: the operating rule after a succession (Q10 point
// 5): platform/ names an identity generation the pin does not know, or
// contradicts its identity list; the server does not start
// (translog.ErrMismatch).
func TestStartPlatformPin(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, ipriv, _ := ed25519.GenerateKey(nil)
	cert, err := keys.NewPlatformCert(ipriv, 2, keys.RoleAdmin, 2, pub, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	certData, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	succ, err := keys.NewPlatformSuccession(ipriv, 2, pub, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	succData, err := succ.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		file     string
		data     []byte
		mismatch bool
		want     string
	}{
		"newer identity":            {"identity-2.pub", pub, true, "kennt nur 1 bis 1"},
		"identity 1 replaced":       {"identity-1.pub", pub, true, "widerspricht der Identitätsliste"},
		"succession to identity 2":  {"identity-2.succ", succData, true, "kennt nur 1 bis 1"},
		"undecodable succession":    {"identity-1.succ", []byte("x"), false, "platform/identity-1.succ"},
		"certificate of identity 2": {"admin-2.cert", certData, true, "kennt nur 1 bis 1"},
	} {
		s := newLogSetup(t)
		if err := store.WriteFileAtomic(s.st.Path("platform", tc.file), tc.data); err != nil {
			t.Fatal(err)
		}
		if err := checkPlatformPin(s.st, s.p); err == nil || errors.Is(err, translog.ErrMismatch) != tc.mismatch {
			t.Fatalf("%s: %v", name, err)
		}
		s.startFails(t, name, tc.want)
	}
}

// TestStartDataDirRights: the rights of 9.1 are checked at the start; a
// data directory open to others is refused, one without setgid is a
// warning.
func TestStartDataDirRights(t *testing.T) {
	s := newLogSetup(t)
	if err := os.Chmod(s.data, 0o2777); err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "open to others", "für andere zugänglich")
	if err := os.Chmod(s.data, 0o2770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.st.Path("users"), 0o775); err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "entry open to others", "users im Datenverzeichnis")
	if err := os.Chmod(s.st.Path("users"), 0o770); err != nil {
		t.Fatal(err)
	}
	// A data directory reached through a link: the rights of its target
	// count.
	link := filepath.Join(s.dir, "data-link")
	if err := os.Symlink(s.data, link); err != nil {
		t.Fatal(err)
	}
	args := s.serveArgs()
	args[2] = link
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb bytes.Buffer
	if code := run(ctx, args, &out, &errb, func(string, string) { cancel() }); code != 0 {
		t.Fatalf("linked data directory: %d %s", code, errb.String())
	}
	logs := s.start(t)
	if !strings.Contains(logs.String(), "without setgid") {
		t.Fatalf("no warning for a directory without setgid: %s", logs.String())
	}
}

// TestStartRolledBackTree: a tree.rec rolled back below existing entries
// stops the start (translog.ErrConsistency). Since task 15c (finding 2)
// the operator log refuses it in every check, so ingest.New already
// fails on its own certificate (CheckPlatform), before the start check
// of the head (SignHead) would.
func TestStartRolledBackTree(t *testing.T) {
	s := newLogSetup(t)
	tree := filepath.Join(s.data, "log", "tree.rec")
	saved, err := os.ReadFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"a@example.org", "b@example.org"} {
		var out, errb bytes.Buffer
		if code := run(context.Background(), s.addArgs(a, s.mbx), &out, &errb, nil); code != 0 {
			t.Fatalf("address add: %d %s", code, errb.String())
		}
	}
	if err := store.WriteFileAtomic(tree, saved); err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "rolled back tree.rec", "tree.rec rolled back")
}

// TestStartPinWithoutQuorum: a pin whose witness quorum violates 2*min > n
// (translog doc.go "Witness quorum") does not decode; the server does
// not start.
func TestStartPinWithoutQuorum(t *testing.T) {
	s := newLogSetup(t)
	w2, _, _ := ed25519.GenerateKey(nil)
	bad, err := pinWithQuorum(s.p, w2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pin, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "quorum 1 of 2", "Pin")
}

// pinWithQuorum encodes p with a second witness and min witnesses,
// without the checks of PlatformPin.Encode.
func pinWithQuorum(p *store.PlatformPin, second ed25519.PublicKey, min uint32) ([]byte, error) {
	ws := []*rec.Record{}
	for _, w := range p.Witnesses {
		ws = append(ws, rec.New(store.WitnessSchema).SetString(1, w.Name).SetBytes(2, w.Pub))
	}
	ws = append(ws, rec.New(store.WitnessSchema).SetString(1, "second-witness").SetBytes(2, second))
	ids := []*rec.Record{}
	for _, id := range p.Identities {
		ids = append(ids, rec.New(store.PlatformIdentitySchema).SetU32(1, id.Gen).SetBytes(2, id.Pub))
	}
	return rec.New(store.PlatformPinSchema).SetU32(1, p.Gen).SetBytes(2, p.Pub).SetU8(3, 1).SetString(4, p.Origin).
		SetList(5, ws).SetU32(6, min).SetList(8, ids).Encode()
}

// TestStartIngestNotLogged: an ingest certificate that is not in the log
// signs nothing a client accepts; the server does not start.
func TestStartIngestNotLogged(t *testing.T) {
	s := newLogSetup(t)
	if err := os.RemoveAll(filepath.Join(s.data, "log")); err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "certificate not logged", "ingest-1.cert is not in the log")
}

var _ = time.Second
