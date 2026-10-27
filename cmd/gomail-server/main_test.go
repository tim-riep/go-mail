package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
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
	dir := t.TempDir()
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	log, _ := translogtest.NewUnverified(true)
	if _, err := ceremony.InitDev(data, keys, time.Now(), log, nil, 0); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	ctx := context.Background()
	for _, args := range [][]string{nil, {"x"}, {"serve"}, {"invite"}, {"invite", "create"}, {"address", "add", "a@b"}, {"serve", "--data", data, "--ingest-key", "k", "extra"}} {
		if run(ctx, args, &out, &errb, nil) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	ingestKey := filepath.Join(keys, ceremony.IngestKeyFile)
	adminKey := filepath.Join(keys, ceremony.AdminKeyFile)
	// serve refuses without --insecure-no-log, on a public address, with
	// the admin key as ingest key, and with a key inside the data dir.
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", ingestKey}, &out, &errb, nil) != 1 {
		t.Fatal("serve without --insecure-no-log")
	}
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", ingestKey, "--insecure-no-log", "--listen", "0.0.0.0:0"}, &out, &errb, nil) != 1 {
		t.Fatal("serve on all interfaces")
	}
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", adminKey, "--insecure-no-log"}, &out, &errb, nil) != 1 {
		t.Fatal("admin key as ingest key")
	}
	inside := filepath.Join(data, "ingest.key")
	store.WriteFileAtomic(inside, []byte("x"))
	if run(ctx, []string{"serve", "--data", data, "--ingest-key", inside, "--insecure-no-log"}, &out, &errb, nil) != 1 {
		t.Fatal("key in the data directory")
	}
	if run(ctx, []string{"serve", "--data", filepath.Join(dir, "none"), "--ingest-key", ingestKey, "--insecure-no-log"}, &out, &errb, nil) != 1 {
		t.Fatal("missing data directory")
	}
	// serve starts and stops with the context.
	ctx2, cancel := context.WithCancel(ctx)
	done := make(chan int)
	go func() {
		done <- run(ctx2, []string{"serve", "--data", data, "--listen", "127.0.0.1:0", "--ingest-key", ingestKey, "--insecure-no-log"}, &out, &errb, func(string, string) { cancel() })
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
	// address add needs an existing mailbox, a valid address and the
	// admin key.
	base := []string{"address", "add", "info@example.org", "--data", data, "--admin-key", adminKey}
	if run(ctx, base, &out, &errb, nil) != 2 {
		t.Fatal("address without mailbox flag")
	}
	withMbx := append(append([]string(nil), base...), "--mailbox", (store.ID{1}).String())
	if run(ctx, withMbx, &out, &errb, nil) != 1 {
		t.Fatal("address without --insecure-no-log")
	}
	if run(ctx, append(withMbx, "--insecure-no-log"), &out, &errb, nil) != 1 {
		t.Fatal("address for a missing mailbox")
	}
	bad := []string{"address", "add", "x", "--data", data, "--admin-key", adminKey, "--mailbox", "bad", "--insecure-no-log"}
	if run(ctx, bad, &out, &errb, nil) != 1 {
		t.Fatal("bad mailbox id")
	}
}
