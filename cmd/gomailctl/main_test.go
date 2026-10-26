package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/translog"
)

func TestUsageAndConfig(t *testing.T) {
	dir := t.TempDir()
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	log, _ := translog.NewUnverified(true)
	ceremony.InitDev(data, keys, time.Now(), log)
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"bogus"}, {"list"}, {"read", "x"}, {"mailbox", "delete", "x"}, {"register"}, {"keygen", "--nope"}} {
		if run(args, strings.NewReader(""), &out, &errb) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	common := []string{"--data", data, "--dir", filepath.Join(dir, "c"), "--platform", filepath.Join(keys, ceremony.PinFile)}
	// Without --insecure-no-log nothing starts.
	if run(append([]string{"sync"}, common...), strings.NewReader(""), &out, &errb) != 1 || !strings.Contains(errb.String(), "insecure-no-log") {
		t.Fatal("client without --insecure-no-log")
	}
	common = append(common, "--insecure-no-log")
	if run([]string{"sync", "--data", data}, strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("missing --platform")
	}
	// keygen asks the passphrase twice; a mismatch stops it.
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	if run(append([]string{"keygen"}, common...), strings.NewReader("a\nb\n"), &out, &errb) != 1 {
		t.Fatal("passphrase mismatch")
	}
	if run(append([]string{"keygen"}, common...), strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("no passphrase")
	}
	// Wrong words: nothing is created.
	errb.Reset()
	if run(append([]string{"keygen"}, common...), strings.NewReader("pw\npw\nx\nx\nx\n"), &out, &errb) != 1 {
		t.Fatal("wrong words")
	}
	// Commands that need a registered user.
	if run(append([]string{"sync"}, common...), strings.NewReader("pw\n"), &out, &errb) != 1 {
		t.Fatal("sync without user")
	}
	if run(append([]string{"register", "--invite", "bad"}, common...), strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("bad invitation code")
	}
	if run([]string{"inspect", filepath.Join(dir, "none")}, strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("inspect of a missing file")
	}
	out.Reset()
	if run([]string{"inspect", filepath.Join(data, "platform", "ingest-1.cert")}, strings.NewReader(""), &out, &errb) != 0 || !strings.Contains(out.String(), "platform-cert") {
		t.Fatal("inspect")
	}
	// A passphrase file.
	pf := filepath.Join(dir, "pass")
	writeFile(t, pf, "pw\n")
	if run(append([]string{"sync", "--passphrase-file", pf}, common...), strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("sync without user via passphrase file")
	}
}
