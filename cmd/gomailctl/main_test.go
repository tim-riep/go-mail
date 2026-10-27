package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
)

func TestUsageAndConfig(t *testing.T) {
	dir := t.TempDir()
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	if _, err := ceremony.InitDev(data, keys, time.Now(), nil, 0); errors.Is(err, ceremony.ErrDev) {
		t.Skip("needs the development ceremony (ceremony.InitDev): go test -tags gomail_dev,gomail_test")
	}
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"bogus"}, {"list"}, {"read", "x"}, {"mailbox", "delete", "x"}, {"register"}, {"keygen", "--nope"}} {
		if run(args, strings.NewReader(""), &out, &errb) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	common := []string{"--data", data, "--dir", filepath.Join(dir, "c"), "--platform", filepath.Join(keys, ceremony.PinFile)}
	// Without --insecure-no-log nothing starts (TODO(task-14): the client
	// log replaces it).
	if run(append([]string{"sync"}, common...), strings.NewReader(""), &out, &errb) != 1 || !strings.Contains(errb.String(), "insecure-no-log") {
		t.Fatal("client without --insecure-no-log")
	}
	common = append(common, "--insecure-no-log")
	// The commands below work beside a running server: its lock on
	// locks/server, held in this process (9.1).
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if run([]string{"sync", "--data", data}, strings.NewReader(""), &out, &errb) != 1 {
		t.Fatal("missing --platform")
	}
	// keygen on stand-in terminals asks the passphrase twice; a mismatch
	// stops it before anything is shown.
	t.Setenv("GOMAILCTL_PASSPHRASE", "")
	keygen := func(answers map[string]string) (int, string, *keyboard) {
		screen := &tty{}
		kb := &keyboard{err: &syncBuf{}, answer: lineSet(answers)}
		code := run(append([]string{"keygen"}, common...), kb, screen, kb.err)
		return code, screen.String(), kb
	}
	for _, c := range []struct {
		answers map[string]string
		want    string
	}{
		{map[string]string{"Passphrase: ": "a", "wiederholen: ": "b"}, "stimmen nicht überein"},
		{nil, "keine Passphrase"},
		{map[string]string{"Passphrase: ": "", "wiederholen: ": ""}, "leere Passphrase"},
		{map[string]string{"Passphrase: ": strings.Repeat("p", 5000)}, "Zeile zu lang"},
	} {
		if code, screen, kb := keygen(c.answers); code != 1 || screen != "" || !strings.Contains(kb.err.String(), c.want) {
			t.Fatalf("keygen with %v: exit %d, screen %q, %s", c.answers, code, screen, kb.err.String())
		}
	}
	// Wrong words: nothing is created, the screen is cleared.
	screen := &tty{}
	kb := &keyboard{err: &syncBuf{}}
	kb.answer = func(prompt string) (string, bool) {
		if wordPromptRe.MatchString(prompt) {
			return "zoo", true
		}
		return lineSet(map[string]string{"Passphrase: ": "pw", "wiederholen: ": "pw", "Bildschirm: ": ""})(prompt)
	}
	code := run(append([]string{"keygen"}, common...), kb, screen, kb.err)
	if code != 1 || !strings.HasSuffix(screen.String(), clearScreen) || !strings.Contains(kb.err.String(), "not confirmed") {
		t.Fatalf("wrong words: exit %d, %q", code, kb.err.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "c", "keystore")); !os.IsNotExist(err) {
		t.Fatal("key store after wrong words")
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

// TestPeerLock: the client works only while the lock of a running server
// is in force (9.1, "Testsperre"), and it holds the shared client lock
// only while it runs.
func TestPeerLock(t *testing.T) {
	dir := t.TempDir()
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	if _, err := ceremony.InitDev(data, keys, time.Now(), nil, 0); errors.Is(err, ceremony.ErrDev) {
		t.Skip("needs the development ceremony (ceremony.InitDev): go test -tags gomail_dev,gomail_test")
	} else if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMAILCTL_PASSPHRASE", "pw")
	args := []string{"sync", "--data", data, "--dir", filepath.Join(dir, "c"), "--platform", filepath.Join(keys, ceremony.PinFile), "--insecure-no-log"}
	var out, errb bytes.Buffer
	// No server: refused before the client touches anything.
	if run(args, strings.NewReader(""), &out, &errb) != 1 || !strings.Contains(errb.String(), "Testsperre") {
		t.Fatalf("without a server: %s", errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "c")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("client directory created without the server lock")
	}
	// The server lock file exists but nobody holds it (a stopped server).
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	release()
	errb.Reset()
	if run(args, strings.NewReader(""), &out, &errb) != 1 || !strings.Contains(errb.String(), "Testsperre") {
		t.Fatalf("stopped server: %s", errb.String())
	}
	// With the server lock held the check passes (sync then fails for
	// the missing user, not for the lock), and the client lock is free
	// again after the command.
	release, err = st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	errb.Reset()
	if run(args, strings.NewReader(""), &out, &errb) != 1 || strings.Contains(errb.String(), "Testsperre") {
		t.Fatalf("beside a server: %s", errb.String())
	}
	if err := st.CheckPeerLock(store.RoleClient); !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("client lock after the command: %v", err)
	}
}
