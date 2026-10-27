package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 11b (findings of the verification of task 11).

func (s *logSetup) newMailbox(t *testing.T) store.ID {
	t.Helper()
	id, err := store.NewID(nil)
	if err != nil {
		t.Fatal(err)
	}
	inbox, _ := store.NewID(nil)
	if err := s.st.WriteMailbox(&store.Mailbox{ID: id, Epoch: 1, Inbox: inbox}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *logSetup) addArgs(addr string, mbx store.ID) []string {
	return []string{"address", "add", addr, "--mailbox", mbx.String(), "--data", s.data,
		"--admin-key", filepath.Join(s.keys, ceremony.AdminKeyFile), "--pin", s.pin}
}

func (s *logSetup) logged(t *testing.T, addr string) int {
	t.Helper()
	es, err := s.operator(t).Lookup(translog.KindAddress, []byte(addr))
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// refused runs args and requires exit status 2 without a log entry, an
// unchanged addresses.json and no address in the output.
func (s *logSetup) refused(t *testing.T, name string, args []string, addr string, mbx store.ID) {
	t.Helper()
	before, _ := os.ReadFile(s.st.AddressesFile())
	n := s.logged(t, addr)
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, nil)
	if code != 2 {
		t.Fatalf("%s: exit %d %s", name, code, errb.String())
	}
	if got := s.logged(t, addr); got != n {
		t.Fatalf("%s: log entries %d -> %d", name, n, got)
	}
	if after, _ := os.ReadFile(s.st.AddressesFile()); !bytes.Equal(before, after) {
		t.Fatalf("%s: addresses.json changed", name)
	}
	msg := strings.ToLower(errb.String() + out.String())
	if strings.Contains(msg, strings.ToLower(addr)) || strings.Contains(msg, "example.org") {
		t.Fatalf("%s: address in the output: %q", name, errb.String())
	}
	if !strings.Contains(errb.String(), "Postfach "+mbx.String()+": Adresse bereits zugeordnet") {
		t.Fatalf("%s: message %q", name, errb.String())
	}
}

// TestAddressReassign (finding 2, from verifier test 4): "address add"
// for an address assigned to another mailbox, in addresses.json or in
// the log, is a usage error (exit 2) before anything is logged; the
// message names the mailbox, not the address. The same mailbox again is
// allowed.
func TestAddressReassign(t *testing.T) {
	s := newLogSetup(t)
	ctx := context.Background()
	other := s.newMailbox(t)
	var out, errb bytes.Buffer
	if code := run(ctx, s.addArgs("info@example.org", s.mbx), &out, &errb, nil); code != 0 {
		t.Fatalf("first: %d %s", code, errb.String())
	}
	s.refused(t, "other mailbox", s.addArgs("Info@Example.ORG", other), "info@example.org", other)
	// The same mailbox again: logged once more, addresses.json unchanged
	// in content.
	if code := run(ctx, s.addArgs("info@example.org", s.mbx), &out, &errb, nil); code != 0 || s.logged(t, "info@example.org") != 2 {
		t.Fatalf("same mailbox: %d %s", code, errb.String())
	}
	// Assigned in the log only (a crash after Append): refused for
	// another mailbox.
	admin, gen, err := ceremony.ReadKey(filepath.Join(s.keys, ceremony.AdminKeyFile), store.KeyRoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	a := &store.AddressAssignment{Address: "log-only@example.org", MailboxID: other, ValidFrom: time.Now().UnixMilli(), AdminGen: gen}
	if err := a.Sign(admin); err != nil {
		t.Fatal(err)
	}
	enc, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operator(t).Append(translog.KindAddress, enc); err != nil {
		t.Fatal(err)
	}
	s.refused(t, "log only", s.addArgs("log-only@example.org", s.mbx), "log-only@example.org", s.mbx)
	// ... and accepted for its own mailbox, which then enters
	// addresses.json.
	if code := run(ctx, s.addArgs("log-only@example.org", other), &out, &errb, nil); code != 0 {
		t.Fatalf("log only, own mailbox: %d %s", code, errb.String())
	}
	// Assigned in addresses.json only: refused, nothing logged.
	if _, err := s.st.AddAddress("json-only@example.org", other); err != nil {
		t.Fatal(err)
	}
	s.refused(t, "addresses.json only", s.addArgs("json-only@example.org", s.mbx), "json-only@example.org", s.mbx)
	// Without the log (--insecure-no-log) addresses.json alone decides.
	noLog := []string{"address", "add", "json-only@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
		"--admin-key", filepath.Join(s.keys, ceremony.AdminKeyFile), "--insecure-no-log"}
	s.refused(t, "without log", noLog, "json-only@example.org", s.mbx)
	// A malformed address: no address in the message either.
	errb.Reset()
	if code := run(ctx, s.addArgs("bad address@example.org", s.mbx), &out, &errb, nil); code != 1 || strings.Contains(errb.String(), "example.org") {
		t.Fatalf("malformed address: %d %q", code, errb.String())
	}
}

// TestPinSymlink (finding 6): pin and data directory are compared with
// their symbolic links resolved; a pin that leads into the data
// directory is a usage error (exit 2) for every command, a link to a pin
// outside works.
func TestPinSymlink(t *testing.T) {
	s := newLogSetup(t)
	ctx := context.Background()
	inside := filepath.Join(s.data, "identity-1.pin")
	data, err := os.ReadFile(s.pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(inside, data); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.dir, "link.pin")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	dataLink := filepath.Join(s.dir, "data-link")
	if err := os.Symlink(s.data, dataLink); err != nil {
		t.Fatal(err)
	}
	adminKey := filepath.Join(s.keys, ceremony.AdminKeyFile)
	ingestKey := filepath.Join(s.keys, ceremony.IngestKeyFile)
	for name, args := range map[string][]string{
		"address add, linked pin": {"address", "add", "a@example.org", "--mailbox", s.mbx.String(), "--data", s.data, "--admin-key", adminKey, "--pin", link},
		"log repair, linked pin":  {"log", "repair", "--data", s.data, "--pin", link},
		"serve, linked pin": {"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", ingestKey, "--pin", link,
			"--log-listen", "127.0.0.1:0"},
		"address add, linked data directory": {"address", "add", "a@example.org", "--mailbox", s.mbx.String(), "--data", dataLink, "--admin-key", adminKey,
			"--pin", inside},
		"log repair, linked data directory": {"log", "repair", "--data", dataLink, "--pin", inside},
	} {
		var out, errb bytes.Buffer
		if code := run(ctx, args, &out, &errb, nil); code != 2 || !strings.Contains(errb.String(), "Pin darf nicht im Datenverzeichnis") {
			t.Fatalf("%s: %d %s", name, code, errb.String())
		}
	}
	if s.logged(t, "a@example.org") != 0 {
		t.Fatal("logged with a pin from the data directory")
	}
	// An ingest key reached through a link into the data directory.
	keyIn := filepath.Join(s.data, "ingest.key")
	kd, err := os.ReadFile(ingestKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(keyIn, kd); err != nil {
		t.Fatal(err)
	}
	keyLink := filepath.Join(s.dir, "ingest-link.key")
	if err := os.Symlink(keyIn, keyLink); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", keyLink, "--insecure-no-log"}, &out, &errb, nil); code != 1 ||
		!strings.Contains(errb.String(), "Ingest-Schlüssel darf nicht im Datenverzeichnis") {
		t.Fatalf("linked ingest key: %d %s", code, errb.String())
	}
	// A link outside the data directory to the pin outside: accepted.
	good := filepath.Join(s.dir, "good.pin")
	if err := os.Symlink(s.pin, good); err != nil {
		t.Fatal(err)
	}
	args := []string{"address", "add", "a@example.org", "--mailbox", s.mbx.String(), "--data", dataLink, "--admin-key", adminKey, "--pin", good}
	if code := run(ctx, args, &out, &errb, nil); code != 0 || s.logged(t, "a@example.org") != 1 {
		t.Fatalf("linked pin outside: %d %s", code, errb.String())
	}
}
