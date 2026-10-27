package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	// There is no way around the log any more (task 15): --insecure-no-log
	// is a usage error, nothing is logged or assigned.
	noLog := []string{"address", "add", "json-only@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
		"--admin-key", filepath.Join(s.keys, ceremony.AdminKeyFile), "--insecure-no-log"}
	before, _ := os.ReadFile(s.st.AddressesFile())
	if code := run(ctx, noLog, &out, &errb, nil); code != 2 || s.logged(t, "json-only@example.org") != 0 {
		t.Fatalf("--insecure-no-log: %d", code)
	}
	if after, _ := os.ReadFile(s.st.AddressesFile()); !bytes.Equal(before, after) {
		t.Fatal("--insecure-no-log: addresses.json changed")
	}
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
	if code := run(ctx, []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", keyLink, "--pin", s.pin,
		"--log-listen", "127.0.0.1:0"}, &out, &errb, nil); code != 1 ||
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
	// The admin key (task 15, from the verification of 11b): inside the
	// data directory, directly or through a link, it is a usage error
	// (exit 2) and nothing is logged.
	adminIn := filepath.Join(s.data, "admin.key")
	ad, err := os.ReadFile(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WritePrivateFileAtomic(adminIn, ad); err != nil {
		t.Fatal(err)
	}
	adminLink := filepath.Join(s.dir, "admin-link.key")
	if err := os.Symlink(adminIn, adminLink); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"admin key inside": adminIn, "admin key through a link": adminLink} {
		errb.Reset()
		args := []string{"address", "add", "k@example.org", "--mailbox", s.mbx.String(), "--data", s.data, "--admin-key", key, "--pin", s.pin}
		if code := run(ctx, args, &out, &errb, nil); code != 2 || !strings.Contains(errb.String(), "Admin-Schlüssel darf nicht im Datenverzeichnis") ||
			s.logged(t, "k@example.org") != 0 {
			t.Fatalf("%s: %d %s", name, code, errb.String())
		}
	}
	// A link outside the data directory to the admin key outside: accepted.
	adminGood := filepath.Join(s.dir, "admin-good.key")
	if err := os.Symlink(adminKey, adminGood); err != nil {
		t.Fatal(err)
	}
	args = []string{"address", "add", "k@example.org", "--mailbox", s.mbx.String(), "--data", s.data, "--admin-key", adminGood, "--pin", s.pin}
	if code := run(ctx, args, &out, &errb, nil); code != 0 || s.logged(t, "k@example.org") != 1 {
		t.Fatalf("linked admin key outside: %d %s", code, errb.String())
	}
}

// TestAddressAddParallel (task 15, from the verification of 11b): two
// "address add" for the same address and different mailboxes at once;
// exactly one wins, the other is a usage error that names no address,
// and addresses.json and the log agree. The runs share this process, so
// addresses.lock serializes them through the lock registry of store as
// two processes through the record lock.
func TestAddressAddParallel(t *testing.T) {
	s := newLogSetup(t)
	for i := 0; i < 8; i++ {
		addr := "par" + strconv.Itoa(i) + "@example.org"
		boxes := []store.ID{s.newMailbox(t), s.newMailbox(t)}
		var wg sync.WaitGroup
		codes := make([]int, 2)
		outs := make([]string, 2)
		for j := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var out, errb bytes.Buffer
				codes[j] = run(context.Background(), s.addArgs(addr, boxes[j]), &out, &errb, nil)
				outs[j] = out.String() + errb.String()
			}()
		}
		wg.Wait()
		s.checkOneWinner(t, addr, boxes, codes, outs)
	}
}

// TestAddressAddInjected: the injection point between the check under
// addresses.lock and the Append. A second "address add" for another
// mailbox started there waits for the lock, finds the first one's log
// entry and refuses.
func TestAddressAddInjected(t *testing.T) {
	s := newLogSetup(t)
	addr := "inject@example.org"
	boxes := []store.ID{s.newMailbox(t), s.newMailbox(t)}
	codes := make([]int, 2)
	outs := make([]string, 2)
	second := make(chan struct{})
	addressHook = func() {
		addressHook = nil
		go func() {
			defer close(second)
			var out, errb bytes.Buffer
			codes[1] = run(context.Background(), s.addArgs(addr, boxes[1]), &out, &errb, nil)
			outs[1] = out.String() + errb.String()
		}()
		// Give the second run time to reach addresses.lock.
		time.Sleep(50 * time.Millisecond)
	}
	defer func() { addressHook = nil }()
	var out, errb bytes.Buffer
	codes[0] = run(context.Background(), s.addArgs(addr, boxes[0]), &out, &errb, nil)
	outs[0] = out.String() + errb.String()
	<-second
	if codes[0] != 0 {
		t.Fatalf("first: %d %s", codes[0], outs[0])
	}
	s.checkOneWinner(t, addr, boxes, codes, outs)
}

// checkOneWinner requires exactly one exit status 0 and one 2, no
// address in the loser's output, and addresses.json and the log naming
// the winner's mailbox only.
func (s *logSetup) checkOneWinner(t *testing.T, addr string, boxes []store.ID, codes []int, outs []string) {
	t.Helper()
	var winner int
	switch {
	case codes[0] == 0 && codes[1] == 2:
		winner = 0
	case codes[1] == 0 && codes[0] == 2:
		winner = 1
	default:
		t.Fatalf("exit codes %v\n%s\n%s", codes, outs[0], outs[1])
	}
	loser := 1 - winner
	if strings.Contains(strings.ToLower(outs[loser]), addr) || strings.Contains(outs[loser], "example.org") {
		t.Fatalf("address in the loser's output: %q", outs[loser])
	}
	cur, err := s.st.LoadAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if cur[addr] != boxes[winner] {
		t.Fatalf("addresses.json names %s, winner %s", cur[addr], boxes[winner])
	}
	es, err := s.operator(t).Lookup(translog.KindAddress, []byte(addr))
	if err != nil || len(es) != 1 {
		t.Fatalf("log entries %d %v", len(es), err)
	}
	a, err := store.DecodeAddressAssignment(es[0].Content)
	if err != nil || a.MailboxID != boxes[winner] {
		t.Fatalf("log names another mailbox than the winner %s", boxes[winner])
	}
}
