package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 15c (findings 3, 5, 7 and 8 of the verification of task
// 15).

// TestRequireClientLock (finding 3, D70): with --require-client-lock the
// server starts only beside a client lock locks/client that is in force;
// without the switch it starts as before.
func TestRequireClientLock(t *testing.T) {
	s := newLogSetup(t)
	args := append(s.serveArgs(), "--require-client-lock")
	var out, errb bytes.Buffer
	if code := run(context.Background(), args, &out, &errb, func(string, string) { t.Fatal("started without a client") }); code != 1 ||
		!strings.Contains(errb.String(), "Testsperre") || !strings.Contains(errb.String(), "locks/client") ||
		!strings.Contains(errb.String(), "ingest: client lock") {
		// "ingest: client lock": refused by ingest.New (Config.PeerCheck),
		// before checkLocks.
		t.Fatalf("without a client: %d %s", code, errb.String())
	}
	// The server lock was released again: a server without the switch
	// starts.
	logs := s.start(t)
	if !strings.Contains(logs.String(), "no client lock held") {
		t.Fatalf("without the switch: %s", logs.String())
	}
}

// TestRequireClientLockHeld: with a client lock held (as gomailctl holds
// it) the server starts with --require-client-lock.
func TestRequireClientLockHeld(t *testing.T) {
	s := newLogSetup(t)
	release, err := s.st.HoldRoleLock(store.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb bytes.Buffer
	started := false
	code := run(ctx, append(s.serveArgs(), "--require-client-lock"), &out, &errb, func(string, string) { started = true; cancel() })
	if code != 0 || !started || !strings.Contains(errb.String(), "client lock in force") {
		t.Fatalf("with a client lock: %d %s", code, errb.String())
	}
}

// TestCheckLocksRequireClient: checkLocks refuses a missing client lock
// only when it is required.
func TestCheckLocksRequireClient(t *testing.T) {
	s := newLogSetup(t)
	release, err := s.st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	logger := slog.New(slog.DiscardHandler)
	if err := checkLocks(s.st, false, logger); err != nil {
		t.Fatal(err)
	}
	if err := checkLocks(s.st, true, logger); err == nil || !errors.Is(err, store.ErrPeerLock) {
		t.Fatalf("required client lock missing: %v", err)
	}
}

// TestCheckDiskSpace (finding 5): a platform that cannot tell the free
// space is reported at the start; otherwise nothing is said.
func TestCheckDiskSpace(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	checkDiskSpace(func() (uint64, uint64, error) { return 0, 0, errors.New("ingest: free space unknown on this platform") }, logger)
	if l := buf.String(); !strings.Contains(l, "accepts no mail until DiskSpace is set") {
		t.Fatalf("log %q", l)
	}
	buf.Reset()
	checkDiskSpace(func() (uint64, uint64, error) { return 50, 100, nil }, logger)
	if buf.Len() != 0 {
		t.Fatalf("log %q", buf.String())
	}
}

// TestNoTestSwitchInProduction (finding 7): a build without the tag
// gomail_test ignores GOMAIL_TEST_MIN_FREE; the free space check of 5.1
// has no switch in the production binary.
func TestNoTestSwitchInProduction(t *testing.T) {
	if testTagged {
		t.Skip("test build with the tag gomail_test")
	}
	t.Setenv("GOMAIL_TEST_MIN_FREE", "0.000001")
	c := ingest.Config{}
	if err := testConfig(&c); err != nil || c.MinFree != 0 {
		t.Fatalf("production build applied the test switch: %v %v", c.MinFree, err)
	}
}

// TestDataDirMessage (finding 8): the start says that only the root and
// the top-level entries were checked.
func TestDataDirMessage(t *testing.T) {
	s := newLogSetup(t)
	var buf bytes.Buffer
	if err := checkDataDir(s.st, slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "root and top-level entries only") {
		t.Fatalf("log %q", buf.String())
	}
}
