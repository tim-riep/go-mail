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
)

// TestSecondServerBeforeKey (task 14 addendum, finding of the
// verification of task 16): a second server checks the server lock
// before it reads the ingest key. With the lock held by another server
// and the key file unreadable (a directory in its place), the start
// fails with the server lock, not with the key.
func TestSecondServerBeforeKey(t *testing.T) {
	s := newLogSetup(t)
	release, err := s.st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	key := filepath.Join(s.keys, ceremony.IngestKeyFile)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(key, 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run(context.Background(), s.serveArgs(), &out, &errb, func(string, string) { t.Fatal("server started") })
	if code != 1 || !strings.Contains(errb.String(), "Serversperre") {
		t.Fatalf("second server with an unreadable key: %d %s", code, errb.String())
	}
	// Without the other server the unreadable key is what stops it.
	release()
	errb.Reset()
	if code := run(context.Background(), s.serveArgs(), &out, &errb, func(string, string) { t.Fatal("server started") }); code != 1 || strings.Contains(errb.String(), "Serversperre") {
		t.Fatalf("unreadable key alone: %d %s", code, errb.String())
	}
}

// TestHeadGapSwitch: the test switch GOMAIL_TEST_HEAD_GAP (task 14)
// exists only in a build with the tag gomail_test
// (testconfig_tagged.go); a production build keeps the minimum gap of
// loghttp.
func TestHeadGapSwitch(t *testing.T) {
	t.Setenv("GOMAIL_TEST_HEAD_GAP", "2s")
	got := testMinGap()
	if testTagged && got != 2*time.Second || !testTagged && got != 0 {
		t.Fatalf("tagged %v: gap %v", testTagged, got)
	}
	t.Setenv("GOMAIL_TEST_HEAD_GAP", "1ms")
	if testMinGap() != 0 {
		t.Fatal("gap below one second accepted")
	}
}
