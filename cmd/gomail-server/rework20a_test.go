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
)

// TestServeNotYetValid (task 20a point 1, RUNBOOK 6 step 4): serve
// refuses an ingest key whose certificate is valid only from a time
// after the clock of the computer, with exit status 2 and the fixed
// message ingestNotYetValid, and leaves no server lock behind; the same
// platform with valid_from in the past starts (TestServeLog).
func TestServeNotYetValid(t *testing.T) {
	s := newLogSetupAt(t, time.Now().Add(time.Hour))
	var out, errb bytes.Buffer
	args := []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", filepath.Join(s.keys, ceremony.IngestKeyFile),
		"--pin", s.pin, "--log-listen", "127.0.0.1:0"}
	if code := run(context.Background(), args, &out, &errb, nil); code != 2 {
		t.Fatalf("exit status %d: %s", code, errb.String())
	}
	if got := errb.String(); got != "gomail-server: "+ingestNotYetValid+"\n" && !strings.HasSuffix(got, "\ngomail-server: "+ingestNotYetValid+"\n") {
		t.Fatalf("stderr %q", got)
	}
	release, err := s.st.HoldRoleLock(store.RoleServer)
	if err != nil {
		t.Fatalf("server lock left behind: %v", err)
	}
	release()
}
