//go:build unix

package client_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestUnprocessedMailEACCES: a mail file marked unprocessed that the
// client may not read (mode 000, EACCES on open, a *fs.PathError) is no
// verdict on the mail: Search takes the terms of the metadata and Index
// leaves the marker, each with the warning "Datei nicht lesbar"; Read
// returns the error of the system without a warning. Once the file can
// be read, Index takes from: and to: from it (task 28, Nr. 102). It runs
// only where a file with mode 000 gives EACCES, that is without
// CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH; as root, for example, it is
// skipped (run it once with setpriv
// --bounding-set=-dac_override,-dac_read_search).
func TestUnprocessedMailEACCES(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0); err != nil {
		t.Fatal(err)
	}
	if fh, err := os.Open(probe); !errors.Is(err, syscall.EACCES) {
		if err == nil {
			fh.Close()
		}
		t.Skipf("a file with mode 000 gives no EACCES here (%v): the process may read it anyway (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, as root)", err)
	}
	f := newFixture(t)
	f.send(t, envFrom, msgLongTo)
	c := f.u.Client
	m := mailBySubject(t, f, "longto")
	path := f.env.Store.MailFile(f.mbx, f.inbox(t), m.ID)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	want := "WARNUNG: Mail " + m.ID.String() + " lässt sich nicht lesen: Datei nicht lesbar. " +
		"Ihr Eintrag in pending/ bleibt für einen späteren Index-Lauf liegen; bis dahin gelten die Suchbegriffe ihrer Metadaten."
	warnings := func(stage string, n int) {
		t.Helper()
		if w := f.env.Warnings.Take(); len(w) != n || n == 1 && w[0] != want {
			t.Fatalf("%s: warnings %q", stage, w)
		}
	}
	for _, tc := range []struct{ q, want string }{
		{"to:addr000@recipients.example", "longto"},
		{"to:addr139@recipients.example", ""},
	} {
		if got := search(t, c, f.mbx, tc.q, ""); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.q, got, tc.want)
		}
		warnings(tc.q, 1)
	}
	for run := 0; run < 2; run++ {
		if n, err := c.Index(f.mbx); err != nil || n != 0 {
			t.Fatal(n, err)
		}
		warnings("index", 1)
		if pendingCount(t, f.env, f.mbx, 1) != 1 || segmentCount(t, f.env, f.mbx, 1) != 0 {
			t.Fatal("the marker must stay while the mail cannot be read")
		}
	}
	var pe *fs.PathError
	if _, _, err := c.Read(f.mbx, m.ID); !errors.Is(err, syscall.EACCES) || !errors.As(err, &pe) {
		t.Fatalf("read: %v", err)
	}
	warnings("read", 0)
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Index(f.mbx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if pendingCount(t, f.env, f.mbx, 1) != 0 {
		t.Fatal("marker left")
	}
	if got := search(t, c, f.mbx, "to:addr139@recipients.example", ""); got != "longto" {
		t.Fatalf("after the mail could be read: %q", got)
	}
	warnings("end", 0)
}
