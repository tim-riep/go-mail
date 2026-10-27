//go:build gomail_dev

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// TestRunDev: init --dev in the test build (tag gomail_dev): the usage
// names it; it needs --data and --keys and nothing of the real ceremony;
// --insecure-no-log is no flag any more (task 15b point 4); the
// certificates are in the operator log of the new data directory; a
// second development ceremony into the same directories is refused.
func TestRunDev(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"x"}, {"init", "--bogus"}, {"init", "--data", "a", "--keys", "b"}, {"init", "--dev"},
		{"init", "--dev", "--data", "a", "--keys", "b", "extra"}, {"init", "--dev", "--data", "a", "--keys", "b", "--shares", "3-of-5"},
		{"init", "--dev", "--data", "a", "--keys", "b", "--insecure-no-log"}} {
		errb.Reset()
		if run(args, nil, &out, &errb) != 2 {
			t.Fatalf("%v accepted", args)
		}
		if !strings.Contains(errb.String(), "init --dev --data") {
			t.Fatalf("%v: usage without init --dev: %q", args, errb.String())
		}
	}
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	errb.Reset()
	if run([]string{"init", "--dev", "--data", data, "--keys", keys}, nil, &out, &errb) != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(errb.String(), "WARNUNG") || !strings.Contains(out.String(), "ingest-1.key") {
		t.Fatal("output")
	}
	pin, err := ceremony.ReadPin(filepath.Join(keys, ceremony.PinFile))
	if err != nil || !pin.Dev {
		t.Fatalf("pin %v", err)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	ids := []translog.Identity{{Gen: 1, Pub: pin.Pub}}
	l, err := translog.Open(translog.Options{Store: st, Identities: ids})
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"admin-1.cert", "ingest-1.cert"} {
		e, err := l.Entry(int64(i))
		if err != nil || string(e.Key.Subject) != name {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if run([]string{"init", "--dev", "--data", data, "--keys", keys}, nil, &out, &errb) != 1 {
		t.Fatal("second ceremony")
	}
}
