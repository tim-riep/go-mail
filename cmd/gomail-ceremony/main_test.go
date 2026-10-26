package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"x"}, {"init", "--bogus"}, {"init", "--data", "a", "--keys", "b"}, {"init", "--dev"}, {"init", "--dev", "--data", "a", "--keys", "b", "extra"}} {
		if run(args, &out, &errb) != 2 {
			t.Fatalf("%v accepted", args)
		}
	}
	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	if run([]string{"init", "--dev", "--data", data, "--keys", keys}, &out, &errb) != 1 {
		t.Fatal("without --insecure-no-log")
	}
	errb.Reset()
	if run([]string{"init", "--dev", "--data", data, "--keys", keys, "--insecure-no-log"}, &out, &errb) != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(errb.String(), "WARNUNG") || !strings.Contains(out.String(), "ingest-1.key") {
		t.Fatal("output")
	}
	if run([]string{"init", "--dev", "--data", data, "--keys", keys, "--insecure-no-log"}, &out, &errb) != 1 {
		t.Fatal("second ceremony")
	}
}
