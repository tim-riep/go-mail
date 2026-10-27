package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestLogRepairOrphans (task 15d point 2): an entry file beyond the
// entries that exist and decode (entries/3.rec beside the two entries
// of the ceremony) keeps the server from starting. "log repair" reports
// it with its count, removes nothing and writes nothing (exit status 1);
// the server still refuses. Once the operator has removed it, "log
// repair" reports no orphan and the server starts.
func TestLogRepairOrphans(t *testing.T) {
	s := newLogSetup(t)
	if s.treeSize(t) != 2 {
		t.Fatal("setup")
	}
	entries := filepath.Join(s.data, "log", "entries")
	data, err := os.ReadFile(filepath.Join(entries, "0.rec"))
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(entries, "3.rec")
	if err := store.WriteFileAtomic(orphan, data); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(s.data, "log", "tree.rec")
	before, err := os.ReadFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	s.startFails(t, "orphan beyond the next index", "log is inconsistent")
	ctx := context.Background()
	repair := []string{"log", "repair", "--data", s.data, "--pin", s.pin}
	var out, errb bytes.Buffer
	if code := run(ctx, repair, &out, &errb, nil); code != 1 ||
		!strings.Contains(errb.String(), "1 orphaned entries beyond the 2 entries") ||
		!strings.Contains(errb.String(), "1 verwaiste Einträge jenseits von 2 gemeldet, 0 verworfen") ||
		!strings.Contains(errb.String(), "Nach Prüfung log/entries/3.rec bewusst entfernen") || out.Len() != 0 {
		t.Fatalf("repair with an orphan: %d %q %q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("orphan removed")
	}
	if after, err := os.ReadFile(tree); err != nil || !bytes.Equal(after, before) {
		t.Fatal("tree.rec written")
	}
	s.startFails(t, "after the refused repair", "log is inconsistent")
	// The operator removes the orphan on purpose and repairs again.
	if err := os.Remove(orphan); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := run(ctx, repair, &out, &errb, nil); code != 0 || !strings.Contains(out.String(), "0 verwaiste Einträge gemeldet, 0 verworfen") {
		t.Fatalf("repair: %d %q %q", code, out.String(), errb.String())
	}
	s.start(t)
}
