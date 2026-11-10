//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 25 package 25A, rework 25A4 (reviews of 25A3): the
// output of publish on standard output, exactly (N2), and the line for a
// replaced witnesses.rec before a later failure without chattr (N3).

// publishedText is what publish prints on standard output last, after
// it succeeded.
func publishedText(from, data, pin string) string {
	return from + " in " + data + " veröffentlicht und ins Log eingetragen.\n" +
		"Den Server jetzt mit diesem Pin starten: gomail-server serve --pin " + pin + " ...\n"
}

// replaceFile puts data under path by rename, as a regular file (a link
// there is replaced, not its target).
func replaceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path+".new", data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

// symlinkOutside moves path to outside and puts a symbolic link to it
// in its place.
func symlinkOutside(t *testing.T, path, outside string) {
	t.Helper()
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
}

// blockLogAppend makes the next append to the operator log of dataDir
// fail, without chattr and whatever the user (root included): a
// directory that is not empty in place of the next entry,
// log/entries/<size>.rec/x, cannot be removed as the leftover of an
// interrupted append (os.Remove fails with ENOTEMPTY), so the append
// fails before it writes anything, while the lookups of publish before
// the log entries only read the committed entries. size is the number
// of entry files, which must be 0.rec to <size-1>.rec. t.TempDir removes
// it like any directory.
func blockLogAppend(t *testing.T, dataDir string) {
	t.Helper()
	entries := filepath.Join(dataDir, filepath.FromSlash(translog.EntriesDir))
	des, err := os.ReadDir(entries)
	if err != nil {
		t.Fatal(err)
	}
	size := len(des)
	for i := range size {
		if _, err := os.Lstat(filepath.Join(entries, strconv.Itoa(i)+".rec")); err != nil {
			t.Fatalf("log/entries/ is not 0.rec to %d.rec: %v", size-1, err)
		}
	}
	next := filepath.Join(entries, strconv.Itoa(size)+".rec")
	if err := os.Mkdir(next, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(next, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPublishWitnessesLineBeforeFailure (review of task 25 A2, N2;
// rework 25A4, N3 without chattr): the line for a replaced
// witnesses.rec, a link as well as a regular file with other witnesses,
// is printed when it is replaced, not only after publish succeeded.
// Here publish fails afterwards, when it appends the log entries: a
// directory in place of the next entry (blockLogAppend) makes the first
// append fail. witnesses.rec stays replaced, and its line alone is on
// standard output.
func TestPublishWitnessesLineBeforeFailure(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	w1, w2, w3 := witnessArg(t, "w1"), witnessArg(t, "w2"), witnessArg(t, "w3")
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	pin1Path := filepath.Join(out, "identity-1.pin")
	dataDir := filepath.Join(base, "data")
	if _, err := store.Init(dataDir); err != nil {
		t.Fatal(err)
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", pin1Path); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	succ := filepath.Join(base, "succ")
	if code := tt.run("succeed", "--pin", pin1Path, "--out", succ, "--witness", w1, "--witness", w2,
		"--witness", w3, "--min-witnesses", "2"); code != 0 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	pin2Path := filepath.Join(succ, "identity-2.pin")
	blockLogAppend(t, dataDir)

	wrec := filepath.Join(dataDir, "platform", "witnesses.rec")
	old := mustRead(t, wrec)
	symlinkOutside(t, wrec, filepath.Join(base, "outside-witnesses.rec"))
	for _, c := range []struct{ kind, line string }{
		{"link", "platform/witnesses.rec war ein symbolischer Link und ist durch die Zeugen des Pins ersetzt " +
			"(der Link wurde nicht gelesen, ein bisheriges Quorum gibt es nicht): jetzt Quorum 2 von 3 (w1, w2, w3) wie im Pin.\n"},
		{"regular", "platform/witnesses.rec ersetzt: bisher Quorum 1 von 1 (w1), jetzt Quorum 2 von 3 (w1, w2, w3) wie im Pin.\n"},
	} {
		if c.kind == "regular" {
			// The working copy of pin 1 again, as a regular file.
			replaceFile(t, wrec, old)
		}
		tt = newTTY()
		code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path, "--replace-witnesses")
		if code != exitFail || !strings.Contains(tt.msgs.String(), "ceremony: logging identity-2.succ: ") ||
			!strings.Contains(tt.msgs.String(), "leftover entry") {
			t.Fatalf("%s: publish with the next entry blocked: %d %s", c.kind, code, tt.msgs.String())
		}
		if o := tt.out.String(); o != c.line {
			t.Fatalf("%s: stdout %q, want %q", c.kind, o, c.line)
		}
		if fi, err := os.Lstat(wrec); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: witnesses.rec after publish: %v %v", c.kind, fi, err)
		}
	}
}

// TestPublishRevokedReplacedOutput (review of task 25 A3, N2): publish
// with a pin with field 7 and --replace-witnesses prints on standard
// output exactly, in this order: the line for the replaced witnesses.rec
// once (at the replacement), the line for the revocations checked
// against the newest confirmed head (after success only) and the closing
// lines; for a regular working copy with other witnesses and for a
// symbolic link as witnesses.rec.
func TestPublishRevokedReplacedOutput(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	shares, pin1, _, dataDir, h, _ := platformSetup(t, base)
	N, T := fmt.Sprint(h.Size), fmt.Sprint(h.Time)
	rev := filepath.Join(base, "rev")
	tt := newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", pin1, "--out", rev, "--role", "ingest", "--generation", "1", "--revoke-at-size", N, "--revoke-at-time", T); code != 0 {
		t.Fatalf("revoke: %d %s", code, tt.msgs.String())
	}
	revPin := filepath.Join(rev, "identity-1.pin")
	out := filepath.Join(base, "out")
	revoked := fmt.Sprintf("Widerrufe des Pins (1) geprüft gegen den neuesten bestätigten Kopf (Größe %d, Zeit %d).\n", h.Size, h.Time)

	// A regular working copy with one more witness, both required.
	wrec := filepath.Join(dataDir, "platform", "witnesses.rec")
	w, err := witness.DecodeWitnesses(mustRead(t, wrec))
	if err != nil {
		t.Fatal(err)
	}
	w9, err := parseWitness(witnessArg(t, "w9"))
	if err != nil {
		t.Fatal(err)
	}
	w.List, w.Min = append(w.List, w9), 2
	other, err := w.Encode()
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, wrec, other)
	for _, c := range []struct{ kind, line string }{
		{"regular", "platform/witnesses.rec ersetzt: bisher Quorum 2 von 2 (w1, w9), jetzt Quorum 1 von 1 (w1) wie im Pin.\n"},
		{"link", "platform/witnesses.rec war ein symbolischer Link und ist durch die Zeugen des Pins ersetzt " +
			"(der Link wurde nicht gelesen, ein bisheriges Quorum gibt es nicht): jetzt Quorum 1 von 1 (w1) wie im Pin.\n"},
	} {
		if c.kind == "link" {
			symlinkOutside(t, wrec, filepath.Join(base, "outside-witnesses.rec"))
		}
		tt = newTTY()
		if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", revPin, "--replace-witnesses"); code != 0 {
			t.Fatalf("%s: publish: %d %s", c.kind, code, tt.msgs.String())
		}
		if o, want := tt.out.String(), c.line+revoked+publishedText(out, dataDir, revPin); o != want {
			t.Fatalf("%s: stdout\n%q, want\n%q", c.kind, o, want)
		}
		// No ingest generation 2 yet: the warning on standard error.
		if m := tt.msgs.String(); !strings.HasPrefix(m, "WARNUNG: Ingest-Generation 1 ist ab 2026-10-01T12:01:00.001Z widerrufen, ingest-2.cert gibt es noch nicht") ||
			strings.Contains(m, "witnesses.rec") || strings.Contains(m, "Widerrufe des Pins") {
			t.Fatalf("%s: stderr %q", c.kind, m)
		}
		if fi, err := os.Lstat(wrec); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: witnesses.rec after publish: %v %v", c.kind, fi, err)
		}
	}
	// Again: nothing to replace, no line about witnesses.rec.
	tt = newTTY()
	if code := tt.run("publish", "--from", out, "--data", dataDir, "--pin", revPin, "--replace-witnesses"); code != 0 {
		t.Fatalf("again: %d %s", code, tt.msgs.String())
	}
	if o, want := tt.out.String(), revoked+publishedText(out, dataDir, revPin); o != want {
		t.Fatalf("again: stdout\n%q, want\n%q", o, want)
	}
}
