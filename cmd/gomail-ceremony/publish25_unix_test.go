//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/witness"
)

// TestPublishLinksAndTmpOutput (review of task 25 A, L1, L2 and H4): the
// output of publish for the cases of 25A2.
//
//   - The temporary files publish removes from platform/ are named on
//     standard error, also when publish refuses afterwards (here: a link
//     as witnesses.rec without --replace-witnesses); a name with control
//     characters is quoted.
//   - A link as witnesses.rec replaced with --replace-witnesses gets its
//     own line on standard output, with the pin's quorum and no old one.
//   - platform/ as a symbolic link is refused with exit 1 before anything
//     is removed.
func TestPublishLinksAndTmpOutput(t *testing.T) {
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
	if strings.Contains(tt.msgs.String(), "Rest eines abgebrochenen Schreibvorgangs") {
		t.Fatalf("temporary file named without one: %q", tt.msgs.String())
	}
	// The first publish writes witnesses.rec, it replaces no link (review
	// of task 25 A2, S12): no line about one.
	if o := tt.out.String(); strings.Contains(o, "witnesses.rec war ") || strings.Contains(o, " Link ") ||
		!strings.Contains(o, " veröffentlicht und ins Log eingetragen.\n") {
		t.Fatalf("first publish: stdout %q", o)
	}
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	succ := filepath.Join(base, "succ")
	if code := tt.run("succeed", "--pin", pin1Path, "--out", succ, "--witness", w1, "--witness", w2,
		"--witness", w3, "--min-witnesses", "2"); code != 0 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	pin2Path := filepath.Join(succ, "identity-2.pin")

	plat := filepath.Join(dataDir, "platform")
	wrec := filepath.Join(plat, "witnesses.rec")
	outside := filepath.Join(base, "outside-witnesses.rec")
	if err := os.Rename(wrec, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, wrec); err != nil {
		t.Fatal(err)
	}
	writeTmp := func(names ...string) {
		t.Helper()
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(plat, n), []byte("rest"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Refused (a link as witnesses.rec), the temporary files named anyway.
	writeTmp(".tmp-0123456789abcdef", ".tmp-\x1b[31mx")
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "is a symbolic link") {
		t.Fatalf("link as witnesses.rec: %d %s", code, tt.msgs.String())
	}
	msgs := tt.msgs.String()
	for _, want := range []string{
		"platform/.tmp-0123456789abcdef: Rest eines abgebrochenen Schreibvorgangs entfernt.\n",
		`platform/".tmp-\x1b[31mx": Rest eines abgebrochenen Schreibvorgangs entfernt.` + "\n",
	} {
		if !strings.Contains(msgs, want) {
			t.Fatalf("stderr without %q: %q", want, msgs)
		}
	}
	if strings.Contains(msgs, "\x1b") {
		t.Fatalf("control character on stderr: %q", msgs)
	}

	// Replaced with the flag: its own line, the pin's quorum.
	writeTmp(".tmp-fedcba9876543210")
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path, "--replace-witnesses"); code != 0 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	// Exactly, the line once and before the closing lines (review of task
	// 25 A3, N2).
	if o, want := tt.out.String(), "platform/witnesses.rec war ein symbolischer Link und ist durch die Zeugen des Pins ersetzt "+
		"(der Link wurde nicht gelesen, ein bisheriges Quorum gibt es nicht): jetzt Quorum 2 von 3 (w1, w2, w3) wie im Pin.\n"+
		publishedText(succ, dataDir, pin2Path); o != want {
		t.Fatalf("stdout\n%q, want\n%q", o, want)
	}
	if m := tt.msgs.String(); m != "platform/.tmp-fedcba9876543210: Rest eines abgebrochenen Schreibvorgangs entfernt.\n" {
		t.Fatalf("stderr %q", m)
	}
	if fi, err := os.Lstat(wrec); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("witnesses.rec: %v %v", fi, err)
	}

	// platform/ as a symbolic link: exit 1, nothing removed.
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.Rename(plat, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, plat); err != nil {
		t.Fatal(err)
	}
	writeTmp(".tmp-1111111111111111")
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin2Path); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "gomail-ceremony: ceremony: platform/ of the data directory is a symbolic link: "+plat+
			" points to "+strconv.Quote(elsewhere)+"; nothing removed or written: ") ||
		strings.Contains(tt.msgs.String(), "Rest eines") {
		t.Fatalf("platform/ as a link: %d %s", code, tt.msgs.String())
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, ".tmp-1111111111111111")); err != nil {
		t.Fatalf("removed through the link: %v", err)
	}
}

// TestWitnessesReplacedNoBefore (review of task 25 A, H4): the message
// for a replaced witnesses.rec does not crash without a working copy
// before (nil), and printableName quotes only what needs it.
func TestWitnessesReplacedNoBefore(t *testing.T) {
	w := &witness.Witnesses{List: []witness.Key{{Name: "w1"}, {Name: "w2"}}, Min: 2}
	for _, c := range []struct {
		got, want string
	}{
		{replacedText(nil, w), "platform/witnesses.rec ersetzt: jetzt Quorum 2 von 2 (w1, w2) wie im Pin.\n"},
		{replacedText(nil, nil), "platform/witnesses.rec ersetzt: jetzt Zeugen und Quorum wie im Pin.\n"},
		{replacedText(&witness.Witnesses{List: w.List[:1], Min: 1}, w),
			"platform/witnesses.rec ersetzt: bisher Quorum 1 von 1 (w1), jetzt Quorum 2 von 2 (w1, w2) wie im Pin.\n"},
		{linkReplacedText("a hard link", w), "platform/witnesses.rec war ein harter Link und ist durch die Zeugen des Pins ersetzt " +
			"(sein Inhalt wurde nicht übernommen, ein bisheriges Quorum gibt es nicht): jetzt Quorum 2 von 2 (w1, w2) wie im Pin.\n"},
		{linkReplacedText("a link", nil), "platform/witnesses.rec war ein Link und ist durch die Zeugen des Pins ersetzt " +
			"(der Link wurde nicht gelesen, ein bisheriges Quorum gibt es nicht): jetzt Zeugen und Quorum wie im Pin.\n"},
		{linkReplacedText("a symbolic link", nil), "platform/witnesses.rec war ein symbolischer Link und ist durch die Zeugen des Pins ersetzt " +
			"(der Link wurde nicht gelesen, ein bisheriges Quorum gibt es nicht): jetzt Zeugen und Quorum wie im Pin.\n"},
		{linkText("something else"), "ein Link"},
	} {
		if c.got != c.want {
			t.Fatalf("%q, want %q", c.got, c.want)
		}
	}
	for in, want := range map[string]string{
		".tmp-0a1b":     ".tmp-0a1b",
		".tmp-a b":      `".tmp-a b"`,
		".tmp-\n":       `".tmp-\n"`,
		".tmp-ä":        `".tmp-ä"`,
		".tmp-\x7f":     `".tmp-\x7f"`,
		".tmp-used-ABC": ".tmp-used-ABC",
	} {
		if got := printableName(in); got != want {
			t.Fatalf("printableName(%q) = %q, want %q", in, got, want)
		}
	}
}
