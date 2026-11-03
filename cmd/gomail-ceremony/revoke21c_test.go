package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 21c (D93): succeed --compromised, revoke, admin-rotate
// and publish with a pin that has field 7, through the command line with
// the stand-in terminal.

// headTime is the time of the heads signed in these tests: after the
// clock of fixClock (valid_from of the certificates of init) and within
// the clock tolerance of the ceremony.
var headTime = time.Date(2026, 10, 1, 12, 1, 0, 0, time.UTC)

// witnessSigner returns a --witness argument and the note signer of
// that witness.
func witnessSigner(t *testing.T, name string) (string, note.Signer) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return name + "=" + vkey, s
}

// signHead signs a head of the operator log of dataDir at time at with
// the ingest key file ingestKey, cosigned by ws, and publishes it, as the
// server and its witnesses would (the log opened with the pin pinPath).
func signHead(t *testing.T, dataDir, pinPath, ingestKey string, at time.Time, ws ...note.Signer) *translog.Head {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := ceremony.ReadPin(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ceremony.OpenLog(st, pin)
	if err != nil {
		t.Fatal(err)
	}
	op := l.(translog.Operator)
	k, _, err := ceremony.ReadKey(ingestKey, store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := translog.NewLogSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	h, err := op.SignHead(signer, at)
	if err != nil {
		t.Fatal(err)
	}
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	if h.Note, err = note.Sign(&note.Note{Text: string(text)}, append([]note.Signer{signer}, ws...)...); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(h); err != nil {
		t.Fatal(err)
	}
	return h
}

// platformSetup runs init 2-of-2 with one witness, publishes it into a
// new data directory and signs a head at headTime. It returns the
// shares, the pin path, the key directory, the data directory, the head
// and the witness signer.
func platformSetup(t *testing.T, base string) (map[int]string, string, string, string, *translog.Head, note.Signer) {
	t.Helper()
	w1, ws := witnessSigner(t, "w1")
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "go-mail.test/log", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	pinPath := filepath.Join(out, "identity-1.pin")
	dataDir := filepath.Join(base, "data")
	if _, err := store.Init(dataDir); err != nil {
		t.Fatal(err)
	}
	pt := newTTY()
	if code := pt.run("publish", "--from", out, "--data", dataDir, "--pin", pinPath); code != 0 {
		t.Fatal(pt.msgs.String())
	}
	h := signHead(t, dataDir, pinPath, filepath.Join(kd, "ingest-1.key"), headTime, ws)
	return tt.shares, pinPath, kd, dataDir, h, ws
}

// TestSucceedCompromised (D93 (4), RUNBOOK 7.3.5): succeed --compromised
// with the boundary of a witness-confirmed head shows the boundary and
// the clock before the first share is asked, writes identity-2.pub and
// the pin of generation 2 with field 7 and no succession, and names the
// mandatory reissue; admin-rotate and ingest-rotate with the new pin and
// the three publishes in the order of the RUNBOOK go through, a forged
// export of identity 1 does not. Without the boundary it is a usage
// error before the terminal is used; a time after the clock is refused
// before any share is asked.
func TestSucceedCompromised(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	shares, pin1, kd, dataDir, h, _ := platformSetup(t, base)
	N, T := fmt.Sprint(h.Size), fmt.Sprint(h.Time)
	succ := filepath.Join(base, "succ")

	// Usage errors: the terminal is not used.
	for _, args := range [][]string{
		{"succeed", "--pin", pin1, "--out", succ, "--compromised"},
		{"succeed", "--pin", pin1, "--out", succ, "--compromised", "--revoke-at-size", N},
		{"succeed", "--pin", pin1, "--out", succ, "--revoke-at-size", N, "--revoke-at-time", T},
		{"succeed", "--compromised"},
	} {
		tt := newTTY()
		tt.queue = []string{shares[1], shares[2]}
		code := tt.run(args...)
		if code != exitUsage || !strings.Contains(tt.msgs.String(), "--revoke-at") && len(args) > 2 {
			t.Fatalf("%v: %d %s", args, code, tt.msgs.String())
		}
		if len(tt.typed) != 0 || tt.reads != 0 || tt.prompts != 0 || tt.echoOff || tt.flowOff || tt.out.Len() != 0 {
			t.Fatalf("%v: the terminal was used: %q", args, tt.screen.String())
		}
	}
	// A time after the clock (plus the tolerance): refused before any
	// share is asked.
	tt := newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("succeed", "--pin", pin1, "--out", succ, "--compromised", "--revoke-at-size", N,
		"--revoke-at-time", fmt.Sprint(now().Add(translog.MaxClockSkew+time.Millisecond).UnixMilli())); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "after the clock of the ceremony") || len(tt.typed) != 0 {
		t.Fatalf("time after the clock: %d %s", code, tt.msgs.String())
	}
	if _, err := os.Stat(succ); err == nil {
		t.Fatal("export written")
	}

	tt = newTTY()
	tt.queue = []string{shares[2], shares[1]}
	if code := tt.run("succeed", "--pin", pin1, "--out", succ, "--compromised", "--revoke-at-size", N, "--revoke-at-time", T); code != 0 {
		t.Fatalf("succeed --compromised: %d %s", code, tt.msgs.String())
	}
	checkScreen(t, tt.screen.String(), shareLines(shares), 2+1)
	tt.checkConfirm(t)
	msgs := tt.msgs.String()
	// revoked_at_time is the time of the head + 1 ms (D93 addendum).
	hint := fmt.Sprintf("Widerruf: Identitätsgeneration 1 ab Logindex %s und Zeit %d (2026-10-01T12:01:00.001Z). Kopf: Größe %s, \"time %s\" (2026-10-01T12:01:00Z); der Kopf selbst bleibt gültig.", N, h.Time+1, N, T)
	if i, j := strings.Index(msgs, hint), strings.Index(msgs, "Anteil eingeben"); i < 0 || j < i {
		t.Fatalf("no boundary before the first prompt: %q", msgs)
	}
	if i, j := strings.Index(msgs, "Uhr dieses Rechners: 2026-10-01T12:00:00Z; die Zeit des Kopfes"), strings.Index(msgs, "Anteil eingeben"); i < 0 || j < i {
		t.Fatalf("no clock before the first prompt: %q", msgs)
	}
	if strings.Contains(msgs, "valid_from der Nachfolge") {
		t.Fatal("clock of a succession shown")
	}
	if got := listFiles(t, succ); got != "[identity-2.pin platform/identity-2.pub]" {
		t.Fatalf("export %s", got)
	}
	o := tt.out.String()
	pin2 := filepath.Join(succ, "identity-2.pin")
	for _, want := range []string{"ohne Nachfolge; Generation 1 ist widerrufen", "Widerruf im Pin:     Identitätsgeneration 1 ab Logindex " + N,
		"Neuer Pin:           " + pin2, "Pflicht: Admin und Ingest unter Generation 2 neu ausstellen: admin-rotate und ingest-rotate mit --pin " + pin2} {
		if !strings.Contains(o, want) {
			t.Fatalf("output %q lacks %q", o, want)
		}
	}
	p2, err := ceremony.ReadPin(pin2)
	if err != nil || p2.Gen != 2 || len(p2.Identities) != 2 || fmt.Sprint(p2.Revoked) != fmt.Sprintf("[{0 1 %d %d}]", h.Size, h.Time+1) {
		t.Fatalf("pin 2 %+v %v", p2, err)
	}

	// The reissue under generation 2 (RUNBOOK 7.3.5 step 2).
	adm, rot := filepath.Join(base, "adm"), filepath.Join(base, "rot")
	vf := "2026-10-02T00:00:00Z"
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("admin-rotate", "--pin", pin2, "--gen", "2", "--out", adm, "--keys", kd, "--valid-from", vf); code != 0 {
		t.Fatalf("admin-rotate: %d %s", code, tt.msgs.String())
	}
	checkScreen(t, tt.screen.String(), shareLines(shares), 2+1)
	tt.checkConfirm(t)
	if o := tt.out.String(); !strings.Contains(o, "Admin-Generation 2 erzeugt, gültig ab "+vf) || !strings.Contains(o, filepath.Join(kd, "admin-2.key")) ||
		!strings.Contains(o, "ordnet nur bis "+vf) {
		t.Fatalf("admin-rotate output %q", o)
	}
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	// The new ingest generation from the boundary on (D93 addendum): a
	// later valid_from is refused by publish, the cascade revokes ingest
	// 1 (certified by identity 1) at the boundary.
	late := filepath.Join(base, "late")
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("ingest-rotate", "--pin", pin2, "--gen", "2", "--out", late, "--keys", filepath.Join(base, "latekeys"), "--valid-from", vf); code != 0 {
		t.Fatalf("ingest-rotate: %d %s", code, tt.msgs.String())
	}
	// The ceremony takes it, but warns before the first share and names
	// the boundary (spec review 21c Low-1).
	if m := tt.msgs.String(); !strings.Contains(m, "WARNUNG: --valid-from 2026-10-02T00:00:00Z liegt nach der Widerrufszeit") ||
		!strings.Contains(m, "dann --valid-from 2026-10-01T12:01:00.001Z") ||
		strings.Index(m, "WARNUNG") > strings.Index(m, "Anteil eingeben") {
		t.Fatalf("ingest-rotate after the boundary: %s", m)
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", late, "--data", dataDir, "--pin", pin2); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "make it valid from 2026-10-01T12:01:00.001Z") {
		t.Fatalf("publish of a late ingest successor: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("ingest-rotate", "--pin", pin2, "--gen", "2", "--out", rot, "--keys", kd, "--valid-from", "2026-10-01T12:01:00.001Z"); code != 0 ||
		strings.Contains(tt.msgs.String(), "WARNUNG") {
		t.Fatalf("ingest-rotate: %d %s", code, tt.msgs.String())
	}
	// Publish in the order of the RUNBOOK, with the new pin; the old pin
	// does not know generation 2.
	tt = newTTY()
	if code := tt.run("publish", "--from", succ, "--data", dataDir, "--pin", pin1); code != exitFail || !strings.Contains(tt.msgs.String(), "install the new pin") {
		t.Fatalf("old pin: %d %s", code, tt.msgs.String())
	}
	for _, from := range []string{succ, adm, rot} {
		tt = newTTY()
		if code := tt.run("publish", "--from", from, "--data", dataDir, "--pin", pin2); code != 0 {
			t.Fatalf("publish %s: %d %s", from, code, tt.msgs.String())
		}
		if !strings.Contains(tt.out.String(), fmt.Sprintf("Widerrufe des Pins (1) geprüft gegen den neuesten bestätigten Kopf (Größe %d, Zeit %d)", h.Size, h.Time)) {
			t.Fatalf("publish %s: %q", from, tt.out.String())
		}
	}
	if got := logNames(t, dataDir, p2); fmt.Sprint(got) != "[admin-1.cert ingest-1.cert admin-2.cert ingest-2.cert]" {
		t.Fatalf("log %v", got)
	}
	// An admin certificate issued by identity 1 after the boundary (the
	// thief's) is refused, nothing written.
	thief := filepath.Join(base, "thief")
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("admin-rotate", "--pin", pin1, "--gen", "3", "--out", thief, "--keys", filepath.Join(base, "thiefkeys"), "--valid-from", vf); code != 0 {
		t.Fatalf("admin-rotate under identity 1: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", thief, "--data", dataDir, "--pin", pin2); code != exitFail || !strings.Contains(tt.msgs.String(), "which the pin revokes") {
		t.Fatalf("publish of a certificate of identity 1: %d %s", code, tt.msgs.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "platform", "admin-3.cert")); err == nil {
		t.Fatal("written")
	}

	// The library without the boundary: ErrCompromised, nothing asked.
	pin, err := ceremony.ReadPin(pin1)
	if err != nil {
		t.Fatal(err)
	}
	p := &countingPrompter{}
	out3 := filepath.Join(base, "out3")
	if _, err := ceremony.Succeed(ceremony.SucceedOptions{UnlockOptions: ceremony.UnlockOptions{IdentityGen: 1, IdentityPub: pin.Pub, Prompter: p},
		Out: out3, Pin: pin, Compromised: true}); !errors.Is(err, ceremony.ErrCompromised) {
		t.Fatalf("library: %v", err)
	}
	if _, err := os.Stat(out3); err == nil || p.calls != 0 {
		t.Fatal("library: export written or share asked")
	}
}

// TestRevokeCommand (D93 (4), RUNBOOK 7.3.3 and 7.3.4): revoke shows
// the boundary before the first share is asked, writes the new pin of
// the same identity generation under the same name into the export
// directory, refuses a generation revoked already and a time after the
// clock; publish with the new pin checks it against the head of the
// data directory.
func TestRevokeCommand(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	shares, pin1, kd, dataDir, h, ws := platformSetup(t, base)
	N, T := fmt.Sprint(h.Size), fmt.Sprint(h.Time)
	rev := filepath.Join(base, "rev")
	tt := newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", pin1, "--out", rev, "--role", "ingest", "--generation", "1", "--revoke-at-size", N, "--revoke-at-time", T); code != 0 {
		t.Fatalf("revoke: %d %s", code, tt.msgs.String())
	}
	checkScreen(t, tt.screen.String(), shareLines(shares), 2+1)
	tt.checkConfirm(t)
	msgs := tt.msgs.String()
	if i, j := strings.Index(msgs, "Widerruf: Ingest-Generation 1 ab Logindex "+N+" und Zeit "+fmt.Sprint(h.Time+1)+" (2026-10-01T12:01:00.001Z). Kopf: Größe "+N+", \"time "+T+"\""), strings.Index(msgs, "Anteil eingeben"); i < 0 || j < i {
		t.Fatalf("no boundary before the first prompt: %q", msgs)
	}
	if got := listFiles(t, rev); got != "[identity-1.pin]" {
		t.Fatalf("export %s", got)
	}
	revPin := filepath.Join(rev, "identity-1.pin")
	o := tt.out.String()
	if !strings.Contains(o, "Widerruf eingetragen: Ingest-Generation 1 ab Logindex "+N) ||
		!strings.Contains(o, "Neuer Pin:           "+revPin+"  (ersetzt identity-1.pin überall") {
		t.Fatalf("output %q", o)
	}
	p, err := ceremony.ReadPin(revPin)
	if err != nil || p.Gen != 1 || fmt.Sprint(p.Revoked) != fmt.Sprintf("[{2 1 %d %d}]", h.Size, h.Time+1) {
		t.Fatalf("pin %+v %v", p, err)
	}
	old, err := ceremony.ReadPin(pin1)
	if err != nil {
		t.Fatal(err)
	}
	old.Revoked = p.Revoked
	if a, _ := old.Encode(); !bytes.Equal(a, mustRead(t, revPin)) {
		t.Fatal("the new pin is not the old one plus field 7")
	}
	// The same generation again: refused before any share.
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", revPin, "--out", filepath.Join(base, "rev2"), "--role", "ingest", "--generation", "1",
		"--revoke-at-size", "1", "--revoke-at-time", T); code != exitFail || !strings.Contains(tt.msgs.String(), "already revokes") || len(tt.typed) != 0 {
		t.Fatalf("again: %d %s", code, tt.msgs.String())
	}
	// A time in seconds (attack review 21c F2).
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", revPin, "--out", filepath.Join(base, "rev2"), "--role", "admin", "--generation", "1",
		"--revoke-at-size", N, "--revoke-at-time", fmt.Sprint(h.Time/1000)); code != exitFail || !strings.Contains(tt.msgs.String(), "not in seconds") || len(tt.typed) != 0 {
		t.Fatalf("seconds: %d %s", code, tt.msgs.String())
	}
	// A time after the clock.
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", revPin, "--out", filepath.Join(base, "rev2"), "--role", "admin", "--generation", "1",
		"--revoke-at-size", N, "--revoke-at-time", fmt.Sprint(now().Add(time.Hour).UnixMilli())); code != exitFail || len(tt.typed) != 0 {
		t.Fatalf("future: %d %s", code, tt.msgs.String())
	}
	// Admin 1 as well: field 7 with two elements, admin first.
	rev2 := filepath.Join(base, "rev2")
	tt = newTTY()
	tt.queue = []string{shares[2], shares[1]}
	if code := tt.run("revoke", "--pin", revPin, "--out", rev2, "--role", "admin", "--generation", "1", "--revoke-at-size", N, "--revoke-at-time", T); code != 0 {
		t.Fatalf("revoke admin: %d %s", code, tt.msgs.String())
	}
	p2, err := ceremony.ReadPin(filepath.Join(rev2, "identity-1.pin"))
	if err != nil || fmt.Sprint(p2.Revoked) != fmt.Sprintf("[{1 1 %d %d} {2 1 %d %d}]", h.Size, h.Time+1, h.Size, h.Time+1) {
		t.Fatalf("pin %+v %v", p2, err)
	}
	// Before the successor exists, publish with the new pin warns that no
	// ingest generation signs heads from T on.
	tt = newTTY()
	if code := tt.run("publish", "--from", filepath.Join(base, "out"), "--data", dataDir, "--pin", revPin); code != 0 ||
		!strings.Contains(tt.msgs.String(), "WARNUNG: Ingest-Generation 1 ist ab 2026-10-01T12:01:00.001Z widerrufen, ingest-2.cert gibt es noch nicht") {
		t.Fatalf("publish without successor: %d %s", code, tt.msgs.String())
	}
	// The successor in the order of the RUNBOOK (7.3.3): ingest-rotate
	// with the new pin and --valid-from at the boundary, as revoke names
	// it; a time before the boundary is refused before any share.
	if !strings.Contains(o, "Nachfolgerin (Pflicht, ohne Lücke): ingest-rotate --pin "+revPin+" --gen 2 ... --valid-from 2026-10-01T12:01:00.001Z") {
		t.Fatalf("revoke output %q", o)
	}
	rot := filepath.Join(base, "rot")
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("ingest-rotate", "--pin", revPin, "--gen", "2", "--out", rot, "--keys", kd, "--valid-from", "2026-10-01T12:01:00Z"); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "must be revoked_at_time") || len(tt.typed) != 0 {
		t.Fatalf("ingest-rotate before the boundary: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("ingest-rotate", "--pin", revPin, "--gen", "2", "--out", rot, "--keys", kd, "--valid-from", "2026-10-01T12:01:00.001Z"); code != 0 {
		t.Fatalf("ingest-rotate: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", rot, "--data", dataDir, "--pin", revPin); code != 0 ||
		!strings.Contains(tt.out.String(), "Widerrufe des Pins (1) geprüft") || strings.Contains(tt.msgs.String(), "WARNUNG") {
		t.Fatalf("publish: %d %s %s", code, tt.out.String(), tt.msgs.String())
	}
	// No gap: the server signs the next head at the boundary with
	// ingest 2, the operator log with the new pin takes it.
	signHead(t, dataDir, revPin, filepath.Join(kd, "ingest-2.key"), headTime.Add(time.Millisecond), ws)
	tt = newTTY()
	if code := tt.run("publish", "--from", rot, "--data", dataDir, "--pin", revPin); code != 0 {
		t.Fatalf("publish again: %d %s", code, tt.msgs.String())
	}
	// A pin whose boundary lies beyond the head of the data directory.
	rev3 := filepath.Join(base, "rev3")
	tt = newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", pin1, "--out", rev3, "--role", "admin", "--generation", "1", "--revoke-at-size", fmt.Sprint(h.Size+5), "--revoke-at-time", T); code != 0 {
		t.Fatalf("revoke: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", rot, "--data", dataDir, "--pin", filepath.Join(rev3, "identity-1.pin")); code != exitFail ||
		!strings.Contains(tt.msgs.String(), "beyond the newest witness-confirmed head") {
		t.Fatalf("publish with a boundary beyond the head: %d %s", code, tt.msgs.String())
	}
}

// TestPublishRevokedHeadCommand (attack review 21c F3): when the newest
// head carries the log signature of an ingest generation that the pin
// revokes at its time (here the head of the boundary signed again a
// minute later by ingest 1), publish goes on and warns on standard
// error that gomail-server log repair moves it.
func TestPublishRevokedHeadCommand(t *testing.T) {
	fixClock(t)
	base := t.TempDir()
	shares, pin1, kd, dataDir, h, ws := platformSetup(t, base)
	h2 := signHead(t, dataDir, pin1, filepath.Join(kd, "ingest-1.key"), headTime.Add(time.Minute), ws)
	rev := filepath.Join(base, "rev")
	tt := newTTY()
	tt.queue = []string{shares[1], shares[2]}
	if code := tt.run("revoke", "--pin", pin1, "--out", rev, "--role", "ingest", "--generation", "1",
		"--revoke-at-size", fmt.Sprint(h.Size), "--revoke-at-time", fmt.Sprint(h.Time)); code != 0 {
		t.Fatalf("revoke: %d %s", code, tt.msgs.String())
	}
	tt = newTTY()
	if code := tt.run("publish", "--from", filepath.Join(base, "out"), "--data", dataDir, "--pin", filepath.Join(rev, "identity-1.pin")); code != 0 ||
		!strings.Contains(tt.msgs.String(), fmt.Sprintf("WARNUNG: der neueste Kopf (Größe %d, Zeit %d, 2026-10-01T12:02:00Z) trägt die Logsignatur von Ingest-Generation 1, die der Pin ab %d (2026-10-01T12:01:00.001Z) widerruft", h2.Size, h2.Time, h.Time+1)) ||
		!strings.Contains(tt.msgs.String(), "gomail-server log repair") {
		t.Fatalf("publish: %d %s", code, tt.msgs.String())
	}
}
