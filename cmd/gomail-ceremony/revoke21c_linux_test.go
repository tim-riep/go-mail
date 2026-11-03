//go:build linux && !ceremony_notty

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
)

// revocationCommands returns the commands of task 21c that read shares
// (admin-rotate, revoke, succeed --compromised) for the pin pinPath,
// writing below base; shareCommands lists them with the others.
func revocationCommands(base, pinPath string) [][]string {
	validFrom := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	at := fmt.Sprint(time.Now().Add(-time.Minute).UnixMilli())
	return [][]string{
		{"admin-rotate", "--pin", pinPath, "--gen", "2", "--out", filepath.Join(base, "o2"), "--keys", filepath.Join(base, "k2"), "--valid-from", validFrom},
		{"revoke", "--pin", pinPath, "--out", filepath.Join(base, "o2"), "--role", "ingest", "--generation", "1", "--revoke-at-size", "2", "--revoke-at-time", at},
		{"succeed", "--pin", pinPath, "--out", filepath.Join(base, "o2"), "--compromised", "--revoke-at-size", "2", "--revoke-at-time", at},
	}
}

// TestPTYRevocation (task 21c): admin-rotate, revoke and succeed
// --compromised on a pseudo terminal follow the terminal rules: the
// shares are typed with the echo off and cleared before the next holder
// and the end, the boundary of a revocation is on the screen before the
// first share is asked, the terminal modes are restored; Ctrl-C while a
// share is typed ends each of them with exit code 130, the screen
// cleared, nothing written.
func TestPTYRevocation(t *testing.T) {
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	tt := newTTY()
	if code := tt.run("init", "--shares", "2-of-3", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o", "--witness", w1, "--min-witnesses", "1"); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	shares := tt.shares
	pinPath := filepath.Join(out, "identity-1.pin")
	for i, args := range revocationCommands(base, pinPath) {
		// Ctrl-C in the middle of the first share typed.
		p := openPTY(t)
		p.start(nil, nil, args...)
		if m := p.next(regexp.MustCompile(`Anteil eingeben[^\n]*\n`)); m == nil {
			t.Fatalf("%s: no prompt\n%s", args[0], p.output())
		}
		screen := p.output()
		if args[0] != "admin-rotate" && !strings.Contains(screen, "Widerruf: ") {
			t.Fatalf("%s: no boundary before the first prompt: %q", args[0], screen)
		}
		p.quietInput()
		ws := strings.Fields(shares[1])
		p.typed = append(p.typed, typing{off: len(p.output()), lines: []string{strings.Join(ws[:12], " ")}})
		p.send(strings.Join(ws[:12], " ") + "\n")
		p.next(regexp.MustCompile(`\(12 von 30 Wörtern\)`))
		p.send("\x03\n")
		if code := p.wait(); code != exitAbort {
			t.Fatalf("%s: exit code %d\n%s", args[0], code, p.output())
		}
		screen = p.checkShares(len(p.typed) + 1)
		if !strings.HasSuffix(strings.TrimSpace(screen), "abgebrochen") {
			t.Fatalf("%s: end of screen %q", args[0], screen[max(0, len(screen)-200):])
		}
		for _, d := range []string{"o2", "k2"} {
			if _, err := os.Lstat(filepath.Join(base, d)); err == nil {
				t.Fatalf("%s: %s written", args[0], d)
			}
		}

		// The whole command.
		p = openPTY(t)
		p.start(nil, nil, args...)
		p.converse([]string{shares[3-i%2], shares[1]})
		if code := p.wait(); code != 0 {
			t.Fatalf("%s: %d\n%s", args[0], code, p.output())
		}
		screen = p.check()
		if len(p.typed) != 2 {
			t.Fatalf("%s: %d typed", args[0], len(p.typed))
		}
		last := strings.LastIndex(screen, clearScreen)
		want := map[string]string{"admin-rotate": "Admin-Generation 2 erzeugt", "revoke": "Widerruf eingetragen: Ingest-Generation 1",
			"succeed": "Identitätsgeneration 2 erzeugt, ohne Nachfolge"}[args[0]]
		if !strings.Contains(screen[last:], want) {
			t.Fatalf("%s: results not after the last clear: %q", args[0], screen[last:])
		}
		t.Logf("%s: %d typed, %d clears", args[0], len(p.typed), strings.Count(screen, clearScreen))
		os.RemoveAll(filepath.Join(base, "o2"))
		os.RemoveAll(filepath.Join(base, "k2"))
	}
	if _, err := ceremony.ReadPin(pinPath); err != nil {
		t.Fatal(err)
	}
}
