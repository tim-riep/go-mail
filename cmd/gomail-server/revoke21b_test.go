package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// revokedPinFile writes the pin of s with field 7 set to rev into a file
// outside the data directory (D93) and returns its path.
func revokedPinFile(t *testing.T, s *logSetup, rev ...store.PlatformRevoked) string {
	t.Helper()
	p := *s.p
	p.Revoked = rev
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, "revoked.pin")
	if err := store.WriteFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	return path
}

// cascadePinFile writes a pin of identity generation 2 (identity list 1
// and 2, a fresh key for 2) that revokes identity generation 1 at (size,
// at), the issuer of admin-1.cert and ingest-1.cert: the pin after
// "succeed --compromised" of identity 1 before admin and ingest are
// reissued (D93 (4) and the cascade of its addendum on task 21a).
func cascadePinFile(t *testing.T, s *logSetup, size, at int64) string {
	t.Helper()
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := *s.p
	p.Gen, p.Pub = 2, pub2
	p.Identities = append(append([]store.PlatformIdentity(nil), s.p.Identities...), store.PlatformIdentity{Gen: 2, Pub: pub2})
	p.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: size, AtTime: at}}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, "cascade.pin")
	if err := store.WriteFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	return path
}

// hasLine reports whether out ends with the line "gomail-server: msg".
func hasLine(out, msg string) bool {
	return out == "gomail-server: "+msg+"\n" || strings.HasSuffix(out, "\ngomail-server: "+msg+"\n")
}

// TestServeRevoked (task 21b, D93): serve reads field 7 of --pin and
// refuses an ingest key of a generation the pin revokes with exit status
// 2 and the fixed message ingestRevoked, leaving no server lock behind;
// so it does when the pin revokes identity generation 1, which issued
// ingest-1.cert (the cascade, ingest.New); a pin that revokes another
// generation (admin 1) does not stop it.
func TestServeRevoked(t *testing.T) {
	s := newLogSetup(t)
	size := s.treeSize(t)
	now := time.Now().UnixMilli()
	args := func(pin string) []string {
		return []string{"serve", "--data", s.data, "--listen", "127.0.0.1:0", "--ingest-key", filepath.Join(s.keys, ceremony.IngestKeyFile),
			"--pin", pin, "--log-listen", "127.0.0.1:0"}
	}
	for _, pin := range []string{
		revokedPinFile(t, s, store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: size, AtTime: now}),
		cascadePinFile(t, s, size, now),
	} {
		var out, errb bytes.Buffer
		if code := run(context.Background(), args(pin), &out, &errb, nil); code != 2 || !hasLine(errb.String(), ingestRevoked) {
			t.Fatalf("%s: exit status %d: %q", filepath.Base(pin), code, errb.String())
		}
		release, err := s.st.HoldRoleLock(store.RoleServer)
		if err != nil {
			t.Fatalf("%s: server lock left behind: %v", filepath.Base(pin), err)
		}
		release()
	}

	pin := revokedPinFile(t, s, store.PlatformRevoked{Role: store.KeyRoleAdmin, Gen: 1, AtSize: size, AtTime: now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan int, 1)
	var sout, serr lockedBuffer
	go func() { done <- run(ctx, args(pin), &sout, &serr, func(string, string) { close(ready) }) }()
	select {
	case <-ready:
	case code := <-done:
		t.Fatalf("serve with admin 1 revoked ended: %d %s", code, serr.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve stopped with %d: %s", code, serr.String())
	}
}

// TestAddressAddRevoked (task 21b, D93): "address add" refuses an admin
// key of a generation the pin revokes, and one whose certificate a
// revoked identity generation issued (the cascade: admin-1.cert is
// issued by identity 1), with exit status 2 and the fixed message
// adminRevoked, before anything is logged or addresses.json changes;
// "log repair" opens the log with the same pin.
func TestAddressAddRevoked(t *testing.T) {
	s := newLogSetup(t)
	size := s.treeSize(t)
	now := time.Now().UnixMilli()
	var out, errb bytes.Buffer
	var pin string
	for _, pin = range []string{
		cascadePinFile(t, s, size, now),
		revokedPinFile(t, s, store.PlatformRevoked{Role: store.KeyRoleAdmin, Gen: 1, AtSize: size, AtTime: now}),
	} {
		out.Reset()
		errb.Reset()
		args := []string{"address", "add", "info@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
			"--admin-key", filepath.Join(s.keys, ceremony.AdminKeyFile), "--pin", pin}
		if code := run(context.Background(), args, &out, &errb, nil); code != 2 || !hasLine(errb.String(), adminRevoked) {
			t.Fatalf("%s: exit status %d: %q", filepath.Base(pin), code, errb.String())
		}
		if strings.Contains(errb.String(), "info@") {
			t.Fatalf("%s: the message names the address: %q", filepath.Base(pin), errb.String())
		}
		if n := s.treeSize(t); n != size {
			t.Fatalf("%s: logged: %d entries, before %d", filepath.Base(pin), n, size)
		}
		if a, err := s.st.LoadAddresses(); err != nil || len(a) != 0 {
			t.Fatalf("%s: addresses.json: %v %v", filepath.Base(pin), a, err)
		}
	}
	out.Reset()
	errb.Reset()
	if code := run(context.Background(), []string{"log", "repair", "--data", s.data, "--pin", pin}, &out, &errb, nil); code != 0 {
		t.Fatalf("log repair with field 7: %d %s", code, errb.String())
	}
}

// TestLogRepairRevokedHeads (task 21b, D93): a head that ingest
// generation 1 signed at or after the revoked_at_time pin field 7 gives
// it stops the log (translog.ErrRevokedHead); "log repair" with that pin
// moves it to log/heads-revoked/, names it and its new place on standard
// output, counts it, and a second repair moves nothing.
func TestLogRepairRevokedHeads(t *testing.T) {
	s := newLogSetup(t)
	key, _, err := ceremony.ReadKey(filepath.Join(s.keys, ceremony.IngestKeyFile), store.KeyRoleIngest)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe(key)
	signer, err := translog.NewLogSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.operator(t).SignHead(signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text, err := h.Text()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	from := translog.HeadPath(h.Size)
	if err := store.WriteFileAtomic(filepath.Join(s.data, filepath.FromSlash(from)), msg); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var out, errb bytes.Buffer
	// Without field 7 the head is valid and stays.
	if code := run(ctx, []string{"log", "repair", "--data", s.data, "--pin", s.pin}, &out, &errb, nil); code != 0 ||
		!strings.HasSuffix(out.String(), "0 verwaiste Einträge gemeldet, 0 verworfen; 0 Köpfe einer widerrufenen Generation nach log/heads-revoked verschoben\n") {
		t.Fatalf("repair without field 7: %d %q %s", code, out.String(), errb.String())
	}
	pin := revokedPinFile(t, s, store.PlatformRevoked{Role: store.KeyRoleIngest, Gen: 1, AtSize: h.Size, AtTime: h.Time})
	out.Reset()
	if code := run(ctx, []string{"log", "repair", "--data", s.data, "--pin", pin}, &out, &errb, nil); code != 0 {
		t.Fatalf("repair: %d %s", code, errb.String())
	}
	to := translog.RevokedHeadPath(h.Size, sha256.Sum256(msg))
	want := from + " von einer widerrufenen Generation signiert (Pin-Feld 7), verschoben nach " + to + "\n" +
		"log/tree.rec, Kacheln und keys/ aus den Einträgen und Köpfen neu gebaut; 0 verwaiste Einträge gemeldet, 0 verworfen; " +
		"1 Köpfe einer widerrufenen Generation nach log/heads-revoked verschoben\n"
	if out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	if got, err := os.ReadFile(filepath.Join(s.data, filepath.FromSlash(to))); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("moved head: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.data, filepath.FromSlash(from))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("head left in heads/: %v", err)
	}
	out.Reset()
	if code := run(ctx, []string{"log", "repair", "--data", s.data, "--pin", pin}, &out, &errb, nil); code != 0 || strings.Contains(out.String(), "verschoben nach") {
		t.Fatalf("second repair: %d %q", code, out.String())
	}
}
