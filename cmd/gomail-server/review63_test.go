package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Tests of task 24, package C, for the two low points the review of the
// patch series of backlog item 63 left open.

// writeAdminKey writes the private admin key priv of generation gen
// into a new file outside the data directory of s and returns its path.
func writeAdminKey(t *testing.T, s *logSetup, gen uint32, priv ed25519.PrivateKey) string {
	t.Helper()
	data, err := store.EncodePlatformKey(store.KeyRoleAdmin, gen, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, fmt.Sprintf("admin-%d-%x.key", gen, []byte(priv.Public().(ed25519.PublicKey))[:4]))
	if err := store.CreatePrivateFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAddressAddCertReadCause (low point 2): when admin-<gen>.cert
// cannot be read together with its .pub, "address add" gives the cause
// after adminKeyMismatch, as it does after adminCertInvalid; for an
// admin key that the readable certificate does not certify there is no
// cause. Nothing is logged, and no message names the address.
func TestAddressAddCertReadCause(t *testing.T) {
	s := newLogSetup(t)
	size := s.treeSize(t)
	pubPath := s.st.Path("platform", store.PlatformFileName("admin", 1, "pub"))
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		pub   []byte // nil: removed
		cause string
	}{
		{"admin-1.pub missing", nil, "admin-1.pub"},
		{"admin-1.pub of another key", other, "admin-1.pub differs from its certificate"},
	} {
		if err := os.Remove(pubPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		if tc.pub != nil {
			if err := store.WriteFileAtomic(pubPath, tc.pub); err != nil {
				t.Fatal(err)
			}
		}
		code, msg := s.addAt(t, "cause@example.org", time.Now().UnixMilli())
		if code != 1 || !strings.Contains(msg, "gomail-server: "+adminKeyMismatch+": ") ||
			!strings.Contains(msg, tc.cause) || strings.Contains(msg, "example.org") {
			t.Fatalf("%s: exit status %d: %q", tc.name, code, msg)
		}
		if n := s.treeSize(t); n != size {
			t.Fatalf("%s: logged: %d entries, before %d", tc.name, n, size)
		}
	}
	if err := store.WriteFileAtomic(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	// Another admin key of generation 1: the certificate is read, it
	// certifies another key, the fixed message has no cause.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"address", "add", "cause@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
		"--admin-key", writeAdminKey(t, s, 1, priv), "--pin", s.pin}
	var out, errb bytes.Buffer
	if code := run(context.Background(), args, &out, &errb, nil); code != 1 || !hasLine(errb.String(), adminKeyMismatch) {
		t.Fatalf("other admin key: exit status %d: %q", code, errb.String())
	}
	if n := s.treeSize(t); n != size {
		t.Fatalf("other admin key: logged: %d entries, before %d", n, size)
	}
}

// TestAddressAddIdentitySuccession (low point 1, rest of F2):
// identityKey takes the key of an identity generation above the pin's
// identity list from the valid succession in the log. Under a pin with
// identities 1 and 2, identity-3.succ signed by identity 2 and
// admin-2.cert signed by identity 3 are logged; "address add" with the
// admin key of generation 2 verifies admin-2.cert with the key of
// identity 3 and assigns.
func TestAddressAddIdentitySuccession(t *testing.T) {
	s := newLogSetup(t)
	now := time.Now().UnixMilli()
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub3, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPub, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := *s.p
	p.Gen, p.Pub = 2, pub2
	p.Identities = append(append([]store.PlatformIdentity(nil), s.p.Identities...), store.PlatformIdentity{Gen: 2, Pub: pub2})
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(s.dir, "identity-2.pin")
	if err := store.WriteFileAtomic(pin, data); err != nil {
		t.Fatal(err)
	}
	l, err := translog.Open(translog.Options{Store: s.st, Origin: p.Origin,
		Identities: []translog.Identity{{Gen: 1, Pub: s.p.Pub}, {Gen: 2, Pub: pub2}}})
	if err != nil {
		t.Fatal(err)
	}
	op := l.(translog.Operator)
	sc, err := keys.NewPlatformSuccession(priv2, 3, pub3, now-60_000)
	if err != nil {
		t.Fatal(err)
	}
	scEnc, err := sc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.NewPlatformCert(priv3, 3, keys.RoleAdmin, 2, adminPub, now-60_000)
	if err != nil {
		t.Fatal(err)
	}
	certEnc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name   string
		data   []byte
		logged bool // a .pub is not logged
	}{
		{store.PlatformFileName("identity", 3, "succ"), scEnc, true},
		{store.PlatformFileName("admin", 2, "cert"), certEnc, true},
		{store.PlatformFileName("admin", 2, "pub"), adminPub, false},
	} {
		if f.logged {
			if err := op.AppendPlatform(f.name, f.data); err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
		}
		if err := store.WriteFileAtomic(s.st.Path("platform", f.name), f.data); err != nil {
			t.Fatal(err)
		}
	}
	setAddressClock(t, now)
	args := []string{"address", "add", "succ@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
		"--admin-key", writeAdminKey(t, s, 2, adminPriv), "--pin", pin}
	var out, errb bytes.Buffer
	if code := run(context.Background(), args, &out, &errb, nil); code != 0 {
		t.Fatalf("exit status %d: %q", code, errb.String())
	}
	es, err := op.Lookup(translog.KindAddress, []byte("succ@example.org"))
	if err != nil || len(es) != 1 {
		t.Fatalf("logged: %d %v", len(es), err)
	}
	a, err := store.DecodeAddressAssignment(es[0].Content)
	if err != nil || a.AdminGen != 2 || a.ValidFrom != now || a.MailboxID != s.mbx {
		t.Fatalf("assignment %+v %v", a, err)
	}
}
