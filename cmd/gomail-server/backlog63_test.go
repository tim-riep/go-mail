package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// TestAddressAddForgedCert (backlog item 63, D93 addendum 23, AUDIT R48):
// "address add" checks admin-<gen>.cert with the key of its identity_gen
// and against the log before it trusts identity_gen. With identity
// generation 1 revoked (the cascade: it issued admin-1.cert), an
// admin-1.cert rewritten with identity_gen 2 would otherwise pass the
// cascade check; whether its signature is wrong or it is signed validly
// by identity generation 2 of the pin but not in the log, it is refused
// with adminCertInvalid before anything is logged or addresses.json
// changes. So is an admin-1.cert with a wrong signature and the
// unchanged, revoked identity_gen 1: without the signature check it would
// end with adminRevoked and exit status 2. An identity_gen above the pin
// without a logged identity-<g>.succ is refused the same way. The
// message carries the cause after adminCertInvalid (rework F3).
func TestAddressAddForgedCert(t *testing.T) {
	s := newLogSetup(t)
	size := s.treeSize(t)
	now := time.Now().UnixMilli()

	// The pin of identity generation 2 that revokes identity 1
	// (cascadePinFile with a known key for generation 2).
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := *s.p
	p.Gen, p.Pub = 2, pub2
	p.Identities = append(append([]store.PlatformIdentity(nil), s.p.Identities...), store.PlatformIdentity{Gen: 2, Pub: pub2})
	p.Revoked = []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: size, AtTime: now}}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(s.dir, "forged.pin")
	if err := store.WriteFileAtomic(pin, data); err != nil {
		t.Fatal(err)
	}

	orig, err := s.st.ReadPlatformCert(keys.RoleAdmin, 1)
	if err != nil {
		t.Fatal(err)
	}
	if orig.IdentityGen != 1 {
		t.Fatalf("admin-1.cert issued by identity generation %d", orig.IdentityGen)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPath := s.st.Path("platform", store.PlatformFileName("admin", 1, "cert"))
	for _, tc := range []struct {
		name   string
		signer ed25519.PrivateKey
		idGen  uint32
		cause  string
	}{
		{"wrong signature", other, 2, ""},
		{"signed by identity 2, not in the log", priv2, 2, ""},
		{"wrong signature, identity_gen 1 revoked", other, 1, ""},
		{"identity_gen 3 above the pin, no identity-3.succ", priv2, 3, "identity generation 3 not in the log"},
	} {
		forged, err := keys.NewPlatformCert(tc.signer, tc.idGen, keys.RoleAdmin, 1, orig.Pub, orig.ValidFrom)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := forged.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteFileAtomic(certPath, enc); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		args := []string{"address", "add", "info@example.org", "--mailbox", s.mbx.String(), "--data", s.data,
			"--admin-key", filepath.Join(s.keys, ceremony.AdminKeyFile), "--pin", pin}
		code := run(context.Background(), args, &out, &errb, nil)
		msg := errb.String()
		if code != 1 || !strings.Contains(msg, "gomail-server: "+adminCertInvalid+": ") || !strings.Contains(msg, tc.cause) {
			t.Fatalf("%s: exit status %d: %q", tc.name, code, msg)
		}
		if n := s.treeSize(t); n != size {
			t.Fatalf("%s: logged: %d entries, before %d", tc.name, n, size)
		}
		if a, err := s.st.LoadAddresses(); err != nil || len(a) != 0 {
			t.Fatalf("%s: addresses.json: %v %v", tc.name, a, err)
		}
	}
}
