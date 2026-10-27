package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

func testRecoveryPub(t *testing.T, b byte) *RecoveryPub {
	t.Helper()
	seed := keys.Seed{b}
	d := keys.DeriveUser(&seed)
	defer d.Zero()
	id, err := d.IdentityKey(RecoveryGen)
	if err != nil {
		t.Fatal(err)
	}
	uw, err := d.UnwrapKey(RecoveryGen)
	if err != nil {
		t.Fatal(err)
	}
	return &RecoveryPub{ID: ID{b, 9}, UnwrapPub: uw.PublicKey(), IdentityPub: id.Public().(ed25519.PublicKey)}
}

func TestRecoveryPubRoundTrip(t *testing.T) {
	p := testRecoveryPub(t, 1)
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	q, err := DecodeRecoveryPub(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := q.Encode()
	if !bytes.Equal(data, again) || q.ID != p.ID || !q.UnwrapPub.Equal(p.UnwrapPub) || !q.IdentityPub.Equal(p.IdentityPub) {
		t.Fatal("round trip")
	}
	if !bytes.HasPrefix(data, []byte("gomail/v1/rec/recovery-pub\x00")) {
		t.Fatal("type string")
	}
	fp, err := p.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	groups := strings.Split(fp, " ")
	if len(groups) != 8 || strings.Join(groups, "") != hex.EncodeToString(h[:]) {
		t.Fatalf("fingerprint %q", fp)
	}
	for _, g := range groups {
		if len(g) != 8 {
			t.Fatalf("group %q", g)
		}
	}
}

func TestRecoveryPubRejected(t *testing.T) {
	p := testRecoveryPub(t, 2)
	zeroX, _ := ecdh.X25519().NewPublicKey(make([]byte, 32))
	for name, bad := range map[string]*RecoveryPub{
		"nil":           nil,
		"zero id":       {UnwrapPub: p.UnwrapPub, IdentityPub: p.IdentityPub},
		"no unwrap":     {ID: p.ID, IdentityPub: p.IdentityPub},
		"zero unwrap":   {ID: p.ID, UnwrapPub: zeroX, IdentityPub: p.IdentityPub},
		"short ident":   {ID: p.ID, UnwrapPub: p.UnwrapPub, IdentityPub: p.IdentityPub[:31]},
		"zero identity": {ID: p.ID, UnwrapPub: p.UnwrapPub, IdentityPub: make([]byte, 32)},
	} {
		if _, err := bad.Encode(); !errors.Is(err, ErrRecovery) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := bad.Fingerprint(); err == nil {
			t.Fatalf("%s: fingerprint", name)
		}
	}
	// Decoding: zero keys, wrong lengths, unknown fields.
	enc := func(id, uw, ident []byte) []byte {
		b, _ := rec.New(RecoveryPubSchema).SetBytes(1, id).SetBytes(2, uw).SetBytes(3, ident).Encode()
		return b
	}
	cases := map[string][]byte{
		"zero id":       enc(make([]byte, 16), p.UnwrapPub.Bytes(), p.IdentityPub),
		"zero unwrap":   enc(p.ID[:], make([]byte, 32), p.IdentityPub),
		"zero identity": enc(p.ID[:], p.UnwrapPub.Bytes(), make([]byte, 32)),
		"short unwrap":  enc(p.ID[:], p.UnwrapPub.Bytes()[:31], p.IdentityPub),
		"junk":          []byte("gomail/v1/rec/recovery-pub\x00junk"),
		"other type":    []byte("gomail/v1/rec/epoch\x00"),
	}
	for name, data := range cases {
		if _, err := DecodeRecoveryPub(data); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRecoveryFiles(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mbx := ID{5}
	p := testRecoveryPub(t, 3)
	if _, _, err := s.ReadRecoveryPub(mbx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.WriteRecoveryPub(mbx, p); err != nil {
		t.Fatal(err)
	}
	// The same record again is kept, another one is never written over it.
	if err := s.WriteRecoveryPub(mbx, p); err != nil {
		t.Fatal(err)
	}
	other := testRecoveryPub(t, 4)
	other.ID = p.ID
	if err := s.WriteRecoveryPub(mbx, other); !errors.Is(err, ErrExists) {
		t.Fatalf("replaced: %v", err)
	}
	if err := s.WriteRecoveryPub(mbx, &RecoveryPub{}); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	q, raw, err := s.ReadRecoveryPub(mbx, p.ID)
	if err != nil || q.ID != p.ID || !q.UnwrapPub.Equal(p.UnwrapPub) {
		t.Fatal(err)
	}
	if fp, _ := p.Fingerprint(); FingerprintOf(raw) != fp {
		t.Fatal("fingerprint of the file")
	}
	// A file under another recipient's name is rejected.
	moved := testRecoveryPub(t, 6)
	data, _ := moved.Encode()
	MkdirAll(s.MailboxDir(mbx))
	os.WriteFile(s.RecoveryPubFile(mbx, ID{7}), data, 0o600)
	if _, _, err := s.ReadRecoveryPub(mbx, ID{7}); !errors.Is(err, ErrRecovery) {
		t.Fatalf("moved file: %v", err)
	}
	os.WriteFile(s.RecoveryPubFile(mbx, ID{8}), []byte("junk"), 0o600)
	if _, _, err := s.ReadRecoveryPub(mbx, ID{8}); err == nil {
		t.Fatal("junk accepted")
	}

	// recovery.wrap: created once, never replaced, removed durably.
	if err := s.CreateRecoveryWrap(mbx, 3, []byte("w1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRecoveryWrap(mbx, 3, []byte("w2")); !errors.Is(err, ErrExists) {
		t.Fatalf("replaced wrap: %v", err)
	}
	if b, err := s.ReadRecoveryWrap(mbx, 3); err != nil || string(b) != "w1" {
		t.Fatal(err)
	}
	if !strings.HasSuffix(s.RecoveryWrapFile(mbx, 3), "/epochs/3/members/recovery.wrap") {
		t.Fatal(s.RecoveryWrapFile(mbx, 3))
	}
	if err := s.RemoveRecoveryWrap(mbx, 3); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRecoveryWrap(mbx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecoveryWrap(mbx, 3); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
