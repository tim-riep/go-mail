package keys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecodeEnforcesStructuralRules: a record that is canonically
// encoded but breaks a structural rule of 2.2 or 2.3 is rejected by the
// decoder itself, before any signature is checked. The records are built
// with toRecord, which bypasses the checks of the constructors and of
// Encode, as a forger with a hand-written encoder would.
func TestDecodeEnforcesStructuralRules(t *testing.T) {
	u, root := testUser(t, 11)
	c1 := genCert(t, u, root, 1)
	c3 := genCert(t, u, root, 3)
	gen := func(f func(c *GenerationCert)) []byte {
		c := *c1
		f(&c)
		b, err := c.toRecord(true).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var seed Seed
	seed[0] = 12
	p := DerivePlatform(&seed)
	idKey, _ := p.IdentityKey(1)
	ingest, _ := p.IngestKey(1)
	pc, err := NewPlatformCert(idKey, 1, RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 1_761_400_000_000)
	if err != nil {
		t.Fatal(err)
	}
	plat := func(withSig bool, f func(c *PlatformCert)) []byte {
		c := *pc
		f(&c)
		b, err := c.toRecord(withSig).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	id2, _ := p.IdentityKey(2)
	sc, err := NewPlatformSuccession(idKey, 2, id2.Public().(ed25519.PublicKey), 5)
	if err != nil {
		t.Fatal(err)
	}
	succ := func(withSig bool, f func(s *PlatformSuccession)) []byte {
		s := *sc
		f(&s)
		b, err := s.toRecord(withSig).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cases := []struct {
		name   string
		decode func() error
		want   error
	}{
		{"generation 0", func() error { _, err := DecodeGenerationCert(gen(func(c *GenerationCert) { c.Gen = 0 })); return err }, ErrGeneration},
		{"generation 1 revoking 1", func() error {
			_, err := DecodeGenerationCert(gen(func(c *GenerationCert) { c.Revokes = 1 }))
			return err
		}, ErrGeneration},
		{"generation 3 revoking 1", func() error {
			_, err := DecodeGenerationCert(gen(func(c *GenerationCert) { c.Gen = 3; c.Revokes = 1; c.Signature = c3.Signature }))
			return err
		}, ErrGeneration},
		{"generation 3 revoking nothing", func() error {
			_, err := DecodeGenerationCert(gen(func(c *GenerationCert) { c.Gen = 3 }))
			return err
		}, ErrGeneration},
		{"platform cert without signature", func() error { _, err := DecodePlatformCert(plat(false, func(*PlatformCert) {})); return err }, ErrCert},
		{"platform cert role 0", func() error {
			_, err := DecodePlatformCert(plat(true, func(c *PlatformCert) { c.Role = 0 }))
			return err
		}, ErrCert},
		{"platform cert role 3", func() error {
			_, err := DecodePlatformCert(plat(true, func(c *PlatformCert) { c.Role = 3 }))
			return err
		}, ErrCert},
		{"platform cert generation 0", func() error {
			_, err := DecodePlatformCert(plat(true, func(c *PlatformCert) { c.Gen = 0 }))
			return err
		}, ErrGeneration},
		{"platform cert identity generation 0", func() error {
			_, err := DecodePlatformCert(plat(true, func(c *PlatformCert) { c.IdentityGen = 0 }))
			return err
		}, ErrGeneration},
		{"succession without signature", func() error {
			_, err := DecodePlatformSuccession(succ(false, func(*PlatformSuccession) {}))
			return err
		}, ErrCert},
		{"succession to generation 1", func() error {
			_, err := DecodePlatformSuccession(succ(true, func(s *PlatformSuccession) { s.Gen = 1 }))
			return err
		}, ErrGeneration},
		{"succession to generation 0", func() error {
			_, err := DecodePlatformSuccession(succ(true, func(s *PlatformSuccession) { s.Gen = 0 }))
			return err
		}, ErrGeneration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.decode(); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
	// Sanity: the untouched records decode.
	if _, err := DecodeGenerationCert(gen(func(*GenerationCert) {})); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlatformCert(plat(true, func(*PlatformCert) {})); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlatformSuccession(succ(true, func(*PlatformSuccession) {})); err != nil {
		t.Fatal(err)
	}
}

// TestEncodeAndVerifyRefuseInvalid: Encode never writes an invalid or
// unsigned record, Verify checks the structure before the signature (an
// invalid record is reported as such, not as a bad signature), and nil
// receivers are rejected without panicking.
func TestEncodeAndVerifyRefuseInvalid(t *testing.T) {
	var seed Seed
	seed[0] = 13
	p := DerivePlatform(&seed)
	idKey, _ := p.IdentityKey(1)
	idPub := idKey.Public().(ed25519.PublicKey)
	ingest, _ := p.IngestKey(1)
	pc, err := NewPlatformCert(idKey, 1, RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 1)
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := p.IdentityKey(2)
	sc, err := NewPlatformSuccession(idKey, 2, id2.Public().(ed25519.PublicKey), 5)
	if err != nil {
		t.Fatal(err)
	}

	unsignedPC := *pc
	unsignedPC.Signature = nil
	if b, err := unsignedPC.Encode(); !errors.Is(err, ErrCert) || b != nil {
		t.Fatalf("unsigned platform cert encoded: %v", err)
	}
	badRole := *pc
	badRole.Role = 7
	if b, err := badRole.Encode(); !errors.Is(err, ErrCert) || b != nil {
		t.Fatalf("platform cert with unknown role encoded: %v", err)
	}
	if err := badRole.Verify(idPub); !errors.Is(err, ErrCert) || errors.Is(err, ErrSignature) {
		t.Fatalf("Verify must report the structure, got %v", err)
	}

	unsignedSC := *sc
	unsignedSC.Signature = sc.Signature[:10]
	if b, err := unsignedSC.Encode(); !errors.Is(err, ErrCert) || b != nil {
		t.Fatalf("succession with a short signature encoded: %v", err)
	}
	badGen := *sc
	badGen.Gen = 1
	if b, err := badGen.Encode(); !errors.Is(err, ErrGeneration) || b != nil {
		t.Fatalf("succession to generation 1 encoded: %v", err)
	}
	if err := badGen.Verify(idPub, 0); !errors.Is(err, ErrGeneration) || errors.Is(err, ErrSignature) {
		t.Fatalf("Verify must report the structure, got %v", err)
	}

	var nilGen *GenerationCert
	var nilPC *PlatformCert
	var nilSC *PlatformSuccession
	if _, err := nilGen.Encode(); !errors.Is(err, ErrCert) {
		t.Fatalf("nil generation cert: %v", err)
	}
	if err := nilGen.Verify(idPub); !errors.Is(err, ErrCert) {
		t.Fatalf("nil generation cert: %v", err)
	}
	if _, err := nilPC.Encode(); !errors.Is(err, ErrCert) {
		t.Fatalf("nil platform cert: %v", err)
	}
	if err := nilPC.Verify(idPub); !errors.Is(err, ErrCert) {
		t.Fatalf("nil platform cert: %v", err)
	}
	if _, err := nilSC.Encode(); !errors.Is(err, ErrCert) {
		t.Fatalf("nil succession: %v", err)
	}
	if err := nilSC.Verify(idPub, 1); !errors.Is(err, ErrCert) {
		t.Fatalf("nil succession: %v", err)
	}
	if err := VerifyGenerationChain(idPub, []*GenerationCert{nil}); err == nil {
		t.Fatal("chain with a nil certificate accepted")
	}
}

// TestSigningRequiresAValidKey: a platform certificate or succession is
// never created with a malformed private key; the error says so and no
// record is returned.
func TestSigningRequiresAValidKey(t *testing.T) {
	var seed Seed
	seed[0] = 14
	p := DerivePlatform(&seed)
	idKey, _ := p.IdentityKey(1)
	ingest, _ := p.IngestKey(1)
	id2, _ := p.IdentityKey(2)
	for _, bad := range []ed25519.PrivateKey{nil, idKey[:32], append(append([]byte(nil), idKey...), 0)} {
		if c, err := NewPlatformCert(bad, 1, RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 1); !errors.Is(err, ErrSignature) || c != nil {
			t.Fatalf("platform cert with a %d-byte key: %v", len(bad), err)
		}
		if s, err := NewPlatformSuccession(bad, 2, id2.Public().(ed25519.PublicKey), 1); !errors.Is(err, ErrSignature) || s != nil {
			t.Fatalf("succession with a %d-byte key: %v", len(bad), err)
		}
	}
}

// TestNilInputsFailClosed: derivation from a nil seed, the words of a nil
// seed and sealing a nil key store return errors instead of panicking or
// producing keys; zeroing a nil key store is a no-op.
func TestNilInputsFailClosed(t *testing.T) {
	u := DeriveUser(nil)
	if k, err := u.RootKey(); err == nil || k != nil {
		t.Fatal("root key derived from a nil seed")
	}
	if k, err := u.IdentityKey(1); err == nil || k != nil {
		t.Fatal("identity key derived from a nil seed")
	}
	if k, err := u.UnwrapKey(1); err == nil || k != nil {
		t.Fatal("unwrap key derived from a nil seed")
	}
	p := DerivePlatform(nil)
	for _, f := range []func(uint32) (ed25519.PrivateKey, error){p.IdentityKey, p.AdminKey, p.IngestKey} {
		if k, err := f(1); err == nil || k != nil {
			t.Fatal("platform key derived from a nil seed")
		}
	}
	var s *Seed
	if w, err := s.Words(); err == nil || w != nil {
		t.Fatal("words of a nil seed")
	}
	var k *Keystore
	if b, err := k.Seal([]byte("pw"), nil); !errors.Is(err, ErrKeystore) || b != nil {
		t.Fatalf("nil key store sealed: %v", err)
	}
	k.Zero()
}

// TestWordLookupBounds: LookupWord and Word reject inputs outside the
// list (empty, longer than any BIP-39 word, prefixes, indices out of
// range) and agree with each other at both ends of the list.
func TestWordLookupBounds(t *testing.T) {
	for _, w := range []string{"", "abandonx", "abandonxx", "zoo\x00", "aban", "ABANDON", strings.Repeat("a", 100)} {
		if i, ok := LookupWord(w); ok {
			t.Fatalf("%q found at %d", w, i)
		}
	}
	for _, i := range []int{-1, -2048, 2048, 2049, 1 << 30} {
		if w, ok := Word(i); ok || w != "" {
			t.Fatalf("Word(%d) = %q", i, w)
		}
	}
	for _, i := range []int{0, 1, 2046, 2047} {
		w, ok := Word(i)
		if !ok {
			t.Fatalf("Word(%d) missing", i)
		}
		if j, ok := LookupWord(w); !ok || j != i {
			t.Fatalf("LookupWord(Word(%d)) = %d, %v", i, j, ok)
		}
	}
	if w, _ := Word(0); w != "abandon" {
		t.Fatalf("first word %q", w)
	}
	if w, _ := Word(2047); w != "zoo" {
		t.Fatalf("last word %q", w)
	}
}

// TestKeystoreSealNeedsNonceRandomness: randomness that suffices for the
// salt but not for the nonce aborts sealing; nothing is returned.
func TestKeystoreSealNeedsNonceRandomness(t *testing.T) {
	k := testKeystore(t)
	if b, err := k.seal([]byte("pw"), bytes.NewReader(make([]byte, 16+11)), DefaultKDFParams, fastKDF); err == nil || b != nil {
		t.Fatal("sealing with a short nonce succeeded")
	}
	// Exactly salt and nonce suffice.
	if _, err := k.seal([]byte("pw"), bytes.NewReader(make([]byte, 16+12)), DefaultKDFParams, fastKDF); err != nil {
		t.Fatal(err)
	}
}

// TestWriteKeystoreFileFailureLeavesNothing: when the final rename fails
// (the target is a non-empty directory), WriteKeystoreFile reports the
// error, removes its temporary file and leaves the target untouched.
func TestWriteKeystoreFileFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keystore")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "inside"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeystoreFile(target, []byte("GMKS data")); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "keystore" || !entries[0].IsDir() {
		t.Fatalf("directory after the failure: %v", entries)
	}
	if b, err := os.ReadFile(filepath.Join(target, "inside")); err != nil || string(b) != "x" {
		t.Fatal("target changed")
	}
}
