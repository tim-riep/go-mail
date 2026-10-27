package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/rec"
)

func testUser(t *testing.T, seedByte byte) (*UserRoot, ed25519.PrivateKey) {
	t.Helper()
	var seed Seed
	for i := range seed {
		seed[i] = seedByte
	}
	u := DeriveUser(&seed)
	root, err := u.RootKey()
	if err != nil {
		t.Fatal(err)
	}
	return u, root
}

func genCert(t *testing.T, u *UserRoot, root ed25519.PrivateKey, gen uint32) *GenerationCert {
	t.Helper()
	id, err := u.IdentityKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	uw, err := u.UnwrapKey(gen)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewGenerationCert(root, gen, id.Public().(ed25519.PublicKey), uw.PublicKey(), 1_761_400_000_000+int64(gen))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignVerify(t *testing.T) {
	_, root := testUser(t, 1)
	pub := root.Public().(ed25519.PublicKey)
	sig, err := Sign(root, DomainEpoch, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, DomainEpoch, []byte("body"), sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pub, DomainAddress, []byte("body"), sig) {
		t.Fatal("signature must be bound to the domain")
	}
	if Verify(pub, DomainEpoch, []byte("bodx"), sig) {
		t.Fatal("signature must be bound to the body")
	}
	if Verify(pub, "epoch\x00", []byte("body"), sig) || Verify(pub, "", []byte("body"), sig) {
		t.Fatal("invalid domains must never verify")
	}
	if Verify(pub[:31], DomainEpoch, []byte("body"), sig) || Verify(pub, DomainEpoch, []byte("body"), sig[:63]) {
		t.Fatal("wrong lengths must never verify")
	}
	// The signed message is the documented prefix.
	msg, err := signedMessage(DomainEpoch, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, []byte("gomail/v1/sig/epoch\x00body")) {
		t.Fatalf("unexpected signed message %q", msg)
	}
	// Only the short names of 3.7 are domains: no unknown names, no full
	// record types, no slashes.
	for _, d := range []string{"", "a\x00b", "ä", "with space", "test", "generation", "gomail/v1/rec/platform-cert", "platform/cert", "identity-succ", "Mail"} {
		if _, err := Sign(root, d, nil); !errors.Is(err, ErrDomain) {
			t.Fatalf("domain %q must be rejected", d)
		}
	}
	if _, err := Sign(root[:10], DomainEpoch, nil); err == nil {
		t.Fatal("short private key must be rejected")
	}
}

func TestGenerationCertRoundTrip(t *testing.T) {
	u, root := testUser(t, 2)
	rootPub := root.Public().(ed25519.PublicKey)
	c1 := genCert(t, u, root, 1)
	if err := c1.Verify(rootPub); err != nil {
		t.Fatal(err)
	}
	enc, err := c1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeGenerationCert(enc)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := dec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatal("re-encoding differs")
	}
	if err := dec.Verify(rootPub); err != nil {
		t.Fatal(err)
	}
	if dec.Gen != 1 || dec.Revokes != 0 || dec.Created != c1.Created || !bytes.Equal(dec.IdentityPub, c1.IdentityPub) || !bytes.Equal(dec.UnwrapPub.Bytes(), c1.UnwrapPub.Bytes()) {
		t.Fatal("decoded fields differ")
	}
	c2 := genCert(t, u, root, 2)
	if c2.Revokes != 1 {
		t.Fatal("generation 2 must revoke generation 1")
	}
	if err := VerifyGenerationChain(rootPub, []*GenerationCert{c1, c2}); err != nil {
		t.Fatal(err)
	}
	// The record layout: the signature is over the record without field 6.
	tbs, _ := c1.toRecord(false).Encode()
	if !Verify(rootPub, DomainUserGen, tbs, c1.Signature) {
		t.Fatal("signature is not over the unsigned record")
	}
}

func TestGenerationCertRejects(t *testing.T) {
	u, root := testUser(t, 3)
	rootPub := root.Public().(ed25519.PublicKey)
	_, otherRoot := testUser(t, 4)
	otherPub := otherRoot.Public().(ed25519.PublicKey)
	c1 := genCert(t, u, root, 1)
	c2 := genCert(t, u, root, 2)
	c3 := genCert(t, u, root, 3)

	if _, err := NewGenerationCert(root, 0, c1.IdentityPub, c1.UnwrapPub, 0); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 0 must be rejected")
	}
	if _, err := NewGenerationCert(root, 1, c1.IdentityPub[:31], c1.UnwrapPub, 0); !errors.Is(err, ErrCert) {
		t.Fatal("short identity key must be rejected")
	}
	if _, err := NewGenerationCert(root, 1, c1.IdentityPub, nil, 0); !errors.Is(err, ErrCert) {
		t.Fatal("nil unwrap key must be rejected")
	}
	if _, err := NewGenerationCert(root[:5], 1, c1.IdentityPub, c1.UnwrapPub, 0); err == nil {
		t.Fatal("bad root key must be rejected")
	}

	if err := c1.Verify(otherPub); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong root must fail: %v", err)
	}
	if err := c1.Verify(rootPub[:31]); !errors.Is(err, ErrSignature) {
		t.Fatalf("short root key must fail: %v", err)
	}

	// Structural rules on generation and revokes.
	mut := func(f func(c *GenerationCert)) *GenerationCert {
		c := *c2
		c.IdentityPub = append([]byte(nil), c.IdentityPub...)
		f(&c)
		return &c
	}
	for name, c := range map[string]*GenerationCert{
		"gen 2 without revokes":     mut(func(c *GenerationCert) { c.Revokes = 0 }),
		"gen 2 revokes 2":           mut(func(c *GenerationCert) { c.Revokes = 2 }),
		"gen 2 revokes 3":           mut(func(c *GenerationCert) { c.Revokes = 3 }),
		"gen 1 with revokes":        mut(func(c *GenerationCert) { c.Gen = 1; c.Revokes = 1 }),
		"gen 0":                     mut(func(c *GenerationCert) { c.Gen = 0 }),
		"tampered identity":         mut(func(c *GenerationCert) { c.IdentityPub[0] ^= 1 }),
		"tampered created":          mut(func(c *GenerationCert) { c.Created++ }),
		"tampered gen":              mut(func(c *GenerationCert) { c.Gen = 3; c.Revokes = 2 }),
		"tampered signature":        mut(func(c *GenerationCert) { c.Signature = append([]byte(nil), c.Signature...); c.Signature[0] ^= 1 }),
		"short signature":           mut(func(c *GenerationCert) { c.Signature = c.Signature[:63] }),
		"identity of another gen":   mut(func(c *GenerationCert) { c.IdentityPub = c3.IdentityPub }),
		"unwrap of another gen":     mut(func(c *GenerationCert) { c.UnwrapPub = c3.UnwrapPub }),
		"signature of another cert": mut(func(c *GenerationCert) { c.Signature = c3.Signature }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.Verify(rootPub); err == nil {
				t.Fatal("expected rejection")
			}
			if enc, err := c.Encode(); err == nil {
				if dec, err := DecodeGenerationCert(enc); err == nil {
					if err := dec.Verify(rootPub); err == nil {
						t.Fatal("expected rejection after decode")
					}
				}
			}
		})
	}

	// Chains.
	chains := map[string][]*GenerationCert{
		"empty":            {},
		"starts at 2":      {c2, c3},
		"gap":              {c1, c3},
		"duplicate":        {c1, c1},
		"descending":       {c2, c1},
		"nil entry":        {c1, nil},
		"foreign root":     {genCert(t, u, otherRoot, 1)},
		"wrong root later": {c1, genCert(t, u, otherRoot, 2)},
	}
	for name, chain := range chains {
		t.Run("chain "+name, func(t *testing.T) {
			if err := VerifyGenerationChain(rootPub, chain); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if err := VerifyGenerationChain(rootPub, []*GenerationCert{c1, c2, c3}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeGenerationCertRejects(t *testing.T) {
	u, root := testUser(t, 5)
	c := genCert(t, u, root, 1)
	enc, _ := c.Encode()
	unsigned, _ := c.toRecord(false).Encode()
	cases := map[string][]byte{
		"empty":         {},
		"garbage":       []byte("not a record"),
		"missing sig":   unsigned,
		"truncated":     enc[:len(enc)-1],
		"trailing byte": append(append([]byte(nil), enc...), 0),
		"wrong type":    append([]byte("gomail/v1/rec/user-gex\x00"), enc[len("gomail/v1/rec/user-gen\x00"):]...),
		"platform cert": func() []byte {
			b, _ := (&PlatformCert{Role: RoleIngest, Gen: 1, Pub: c.IdentityPub, IdentityGen: 1, Signature: c.Signature}).Encode()
			return b
		}(),
		"gen 1 revoking": func() []byte { x := *c; x.Revokes = 1; b, _ := x.Encode(); return b }(),
		"gen 0":          func() []byte { x := *c; x.Gen = 0; b, _ := x.Encode(); return b }(),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeGenerationCert(data); err == nil || got != nil {
				t.Fatalf("expected rejection, got %v, %v", got, err)
			}
		})
	}
}

func TestPlatformCert(t *testing.T) {
	var seed Seed
	seed[0] = 9
	p := DerivePlatform(&seed)
	idKey, _ := p.IdentityKey(1)
	idPub := idKey.Public().(ed25519.PublicKey)
	ingest, _ := p.IngestKey(1)
	admin, _ := p.AdminKey(2)
	c, err := NewPlatformCert(idKey, 1, RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 1_761_400_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(idPub); err != nil {
		t.Fatal(err)
	}
	enc, _ := c.Encode()
	dec, err := DecodePlatformCert(enc)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := dec.Encode()
	if !bytes.Equal(enc, enc2) {
		t.Fatal("re-encoding differs")
	}
	if err := dec.Verify(idPub); err != nil {
		t.Fatal(err)
	}
	a, err := NewPlatformCert(idKey, 1, RoleAdmin, 2, admin.Public().(ed25519.PublicKey), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(idPub); err != nil {
		t.Fatal(err)
	}
	// Rejections.
	if _, err := NewPlatformCert(idKey, 1, Role(3), 1, idPub, 0); !errors.Is(err, ErrCert) {
		t.Fatal("unknown role must be rejected")
	}
	if _, err := NewPlatformCert(idKey, 0, RoleIngest, 1, idPub, 0); !errors.Is(err, ErrGeneration) {
		t.Fatal("identity generation 0 must be rejected")
	}
	if _, err := NewPlatformCert(idKey, 1, RoleIngest, 0, idPub, 0); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 0 must be rejected")
	}
	if _, err := NewPlatformCert(idKey, 1, RoleIngest, 1, idPub[:5], 0); !errors.Is(err, ErrCert) {
		t.Fatal("short key must be rejected")
	}
	other, _ := p.IdentityKey(2)
	if err := c.Verify(other.Public().(ed25519.PublicKey)); !errors.Is(err, ErrSignature) {
		t.Fatal("wrong identity must fail")
	}
	x := *c
	x.Role = RoleAdmin
	if err := x.Verify(idPub); !errors.Is(err, ErrSignature) {
		t.Fatal("role must be signed")
	}
	y := *c
	y.IdentityGen = 2
	if err := y.Verify(idPub); !errors.Is(err, ErrSignature) {
		t.Fatal("identity generation must be signed")
	}
	// A generation certificate is not a platform certificate.
	u, root := testUser(t, 6)
	g, _ := genCert(t, u, root, 1).Encode()
	if _, err := DecodePlatformCert(g); err == nil {
		t.Fatal("generation certificate accepted as platform certificate")
	}
	if _, err := DecodePlatformCert(nil); err == nil {
		t.Fatal("empty input accepted")
	}
}

func TestPlatformSuccession(t *testing.T) {
	var seed Seed
	seed[0] = 10
	p := DerivePlatform(&seed)
	g1, _ := p.IdentityKey(1)
	g2, _ := p.IdentityKey(2)
	g3, _ := p.IdentityKey(3)
	pub1 := g1.Public().(ed25519.PublicKey)
	pub2 := g2.Public().(ed25519.PublicKey)
	s, err := NewPlatformSuccession(g1, 2, pub2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pub1, 1); err != nil {
		t.Fatal(err)
	}
	enc, _ := s.Encode()
	dec, err := DecodePlatformSuccession(enc)
	if err != nil {
		t.Fatal(err)
	}
	if enc2, _ := dec.Encode(); !bytes.Equal(enc, enc2) {
		t.Fatal("re-encoding differs")
	}
	if err := dec.Verify(pub1, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pub1, 2); !errors.Is(err, ErrGeneration) {
		t.Fatal("successor must be exactly one generation higher")
	}
	if err := s.Verify(pub2, 1); !errors.Is(err, ErrSignature) {
		t.Fatal("must be signed by the previous generation")
	}
	if _, err := NewPlatformSuccession(g1, 1, pub2, 0); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 1 has no predecessor")
	}
	if _, err := NewPlatformSuccession(g1, 2, pub2[:3], 0); !errors.Is(err, ErrCert) {
		t.Fatal("short key must be rejected")
	}
	// A successor cannot be signed by a later generation.
	s3, _ := NewPlatformSuccession(g3, 3, g3.Public().(ed25519.PublicKey), 0)
	if err := s3.Verify(pub2, 2); !errors.Is(err, ErrSignature) {
		t.Fatal("self-signed succession must fail")
	}
	if _, err := DecodePlatformSuccession([]byte("x")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSchemasExported(t *testing.T) {
	for _, s := range []*rec.Schema{GenerationCertSchema, PlatformCertSchema, PlatformSuccessionSchema, KeystoreHeaderSchema, KeystoreContentSchema} {
		if s == nil || s.Type == "" {
			t.Fatal("schema missing")
		}
	}
}

var _ = ecdh.X25519

// TestPlatformRecordLayout pins the field order of the platform records
// to 2.3 and their signature domain to 3.7 (version 1.2): platform-cert is
// role, gen, pub, identity_gen, valid_from, sig; platform-succ is gen,
// pub, valid_from, sig; both are signed under "gomail/v1/sig/" || short
// name || 0x00, the short name being the record type without
// "gomail/v1/rec/".
func TestPlatformRecordLayout(t *testing.T) {
	var seed Seed
	seed[0] = 11
	p := DerivePlatform(&seed)
	idKey, _ := p.IdentityKey(1)
	idPub := idKey.Public().(ed25519.PublicKey)
	ingest, _ := p.IngestKey(1)
	c, err := NewPlatformCert(idKey, 1, RoleIngest, 3, ingest.Public().(ed25519.PublicKey), 1_761_400_000_000)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := c.Encode()
	r, err := rec.Decode(PlatformCertSchema, enc)
	if err != nil {
		t.Fatal(err)
	}
	if r.U8(1) != 2 || r.U32(2) != 3 || !bytes.Equal(r.Bytes(3), ingest.Public().(ed25519.PublicKey)) || r.U32(4) != 1 || r.I64(5) != 1_761_400_000_000 || len(r.Bytes(6)) != 64 {
		t.Fatal("platform-cert field layout differs from 2.3")
	}
	if PlatformCertSchema.Fields[3].Name != "identity_gen" || PlatformCertSchema.Fields[4].Name != "valid_from" {
		t.Fatal("field names")
	}
	if d, err := RecordDomain(PlatformCertSchema); err != nil || d != DomainPlatformCert {
		t.Fatal("the domain must be the short name of the record type")
	}
	if d, err := RecordDomain(PlatformSuccessionSchema); err != nil || d != DomainPlatformSuccession {
		t.Fatal("the succession domain must be the short name of the record type")
	}
	if PlatformSuccessionSchema.Type != "gomail/v1/rec/platform-succ" {
		t.Fatalf("succession record type %q", PlatformSuccessionSchema.Type)
	}
	// The signature is over the record without field 6 under the short
	// name. The full record type of version 1.1 is no domain any more.
	tbs, _ := c.toRecord(false).Encode()
	if !Verify(idPub, "platform-cert", tbs, c.Signature) {
		t.Fatal("signature under the short name must verify")
	}
	if Verify(idPub, "gomail/v1/rec/platform-cert", tbs, c.Signature) {
		t.Fatal("the full record type must not verify")
	}
	msg, _ := signedMessage(DomainPlatformCert, tbs)
	if !bytes.HasPrefix(msg, []byte("gomail/v1/sig/platform-cert\x00")) || bytes.HasPrefix(msg, []byte("gomail/v1/sig/gomail/")) {
		t.Fatalf("signed message prefix %q", msg[:30])
	}
	// A version 1.1 signature (domain = full record type) does not verify.
	msg11 := append([]byte("gomail/v1/sig/gomail/v1/rec/platform-cert\x00"), tbs...)
	if Verify(idPub, DomainPlatformCert, tbs, ed25519.Sign(idKey, msg11)) {
		t.Fatal("a version 1.1 signature must not verify")
	}
	// Same for the succession.
	g2, _ := p.IdentityKey(2)
	s, err := NewPlatformSuccession(idKey, 2, g2.Public().(ed25519.PublicKey), 7)
	if err != nil {
		t.Fatal(err)
	}
	senc, _ := s.Encode()
	sr, err := rec.Decode(PlatformSuccessionSchema, senc)
	if err != nil {
		t.Fatal(err)
	}
	if sr.U32(1) != 2 || !bytes.Equal(sr.Bytes(2), g2.Public().(ed25519.PublicKey)) || sr.I64(3) != 7 || len(sr.Bytes(4)) != 64 {
		t.Fatal("platform-succ field layout differs from 2.3")
	}
	stbs, _ := s.toRecord(false).Encode()
	if !Verify(idPub, "platform-succ", stbs, s.Signature) || Verify(idPub, "gomail/v1/rec/platform-succ", stbs, s.Signature) || Verify(idPub, "identity-succ", stbs, s.Signature) {
		t.Fatal("succession domain")
	}
	// A phase 0 platform certificate (created before identity_gen,
	// short domain) does not decode: field 4 has the wrong width.
	old := rec.MustSchema("gomail/v1/rec/platform-cert",
		rec.Field{Num: 1, Name: "role", Kind: rec.U8, Required: true},
		rec.Field{Num: 2, Name: "gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 3, Name: "pub", Kind: rec.Bytes, Size: 32, Required: true},
		rec.Field{Num: 4, Name: "created", Kind: rec.I64, Required: true},
		rec.Field{Num: 5, Name: "identity_gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 6, Name: "sig", Kind: rec.Bytes, Size: 64})
	oldEnc, _ := rec.New(old).SetU8(1, 2).SetU32(2, 3).SetBytes(3, c.Pub).SetI64(4, c.ValidFrom).SetU32(5, 1).SetBytes(6, c.Signature).Encode()
	if _, err := DecodePlatformCert(oldEnc); err == nil {
		t.Fatal("phase 0 layout accepted")
	}
}

// TestDomainTable pins the short names of 3.7 (version 1.3): exactly the
// fourteen names of the table, unique, ASCII without a slash, and the record
// types of the signed records carry them.
func TestDomainTable(t *testing.T) {
	want := []string{"platform-cert", "platform-succ", "user-gen", "epoch", "address", "checkpoint", "user", "invite", "wrap-accept", "mail", "meta", "pending", "wrap", "index"}
	if len(domains) != len(want) {
		t.Fatalf("%d domains, want %d", len(domains), len(want))
	}
	seen := map[string]bool{}
	for i, d := range domains {
		if d != want[i] {
			t.Fatalf("domain %d is %q, want %q", i, d, want[i])
		}
		if seen[d] {
			t.Fatalf("duplicate domain %q", d)
		}
		seen[d] = true
		for j := 0; j < len(d); j++ {
			if c := d[j]; c < 0x21 || c > 0x7e || c == '/' {
				t.Fatalf("domain %q is not ASCII without a slash", d)
			}
		}
		if !KnownDomain(d) {
			t.Fatalf("%q not known", d)
		}
	}
	for s, d := range map[*rec.Schema]string{GenerationCertSchema: "user-gen", PlatformCertSchema: "platform-cert", PlatformSuccessionSchema: "platform-succ"} {
		got, err := RecordDomain(s)
		if err != nil || got != d {
			t.Fatalf("RecordDomain(%s) = %q, %v", s.Type, got, err)
		}
	}
	// Records that are not signed have no domain.
	for _, s := range []*rec.Schema{KeystoreHeaderSchema, KeystoreContentSchema, nil, rec.MustSchema("other/epoch", rec.Field{Num: 1, Name: "a", Kind: rec.U8})} {
		if _, err := RecordDomain(s); !errors.Is(err, ErrDomain) {
			t.Fatal("unsigned or foreign record type must have no domain")
		}
	}
	// The generation certificate signs under "gomail/v1/sig/user-gen".
	seed := Seed{1}
	u := DeriveUser(&seed)
	root, _ := u.RootKey()
	id, _ := u.IdentityKey(1)
	uw, _ := u.UnwrapKey(1)
	c, err := NewGenerationCert(root, 1, id.Public().(ed25519.PublicKey), uw.PublicKey(), 5)
	if err != nil {
		t.Fatal(err)
	}
	tbs, _ := c.toRecord(false).Encode()
	if !ed25519.Verify(root.Public().(ed25519.PublicKey), append([]byte("gomail/v1/sig/user-gen\x00"), tbs...), c.Signature) {
		t.Fatal("generation certificate must be signed under gomail/v1/sig/user-gen")
	}
	if !bytes.HasPrefix(tbs, []byte("gomail/v1/rec/user-gen\x00")) {
		t.Fatal("generation record type")
	}
}
