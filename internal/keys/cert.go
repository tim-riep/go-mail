package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"

	"github.com/tim-riep/go-mail/internal/rec"
)

// Signature domains. A signature is always over
// "gomail/v1/sig/" || domain || 0x00 || body, so a signature made for one
// purpose can never pass as a signature for another (specification 3.4).
// For platform certificates and successions the domain is the record
// type (2.3, version 1.1: prefix "gomail/v1/sig/" || record type || 0x00).
const (
	sigPrefix = "gomail/v1/sig/"

	DomainGeneration         = "generation"
	DomainPlatformCert       = "gomail/v1/rec/platform-cert"
	DomainPlatformSuccession = "gomail/v1/rec/platform-succ"
)

// signedMessage returns the bytes that are signed for domain and body.
func signedMessage(domain string, body []byte) ([]byte, error) {
	if domain == "" {
		return nil, fmt.Errorf("%w: empty", ErrDomain)
	}
	for i := 0; i < len(domain); i++ {
		if c := domain[i]; c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("%w: must be printable ASCII without spaces", ErrDomain)
		}
	}
	msg := make([]byte, 0, len(sigPrefix)+len(domain)+1+len(body))
	msg = append(msg, sigPrefix...)
	msg = append(msg, domain...)
	msg = append(msg, 0)
	return append(msg, body...), nil
}

// Sign returns the Ed25519 signature of body under domain.
func Sign(priv ed25519.PrivateKey, domain string, body []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key has wrong length", ErrSignature)
	}
	msg, err := signedMessage(domain, body)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, msg), nil
}

// Verify reports whether sig is a valid signature of body under domain.
// Invalid keys, domains or signature lengths never verify.
func Verify(pub ed25519.PublicKey, domain string, body, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := signedMessage(domain, body)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// GenerationCertSchema is the record of a user generation (2.2). The
// signature (field 6) is made by the user's root key over the record
// without that field, under DomainGeneration.
var GenerationCertSchema = rec.MustSchema("gomail/v1/rec/generation",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "identity_pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "unwrap_pub", Kind: rec.Bytes, Size: 32, Required: true},
	rec.Field{Num: 4, Name: "created", Kind: rec.I64, Required: true},
	rec.Field{Num: 5, Name: "revokes", Kind: rec.U32},
	rec.Field{Num: 6, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// GenerationCert certifies the identity and unwrap keys of one generation
// of a user. Generation n > 1 revokes generation n-1 in the same step.
type GenerationCert struct {
	Gen         uint32
	IdentityPub ed25519.PublicKey
	UnwrapPub   *ecdh.PublicKey
	Created     int64  // milliseconds since 1970 UTC
	Revokes     uint32 // generation revoked by this one; 0 for generation 1
	Signature   []byte // by the root key
}

// NewGenerationCert creates and signs the certificate of generation gen.
func NewGenerationCert(root ed25519.PrivateKey, gen uint32, identityPub ed25519.PublicKey, unwrapPub *ecdh.PublicKey, created int64) (*GenerationCert, error) {
	c := &GenerationCert{Gen: gen, IdentityPub: identityPub, UnwrapPub: unwrapPub, Created: created}
	if gen > 1 {
		c.Revokes = gen - 1
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	tbs, err := c.toRecord(false).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	sig, err := Sign(root, DomainGeneration, tbs)
	if err != nil {
		return nil, err
	}
	c.Signature = sig
	return c, nil
}

// validate checks the structural rules of 2.2 on generations.
func (c *GenerationCert) validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil", ErrCert)
	}
	if c.Gen == 0 {
		return fmt.Errorf("%w: generations start at 1", ErrGeneration)
	}
	if c.Gen == 1 && c.Revokes != 0 {
		return fmt.Errorf("%w: generation 1 revokes nothing", ErrGeneration)
	}
	if c.Gen > 1 && c.Revokes != c.Gen-1 {
		return fmt.Errorf("%w: generation %d must revoke exactly generation %d", ErrGeneration, c.Gen, c.Gen-1)
	}
	if len(c.IdentityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: identity key has wrong length", ErrCert)
	}
	if c.UnwrapPub == nil || c.UnwrapPub.Curve() != ecdh.X25519() {
		return fmt.Errorf("%w: unwrap key is not X25519", ErrCert)
	}
	return nil
}

// toRecord builds the record, with the signature field if withSig.
func (c *GenerationCert) toRecord(withSig bool) *rec.Record {
	r := rec.New(GenerationCertSchema).
		SetU32(1, c.Gen).
		SetBytes(2, c.IdentityPub).
		SetBytes(3, c.UnwrapPub.Bytes()).
		SetI64(4, c.Created)
	if c.Revokes != 0 {
		r.SetU32(5, c.Revokes)
	}
	if withSig {
		r.SetBytes(6, c.Signature)
	}
	return r
}

// Encode returns the canonical encoding including the signature.
func (c *GenerationCert) Encode() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	b, err := c.toRecord(true).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	return b, nil
}

// DecodeGenerationCert parses a certificate and checks its structure. It
// does not verify the signature; call Verify with the root public key.
func DecodeGenerationCert(data []byte) (*GenerationCert, error) {
	r, err := rec.Decode(GenerationCertSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !r.Has(6) {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	if r.Has(5) && r.U32(5) == 0 {
		// An explicit "revokes 0" encodes the same certificate as an absent
		// field; only the absent form is canonical.
		return nil, fmt.Errorf("%w: revokes 0", ErrGeneration)
	}
	pub, err := ecdh.X25519().NewPublicKey(r.Bytes(3))
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap key: %v", ErrCert, err)
	}
	c := &GenerationCert{
		Gen:         r.U32(1),
		IdentityPub: ed25519.PublicKey(r.Bytes(2)),
		UnwrapPub:   pub,
		Created:     r.I64(4),
		Revokes:     r.U32(5),
		Signature:   r.Bytes(6),
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify checks the structure and the root signature.
func (c *GenerationCert) Verify(rootPub ed25519.PublicKey) error {
	if err := c.validate(); err != nil {
		return err
	}
	tbs, err := c.toRecord(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !Verify(rootPub, DomainGeneration, tbs, c.Signature) {
		return fmt.Errorf("%w: generation certificate", ErrSignature)
	}
	return nil
}

// VerifyGenerationChain checks that certs are the complete, contiguous
// generations 1..n of a user, each signed by rootPub and each revoking its
// predecessor. Gaps, jumps, duplicates and reordering are rejected.
func VerifyGenerationChain(rootPub ed25519.PublicKey, certs []*GenerationCert) error {
	if len(certs) == 0 {
		return fmt.Errorf("%w: no generations", ErrGeneration)
	}
	for i, c := range certs {
		if c == nil {
			return fmt.Errorf("%w: nil certificate at %d", ErrCert, i)
		}
		if want := uint32(i + 1); c.Gen != want {
			return fmt.Errorf("%w: expected generation %d at position %d", ErrGeneration, want, i)
		}
		if err := c.Verify(rootPub); err != nil {
			return err
		}
	}
	return nil
}

// Role of a certified platform key.
type Role uint8

const (
	RoleAdmin  Role = 1
	RoleIngest Role = 2
)

// PlatformCertSchema is the record of a platform admin or ingest key
// certificate (2.3, version 1.1): role, generation, public key,
// generation of the issuing identity, valid from, signature. It is
// signed by the platform identity under DomainPlatformCert over the
// record without field 6.
var PlatformCertSchema = rec.MustSchema("gomail/v1/rec/platform-cert",
	rec.Field{Num: 1, Name: "role", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 4, Name: "identity_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 5, Name: "valid_from", Kind: rec.I64, Required: true},
	rec.Field{Num: 6, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// PlatformCert certifies an admin or ingest key of generation Gen. It
// names the generation of the identity key that signed it, so a client
// knows which identity to verify it with. ValidFrom is in milliseconds
// since 1970 UTC.
type PlatformCert struct {
	Role        Role
	Gen         uint32
	Pub         ed25519.PublicKey
	IdentityGen uint32
	ValidFrom   int64
	Signature   []byte
}

// NewPlatformCert signs a certificate for pub with the identity key of
// generation identityGen.
func NewPlatformCert(identity ed25519.PrivateKey, identityGen uint32, role Role, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformCert, error) {
	c := &PlatformCert{Role: role, Gen: gen, Pub: pub, IdentityGen: identityGen, ValidFrom: validFrom}
	if err := c.validate(); err != nil {
		return nil, err
	}
	tbs, err := c.toRecord(false).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	sig, err := Sign(identity, DomainPlatformCert, tbs)
	if err != nil {
		return nil, err
	}
	c.Signature = sig
	return c, nil
}

func (c *PlatformCert) validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil", ErrCert)
	}
	if c.Role != RoleAdmin && c.Role != RoleIngest {
		return fmt.Errorf("%w: unknown role", ErrCert)
	}
	if err := checkGeneration(c.Gen); err != nil {
		return err
	}
	if err := checkGeneration(c.IdentityGen); err != nil {
		return err
	}
	if len(c.Pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key has wrong length", ErrCert)
	}
	return nil
}

func (c *PlatformCert) toRecord(withSig bool) *rec.Record {
	r := rec.New(PlatformCertSchema).
		SetU8(1, uint8(c.Role)).
		SetU32(2, c.Gen).
		SetBytes(3, c.Pub).
		SetU32(4, c.IdentityGen).
		SetI64(5, c.ValidFrom)
	if withSig {
		r.SetBytes(6, c.Signature)
	}
	return r
}

// Encode returns the canonical encoding including the signature.
func (c *PlatformCert) Encode() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	b, err := c.toRecord(true).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	return b, nil
}

// DecodePlatformCert parses a certificate and checks its structure. It
// does not verify the signature.
func DecodePlatformCert(data []byte) (*PlatformCert, error) {
	r, err := rec.Decode(PlatformCertSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !r.Has(6) {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	c := &PlatformCert{
		Role:        Role(r.U8(1)),
		Gen:         r.U32(2),
		Pub:         ed25519.PublicKey(r.Bytes(3)),
		IdentityGen: r.U32(4),
		ValidFrom:   r.I64(5),
		Signature:   r.Bytes(6),
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify checks the structure and the signature by identityPub, which
// must be the identity key of generation c.IdentityGen.
func (c *PlatformCert) Verify(identityPub ed25519.PublicKey) error {
	if err := c.validate(); err != nil {
		return err
	}
	tbs, err := c.toRecord(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !Verify(identityPub, DomainPlatformCert, tbs, c.Signature) {
		return fmt.Errorf("%w: platform certificate", ErrSignature)
	}
	return nil
}

// PlatformSuccessionSchema is the record by which platform identity
// generation n-1 names its successor n (2.3, version 1.1,
// "identity-<gen>.succ"): new generation, new public identity key, valid
// from, signature of the previous generation under
// DomainPlatformSuccession over the record without field 4.
var PlatformSuccessionSchema = rec.MustSchema("gomail/v1/rec/platform-succ",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "valid_from", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// PlatformSuccession is the regular hand-over from platform identity
// generation Gen-1 to Gen. It is not usable after a compromise of Gen-1;
// that case is handled by a client update (2.3).
type PlatformSuccession struct {
	Gen       uint32
	Pub       ed25519.PublicKey
	ValidFrom int64
	Signature []byte
}

// NewPlatformSuccession signs the succession to generation gen with the
// identity key of generation gen-1.
func NewPlatformSuccession(prev ed25519.PrivateKey, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformSuccession, error) {
	s := &PlatformSuccession{Gen: gen, Pub: pub, ValidFrom: validFrom}
	if err := s.validate(); err != nil {
		return nil, err
	}
	tbs, err := s.toRecord(false).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	sig, err := Sign(prev, DomainPlatformSuccession, tbs)
	if err != nil {
		return nil, err
	}
	s.Signature = sig
	return s, nil
}

func (s *PlatformSuccession) validate() error {
	if s == nil {
		return fmt.Errorf("%w: nil", ErrCert)
	}
	if s.Gen < 2 {
		return fmt.Errorf("%w: a successor generation is at least 2", ErrGeneration)
	}
	if len(s.Pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key has wrong length", ErrCert)
	}
	return nil
}

func (s *PlatformSuccession) toRecord(withSig bool) *rec.Record {
	r := rec.New(PlatformSuccessionSchema).
		SetU32(1, s.Gen).
		SetBytes(2, s.Pub).
		SetI64(3, s.ValidFrom)
	if withSig {
		r.SetBytes(4, s.Signature)
	}
	return r
}

// Encode returns the canonical encoding including the signature.
func (s *PlatformSuccession) Encode() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	b, err := s.toRecord(true).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	return b, nil
}

// DecodePlatformSuccession parses a succession record without verifying
// the signature.
func DecodePlatformSuccession(data []byte) (*PlatformSuccession, error) {
	r, err := rec.Decode(PlatformSuccessionSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !r.Has(4) {
		return nil, fmt.Errorf("%w: missing signature", ErrCert)
	}
	s := &PlatformSuccession{Gen: r.U32(1), Pub: ed25519.PublicKey(r.Bytes(2)), ValidFrom: r.I64(3), Signature: r.Bytes(4)}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Verify checks that s names the generation directly after prevGen and
// is signed by prevPub, the identity key of generation prevGen.
func (s *PlatformSuccession) Verify(prevPub ed25519.PublicKey, prevGen uint32) error {
	if err := s.validate(); err != nil {
		return err
	}
	if s.Gen != prevGen+1 {
		return fmt.Errorf("%w: generation %d does not follow %d", ErrGeneration, s.Gen, prevGen)
	}
	tbs, err := s.toRecord(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCert, err)
	}
	if !Verify(prevPub, DomainPlatformSuccession, tbs, s.Signature) {
		return fmt.Errorf("%w: identity succession", ErrSignature)
	}
	return nil
}
