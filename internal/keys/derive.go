package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Salts and labels of the HKDF derivation (specification 2.2 and 2.3).
const (
	SaltUserSeed     = "gomail/v1/user-seed"
	SaltPlatformRoot = "gomail/v1/platform-root"

	LabelUserRoot         = "gomail/v1/user/root"
	LabelUserIdentity     = "gomail/v1/user/identity"
	LabelUserUnwrap       = "gomail/v1/user/unwrap"
	LabelPlatformIdentity = "gomail/v1/platform/identity"
	LabelPlatformAdmin    = "gomail/v1/platform/admin"
	LabelPlatformIngest   = "gomail/v1/platform/ingest"
)

// deriver holds the HKDF pseudorandom key extracted from a seed.
type deriver struct {
	prk    []byte
	err    error
	zeroed bool
}

func newDeriver(seed *Seed, salt string) deriver {
	if seed == nil {
		return deriver{err: fmt.Errorf("keys: nil seed")}
	}
	prk, err := hkdf.Extract(sha256.New, seed[:], []byte(salt))
	if err != nil {
		return deriver{err: fmt.Errorf("keys: HKDF-Extract: %w", err)}
	}
	return deriver{prk: prk}
}

// expand derives 32 bytes for label. With gen > 0 the info is
// label || 0x00 || uint32 big endian gen; with gen == 0 (only for the
// user root) it is the label alone. Callers that take a generation reject
// 0 before calling expand.
func (d *deriver) expand(label string, gen uint32) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	if d.zeroed {
		return nil, ErrZeroed
	}
	info := []byte(label)
	if gen != 0 {
		info = append(info, 0)
		info = binary.BigEndian.AppendUint32(info, gen)
	}
	out, err := hkdf.Expand(sha256.New, d.prk, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("keys: HKDF-Expand: %w", err)
	}
	return out, nil
}

func (d *deriver) zero() {
	Wipe(d.prk)
	d.zeroed = true
}

func (d *deriver) ed25519Key(label string, gen uint32) (ed25519.PrivateKey, error) {
	b, err := d.expand(label, gen)
	if err != nil {
		return nil, err
	}
	k := ed25519.NewKeyFromSeed(b)
	Wipe(b)
	return k, nil
}

func (d *deriver) x25519Key(label string, gen uint32) (*ecdh.PrivateKey, error) {
	b, err := d.expand(label, gen)
	if err != nil {
		return nil, err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	Wipe(b)
	if err != nil {
		return nil, fmt.Errorf("keys: X25519 key: %w", err)
	}
	return k, nil
}

func checkGeneration(gen uint32) error {
	if gen == 0 {
		return fmt.Errorf("%w: generations start at 1", ErrGeneration)
	}
	return nil
}

// UserRoot derives the keys of a user from the seed (2.2). It holds only
// the HKDF pseudorandom key; Zero it as soon as the needed keys are
// derived.
type UserRoot struct {
	d deriver
}

// DeriveUser prepares the derivation of user keys from seed.
func DeriveUser(seed *Seed) *UserRoot {
	return &UserRoot{d: newDeriver(seed, SaltUserSeed)}
}

// RootKey returns the Ed25519 root key that certifies generations. It is
// never stored; derive it only while the seed is being entered.
func (u *UserRoot) RootKey() (ed25519.PrivateKey, error) {
	return u.d.ed25519Key(LabelUserRoot, 0)
}

// IdentityKey returns the Ed25519 identity key of generation gen.
func (u *UserRoot) IdentityKey(gen uint32) (ed25519.PrivateKey, error) {
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	return u.d.ed25519Key(LabelUserIdentity, gen)
}

// UnwrapKey returns the X25519 unwrap key of generation gen.
func (u *UserRoot) UnwrapKey(gen uint32) (*ecdh.PrivateKey, error) {
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	return u.d.x25519Key(LabelUserUnwrap, gen)
}

// Zero overwrites the derivation key. Further derivations fail with
// ErrZeroed.
func (u *UserRoot) Zero() { u.d.zero() }

// PlatformRoot derives the platform keys from the platform root seed
// (2.3). Only the identity key's public part and the derived admin and
// ingest keys leave the ceremony.
type PlatformRoot struct {
	d deriver
}

// DerivePlatform prepares the derivation of platform keys from seed.
func DerivePlatform(seed *Seed) *PlatformRoot {
	return &PlatformRoot{d: newDeriver(seed, SaltPlatformRoot)}
}

// IdentityKey returns the Ed25519 platform identity key of generation gen.
func (p *PlatformRoot) IdentityKey(gen uint32) (ed25519.PrivateKey, error) {
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	return p.d.ed25519Key(LabelPlatformIdentity, gen)
}

// AdminKey returns the Ed25519 admin key of generation gen.
func (p *PlatformRoot) AdminKey(gen uint32) (ed25519.PrivateKey, error) {
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	return p.d.ed25519Key(LabelPlatformAdmin, gen)
}

// IngestKey returns the Ed25519 ingest key of generation gen.
func (p *PlatformRoot) IngestKey(gen uint32) (ed25519.PrivateKey, error) {
	if err := checkGeneration(gen); err != nil {
		return nil, err
	}
	return p.d.ed25519Key(LabelPlatformIngest, gen)
}

// Zero overwrites the derivation key. Further derivations fail with
// ErrZeroed.
func (p *PlatformRoot) Zero() { p.d.zero() }
