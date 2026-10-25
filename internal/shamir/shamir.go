// Package shamir splits a 32-byte secret into shares over GF(2^8) so that
// any threshold of them reconstructs it and fewer reveal nothing
// (specification 2.3). Each share is also encoded as a list of 30 words
// with a checksum, after the model of SLIP-39.
//
// The construction follows OpenBao's sdk/helper/shamir package (itself
// derived from HashiCorp Vault): one random polynomial per secret byte
// with the secret byte as constant term, evaluated at the share indices;
// reconstruction by Lagrange interpolation at zero. The code here is an
// independent implementation written against that design; see field.go
// for why no lookup tables are used.
//
// Shamir sharing gives no integrity: a wrong or tampered share produces a
// wrong secret without any error. Callers must verify the result by other
// means, as the ceremony does with a trial reconstruction.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// SecretSize is the only supported secret length: the 32-byte seeds of
// specification 2.2 and 2.3.
const SecretSize = 32

// Exported errors. Every error of this package wraps one of them.
var (
	ErrParams       = errors.New("shamir: threshold and count must satisfy 2 <= threshold <= count <= 255")
	ErrSecretSize   = errors.New("shamir: secret must be exactly 32 bytes")
	ErrShare        = errors.New("shamir: malformed share")
	ErrDuplicate    = errors.New("shamir: duplicate share index")
	ErrMismatch     = errors.New("shamir: shares belong to different splits")
	ErrInsufficient = errors.New("shamir: fewer shares than the threshold")
	ErrWordCount    = errors.New("shamir: a share has exactly 30 words")
	ErrUnknownWord  = errors.New("shamir: word is not in the BIP-39 list")
	ErrChecksum     = errors.New("shamir: share checksum mismatch")
)

// Split divides secret into count shares of which threshold are needed to
// reconstruct it. Randomness comes from r, or crypto/rand if r is nil: 2
// bytes for the set identifier, then (threshold-1) coefficient bytes for
// each of the 32 secret bytes in order.
//
// Share indices are 1..count. Index 0 is never used because the
// polynomial's value there is the secret byte itself.
func Split(secret []byte, threshold, count int, r io.Reader) ([]*Share, error) {
	if len(secret) != SecretSize {
		return nil, ErrSecretSize
	}
	if threshold < 2 || count < threshold || count > 255 {
		return nil, ErrParams
	}
	if r == nil {
		r = rand.Reader
	}
	var idb [2]byte
	if _, err := io.ReadFull(r, idb[:]); err != nil {
		return nil, fmt.Errorf("shamir: reading randomness: %w", err)
	}
	id := uint16(idb[0])<<8 | uint16(idb[1])
	coeffs := make([]byte, SecretSize*(threshold-1))
	if _, err := io.ReadFull(r, coeffs); err != nil {
		return nil, fmt.Errorf("shamir: reading randomness: %w", err)
	}
	defer wipe(coeffs)

	shares := make([]*Share, count)
	for i := range shares {
		shares[i] = &Share{ID: id, Threshold: uint8(threshold), Index: uint8(i + 1)}
	}
	p := polynomial{coeffs: make([]uint8, threshold)}
	defer wipe(p.coeffs)
	for j := 0; j < SecretSize; j++ {
		p.coeffs[0] = secret[j]
		copy(p.coeffs[1:], coeffs[j*(threshold-1):(j+1)*(threshold-1)])
		for _, s := range shares {
			s.Y[j] = p.eval(s.Index)
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from shares. All shares must come from
// the same split (same identifier and threshold), have distinct indices,
// and number at least the threshold. More shares than the threshold are
// all used; an inconsistent extra share yields a wrong secret, as any
// wrong share does.
func Combine(shares []*Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, ErrInsufficient
	}
	for i, s := range shares {
		if err := s.validate(); err != nil {
			return nil, fmt.Errorf("%w (share %d)", err, i)
		}
	}
	first := shares[0]
	var seen [256]bool
	for _, s := range shares {
		if s.ID != first.ID || s.Threshold != first.Threshold {
			return nil, ErrMismatch
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("%w: %d", ErrDuplicate, s.Index)
		}
		seen[s.Index] = true
	}
	if len(shares) < int(first.Threshold) {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficient, len(shares), first.Threshold)
	}
	return interpolateShares(shares), nil
}

// interpolateShares reconstructs byte-wise without any validation. It is
// only called by Combine after validation, and by tests.
func interpolateShares(shares []*Share) []byte {
	xs := make([]uint8, len(shares))
	ys := make([]uint8, len(shares))
	defer wipe(ys)
	for i, s := range shares {
		xs[i] = s.Index
	}
	secret := make([]byte, SecretSize)
	for j := 0; j < SecretSize; j++ {
		for i, s := range shares {
			ys[i] = s.Y[j]
		}
		secret[j] = interpolateAtZero(xs, ys)
	}
	return secret
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
