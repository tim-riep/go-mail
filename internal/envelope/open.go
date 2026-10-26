package envelope

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"

	"github.com/tim-riep/go-mail/internal/keys"
)

// RecipientKey is the private key the file key is unwrapped with. Type,
// ID and Gen select the recipient entry; an entry that does not match
// all three is never tried (3.2).
type RecipientKey struct {
	Type       RecipientType
	ID         [16]byte
	Gen        uint32
	PrivateKey *ecdh.PrivateKey // X25519
}

// signedBytes returns the signed structure of this file for signer ref
// and extra.
func (f *File) signedBytes(ref SignerRef, extra []byte) ([]byte, error) {
	return signedStructure(f.FileHash(), ref, extra)
}

// VerifySignature checks the trailer signature with pub, the public key
// of the signer named in the trailer. extra must be the kind-specific
// fields the signer used, or nil.
func (f *File) VerifySignature(pub ed25519.PublicKey, extra []byte) error {
	if f.Trailer == nil {
		return ErrUnsigned
	}
	if !f.Header.Kind.valid() {
		return fmt.Errorf("%w: unknown kind %d", ErrHeader, f.Header.Kind)
	}
	signed, err := f.signedBytes(f.Trailer.Signer, extra)
	if err != nil {
		return err
	}
	if !keys.Verify(pub, f.Header.Kind.String(), signed, f.Trailer.Signature) {
		return ErrSignature
	}
	return nil
}

// Decrypt unwraps the file key with key and decrypts all blocks. The
// plaintext is returned only after the last block authenticated with its
// end flag; on any failure nothing is returned.
func (f *File) Decrypt(key RecipientKey) ([]byte, error) {
	if !key.Type.valid() || key.Gen == 0 || key.PrivateKey == nil || key.PrivateKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%w: invalid key", ErrNoRecipient)
	}
	ref := recipientRef{key.Type, key.ID, key.Gen}
	var entry *RecipientEntry
	for i := range f.Recipients {
		e := &f.Recipients[i]
		if e.Type == ref.Type && e.ID == ref.ID && e.Gen == ref.Gen {
			entry = e
			break
		}
	}
	if entry == nil {
		return nil, ErrNoRecipient
	}

	// Unwrap the file key (3.2). Any HPKE failure, including a low-order
	// encapsulated key, rejects the file.
	sk, err := hpke.NewDHKEMPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	recipient, err := hpke.NewRecipient(entry.Enc, sk, hpke.HKDFSHA256(), hpke.AES256GCM(), wrapInfo(ref))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	fileKey, err := recipient.Open(aadHash(aadWrap, f.preamble, f.headerBytes), entry.WrappedKey)
	if err != nil {
		return nil, ErrUnwrap
	}
	defer wipe(fileKey)
	if len(fileKey) != FileKeySize {
		return nil, ErrUnwrap
	}

	// Decrypt the blocks (3.3) into a buffer that is released only when
	// every block has authenticated.
	aead, err := contentAEAD(fileKey, f.Header.NoncePrefix)
	if err != nil {
		return nil, err
	}
	aad := aadHash(aadBlock, f.preamble, f.headerBytes)
	size := 0
	for _, b := range f.blocks {
		size += len(b) - TagSize
	}
	out := make([]byte, 0, size)
	for i, b := range f.blocks {
		last := i == len(f.blocks)-1
		pt, err := aead.Open(out[len(out):], blockNonce(f.Header.NoncePrefix, uint32(i), last), b, aad)
		if err != nil {
			wipe(out[:cap(out)])
			return nil, fmt.Errorf("%w: block %d", ErrDecrypt, i)
		}
		out = out[:len(out)+len(pt)]
	}
	return out, nil
}

// OpenOptions configure Open.
type OpenOptions struct {
	// ExpectedSuite is the suite of the file's epoch. A file with another
	// suite is rejected (3.5, rule 2). It must be set.
	ExpectedSuite Suite
	// Key unwraps the file key.
	Key RecipientKey
	// ResolveSigner returns the public key for the signer named in the
	// trailer, or an error if the signer is unknown, revoked or not
	// covered by a certificate. It is required for signed files.
	ResolveSigner func(SignerRef) (ed25519.PublicKey, error)
	// AllowUnsigned accepts a file without trailer. Mail files are
	// unsigned; everything else carries a signature (section 7).
	AllowUnsigned bool
	// Extra are the kind-specific signed fields, as given to the signer.
	Extra []byte
}

// Open parses, checks the suite, verifies the signature according to the
// options, and decrypts. It returns the parsed file and the plaintext, or
// an error and nothing else.
func Open(data []byte, opts OpenOptions) (*File, []byte, error) {
	if opts.ExpectedSuite == 0 {
		return nil, nil, fmt.Errorf("%w: expected suite not set", ErrSuite)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	if f.Suite != opts.ExpectedSuite {
		return nil, nil, fmt.Errorf("%w: file has suite %d, epoch has %d", ErrSuite, f.Suite, opts.ExpectedSuite)
	}
	if f.Trailer == nil {
		if !opts.AllowUnsigned {
			return nil, nil, ErrUnsigned
		}
	} else {
		if opts.ResolveSigner == nil {
			return nil, nil, ErrSignaturePolicy
		}
		pub, err := opts.ResolveSigner(f.Trailer.Signer)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrSigner, err)
		}
		if err := f.VerifySignature(pub, opts.Extra); err != nil {
			return nil, nil, err
		}
	}
	pt, err := f.Decrypt(opts.Key)
	if err != nil {
		return nil, nil, err
	}
	return f, pt, nil
}
