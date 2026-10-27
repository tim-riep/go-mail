package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tim-riep/go-mail/internal/rec"
)

// The recovery recipient of a mailbox (2.4 "Wiederherstellungsempfänger",
// K3, QUESTIONS Q1). Its key is a seed of its own, derived like a user
// seed (keys.DeriveUser, generation 1), that is never registered as a
// user. A member enters it into the member list of an epoch (kind 2,
// MemberRecovery) and wraps the epoch keys for it in
// epochs/<n>/members/recovery.wrap (recipient type 4).
//
// TODO(Q1): the record, its file in the data directory and the ID and
// generation of the recipient entry are the proposal (a) to (c) of
// QUESTIONS Q1, built behind an internal API; no command uses them until
// the question is decided.

// RecoveryGen is the generation of every recovery recipient (Q1 (b)): the
// recovery seed is never rotated, a new seed is a new recipient.
const RecoveryGen uint32 = 1

// RecoveryPubSchema is gomail/v1/rec/recovery-pub (Q1 (c)): the random ID
// of the recovery recipient and its public unwrap and identity keys. It
// carries no signature: a member confirms its fingerprint before it enters
// the recipient (K3 point 3).
var RecoveryPubSchema = rec.MustSchema("gomail/v1/rec/recovery-pub",
	id16(1, "recovery_id", true),
	bytes32(2, "unwrap_pub", true),
	rec.Field{Num: 3, Name: "identity_pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
)

// ErrRecovery reports an invalid recovery record or file.
var ErrRecovery = errors.New("store: invalid recovery recipient")

// RecoveryPub is a decoded recovery-pub record.
type RecoveryPub struct {
	ID          ID
	UnwrapPub   *ecdh.PublicKey   // X25519, recipient of recovery.wrap
	IdentityPub ed25519.PublicKey // Ed25519
}

func (p *RecoveryPub) check() error {
	if p == nil || p.ID.IsZero() || p.UnwrapPub == nil || p.UnwrapPub.Curve() != ecdh.X25519() || len(p.IdentityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: incomplete record", ErrRecovery)
	}
	if bytes.Equal(p.UnwrapPub.Bytes(), make([]byte, 32)) || bytes.Equal(p.IdentityPub, make([]byte, ed25519.PublicKeySize)) {
		return fmt.Errorf("%w: zero key", ErrRecovery)
	}
	return nil
}

// Encode returns the canonical encoding.
func (p *RecoveryPub) Encode() ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return rec.New(RecoveryPubSchema).SetBytes(1, p.ID[:]).SetBytes(2, p.UnwrapPub.Bytes()).SetBytes(3, p.IdentityPub).Encode()
}

// DecodeRecoveryPub decodes a recovery-pub record.
func DecodeRecoveryPub(data []byte) (*RecoveryPub, error) {
	r, err := rec.Decode(RecoveryPubSchema, data)
	if err != nil {
		return nil, err
	}
	p := &RecoveryPub{ID: idFromBytes(r.Bytes(1)), IdentityPub: ed25519.PublicKey(r.Bytes(3))}
	if p.UnwrapPub, err = ecdh.X25519().NewPublicKey(r.Bytes(2)); err != nil {
		return nil, fmt.Errorf("%w: unwrap key: %v", ErrRecovery, err)
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
}

// Fingerprint returns the SHA-256 of the encoded record as 8 groups of 8
// hex digits separated by spaces, for the confirmation by a member (K3
// point 3).
func (p *RecoveryPub) Fingerprint() (string, error) {
	data, err := p.Encode()
	if err != nil {
		return "", err
	}
	return FingerprintOf(data), nil
}

// FingerprintOf returns the fingerprint of an encoded record (see
// Fingerprint).
func FingerprintOf(data []byte) string {
	h := sha256.Sum256(data)
	s := hex.EncodeToString(h[:])
	groups := make([]string, 0, 8)
	for i := 0; i < len(s); i += 8 {
		groups = append(groups, s[i:i+8])
	}
	return strings.Join(groups, " ")
}

// RecoveryPubFile is mailboxes/<id>/recovery/<recovery-id>.pub, the
// public keys of a recovery recipient of the mailbox, so that every member
// can wrap new epochs for it (TODO(Q1): not in section 4).
func (s *Store) RecoveryPubFile(id, recovery ID) string {
	return filepath.Join(s.MailboxDir(id), "recovery", recovery.String()+".pub")
}

// WriteRecoveryPub creates the file of p. An existing file with the same
// bytes is kept; one with other bytes is never replaced (ErrExists).
func (s *Store) WriteRecoveryPub(id ID, p *RecoveryPub) error {
	data, err := p.Encode()
	if err != nil {
		return err
	}
	path := s.RecoveryPubFile(id, p.ID)
	if err := MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	err = CreateFileAtomic(path, data)
	if errors.Is(err, ErrExists) {
		old, rerr := ReadFileLimited(path, MaxRecordFile)
		if rerr == nil && bytes.Equal(old, data) {
			return nil
		}
		return fmt.Errorf("%w: another record for recovery recipient %s", ErrExists, p.ID)
	}
	return err
}

// ReadRecoveryPub reads the file of recovery recipient rid of mailbox id
// and checks that it names rid. It returns the raw bytes for the
// fingerprint.
func (s *Store) ReadRecoveryPub(id, rid ID) (*RecoveryPub, []byte, error) {
	data, err := ReadFileLimited(s.RecoveryPubFile(id, rid), MaxRecordFile)
	if err != nil {
		return nil, nil, err
	}
	p, err := DecodeRecoveryPub(data)
	if err != nil {
		return nil, nil, err
	}
	if p.ID != rid {
		return nil, nil, fmt.Errorf("%w: recovery/%s.pub names another recipient", ErrRecovery, rid)
	}
	return p, data, nil
}

// RecoveryWrapFile is epochs/<n>/members/recovery.wrap (2.4, 3.1).
func (s *Store) RecoveryWrapFile(id ID, n uint32) string {
	return filepath.Join(s.EpochDir(id, n), "members", "recovery.wrap")
}

// CreateRecoveryWrap creates recovery.wrap of epoch n; an existing one is
// never replaced (ErrExists).
func (s *Store) CreateRecoveryWrap(id ID, n uint32, data []byte) error {
	p := s.RecoveryWrapFile(id, n)
	if err := MkdirAll(filepath.Dir(p)); err != nil {
		return err
	}
	return CreateFileAtomic(p, data)
}

// ReadRecoveryWrap reads recovery.wrap of epoch n.
func (s *Store) ReadRecoveryWrap(id ID, n uint32) ([]byte, error) {
	return ReadFileLimited(s.RecoveryWrapFile(id, n), MaxWrapFile)
}

// RemoveRecoveryWrap deletes recovery.wrap of epoch n durably; a missing
// file is not an error.
func (s *Store) RemoveRecoveryWrap(id ID, n uint32) error {
	return RemoveDurable(s.RecoveryWrapFile(id, n))
}
