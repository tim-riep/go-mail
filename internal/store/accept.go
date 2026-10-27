package store

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// WrapAcceptSchema is epochs/<n>/members/<user-id>.accept (2.2 point 4,
// 3.7, S13): a member's countersignature over its own wrap. It names
// mailbox, epoch and member, the SHA-256 of the whole .wrap file and the
// generation of the member's identity, and carries the signature of that
// identity under the short name "wrap-accept" over the record without
// field 6. A member signs it once it has verified its wrap, so the wrap
// stays usable when the member who made it later loses a generation or
// leaves. The acceptance rules are the client's (task 06).
var WrapAcceptSchema = rec.MustSchema("gomail/v1/rec/wrap-accept",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	id16(3, "user_id", true),
	bytes32(4, "wrap_hash", true),
	rec.Field{Num: 5, Name: "user_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 6, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// WrapAccept is a decoded .accept file.
type WrapAccept struct {
	MailboxID ID
	Epoch     uint32
	UserID    ID
	WrapHash  [32]byte // SHA-256 of the whole .wrap file
	UserGen   uint32
	Signature []byte
}

func (a *WrapAccept) check() error {
	if a.MailboxID.IsZero() || a.Epoch == 0 || a.UserID.IsZero() || a.UserGen == 0 || a.WrapHash == [32]byte{} {
		return fmt.Errorf("%w: incomplete wrap acceptance", ErrRecord)
	}
	return nil
}

func (a *WrapAccept) record(withSig bool) *rec.Record {
	r := rec.New(WrapAcceptSchema).SetBytes(1, a.MailboxID[:]).SetU32(2, a.Epoch).SetBytes(3, a.UserID[:]).
		SetBytes(4, a.WrapHash[:]).SetU32(5, a.UserGen)
	if withSig {
		r.SetBytes(6, a.Signature)
	}
	return r
}

// Sign signs the acceptance with the identity key of generation UserGen
// of the member.
func (a *WrapAccept) Sign(identity ed25519.PrivateKey) error {
	if err := a.check(); err != nil {
		return err
	}
	tbs, err := a.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	a.Signature, err = keys.Sign(identity, keys.DomainWrapAccept, tbs)
	return err
}

// Verify checks the signature with the identity key of the member
// (UserID, UserGen); finding that key is the caller's task.
func (a *WrapAccept) Verify(identity ed25519.PublicKey) error {
	if err := a.check(); err != nil {
		return err
	}
	tbs, err := a.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	if !keys.Verify(identity, keys.DomainWrapAccept, tbs, a.Signature) {
		return fmt.Errorf("%w: wrap acceptance", keys.ErrSignature)
	}
	return nil
}

// Encode returns the canonical encoding of a signed acceptance.
func (a *WrapAccept) Encode() ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: wrap acceptance is not signed", ErrRecord)
	}
	return a.record(true).Encode()
}

// DecodeWrapAccept decodes an .accept file. The signature must be
// verified separately with the member's key.
func DecodeWrapAccept(data []byte) (*WrapAccept, error) {
	r, err := rec.Decode(WrapAcceptSchema, data)
	if err != nil {
		return nil, err
	}
	if !r.Has(6) {
		return nil, fmt.Errorf("%w: wrap acceptance is not signed", ErrRecord)
	}
	a := &WrapAccept{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2), UserID: idFromBytes(r.Bytes(3)), UserGen: r.U32(5), Signature: r.Bytes(6)}
	copy(a.WrapHash[:], r.Bytes(4))
	if err := a.check(); err != nil {
		return nil, err
	}
	return a, nil
}

// AcceptFile is epochs/<n>/members/<user-id>.accept.
func (s *Store) AcceptFile(id ID, n uint32, user ID) string {
	return filepath.Join(s.EpochDir(id, n), "members", user.String()+".accept")
}

// WriteAccept replaces the acceptance of member a.UserID for epoch
// a.Epoch (a new wrap needs a new acceptance).
func (s *Store) WriteAccept(a *WrapAccept) error {
	data, err := a.Encode()
	if err != nil {
		return err
	}
	p := s.AcceptFile(a.MailboxID, a.Epoch, a.UserID)
	if err := MkdirAll(filepath.Dir(p)); err != nil {
		return err
	}
	return WriteFileAtomic(p, data)
}

// ReadAccept reads the acceptance of user for epoch n and checks that it
// names this mailbox, epoch and user. The signature is checked by the
// caller.
func (s *Store) ReadAccept(id ID, n uint32, user ID) (*WrapAccept, error) {
	data, err := ReadFileLimited(s.AcceptFile(id, n, user), MaxRecordFile)
	if err != nil {
		return nil, err
	}
	a, err := DecodeWrapAccept(data)
	if err != nil {
		return nil, err
	}
	if a.MailboxID != id || a.Epoch != n || a.UserID != user {
		return nil, fmt.Errorf("%w: epochs/%d/members/%s.accept names another place", ErrRecord, n, user)
	}
	return a, nil
}
