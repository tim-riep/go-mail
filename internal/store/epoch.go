package store

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// Reason is why an epoch began (2.4). The values are fixed: exactly the
// six reasons of the table in 2.4, in its order.
type Reason uint8

const (
	ReasonRegular           Reason = 1 // monthly supply, planned with lead time
	ReasonMemberAdded       Reason = 2 // a member was added or a delegation began
	ReasonMemberRemoved     Reason = 3 // a member was removed (2.5)
	ReasonDelegationEnded   Reason = 4 // a delegation ended (2.5)
	ReasonRecoveryChanged   Reason = 5 // recovery recipient set, changed or removed (K3)
	ReasonGenerationRevoked Reason = 6 // a member revoked a generation (device lost, 2.2)
)

func (r Reason) valid() bool { return r >= ReasonRegular && r <= ReasonGenerationRevoked }

// Immediate reports whether an epoch of this reason takes effect
// immediately (2.4): every reason except regular. member-added is "planned
// or immediate" in 2.4; M1 builds only the immediate form (QUESTIONS Q5).
// Only an immediate epoch may discard epochs of the supply.
func (r Reason) Immediate() bool { return r.valid() && r != ReasonRegular }

// MemberKind distinguishes users, the recovery recipient and delegates
// (2.4, 2.5).
type MemberKind uint8

const (
	MemberUser     MemberKind = 1
	MemberRecovery MemberKind = 2
	// MemberDelegate is a delegation (2.5): it gets the wraps of the
	// epochs of its period but never signs epochs (K2 rule 1).
	// TODO(Q6): kind 3 is the strictest reading of QUESTIONS Q6; no
	// command uses it until the question is decided.
	MemberDelegate MemberKind = 3
)

func (k MemberKind) valid() bool { return k >= MemberUser && k <= MemberDelegate }

// Member is one entry of the member list of an epoch: a user with the
// generation its keys are wrapped for, the recovery recipient or a
// delegate.
type Member struct {
	Kind MemberKind
	ID   ID
	Gen  uint32
}

// MemberSchema is one element of the member list.
var MemberSchema = rec.MustSchema("gomail/v1/rec/epoch-member",
	rec.Field{Num: 1, Name: "kind", Kind: rec.U8, Required: true},
	id16(2, "id", true),
	rec.Field{Num: 3, Name: "gen", Kind: rec.U32, Required: true},
)

// MaxDiscards bounds the list discards of one epoch.
const MaxDiscards = 1024

// DiscardSchema is one element of discards: the number of an epoch of
// the supply that an immediate epoch discards (2.4).
var DiscardSchema = rec.MustSchema("gomail/v1/rec/epoch-discard",
	rec.Field{Num: 1, Name: "number", Kind: rec.U32, Required: true},
)

// EpochSchema is mailboxes/<id>/epochs/<n>/epoch.rec (2.4): number,
// begin, reason, suite, public keys, members with generation, the epochs
// this one discards and the SHA-256 of the previous epoch.rec, signed by
// the identity of the creating member under the short name "epoch" (3.7).
// The mailbox ID and the signer are part of the record so that an epoch
// cannot be moved to another mailbox and the verifier knows the signing
// key (DECISIONS D49). discards precedes the signer fields; like every
// optional field it is present only when it is not empty, so each value
// has exactly one encoding.
var EpochSchema = rec.MustSchema("gomail/v1/rec/epoch",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "number", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "begin", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "reason", Kind: rec.U8, Required: true},
	rec.Field{Num: 5, Name: "suite", Kind: rec.U8, Required: true},
	bytes32(6, "content_pub", true),
	bytes32(7, "meta_pub", true),
	rec.Field{Num: 8, Name: "members", Kind: rec.List, Elem: MemberSchema, MaxCount: MaxMembers, Required: true},
	rec.Field{Num: 9, Name: "discards", Kind: rec.List, Elem: DiscardSchema, MaxCount: MaxDiscards},
	bytes32(10, "prev_hash", false),
	id16(11, "signer_id", true),
	rec.Field{Num: 12, Name: "signer_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 13, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// Epoch is a decoded epoch.rec.
type Epoch struct {
	MailboxID  ID
	Number     uint32
	Begin      int64 // milliseconds since 1970 UTC
	Reason     Reason
	Suite      envelope.Suite
	ContentPub *ecdh.PublicKey
	MetaPub    *ecdh.PublicKey
	Members    []Member
	Discards   []uint32 // epochs of the supply this one discards, ascending
	PrevHash   [32]byte // zero for epoch 1
	SignerID   ID
	SignerGen  uint32
	Signature  []byte
}

func (e *Epoch) check() error {
	switch {
	case e.MailboxID.IsZero():
		return fmt.Errorf("%w: zero mailbox id", ErrRecord)
	case e.Number == 0:
		return fmt.Errorf("%w: epoch 0", ErrRecord)
	case !e.Reason.valid():
		return fmt.Errorf("%w: unknown reason %d", ErrRecord, e.Reason)
	case e.Suite != envelope.Suite1:
		return fmt.Errorf("%w: unknown suite %d", ErrRecord, e.Suite)
	case e.ContentPub == nil || e.MetaPub == nil || e.ContentPub.Curve() != ecdh.X25519() || e.MetaPub.Curve() != ecdh.X25519():
		return fmt.Errorf("%w: missing public key", ErrRecord)
	case len(e.Members) == 0 || len(e.Members) > MaxMembers:
		return fmt.Errorf("%w: %d members", ErrRecord, len(e.Members))
	case e.SignerID.IsZero() || e.SignerGen == 0:
		return fmt.Errorf("%w: no signer", ErrRecord)
	case (e.Number == 1) != (e.PrevHash == [32]byte{}):
		return fmt.Errorf("%w: epoch 1 has no predecessor, every other epoch has one", ErrRecord)
	case len(e.Discards) > MaxDiscards:
		return fmt.Errorf("%w: %d discarded epochs", ErrRecord, len(e.Discards))
	case len(e.Discards) > 0 && !e.Reason.Immediate():
		// 2.4 rule 2: an epoch with planned effect discards nothing.
		return fmt.Errorf("%w: only an immediate epoch discards epochs", ErrRecord)
	}
	for i, n := range e.Discards {
		if n == 0 || n >= e.Number || i > 0 && n <= e.Discards[i-1] {
			return fmt.Errorf("%w: discards must be strictly ascending numbers of earlier epochs", ErrRecord)
		}
	}
	// An ID occurs once in the member list, whatever its kind.
	seen := make(map[ID]bool, len(e.Members))
	recovery := 0
	for _, m := range e.Members {
		if !m.Kind.valid() || m.ID.IsZero() || m.Gen == 0 {
			return fmt.Errorf("%w: invalid member", ErrRecord)
		}
		if seen[m.ID] {
			return fmt.Errorf("%w: duplicate member", ErrRecord)
		}
		seen[m.ID] = true
		if m.Kind == MemberRecovery {
			recovery++
		}
	}
	if recovery > 1 {
		return fmt.Errorf("%w: more than one recovery recipient", ErrRecord)
	}
	// The signer is a user member of the epoch it signs, with exactly the
	// generation it signs with (K2 rule 1, HANDOFF C7). A recovery
	// recipient or a delegate never signs an epoch.
	if m, ok := e.Member(e.SignerID); !ok || m.Gen != e.SignerGen {
		return fmt.Errorf("%w: signer is not a user member of generation %d", ErrRecord, e.SignerGen)
	}
	return nil
}

func (e *Epoch) record(withSig bool) *rec.Record {
	members := make([]*rec.Record, 0, len(e.Members))
	for _, m := range e.Members {
		members = append(members, rec.New(MemberSchema).SetU8(1, uint8(m.Kind)).SetBytes(2, m.ID[:]).SetU32(3, m.Gen))
	}
	r := rec.New(EpochSchema).
		SetBytes(1, e.MailboxID[:]).
		SetU32(2, e.Number).
		SetI64(3, e.Begin).
		SetU8(4, uint8(e.Reason)).
		SetU8(5, uint8(e.Suite)).
		SetBytes(6, e.ContentPub.Bytes()).
		SetBytes(7, e.MetaPub.Bytes()).
		SetList(8, members)
	if len(e.Discards) > 0 {
		list := make([]*rec.Record, 0, len(e.Discards))
		for _, n := range e.Discards {
			list = append(list, rec.New(DiscardSchema).SetU32(1, n))
		}
		r.SetList(9, list)
	}
	if e.Number > 1 {
		r.SetBytes(10, e.PrevHash[:])
	}
	r.SetBytes(11, e.SignerID[:]).SetU32(12, e.SignerGen)
	if withSig {
		r.SetBytes(13, e.Signature)
	}
	return r
}

// Sign signs the epoch with the identity key of the signer named in it.
func (e *Epoch) Sign(identity ed25519.PrivateKey) error {
	if err := e.check(); err != nil {
		return err
	}
	tbs, err := e.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	sig, err := keys.Sign(identity, keys.DomainEpoch, tbs)
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// Encode returns the canonical encoding of a signed epoch.
func (e *Epoch) Encode() ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: epoch is not signed", ErrRecord)
	}
	return e.record(true).Encode()
}

// VerifySignature checks the signature with the identity key of the
// signer (SignerID, SignerGen); finding that key is the caller's task.
func (e *Epoch) VerifySignature(pub ed25519.PublicKey) error {
	tbs, err := e.record(false).Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	if !keys.Verify(pub, keys.DomainEpoch, tbs, e.Signature) {
		return fmt.Errorf("%w: epoch %d", keys.ErrSignature, e.Number)
	}
	return nil
}

// DecodeEpoch decodes epoch.rec. The signature must be verified
// separately.
func DecodeEpoch(data []byte) (*Epoch, error) {
	r, err := rec.Decode(EpochSchema, data)
	if err != nil {
		return nil, err
	}
	if !r.Has(13) {
		return nil, fmt.Errorf("%w: epoch is not signed", ErrRecord)
	}
	e := &Epoch{
		MailboxID: idFromBytes(r.Bytes(1)),
		Number:    r.U32(2),
		Begin:     r.I64(3),
		Reason:    Reason(r.U8(4)),
		Suite:     envelope.Suite(r.U8(5)),
		SignerID:  idFromBytes(r.Bytes(11)),
		SignerGen: r.U32(12),
		Signature: r.Bytes(13),
	}
	if e.ContentPub, err = ecdh.X25519().NewPublicKey(r.Bytes(6)); err != nil {
		return nil, fmt.Errorf("%w: content key: %v", ErrRecord, err)
	}
	if e.MetaPub, err = ecdh.X25519().NewPublicKey(r.Bytes(7)); err != nil {
		return nil, fmt.Errorf("%w: meta key: %v", ErrRecord, err)
	}
	if r.Has(9) {
		// An empty list is never encoded (canonical form).
		list := r.List(9)
		if len(list) == 0 {
			return nil, fmt.Errorf("%w: empty discards", ErrRecord)
		}
		e.Discards = make([]uint32, 0, len(list))
		for _, d := range list {
			e.Discards = append(e.Discards, d.U32(1))
		}
	}
	if r.Has(10) {
		copy(e.PrevHash[:], r.Bytes(10))
		if e.PrevHash == [32]byte{} {
			return nil, fmt.Errorf("%w: zero previous hash", ErrRecord)
		}
	}
	for _, m := range r.List(8) {
		e.Members = append(e.Members, Member{Kind: MemberKind(m.U8(1)), ID: idFromBytes(m.Bytes(2)), Gen: m.U32(3)})
	}
	if err := e.check(); err != nil {
		return nil, err
	}
	return e, nil
}

// Member returns the user member id, if any. Recovery recipients and
// delegates are not user members.
func (e *Epoch) Member(id ID) (Member, bool) {
	for _, m := range e.Members {
		if m.Kind == MemberUser && m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

// EpochHash is the SHA-256 of an encoded epoch.rec, the link of the chain.
func EpochHash(data []byte) [32]byte { return sha256.Sum256(data) }
