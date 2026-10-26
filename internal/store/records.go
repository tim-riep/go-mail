package store

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// ErrRecord reports a record that is structurally valid canonical
// encoding but violates a rule of its type.
var ErrRecord = errors.New("store: invalid record")

// Limits of the records defined here (DECISIONS D48).
const (
	MaxGenerations = 1024  // generations in user.rec
	MaxMembers     = 64    // members of one epoch
	MaxNameSize    = 8192  // sealed mailbox name in mailbox.rec
	MaxRecipients  = 100   // envelope recipients in metadata (5.1)
	MaxAddressLen  = 320   // one address
	MaxTextLen     = 4096  // one header value in metadata
	MaxBatch       = 100   // entries of one pending batch (5.4)
	MaxTerms       = 256   // terms of one mail
	MaxTermLen     = 1024  // one term
	MaxJournal     = 3 * MaxRecipients
	MaxPathLen     = 512
)

func id16(n uint8, name string, required bool) rec.Field {
	return rec.Field{Num: n, Name: name, Kind: rec.Bytes, Size: 16, Required: required}
}

func bytes32(n uint8, name string, required bool) rec.Field {
	return rec.Field{Num: n, Name: name, Kind: rec.Bytes, Size: 32, Required: required}
}

// ---------------------------------------------------------------- user.rec

// UserSchema is users/<user-id>/user.rec (2.2): the user ID, the public
// root key and the generation certificates 1..n, each signed by the root.
// The record itself carries no signature: the table of signature domains
// in 3.7 has no entry for it (SPEC-ISSUES S16). Its content is protected
// by the root signatures of the certificates; the binding of user ID and
// root key is a task of the transparency log (TODO(phase3-translog)).
var UserSchema = rec.MustSchema("gomail/v1/rec/user",
	id16(1, "user_id", true),
	rec.Field{Num: 2, Name: "root_pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "generations", Kind: rec.List, Elem: keys.GenerationCertSchema, MaxCount: MaxGenerations, Required: true},
)

// User is a decoded and verified user.rec.
type User struct {
	ID          ID
	RootPub     ed25519.PublicKey
	Generations []*keys.GenerationCert // generations 1..n in order
}

// Encode returns the canonical encoding after checking the chain.
func (u *User) Encode() ([]byte, error) {
	if err := u.check(); err != nil {
		return nil, err
	}
	list := make([]*rec.Record, 0, len(u.Generations))
	for _, g := range u.Generations {
		b, err := g.Encode()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecord, err)
		}
		r, err := rec.Decode(keys.GenerationCertSchema, b)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecord, err)
		}
		list = append(list, r)
	}
	return rec.New(UserSchema).SetBytes(1, u.ID[:]).SetBytes(2, u.RootPub).SetList(3, list).Encode()
}

func (u *User) check() error {
	if u.ID.IsZero() {
		return fmt.Errorf("%w: zero user id", ErrRecord)
	}
	if len(u.RootPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: root key length", ErrRecord)
	}
	if err := keys.VerifyGenerationChain(u.RootPub, u.Generations); err != nil {
		return fmt.Errorf("%w: %v", ErrRecord, err)
	}
	return nil
}

// DecodeUser decodes user.rec and verifies the generation chain against
// the root key in it.
func DecodeUser(data []byte) (*User, error) {
	r, err := rec.Decode(UserSchema, data)
	if err != nil {
		return nil, err
	}
	u := &User{ID: idFromBytes(r.Bytes(1)), RootPub: ed25519.PublicKey(r.Bytes(2))}
	for _, e := range r.List(3) {
		b, err := e.Encode()
		if err != nil {
			return nil, err
		}
		c, err := keys.DecodeGenerationCert(b)
		if err != nil {
			return nil, err
		}
		u.Generations = append(u.Generations, c)
	}
	if err := u.check(); err != nil {
		return nil, err
	}
	return u, nil
}

// Current returns the newest generation; all older ones are revoked by
// their successors (2.2).
func (u *User) Current() *keys.GenerationCert { return u.Generations[len(u.Generations)-1] }

// Generation returns generation gen or nil.
func (u *User) Generation(gen uint32) *keys.GenerationCert {
	if gen == 0 || uint64(gen) > uint64(len(u.Generations)) {
		return nil
	}
	return u.Generations[gen-1]
}

// ------------------------------------------------------------- mailbox.rec

// MailboxSchema is mailboxes/<id>/mailbox.rec (section 4): mailbox ID,
// the highest epoch number (head of the epoch chain), the ID of the inbox
// folder the server delivers to, and the mailbox name as a sealed .gml
// file (kind meta, epoch 1, signed by the creating member). The record is
// not signed (3.7 has no short name for it); a client detects a reset
// head with its local state (2.4).
var MailboxSchema = rec.MustSchema("gomail/v1/rec/mailbox",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	id16(3, "inbox", true),
	rec.Field{Num: 4, Name: "name", Kind: rec.Bytes, MaxLen: MaxNameSize, Required: true},
)

// Mailbox is a decoded mailbox.rec.
type Mailbox struct {
	ID    ID
	Epoch uint32 // head of the epoch chain
	Inbox ID
	Name  []byte // sealed .gml
}

// Encode returns the canonical encoding.
func (m *Mailbox) Encode() ([]byte, error) {
	if m.ID.IsZero() || m.Inbox.IsZero() || m.Epoch == 0 || len(m.Name) == 0 {
		return nil, fmt.Errorf("%w: incomplete mailbox", ErrRecord)
	}
	return rec.New(MailboxSchema).SetBytes(1, m.ID[:]).SetU32(2, m.Epoch).SetBytes(3, m.Inbox[:]).SetBytes(4, m.Name).Encode()
}

// DecodeMailbox decodes mailbox.rec.
func DecodeMailbox(data []byte) (*Mailbox, error) {
	r, err := rec.Decode(MailboxSchema, data)
	if err != nil {
		return nil, err
	}
	m := &Mailbox{ID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2), Inbox: idFromBytes(r.Bytes(3)), Name: r.Bytes(4)}
	if m.ID.IsZero() || m.Inbox.IsZero() || m.Epoch == 0 {
		return nil, fmt.Errorf("%w: incomplete mailbox", ErrRecord)
	}
	return m, nil
}

// --------------------------------------------------------------- epoch.rec

// Reason is why an epoch began (2.4, 2.6).
type Reason uint8

const (
	ReasonInitial       Reason = 1 // first epoch of a mailbox
	ReasonMonthly       Reason = 2 // regular monthly change, created in advance
	ReasonMemberRemoved Reason = 3 // a member was removed (2.5)
	ReasonSubstitution  Reason = 4 // begin or end of a substitution (2.5)
	ReasonDeleted       Reason = 5 // deletion marker (2.6)
	ReasonImmediate     Reason = 6 // immediate begin after the supply ran out (2.4)
)

func (r Reason) valid() bool { return r >= ReasonInitial && r <= ReasonImmediate }

// MemberKind distinguishes users and the recovery recipient (2.4).
type MemberKind uint8

const (
	MemberUser     MemberKind = 1
	MemberRecovery MemberKind = 2
)

// Member is one entry of the member list of an epoch: a user with the
// generation its keys are wrapped for, or the recovery recipient.
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

// EpochSchema is mailboxes/<id>/epochs/<n>/epoch.rec (2.4): number,
// begin, reason, suite, public keys, members with generation and the
// SHA-256 of the previous epoch.rec, signed by the identity of the
// creating member under the short name "epoch" (3.7). The mailbox ID and
// the signer are part of the record so that an epoch cannot be moved to
// another mailbox and the verifier knows the signing key (DECISIONS D49).
var EpochSchema = rec.MustSchema("gomail/v1/rec/epoch",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "number", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "begin", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "reason", Kind: rec.U8, Required: true},
	rec.Field{Num: 5, Name: "suite", Kind: rec.U8, Required: true},
	bytes32(6, "content_pub", true),
	bytes32(7, "meta_pub", true),
	rec.Field{Num: 8, Name: "members", Kind: rec.List, Elem: MemberSchema, MaxCount: MaxMembers, Required: true},
	bytes32(9, "prev_hash", false),
	id16(10, "signer_id", true),
	rec.Field{Num: 11, Name: "signer_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 12, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
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
	case (e.Number == 1) != (e.Reason == ReasonInitial):
		return fmt.Errorf("%w: reason initial is for epoch 1 only", ErrRecord)
	}
	seen := map[[17]byte]bool{}
	recovery := 0
	for _, m := range e.Members {
		if m.Kind != MemberUser && m.Kind != MemberRecovery || m.ID.IsZero() || m.Gen == 0 {
			return fmt.Errorf("%w: invalid member", ErrRecord)
		}
		var k [17]byte
		k[0] = byte(m.Kind)
		copy(k[1:], m.ID[:])
		if seen[k] {
			return fmt.Errorf("%w: duplicate member", ErrRecord)
		}
		seen[k] = true
		if m.Kind == MemberRecovery {
			recovery++
		}
	}
	if recovery > 1 {
		return fmt.Errorf("%w: more than one recovery recipient", ErrRecord)
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
	if e.Number > 1 {
		r.SetBytes(9, e.PrevHash[:])
	}
	r.SetBytes(10, e.SignerID[:]).SetU32(11, e.SignerGen)
	if withSig {
		r.SetBytes(12, e.Signature)
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
	if !r.Has(12) {
		return nil, fmt.Errorf("%w: epoch is not signed", ErrRecord)
	}
	e := &Epoch{
		MailboxID: idFromBytes(r.Bytes(1)),
		Number:    r.U32(2),
		Begin:     r.I64(3),
		Reason:    Reason(r.U8(4)),
		Suite:     envelope.Suite(r.U8(5)),
		SignerID:  idFromBytes(r.Bytes(10)),
		SignerGen: r.U32(11),
		Signature: r.Bytes(12),
	}
	if e.ContentPub, err = ecdh.X25519().NewPublicKey(r.Bytes(6)); err != nil {
		return nil, fmt.Errorf("%w: content key: %v", ErrRecord, err)
	}
	if e.MetaPub, err = ecdh.X25519().NewPublicKey(r.Bytes(7)); err != nil {
		return nil, fmt.Errorf("%w: meta key: %v", ErrRecord, err)
	}
	if r.Has(9) {
		copy(e.PrevHash[:], r.Bytes(9))
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

// Member returns the user member id, if any.
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

// ErrChain reports a broken epoch chain (2.4).
var ErrChain = errors.New("store: broken epoch chain")

// CheckLink checks that next follows prev in the chain of one mailbox:
// same mailbox, number + 1, prev_hash = SHA-256 of prev's encoding, begin
// not earlier, suite not older (3.5), and next signed by a user who is a
// member of prev (only members create epochs, 2.4). The signature itself
// is checked by the caller with the signer's key.
func CheckLink(prev *Epoch, prevData []byte, next *Epoch) error {
	switch {
	case next.MailboxID != prev.MailboxID:
		return fmt.Errorf("%w: epoch %d belongs to another mailbox", ErrChain, next.Number)
	case next.Number != prev.Number+1:
		return fmt.Errorf("%w: epoch %d follows epoch %d", ErrChain, next.Number, prev.Number)
	case next.PrevHash != EpochHash(prevData):
		return fmt.Errorf("%w: epoch %d does not name epoch %d", ErrChain, next.Number, prev.Number)
	case next.Begin < prev.Begin:
		return fmt.Errorf("%w: epoch %d begins before epoch %d", ErrChain, next.Number, prev.Number)
	}
	if err := envelope.CheckSuiteTransition(prev.Suite, next.Suite); err != nil {
		return fmt.Errorf("%w: %v", ErrChain, err)
	}
	if _, ok := prev.Member(next.SignerID); !ok {
		return fmt.Errorf("%w: epoch %d signed by a non-member", ErrChain, next.Number)
	}
	return nil
}

// ------------------------------------------------------- wrap (epoch keys)

// EpochKeysSchema is the plaintext of members/<user-id>.wrap (2.4): the
// three private epoch keys, bound to mailbox and epoch.
var EpochKeysSchema = rec.MustSchema("gomail/v1/rec/epoch-keys",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	bytes32(3, "content", true),
	bytes32(4, "meta", true),
	bytes32(5, "index", true),
)

// EpochKeys are the private keys of one epoch.
type EpochKeys struct {
	MailboxID ID
	Epoch     uint32
	Content   *ecdh.PrivateKey
	Meta      *ecdh.PrivateKey
	Index     [32]byte
}

// Encode returns the canonical encoding. The caller wipes the result.
func (k *EpochKeys) Encode() ([]byte, error) {
	if k.MailboxID.IsZero() || k.Epoch == 0 || k.Content == nil || k.Meta == nil {
		return nil, fmt.Errorf("%w: incomplete epoch keys", ErrRecord)
	}
	c, m := k.Content.Bytes(), k.Meta.Bytes()
	defer keys.Wipe(c)
	defer keys.Wipe(m)
	return rec.New(EpochKeysSchema).SetBytes(1, k.MailboxID[:]).SetU32(2, k.Epoch).SetBytes(3, c).SetBytes(4, m).SetBytes(5, k.Index[:]).Encode()
}

// DecodeEpochKeys decodes the plaintext of a wrap.
func DecodeEpochKeys(data []byte) (*EpochKeys, error) {
	r, err := rec.Decode(EpochKeysSchema, data)
	if err != nil {
		return nil, err
	}
	k := &EpochKeys{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2)}
	c, m, ix := r.Bytes(3), r.Bytes(4), r.Bytes(5)
	defer keys.Wipe(c)
	defer keys.Wipe(m)
	defer keys.Wipe(ix)
	if k.Content, err = ecdh.X25519().NewPrivateKey(c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecord, err)
	}
	if k.Meta, err = ecdh.X25519().NewPrivateKey(m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecord, err)
	}
	copy(k.Index[:], ix)
	if k.MailboxID.IsZero() || k.Epoch == 0 {
		return nil, fmt.Errorf("%w: incomplete epoch keys", ErrRecord)
	}
	return k, nil
}

// Matches reports whether the keys belong to epoch e: same mailbox, same
// number and public keys equal to those in the signed epoch.rec.
func (k *EpochKeys) Matches(e *Epoch) bool {
	return k.MailboxID == e.MailboxID && k.Epoch == e.Number &&
		k.Content.PublicKey().Equal(e.ContentPub) && k.Meta.PublicKey().Equal(e.MetaPub)
}

// Zero wipes the index key. ecdh keys cannot be wiped (DECISIONS D04).
func (k *EpochKeys) Zero() {
	keys.Wipe(k.Index[:])
	k.Content, k.Meta = nil, nil
}

// ---------------------------------------------------------------- metadata

// RcptSchema is one envelope recipient in the metadata.
var RcptSchema = rec.MustSchema("gomail/v1/rec/rcpt",
	rec.Field{Num: 1, Name: "address", Kind: rec.String, MaxLen: MaxAddressLen, Required: true},
)

// MailMetaSchema is the plaintext of <mail-id>.meta.gml (5.2 step 3):
// version counter (section 7), receipt, the SHA-256 of the whole
// encrypted mail file (section 7, S06), size, folder, flags, envelope and
// the header fields a client lists. Header fields are cleaned (valid
// UTF-8, NFC, no control characters) and may be cut (DECISIONS D51).
var MailMetaSchema = rec.MustSchema("gomail/v1/rec/mail-meta",
	rec.Field{Num: 1, Name: "version", Kind: rec.U32, Required: true},
	id16(2, "mail_id", true),
	rec.Field{Num: 3, Name: "received", Kind: rec.I64, Required: true},
	bytes32(4, "mail_hash", true),
	rec.Field{Num: 5, Name: "size", Kind: rec.U32, Required: true},
	id16(6, "folder", true),
	rec.Field{Num: 7, Name: "flags", Kind: rec.U32, Required: true},
	rec.Field{Num: 8, Name: "envelope_from", Kind: rec.String, MaxLen: MaxAddressLen},
	rec.Field{Num: 9, Name: "recipients", Kind: rec.List, Elem: RcptSchema, MaxCount: MaxRecipients, Required: true},
	rec.Field{Num: 10, Name: "from", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 11, Name: "to", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 12, Name: "cc", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 13, Name: "subject", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 14, Name: "date", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 15, Name: "message_id", Kind: rec.String, MaxLen: MaxTextLen},
	rec.Field{Num: 16, Name: "attachment", Kind: rec.U8},
	rec.Field{Num: 17, Name: "headers_parsed", Kind: rec.U8, Required: true},
)

// MailMeta is the content of a metadata file.
type MailMeta struct {
	Version       uint32
	MailID        ID
	Received      int64 // milliseconds since 1970 UTC
	MailHash      [32]byte
	Size          uint32
	Folder        ID
	Flags         uint32
	EnvelopeFrom  string
	Recipients    []string
	From          string
	To            string
	Cc            string
	Subject       string
	Date          string
	MessageID     string
	Attachment    bool
	HeadersParsed bool
}

// Encode returns the canonical encoding.
func (m *MailMeta) Encode() ([]byte, error) {
	if m.Version == 0 || m.MailID.IsZero() || m.Folder.IsZero() || len(m.Recipients) == 0 {
		return nil, fmt.Errorf("%w: incomplete metadata", ErrRecord)
	}
	rcpts := make([]*rec.Record, 0, len(m.Recipients))
	for _, a := range m.Recipients {
		rcpts = append(rcpts, rec.New(RcptSchema).SetString(1, a))
	}
	r := rec.New(MailMetaSchema).
		SetU32(1, m.Version).SetBytes(2, m.MailID[:]).SetI64(3, m.Received).SetBytes(4, m.MailHash[:]).
		SetU32(5, m.Size).SetBytes(6, m.Folder[:]).SetU32(7, m.Flags)
	setOpt := func(n uint8, s string) {
		if s != "" {
			r.SetString(n, s)
		}
	}
	setOpt(8, m.EnvelopeFrom)
	r.SetList(9, rcpts)
	setOpt(10, m.From)
	setOpt(11, m.To)
	setOpt(12, m.Cc)
	setOpt(13, m.Subject)
	setOpt(14, m.Date)
	setOpt(15, m.MessageID)
	if m.Attachment {
		r.SetU8(16, 1)
	}
	parsed := uint8(0)
	if m.HeadersParsed {
		parsed = 1
	}
	return r.SetU8(17, parsed).Encode()
}

// DecodeMailMeta decodes the plaintext of a metadata file.
func DecodeMailMeta(data []byte) (*MailMeta, error) {
	r, err := rec.Decode(MailMetaSchema, data)
	if err != nil {
		return nil, err
	}
	m := &MailMeta{
		Version: r.U32(1), MailID: idFromBytes(r.Bytes(2)), Received: r.I64(3),
		Size: r.U32(5), Folder: idFromBytes(r.Bytes(6)), Flags: r.U32(7),
		EnvelopeFrom: r.String(8), From: r.String(10), To: r.String(11), Cc: r.String(12),
		Subject: r.String(13), Date: r.String(14), MessageID: r.String(15),
	}
	copy(m.MailHash[:], r.Bytes(4))
	for _, e := range r.List(9) {
		m.Recipients = append(m.Recipients, e.String(1))
	}
	// Optional flags are present only when set, so the encoding of every
	// value is unique (compare DECISIONS D18).
	if r.Has(16) {
		if r.U8(16) != 1 {
			return nil, fmt.Errorf("%w: attachment flag", ErrRecord)
		}
		m.Attachment = true
	}
	switch r.U8(17) {
	case 0:
	case 1:
		m.HeadersParsed = true
	default:
		return nil, fmt.Errorf("%w: headers_parsed flag", ErrRecord)
	}
	if m.Version == 0 || m.MailID.IsZero() || m.Folder.IsZero() || len(m.Recipients) == 0 {
		return nil, fmt.Errorf("%w: incomplete metadata", ErrRecord)
	}
	// Optional strings are present only when not empty.
	for _, n := range []uint8{8, 10, 11, 12, 13, 14, 15} {
		if r.Has(n) && r.String(n) == "" {
			return nil, fmt.Errorf("%w: empty optional field %d", ErrRecord, n)
		}
	}
	return m, nil
}

// MetaSignedSchema is the kind-specific part of the signed structure of a
// metadata file (section 7): mailbox, epoch, mail ID, receipt, SHA-256 of
// the encrypted mail file and the version counter. The SHA-256 of the
// encrypted metadata and the ingest generation are already part of the
// signed structure of envelope (file_hash, signer_gen).
var MetaSignedSchema = rec.MustSchema("gomail/v1/rec/meta-signed",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	id16(3, "mail_id", true),
	rec.Field{Num: 4, Name: "received", Kind: rec.I64, Required: true},
	bytes32(5, "mail_hash", true),
	rec.Field{Num: 6, Name: "version", Kind: rec.U32, Required: true},
)

// SignedExtra returns the extra fields signed with a metadata file of
// mailbox mbx and epoch.
func (m *MailMeta) SignedExtra(mbx ID, epoch uint32) ([]byte, error) {
	return rec.New(MetaSignedSchema).SetBytes(1, mbx[:]).SetU32(2, epoch).SetBytes(3, m.MailID[:]).
		SetI64(4, m.Received).SetBytes(5, m.MailHash[:]).SetU32(6, m.Version).Encode()
}

// ------------------------------------------------------------ term lists

// TermSchema is one term of a mail (5.4).
var TermSchema = rec.MustSchema("gomail/v1/rec/term",
	rec.Field{Num: 1, Name: "term", Kind: rec.String, MaxLen: MaxTermLen, Required: true},
)

// PendingEntrySchema is one mail in a term list: either the marker
// "unprocessed" (5.2 step 3) or the terms of the mail (5.4).
var PendingEntrySchema = rec.MustSchema("gomail/v1/rec/pending-entry",
	id16(1, "mail_id", true),
	rec.Field{Num: 2, Name: "unprocessed", Kind: rec.U8},
	rec.Field{Num: 3, Name: "terms", Kind: rec.List, Elem: TermSchema, MaxCount: MaxTerms},
)

// PendingSchema is the plaintext of pending/<n>/<batch-id>.gml: mailbox,
// epoch and up to 100 entries (5.4). A marker is a pending file with one
// unprocessed entry whose file ID is the mail ID.
var PendingSchema = rec.MustSchema("gomail/v1/rec/pending",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "entries", Kind: rec.List, Elem: PendingEntrySchema, MaxCount: MaxBatch, Required: true},
)

// PendingEntry is one mail of a term list.
type PendingEntry struct {
	MailID      ID
	Unprocessed bool
	Terms       []string
}

// Pending is the content of a term list or marker.
type Pending struct {
	MailboxID ID
	Epoch     uint32
	Entries   []PendingEntry
}

// Encode returns the canonical encoding.
func (p *Pending) Encode() ([]byte, error) {
	if p.MailboxID.IsZero() || p.Epoch == 0 || len(p.Entries) == 0 {
		return nil, fmt.Errorf("%w: empty term list", ErrRecord)
	}
	entries := make([]*rec.Record, 0, len(p.Entries))
	for _, e := range p.Entries {
		if e.MailID.IsZero() || e.Unprocessed && len(e.Terms) > 0 {
			return nil, fmt.Errorf("%w: invalid term list entry", ErrRecord)
		}
		r := rec.New(PendingEntrySchema).SetBytes(1, e.MailID[:])
		if e.Unprocessed {
			r.SetU8(2, 1)
		} else {
			terms := make([]*rec.Record, 0, len(e.Terms))
			for _, t := range e.Terms {
				terms = append(terms, rec.New(TermSchema).SetString(1, t))
			}
			r.SetList(3, terms)
		}
		entries = append(entries, r)
	}
	return rec.New(PendingSchema).SetBytes(1, p.MailboxID[:]).SetU32(2, p.Epoch).SetList(3, entries).Encode()
}

// DecodePending decodes a term list or marker.
func DecodePending(data []byte) (*Pending, error) {
	r, err := rec.Decode(PendingSchema, data)
	if err != nil {
		return nil, err
	}
	p := &Pending{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2)}
	if p.MailboxID.IsZero() || p.Epoch == 0 {
		return nil, fmt.Errorf("%w: term list without mailbox or epoch", ErrRecord)
	}
	entries := r.List(3)
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty term list", ErrRecord)
	}
	for _, e := range entries {
		pe := PendingEntry{MailID: idFromBytes(e.Bytes(1))}
		if pe.MailID.IsZero() {
			return nil, fmt.Errorf("%w: zero mail id", ErrRecord)
		}
		// Exactly one of "unprocessed = 1" and "terms" is present.
		switch {
		case e.Has(2) && !e.Has(3) && e.U8(2) == 1:
			pe.Unprocessed = true
		case !e.Has(2) && e.Has(3):
			for _, t := range e.List(3) {
				pe.Terms = append(pe.Terms, t.String(1))
			}
		default:
			return nil, fmt.Errorf("%w: invalid term list entry", ErrRecord)
		}
		p.Entries = append(p.Entries, pe)
	}
	return p, nil
}

// ------------------------------------------------------------ epoch note

// EpochNoteSchema is mailboxes/<id>/epoch-fallback.rec: the server's note
// that it kept using the last epoch because no epoch for the current
// month existed (2.4, "verwendet die zuletzt vorhandene weiter und
// vermerkt das"). It holds no content, only the epoch, the first and last
// receipt time and the number of mails.
var EpochNoteSchema = rec.MustSchema("gomail/v1/rec/epoch-note",
	id16(1, "mailbox_id", true),
	rec.Field{Num: 2, Name: "epoch", Kind: rec.U32, Required: true},
	rec.Field{Num: 3, Name: "first", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "last", Kind: rec.I64, Required: true},
	rec.Field{Num: 5, Name: "count", Kind: rec.U32, Required: true},
)

// EpochNote is a decoded epoch-fallback.rec.
type EpochNote struct {
	MailboxID   ID
	Epoch       uint32
	First, Last int64
	Count       uint32
}

// Encode returns the canonical encoding.
func (n *EpochNote) Encode() ([]byte, error) {
	return rec.New(EpochNoteSchema).SetBytes(1, n.MailboxID[:]).SetU32(2, n.Epoch).SetI64(3, n.First).SetI64(4, n.Last).SetU32(5, n.Count).Encode()
}

// DecodeEpochNote decodes epoch-fallback.rec.
func DecodeEpochNote(data []byte) (*EpochNote, error) {
	r, err := rec.Decode(EpochNoteSchema, data)
	if err != nil {
		return nil, err
	}
	return &EpochNote{MailboxID: idFromBytes(r.Bytes(1)), Epoch: r.U32(2), First: r.I64(3), Last: r.I64(4), Count: r.U32(5)}, nil
}

// ---------------------------------------------------------------- journal

// MoveSchema is one rename of a spool transaction.
var MoveSchema = rec.MustSchema("gomail/v1/rec/move",
	rec.Field{Num: 1, Name: "src", Kind: rec.String, MaxLen: MaxPathLen, Required: true},
	rec.Field{Num: 2, Name: "dst", Kind: rec.String, MaxLen: MaxPathLen, Required: true},
)

// JournalSchema is spool/<txn>/journal.rec: the renames of one accepted
// mail from spool/ into the mailboxes, relative to the data directory.
// While it exists, the transaction is not committed; recovery undoes
// every rename it lists (DECISIONS D52).
var JournalSchema = rec.MustSchema("gomail/v1/rec/journal",
	rec.Field{Num: 1, Name: "moves", Kind: rec.List, Elem: MoveSchema, MaxCount: MaxJournal, Required: true},
)

// Move is one rename.
type Move struct{ Src, Dst string }

// EncodeJournal encodes the moves.
func EncodeJournal(moves []Move) ([]byte, error) {
	list := make([]*rec.Record, 0, len(moves))
	for _, m := range moves {
		list = append(list, rec.New(MoveSchema).SetString(1, m.Src).SetString(2, m.Dst))
	}
	return rec.New(JournalSchema).SetList(1, list).Encode()
}

// DecodeJournal decodes the moves. Every path must be a clean relative
// path below the data directory.
func DecodeJournal(data []byte) ([]Move, error) {
	r, err := rec.Decode(JournalSchema, data)
	if err != nil {
		return nil, err
	}
	var moves []Move
	for _, e := range r.List(1) {
		m := Move{Src: e.String(1), Dst: e.String(2)}
		if !safeRel(m.Src) || !safeRel(m.Dst) {
			return nil, fmt.Errorf("%w: unsafe path in journal", ErrRecord)
		}
		moves = append(moves, m)
	}
	return moves, nil
}

// safeRel accepts relative slash-separated paths whose elements are
// non-empty, not "." or "..", and consist of [a-z0-9.-].
func safeRel(p string) bool {
	if p == "" || p[0] == '/' {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == "" || el == "." || el == ".." {
			return false
		}
		for i := 0; i < len(el); i++ {
			c := el[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ------------------------------------------------- platform keys and pins

// Role of a platform key file.
const (
	KeyRoleIdentity uint8 = 0
	KeyRoleAdmin          = uint8(keys.RoleAdmin)
	KeyRoleIngest         = uint8(keys.RoleIngest)
)

// PlatformKeySchema is a private platform key file written by
// gomail-ceremony (never into the data directory): role, generation and
// the 32-byte Ed25519 seed.
var PlatformKeySchema = rec.MustSchema("gomail/v1/rec/platform-key",
	rec.Field{Num: 1, Name: "role", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "gen", Kind: rec.U32, Required: true},
	bytes32(3, "seed", true),
)

// EncodePlatformKey encodes a private key file. The caller wipes the result.
func EncodePlatformKey(role uint8, gen uint32, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize || gen == 0 {
		return nil, fmt.Errorf("%w: invalid platform key", ErrRecord)
	}
	return rec.New(PlatformKeySchema).SetU8(1, role).SetU32(2, gen).SetBytes(3, priv.Seed()).Encode()
}

// DecodePlatformKey decodes a private key file.
func DecodePlatformKey(data []byte) (role uint8, gen uint32, priv ed25519.PrivateKey, err error) {
	r, err := rec.Decode(PlatformKeySchema, data)
	if err != nil {
		return 0, 0, nil, err
	}
	seed := r.Bytes(3)
	defer keys.Wipe(seed)
	if r.U32(2) == 0 || r.U8(1) > KeyRoleIngest {
		return 0, 0, nil, fmt.Errorf("%w: invalid platform key", ErrRecord)
	}
	return r.U8(1), r.U32(2), ed25519.NewKeyFromSeed(seed), nil
}

// PlatformPinSchema is the platform identity a client trusts (2.3, "im
// Client hinterlegt"): generation, public key and whether it comes from a
// development ceremony. A client accepts a development identity only
// together with --insecure-no-log.
var PlatformPinSchema = rec.MustSchema("gomail/v1/rec/platform-pin",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "dev", Kind: rec.U8, Required: true},
)

// PlatformPin is a trusted platform identity.
type PlatformPin struct {
	Gen uint32
	Pub ed25519.PublicKey
	Dev bool
}

// Encode returns the canonical encoding.
func (p *PlatformPin) Encode() ([]byte, error) {
	dev := uint8(0)
	if p.Dev {
		dev = 1
	}
	return rec.New(PlatformPinSchema).SetU32(1, p.Gen).SetBytes(2, p.Pub).SetU8(3, dev).Encode()
}

// DecodePlatformPin decodes a pin.
func DecodePlatformPin(data []byte) (*PlatformPin, error) {
	r, err := rec.Decode(PlatformPinSchema, data)
	if err != nil {
		return nil, err
	}
	if r.U32(1) == 0 || r.U8(3) > 1 {
		return nil, fmt.Errorf("%w: invalid platform pin", ErrRecord)
	}
	return &PlatformPin{Gen: r.U32(1), Pub: ed25519.PublicKey(r.Bytes(2)), Dev: r.U8(3) == 1}, nil
}

// ------------------------------------------------------------------- text

// CleanText makes s storable in a record string field of at most max
// bytes (3.6 rule 3): invalid UTF-8 becomes U+FFFD, control characters
// other than tab become spaces, the result is in NFC and cut at a
// character boundary so that it stays in NFC.
func CleanText(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) > 4*max+16 {
		s = s[:4*max+16]
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = norm.NFC.String(s)
	// Normalizing a prefix can make it longer again (a few characters
	// expand under NFC); the cut point shrinks on every round, so the loop
	// ends.
	for limit := max; len(s) > max; limit-- {
		cut := limit
		if cut > len(s) {
			cut = len(s)
		}
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = norm.NFC.String(s[:cut])
	}
	return s
}


// ------------------------------------------------------ address assignment

// AddressSchema is a signed address assignment (2.3): address, mailbox,
// valid from, generation of the admin key and the signature of the admin
// key under the short name "address" (3.7) over the record without
// field 5. It goes into the transparency log; addresses.json is only the
// server's working copy.
var AddressSchema = rec.MustSchema("gomail/v1/rec/address",
	rec.Field{Num: 1, Name: "address", Kind: rec.String, MaxLen: 254, Required: true},
	id16(2, "mailbox_id", true),
	rec.Field{Num: 3, Name: "valid_from", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "admin_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 5, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize},
)

// AddressAssignment is a decoded address record.
type AddressAssignment struct {
	Address   string
	MailboxID ID
	ValidFrom int64
	AdminGen  uint32
	Signature []byte
}

func (a *AddressAssignment) record(withSig bool) *rec.Record {
	r := rec.New(AddressSchema).SetString(1, a.Address).SetBytes(2, a.MailboxID[:]).SetI64(3, a.ValidFrom).SetU32(4, a.AdminGen)
	if withSig {
		r.SetBytes(5, a.Signature)
	}
	return r
}

func (a *AddressAssignment) check() error {
	if n, err := NormalizeAddress(a.Address); err != nil || n != a.Address {
		return fmt.Errorf("%w: address not normalized", ErrRecord)
	}
	if a.MailboxID.IsZero() || a.AdminGen == 0 {
		return fmt.Errorf("%w: incomplete address assignment", ErrRecord)
	}
	return nil
}

// Sign signs the assignment with the admin key of generation AdminGen.
func (a *AddressAssignment) Sign(admin ed25519.PrivateKey) error {
	if err := a.check(); err != nil {
		return err
	}
	tbs, err := a.record(false).Encode()
	if err != nil {
		return err
	}
	a.Signature, err = keys.Sign(admin, keys.DomainAddress, tbs)
	return err
}

// Encode returns the canonical encoding of a signed assignment.
func (a *AddressAssignment) Encode() ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: address assignment is not signed", ErrRecord)
	}
	return a.record(true).Encode()
}

// Verify checks the signature with the admin key.
func (a *AddressAssignment) Verify(admin ed25519.PublicKey) error {
	tbs, err := a.record(false).Encode()
	if err != nil {
		return err
	}
	if !keys.Verify(admin, keys.DomainAddress, tbs, a.Signature) {
		return keys.ErrSignature
	}
	return nil
}

// DecodeAddressAssignment decodes a signed address record.
func DecodeAddressAssignment(data []byte) (*AddressAssignment, error) {
	r, err := rec.Decode(AddressSchema, data)
	if err != nil {
		return nil, err
	}
	if !r.Has(5) {
		return nil, fmt.Errorf("%w: address assignment is not signed", ErrRecord)
	}
	a := &AddressAssignment{Address: r.String(1), MailboxID: idFromBytes(r.Bytes(2)), ValidFrom: r.I64(3), AdminGen: r.U32(4), Signature: r.Bytes(5)}
	if err := a.check(); err != nil {
		return nil, err
	}
	return a, nil
}
