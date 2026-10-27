package store

import (
	"crypto/ecdh"
	"crypto/ed25519"
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
	MaxGenerations = 1024 // generations in user.rec
	MaxMembers     = 64   // members of one epoch
	MaxRecipients  = 100  // envelope recipients in metadata (5.1)
	MaxAddressLen  = 320  // one address
	MaxTextLen     = 4096 // one header value in metadata
	MaxBatch       = 100  // entries of one pending batch (5.4)
	MaxTerms       = 256  // terms of one mail
	MaxTermLen     = 1024 // one term
	MaxJournal     = 3 * MaxRecipients
	MaxPathLen     = 512
)

func id16(n uint8, name string, required bool) rec.Field {
	return rec.Field{Num: n, Name: name, Kind: rec.Bytes, Size: 16, Required: required}
}

func bytes32(n uint8, name string, required bool) rec.Field {
	return rec.Field{Num: n, Name: name, Kind: rec.Bytes, Size: 32, Required: required}
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
// mailbox mbx and epoch. For consistent metadata (file_id = MailID,
// created = Received, version = Version) it equals MetaSignedExtra of the
// header.
func (m *MailMeta) SignedExtra(mbx ID, epoch uint32) ([]byte, error) {
	return rec.New(MetaSignedSchema).SetBytes(1, mbx[:]).SetU32(2, epoch).SetBytes(3, m.MailID[:]).
		SetI64(4, m.Received).SetBytes(5, m.MailHash[:]).SetU32(6, m.Version).Encode()
}

// MetaSignedExtra builds meta-signed of a metadata file from its clear
// header alone (section 7): mailbox, epoch, file_id (the mail ID),
// created (the time of receipt), version, and the SHA-256 of the whole
// mail file. Every value is in the header or a hash over ciphertext, so
// the server can check a metadata signature without keys.
func MetaSignedExtra(h envelope.Header, mailHash [32]byte) ([]byte, error) {
	if h.Kind != envelope.KindMeta {
		return nil, fmt.Errorf("%w: meta-signed of a %s file", ErrRecord, h.Kind)
	}
	if h.Version == 0 || h.Epoch == 0 || ID(h.MailboxID).IsZero() || ID(h.FileID).IsZero() {
		return nil, fmt.Errorf("%w: incomplete header for meta-signed", ErrRecord)
	}
	return rec.New(MetaSignedSchema).SetBytes(1, h.MailboxID[:]).SetU32(2, h.Epoch).SetBytes(3, h.FileID[:]).
		SetI64(4, h.Created).SetBytes(5, mailHash[:]).SetU32(6, h.Version).Encode()
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

// Limits of the pin and of the witness list (translog doc.go "Pin"). The
// package translog keeps constants of the same value (MaxPinFile,
// MaxOrigin, MaxWitnesses, MaxIdentities; store.MaxOrigin is in
// checkpoint.go) and its tests check that they
// agree; store cannot import translog.
const (
	// MaxPinFile is the read limit for identity-<gen>.pin
	// (ReadPlatformPin): the largest pin of fields 1 to 6 and 8 takes about
	// 23 KiB, and the limit leaves room for field 7 should Q8 be decided as
	// proposed (translog.MaxRevoked).
	MaxPinFile = 64 << 10
	// MaxPinWitnesses is the most witnesses of a pin
	// (translog.MaxWitnesses).
	MaxPinWitnesses = 16
	// MaxWitnessName is the longest witness name (witness.MaxName).
	MaxWitnessName = 64
	// MaxPinIdentities is the longest identity list of a pin
	// (translog.MaxIdentities).
	MaxPinIdentities = 256
)

// logSignerName is the note name of the log key (translog.LogSignerName);
// no witness may use it.
const logSignerName = "gomail-log"

// WitnessSchema is one witness: its note name and Ed25519 public key
// (translog doc.go "Pin", field 5; the element of platform/witnesses.rec,
// package witness). The verifier key line is derived
// (note.NewEd25519VerifierKey), so the key hash is never stored and cannot
// disagree with the key.
var WitnessSchema = rec.MustSchema("gomail/v1/rec/witness",
	rec.Field{Num: 1, Name: "name", Kind: rec.String, MaxLen: MaxWitnessName, Required: true},
	rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
)

// PlatformIdentitySchema is one generation of the platform identity in
// the identity list of a pin (field 8).
var PlatformIdentitySchema = rec.MustSchema("gomail/v1/rec/platform-identity",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
)

// PlatformPinSchema is the platform identity a client trusts (2.3, "im
// Client hinterlegt") and the anchor of the transparency log (Q4,
// translog doc.go "Pin"):
//
//	1 gen            the current identity generation
//	2 pub            its key
//	3 dev            1 for a development ceremony, else 0
//	4 origin         the log origin (CheckPinOrigin)
//	5 witnesses      the pinned witnesses (WitnessSchema), unique names and keys
//	6 min_witnesses  quorum: 1 <= min <= len(witnesses), 2*min > len(witnesses)
//	8 identities     every identity generation from 1 to gen (PlatformIdentitySchema)
//
// Field 7 (revoked) is not part of the schema: TODO(ask), Q8 is open. If
// Q8 is decided as proposed, field 7 is an optional list of
// gomail/v1/rec/platform-revoked (1 role u8, 2 gen u32, 3 revoked_at_size
// i64, proposed 4 revoked_at_time i64) with at most translog.MaxRevoked
// elements, so that the largest pin stays below MaxPinFile. Until then a
// pin with field 7 is rejected like any unknown field.
var PlatformPinSchema = rec.MustSchema("gomail/v1/rec/platform-pin",
	rec.Field{Num: 1, Name: "gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 2, Name: "pub", Kind: rec.Bytes, Size: ed25519.PublicKeySize, Required: true},
	rec.Field{Num: 3, Name: "dev", Kind: rec.U8, Required: true},
	rec.Field{Num: 4, Name: "origin", Kind: rec.String, MaxLen: MaxOrigin, Required: true},
	rec.Field{Num: 5, Name: "witnesses", Kind: rec.List, Elem: WitnessSchema, MaxCount: MaxPinWitnesses, Required: true},
	rec.Field{Num: 6, Name: "min_witnesses", Kind: rec.U32, Required: true},
	rec.Field{Num: 8, Name: "identities", Kind: rec.List, Elem: PlatformIdentitySchema, MaxCount: MaxPinIdentities, Required: true},
)

// Witness is a pinned witness.
type Witness struct {
	Name string
	Pub  ed25519.PublicKey
}

// PlatformIdentity is one generation of the platform identity.
type PlatformIdentity struct {
	Gen uint32
	Pub ed25519.PublicKey
}

// PlatformPin is a trusted platform identity together with the anchor of
// the transparency log.
type PlatformPin struct {
	Gen          uint32
	Pub          ed25519.PublicKey
	Dev          bool
	Origin       string
	Witnesses    []Witness
	MinWitnesses int
	// Identities lists every identity generation from 1 to Gen in
	// ascending order; the last element is (Gen, Pub).
	Identities []PlatformIdentity
}

// CheckPinOrigin reports whether o is a valid log origin: 1 to
// MaxOrigin bytes of printable ASCII (0x21 to 0x7e) without "+"
// (translog.CheckOrigin).
func CheckPinOrigin(o string) error {
	if o == "" || len(o) > MaxOrigin {
		return fmt.Errorf("%w: origin length", ErrRecord)
	}
	if !printableNoPlus(o) {
		return fmt.Errorf("%w: origin must be printable ASCII without spaces and '+'", ErrRecord)
	}
	return nil
}

// CheckWitnessName reports whether name is a valid witness name: 1 to
// MaxWitnessName bytes of printable ASCII without "+" (note forbids "+"
// and spaces in names), and not the name of the log signer
// (witness.CheckName).
func CheckWitnessName(name string) error {
	if name == "" || len(name) > MaxWitnessName {
		return fmt.Errorf("%w: witness name length", ErrRecord)
	}
	if !printableNoPlus(name) {
		return fmt.Errorf("%w: witness name must be printable ASCII without spaces and '+'", ErrRecord)
	}
	if name == logSignerName {
		return fmt.Errorf("%w: witness name of the log signer", ErrRecord)
	}
	return nil
}

func printableNoPlus(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '+' {
			return false
		}
	}
	return true
}

// CheckWitnessQuorum reports whether min of n witnesses is an admissible
// quorum: 1 <= min <= n and 2*min > n (translog.CheckQuorum, which gives
// the reasons).
func CheckWitnessQuorum(min, n int) error {
	if n < 1 || min < 1 || min > n || 2*min <= n {
		return fmt.Errorf("%w: quorum %d of %d admits a split view (2*min must exceed the number of witnesses)", ErrRecord, min, n)
	}
	return nil
}

// CheckWitnesses checks a witness list with its quorum: at most
// MaxPinWitnesses witnesses, valid and unique names, keys of
// ed25519.PublicKeySize bytes and unique, and CheckWitnessQuorum.
func CheckWitnesses(list []Witness, min int) error {
	if len(list) > MaxPinWitnesses {
		return fmt.Errorf("%w: %d witnesses", ErrRecord, len(list))
	}
	if err := CheckWitnessQuorum(min, len(list)); err != nil {
		return err
	}
	for i, w := range list {
		if err := CheckWitnessName(w.Name); err != nil {
			return err
		}
		if len(w.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: witness key length", ErrRecord)
		}
		for _, o := range list[:i] {
			if o.Name == w.Name || o.Pub.Equal(w.Pub) {
				return fmt.Errorf("%w: duplicate witness", ErrRecord)
			}
		}
	}
	return nil
}

// CheckPinIdentities checks the identity list of a pin (field 8,
// translog.CheckIdentities): 1 to MaxPinIdentities elements with the
// generations 1, 2, ... in this order, every key of
// ed25519.PublicKeySize bytes and distinct from the others, and the last
// element equal to (gen, pub).
func CheckPinIdentities(list []PlatformIdentity, gen uint32, pub ed25519.PublicKey) error {
	if len(list) == 0 || len(list) > MaxPinIdentities {
		return fmt.Errorf("%w: identity list has %d generations", ErrRecord, len(list))
	}
	for i, id := range list {
		if id.Gen != uint32(i+1) {
			return fmt.Errorf("%w: identity generations must run from 1 without gaps", ErrRecord)
		}
		if len(id.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: identity key length", ErrRecord)
		}
		for _, o := range list[:i] {
			if o.Pub.Equal(id.Pub) {
				return fmt.Errorf("%w: identity key repeated", ErrRecord)
			}
		}
	}
	last := list[len(list)-1]
	if last.Gen != gen || !last.Pub.Equal(pub) {
		return fmt.Errorf("%w: identity list does not end with the current generation", ErrRecord)
	}
	return nil
}

func (p *PlatformPin) check() error {
	if p.Gen == 0 || len(p.Pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid platform pin", ErrRecord)
	}
	if err := CheckPinOrigin(p.Origin); err != nil {
		return err
	}
	if err := CheckWitnesses(p.Witnesses, p.MinWitnesses); err != nil {
		return err
	}
	return CheckPinIdentities(p.Identities, p.Gen, p.Pub)
}

// Encode returns the canonical encoding after checking every rule that
// DecodePlatformPin checks.
func (p *PlatformPin) Encode() ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	dev := uint8(0)
	if p.Dev {
		dev = 1
	}
	ws := make([]*rec.Record, 0, len(p.Witnesses))
	for _, w := range p.Witnesses {
		ws = append(ws, rec.New(WitnessSchema).SetString(1, w.Name).SetBytes(2, w.Pub))
	}
	ids := make([]*rec.Record, 0, len(p.Identities))
	for _, id := range p.Identities {
		ids = append(ids, rec.New(PlatformIdentitySchema).SetU32(1, id.Gen).SetBytes(2, id.Pub))
	}
	return rec.New(PlatformPinSchema).SetU32(1, p.Gen).SetBytes(2, p.Pub).SetU8(3, dev).
		SetString(4, p.Origin).SetList(5, ws).SetU32(6, uint32(p.MinWitnesses)).SetList(8, ids).Encode()
}

// DecodePlatformPin decodes a pin strictly: the dev flag 0 or 1, a valid
// origin, a witness list with unique names and keys and an admissible
// quorum (CheckWitnesses, translog doc.go "Witness quorum"), and an
// identity list that passes CheckPinIdentities.
func DecodePlatformPin(data []byte) (*PlatformPin, error) {
	r, err := rec.Decode(PlatformPinSchema, data)
	if err != nil {
		return nil, err
	}
	if r.U8(3) > 1 || r.U32(6) > MaxPinWitnesses {
		return nil, fmt.Errorf("%w: invalid platform pin", ErrRecord)
	}
	p := &PlatformPin{Gen: r.U32(1), Pub: ed25519.PublicKey(r.Bytes(2)), Dev: r.U8(3) == 1, Origin: r.String(4), MinWitnesses: int(r.U32(6))}
	for _, e := range r.List(5) {
		p.Witnesses = append(p.Witnesses, Witness{Name: e.String(1), Pub: ed25519.PublicKey(e.Bytes(2))})
	}
	for _, e := range r.List(8) {
		p.Identities = append(p.Identities, PlatformIdentity{Gen: e.U32(1), Pub: ed25519.PublicKey(e.Bytes(2))})
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
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
