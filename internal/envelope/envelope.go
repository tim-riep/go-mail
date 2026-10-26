// Package envelope implements the .gml file format of section 3 of the
// specification: a preamble, a canonically encoded header, a recipient
// section with the file key wrapped by HPKE for each recipient, the
// content as a sequence of AES-256-GCM blocks in the STREAM construction,
// and an optional trailer with an Ed25519 signature over the ciphertext.
// After the recipient section every part of the file is an element
// "type (1 byte) || length (uint32 big endian) || payload"; the type byte
// says whether the element is a block (ElemBlock), the last block
// (ElemLastBlock) or the trailer (ElemTrailer), so the structure can be
// parsed without any key (3.1, version 1.1).
//
// Everything read from a file is untrusted. Parse checks every length
// against the limits below before allocating, rejects any structural
// deviation, and never panics on malformed input. Decryption is fail
// closed: plaintext is returned only after every block, including the
// last one with its end flag, has authenticated; on any error nothing is
// returned.
//
// No cryptographic primitive is implemented here. HPKE comes from
// crypto/hpke, AES-GCM from crypto/aes and crypto/cipher, HKDF from
// crypto/hkdf, X25519 from crypto/ecdh, Ed25519 from crypto/ed25519 via
// package keys, randomness from crypto/rand unless a reader is injected
// for tests.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/rec"
)

// Format constants (specification 3.1 to 3.5).
const (
	Magic         = "GOML"
	FormatVersion = 1
	PreambleSize  = 6 // magic, version, suite

	MaxHeaderSize     = 4 * 1024
	MaxRecipientsSize = 16 * 1024
	MaxTrailerSize    = 1024
	MaxRecipients     = 4
	MaxExtraSize      = 4096 // kind-specific signed fields

	ChunkSize      = 65536
	MaxBlocks      = 800
	MaxContentSize = MaxBlocks * ChunkSize // 50 MiB
	TagSize        = 16
	MaxBlockSize   = ChunkSize + TagSize // ciphertext of one block

	// Element type bytes (3.1). After the recipient section the file is a
	// sequence of elements matching ElemBlock* ElemLastBlock ElemTrailer?.
	ElemBlock     = 0x01 // a full block, nonce flag 0x00
	ElemLastBlock = 0x02 // the last block, nonce flag 0x01
	ElemTrailer   = 0x03 // the signature trailer

	elemHeaderSize = 1 + 4 // type byte and length

	// MaxFileSize is the largest file Parse accepts.
	MaxFileSize = PreambleSize + 4 + MaxHeaderSize + 4 + MaxRecipientsSize +
		MaxBlocks*(elemHeaderSize+MaxBlockSize) + elemHeaderSize + MaxTrailerSize

	FileKeySize = 32

	encSize        = 32 // DHKEM(X25519) encapsulation
	wrappedKeySize = FileKeySize + TagSize

	labelWrap   = "gomail/v1/wrap"
	aadWrap     = "gomail/v1/aad/wrap"
	aadBlock    = "gomail/v1/aad/block"
	infoContent = "gomail/v1/content"
)

// Exported errors. Every error of this package wraps one of them.
var (
	ErrMagic           = errors.New("envelope: not a .gml file")
	ErrVersion         = errors.New("envelope: unsupported format version")
	ErrSuite           = errors.New("envelope: unsupported or mismatched algorithm suite")
	ErrTruncated       = errors.New("envelope: file is truncated")
	ErrTooLarge        = errors.New("envelope: file or content exceeds the size limit")
	ErrHeader          = errors.New("envelope: invalid header")
	ErrHeaderSize      = errors.New("envelope: header length exceeds the limit")
	ErrRecipients      = errors.New("envelope: invalid recipient section")
	ErrRecipientsSize  = errors.New("envelope: recipient section length exceeds the limit")
	ErrBlockSize       = errors.New("envelope: invalid block length")
	ErrEmptyBlock      = errors.New("envelope: empty block in non-empty content")
	ErrElementType     = errors.New("envelope: unknown element type")
	ErrElement         = errors.New("envelope: invalid element sequence")
	ErrTrailer         = errors.New("envelope: invalid trailer")
	ErrTrailerSize     = errors.New("envelope: trailer length exceeds the limit")
	ErrNoRecipient     = errors.New("envelope: no recipient entry for this key")
	ErrUnwrap          = errors.New("envelope: unwrapping the file key failed")
	ErrDecrypt         = errors.New("envelope: content authentication failed")
	ErrSignature       = errors.New("envelope: signature verification failed")
	ErrSigner          = errors.New("envelope: invalid or unknown signer")
	ErrUnsigned        = errors.New("envelope: file is not signed")
	ErrSignaturePolicy = errors.New("envelope: signed file but no signer resolver given")
	ErrWrap            = errors.New("envelope: wrapping the file key failed")
	ErrRandom          = errors.New("envelope: reading randomness failed")
	ErrClosed          = errors.New("envelope: writer is closed")
)

// Suite identifies the algorithm suite (3.5). The proof of concept knows
// exactly Suite1; every other value is rejected.
type Suite uint8

// Suite1 is HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM and Ed25519.
const Suite1 Suite = 1

// CheckSuiteTransition reports whether an epoch with suite next may follow
// an epoch with suite prev: suites never go backwards (3.5, rule 3).
func CheckSuiteTransition(prev, next Suite) error {
	if prev == 0 || next == 0 {
		return fmt.Errorf("%w: suite 0", ErrSuite)
	}
	if next < prev {
		return fmt.Errorf("%w: suite %d after suite %d", ErrSuite, next, prev)
	}
	return nil
}

// Kind is the file kind in the header.
type Kind uint8

const (
	KindMail    Kind = 1
	KindMeta    Kind = 2
	KindPending Kind = 3
	KindWrap    Kind = 4
	KindIndex   Kind = 5
)

// String returns the name used in the signature domain
// "gomail/v1/sig/<kind>".
func (k Kind) String() string {
	switch k {
	case KindMail:
		return "mail"
	case KindMeta:
		return "meta"
	case KindPending:
		return "pending"
	case KindWrap:
		return "wrap"
	case KindIndex:
		return "index"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

func (k Kind) valid() bool { return k >= KindMail && k <= KindIndex }

// RecipientType says which key a recipient entry is wrapped for.
type RecipientType uint8

const (
	RecipientEpochContent RecipientType = 1
	RecipientEpochMeta    RecipientType = 2
	RecipientUserUnwrap   RecipientType = 3
	RecipientRecovery     RecipientType = 4
)

func (t RecipientType) valid() bool { return t >= RecipientEpochContent && t <= RecipientRecovery }

// SignerType says which kind of key signed the trailer.
type SignerType uint8

const (
	SignerIngest SignerType = 1
	SignerUser   SignerType = 2
)

func (t SignerType) valid() bool { return t == SignerIngest || t == SignerUser }

// Header is the file header (3.1). NoncePrefix and ChunkSize are set by
// the writer; a caller's values are ignored.
type Header struct {
	Kind        Kind
	MailboxID   [16]byte
	Epoch       uint32
	FileID      [16]byte
	NoncePrefix [7]byte
	ChunkSize   uint32
	Created     int64 // milliseconds since 1970 UTC
}

// HeaderSchema is the canonical encoding of the header.
var HeaderSchema = rec.MustSchema("gomail/v1/rec/header",
	rec.Field{Num: 1, Name: "kind", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "mailbox_id", Kind: rec.Bytes, Size: 16, Required: true},
	rec.Field{Num: 3, Name: "epoch", Kind: rec.U32, Required: true},
	rec.Field{Num: 4, Name: "file_id", Kind: rec.Bytes, Size: 16, Required: true},
	rec.Field{Num: 5, Name: "nonce_prefix", Kind: rec.Bytes, Size: 7, Required: true},
	rec.Field{Num: 6, Name: "chunk_size", Kind: rec.U32, Required: true},
	rec.Field{Num: 7, Name: "created", Kind: rec.I64, Required: true},
)

func (h *Header) encode() ([]byte, error) {
	b, err := rec.New(HeaderSchema).
		SetU8(1, uint8(h.Kind)).
		SetBytes(2, h.MailboxID[:]).
		SetU32(3, h.Epoch).
		SetBytes(4, h.FileID[:]).
		SetBytes(5, h.NoncePrefix[:]).
		SetU32(6, h.ChunkSize).
		SetI64(7, h.Created).
		Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeader, err)
	}
	return b, nil
}

func decodeHeader(data []byte) (Header, error) {
	r, err := rec.Decode(HeaderSchema, data)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %v", ErrHeader, err)
	}
	h := Header{Kind: Kind(r.U8(1)), Epoch: r.U32(3), ChunkSize: r.U32(6), Created: r.I64(7)}
	copy(h.MailboxID[:], r.Bytes(2))
	copy(h.FileID[:], r.Bytes(4))
	copy(h.NoncePrefix[:], r.Bytes(5))
	if !h.Kind.valid() {
		return Header{}, fmt.Errorf("%w: unknown kind %d", ErrHeader, h.Kind)
	}
	if h.ChunkSize != ChunkSize {
		return Header{}, fmt.Errorf("%w: chunk size %d", ErrHeader, h.ChunkSize)
	}
	return h, nil
}

// RecipientEntry is one parsed entry of the recipient section.
type RecipientEntry struct {
	Type       RecipientType
	ID         [16]byte
	Gen        uint32
	Enc        []byte // HPKE encapsulated key
	WrappedKey []byte // HPKE ciphertext of the file key
}

// RecipientSchema is one entry; RecipientsSchema is the section.
var (
	RecipientSchema = rec.MustSchema("gomail/v1/rec/recipient",
		rec.Field{Num: 1, Name: "type", Kind: rec.U8, Required: true},
		rec.Field{Num: 2, Name: "id", Kind: rec.Bytes, Size: 16, Required: true},
		rec.Field{Num: 3, Name: "gen", Kind: rec.U32, Required: true},
		rec.Field{Num: 4, Name: "enc", Kind: rec.Bytes, Size: encSize, Required: true},
		rec.Field{Num: 5, Name: "wrapped_key", Kind: rec.Bytes, Size: wrappedKeySize, Required: true},
	)
	RecipientsSchema = rec.MustSchema("gomail/v1/rec/recipients",
		rec.Field{Num: 1, Name: "entries", Kind: rec.List, Elem: RecipientSchema, MaxCount: MaxRecipients, Required: true},
	)
)

type recipientRef struct {
	Type RecipientType
	ID   [16]byte
	Gen  uint32
}

func encodeRecipients(entries []RecipientEntry) ([]byte, error) {
	list := make([]*rec.Record, len(entries))
	for i, e := range entries {
		list[i] = rec.New(RecipientSchema).
			SetU8(1, uint8(e.Type)).
			SetBytes(2, e.ID[:]).
			SetU32(3, e.Gen).
			SetBytes(4, e.Enc).
			SetBytes(5, e.WrappedKey)
	}
	b, err := rec.New(RecipientsSchema).SetList(1, list).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipients, err)
	}
	return b, nil
}

func decodeRecipients(data []byte) ([]RecipientEntry, error) {
	r, err := rec.Decode(RecipientsSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipients, err)
	}
	list := r.List(1)
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrRecipients)
	}
	entries := make([]RecipientEntry, len(list))
	seen := make(map[recipientRef]bool, len(list))
	for i, e := range list {
		entries[i] = RecipientEntry{Type: RecipientType(e.U8(1)), Gen: e.U32(3), Enc: e.Bytes(4), WrappedKey: e.Bytes(5)}
		copy(entries[i].ID[:], e.Bytes(2))
		if !entries[i].Type.valid() {
			return nil, fmt.Errorf("%w: unknown recipient type %d", ErrRecipients, entries[i].Type)
		}
		if entries[i].Gen == 0 {
			return nil, fmt.Errorf("%w: generation 0", ErrRecipients)
		}
		ref := recipientRef{entries[i].Type, entries[i].ID, entries[i].Gen}
		if seen[ref] {
			return nil, fmt.Errorf("%w: duplicate entry", ErrRecipients)
		}
		seen[ref] = true
	}
	return entries, nil
}

// SignerRef identifies the key that signed a trailer.
type SignerRef struct {
	Type SignerType
	ID   [16]byte
	Gen  uint32
}

// Trailer is the parsed signature trailer (3.4).
type Trailer struct {
	Signer    SignerRef
	Signature []byte
}

// TrailerSchema is the canonical encoding of the trailer.
var TrailerSchema = rec.MustSchema("gomail/v1/rec/trailer",
	rec.Field{Num: 1, Name: "signer_type", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "signer_id", Kind: rec.Bytes, Size: 16, Required: true},
	rec.Field{Num: 3, Name: "signer_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 4, Name: "sig", Kind: rec.Bytes, Size: ed25519.SignatureSize, Required: true},
)

func (t *Trailer) encode() ([]byte, error) {
	b, err := rec.New(TrailerSchema).
		SetU8(1, uint8(t.Signer.Type)).
		SetBytes(2, t.Signer.ID[:]).
		SetU32(3, t.Signer.Gen).
		SetBytes(4, t.Signature).
		Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrailer, err)
	}
	return b, nil
}

func decodeTrailer(data []byte) (*Trailer, error) {
	r, err := rec.Decode(TrailerSchema, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrailer, err)
	}
	t := &Trailer{Signer: SignerRef{Type: SignerType(r.U8(1)), Gen: r.U32(3)}, Signature: r.Bytes(4)}
	copy(t.Signer.ID[:], r.Bytes(2))
	if !t.Signer.Type.valid() {
		return nil, fmt.Errorf("%w: unknown signer type %d", ErrTrailer, t.Signer.Type)
	}
	if t.Signer.Gen == 0 {
		return nil, fmt.Errorf("%w: signer generation 0", ErrTrailer)
	}
	return t, nil
}

// SignedSchema is the canonical structure that is signed (3.4): the
// SHA-256 over every byte of the file before the trailer element
// (preamble, header, recipient section and all block elements with their
// type bytes and length fields), the signer, and optional kind-specific
// fields supplied by the caller as an embedded canonical record. The
// signature domain is "gomail/v1/sig/<kind>".
var SignedSchema = rec.MustSchema("gomail/v1/rec/signed",
	rec.Field{Num: 1, Name: "file_hash", Kind: rec.Bytes, Size: sha256.Size, Required: true},
	rec.Field{Num: 2, Name: "signer_type", Kind: rec.U8, Required: true},
	rec.Field{Num: 3, Name: "signer_id", Kind: rec.Bytes, Size: 16, Required: true},
	rec.Field{Num: 4, Name: "signer_gen", Kind: rec.U32, Required: true},
	rec.Field{Num: 5, Name: "extra", Kind: rec.Bytes, MaxLen: MaxExtraSize},
)

func signedStructure(fileHash [sha256.Size]byte, ref SignerRef, extra []byte) ([]byte, error) {
	r := rec.New(SignedSchema).
		SetBytes(1, fileHash[:]).
		SetU8(2, uint8(ref.Type)).
		SetBytes(3, ref.ID[:]).
		SetU32(4, ref.Gen)
	if len(extra) > 0 {
		r.SetBytes(5, extra)
	}
	b, err := r.Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	return b, nil
}

// wrapInfo is the HPKE info of a recipient entry (3.2):
// "gomail/v1/wrap" || 0x00 || type || id || gen, all fixed width.
func wrapInfo(ref recipientRef) []byte {
	info := make([]byte, 0, len(labelWrap)+1+1+16+4)
	info = append(info, labelWrap...)
	info = append(info, 0, uint8(ref.Type))
	info = append(info, ref.ID[:]...)
	return binary.BigEndian.AppendUint32(info, ref.Gen)
}

// aadHash is SHA-256(label || 0x00 || preamble || header), the associated
// data of the wrapping (label aadWrap) and of every block (label aadBlock).
func aadHash(label string, preamble, header []byte) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(preamble)
	h.Write(header)
	return h.Sum(nil)
}

// blockNonce is nonce_prefix || counter (uint32 big endian) || last flag.
func blockNonce(prefix [7]byte, counter uint32, last bool) []byte {
	n := make([]byte, 0, 12)
	n = append(n, prefix[:]...)
	n = binary.BigEndian.AppendUint32(n, counter)
	if last {
		return append(n, 1)
	}
	return append(n, 0)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
