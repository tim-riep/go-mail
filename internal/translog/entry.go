package translog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// ErrEntry reports a log entry that is not well formed: not canonical,
// an unknown kind, content of the wrong record type, or a key that does
// not match the key derived from the content.
var ErrEntry = errors.New("translog: invalid log entry")

// Kind is the kind of a log entry (2.7: "jede user.rec, jede epoch.rec,
// jede Adresszuordnung, jedes Zertifikat und jede Nachfolge der
// Plattformidentität").
type Kind uint8

const (
	// KindUser is a complete users/<id>/user.rec (gomail/v1/rec/user),
	// logged once per generation (2.2 rule 3).
	KindUser Kind = 1
	// KindEpoch is an epoch.rec (gomail/v1/rec/epoch).
	KindEpoch Kind = 2
	// KindAddress is a signed address assignment (gomail/v1/rec/address).
	KindAddress Kind = 3
	// KindPlatform is a platform certificate (gomail/v1/rec/platform-cert,
	// file admin-<gen>.cert or ingest-<gen>.cert) or a succession of the
	// platform identity (gomail/v1/rec/platform-succ, file
	// identity-<gen>.succ).
	KindPlatform Kind = 4
)

// String returns the name of the kind as used in paths under log/keys/.
func (k Kind) String() string {
	switch k {
	case KindUser:
		return "user"
	case KindEpoch:
		return "epoch"
	case KindAddress:
		return "address"
	case KindPlatform:
		return "platform"
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// Limits of entries.
const (
	// MaxContent is the largest record that can be logged: a user.rec
	// with all its generations (store.MaxUserFile). The encoded entry
	// stays below rec.MaxRecordSize.
	MaxContent = store.MaxUserFile
	// MaxSubject is the longest subject (an address, see
	// store.AddressSchema, or a platform file name).
	MaxSubject = 254
	// MaxEntryFile is the read limit for log/entries/<index>.rec.
	MaxEntryFile = MaxContent + 1024
)

// Key identifies what an entry is about. Two entries with the same key
// are duplicates; only the first one in log order counts and every later
// one is rejected (PHASE2-KLAERUNGEN K2 rules 3 and 4: the order in the
// log replaces the order of writes under the mailbox lock).
//
// Subject is what Lookup searches by; Seq distinguishes the entries of
// one subject:
//
//	kind      subject                           seq
//	user      user ID (16 bytes)                generation = number of generations in the user.rec
//	epoch     mailbox ID (16 bytes)             epoch number
//	address   normalized address (ASCII)        valid_from (ms since 1970 UTC, >= 0)
//	platform  file name ("ingest-2.cert",       0
//	          "admin-1.cert", "identity-2.succ")
//
// The key is always derived from the content (KeyOf); an entry whose
// stored key differs from the derived one is invalid (ErrEntry). That
// way no entry can claim a key other than the one its signed content
// carries, and duplicate detection cannot be bypassed by a wrong key.
type Key struct {
	Kind    Kind
	Subject []byte
	Seq     int64
}

// Equal reports whether k and o are the same key.
func (k Key) Equal(o Key) bool {
	return k.Kind == o.Kind && k.Seq == o.Seq && bytes.Equal(k.Subject, o.Subject)
}

// Entry is one entry of the log.
type Entry struct {
	Key
	// Content is the unchanged canonical encoding of the logged record,
	// byte for byte the file in the data directory (user.rec, epoch.rec,
	// the address record, the .cert or .succ file).
	Content []byte
	// Index is the position in the log (0-based, the tlog record number).
	// It is not part of the encoding: the position is fixed by the tree.
	Index int64
}

// EntrySchema is the encoding of an entry in log/entries/<index>.rec
// (section 4 "log/entries/"). The leaf hash of the tree is
// tlog.RecordHash over exactly this encoding (see LeafHash).
var EntrySchema = rec.MustSchema("gomail/v1/rec/log-entry",
	rec.Field{Num: 1, Name: "kind", Kind: rec.U8, Required: true},
	rec.Field{Num: 2, Name: "subject", Kind: rec.Bytes, MaxLen: MaxSubject, Required: true},
	rec.Field{Num: 3, Name: "seq", Kind: rec.I64, Required: true},
	rec.Field{Num: 4, Name: "content", Kind: rec.Bytes, MaxLen: MaxContent, Required: true},
)

// NewEntry builds the entry for a record of the given kind; the key is
// derived from the content. Index is left at -1 (not yet in the log).
func NewEntry(kind Kind, content []byte) (*Entry, error) {
	k, err := KeyOf(kind, content)
	if err != nil {
		return nil, err
	}
	return &Entry{Key: k, Content: content, Index: -1}, nil
}

// Encode returns the canonical encoding of the entry. It fails unless
// the key is the one derived from the content.
func (e *Entry) Encode() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("%w: nil", ErrEntry)
	}
	k, err := KeyOf(e.Kind, e.Content)
	if err != nil {
		return nil, err
	}
	if !k.Equal(e.Key) {
		return nil, fmt.Errorf("%w: key does not match the content", ErrEntry)
	}
	b, err := rec.New(EntrySchema).SetU8(1, uint8(e.Kind)).SetBytes(2, e.Subject).SetI64(3, e.Seq).SetBytes(4, e.Content).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	return b, nil
}

// DecodeEntry decodes an entry read from log/entries/<index>.rec and
// checks that its key is the one derived from its content. The index is
// set by the caller (it comes from the position, not from the file) and
// must satisfy 0 <= index < MaxTreeSize (ErrEntry otherwise).
//
// Cost: KeyOf decodes the content strictly, and a user.rec verifies its
// whole chain of generation certificates; a user.rec with 1,024
// generations takes about 100 ms. MaxContent stays as it is (it bounds
// the cost); the client's audit index (doc.go "Audit") stores what it
// derived from an entry and never decodes or checks an entry twice.
func DecodeEntry(data []byte, index int64) (*Entry, error) {
	e, _, err := decodeEntry(data, index)
	return e, err
}

// decodeEntry is DecodeEntry that also returns the decoded content
// (decodeContent).
func decodeEntry(data []byte, index int64) (*Entry, any, error) {
	if index < 0 || index >= MaxTreeSize {
		return nil, nil, fmt.Errorf("%w: index out of range", ErrEntry)
	}
	r, err := rec.Decode(EntrySchema, data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	e := &Entry{Key: Key{Kind: Kind(r.U8(1)), Subject: r.Bytes(2), Seq: r.I64(3)}, Content: r.Bytes(4), Index: index}
	k, obj, err := decodeContent(e.Kind, e.Content)
	if err != nil {
		return nil, nil, err
	}
	if !k.Equal(e.Key) {
		return nil, nil, fmt.Errorf("%w: key does not match the content", ErrEntry)
	}
	return e, obj, nil
}

// keyID is the identifier of a key in the audit index and the relative
// path below log/keys/: <kind>/<hex SHA-256(subject)>/<seq>. Subjects
// (addresses, IDs) never appear in clear.
func keyID(k Key) string {
	return subjectID(k.Kind, k.Subject) + "/" + strconv.FormatInt(k.Seq, 10)
}

// subjectID is <kind>/<hex SHA-256(subject)>.
func subjectID(kind Kind, subject []byte) string {
	h := sha256.Sum256(subject)
	return kind.String() + "/" + hex.EncodeToString(h[:])
}

// LeafHash is the hash of an encoded entry in the Merkle tree:
// tlog.RecordHash, that is SHA-256(0x00 || encoding) as in RFC 6962.
func LeafHash(encoded []byte) tlog.Hash { return tlog.RecordHash(encoded) }

// KindOf returns the kind of a record by its type string. Every record
// starts with its type and a NUL (3.6 rule 5), so the kind is never
// ambiguous.
func KindOf(content []byte) (Kind, error) {
	switch {
	case hasType(content, store.UserSchema):
		return KindUser, nil
	case hasType(content, store.EpochSchema):
		return KindEpoch, nil
	case hasType(content, store.AddressSchema):
		return KindAddress, nil
	case hasType(content, keys.PlatformCertSchema), hasType(content, keys.PlatformSuccessionSchema):
		return KindPlatform, nil
	}
	return 0, fmt.Errorf("%w: not a loggable record", ErrEntry)
}

func hasType(b []byte, s *rec.Schema) bool { return bytes.HasPrefix(b, s.Prefix()) }

// KeyOf decodes content as a record of the given kind (strictly, with
// the decoders of store and keys) and returns its key. It checks the
// structure only; signatures are checked where the record is used
// (Check* of Log, see doc.go), except that a user.rec is only decodable
// with a valid chain of generation certificates.
func KeyOf(kind Kind, content []byte) (Key, error) {
	k, _, err := decodeContent(kind, content)
	return k, err
}

// decodeContent is KeyOf that also returns the decoded record:
// *store.User, *store.Epoch, *store.AddressAssignment,
// *keys.PlatformCert or *keys.PlatformSuccession. The validity rules use
// it so that an entry is decoded only once.
func decodeContent(kind Kind, content []byte) (Key, any, error) {
	if len(content) > MaxContent {
		return Key{}, nil, fmt.Errorf("%w: content too large", ErrEntry)
	}
	switch kind {
	case KindUser:
		u, err := store.DecodeUser(content)
		if err != nil {
			return Key{}, nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		return Key{Kind: kind, Subject: clone(u.ID[:]), Seq: int64(len(u.Generations))}, u, nil
	case KindEpoch:
		e, err := store.DecodeEpoch(content)
		if err != nil {
			return Key{}, nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		return Key{Kind: kind, Subject: clone(e.MailboxID[:]), Seq: int64(e.Number)}, e, nil
	case KindAddress:
		a, err := store.DecodeAddressAssignment(content)
		if err != nil {
			return Key{}, nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		if a.ValidFrom < 0 {
			return Key{}, nil, fmt.Errorf("%w: negative valid_from", ErrEntry)
		}
		return Key{Kind: kind, Subject: []byte(a.Address), Seq: a.ValidFrom}, a, nil
	case KindPlatform:
		name, obj, err := platformName(content)
		if err != nil {
			return Key{}, nil, err
		}
		return Key{Kind: kind, Subject: []byte(name), Seq: 0}, obj, nil
	}
	return Key{}, nil, fmt.Errorf("%w: unknown kind %d", ErrEntry, kind)
}

// platformName returns the file name of section 4 under which a
// certificate or succession is stored in platform/, and the decoded
// record.
func platformName(content []byte) (string, any, error) {
	switch {
	case hasType(content, keys.PlatformCertSchema):
		c, err := keys.DecodePlatformCert(content)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		return certName(c.Role, c.Gen), c, nil
	case hasType(content, keys.PlatformSuccessionSchema):
		s, err := keys.DecodePlatformSuccession(content)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		return succName(s.Gen), s, nil
	}
	return "", nil, fmt.Errorf("%w: not a platform certificate or succession", ErrEntry)
}

// certName returns admin-<gen>.cert or ingest-<gen>.cert.
func certName(role keys.Role, gen uint32) string {
	r := "admin"
	if role == keys.RoleIngest {
		r = "ingest"
	}
	return store.PlatformFileName(r, gen, "cert")
}

// succName returns identity-<gen>.succ.
func succName(gen uint32) string { return store.PlatformFileName("identity", gen, "succ") }

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// ----------------------------------------------------------------- paths

// Layout of data/log/ (section 4, extended by lock, tree.rec and keys/).
// All paths are relative to the data directory and use "/".
const (
	// Dir is the log directory inside the data directory.
	Dir = "log"
	// LockFile is the record lock of the log (9.1, POSIX record lock as
	// in store). Every writer holds it: appenders (client, server,
	// ceremony) and the server when it writes a head.
	LockFile = Dir + "/lock"
	// TreeFile holds the committed size of the log and the root hash of
	// the tree of that size (TreeSchema). Writing it is the commit point
	// of an append; entries, tiles and keys at or beyond the size are
	// leftovers of an interrupted append and do not exist.
	TreeFile = Dir + "/tree.rec"
	// EntriesDir holds entries/<index>.rec, one file per entry, written
	// once (exclusive create), never replaced.
	EntriesDir = Dir + "/entries"
	// TilesDir holds the stored hashes of the tree as tlog tiles of
	// height TileHeight: tree/<tlog.Tile.Path()>, for example
	// tree/tile/8/0/001 (full) or tree/tile/8/0/002.p/17 (partial). Every
	// path is written once; a partial tile of another width has another
	// path.
	TilesDir = Dir + "/tree"
	// HeadsDir holds heads/<size>.sig: the signed head of that size as a
	// note (log signature and all witness cosignatures collected so far).
	HeadsDir = Dir + "/heads"
	// KeysDir holds the duplicate index:
	// keys/<kind>/<hex SHA-256(subject)>/<seq>, each containing the
	// decimal index of the entry with that key. It is derived data that
	// makes Append and Lookup cheap; every reader that matters (the
	// server before signing, the client when auditing) checks it against
	// the entries and never trusts it alone.
	KeysDir = Dir + "/keys"
	// TileHeight is the height of the tiles (as in the Go checksum
	// database): a full tile holds 256 hashes.
	TileHeight = 8
)

// TreeSchema is log/tree.rec: the committed size and the root hash of
// the tree of that size (tlog.TreeHash). It is not signed; the hash lets
// every reader detect tiles that were changed after the commit. A size
// outside 0..MaxTreeSize is ErrConsistency on open.
var TreeSchema = rec.MustSchema("gomail/v1/rec/log-tree",
	rec.Field{Num: 1, Name: "size", Kind: rec.I64, Required: true},
	rec.Field{Num: 2, Name: "root_hash", Kind: rec.Bytes, Size: tlog.HashSize, Required: true},
)

// EntryPath returns log/entries/<index>.rec, index in decimal without
// leading zeros.
func EntryPath(index int64) string {
	return path.Join(EntriesDir, strconv.FormatInt(index, 10)+".rec")
}

// HeadPath returns log/heads/<size>.sig.
func HeadPath(size int64) string {
	return path.Join(HeadsDir, strconv.FormatInt(size, 10)+".sig")
}

// TilePath returns the path of a tile under log/tree/.
func TilePath(t tlog.Tile) string { return path.Join(TilesDir, t.Path()) }

// KeyPath returns the duplicate index file of a key:
// log/keys/<kind>/<hex SHA-256(subject)>/<seq>. Hashing the subject
// keeps addresses and binary IDs out of file names.
func KeyPath(k Key) string { return path.Join(KeysDir, keyID(k)) }
