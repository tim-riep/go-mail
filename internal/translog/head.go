package translog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// ErrHead reports a tree head that is malformed, has a wrong origin,
// lacks a valid log signature, goes back in time or lies in the future.
var ErrHead = errors.New("translog: invalid tree head")

// Head format and limits (QUESTIONS Q4, 3.7 last paragraph).
const (
	// LogSignerName is the note signer name of the log key (Q4). The key
	// itself is a parameter (NewLogSigner); with Q4 it is the ingest key.
	LogSignerName = "gomail-log"
	// MaxOrigin is the longest origin. Requirement on task 02: the
	// record gomail/v1/rec/checkpoint, which task 02 adds to store in
	// parallel and which does not exist yet, must allow an origin of 128
	// bytes (doc.go "Client checkpoints").
	MaxOrigin = 128
	// MaxTreeSize is the largest tree size (and the bound of every entry
	// index, which is below it) this module accepts: in a head, in a
	// proof, in tree.rec, in state.json and in the witness protocol.
	// Everything larger is refused before any tlog function is called
	// (task 03b, finding A5: tlog.CheckTree and tlog.CheckRecord do not
	// return for sizes above 2^62, because maxpow2 overflows).
	//
	// Why 2^40: the log holds users, epochs, address assignments and
	// platform certificates, a few entries per user and month; 2^40
	// (about 10^12) entries would need about 2^40 entry files and 64 TiB
	// of tree hashes, far beyond any plausible PoC or production log,
	// while every proof stays below 2*40 hashes and every tlog loop over
	// the bits of a size runs at most 40 times, with a margin of 2^22 to
	// the overflow of tlog. It also keeps sizes exact in a float64 (2^53)
	// for any tool that prints them.
	MaxTreeSize int64 = 1 << 40
	// MaxHeadText is the longest head text: origin, size, hash, time.
	MaxHeadText = MaxOrigin + 20 + 45 + 26 + 4
	// MaxHeadNote is the read limit for a signed head (heads/<n>.sig, the
	// HTTP bodies of the witness protocol): the text and up to
	// MaxSignatures signature lines.
	MaxHeadNote = 16 << 10
	// MaxWitnesses is the most witnesses a pin or platform/witnesses.rec
	// may list (witness.MaxWitnesses is this constant).
	MaxWitnesses = 16
	// MaxSignatures is the most signature lines a head may carry: exactly
	// one log signature and one cosignature per witness. Task 03d finding
	// 10: the reserve for a second log key during an ingest rotation is
	// dropped. For the tree of a head at most one ingest generation
	// Covers its time line (LogKey.Covers), and since clients know every
	// certificate in platform/ before they open a head (Verifier.LogKeys,
	// task 03d finding 1), the server signs each head with exactly that
	// generation and stores only that log line (Operator.PublishHead);
	// a second log signature would count for nobody.
	MaxSignatures = 1 + MaxWitnesses
	// MaxHeadAge is the freshness limit of 2.3: a client whose last
	// verified head is older processes no new signatures.
	MaxHeadAge = 24 * time.Hour
	// MaxPendingHeadAge is the freshness limit while an own appended
	// entry is pending (Verifier.Fresh, doc.go "Withheld entries", task
	// 03d finding 7): MaxHeadAge - HeadInterval, 23 hours. A server may
	// keep re-signing heads with a time line that stays at the append
	// time + HeadInterval (witnesses accept an equal time), which never
	// counts as a newer head; the client then stops at the latest
	// HeadInterval + MaxPendingHeadAge = 24 hours after the append, as
	// 2.7 demands ("Zurückhalten eines Widerrufs über 24 Stunden"), not
	// after 25 hours. Reading: the price is that an outage stops a client
	// with a pending entry one hour earlier than one without.
	MaxPendingHeadAge = MaxHeadAge - HeadInterval
	// MaxClockSkew is how far a head time may lie in the future of the
	// verifier's clock (same tolerance as the clock rules of 2.4).
	MaxClockSkew = 5 * time.Minute
	// HeadInterval is the longest time the server lets pass between two
	// signed heads, even when the log does not grow, so that clients and
	// witnesses always find a head well inside MaxHeadAge.
	HeadInterval = time.Hour
)

const timePrefix = "time "

// Head is a tree head of the log: the text of a checkpoint
//
//	<origin>\n
//	<size>\n
//	<root hash, base64>\n
//	time <milliseconds since 1970 UTC>\n
//
// signed as a golang.org/x/mod/sumdb/note by the log key under the name
// LogSignerName and cosigned by witnesses with their own note keys
// (2.7, Q4). The first three lines are the checkpoint format of the Go
// checksum ecosystem (C2SP tlog-checkpoint) with the origin as first
// line; the fourth line is an extension line that only this log uses.
// Witnesses sign the same text, so the time is covered by every
// signature.
//
// Strict form (ParseHeadText): exactly these four lines; the origin is
// 1 to MaxOrigin bytes of printable ASCII (0x21 to 0x7e) without "+";
// size is decimal without sign or leading zeros, at least 1 (a head
// of the empty log is never signed: the ceremony logs the platform
// certificates before the server signs its first head) and at most
// MaxTreeSize; the hash is
// standard base64 with padding of exactly 32 bytes; time is decimal
// without sign or leading zeros. Anything else is rejected.
type Head struct {
	Origin string
	Size   int64
	Hash   tlog.Hash
	Time   int64 // milliseconds since 1970 UTC, clock of the server
	// Sigs are the signatures verified by the verifiers passed to
	// OpenHead (log and witnesses); signatures by unknown keys are not
	// listed and never count.
	Sigs []note.Signature
	// Note is the signed note as read (heads/<size>.sig, HTTP body).
	Note []byte
}

// Text returns the head text (the note text that is signed).
func (h *Head) Text() ([]byte, error) {
	if err := checkOrigin(h.Origin); err != nil {
		return nil, err
	}
	if h.Size < 1 || h.Size > MaxTreeSize || h.Time < 0 {
		return nil, fmt.Errorf("%w: size or time out of range", ErrHead)
	}
	var b bytes.Buffer
	b.WriteString(h.Origin)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(h.Size, 10))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(h.Hash[:]))
	b.WriteByte('\n')
	b.WriteString(timePrefix)
	b.WriteString(strconv.FormatInt(h.Time, 10))
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// ParseHeadText parses a head text in the strict form described at Head.
// Sigs and Note stay empty.
func ParseHeadText(text []byte) (*Head, error) {
	if len(text) > MaxHeadText {
		return nil, fmt.Errorf("%w: text too long", ErrHead)
	}
	s := string(text)
	if !strings.HasSuffix(s, "\n") {
		return nil, fmt.Errorf("%w: missing final newline", ErrHead)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != 4 {
		return nil, fmt.Errorf("%w: a head has exactly four lines", ErrHead)
	}
	h := &Head{Origin: lines[0]}
	if err := checkOrigin(h.Origin); err != nil {
		return nil, err
	}
	size, err := parseDecimal(lines[1])
	if err != nil || size < 1 || size > MaxTreeSize {
		return nil, fmt.Errorf("%w: size", ErrHead)
	}
	h.Size = size
	raw, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(raw) != tlog.HashSize || base64.StdEncoding.EncodeToString(raw) != lines[2] {
		return nil, fmt.Errorf("%w: root hash", ErrHead)
	}
	copy(h.Hash[:], raw)
	t, ok := strings.CutPrefix(lines[3], timePrefix)
	if !ok {
		return nil, fmt.Errorf("%w: time line", ErrHead)
	}
	if h.Time, err = parseDecimal(t); err != nil {
		return nil, fmt.Errorf("%w: time", ErrHead)
	}
	return h, nil
}

// parseDecimal accepts a non-negative decimal int64 without sign and
// without leading zeros ("0" itself is allowed).
func parseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrHead
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrHead
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func checkOrigin(o string) error {
	if o == "" || len(o) > MaxOrigin {
		return fmt.Errorf("%w: origin length", ErrHead)
	}
	for i := 0; i < len(o); i++ {
		if c := o[i]; c < 0x21 || c > 0x7e || c == '+' {
			return fmt.Errorf("%w: origin must be printable ASCII without spaces and '+'", ErrHead)
		}
	}
	return nil
}

// CheckOrigin reports whether o is a valid origin (see Head).
func CheckOrigin(o string) error { return checkOrigin(o) }

// OpenHead parses a signed head (heads/<size>.sig or an HTTP body). It
// verifies every signature line whose key is in known (note.Open: a
// known key with an invalid signature is an error) and parses the text
// strictly. It does not decide whether the signatures suffice: that is
// Verifier.CheckHead for clients and the witness rules for witnesses.
// A note without any signature by a known key is rejected.
//
// Poisoned signature lines (task 03b, finding A2-10): note.Open verifies
// every line whose name and key hash belong to a known key and fails the
// whole note on the first invalid one. A line with the name and key hash
// of a pinned witness but a wrong signature, anywhere in heads/<n>.sig,
// therefore makes the head unopenable for every client. That is a denial
// of service, not a loss of trust: whoever can write heads/ can delete
// the file anyway, and no forged signature is ever accepted. The server
// prevents it on its side: it stores only lines it verified itself
// (Operator.PublishHead, POST /gomail/log/cosign), so an invalid
// cosignature never reaches heads/. OpenHead keeps note.Open's
// behaviour (fail closed on any invalid signature by a known key)
// instead of parsing signature lines itself.
func OpenHead(msg []byte, known note.Verifiers) (*Head, error) {
	if len(msg) > MaxHeadNote {
		return nil, fmt.Errorf("%w: signed head too long", ErrHead)
	}
	n, err := note.Open(msg, known)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHead, err)
	}
	if len(n.Sigs)+len(n.UnverifiedSigs) > MaxSignatures {
		return nil, fmt.Errorf("%w: too many signatures", ErrHead)
	}
	h, err := ParseHeadText([]byte(n.Text))
	if err != nil {
		return nil, err
	}
	h.Sigs = n.Sigs
	h.Note = append([]byte(nil), msg...)
	return h, nil
}

// NewLogVerifier returns the note verifier of a log key: name
// LogSignerName, key hash as defined by note for Ed25519 keys. With Q4
// the client builds one verifier per certified ingest generation that
// may sign heads (see Verifier.LogKeys).
func NewLogVerifier(pub ed25519.PublicKey) (note.Verifier, error) {
	vkey, err := note.NewEd25519VerifierKey(LogSignerName, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHead, err)
	}
	return note.NewVerifier(vkey)
}

// NewLogSigner returns the note signer of the log for an Ed25519 key.
// The key is a parameter (Q4 proposes the ingest key, the only private
// key the server holds); the signer keeps a reference to priv and never
// copies the seed into a string, so the caller can wipe priv after use.
//
// Why reusing the ingest key does not confuse signatures: every
// signature under 3.7 is over "gomail/v1/sig/" || short name || 0x00 ||
// bytes, while a note text never contains a NUL (note forbids control
// characters other than newline, and Head.Text produces none). The two
// message sets are disjoint.
func NewLogSigner(priv ed25519.PrivateKey) (note.Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: log key has wrong length", ErrHead)
	}
	v, err := NewLogVerifier(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &logSigner{hash: v.KeyHash(), priv: priv}, nil
}

type logSigner struct {
	hash uint32
	priv ed25519.PrivateKey
}

func (s *logSigner) Name() string    { return LogSignerName }
func (s *logSigner) KeyHash() uint32 { return s.hash }
func (s *logSigner) Sign(msg []byte) ([]byte, error) {
	if bytes.IndexByte(msg, 0) >= 0 {
		// Never sign anything that could be a message of 3.7.
		return nil, fmt.Errorf("%w: refusing to sign a text with NUL", ErrHead)
	}
	return ed25519.Sign(s.priv, msg), nil
}
