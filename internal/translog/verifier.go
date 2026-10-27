package translog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
)

// Errors of the log. Every error returned by this package wraps exactly
// one of them (ErrPending also wraps ErrNotInLog, ErrWithheld also wraps
// ErrStale, ErrUnloggedSigner also wraps ErrPrerequisite), so callers use
// errors.Is. Messages never contain addresses or record contents.
var (
	// ErrNotInLog: the record, or the entry with that key, is not in the
	// tree of the reference head (see doc.go "Reference head").
	ErrNotInLog = errors.New("translog: not in the log")
	// ErrPending: the entry exists beyond the reference head; it becomes
	// checkable with the next head. Callers treat it like ErrNotInLog
	// (fail closed) but may tell the user to sync later.
	ErrPending = fmt.Errorf("%w: not yet covered by a verified head", ErrNotInLog)
	// ErrMismatch: the log holds an entry with the same key but other
	// content, or the address is assigned to another mailbox: the data
	// directory contradicts the log (2.7 "Entfernen oder Ändern eines
	// Logeintrags", 2.3 "stilles Umleiten"). Also: a succession
	// identity-<g>.succ whose generation g is in the identity list of the
	// anchor names another key than the list (the log contradicts the
	// pin; the entry is invalid for this anchor, doc.go "Validity rules",
	// task 03c finding 3, task 03d finding 10).
	ErrMismatch = errors.New("translog: data directory contradicts the log")
	// ErrSuperseded: a newer entry of the same subject exists (a user.rec
	// with more generations); the presented record is a rollback.
	ErrSuperseded = errors.New("translog: a newer entry exists")
	// ErrDuplicate: an entry with the same key is already in the log
	// (K2 rules 3 and 4: the first entry wins).
	ErrDuplicate = errors.New("translog: duplicate log entry")
	// ErrOrder: the entry violates a validity rule (doc.go "Validity
	// rules") that no later entry can repair: a signature that does not
	// verify with the key the log provides, a signer who is not a member
	// of the previous epoch or whose generation was revoked before, a
	// broken epoch chain (prev_hash, discards, begin), a user.rec that
	// does not extend the logged one, an address valid_from that does
	// not increase. Such an entry is never loggable; only on ErrOrder may
	// a member replace an unlogged epoch.rec in store (doc.go "Who
	// writes").
	ErrOrder = errors.New("translog: log entry violates a validity rule")
	// ErrPrerequisite: an entry this one depends on is not in the log
	// yet (epoch n-1 of the mailbox, the user entry of the signer
	// generation, the admin certificate, the previous platform
	// generation). Unlike ErrOrder it is transient: the appender logs
	// the missing entry first (it is in the data directory) and appends
	// again. It is never a reason to replace a record in store.
	ErrPrerequisite = errors.New("translog: an entry this one depends on is not in the log yet")
	// ErrUnloggedSigner: the user entry (signer_id, signer_gen) an epoch
	// entry depends on is not in the log. Any member may then log the
	// signer's user.rec from the data directory; if that does not yield
	// the generation, the epoch counts as ErrOrder (doc.go "Who writes",
	// task 03c finding 2).
	ErrUnloggedSigner = fmt.Errorf("%w: user entry of the signer", ErrPrerequisite)
	// ErrConsistency: a head is not an extension of the last verified
	// head, a proof does not verify, two heads of one size differ, or the
	// files under log/ do not match the committed tree.
	ErrConsistency = errors.New("translog: log is inconsistent")
	// ErrWitness: a head carries fewer valid witness cosignatures than
	// required (2.7 "Zeugen (verbindlich)").
	ErrWitness = errors.New("translog: not enough witness cosignatures")
	// ErrStale: the last verified head is older than MaxHeadAge (2.3), or
	// there is none.
	ErrStale = errors.New("translog: no fresh verified tree head")
	// ErrWithheld: a verified head with a time more than HeadInterval
	// after an append of this client does not cover the appended entry
	// (doc.go "Withheld entries", SPEC-ISSUES proposal of task 03b,
	// narrowed by task 03c finding 5). The server keeps signing an older
	// size and withholds the entry, typically a revocation; witnesses
	// cannot see that, ErrStale never fires. The client treats it like
	// ErrStale: it processes no new signatures and warns. Without any
	// newer head there is no ErrWithheld; the 24-hour limit (ErrStale)
	// covers an outage.
	ErrWithheld = fmt.Errorf("%w: own log entry withheld by the server", ErrStale)
	// ErrPin: the trust anchor from the pin is malformed: an identity list
	// that does not run from generation 1 to the current one (task 03c
	// finding 3, CheckIdentities).
	ErrPin = errors.New("translog: invalid pinned trust anchor")
	// ErrNotImplemented: interface of task 03, built by task 07.
	ErrNotImplemented = errors.New("translog: not implemented yet")
	// ErrIO: a file outside the tree could not be read or written, in
	// practice the audit index of a client log in the client directory
	// (Options.IndexFile; task 07b finding 3). Errors of the file system
	// under log/ are ErrConsistency instead: the files there do not hold
	// the committed tree. ErrIO says nothing about the log; the operation
	// changed nothing the caller relies on and may be repeated once the
	// file system is repaired (Refresh keeps the old reference head).
	ErrIO = errors.New("translog: input/output error outside the log")
)

// Revoked names a platform key generation that a client update declared
// compromised (2.3 "Wechsel der Identität": clients reject every
// signature of the compromised generation from that update on). Role is
// store.KeyRoleIdentity, store.KeyRoleAdmin or store.KeyRoleIngest.
//
// AtSize is the log size of the revocation (pin field 7, doc.go "Pin").
// TODO(ask): Q8 is open, and Revoked exists only for the case that Q8 is
// decided as proposed: then the pin carries (role, gen,
// revoked_at_size) and, as for users (2.2 rule 4), entries with an index
// below AtSize stay valid and metadata whose receipt time lies before
// the head time of size AtSize stay valid; everything else signed by the
// generation is rejected. Until Q8 is decided pins have no field 7,
// Verifier.Revoked is empty and IsRevoked reports false for every
// generation; no rule of this design depends on it (task 03c finding
// 8b).
type Revoked struct {
	Role   uint8
	Gen    uint32
	AtSize int64
}

// Identity is a platform identity generation and its public key: the
// anchor against which platform certificates and successions in the log
// are validated (doc.go "Validity rules"). For a client it comes from
// the pin, never from the data directory.
type Identity struct {
	Gen uint32
	Pub ed25519.PublicKey
}

// MaxIdentities is the longest identity list of a pin (field 8). Reading:
// the identity changes only in a ceremony with three share holders
// (2.3), a handful of times in the life of a platform. With 256
// generations the identity list alone takes about 21 KiB (82 bytes per
// generation in the canonical encoding) and the largest pin of the
// proposal in doc.go "Pin" about 23 KiB (measured by TestPinSize; task
// 03d finding 9, which corrects the earlier "below 10 KiB"), well below
// MaxPinFile.
const MaxIdentities = 256

// MaxPinFile is the read limit for identity-<gen>.pin (task 07:
// store.ReadFileLimited with this limit wherever a pin is read, client
// and server). It covers the largest pin of the proposal, about 23 KiB
// with MaxIdentities generations, MaxWitnesses witnesses and an origin
// of MaxOrigin bytes, and leaves room for field 7 should Q8 be decided
// as proposed (TestPinSize: with MaxIdentities revoked entries the pin
// takes about 39 KiB).
const MaxPinFile = 64 << 10

// MaxRevoked is the most elements pin field 7 may hold, should Q8 be
// decided as proposed (doc.go "Pin", task 07 finding Q10 (1)); until
// then pins have no field 7 and the constant only reserves room. With
// MaxRevoked elements of the proposed four components (role, gen,
// revoked_at_size and the proposed revoked_at_time) the largest pin
// stays below MaxPinFile (TestPinSize: about 61 KiB). Reading: two
// compromised generations for each identity generation the list can
// hold, far more than a platform ever sees.
const MaxRevoked = 2 * MaxIdentities

// CheckIdentities checks the identity list of a pin (field 8, doc.go
// "Pin", task 03c finding 3): 1 to MaxIdentities elements with the
// generations 1, 2, ... in this order, every key of ed25519.PublicKeySize
// bytes and distinct from the others, and the last element equal to
// current (pin fields 1 and 2). Errors wrap ErrPin.
func CheckIdentities(list []Identity, current Identity) error {
	if len(list) == 0 || len(list) > MaxIdentities {
		return fmt.Errorf("%w: identity list has %d generations", ErrPin, len(list))
	}
	for i, id := range list {
		if id.Gen != uint32(i+1) {
			return fmt.Errorf("%w: identity generations must run from 1 without gaps", ErrPin)
		}
		if len(id.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: identity key has wrong length", ErrPin)
		}
		for _, o := range list[:i] {
			if bytes.Equal(o.Pub, id.Pub) {
				return fmt.Errorf("%w: identity key repeated", ErrPin)
			}
		}
	}
	last := list[len(list)-1]
	if last.Gen != current.Gen || !bytes.Equal(last.Pub, current.Pub) {
		return fmt.Errorf("%w: identity list does not end with the current generation", ErrPin)
	}
	return nil
}

// IdentityKey returns the key of identity generation gen from a list
// that passed CheckIdentities, and false when the list does not reach
// gen (the key then comes from a valid succession in the log, doc.go
// "Validity rules").
func IdentityKey(list []Identity, gen uint32) (ed25519.PublicKey, bool) {
	if gen == 0 || uint64(gen) > uint64(len(list)) || list[gen-1].Gen != gen {
		return nil, false
	}
	return list[gen-1].Pub, true
}

// LogKey is a key that may sign heads (Q4: an ingest generation) together
// with what decides whether it signed a given head validly (doc.go
// "Platform generations", task 03c finding 6, task 03d finding 1).
//
// The client builds one LogKey for every ingest-<Gen>.cert in platform/
// of the data directory that verifies against the pinned identity list,
// whatever its log status: the first head after a rotation may be signed
// by generation Gen alone and may be the first head whose tree holds
// ingest-<Gen>.cert, so the key must be known before that head is opened.
// Whether the certificate is logged enters only through Logged, which
// the caller sets from the audit of the tree of the head being checked.
type LogKey struct {
	// Gen is the ingest generation.
	Gen uint32
	// Verifier is NewLogVerifier of the certified key.
	Verifier note.Verifier
	// ValidFrom is valid_from of ingest-<Gen>.cert (ms). TODO(Q4): the
	// strictest reading lets a generation sign only heads with a time
	// at or after it.
	ValidFrom int64
	// Logged reports that ingest-<Gen>.cert is a valid entry in the tree
	// of the head being checked (and, when its issuing identity
	// generation is above the pinned list, that the successions leading
	// to it are as well). An unlogged certificate opens heads but signs
	// none validly.
	Logged bool
	// Until is valid_from of ingest-<Gen+1>.cert (ms) once that
	// certificate is a valid entry in the tree of the head being
	// checked, 0 while there is none. The server signs with Gen+1 from
	// then on.
	Until int64
}

// Covers reports whether k may have signed a head with time t: the
// certificate is Logged in the tree of that head, ValidFrom <= t
// (valid_from reached) and, with Until set, t < Until (not superseded
// by its successor). Revocation (only if Q8) is checked separately
// (Verifier.IsRevoked). For a given tree at most one generation covers
// any time t, because the intervals [ValidFrom, Until) of consecutive
// generations do not overlap; a head therefore needs exactly one log
// signature (MaxSignatures).
func (k LogKey) Covers(t int64) bool {
	return k.Logged && k.ValidFrom <= t && (k.Until == 0 || t < k.Until)
}

// Pending is an entry this client appended that no verified head
// covered yet (doc.go "Withheld entries"). The client keeps the list in
// state.json (D57) together with Last.
type Pending struct {
	// Index is what Append returned.
	Index int64
	// Leaf is LeafHash of the encoded entry: once a head covers Index,
	// the record proof for Index must verify with exactly this leaf
	// (ErrConsistency otherwise).
	Leaf tlog.Hash
	// At is the time of the append in milliseconds since 1970 UTC, by
	// the client's own clock (Verifier.Now). The entry counts as withheld
	// once the reference head has Time > At + HeadInterval and still
	// Size <= Index (task 03c finding 5). While it is pending, the
	// freshness limit is MaxPendingHeadAge instead of MaxHeadAge (task
	// 03d finding 7).
	At int64
}

// Verifier is the client side of the log: it decides whether a head may
// become the client's reference head and answers the freshness question
// of 2.3. It holds no file system access and no state other than Last;
// the caller supplies heads and proofs (from Log.Head and
// Log.ConsistencyProof) and persists Last after every successful
// CheckHead (client: state.json, DECISIONS D57).
//
// All trust anchors come from the client's pin (identity-<gen>.pin, Q4
// and doc.go "Pin"), never from the data directory:
type Verifier struct {
	// Origin is the pinned origin of the log; a head with another origin
	// is rejected (ErrHead).
	Origin string
	// LogKeys are the keys that may sign heads. With Q4 these are the
	// ingest generations of every ingest-<g>.cert in platform/ of the
	// data directory that verifies against the pinned identity list
	// (Identities, or a generation above it named by a succession from
	// platform/ that verifies in a chain from the list), independent of
	// its log status (task 03d finding 1). Their verifiers open heads
	// (Options.Known). A head needs at least one valid signature by a
	// LogKey that Covers the head's own time line and is not Revoked
	// (only if Q8) (ErrHead otherwise): the certificate is a valid entry
	// in the tree of the head (Logged), its valid_from is reached and it
	// is not superseded by ingest-<g+1>.cert in that tree; strictest
	// reading without Q8 (doc.go "Platform generations", task 03c finding
	// 6). The caller (Refresh) reads platform/ anew before it opens the
	// newest head, audits the entries the new head covers and sets Logged
	// and Until from them before it calls CheckHead.
	LogKeys []LogKey
	// Witnesses are the pinned witness keys (name and Ed25519 key), each
	// built with NewWitnessVerifier. Names are unique and differ from
	// LogSignerName, and keys are unique (task 07b finding 8: one key
	// under two names would count twice towards MinWitnesses). A note
	// verifier built otherwise does not reveal its key and is refused
	// with ErrWitness.
	Witnesses []note.Verifier
	// MinWitnesses is the number of distinct witnesses that must have
	// cosigned a head (2.7: at least 1; 2 of 3 before real mail). It must
	// satisfy CheckQuorum(MinWitnesses, len(Witnesses)), that is
	// 1 <= MinWitnesses <= len(Witnesses) and 2*MinWitnesses >
	// len(Witnesses); a Verifier that violates it accepts nothing
	// (ErrWitness), because with a smaller quorum two disjoint sets of
	// honest witnesses can cosign two different heads of one size.
	MinWitnesses int
	// Identity is the pinned current platform identity (pin fields 1 and
	// 2); it equals the last element of Identities.
	Identity Identity
	// Identities is the pinned list of all identity generations from 1
	// to Identity.Gen (pin field 8, CheckIdentities, task 03c finding
	// 3): the anchor of every platform entry the audit validates. A
	// certificate is checked with the key of its identity_gen from this
	// list (IdentityKey); a succession in the log for a generation in
	// the list must name the list's key (ErrMismatch).
	Identities []Identity
	// Revoked lists compromised platform generations from pin field 7;
	// empty until Q8 is decided (see Revoked).
	Revoked []Revoked
	// Pending are the own appends not yet covered by Last (state.json).
	// The client log adds one per Append and removes it once a verified
	// head covers it with the right leaf.
	Pending []Pending
	// Last is the last verified head, nil on first contact (2.7 "Neue
	// Geräte": trust on first use, protected by the witnesses only).
	Last *Head
	// Now is the injected clock. Open of a client log sets it to
	// Options.Now when that is set (Options.Now takes precedence and is
	// copied here, task 07b finding 4), so that the log and its Verifier
	// use one clock.
	Now func() time.Time
}

// CheckHead decides whether h becomes the new reference head. In this
// order, failing on the first violation:
//
//  0. CheckQuorum(MinWitnesses, len(Witnesses)) (ErrWitness),
//     CheckIdentities(Identities, Identity) (ErrPin), and h.Size and
//     Last.Size at most MaxTreeSize (ErrHead; ParseHeadText already
//     refuses larger sizes, a Last read back from state.json is checked
//     again) before any tlog function runs
//  1. h.Origin == Origin (ErrHead)
//  2. at least one valid signature by the Verifier of a LogKey that
//     Covers(h.Time) and is not IsRevoked(ingest, Gen) (ErrHead): the
//     signing generation is valid at the head's time line, its
//     certificate is logged in the tree of h, valid_from is reached, it
//     is not superseded by its successor and (only if Q8) not revoked
//  3. at least MinWitnesses valid signatures by distinct keys in
//     Witnesses (ErrWitness); signatures by unknown keys never count
//  4. h.Time <= Now() + MaxClockSkew (ErrHead)
//  5. with Last set: h.Size >= Last.Size and h.Time >= Last.Time
//     (ErrConsistency resp. ErrHead); h.Size == Last.Size requires
//     h.Hash == Last.Hash (ErrConsistency: two heads of one size with
//     different content are a split view, 2.7 "Garantien"); otherwise
//     CheckTreeProof(proof, h.Size, h.Hash, Last.Size, Last.Hash) must
//     succeed (ErrConsistency). Without Last the proof must be empty.
//     Reading (doc.go "Heads"): a head of the same size and hash with a
//     time not earlier (>=) is a re-signature for freshness, not a
//     second view.
//
// On success Last = h. CheckHead does not check MaxHeadAge; a head may
// be valid and still not fresh (Fresh).
func (v *Verifier) CheckHead(h *Head, proof tlog.TreeProof) error {
	if err := v.checkConfig(); err != nil {
		return err
	}
	if h == nil || h.Size < 1 || h.Size > MaxTreeSize {
		return fmt.Errorf("%w: head size out of range", ErrHead)
	}
	if v.Last != nil && (v.Last.Size < 1 || v.Last.Size > MaxTreeSize) {
		return fmt.Errorf("%w: last head size out of range", ErrHead)
	}
	// 1. origin
	if h.Origin != v.Origin {
		return fmt.Errorf("%w: head of another log", ErrHead)
	}
	// The signatures are verified here again from the note; Head.Sigs
	// is never trusted.
	text, err := h.Text()
	if err != nil {
		return err
	}
	known := &verifierSet{list: append([]note.Verifier(nil), v.Witnesses...)}
	for _, k := range v.LogKeys {
		known.list = append(known.list, k.Verifier)
	}
	if len(h.Note) > MaxHeadNote {
		return fmt.Errorf("%w: signed head too long", ErrHead)
	}
	n, err := note.Open(h.Note, known)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHead, err)
	}
	if n.Text != string(text) {
		return fmt.Errorf("%w: note text differs from the head", ErrHead)
	}
	// 2. a log signature by a generation valid at the head's time line
	logOK := false
	for _, s := range n.Sigs {
		if s.Name != LogSignerName {
			continue
		}
		for _, k := range v.LogKeys {
			if k.Verifier != nil && k.Verifier.Name() == LogSignerName && k.Verifier.KeyHash() == s.Hash &&
				k.Covers(h.Time) && !v.IsRevoked(store.KeyRoleIngest, k.Gen) {
				logOK = true
			}
		}
	}
	if !logOK {
		return fmt.Errorf("%w: no log signature by a generation valid at the head's time", ErrHead)
	}
	// 3. witness quorum, distinct keys (checkConfig refused one key
	// under two names; counting keys keeps it so)
	seen := map[string]bool{}
	for _, s := range n.Sigs {
		for _, w := range v.Witnesses {
			if w.Name() == s.Name && w.KeyHash() == s.Hash {
				k, _ := witnessKey(w)
				seen[string(k)] = true
			}
		}
	}
	if len(seen) < v.MinWitnesses {
		return fmt.Errorf("%w: %d of %d required cosignatures", ErrWitness, len(seen), v.MinWitnesses)
	}
	// 4. not in the future
	if v.Now == nil {
		return fmt.Errorf("%w: no clock", ErrHead)
	}
	if h.Time > v.Now().UnixMilli()+MaxClockSkew.Milliseconds() {
		return fmt.Errorf("%w: head time in the future", ErrHead)
	}
	// 5. continuation of the last head
	if v.Last == nil {
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof without a previous head", ErrConsistency)
		}
	} else {
		switch {
		case h.Size < v.Last.Size:
			return fmt.Errorf("%w: head smaller than the last verified one", ErrConsistency)
		case h.Time < v.Last.Time:
			return fmt.Errorf("%w: head older than the last verified one", ErrHead)
		case h.Size == v.Last.Size:
			if h.Hash != v.Last.Hash {
				return fmt.Errorf("%w: two heads of one size with different hashes (split view)", ErrConsistency)
			}
		default:
			if err := CheckTreeProof(proof, h.Size, h.Hash, v.Last.Size, v.Last.Hash); err != nil {
				return err
			}
		}
	}
	c := *h
	c.Sigs = n.Sigs
	c.Note = append([]byte(nil), h.Note...)
	v.Last = &c
	return nil
}

// checkConfig checks the pinned anchors: the quorum (ErrWitness), the
// witnesses (built with NewWitnessVerifier, names unique and not the
// log's name, keys unique; ErrWitness), the identity list (ErrPin) and
// the origin (ErrHead).
func (v *Verifier) checkConfig() error {
	if err := checkWitnessSet(v.Witnesses, v.MinWitnesses); err != nil {
		return err
	}
	if err := CheckIdentities(v.Identities, v.Identity); err != nil {
		return err
	}
	return checkOrigin(v.Origin)
}

// checkWitnessSet checks a witness set with its quorum (ErrWitness):
// CheckQuorum, at most MaxWitnesses, every verifier built with
// NewWitnessVerifier, names unique and not LogSignerName, keys unique.
// The client's pinned set (Verifier) and the operator's working copy
// (Options.Witnesses, task 11) follow the same rules.
func checkWitnessSet(ws []note.Verifier, min int) error {
	if err := CheckQuorum(min, len(ws)); err != nil {
		return err
	}
	if len(ws) > MaxWitnesses {
		return fmt.Errorf("%w: too many witnesses", ErrWitness)
	}
	for i, w := range ws {
		if w == nil || w.Name() == LogSignerName {
			return fmt.Errorf("%w: invalid witness", ErrWitness)
		}
		k, ok := witnessKey(w)
		if !ok {
			return fmt.Errorf("%w: witness verifier not built with NewWitnessVerifier", ErrWitness)
		}
		for _, o := range ws[:i] {
			if o.Name() == w.Name() {
				return fmt.Errorf("%w: witness names must be unique", ErrWitness)
			}
			if ok2, _ := witnessKey(o); bytes.Equal(ok2, k) {
				return fmt.Errorf("%w: one witness key under two names", ErrWitness)
			}
		}
	}
	return nil
}

// Fresh reports ErrStale unless Last is set and now - Last.Time <=
// MaxHeadAge (2.3 "Aktualitätsgrenze"). A Pending entry that Last
// covers (Index < Last.Size) is ErrConsistency (task 07b finding 2):
// Refresh makes a head the reference head only after it has checked
// every Pending entry the head covers against its leaf and then drops
// them, so after a successful Refresh there is none; one that is still
// there means a Last and a Pending list that do not belong together (for
// instance a state.json written with the new head but the old list), and
// skipping it would let an own entry that the log replaced go unnoticed.
// Refresh against the same head checks it and drops it. Last.Time later than now +
// MaxClockSkew is ErrHead (CheckHead already refused such a head; a
// Last read back from state.json is checked again). It reports
// ErrWithheld when a Pending entry has Last.Time > At + HeadInterval
// (in ms) and Last.Size <= Index (doc.go "Withheld entries", task 03c
// finding 5): a head signed well after the append leaves the own entry
// out, which is treated like a stale head. While a Pending entry
// without such a newer head exists, the limit is MaxPendingHeadAge
// instead of MaxHeadAge (ErrStale once now - Last.Time >
// MaxPendingHeadAge, task 03d finding 7): a server that keeps signing
// heads with a time line frozen at At + HeadInterval never triggers
// ErrWithheld, and with MaxHeadAge it would stay undetected until At +
// HeadInterval + MaxHeadAge, 25 hours; with MaxPendingHeadAge the own
// entry is either covered or the client stops within 24 hours of the
// append (2.7 "Zurückhalten eines Widerrufs über 24 Stunden").
func (v *Verifier) Fresh(now time.Time) error {
	if v.Last == nil {
		return fmt.Errorf("%w: no verified head", ErrStale)
	}
	if v.Last.Size < 1 || v.Last.Size > MaxTreeSize {
		return fmt.Errorf("%w: last head size out of range", ErrHead)
	}
	nowMs := now.UnixMilli()
	if v.Last.Time > nowMs+MaxClockSkew.Milliseconds() {
		return fmt.Errorf("%w: last head time in the future", ErrHead)
	}
	limit := MaxHeadAge
	for _, p := range v.Pending {
		if p.Index < v.Last.Size {
			return fmt.Errorf("%w: own entry %d is covered by the reference head but was never checked", ErrConsistency, p.Index)
		}
		if v.Last.Time > p.At+HeadInterval.Milliseconds() {
			return fmt.Errorf("%w: entry %d", ErrWithheld, p.Index)
		}
		limit = MaxPendingHeadAge
	}
	if nowMs-v.Last.Time > limit.Milliseconds() {
		return fmt.Errorf("%w: last verified head is older than %v", ErrStale, limit)
	}
	return nil
}

// CheckInclusion checks that the encoded entry is record index of the
// tree of Last: 0 <= index (ErrNotInLog), index < Last.Size (ErrPending
// otherwise) and CheckRecordProof(proof, Last.Size, Last.Hash, index,
// LeafHash(encoded)) (ErrConsistency otherwise). Every Check* of the
// client-side Log runs it for each entry it relies on.
func (v *Verifier) CheckInclusion(index int64, encoded []byte, proof tlog.RecordProof) error {
	if index < 0 {
		return fmt.Errorf("%w: negative index", ErrNotInLog)
	}
	if v.Last == nil || index >= v.Last.Size {
		return fmt.Errorf("%w: entry %d", ErrPending, index)
	}
	return CheckRecordProof(proof, v.Last.Size, v.Last.Hash, index, LeafHash(encoded))
}

// CheckCheckpoint checks a note of another client or device
// (checkpoints/<user-id>-<device-id>.rec, 2.7 "Abgleich zwischen
// Clients") against Last. The fields are those of
// gomail/v1/rec/checkpoint (store.Checkpoint): origin, size and
// root_hash are the other client's reference head, headTime its time
// line. In this order:
//
//   - origin != Origin: ErrHead
//   - size < 1 or size > MaxTreeSize, or headTime < 0: ErrHead, before
//     any proof
//   - Last nil: ErrStale (nothing to compare with)
//   - size > Last.Size: ErrPending (refresh first, then compare)
//   - size == Last.Size: root must equal Last.Hash, else
//     ErrConsistency; the times may differ either way (heads of one
//     size are re-signed, doc.go "Heads")
//   - size < Last.Size: headTime <= Last.Time, else ErrConsistency, and
//     CheckTreeProof(proof, Last.Size, Last.Hash, size, root), else
//     ErrConsistency
//
// Role of headTime (Reading, strictest; TODO(ask)): it does not enter
// any proof, but it orders the two views. The server signs only its
// committed size and never signs a smaller size after a larger one
// (Operator.SignHead), and every head time is the server's clock, so a
// head smaller than Last always has a time at most Last.Time. A smaller
// head with a later time shows that the server kept re-signing an old
// size for the other client after it had shown this one a newer tree:
// it withholds the newer entries from the other client (the case of
// doc.go "Withheld entries" seen from outside), which is a different
// view of the log (2.7 "verschiedene Sichten").
//
// Rules for the caller (doc.go "Client checkpoints"), before
// CheckCheckpoint: the record decodes strictly (store.DecodeCheckpoint,
// size >= 1) and its file name names its user_id and device_id; user_id
// is a user member of the mailbox in whose checkpoints/ the record lies
// (member of the head epoch of the mailbox's verified chain); user_gen
// is the current generation of user_id according to the log (the newest
// valid user entry of user_id has exactly user_gen generations:
// CheckGeneration(user_id, user_gen) succeeds and the user entry
// (user_id, user_gen+1) does not exist, ErrSuperseded otherwise); the
// signature (domain "checkpoint") verifies with the identity key of
// user_gen from that logged user entry. A checkpoint that fails any of
// these is ignored with a warning; it says nothing about the log.
//
// ErrConsistency here means the server showed the two clients different
// logs; the client warns and stops processing (2.7).
func (v *Verifier) CheckCheckpoint(origin string, size int64, root tlog.Hash, headTime int64, proof tlog.TreeProof) error {
	if origin != v.Origin {
		return fmt.Errorf("%w: checkpoint of another log", ErrHead)
	}
	if size < 1 || size > MaxTreeSize || headTime < 0 {
		return fmt.Errorf("%w: checkpoint size or time out of range", ErrHead)
	}
	if v.Last == nil {
		return fmt.Errorf("%w: no verified head to compare with", ErrStale)
	}
	switch {
	case size > v.Last.Size:
		return fmt.Errorf("%w: checkpoint beyond the reference head", ErrPending)
	case size == v.Last.Size:
		if root != v.Last.Hash {
			return fmt.Errorf("%w: checkpoint of the same size with another hash (split view)", ErrConsistency)
		}
		return nil
	case headTime > v.Last.Time:
		return fmt.Errorf("%w: a smaller head signed after the reference head (entries withheld from the other client)", ErrConsistency)
	}
	return CheckTreeProof(proof, v.Last.Size, v.Last.Hash, size, root)
}

// IsRevoked reports whether the pin declares the platform generation
// compromised.
func (v *Verifier) IsRevoked(role uint8, gen uint32) bool {
	for _, r := range v.Revoked {
		if r.Role == role && r.Gen == gen {
			return true
		}
	}
	return false
}

// CheckQuorum reports whether min of n witnesses is an admissible
// quorum (task 03b, finding S1): 1 <= min <= n and 2*min > n. The upper
// bound on n (witness.MaxWitnesses) is the caller's.
//
// Why 2*min > n: a witness cosigns at most one head per size (2.7), so
// two heads of one size with different hashes need min cosignatures
// each. Let c witnesses collude with the server (they cosign both
// heads) and the n - c honest ones be split between the two heads, h1
// and h2 with h1 + h2 <= n - c. Both heads reach the quorum when c + h1
// >= min and c + h2 >= min, which is possible exactly when
// 2*(min - c) <= n - c, that is c >= 2*min - n. A split view is
// therefore excluded exactly when fewer than 2*min - n witnesses
// collude. Without collusion (c = 0) this is 2*min > n; with 1 of 2 the
// server shows each witness another head and gets two valid heads of
// one size. 2.7's "2 of 3" (2*2 - 3 = 1) tolerates no colluding
// witness; tolerating one colluding witness of three needs min = 3
// (which then tolerates up to two, 2.7's assumption "not all required
// witnesses"). The PoC configuration 1 of 1 satisfies the rule.
func CheckQuorum(min, n int) error {
	if n < 1 || min < 1 || min > n || 2*min <= n {
		return fmt.Errorf("%w: quorum %d of %d admits a split view (2*min must exceed the number of witnesses)", ErrWitness, min, n)
	}
	return nil
}

// CheckTreeProof checks a consistency proof as tlog.CheckTree(proof, n,
// h, m, th) does: the tree of size n with hash h extends the tree of
// size m with hash th. It refuses sizes outside 1 <= m <= n <=
// MaxTreeSize before calling tlog (finding A5: tlog.CheckTree does not
// return for sizes above 2^62). Every consistency check of this module
// (Verifier, witness) goes through it. Errors wrap ErrConsistency.
func CheckTreeProof(proof tlog.TreeProof, n int64, h tlog.Hash, m int64, th tlog.Hash) error {
	if m < 1 || m > n || n > MaxTreeSize {
		return fmt.Errorf("%w: tree sizes out of range", ErrConsistency)
	}
	if err := tlog.CheckTree(proof, n, h, m, th); err != nil {
		return fmt.Errorf("%w: consistency proof does not verify", ErrConsistency)
	}
	return nil
}

// CheckRecordProof checks an inclusion proof as tlog.CheckRecord(proof,
// t, th, n, leaf) does: leaf is record n of the tree of size t with hash
// th. It refuses anything outside 0 <= n < t <= MaxTreeSize before
// calling tlog (finding A5). Every inclusion check of this module goes
// through it. Errors wrap ErrConsistency.
func CheckRecordProof(proof tlog.RecordProof, t int64, th tlog.Hash, n int64, leaf tlog.Hash) error {
	if n < 0 || n >= t || t > MaxTreeSize {
		return fmt.Errorf("%w: record index or tree size out of range", ErrConsistency)
	}
	if err := tlog.CheckRecord(proof, t, th, n, leaf); err != nil {
		return fmt.Errorf("%w: inclusion proof does not verify", ErrConsistency)
	}
	return nil
}

// NewWitnessVerifier returns the note verifier of a witness key (name
// and Ed25519 public key as in witnesses.rec and the pin). The verifier
// keeps the key, so that Verifier.checkConfig can refuse one key under
// two names (task 07b finding 8).
func NewWitnessVerifier(name string, pub ed25519.PublicKey) (note.Verifier, error) {
	if name == LogSignerName {
		return nil, fmt.Errorf("%w: a witness cannot use the log's name", ErrWitness)
	}
	vkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWitness, err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWitness, err)
	}
	return &witnessVerifier{Verifier: v, pub: append(ed25519.PublicKey(nil), pub...)}, nil
}

// witnessVerifier is a note verifier of a witness that knows its key.
type witnessVerifier struct {
	note.Verifier
	pub ed25519.PublicKey
}

// witnessKey returns the key of a verifier built with NewWitnessVerifier.
func witnessKey(v note.Verifier) (ed25519.PublicKey, bool) {
	w, ok := v.(*witnessVerifier)
	if !ok || w == nil || len(w.pub) != ed25519.PublicKeySize {
		return nil, false
	}
	return w.pub, true
}
