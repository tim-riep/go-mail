// Package translog is the interface to the transparency log (2.7).
//
// Several rules of the specification depend on the log: a user generation
// is valid only from its log entry on (2.2 rule 3), signatures of a
// revoked generation count only if they were logged before the revocation
// (2.2 rule 4), address assignments are checked against the log (2.3),
// epochs and certificates are logged, and a client stops processing new
// signatures when its last verified tree head is older than 24 hours
// (2.3). Every one of these checks goes through Log, so that nothing is
// weakened silently.
//
// The log itself (golang.org/x/mod/sumdb/tlog, witnesses) is built in
// phase 3. Phase 1 has exactly one implementation, Unverified, which
// accepts everything. It can only be created with an explicit
// insecureNoLog switch (command line flag --insecure-no-log), and clients
// print Warning on every start.
//
// The interface for milestone M1 (task 03) is laid out in doc.go: the
// file format of data/log/, the entries and their duplicate keys, the
// signed heads, who writes, what an attacker with write access to log/
// achieves, the proofs behind each Check method, and the table of all
// open phase-3 sites. entry.go, head.go and
// verifier.go hold the types, log.go the server side and the
// constructor.
package translog

import (
	"errors"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
)

// ErrNoLog is returned when no verifying log is available and the caller
// did not explicitly accept running without one.
var ErrNoLog = errors.New("translog: no transparency log available; refusing to start (development only: --insecure-no-log)")

// Warning is printed by clients on every start with Unverified.
const Warning = "WARNUNG: Ohne Transparenzlog (--insecure-no-log). Generationen, Widerrufe, Epochen, " +
	"Zertifikate und Adresszuordnungen werden NICHT gegen ein Log geprüft. Ein Server kann " +
	"unbemerkt abweichende Zustände zeigen. Nur für die Entwicklung, nie mit echten Mails."

// Log is every operation that involves the transparency log.
//
// Every Check method runs against the reference head (doc.go): for a
// client the last head its Verifier accepted (log signature, witness
// cosignatures, consistency with the previous one), for the server and
// the ceremony the committed tree of log/tree.rec. "Included" below
// always means: the entry is record i of that tree, proven with
// InclusionProof(i, size) and Verifier.CheckInclusion, and its encoding
// carries exactly the bytes given. A client's Log has read and proven
// every entry up to the reference head (doc.go "Audit"), so "no entry"
// is a statement about the whole log, not about a lookup that might have
// been incomplete.
type Log interface {
	// Verified reports whether the checks are backed by a real log.
	Verified() bool

	// AppendUser logs a new or extended user.rec (2.2 rule 3).
	// Equivalent to Append(KindUser, userRec) after checking that the
	// derived key names user (ErrEntry otherwise); the index is dropped.
	AppendUser(user store.ID, userRec []byte) error
	// AppendEpoch logs an epoch.rec (2.7). Equivalent to
	// Append(KindEpoch, epochRec) after checking mailbox and number.
	AppendEpoch(mailbox store.ID, number uint32, epochRec []byte) error
	// AppendAddress logs a signed address assignment (2.3). Equivalent
	// to Append(KindAddress, addressRec).
	AppendAddress(addressRec []byte) error
	// AppendPlatform logs a platform certificate or succession (2.7).
	// Equivalent to Append(KindPlatform, data) after checking that name
	// is the file name derived from data.
	AppendPlatform(name string, data []byte) error

	// CheckUser verifies that this user.rec is the one in the log
	// (inclusion proof, 2.7).
	//
	// Proof: the entry with key (user, user ID, number of generations of
	// userRec) is included and its content equals userRec byte for byte
	// (ErrNotInLog, ErrPending, ErrMismatch), and no user entry of the
	// same user with more generations is included (ErrSuperseded: a
	// rolled back user.rec would hide a revocation, 2.3). This also binds
	// the user ID to the root key (SPEC-ISSUES S16): the first entry of a
	// user fixes the root, every later one must extend it (ErrOrder at
	// append and audit).
	CheckUser(user store.ID, userRec []byte) error
	// CheckGeneration verifies that generation gen of user is in the log
	// and therefore valid (2.2 rule 3).
	//
	// Proof: the user entry with key (user, user ID, gen) is included.
	// It says nothing about revocation; signatures of a revoked
	// generation go through CheckRevokedSignature.
	CheckGeneration(user store.ID, gen uint32) error
	// CheckRevokedSignature verifies that a record signed by the revoked
	// generation gen of user was logged before the revocation (2.2
	// rule 4, SPEC-ISSUES S13).
	//
	// Proof: signed is a loggable record (KindOf; in practice an
	// epoch.rec); the entry with its key is included with exactly these
	// bytes (ErrNotInLog, ErrPending, ErrMismatch); if the user entry
	// with key (user, user ID, gen+1), the one that revokes gen, is
	// included, the index of the signed record is smaller than its index
	// (ErrOrder otherwise). Files outside the log (wraps, folders.gml,
	// metadata) are never passed here; their signatures by a revoked
	// generation are invalid (S13, the caller's rule).
	CheckRevokedSignature(user store.ID, gen uint32, signed []byte) error
	// CheckEpoch verifies that epoch.rec is in the log (2.7).
	//
	// Proof: the entry with key (epoch, mailbox, number) is included and
	// its content equals epochRec byte for byte (ErrNotInLog, ErrPending,
	// ErrMismatch). Because a key exists at most once in the log, this
	// is K2 rule 4: of two epochs with one number the first logged one
	// is the only valid one. The caller also compares the head of
	// mailbox.rec with the newest epoch entry of the mailbox
	// (Lookup(KindEpoch, mailbox)); a lower head is a rollback (2.4).
	CheckEpoch(mailbox store.ID, number uint32, epochRec []byte) error
	// CheckAddress verifies that address was assigned to mailbox at time
	// at (milliseconds) according to the log (2.3).
	//
	// Proof: among the valid included address entries of address (log
	// order equals valid_from order, ErrOrder at append and audit) the
	// one with the greatest valid_from <= at names mailbox (ErrNotInLog
	// when there is none, ErrMismatch when it names another mailbox).
	// Its admin signature verifies with the admin certificate of its
	// admin_gen, which is included as a platform entry logged before it,
	// verifies against the pinned identity list and has valid_from <=
	// the assignment's valid_from (validity rules, the entry is skipped
	// otherwise).
	//
	// Reading (task 03b finding S7, task 03c finding 4): 2.3 says "zum
	// Zeitpunkt des Empfangs zugeordnet"; the assignment in force at a
	// time is the newest one that had begun, so the greatest valid_from
	// <= at decides, with no upper bound on valid_from. TODO(Q9): the
	// bound of task 03b (valid_from at most the time of the head that
	// first covered the entry) is dropped because that head differs from
	// client to client; a backdated assignment can therefore legitimize
	// mail received before it was logged, and a future-dated one takes
	// effect without a new entry. Q9 proposes a signed field issued in
	// the address record that bounds this equally for every client
	// (doc.go "Address assignments").
	CheckAddress(address string, mailbox store.ID, at int64) error
	// CheckPlatform verifies that a platform certificate or succession is
	// in the log and its generation is not marked compromised (2.3).
	//
	// Proof: the platform entry with key (platform, name, 0) is included
	// with exactly data (ErrNotInLog, ErrPending, ErrMismatch) and is
	// valid. A certificate verifies with the key of its identity_gen
	// taken from the pin's identity list (Verifier.Identities, pin field
	// 8, IdentityKey), or, for a generation above the list, from the
	// valid succession identity-<identity_gen>.succ in the log. A
	// succession identity-<g>.succ whose generation is in the list must
	// name exactly the list's key (ErrMismatch otherwise: the log
	// contradicts the pin, task 03c finding 3, Reading).
	//
	// Only if Q8 is decided as proposed: the pin's field 7 does not list
	// the generation of the certified key or of the issuing identity as
	// compromised (ErrMismatch). TODO(ask), Q8: the specification has no
	// record by which a compromised ingest or admin generation is
	// revoked; until Q8 is decided the pin has no field 7 and this part
	// checks nothing (doc.go "Pin", Revoked).
	//
	// Rule for the caller, strictest reading without Q8 (doc.go
	// "Platform generations"): CheckPlatform does not know the receipt
	// time. A caller that verifies an ingest signature of generation g
	// on metadata additionally requires, once ingest-<g+1>.cert is a
	// valid included entry (Lookup(KindPlatform, "ingest-<g+1>.cert")),
	// that the receipt time lies before that certificate's valid_from
	// (ErrMismatch otherwise; task 14, client/read.go ingestKeyFor).
	CheckPlatform(name string, data []byte) error
	// CheckFresh verifies that the last verified tree head with witness
	// signature is at most 24 hours old (2.3, 2.7).
	//
	// Proof: Verifier.Fresh(now) on the reference head. A server-side
	// Log (no Verifier) returns nil: the server is the operator and has
	// no reference head of its own to age.
	CheckFresh(now time.Time) error

	// Append logs a record of the given kind and returns its index. The
	// key is derived from the content (KeyOf). Under log/lock the
	// appender checks, against the valid entries of the committed tree,
	// that the key is not taken by a valid entry (ErrDuplicate) and
	// that the entry satisfies every validity rule, signatures included
	// (doc.go "Validity rules": ErrOrder when it never can,
	// ErrPrerequisite when an entry it depends on is missing,
	// ErrUnloggedSigner when that entry is the user entry of an epoch's
	// signer, ErrMismatch for a succession that contradicts the identity
	// list of the anchor); then it
	// writes the entry, the tiles and the key file and commits by
	// writing log/tree.rec. Nothing that violates a rule is appended.
	//
	// Leftovers (task 03d finding 3): with committed size n, Append
	// removes leftovers of an interrupted append only at exactly index n
	// (entries/<n>.rec, its key file, the tiles of tlog.NewTiles(8, n,
	// n+1)): one crashed append leaves at most one entry. If
	// entries/<n+1>.rec exists or a head in heads/ names a size above n,
	// tree.rec was rolled back or damaged; Append then deletes nothing
	// and refuses with ErrConsistency (doc.go "File format").
	// The entry becomes checkable once the server has signed a head that
	// covers it (ErrPending until then).
	//
	// Append is idempotent: when the entry with the same key has exactly
	// the same content, it returns that entry's index and nil. A writer
	// that crashed between writing the record and logging it therefore
	// simply appends again on its next run; only different content under
	// a taken key is ErrDuplicate. For the first entry of a subject (user
	// generation 1, epoch 1) the client appends before it writes the
	// data directory, from a copy in its client directory (doc.go "Who
	// writes", task 03c finding 1).
	//
	// A client log adds Pending{index, LeafHash, now} to its Verifier
	// for every append, also an idempotent one not yet covered; the
	// caller persists it in state.json before it relies on the entry
	// (doc.go "Withheld entries").
	Append(kind Kind, content []byte) (int64, error)
	// Refresh first reads platform/ anew and rebuilds the candidate
	// Verifier.LogKeys from every ingest certificate there that verifies
	// against the pinned identity list, logged or not (task 03d finding
	// 1); then it opens the newest published head (heads/) with those
	// keys and the pinned witnesses, audits every entry between the old
	// and the new head with proofs against the new head (doc.go
	// "Audit"), sets LogKey.Logged and Until from that audit, and makes
	// the head the reference head if the Verifier accepts it (CheckHead
	// with ConsistencyProof(last, new)); on any failure the audit of the
	// new entries is discarded. It checks every Pending entry the new
	// head covers against its leaf (ErrConsistency) and drops it, and
	// returns the new reference head for the caller to persist. It
	// returns ErrWithheld (an ErrStale) when the reference head is newer
	// than a Pending entry by more than HeadInterval (Time > At +
	// HeadInterval) and still does not cover it, and ErrStale when a
	// Pending entry is uncovered and the reference head is older than
	// MaxPendingHeadAge (doc.go "Withheld entries", Verifier.Fresh). A
	// server-side Log returns the newest head it signed, without witness
	// checks.
	Refresh(now time.Time) (*Head, error)
	// Head returns the newest published head as stored in heads/,
	// opened with Options.Known and, for a client, the verifiers of
	// Verifier.LogKeys (as of the last Refresh), but not yet judged.
	Head() (*Head, error)
	// Entry returns entry index, decoded with DecodeEntry; for a client
	// only below the reference size (ErrPending beyond). An index
	// outside 0 <= index < MaxTreeSize is ErrNotInLog without any file
	// access.
	Entry(index int64) (*Entry, error)
	// InclusionProof returns the proof that entry index is in the tree
	// of the given size (tlog.ProveRecord over the tiles). Arguments
	// outside 0 <= index < size <= MaxTreeSize are ErrConsistency before
	// tlog is called (finding A5).
	InclusionProof(index, size int64) (tlog.RecordProof, error)
	// ConsistencyProof returns the proof that the tree of size to
	// extends the tree of size from (tlog.ProveTree over the tiles).
	// Arguments outside 1 <= from <= to <= MaxTreeSize are
	// ErrConsistency before tlog is called (finding A5).
	ConsistencyProof(from, to int64) (tlog.TreeProof, error)
	// Lookup returns all valid entries of kind with this subject (see
	// Key) in log order; for a client only those covered by the
	// reference head. Invalid entries (doc.go "Validity rules") are never
	// returned. An empty result is not an error.
	Lookup(kind Kind, subject []byte) ([]Entry, error)
}

// NoIndex is the index Unverified returns for an append.
const NoIndex int64 = -1

// Unverified accepts everything. It exists so that phase 1 can run
// before the log is built; every method is a placeholder for phase 3.
type Unverified struct{}

// NewUnverified returns the accepting placeholder if insecureNoLog is
// set, and ErrNoLog otherwise.
func NewUnverified(insecureNoLog bool) (*Unverified, error) {
	if !insecureNoLog {
		return nil, ErrNoLog
	}
	return &Unverified{}, nil
}

// Verified is false.
func (*Unverified) Verified() bool { return false }

// TODO(phase3-translog): append user.rec to the log.
func (*Unverified) AppendUser(store.ID, []byte) error { return nil }

// TODO(phase3-translog): append epoch.rec to the log.
func (*Unverified) AppendEpoch(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): append the signed address assignment.
func (*Unverified) AppendAddress([]byte) error { return nil }

// TODO(phase3-translog): append certificates and successions.
func (*Unverified) AppendPlatform(string, []byte) error { return nil }

// TODO(phase3-translog): inclusion proof for user.rec.
func (*Unverified) CheckUser(store.ID, []byte) error { return nil }

// TODO(phase3-translog): a generation is valid only from its log entry on.
func (*Unverified) CheckGeneration(store.ID, uint32) error { return nil }

// TODO(phase3-translog): signature of a revoked generation logged before the revocation.
func (*Unverified) CheckRevokedSignature(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): inclusion proof for epoch.rec.
func (*Unverified) CheckEpoch(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): address assignment at the time of receipt.
func (*Unverified) CheckAddress(string, store.ID, int64) error { return nil }

// TODO(phase3-translog): certificate in the log, generation not compromised.
func (*Unverified) CheckPlatform(string, []byte) error { return nil }

// TODO(phase3-translog): tree head with witness signature at most 24 hours old.
func (*Unverified) CheckFresh(time.Time) error { return nil }

// Append accepts the record and logs nothing (NoIndex).
func (*Unverified) Append(Kind, []byte) (int64, error) { return NoIndex, nil }

// Refresh has no head to return.
func (*Unverified) Refresh(time.Time) (*Head, error) { return nil, nil }

// Head reports that there is no log.
func (*Unverified) Head() (*Head, error) { return nil, ErrNoLog }

// Entry reports that there is no log.
func (*Unverified) Entry(int64) (*Entry, error) { return nil, ErrNoLog }

// InclusionProof reports that there is no log.
func (*Unverified) InclusionProof(int64, int64) (tlog.RecordProof, error) { return nil, ErrNoLog }

// ConsistencyProof reports that there is no log.
func (*Unverified) ConsistencyProof(int64, int64) (tlog.TreeProof, error) { return nil, ErrNoLog }

// Lookup finds nothing.
func (*Unverified) Lookup(Kind, []byte) ([]Entry, error) { return nil, nil }
