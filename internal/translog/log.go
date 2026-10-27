package translog

import (
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/store"
)

// Operator is the server side of the log (task 11): only the server
// signs heads (doc.go "Who writes"). It extends Log; Check methods of an
// Operator run against the committed tree.
type Operator interface {
	Log

	// SignHead validates every entry after the newest published head up
	// to the committed size with the validity rules (doc.go "Validity
	// rules"), recomputes the root hash from the entries (not from tiles
	// written by others) and returns a head of that size with time now,
	// signed by signer and by nothing else. Nothing is written: the
	// result is the candidate that witnesses fetch (GET /gomail/log/head,
	// package witness).
	//
	// An entry that fails validation (ErrEntry, ErrDuplicate, ErrOrder,
	// ErrPrerequisite: written past Append by someone with write access
	// to log/) is committed and immutable; it stays in the tree, occupies
	// no key and is skipped by every audit. SignHead covers it and
	// returns the head together with an error wrapping the first such
	// error, with the indices, so that the operator is alerted. Reading:
	// stopping at the bad entry instead would let any writer of log/
	// stop the log for good. Only an inconsistent tree (tiles or
	// tree.rec contradicting the entries, or a published head larger
	// than the committed size: a rolled back tree.rec, task 03d finding
	// 3) stops signing (ErrConsistency, no head).
	//
	// Cadence (task 11): the server calls SignHead whenever the committed
	// size has grown since the last candidate, at most once a minute, and
	// otherwise every HeadInterval; with no new entries it re-signs the
	// newest size with a new time. Reading, task 03b finding S5: a head
	// of the same size and hash with a time not earlier (>=) is not a
	// second view (the hash commits to the same tree) but the only way
	// to stay inside MaxHeadAge without adding entries; the
	// alternatives, an empty heartbeat entry per interval or a separate
	// signed time note, grow the log or add a second signed format.
	// Every head signed more than HeadInterval after an entry was
	// committed must cover it; a client that sees such a head without
	// its own entry stops (ErrWithheld, task 03c finding 5).
	//
	// Signer (Q4, task 03c finding 6): the caller passes the ingest
	// generation g whose LogKey covers now: from valid_from of
	// ingest-<g+1>.cert on, once that certificate is in the log, the
	// server signs with generation g+1 and never again with g, because
	// clients judge the signing generation against the head's own time
	// line (Verifier.LogKeys).
	//
	// Built by task 11, in this order under log/lock:
	//
	//  1. Options.Origin is set (ErrHead); the committed size n of
	//     tree.rec is at least 1 (ErrNotInLog: a head of the empty log is
	//     never signed); no entries/<n+1>.rec and no head in heads/ above
	//     n (ErrConsistency: tree.rec rolled back, task 03d finding 3);
	//  2. the base is the newest published head (heads/, its text taken
	//     from the lines that verify with a logged ingest key; a file
	//     without such a line is ErrConsistency) or, when larger, the
	//     last head this process signed; the committed tree must extend
	//     both (root hash of their size, ErrConsistency) and now must not
	//     lie before their times (ErrHead: the server's clock went back);
	//  3. the root hash of size n is recomputed from the entries after
	//     the base (tlog.StoredHashes over entries/<i>.rec, the hashes
	//     below the base read from tiles verified against the base's
	//     hash) and must equal tree.rec (ErrConsistency);
	//  4. the entries after the base, the tiles that changed, tree.rec
	//     and their directories are synced (fsync, task 07 finding Q10
	//     (2)): a head is signed only over a durable tree;
	//  5. signer must be the ingest generation whose certificate is a
	//     valid entry of the tree and Covers now (ErrHead otherwise; the
	//     signature is checked with the certified key after signing).
	//
	// The validity rules run as for every Check method (the operator's
	// state of the committed tree); the entries from the newest
	// published head on that failed them are reported with an
	// *InvalidEntriesError beside the head. The process remembers the
	// returned head as the last signed one, in memory only: after a
	// restart the base is the newest published head (doc.go "Tasks"
	// point 11, Q10 (4)).
	SignHead(signer note.Signer, now time.Time) (*Head, error)

	// PublishHead writes h to heads/<size>.sig under log/lock. h must
	// carry a valid log signature by the ingest generation that covers
	// its time line (ErrHead) and at least the minimum
	// number of cosignatures of the server's working copy
	// platform/witnesses.rec (ErrWitness). An existing head of the same
	// size is replaced only by one with the same hash (ErrConsistency
	// otherwise: never two heads of one size) and a time not earlier
	// (>=; Reading, see SignHead), and its cosignatures are kept when they
	// are for the same text (merge of note signature lines, one line
	// per key).
	//
	// The server writes only signature lines it verified itself: exactly
	// one log signature (of the covering generation; a head needs no
	// second one, MaxSignatures) and cosignatures that verify with a key
	// of witnesses.rec. Every other line, an invalid cosignature as well as
	// a line by an unknown key, is dropped and never stored (task 03b,
	// finding A2-10: one invalid line by a known key makes the whole
	// note unopenable, see OpenHead).
	//
	// Built by task 11, under log/lock: the text of h.Note must be the
	// text of h (ErrHead) with Options.Origin (ErrHead); its size at most
	// the committed size and its hash the root of that size of the
	// committed tree (ErrConsistency: the server publishes only heads of
	// its own tree); no larger head in heads/ (ErrConsistency) and a time
	// not before the newest one (ErrHead). Every signature line is
	// verified on its own (one note.Open per line), so that an invalid
	// line is dropped instead of failing the note; the log line must
	// verify with the ingest generation whose certificate is a valid
	// entry of the tree of h and Covers its time (LogKey.Covers, the
	// same rule as Verifier.CheckHead), the cosignatures with
	// Options.Witnesses; the quorum counts distinct witnesses
	// (Options.MinWitnesses). A stored head of the same size whose lines
	// do not give a log signature over a head text is ErrConsistency.
	PublishHead(h *Head) error

	// LogKeys returns a LogKey for every valid ingest certificate of the
	// committed tree (Logged set, Until from the valid_from of the next
	// generation's certificate when that is a valid entry): the keys
	// PublishHead chooses the covering generation from. The log side of
	// the server opens POST /gomail/log/cosign bodies with them (task 11b
	// finding 7: a published head signed by the generation before an
	// ingest rotation). Whether a line is by the generation that covers
	// the head time is decided by PublishHead, not by this list.
	LogKeys() ([]LogKey, error)
}

// Options configures a log on the data directory.
type Options struct {
	// Store is the data directory; the log lives in log/ (Dir).
	Store *store.Store
	// Verifier makes the Log a client log: Check methods run against the
	// head the Verifier last accepted, and Refresh audits new entries.
	// Nil makes it an operator log (server, ceremony): Check methods run
	// against the committed tree; only the server signs heads.
	Verifier *Verifier
	// Known are the fixed note verifiers Head and Refresh use to open
	// heads/<n>.sig.
	//
	//   - Client: the pinned witnesses. The log keys are not fixed at
	//     Open: on every Refresh the client log reads platform/ anew and
	//     adds the verifier of every ingest-<g>.cert there that verifies
	//     against the pinned identity list, whatever its log status
	//     (Verifier.LogKeys, task 03d finding 1). Otherwise the first
	//     head after an ingest rotation, signed by generation g+1 alone,
	//     could never be opened: ingest-<g+1>.cert becomes a logged entry
	//     only in the tree of that very head. Whether the signing
	//     generation was valid at the head's time is decided by
	//     CheckHead (LogKey.Covers), not by Known.
	//   - Operator: the witnesses of witnesses.rec, read at Open (the
	//     server restarts with the new ingest key after a rotation
	//     anyway). Since task 11 the operator log adds the log key of
	//     every valid ingest certificate of the committed tree itself
	//     (Head, Refresh), so Known needs no log key; one given here
	//     opens heads as well.
	Known note.Verifiers
	// Identities anchors the validation of platform entries of an
	// operator log (doc.go "Validity rules"), in the form of pin field 8
	// (CheckIdentities); Open of an operator log fails with ErrPin when
	// it is missing or malformed. Ignored for a client log, whose anchor
	// is Verifier.Identities from its pin.
	//
	// Task 03d finding 2 (replaces the reading of task 03c finding 8f):
	// every operator takes the identity list from a pin, never from
	// files in the data directory and never by deriving a chain from
	// logged successions, so that server, ceremony and clients with the
	// same pin judge every entry alike:
	//
	//   - server: the identity list of its pin, the same
	//     identity-<gen>.pin the clients get, read from a path of the
	//     server configuration outside the data directory (task 15,
	//     proposal "gomail-server --pin <file>", an addition to 9.2;
	//     read limit MaxPinFile). The operator installs every new pin of
	//     a client update on the server as well. Reading: a working copy
	//     platform/identities.rec in the data directory was the
	//     alternative; anybody with write access to the data directory
	//     could change it, and the server would judge differently from
	//     the clients.
	//   - ceremony (Publish): the whole identity list of
	//     PublishOptions.Pin.
	Identities []Identity
	// IndexFile is the audit index of a client log (doc.go "Audit"): a
	// file in the client directory, never in the data directory. Open
	// resolves the symbolic links of its directory, which must exist,
	// and of Store.Root, and refuses with ErrIO a path that lies inside
	// the data directory, also when it leads there through a link, and
	// an index file that is itself a link (task 07c finding 4). It is
	// written atomically with mode 0600 after every Refresh that changed
	// the reference head.
	// It holds IDs, numbers, public keys and hashes (JSON), no record
	// content and no address in clear. Open rebuilds it from entry 0
	// against Verifier.Last when it is missing, damaged, built for
	// another identity list (a new pin) or for another head than Last.
	// Required for a client log, ignored for an operator log.
	IndexFile string
	// Origin is the log origin of the operator's pin (pin field 4, doc.go
	// "Heads"): SignHead signs heads with it and PublishHead and
	// RepairTree accept only heads with it (ErrHead). Task 11: required
	// for SignHead and PublishHead (ErrHead without it), checked with
	// CheckOrigin at Open when set; the ceremony, which signs no heads,
	// leaves it empty. Ignored for a client log, whose origin is
	// Verifier.Origin.
	Origin string
	// Witnesses and MinWitnesses are the server's working copy
	// platform/witnesses.rec (package witness, task 11): the note
	// verifiers of its witnesses, each built with NewWitnessVerifier
	// (names unique and not LogSignerName, keys unique), and the number
	// of distinct cosignatures PublishHead requires. Open of an operator
	// log refuses a set that violates CheckQuorum (ErrWitness); without
	// witnesses PublishHead returns ErrWitness. Ignored for a client log,
	// whose witnesses come from its pin (Verifier.Witnesses).
	Witnesses    []note.Verifier
	MinWitnesses int
	// Now is the injected clock. For a client log it takes precedence
	// over Verifier.Now and Open copies it into the Verifier (task 07b
	// finding 4), so that CheckHead, Fresh and the Pending times use one
	// clock; without it a client log uses Verifier.Now (one of the two is
	// required).
	Now func() time.Time
}
