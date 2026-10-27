package ceremony

// Interface of the real ceremony (2.3 "Zeremonie", task 03), implemented
// by task 10 (init.go, unlock.go, files.go, pin.go, publish.go). InitDev
// (ceremony.go) stays the development ceremony.
//
// # Where the ceremony runs and what it writes
//
// The ceremony runs on a computer without network from a live system
// (2.3). It never touches the server's data directory. It writes
//
//   - public files into an export directory Out, laid out like the data
//     directory: Out/platform/<file> with the names of section 4;
//   - the client pin into Out/identity-<gen>.pin (not under platform/:
//     the pin reaches clients with a client update, never through the
//     data directory, D58). TODO(task-07): store.PlatformPin has only
//     fields 1 to 3 so far; newPin (pin.go) checks fields 4 to 6 and 8
//     and returns the identity list in Result.Identities, but writes
//     them only once task 07 has added them to store;
//   - private admin and ingest keys into KeyDir (gomail/v1/rec/platform-key,
//     rights 0600, directory 0700, exclusive create, file names
//     <role>-<gen>.key as in D58). KeyDir must not be inside Out and Out
//     not inside KeyDir; an existing KeyDir must have mode 0700 and
//     belong to the user running the ceremony, and its last element must
//     not be a symbolic link, neither when the ceremony starts (checked
//     with Lstat before the path is resolved, task 10e finding 5) nor
//     when the keys are written (ErrKeyDir, task 10b); links in the
//     elements before it are resolved. The operator moves the admin key to the
//     administrator and the ingest key to the server machine (2.3 table).
//
// The platform root and the shares are never written to any file: the
// shares go only to Display, the root exists only in memory and is wiped
// (keys.Seed.Zero) before the function returns. Nothing is written
// before the trial reconstruction succeeded; a failed ceremony leaves Out
// and KeyDir untouched, and the shares shown are worthless.
//
// Writing (files.go, commit): the export is built in a hidden staging
// directory next to Out, the private keys are then created exclusively
// relative to KeyDir opened as an os.Root, and the rename of the
// staging directory to Out is the commit point. Every error before it
// removes the keys written so far and the staging directory. A signal
// in between is deferred: before the commit point it rolls the files
// back, after it it is ignored (CommitGuard). A hard crash before the commit point can
// leave key files in KeyDir and a staging directory ".tmp-ceremony-*"
// next to Out, but never a partial Out: without Out the ceremony did not
// happen, its keys are certified nowhere, and the operator deletes them
// (a new ceremony into the same KeyDir refuses with ErrKeyDir until he
// has).
//
// Publish (online, no secret involved) copies an export directory into
// the data directory and appends every certificate and succession to the
// log (translog: the ceremony is the writer of platform entries).
// Additions to 9.2: 9.2 names only init, ingest-rotate and reshare;
// "gomail-ceremony publish --from <out> --data <dir>" (an offline
// ceremony cannot append to the server's log) and "gomail-ceremony
// succeed" (2.3 "Wechsel der Identität" has no command in 9.2) are
// proposed by task 03.
//
// # Files per ceremony
//
//	Init          Out/platform/identity-1.pub, admin-1.pub, admin-1.cert,
//	              ingest-1.pub, ingest-1.cert, witnesses.rec;
//	              Out/identity-1.pin; KeyDir/admin-1.key, KeyDir/ingest-1.key
//	IngestRotate  Out/platform/ingest-<g>.pub, ingest-<g>.cert; KeyDir/ingest-<g>.key
//	Reshare       nothing (new shares on Display only)
//	Succeed       Out/platform/identity-<g>.pub, identity-<g>.succ;
//	              Out/identity-<g>.pin with the whole identity list 1..g
//	Publish       data/platform/<files of Out/platform> (exclusive, except
//	              witnesses.rec, the server's working copy, which is
//	              replaced) and one log entry per .cert and .succ, in the
//	              order successions by generation, then certificates by
//	              role and generation (translog doc.go "Validity rules")
//
// # --dev from now on
//
// "gomail-ceremony init --dev" (InitDev) stays for tests:
// root without Shamir in an INSECURE file, pin with the development flag
// (dev = 1). A client accepts a pin with dev = 1 only when its Config has
// AllowDevIdentity set; only tests set it, there is no command line flag
// for it (task 14). So gomailctl never accepts a development identity,
// with or without a log, --insecure-no-log disappears (task 15) and the
// RUNBOOK moves to the real ceremony (task 19).

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Errors of the ceremony. Every error wraps one of these or one of
// ErrKeyDir, shamir's, keys', store's, translog's or witness's errors,
// or is the error of CommitGuard.CommitPoint.
var (
	// ErrOptions: a required option is missing.
	ErrOptions = errors.New("ceremony: incomplete options")
	// ErrShares: an invalid "k-of-n", a share of another split, the
	// wrong share index, or fewer shares than the threshold.
	ErrShares = errors.New("ceremony: invalid shares")
	// ErrProbe: the trial reconstruction did not yield the root that
	// derives the exported identity key (2.3 step 4). Nothing is written.
	ErrProbe = errors.New("ceremony: trial reconstruction failed")
	// ErrIdentity: the root rebuilt from the shares does not derive the
	// expected identity key (wrong shares or wrong pin).
	ErrIdentity = errors.New("ceremony: shares do not belong to this platform identity")
	// ErrOutDir: the export directory is not new or empty, or overlaps
	// the key directory.
	ErrOutDir = errors.New("ceremony: unusable export directory")
)

// MaxShareCount is the largest n of "k-of-n" (shamir allows 255; a
// ceremony with more holders is not plausible and every share is asked
// interactively). Reading, not in the specification.
const MaxShareCount = 16

// Shares is a split "k-of-n": Threshold shares of Count reconstruct the
// root (2.3: 3 of 5).
type Shares struct {
	Threshold int
	Count     int
}

// String returns "k-of-n".
func (s Shares) String() string { return fmt.Sprintf("%d-of-%d", s.Threshold, s.Count) }

// ParseShares parses "k-of-n" with k and n in decimal without sign or
// leading zeros and 2 <= k <= n <= MaxShareCount.
func ParseShares(s string) (Shares, error) {
	ks, ns, ok := strings.Cut(s, "-of-")
	if !ok {
		return Shares{}, fmt.Errorf("%w: expected k-of-n", ErrShares)
	}
	k, okK := parseSmall(ks)
	n, okN := parseSmall(ns)
	if !okK || !okN {
		return Shares{}, fmt.Errorf("%w: expected k-of-n with decimal numbers", ErrShares)
	}
	sh := Shares{Threshold: k, Count: n}
	if err := sh.check(); err != nil {
		return Shares{}, err
	}
	return sh, nil
}

// parseSmall parses a decimal number of at most three digits without
// sign or leading zeros.
func parseSmall(s string) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int(s[i]-'0')
	}
	return v, true
}

// check reports whether 2 <= Threshold <= Count <= MaxShareCount.
func (s Shares) check() error {
	if s.Threshold < 2 || s.Count < s.Threshold || s.Count > MaxShareCount {
		return fmt.Errorf("%w: %d-of-%d (2 <= k <= n <= %d)", ErrShares, s.Threshold, s.Count, MaxShareCount)
	}
	return nil
}

// Prompter is the interactive part of a ceremony, as client.Prompter is
// for keygen. Shares are shown on the Display writer of the options, one
// holder at a time; words are entered through AskShare.
type Prompter interface {
	// Handover is called before share index (1-based) of count is
	// written to Display. The command line waits until that holder is
	// at the screen and clears the screen after the holder confirms.
	Handover(index, count int) error
	// AskShare asks for the 30 words of a share. want is the share index
	// the ceremony asks for (trial reconstruction: the tool picks the
	// shares at random with crypto/rand) or 0 for any share (rotation,
	// resharing, succession). The command line normalizes the input
	// (2.2 "Eingabe von Wörtern", S11: NFKD, lower case, split at any
	// white space); shamir.ShareFromWords then requires the exact words.
	// A share with another index than want is ErrShares.
	AskShare(want int) ([]string, error)
}

// CommitGuard may be implemented by a Prompter. The ceremony calls
// BeginCommit before it writes the first file (commit: staging
// directory, keys, export), CommitPoint once the staging directory and
// the keys are written, just before the rename of the staging
// directory to Out (the commit point), and EndCommit after the files
// are complete (committed: the rename succeeded) or every file written
// is removed again (committed false), before it returns. An error of
// CommitPoint is not a failure of the files: the ceremony does not
// rename, removes every file written and returns that error.
//
// The command line (task 10c finding 3, task 10e finding 2) defers its
// abort signals (SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP and the
// others of its abortSignals) from BeginCommit on, so that a signal does
// not leave keys or a staging directory behind:
//
//   - a signal before CommitPoint makes CommitPoint fail; the files are
//     rolled back, and EndCommit(false) ends the program with
//     "abgebrochen" and exit code 130;
//   - a signal after CommitPoint (the export is complete once the rename
//     succeeded) is ignored: EndCommit(true) returns, the ceremony
//     reports its results and that a signal was ignored, exit code 0;
//     should the rename fail after all, EndCommit(false) ends the
//     program with exit code 130 as before the commit point.
type CommitGuard interface {
	BeginCommit()
	CommitPoint() error
	EndCommit(committed bool)
}

// InitOptions configures Init.
type InitOptions struct {
	Out    string // export directory, new or empty
	KeyDir string // private admin and ingest keys
	Shares Shares // 2.3: 3-of-5
	// Origin of the log (translog.CheckOrigin), pinned for clients.
	Origin string
	// Witnesses and MinWitnesses go into the pin (binding for clients,
	// Q4) and into platform/witnesses.rec (the server's working copy).
	// 2.7: at least one witness. Init refuses, before anything else, a
	// quorum with 2*MinWitnesses <= len(Witnesses)
	// (translog.CheckQuorum, task 03b finding S1).
	Witnesses    []witness.Key
	MinWitnesses int
	// Display receives the shares and nothing else secret; it is never
	// a file (the command passes the terminal).
	Display  io.Writer
	Prompter Prompter
	Now      func() time.Time
	// Rand is crypto/rand when nil; only tests set it.
	Rand io.Reader
}

// Init runs the initial ceremony (2.3 steps 1 to 4):
//
//  1. root: 32 bytes from crypto/rand (keys.NewSeed)
//  2. identity 1, admin 1 and ingest 1 derived (keys.DerivePlatform),
//     admin and ingest certified by identity 1 with valid_from = Now
//  3. root split with shamir.Split(Threshold, Count); each share shown
//     as 30 words (shamir.Share.Words) on Display after
//     Prompter.Handover, nowhere else
//  4. trial reconstruction: Threshold share indices chosen at random
//     with crypto/rand (2.3: three for 3-of-5), asked back with
//     AskShare(index), combined with shamir.Combine; identity 1 derived
//     from the result must equal the exported identity key, else
//     ErrProbe and nothing is written
//  5. only then the files of the table above are written; the root, the
//     shares and all private keys are wiped
//
// Result.Pin is the pin written to Out/identity-1.pin (dev = 0), with
// the identity list (pin field 8, translog doc.go "Pin") holding the one
// element (1, identity 1); until task 07 extends store.PlatformPin the
// list is in Result.Identities and the pin file carries fields 1 to 3
// only (TODO(task-07), pin.go).
func Init(opts InitOptions) (*Result, error) { return runInit(opts) }

// UnlockOptions are the options shared by the ceremonies that need the
// root again: three holders come together (2.3 last paragraph).
type UnlockOptions struct {
	// IdentityGen and IdentityPub are the current platform identity as
	// the operator trusts it: from the pin, or from a succession that
	// verifies against it. The root rebuilt from the shares must derive
	// exactly this key (ErrIdentity).
	IdentityGen uint32
	IdentityPub ed25519.PublicKey
	Prompter    Prompter
	Now         func() time.Time
}

// RotateOptions configures IngestRotate.
type RotateOptions struct {
	UnlockOptions
	Out    string
	KeyDir string
	// Gen is the new ingest generation: the highest existing one + 1
	// (the operator reads it from data/platform/ingest-*.cert), at least
	// 2. A gap or an existing generation is not detectable offline;
	// Publish refuses it: a gap with translog.ErrPrerequisite (translog
	// doc.go "Validity rules": <role>-<g>.cert with g > 1 follows
	// <role>-<g-1>.cert), an existing generation with other content with
	// an error that wraps both store.ErrExists and translog.ErrDuplicate.
	Gen uint32
	// ValidFrom is valid_from of the new certificate, the switch time
	// (see IngestRotate); the zero time means Now. A time before Now is
	// ErrOptions (task 10c finding 7).
	ValidFrom time.Time
}

// RotateResult names the new ingest generation.
type RotateResult struct {
	Gen uint32
	Pub ed25519.PublicKey
}

// IngestRotate creates ingest generation Gen (2.3 "Für einen neuen
// Ingest-Schlüssel"): shares asked with AskShare(0) until the threshold
// of the first share is reached, root combined and checked against
// IdentityPub, ingest key Gen derived, certificate signed by the identity
// with valid_from = ValidFrom (Now when zero), files written (see
// table), root wiped. After
// Publish the server switches to the new key; the log's signer key (Q4)
// changes with it, so witnesses need the new --log-key and clients build
// their Verifier.LogKeys from the new certificate, which they read from
// platform/ before they open a head, logged or not, and count only once
// it is logged in the tree of the head (translog.LogKey, task 03d
// finding 1). The server signs
// heads with generation Gen from valid_from of ingest-<Gen>.cert on and
// with Gen-1 only before it: clients judge the signing generation
// against the time line of each head (translog.LogKey.Covers, task 03c
// finding 6), so a head after valid_from signed only by Gen-1 is
// refused.
//
// The old ingest key stays valid for checking old signatures: its
// certificate is not revoked and metadata received while it was the
// current key remain verifiable. Rule (strictest reading without Q8,
// translog doc.go "Platform generations", task 14): an ingest signature
// of generation Gen-1 is valid only for metadata received before
// valid_from of ingest-<Gen>.cert once that certificate is in the log,
// and only for heads with an earlier time line. valid_from is therefore
// the switch time, not the time of the ceremony: mail that the server
// ingests with the old key after valid_from would be rejected by
// clients. The operator passes the planned switch time as ValidFrom
// (gomail-ceremony ingest-rotate --valid-from, task 10), after Publish,
// and switches the server to the new key at that time; mail received
// between valid_from and the switch is lost for clients (it stays in
// the mailbox, unverifiable). A ValidFrom before Now (the clock of the
// ceremony, UnlockOptions.Now) is refused with ErrOptions before any
// share is asked, and again after the shares were entered, before the
// certificate is signed (task 10c finding 7): it would make ingest
// signatures of the old generation made since then invalid
// retroactively. Without ValidFrom the certificate is valid from Now
// read after the shares were entered.
func IngestRotate(opts RotateOptions) (*RotateResult, error) { return runRotate(opts) }

// ReshareOptions configures Reshare.
type ReshareOptions struct {
	UnlockOptions
	// Shares is the new split; it may differ from the old one.
	Shares  Shares
	Display io.Writer
	Rand    io.Reader
}

// Reshare splits the same root anew (2.3 "Neuverteilung der Anteile"):
// shares asked with AskShare(0), root combined and checked against
// IdentityPub, a new split with a new random split identifier shown on
// Display, trial reconstruction as in Init. No file is written.
//
// The old shares are not invalidated and cannot be recalled: a Shamir
// share is a point of a polynomial whose constant term is the root, and
// any Threshold old shares still rebuild the same root. Resharing helps
// against lost shares and when holders change and destroy their old
// shares; it does nothing against shares that are already compromised.
// If Threshold old shares may be in wrong hands, the root itself must be
// replaced: a new Init with a new platform identity, distributed by a
// client update (2.3 "Wechsel der Identität", compromise case). The new
// split identifier only lets the tool warn when old and new shares are
// mixed (shamir.ErrMismatch); Reshare draws the split again until its
// identifier differs from the one of the shares entered.
func Reshare(opts ReshareOptions) error { return runReshare(opts) }

// SucceedOptions configures Succeed.
type SucceedOptions struct {
	UnlockOptions
	Out string
	// Compromised marks IdentityGen as compromised (2.3: the succession
	// chain is useless then). TODO(ask): see Succeed.
	Compromised bool
	// Identities is the identity list of the current pin (pin field 8),
	// ending with IdentityGen and IdentityPub (translog.CheckIdentities);
	// the new pin carries it plus the new generation.
	Identities []translog.Identity
	// Origin, Witnesses and MinWitnesses are copied into the new pin;
	// the quorum rule of InitOptions applies.
	Origin       string
	Witnesses    []witness.Key
	MinWitnesses int
}

// Succeed creates identity generation IdentityGen+1 (2.3 "Wechsel der
// Identität"): shares asked, root combined and checked against
// IdentityPub, identity IdentityGen+1 derived, and
//
//   - regular change: the succession gomail/v1/rec/platform-succ signed by
//     identity IdentityGen (keys.NewPlatformSuccession, valid_from = Now)
//     into Out/platform/identity-<g>.succ, the key into
//     Out/platform/identity-<g>.pub, and a pin for new clients
//     Out/identity-<g>.pin; existing clients follow the succession from
//     the log (translog.Log.CheckPlatform on identity-<g>.succ) and
//     remember the new generation;
//   - compromise (Compromised): no succession (the attacker could sign
//     one himself); only the pin Out/identity-<g>.pin for a client update,
//     listing IdentityGen as revoked only if Q8 is decided as proposed
//     (translog doc.go "Pin", field 7, TODO(ask) Q8: (role, gen,
//     revoked_at_size), revoked_at_size the committed log size the
//     operator reads before the ceremony).
//     TODO(ask): certificates of admin and ingest keys issued by the
//     compromised generation must be reissued by the new one, which needs
//     new admin and ingest generations (a certificate file per role and
//     generation exists only once); the specification does not say so.
//
// In both cases the new pin carries the whole identity list (pin field
// 8): the list of the old pin (passed in Identities, ending with
// IdentityGen and IdentityPub) plus (IdentityGen+1, new key), so that a
// new device can check certificates issued by every earlier generation
// (translog.CheckIdentities, task 03c finding 3; Reading). The operator
// installs the new pin on the server as well (gomail-server --pin,
// translog Options.Identities, task 03d finding 2). After a compromise
// generation IdentityGen+1 has no succession in the log; a later
// regular succession identity-<IdentityGen+2>.succ is valid against
// every pin whose list holds IdentityGen+1, because generations of the
// list need no logged succession (translog doc.go "Validity rules").
//
// Every generation of Identities must derive from the rebuilt root
// (ErrIdentity otherwise). Result.Identities is the new list; the pin
// file carries it only once task 07 has extended store.PlatformPin
// (TODO(task-07), pin.go).
func Succeed(opts SucceedOptions) (*Result, error) { return runSucceed(opts) }

// PublishOptions configures Publish.
type PublishOptions struct {
	// From is an export directory written by a ceremony.
	From string
	// Data is the data directory of the server.
	Data *store.Store
	// Log receives one Append(translog.KindPlatform, ...) per certificate
	// and succession.
	Log translog.Log
	// Pin is the identity the files must verify against: certificates
	// signed by an identity generation of the pin's identity list (field
	// 8) or of a succession above it. The log's anchor is the whole
	// identity list of this pin (translog Options.Identities, task 03d
	// finding 2, which replaces the reading of task 03c finding 8f), the
	// same list the clients and the server judge with.
	Pin *store.PlatformPin
	// Identities is the identity list of Pin (field 8). TODO(task-07):
	// store.PlatformPin carries no field 8 yet; until it does, the caller
	// passes the list here (Result.Identities of Init or Succeed), and
	// nil means the list of PinIdentities(Pin), which exists only for a
	// pin of generation 1. It must end with Pin's generation and key
	// (translog.CheckIdentities).
	Identities []translog.Identity
}

// Publish copies Out/platform/ of a ceremony into the data directory and
// logs its certificates and successions (see the table at the top). Every
// certificate and succession is verified against Pin before anything is
// written; files that already exist with the same content are skipped,
// with other content they are store.ErrExists (for a certificate or
// succession also translog.ErrDuplicate). A certificate <role>-<g>.cert
// with g > 1 whose predecessor <role>-<g-1>.cert is neither in the
// export nor in data/platform/ is translog.ErrPrerequisite, as Append
// would report it (translog doc.go "Validity rules"); a certificate or
// succession whose signature fails is translog.ErrOrder.
//
// Order (translog doc.go "Who writes", later entries: record first, then
// log entry): all files are written first, then the log entries are
// appended. A crash in between leaves certificates in platform/ that are
// not logged, which gives nobody anything (translog doc.go "Platform
// generations"); running Publish again skips the identical files and
// appends again (Append is idempotent).
func Publish(opts PublishOptions) error { return runPublish(opts) }
