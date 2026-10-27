package ceremony

// Interface of the real ceremony (2.3 "Zeremonie", task 03), implemented
// by task 10 (init.go, unlock.go, files.go, pin.go, publish.go). InitDev
// (initdev_dev.go, tag gomail_dev) stays the development ceremony.
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
//     data directory, D58), with fields 1 to 6 and 8 of
//     store.PlatformPin (newPin, pin.go; the origin, the witnesses with
//     their quorum and the identity list 1..gen; field 7 only if Q8 is
//     decided as proposed);
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
// Publish (online, no secret involved, while no server runs) copies an
// export directory into the data directory and appends every
// certificate and succession to the operator log of the data directory
// (translog: the ceremony is the writer of platform entries).
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
//	              (the compromise case is locked, ErrCompromised, Q19)
//	Publish       data/platform/<files of Out/platform> (exclusive;
//	              witnesses.rec, the server's working copy, only when the
//	              data directory has none, and it must equal the pin's
//	              witnesses and quorum; replaced by the pin's only with
//	              ReplaceWitnesses) and one log entry per .cert and
//	              .succ, in the order successions by generation, then
//	              certificates by role and generation (translog doc.go
//	              "Validity rules"); a succession of data/platform/ that
//	              the export depends on and that is not logged yet is
//	              logged first
//
// # --dev from now on
//
// "gomail-ceremony init --dev" (InitDev) stays for tests, and only in a
// build with the tag gomail_dev (task 15b point 4): root without Shamir
// in an INSECURE file, pin with the development flag (dev = 1). A
// client accepts a pin with dev = 1 only when its Config has
// AllowDevIdentity set; only tests set it, there is no command line flag
// for it (task 14). So gomailctl never accepts a development identity,
// with or without a log, --insecure-no-log disappears (task 15; task 15b
// for gomail-ceremony) and the RUNBOOK moves to the real ceremony (task
// 19).

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
	// ErrCompromised: a succession after a compromise
	// (SucceedOptions.Compromised) is locked until the revocation of a
	// platform generation is specified. TODO(Q19): without a mark in the
	// pin, the succession or the log, the compromised generation would
	// go on issuing certificates that Publish, the log and clients
	// accept (2.3 asks that clients reject every signature of it from
	// the update on). Nothing is asked or written.
	ErrCompromised = errors.New("ceremony: not available yet: the revocation of a platform generation is not specified (Q19)")
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
// Result.Pin is the pin written to Out/identity-1.pin (dev = 0): Origin,
// Witnesses and MinWitnesses of the options (fields 4 to 6) and the
// identity list (pin field 8, translog doc.go "Pin") holding the one
// element (1, identity 1). The certificates are valid from Now (the clock
// of the ceremony computer, which the command line shows before the
// first prompt).
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
	// chain is useless then). Locked: Succeed refuses it with
	// ErrCompromised before anything else (TODO(Q19), see Succeed).
	Compromised bool
	// Pin is the pin of the current identity: generation and key equal to
	// IdentityGen and IdentityPub (ErrIdentity otherwise), not a
	// development pin. The new pin carries its identity list (field 8)
	// plus the new generation, and its origin, witnesses and quorum
	// (fields 4 to 6) unless changed below.
	Pin *store.PlatformPin
	// Origin, when set, must equal the origin of Pin (ErrOptions): the
	// origin of a log does not change (a new origin is a new log, Q10
	// point 4).
	Origin string
	// Witnesses and MinWitnesses, when set (not nil, not 0), replace
	// those of Pin in the new pin: a change only when asked for. The
	// quorum rule of InitOptions applies to the result.
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
//   - compromise (Compromised, gomail-ceremony succeed --compromised):
//     LOCKED (task 15f point 1, Q19 stopping point 2): Succeed returns
//     ErrCompromised before it checks or asks anything, and the command
//     line refuses the flag as a usage error. TODO(Q19): the compromised
//     generation stays in the identity list of the new pin (old
//     certificates must stay verifiable), and nothing in the pin, the
//     succession or the log marks it: its owner could go on issuing
//     ingest-<n>.cert and admin-<n>.cert that Publish copies, the
//     operator log takes as valid and clients with the new pin accept
//     (the test TestVerifyCompromisedIdentityStillIssues documents it,
//     skipped until Q19 is answered). The code below the lock stays as
//     task 15b built it and is unreachable: no succession (the attacker
//     could sign one himself); the pin Out/identity-<g>.pin for a client
//     update and the public key Out/platform/identity-<g>.pub, which
//     Publish copies into the data directory (no log entry: a public key
//     is none). Generation g is valid by the pin alone (translog doc.go
//     "Validity rules": generations of the list need no logged
//     succession).
//     TODO(Q19): task 15b asks for a succession that carries a mark
//     "compromised", after whose log entry (not only after its
//     valid_from) the predecessor is invalid, handled by clients and
//     server as translog does it. Neither exists: the succession
//     gomail/v1/rec/platform-succ (package keys, phase 0) has no such
//     field, the pin has no field 7 (Q8 is open: (role, gen,
//     revoked_at_size), translog doc.go "Pin"), Verifier.Revoked stays
//     empty, and no rule of translog makes a generation invalid from a
//     log entry on. A new field or record is not built here (strictest
//     reading: the compromised generation stays valid for everything the
//     log holds; only what the new generation signs is new). Until then
//     the compromised ingest key is replaced by IngestRotate under the
//     new identity: from valid_from of that certificate, once it is
//     logged, the old ingest generation signs nothing validly (translog
//     doc.go "Platform generations"; the server refuses it,
//     ingest.ErrSuperseded).
//     TODO(Q19): certificates of admin and ingest keys issued by the
//     compromised generation must be reissued by the new one, which needs
//     new admin and ingest generations (a certificate file per role and
//     generation exists only once; there is no admin rotation, Q8 (d));
//     the specification does not say so.
//
// The new pin carries the whole identity list (pin field 8): the list
// of Pin (ending with IdentityGen and IdentityPub) plus
// (IdentityGen+1, new key), so that a new device can check certificates
// issued by every earlier generation (translog.CheckIdentities, task 03c
// finding 3; Reading), and origin, witnesses and quorum of Pin unless
// the options change witnesses or quorum. The operator installs the new
// pin on the server as well (gomail-server --pin, translog
// Options.Identities, task 03d finding 2) before Publish (Q10 point 5).
// Publish requires the succession of the predecessor for a succession
// of generation 3 or higher (task 15f point 3), so a chain without a gap
// reaches the log; after a compromise (locked) generation IdentityGen+1
// would have no succession and the next regular one would need a way
// around that check (Q19).
//
// Every generation of the list must derive from the rebuilt root
// (ErrIdentity otherwise). Result.Pin is the new pin.
func Succeed(opts SucceedOptions) (*Result, error) { return runSucceed(opts) }

// PublishOptions configures Publish.
type PublishOptions struct {
	// From is an export directory written by a ceremony.
	From string
	// Data is the data directory of the server.
	Data *store.Store
	// Pin is the pin the server runs with, with the identity list of
	// field 8; after a succession the new one (Q10 point 5: the operator
	// installs the new pin on the server before Publish). The files must
	// verify against its identity list only: every identity generation
	// the export or data/platform/ names must be in the list. The log's
	// anchor is the same list (translog Options.Identities, task 03d
	// finding 2), the one the clients and the server judge with.
	Pin *store.PlatformPin
	// Log receives one AppendPlatform per certificate and succession. Nil
	// (the command line) opens the operator log of Data against Pin as
	// gomail-server does (OpenLog); tests pass their own.
	Log translog.Log
	// ReplaceWitnesses (gomail-ceremony publish --replace-witnesses, task
	// 15f point 2) replaces platform/witnesses.rec of Data, the server's
	// working copy, by the witnesses and the quorum of Pin when they
	// differ, instead of refusing with translog.ErrMismatch: the way a
	// change made on purpose with succeed --witness/--min-witnesses
	// reaches a data directory. The replacement is atomic, under the
	// server lock, and only after every other check passed (in
	// particular: the pin knows every identity generation of
	// data/platform/ and of the log). A witnesses.rec in the export must
	// still equal the pin's.
	//
	// The pin file is not signed (store.PlatformPin): with
	// ReplaceWitnesses the witnesses and the quorum the server will
	// trust rest on the authenticity of the pin file alone, which the
	// operator takes from the ceremony computer as his trust anchor,
	// exactly as for the start of gomail-server. Publish only refuses a
	// pin that contradicts data/platform/ or the log (an old pin, a
	// foreign identity); it cannot tell a forged pin of the right
	// identity list with other witnesses (task 15g point 4).
	ReplaceWitnesses bool
	// WitnessesReplaced, when not nil, is called once witnesses.rec was
	// replaced, with the working copy before and after (for the message
	// of the command line). It is not called when nothing was replaced.
	WitnessesReplaced func(before, after *witness.Witnesses)
}

// Publish copies Out/platform/ of a ceremony into the data directory and
// logs its certificates and successions (see the table at the top). It
// holds the server lock locks/server for its whole run (9.1, D70): while
// a server runs on the data directory it refuses with ErrServer, and no
// server starts meanwhile. Before anything is written it checks
//
//   - platform/ of the data directory against Pin as gomail-server does
//     at its start (Q10 point 5): an identity generation above the pin's
//     (identity-<g>.pub, identity-<g>.succ, a certificate issued by it)
//     or a contradiction to its identity list is translog.ErrMismatch;
//     so is a succession or a certificate there whose signature does not
//     verify with the pin's list (task 15g point 2b; the operator
//     removes such a file on purpose), and a valid succession in the log
//     above the pin's generation (task 15g point 3, also when its files
//     are gone from platform/);
//   - witnesses.rec of the export and of the data directory against the
//     witnesses and the quorum of Pin (fields 5 and 6): a difference is
//     translog.ErrMismatch, the working copy is never replaced silently;
//     it is written from the pin when the data directory has none, and
//     replaced by the pin's only with ReplaceWitnesses (the export's
//     must equal the pin's in any case);
//   - the operator log (OpenLog, when Log is nil): tiles against
//     tree.rec, the newest published head, if any, with a valid log
//     signature;
//   - every certificate and succession against the identity list of Pin:
//     a generation above it is translog.ErrMismatch, a succession of a
//     listed generation must name the list's key (translog.ErrMismatch);
//     files that already exist with the same content are skipped, with
//     other content they are store.ErrExists (for a certificate or
//     succession also translog.ErrDuplicate). A certificate
//     <role>-<g>.cert with g > 1 whose predecessor <role>-<g-1>.cert is
//     neither in the export nor in data/platform/ is
//     translog.ErrPrerequisite, as Append would report it (translog
//     doc.go "Validity rules"). The succession identity-<g>.succ of
//     every generation g >= 2 that the export depends on (an
//     identity-<g>.pub, the predecessor of identity-<g+1>.succ, the
//     issuer of a certificate; tasks 15f point 3 and 15g points 1 and 2)
//     must be in the export or a valid entry of the log; one that is
//     only in data/platform/ (a crash before its log entry) counts only
//     if it verifies against the pin, and Publish then logs it first;
//     otherwise translog.ErrPrerequisite (a client with an older pin
//     could not follow the chain; there is no flag around it, the
//     compromise case that would leave such a gap is locked, Q19); a
//     certificate or succession whose signature fails is
//     translog.ErrOrder.
//
// Order (translog doc.go "Who writes", later entries: record first, then
// log entry, and the head last): all files are written first, then the
// log entries are appended (translog.Log.AppendPlatform), always in the
// order of the chain: successions by generation (g-1 before g), then
// certificates; the head that covers them is signed by the server once
// it runs again, with the pin it must be started with (gomail-server
// checks platform/ against it). A crash in between leaves certificates
// and successions in platform/ that are not logged, which gives nobody
// anything (translog doc.go "Platform generations"; nothing counts a
// file of platform/ as logged); running Publish again skips the
// identical files and appends again (Append is idempotent).
func Publish(opts PublishOptions) error { return runPublish(opts) }
