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
//     their quorum and the identity list 1..gen), and with field 7 (the
//     revoked platform generations, D93) once a pin revokes one: every
//     later pin carries the list over;
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
// proposed by task 03; "admin-rotate", "revoke" and "succeed
// --compromised" come with D93 (task 21c).
//
// # Revocation (D93)
//
// A compromised platform generation is revoked in field 7 of a new pin
// (store.PlatformRevoked: role, generation, revoked_at_size,
// revoked_at_time): Succeed with Compromised for the current identity
// generation, Revoke for an admin or ingest generation. Whatever the
// generation issues or concerns from log index revoked_at_size on is
// invalid, and what it signs with a time from revoked_at_time on
// (translog doc.go "Platform generations"); what it logged before stays
// valid. The operator reads size N and time T of a witness-confirmed
// head before the ceremony (RUNBOOK 7.3); the ceremony writes
// revoked_at_size = N and revoked_at_time = T + 1 ms (D93 addendum: the
// confirmed head itself stays valid). The ceremony runs offline and
// knows no head: it checks N and T for plausibility only (checkBoundary:
// 1 <= N <= translog.MaxTreeSize, 2025-01-01T00:00:00Z <= T <= the clock
// of the ceremony + translog.MaxClockSkew, T in milliseconds; the lower
// bound catches a time in seconds). Publish knows the log: a pin with
// field 7 is accepted only when the newest published head of the data
// directory carries the witness quorum of the pin, is at least as large
// as every revoked_at_size and not earlier than every revoked_at_time -
// 1 ms, and when the certificate of every revoked admin and ingest
// generation is a valid entry of the log below that element's
// revoked_at_size (else the role would be locked for good, translog
// doc.go "Reading for the operator") with a valid_from before the
// element's revoked_at_time (unless the generation was not valid yet at
// that head). That newest head is the one the operator log opens, with
// the log signature of any valid ingest certificate, also one that field
// 7 revokes at the head's time (such a head is reported,
// PublishOptions.RevokedHead, and moved by "gomail-server log repair"
// afterwards); and a new successor of an ingest generation that is
// revoked at some time (by its own element or by the element of the
// identity generation that certified it) must have a valid_from not
// after that time (D93 addendum, checkSuccessors). A revocation stays in
// every later pin (newPin, addRevoked); its boundary is never moved, and
// a revoked admin or ingest key is never certified again (runRotate).
//
// # Files per ceremony
//
//	Init          Out/platform/identity-1.pub, admin-1.pub, admin-1.cert,
//	              ingest-1.pub, ingest-1.cert, witnesses.rec;
//	              Out/identity-1.pin; KeyDir/admin-1.key, KeyDir/ingest-1.key
//	IngestRotate  Out/platform/ingest-<g>.pub, ingest-<g>.cert; KeyDir/ingest-<g>.key
//	AdminRotate   Out/platform/admin-<g>.pub, admin-<g>.cert; KeyDir/admin-<g>.key
//	Reshare       nothing (new shares on Display only)
//	Succeed       Out/platform/identity-<g>.pub, identity-<g>.succ;
//	              Out/identity-<g>.pin with the whole identity list 1..g;
//	              after a compromise (Compromised) no identity-<g>.succ,
//	              and the pin revokes generation g-1 in field 7
//	Revoke        Out/identity-<g>.pin: the pin of the same identity
//	              generation g with one more element in field 7 (admin or
//	              ingest)
//	Publish       data/platform/<files of Out/platform> (exclusive; a
//	              certificate or succession whose name has no valid log
//	              entry, and its public key, replaced atomically;
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
	// ErrRevocation: a revocation (Succeed with Compromised, Revoke) that
	// is not plausible or not allowed: a boundary out of range or after
	// the clock of the ceremony, a role other than admin or ingest for
	// Revoke, a generation the pin already revokes, too many revoked
	// generations; for Publish a pin whose field 7 contradicts the log
	// or the data directory. Nothing is asked or written.
	ErrRevocation = errors.New("ceremony: invalid revocation")
	// ErrCompromised: a succession after a compromise
	// (SucceedOptions.Compromised) without the boundary of the
	// revocation (HeadSize, HeadTime): without it the
	// compromised generation would go on issuing certificates that
	// Publish, the log and clients accept (2.3: clients reject every
	// signature of it from the update on). The error wraps ErrRevocation
	// as well. Nothing is asked or written.
	ErrCompromised = errors.New("ceremony: a succession after a compromise needs the boundary of the revocation (revoked_at_size and revoked_at_time)")
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

// RotateOptions configures IngestRotate and AdminRotate.
type RotateOptions struct {
	UnlockOptions
	Out    string
	KeyDir string
	// Gen is the new ingest (admin) generation: the highest existing
	// one + 1 (the operator reads it from data/platform/ingest-*.cert or
	// admin-*.cert), at least 2. A gap or an existing generation is not detectable offline;
	// Publish refuses it: a gap with translog.ErrPrerequisite (translog
	// doc.go "Validity rules": <role>-<g>.cert with g > 1 follows
	// <role>-<g-1>.cert), an existing generation with other content with
	// an error that wraps both store.ErrExists and translog.ErrDuplicate.
	Gen uint32
	// ValidFrom is valid_from of the new certificate, the switch time
	// (see IngestRotate); the zero time means Now. A time before Now is
	// ErrOptions (task 10c finding 7), with two exceptions for
	// IngestRotate (D93 addendum, checkValidFrom):
	//   - Revoked revokes ingest generation Gen-1: ValidFrom must be its
	//     revoked_at_time exactly (the zero time means it; anything else
	//     is ErrRevocation), so that some ingest generation signs heads
	//     at every time and no signature of Gen-1 before its boundary
	//     becomes invalid;
	//   - Revoked revokes identity generation IdentityGen-1 (the pin of
	//     succeed --compromised): ValidFrom may lie in the past down to
	//     its revoked_at_time, not before (ErrOptions). Publish refuses a
	//     successor of an ingest generation certified by the revoked
	//     identity whose valid_from lies after that time.
	// When Revoked revokes both, with the identity's revoked_at_time
	// earlier than the predecessor's own, the earlier time applies if
	// identity generation IdentityGen-1 certified Gen-1, else the own
	// one; the ceremony does not know which, so ValidFrom must be one of
	// the two, given explicitly (anything else, the zero time included,
	// is ErrRevocation naming both). With the identity's time not earlier
	// the own one applies as above.
	ValidFrom time.Time
	// Revoked is field 7 of the pin the rotation runs with (the command
	// line passes the pin of --pin): ValidFrom above, and a generation
	// Gen that it revokes for the role is ErrRevocation before any share
	// is asked (its key, derived from the root and Gen, is the stolen
	// one: a revoked key is never certified again).
	Revoked []store.PlatformRevoked
}

// RotateResult names the new ingest or admin generation.
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
// current key remain verifiable. Rule (D93,
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
//
// A compromised ingest generation is not ended by the rotation alone (it
// could still sign metadata dated before valid_from): Revoke revokes it
// in a new pin (D93, RUNBOOK 7.3.3). Order: Revoke first, then
// IngestRotate with the new pin (Revoked) and ValidFrom equal to
// revoked_at_time of the revoked generation (required, see ValidFrom): a
// later ValidFrom would leave the time from revoked_at_time to ValidFrom
// without a valid ingest generation (no head can be signed, clients stop
// 24 hours after the last one). The same holds after Succeed with
// Compromised for the ingest generation the compromised identity
// certified (cascade, D93 addendum); Publish enforces it
// (checkSuccessors) and reports a revoked ingest generation without
// successor (PublishOptions.IngestGap).
func IngestRotate(opts RotateOptions) (*RotateResult, error) {
	return runRotate(opts, store.KeyRoleIngest)
}

// AdminRotate creates admin generation Gen (D93 (3), RUNBOOK 7.3.4) as
// IngestRotate creates an ingest generation: shares asked, root checked
// against IdentityPub, admin key Gen derived, certificate admin-<Gen>.cert
// signed by identity IdentityGen with valid_from = ValidFrom (Now when
// zero; a time before Now is ErrOptions, before any share is asked and
// again after), files Out/platform/admin-<Gen>.pub, admin-<Gen>.cert and
// KeyDir/admin-<Gen>.key. Admin generation Gen-1 assigns addresses
// validly only before valid_from of admin-<Gen>.cert once that
// certificate is in the log (translog: admin supersession); the new key
// assigns from valid_from on. A gap or an existing generation is refused
// by Publish as for IngestRotate. After Succeed with Compromised the
// rotation under the new identity is mandatory (D93 (4)): it ends the
// admin generations the compromised identity issued, a thief's as well.
// AdminRotate alone does not end a leaked admin key: the old generation
// keeps assigning validly with a valid_from before that of the new
// certificate (backdated); Revoke revokes it (RUNBOOK 7.3.4).
func AdminRotate(opts RotateOptions) (*RotateResult, error) {
	return runRotate(opts, store.KeyRoleAdmin)
}

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
	// chain is useless then, D93 (4)): the new pin revokes IdentityGen in
	// field 7 with HeadSize and HeadTime, and no succession is
	// written (see Succeed).
	Compromised bool
	// HeadSize and HeadTime (milliseconds since 1970 UTC) are size and
	// time of a witness-confirmed head of the log, read by the operator
	// before the ceremony: the boundary of the revocation is
	// revoked_at_size = HeadSize and revoked_at_time = HeadTime + 1 ms
	// (D93 addendum: the confirmed head itself stays valid). Required
	// with Compromised (both zero is ErrCompromised, an implausible value
	// ErrRevocation, checked before any share is asked: checkBoundary);
	// without Compromised they must be zero (ErrOptions).
	HeadSize int64
	HeadTime int64
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
//   - compromise (Compromised, gomail-ceremony succeed --compromised,
//     D93 (4)): no succession (the thief could sign one himself); the
//     pin Out/identity-<g>.pin for a client update, whose field 7
//     revokes generation IdentityGen at (HeadSize, HeadTime + 1 ms)
//     (store.PlatformRevoked, role store.KeyRoleIdentity), and the public
//     key Out/platform/identity-<g>.pub, which Publish copies into the
//     data directory (no log entry: a public key is none). Generation g
//     is valid by the pin alone (translog doc.go "Validity rules":
//     generations of the list need no logged succession), and Publish
//     takes it without identity-<g>.succ because the pin revokes g-1.
//     The compromised generation stays in the identity list (what it
//     logged before revoked_at_size stays verifiable); what it issues or
//     concerns from log index revoked_at_size on is invalid for the
//     operator log, Publish, the server and every client with the new
//     pin. Admin and ingest must be issued anew under generation g
//     (AdminRotate, IngestRotate with the new pin; D93 (4), RUNBOOK
//     7.3.5): only the supersession rules end the admin and ingest
//     generations the compromised identity issued, a thief's ones logged
//     before the boundary included. A client with the old pin knows
//     nothing of it (no succession in the log): the new pin reaches
//     clients by a client update only. A compromised root (or Threshold
//     shares in wrong hands) is no case for Succeed: a new Init with a
//     new origin (D93 (5)).
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
// reaches the log; the chain may start anew at a generation whose
// predecessor the pin revokes (after a compromise). The new pin carries
// field 7 of Pin over, plus the compromised generation with
// Compromised.
//
// Every generation of the list must derive from the rebuilt root
// (ErrIdentity otherwise). Result.Pin is the new pin.
func Succeed(opts SucceedOptions) (*Result, error) { return runSucceed(opts) }

// RevokeOptions configures Revoke.
type RevokeOptions struct {
	UnlockOptions
	// Out is the export directory, new or empty; it receives only the new
	// pin Out/identity-<g>.pin (g = IdentityGen, the same name as the
	// current pin: the operator replaces the old pin everywhere).
	Out string
	// Pin is the pin of the current identity, as for Succeed: generation
	// and key equal to IdentityGen and IdentityPub (ErrIdentity), not a
	// development pin.
	Pin *store.PlatformPin
	// Role is store.KeyRoleAdmin or store.KeyRoleIngest (ErrRevocation
	// otherwise: an identity generation is revoked by Succeed with
	// Compromised), Gen the compromised generation (at least 1).
	Role uint8
	Gen  uint32
	// HeadSize and HeadTime are the head of the boundary as in
	// SucceedOptions (revoked_at_size = HeadSize, revoked_at_time =
	// HeadTime + 1 ms), required (ErrRevocation).
	HeadSize int64
	HeadTime int64
}

// Revoke revokes admin or ingest generation Gen (D93 (4), RUNBOOK 7.3.3
// and 7.3.4): the boundary is checked (checkBoundary), and Gen must not
// be revoked by Pin already (ErrRevocation), before any share is asked;
// then shares are asked with AskShare(0), the root is combined and
// checked against IdentityPub and every generation of the identity list
// of Pin (ErrIdentity; the holders confirm the revocation with their
// shares, as for every other change of the trust anchor), and the new
// pin is written to Out/identity-<IdentityGen>.pin: everything of Pin
// (identity list, origin, witnesses, quorum, field 7) plus the element
// (Role, Gen, HeadSize, HeadTime + 1) in field 7. Nothing is signed.
//
// The pin is not signed and is distributed like any new pin (server,
// administrator, clients); a client or server with the old pin knows
// nothing of the revocation. Revoke does not check that generation Gen
// exists (it runs offline); Publish with the new pin refuses a pin that
// revokes an admin or ingest generation without a certificate in the
// data directory (a mistyped generation, ErrRevocation). A revoked
// ingest generation that is the current one of the server needs a new
// one first (IngestRotate; the server refuses to start with a revoked
// own generation), a revoked admin generation a new one for further
// address assignments (AdminRotate). Result.Pin is the new pin,
// Result.KeyDir is empty.
func Revoke(opts RevokeOptions) (*Result, error) { return runRevoke(opts) }

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
	// gomail-server does (OpenLog, with the identity list and field 7 of
	// Pin); tests pass their own.
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
	// IngestGap, when not nil, is called for every ingest generation gen
	// that Pin revokes at time at (by its own element of field 7 or by
	// the element of the identity generation that certified it) whose
	// successor ingest-<gen+1>.cert in data/platform/ has a valid_from
	// after at (logged before; a new one in the export is refused,
	// checkSuccessors), or that has no successor yet (validFrom 0):
	// from at on no ingest generation signs heads validly until
	// validFrom, and clients stop 24 hours after the last head (task 21a
	// review F4). Publish goes on; the command line warns.
	IngestGap func(gen uint32, at, validFrom int64)
	// RevocationsChecked, when not nil, is called when Pin has field 7
	// and it passed the checks against the log, with the newest
	// published head it was checked against (for the message of the
	// command line).
	RevocationsChecked func(head *translog.Head)
	// RevokedHead, when not nil, is called when Pin has field 7 and the
	// newest published head it was checked against (RevocationsChecked)
	// carries the log signature of an ingest generation gen that Pin
	// revokes at time at <= the head's time (by its own element or by the
	// element of the identity generation that certified it): the operator
	// log opens its newest head with every valid ingest certificate, but
	// clients refuse this one, and "gomail-server log repair" moves it to
	// log/heads-revoked/ (attack review 21c F3). If the boundary was read
	// from it, or from a head of the same size it replaced, no head the
	// boundary comes from stays in heads/. Publish goes on; the command
	// line warns.
	RevokedHead func(head *translog.Head, gen uint32, at int64)
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
//     files that already exist with the same content are skipped. A
//     certificate or succession of data/platform/ with other content is
//     replaced by the export's when the log holds no valid entry of its
//     name under Pin (the entry there is invalid, such as the thief's
//     certificate that field 7 invalidates, or there is none): the name
//     is free, and translog doc.go "Reading for the operator" reissues
//     it under the same name (attack review 21c F1); the public key of
//     an admin or ingest certificate is replaced together with it. Both
//     are replaced atomically, under the server lock, after every other
//     check. Any other file with other content is store.ErrExists (for
//     a certificate or succession also translog.ErrDuplicate), naming
//     both files. A certificate <role>-<g>.cert with g > 1 whose
//     predecessor <role>-<g-1>.cert is neither in the export nor a
//     valid entry of the log is translog.ErrPrerequisite, as Append
//     would report it (translog doc.go "Validity rules"), before any
//     file is written. The succession identity-<g>.succ of
//     every generation g >= 2 that the export depends on (an
//     identity-<g>.pub, the predecessor of identity-<g+1>.succ, the
//     issuer of a certificate; tasks 15f point 3 and 15g points 1 and 2)
//     must be in the export or a valid entry of the log; one that is
//     only in data/platform/ (a crash before its log entry) counts only
//     if it verifies against the pin, and Publish then logs it first;
//     otherwise translog.ErrPrerequisite (a client with an older pin
//     could not follow the chain; there is no flag around it). The one
//     exception is the compromise case (Succeed with Compromised, D93
//     (4)): a generation g whose predecessor g-1 the pin revokes
//     (field 7) needs no succession, the chain starts anew at g. A
//     certificate or succession whose signature fails is
//     translog.ErrOrder;
//   - field 7 of the pin, when it has one (D93; ErrRevocation): the
//     newest published head of the log must exist, carry the witness
//     quorum of the pin (signatures of its witnesses, fields 5 and 6)
//     and be at least as large as every revoked_at_size and not earlier
//     than every revoked_at_time - 1 ms of the list (the boundaries come
//     from a witness-confirmed head of this log; a larger size or a
//     later time is a mistyped value or a head of another log, and
//     would leave entries of a compromised generation valid);
//     revoked_at_time - 1 ms must not lie before 2025-01-01 (a time in
//     seconds); the certificate of every revoked admin or ingest
//     generation must be a valid entry of the log below that element's
//     revoked_at_size (a mistyped generation leaves the compromised one
//     valid, and one without such a certificate locks the role for
//     good: translog doc.go "Reading for the operator"), and the
//     element's revoked_at_time must lie after valid_from of that
//     certificate when the generation was valid at the head's time (else
//     it would never have been valid). The newest published head is the
//     one the operator log opens: with the log signature of any valid
//     ingest certificate, also of a generation that field 7 revokes at
//     the head's time; such a head is reported (RevokedHead);
//   - a new certificate ingest-<g+1>.cert of the export whose
//     predecessor ingest generation g is revoked at time A (by its own
//     element, or by the element of the identity generation that
//     certified ingest-<g>.cert, the cascade of D93) must have a
//     valid_from not after A (D93 addendum: no time without an ingest
//     generation that signs heads); ErrRevocation otherwise;
//   - every certificate and succession that Publish would log and that
//     is not a valid entry of the log yet, against field 7: one issued
//     by a revoked identity generation, a succession to one, or the
//     certificate of a revoked admin or ingest generation is
//     translog.ErrRevoked (an ErrOrder), before anything is written; by
//     the check above every log index it could get lies at or after the
//     boundary, and Append would refuse it after the files are written.
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
