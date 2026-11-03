// Package client is the user's side of go-mail (gomailctl): key
// generation and registration (2.2), mailbox creation and the epoch
// supply (2.4), and the read paths with every check of 2.4 and section 7:
// signature of the metadata by a certified ingest key, SHA-256 of the
// mail file against the metadata (S06), header fields against the
// metadata, the signed epoch chain with the locally remembered head, the
// epoch rule for received mails, and the version counter.
//
// Private keys come only from the key store of package keys. Nothing the
// client writes into the data directory is plaintext except public keys,
// signed records and the plain mailbox record.
//
// Two versions of the same metadata (task 09b point 5, ErrMetaChanged).
// The client remembers, per mail, the SHA-256 of the metadata file of the
// highest version it has seen. Another file with that version is rejected
// (strictest reading): two valid files with the same version only exist
// after a fork (the server shows members different files, or the mailbox
// lock did not hold between two machines, K2 rule 3, K4). The client
// that sees it cannot resolve this state by itself: say it wrote or saw
// version n+1, and the file in place is another valid version n+1. Read
// and List reject the file, and SetFlags, which reads the version in
// place first, fails the same way, so this client cannot write n+2;
// taking the file in place as the base of n+2 would be the loosening that
// point 5 rules out, and the client does not keep the content of its own
// version n+1 to write n+2 from it. The mail stays hidden for this client
// (a warning names the mail ID) until another user member, for whom the
// file in place checks, writes version n+2 with any flag change: a higher
// version is accepted (TestAttack09bMetaChangedNoRecovery). This is the
// way out; a client never accepts the other version n+1.
//
// Concurrency. A Client is not safe for concurrent use by several
// goroutines, Close included (task 20i point 3): its methods read and
// change its state, its key stores and its caches without a common lock,
// and Close wipes the keys while another method may still use them. The
// caller runs one method at a time per Client, Close after the last one
// has returned; the check for a closed client at the start of every
// method (ErrClosed) does not make a concurrent Close safe. Several
// processes or machines on the same data directory are coordinated by
// the locks of the client directory and of each mailbox, not by this
// package.
package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Errors of the client. Every rejection of a file is reported through
// Config.Warn as well.
var (
	ErrNotRegistered = errors.New("client: no registered user in this client directory")
	ErrRegistered    = errors.New("client: this client directory already has a user")
	ErrConfirm       = errors.New("client: the seed words were not confirmed")
	ErrDevIdentity   = errors.New("client: a development platform identity is accepted only by tests (Config.AllowDevIdentity)")
	ErrPlatform      = errors.New("client: platform certificate not valid")
	ErrUserRecord    = errors.New("client: user.rec in the data directory differs from the registered one")
	ErrRollback      = errors.New("client: mailbox.rec points to an older epoch than already seen")
	ErrEpoch         = errors.New("client: file belongs to an epoch outside the verified chain")
	ErrStaleEpoch    = errors.New("client: mail encrypted for an epoch after a newer epoch had begun")
	// ErrDiscardedEpoch rejects every file of an epoch that a later
	// immediate epoch discarded (2.4 rule 3, K1 point 3).
	ErrDiscardedEpoch = errors.New("client: file belongs to a discarded epoch")
	ErrReplay         = errors.New("client: older metadata version than already seen")
	ErrMailHash       = errors.New("client: mail file does not match its signed metadata")
	ErrMismatch       = errors.New("client: file does not match its location or metadata")
	ErrSigner         = errors.New("client: file not signed by an accepted key")
	ErrWrap           = errors.New("client: epoch keys not available")
	ErrNotFound       = errors.New("client: mail not found")
	// ErrNotMember rejects creating an epoch or rewriting folders.gml by
	// a client that is not a user member (kind 1) of the epochs concerned:
	// a delegate or a recovery recipient never creates epochs (K2 rule 1)
	// and never signs folders.gml (section 4, QUESTIONS Q6).
	ErrNotMember = errors.New("client: only a user member of the mailbox may create epochs or change its folders; a delegate or recovery recipient may not")
	// ErrReadOnly rejects every change by a client opened with
	// RecoverRead: the recovery recipient only reads (K3 point 4, Q1).
	ErrReadOnly = errors.New("client: opened with the recovery key, which only reads")
	// ErrSelfRevoke rejects revoking oneself: the epoch member-removed
	// must be signed by a remaining member (K2 rule 2), and the last user
	// member can never leave.
	ErrSelfRevoke = errors.New("client: a member cannot revoke itself; another user member must do it, and the last user member never")
	// ErrRange rejects a share whose period is not a valid range of past
	// epochs.
	ErrRange = errors.New("client: invalid period of epochs")
	// ErrRecovery reports a missing, unconfirmed or mismatching recovery
	// recipient (K3, Q1).
	ErrRecovery = errors.New("client: recovery recipient not available")
	// ErrPartial reports a share that wrapped only some of the requested
	// existing epochs: an epoch that is not discarded was skipped because
	// this user is not a user member of it or its keys were not
	// available. The wraps written stay; the error names only epoch
	// numbers.
	ErrPartial = errors.New("client: not every requested epoch was wrapped")
	// ErrSeed rejects seed words or shares whose root key is not the root
	// key of the user (DeviceLost, Restore). Nothing is written.
	ErrSeed = errors.New("client: the seed does not belong to this user")
	// ErrDeviceLostPending reports a device lost that was interrupted
	// after user.rec named the new generation: the key store still holds
	// the old one. Running DeviceLost again with the seed completes it.
	ErrDeviceLostPending = errors.New("client: an interrupted device lost must be completed with the seed (device lost)")
	// ErrRevoked rejects a file outside the log signed by a revoked
	// generation that is not countersigned (wrap-accept) or not checked
	// by this client before the revocation (2.2 rule 4, S13).
	ErrRevoked = errors.New("client: signed by a revoked generation")
	// ErrMetaChanged rejects a metadata version whose receipt time
	// (created) or mail hash differs from the one remembered for the mail:
	// both stay the same over all versions (section 7, task 09); or another
	// metadata file with the version already seen (task 09b).
	ErrMetaChanged = errors.New("client: metadata version changes receipt time or mail hash")
	// ErrConflict reports a flag change that lost the race for the next
	// metadata version in every attempt (K4 point 2).
	ErrConflict = errors.New("client: metadata changed concurrently in every attempt")
	// ErrQuery rejects a search term that is not one of the terms of 5.4.
	// It never contains the term.
	ErrQuery = errors.New("client: invalid search term")
	// ErrClosed is returned by every method of a Client after Close that
	// returns an error (task 20h point 2).
	ErrClosed = errors.New("client: the client is closed")
)

// Config configures a client.
type Config struct {
	// Store is the data directory (shared file system in the PoC, 9.1).
	Store *store.Store
	// Dir is the client directory (default ~/.config/gomailctl): key
	// store, own user.rec and local state. It must not be inside the data
	// directory, also not through a symbolic link (task 20o point 3).
	Dir string
	// Pin is the trusted platform identity (2.3) and the anchor of the
	// transparency log (translog doc.go "Pin"): origin, witnesses, quorum
	// and identity list. The client opens the log of the data directory
	// itself with it (task 14); there is no way to run without the log.
	Pin *store.PlatformPin
	// AllowDevIdentity accepts a pin with the development flag (pin field
	// 3, ceremony init --dev). Only tests set it (package testenv, and
	// gomailctl in a build with the tag gomail_test); without it such a
	// pin is refused (ErrDevIdentity). There is no command line flag.
	AllowDevIdentity bool
	// BeforeRefresh, if set, runs before every Refresh of the client log.
	// gomailctl leaves it nil; a test platform (package testenv) lets its
	// server sign and publish a head with witness cosignatures there, as
	// gomail-server does on its own cadence. It cannot weaken a check:
	// Refresh verifies every head it finds.
	BeforeRefresh func()
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Warn receives warnings for the user (stderr in gomailctl).
	Warn func(string)
}

func (cfg *Config) check() error {
	if cfg.Dir == "" {
		return fmt.Errorf("client: incomplete configuration")
	}
	if err := cfg.checkReader(); err != nil {
		return err
	}
	dir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return err
	}
	if insideDataDir(dir, cfg.Store.Root) {
		return errInsideDataDir
	}
	cfg.Dir = dir
	return nil
}

// errInsideDataDir rejects a client directory inside the data directory
// (Config.Dir).
var errInsideDataDir = errors.New("client: the client directory must not be inside the data directory")

// insideDataDir reports whether the absolute path dir is root or lies
// below it, compared as given and with symbolic links resolved as far as
// the paths exist (resolveExisting; L3 of the review of the client
// directories, task 20o point 3): a client directory named through a
// symbolic link into the data directory, at dir itself or at one of its
// parents, is inside it.
func insideDataDir(dir, root string) bool {
	return below(dir, root) || below(resolveExisting(dir), resolveExisting(root))
}

// below reports whether the absolute path p is base or lies below it.
func below(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && filepath.IsLocal(rel) || p == base
}

// resolveExisting returns the absolute path p with the symbolic links of
// its longest prefix that filepath.EvalSymlinks resolves replaced; the
// rest of p, which does not exist (or cannot be resolved), is appended as
// it is.
func resolveExisting(p string) string {
	rest := ""
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Join(p, rest)
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// checkReader checks everything but the client directory, which a
// client opened with RecoverRead does not use.
func (cfg *Config) checkReader() error {
	if cfg.Store == nil || cfg.Pin == nil {
		return fmt.Errorf("client: incomplete configuration")
	}
	if cfg.Pin.Dev && !cfg.AllowDevIdentity {
		return ErrDevIdentity
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Warn == nil {
		cfg.Warn = func(string) {}
	}
	return nil
}

func (cfg *Config) keystorePath() string { return filepath.Join(cfg.Dir, "keystore") }
func (cfg *Config) userPath() string     { return filepath.Join(cfg.Dir, "user.rec") }
func (cfg *Config) statePath() string    { return filepath.Join(cfg.Dir, "state.json") }

// readKeystore reads the sealed key store at path for keys.OpenKeystore
// (Open, DeviceLost; task 20l point 2, F3 of the attack review of task
// 20i, R41). It reads with store.ReadFileLimited, at most
// keys.MaxKeystoreSize bytes: a FIFO in place of the key store is
// refused at once instead of blocking the open until a writer comes,
// and a terminal device does not become the controlling terminal of a
// process that has none (O_NONBLOCK and O_NOCTTY of store.OpenRegular);
// keys.ReadKeystoreFile opens with neither. As there, a file that is
// not regular or too large is keys.ErrKeystore (and store.ErrNotRegular
// or store.ErrTooLarge), a missing one fs.ErrNotExist (and
// store.ErrNotFound).
func readKeystore(path string) ([]byte, error) {
	data, err := store.ReadFileLimited(path, keys.MaxKeystoreSize)
	switch {
	case err == nil:
		return data, nil
	case errors.Is(err, store.ErrNotRegular), errors.Is(err, store.ErrTooLarge):
		return nil, fmt.Errorf("%w: %w", keys.ErrKeystore, err)
	case errors.Is(err, store.ErrNotFound):
		return nil, fmt.Errorf("%w (%w)", err, fs.ErrNotExist)
	}
	return nil, err
}

// state is the client's memory between runs (2.4, section 7): the
// highest epoch seen per mailbox with the hash of its epoch.rec, and the
// highest metadata version per mail.
type state struct {
	UserID     string                   `json:"user_id"`
	Registered bool                     `json:"registered"`
	Mailboxes  map[string]*mailboxState `json:"mailboxes"`
	// Unconfirmed is set by Restore: the client was restored from the
	// seed without another device and trusts on first contact (2.7 "Neue
	// Geräte und Wiederherstellung"); every start warns until a confirmed
	// state exists. TODO(Q20), strictest reading (task 14b point 6): the
	// mark stays until a valid checkpoint of another user member (another
	// user, not another device of this user) was compared with the
	// reference head and agreed (checkCheckpoints: same view, or a
	// checkpoint the own head covers); a witnessed head alone does not
	// clear it, because witnesses check consistency, not completeness. A
	// sole member stays marked for good (a warning, no error).
	Unconfirmed bool `json:"unconfirmed,omitempty"`
	// Checkpointed names, per mailbox, the reference head and the
	// generation of the last checkpoint this client wrote there
	// (checkpointMark; task 14b point 4): Open and every refresh write a
	// checkpoint again whenever the reference head or the generation
	// differs, also after Restore and DeviceLost, which do not change the
	// head. Only IDs, numbers and hashes.
	Checkpointed map[string]string `json:"checkpointed,omitempty"`
	// InviteUsed is set by Register right after the invitation was
	// consumed and before the user entry is appended to the log, so that
	// a resumed Register skips ConsumeInvite (translog doc.go "Who
	// writes", finding 03d-5).
	InviteUsed bool `json:"invite_used,omitempty"`
	// Log is the client log's memory: reference head and pending
	// entries (task 14).
	Log *logMemory `json:"log,omitempty"`
	// Device is the random device ID of this client directory, the first
	// part of the name of its index segments (6.2, K5). Created by the
	// first Index.
	Device string `json:"device,omitempty"`
}

// mailboxState is what this client remembers of one mailbox. It is the
// protection against a server that rolls back or replaces files (2.4,
// K1 point 3, 2.2 point 4, K3, section 7), so it only ever grows. Fixed
// rule (task 06h): no path makes Epoch/EpochHash (the highest epoch seen),
// Epochs (verified and discarded epochs), Checked (check records),
// Recovery (confirmed recovery records), Versions, Folders or Mails of a
// mailbox smaller, and no path removes or replaces the entry of a mailbox:
// not device lost when mailbox.rec is missing (reissueAll), not the
// adoption of memberships (adoptMemberships, which adds entries only).
// Only a command by which the user explicitly asks to forget a mailbox
// could remove an entry; there is none. Reissue is a mark, not memory:
// it is set and cleared. One exception, which removes nothing remembered
// (task 06h): an entry that state.json holds as null (in Epochs, a
// damaged memo) is dropped when the state is loaded (mailboxState); it
// carries no value, and the chain fills it in again.
type mailboxState struct {
	Epoch     uint32            `json:"epoch"`
	EpochHash string            `json:"epoch_hash"`
	Versions  map[string]uint32 `json:"versions"`
	// Epochs remembers every verified epoch: its begin and reason (the
	// first values seen) and whether a later epoch discarded it, so that
	// the epoch rule of 2.4 still holds when a later epoch is removed or
	// replaced (DECISIONS D50) and a discarded epoch never becomes valid
	// again (K1 point 3).
	Epochs map[string]*epochMemo `json:"epochs"`
	// Begins is the format before discarded epochs: the begin of every
	// verified epoch, all of them planned. It is only read, and moved into
	// Epochs.
	Begins map[string]int64 `json:"begins,omitempty"`
	// Recovery holds, per recovery recipient ID, the SHA-256 (hex) of the
	// recovery-pub record whose fingerprint the user confirmed on this
	// device (K3 point 3). Only a confirmed record is used to wrap new
	// epochs for the recovery recipient. TODO(Q1).
	Recovery map[string]string `json:"recovery,omitempty"`
	// Folders holds, per epoch, the highest version of folders.gml seen
	// (section 7 "Gegen Wiedereinspielen", applied to folders.gml).
	Folders map[string]uint32 `json:"folders,omitempty"`
	// Checked is the local check record for files outside the log that
	// a user signed (2.2 rule 4 "Übernahme durch andere Mitglieder",
	// S13): per file ("folders/<n>", "meta/<mail-id>", and per content
	// for a segment, "index/<n>/<device>/<sha-256>", task 09c) the hash,
	// signer and generation of the last version this client verified
	// while the signer's generation was valid, and the size of the
	// reference tree it verified against. Only hashes, IDs and numbers.
	// Records of segments in the format before task 09c
	// ("index/<n>/<device>-<seq>") stay (no path makes Checked smaller);
	// no new ones are made, and one counts only for the file at its place
	// whose hash it names (task 09d, oldSegmentMemo). The record of a
	// segment whose content this client issued again or merged is marked
	// in place, without growing (checkMemo.Next, supersede, task 09d):
	// records are changed, never removed.
	Checked map[string]*checkMemo `json:"checked,omitempty"`
	// Reissue is set by DeviceLost to the new generation if it could not
	// issue every file of this mailbox again (ErrPartial); DeviceLost run
	// again (which always creates the next generation, task 14) works on
	// it in the same run, and Sync clears it once nothing signed by the
	// revoked generation is left and the head no longer names it
	// (syncGenerations). Only a number.
	Reissue uint32 `json:"reissue,omitempty"`
	// Mails holds, per mail, the epoch, the receipt time and the SHA-256
	// of the mail file of the first metadata version seen: every later version
	// must carry the same (section 7, task 09); and the SHA-256 of the
	// metadata file of the highest version seen (task 09b); and, in state
	// files of tasks 09d to 09f, whether this client indexed a pending
	// entry of the mail (no longer used, task 09g). Only hashes over
	// ciphertext, times that stand in clear in the header and epoch
	// numbers.
	Mails map[string]*mailMemo `json:"mails,omitempty"`
	// IndexSeq holds, per epoch, the next sequence number of this
	// device's index segments (6.2, K5); it is checked against the
	// existing files before a segment is created.
	IndexSeq map[string]uint64 `json:"index_seq,omitempty"`
	// Merged and MergedResult held the limit of tasks 09e and 09f on
	// merges (the postings and the segments of the own last merge result
	// per epoch). Since task 09g (Q22 variant A) they are no longer made
	// or used; a state file that holds them is read, and they are kept as
	// they are (D84 (2)).
	Merged       map[string]uint64   `json:"merged,omitempty"`
	MergedResult map[string][]string `json:"merged_result,omitempty"`
}

// mailMemo is what the client remembers of one mail besides its version.
type mailMemo struct {
	Epoch    uint32 `json:"epoch"`
	Received int64  `json:"received"`
	MailHash string `json:"mail_hash"`
	// FileVersion and FileHash name the highest version of the metadata
	// seen and the SHA-256 (hex) of its metadata file (task 09b): another
	// file with the same version is ErrMetaChanged. Only a hash over
	// ciphertext.
	FileVersion uint32 `json:"file_version,omitempty"`
	FileHash    string `json:"file_hash,omitempty"`
	// IndexedMarker and IndexedTerms noted, per kind of pending entry,
	// the epoch in which this client indexed an entry of the mail first
	// (tasks 09d, 09e), and Index did not index an entry of that kind
	// again. Since task 09g every entry that checks is indexed, and only
	// the postings no segment of the epoch holds are written, so that
	// pending/ and index/ restored from a backup stay searchable. The
	// fields are no longer made or used; a state file that holds them is
	// read, and they are kept as they are. A memo that Index made before
	// the metadata of its mail were checked holds only these fields
	// (MailHash empty); noteVersion fills it on the first check.
	IndexedMarker uint32 `json:"indexed,omitempty"`
	IndexedTerms  uint32 `json:"indexed_terms,omitempty"`
}

// epochMemo is what the client remembers of one epoch.
type epochMemo struct {
	Begin     int64 `json:"begin"`
	Immediate bool  `json:"immediate"`
	Discarded bool  `json:"discarded"`
}

// saveHook is called by tests before the state is saved, with c.dirty
// (versions or check records noted and not saved yet); an error makes the
// save fail. It is nil in production.
var saveHook func(dirty bool) error

func loadState(path string) (*state, error) {
	data, err := store.ReadFileLimited(path, 64<<20)
	if errors.Is(err, store.ErrNotFound) {
		return &state{Mailboxes: map[string]*mailboxState{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("client: damaged state file: %w", err)
	}
	if s.Mailboxes == nil {
		s.Mailboxes = map[string]*mailboxState{}
	}
	return &s, nil
}

func saveState(path string, s *state) error {
	data, err := stateData(s)
	if err != nil {
		return err
	}
	return store.WritePrivateFileAtomic(path, data)
}

// stateData is the content of state.json for s.
func stateData(s *state) ([]byte, error) { return json.MarshalIndent(s, "", "  ") }

// Client is an unlocked client. It is not safe for concurrent use: one
// method at a time, Close included (see the package comment, task 20i
// point 3). Its mutex guards only the closed mark and the caches of
// epoch keys and ingest keys, not a method as a whole.
type Client struct {
	cfg   Config
	st    *store.Store
	ks    *keys.Keystore
	user  *store.User
	me    store.ID
	state *state

	unlock func() // releases the lock of the client directory
	// rk is set only for a client opened with RecoverRead: it reads with
	// the recovery key from recovery.wrap, changes nothing and keeps its
	// state in memory only.
	rk *recoveryKey
	// skipLock is set only by tests: the mailbox lock is not taken, to
	// simulate a lock that is not in force across machines (K2 rule 3).
	skipLock bool
	// created holds the epochs written by the running change; they are
	// remembered in the state once mailbox.rec names them (commitHead).
	created []*store.Epoch
	// next is the epoch.rec after the verified chain that the running
	// change found not adoptable (loadChain with adopt), nil if none.
	next *nextEpoch
	mu   sync.Mutex
	// closed is set by Close (under mu); every method that returns an
	// error returns ErrClosed afterwards (open).
	closed    bool
	ingest    map[uint32]ingestKey
	epochKeys map[epochRef]*store.EpochKeys
	// locked is the mailbox whose lock mutate holds (zero otherwise), so
	// that a takeover inside a change writes without taking it again.
	locked store.ID
	// prevKs is set only during step 4 of DeviceLost and its continuation:
	// the key stores of this user's revoked generations (the old key store
	// and those derived from the seed), still used to open the own wraps
	// made for them, to check the templates they signed (oldGenKey) and,
	// since holding the seed proves them, the own wraps they signed
	// (seedProof). See prevGen.
	prevKs []*keys.Keystore
	// noAccept suppresses the wrap-accept of keysFor while DeviceLost
	// countersigns with the new generation itself.
	noAccept bool
	// noTakeover is set during step 2 of DeviceLost: a file signed by a
	// revoked generation with a check record is only checked, not signed
	// again; step 4 signs it with the new generation (reissueFolders).
	noTakeover bool
	// reissuing is set while step 4 of DeviceLost or its continuation in
	// Sync issues again the metadata and index segments a revoked
	// generation signed (reissueMetaAndSegments, task 09d): a file taken
	// over that cannot be signed again is then a failure of the mailbox
	// (errNotReissued), not a warning as in Search, List and Read.
	reissuing bool
	// checkedOwn is set only during a DeviceLost run: step 4 then checks
	// the own files it does not find (missingOwnFiles), and step 2, if
	// the run does it, notes per mailbox the own segments it checked
	// (task 09f, finding low 2; ownFiles).
	checkedOwn map[store.ID]*ownFiles
	// dirty is set when a metadata version or mail memo was noted in the
	// state but not yet saved (checkMeta); saveSeen writes it once per
	// List, Read, Search, Index or SetFlags.
	dirty bool
	// lg is the client log (task 14).
	lg *logConn
	// mbxUnlock releases the mailbox lock that mutate holds (nil
	// without one), so that a replacement by store.ReplaceEpoch, which
	// takes the lock itself, can run inside a change (withoutLock).
	mbxUnlock func()
	// addrRefreshed is set once a check of an address assignment
	// refreshed the client log in the running operation (checkMeta);
	// ready clears it.
	addrRefreshed bool
	// cpSeen holds, per checkpoint file of another client, the hash of
	// the file and the reference head it was checked against
	// (checkCheckpoints).
	cpSeen map[string]string
}

type ingestKey struct {
	pub       ed25519.PublicKey
	validFrom int64
	// until is valid_from of the next generation's certificate once that
	// is a valid entry of the log (superseded), the receipt time from
	// which this generation signs nothing validly (ingestKeyFor).
	until      int64
	superseded bool
	// gen and issuer (identity_gen of ingest-<gen>.cert) name the
	// generation for the revocation rules of pin field 7 (revokedFor).
	gen, issuer uint32
}

type epochRef struct {
	mailbox store.ID
	epoch   uint32
}

// Open unlocks the key store with passphrase and loads the registered
// user. It opens the client log (task 14): Refresh and then always
// CheckFresh (2.3: no verified tree head with witness signatures at most
// 24 hours old, or an own entry withheld, stops everything with ErrLog),
// the reference head into state.json, and CheckUser of the own user.rec
// (a newer logged user.rec makes it outdated: ErrSuperseded; one the log
// does not hold is tried once more after a rebuild of the audit index
// and once more after appending it again, checkOwnUser). The mark
// Unconfirmed of Restore stays until checkCheckpoints compared the view
// with another user member (TODO(Q20)); every start warns while it is
// set. The checkpoints are written when none were written for the
// reference head and the current generation yet. A CreateMailbox
// interrupted after its log entry is completed (resumeMailboxes). A
// directory with the marker .incomplete of an unfinished keygen or restore
// is refused before anything is written (errIncompleteDir, task 20o).
func Open(cfg Config, passphrase []byte) (c *Client, err error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := refuseIncomplete(cfg.Dir); err != nil {
		return nil, err
	}
	// One client process per client directory: the local state (highest
	// epoch, versions) must not be overwritten by a concurrent run.
	if err := mkdirClient(cfg.Dir); err != nil {
		return nil, err
	}
	unlock, err := lockClientDir(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			unlock()
		}
	}()
	st, err := loadState(cfg.statePath())
	if err != nil {
		return nil, err
	}
	if !st.Registered {
		return nil, ErrNotRegistered
	}
	me, err := store.ParseID(st.UserID)
	if err != nil {
		return nil, ErrNotRegistered
	}
	local, err := store.ReadFileLimited(cfg.userPath(), store.MaxUserFile)
	if err != nil {
		return nil, ErrNotRegistered
	}
	user, err := store.DecodeUser(local)
	if err != nil || user.ID != me {
		return nil, ErrNotRegistered
	}
	c = &Client{cfg: cfg, st: cfg.Store, user: user, me: me, state: st,
		ingest: map[uint32]ingestKey{}, epochKeys: map[epochRef]*store.EpochKeys{}}
	lc, err := openLog(&c.cfg, st, false)
	if err != nil {
		return nil, err
	}
	c.lg = lc
	defer func() {
		if err != nil {
			lc.close()
		}
	}()
	if _, err := lc.refresh(); err != nil {
		return nil, err
	}
	// The data directory must hold exactly the user.rec this client
	// registered (2.2), and the log must contain it.
	_, remote, err := cfg.Store.ReadUser(me)
	if err == nil && extendsUser(user, remote) {
		cfg.Warn(warnDeviceLostPending)
		return nil, ErrDeviceLostPending
	}
	if err != nil || string(remote) != string(local) {
		cfg.Warn("WARNUNG: user.rec im Datenverzeichnis weicht vom registrierten Stand ab.")
		return nil, ErrUserRecord
	}
	if err := c.checkOwnUser(local); err != nil {
		return nil, err
	}
	ksData, err := readKeystore(cfg.keystorePath())
	if err != nil {
		return nil, err
	}
	ks, err := keys.OpenKeystore(ksData, passphrase)
	keys.Wipe(ksData)
	if err != nil {
		return nil, err
	}
	g := user.Current()
	if ks.Generation != g.Gen || !ks.Identity.Public().(ed25519.PublicKey).Equal(g.IdentityPub) || !ks.Unwrap.PublicKey().Equal(g.UnwrapPub) {
		ks.Zero()
		if ks.Generation+1 == g.Gen {
			cfg.Warn(warnDeviceLostPending)
			return nil, ErrDeviceLostPending
		}
		return nil, fmt.Errorf("client: the key store does not hold the current generation of the user")
	}
	c.ks = ks
	defer func() {
		if err != nil {
			ks.Zero()
		}
	}()
	// TODO(Q20): every start warns while the view is not compared with a
	// checkpoint of another user member (checkCheckpoints clears it).
	warnUnconfirmed(cfg, st)
	// The checkpoints for the reference head and the current generation,
	// if none were written for them yet (task 14b point 4: also after
	// Restore and DeviceLost, which do not change the head).
	c.writeCheckpoints()
	if err := c.resumeMailboxes(); err != nil {
		return nil, err
	}
	c.unlock = unlock
	return c, nil
}

// UserID returns the user's ID.
func (c *Client) UserID() store.ID { return c.me }

// Close wipes the keys and releases the lock of the client directory.
// Afterwards every method that returns an error returns ErrClosed and
// nothing else (task 20h point 2); UserID and Mailboxes still return the
// public IDs held in memory, and Close again does nothing.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for _, k := range c.epochKeys {
		k.Zero()
	}
	c.epochKeys = map[epochRef]*store.EpochKeys{}
	if c.ks != nil {
		c.ks.Zero()
		c.ks = nil
	}
	c.rk = nil
	c.lg.close()
	if c.unlock != nil {
		c.unlock()
		c.unlock = nil
	}
}

func (c *Client) warn(format string, args ...any) { c.cfg.Warn(fmt.Sprintf(format, args...)) }

func (c *Client) save() error {
	if c.rk != nil {
		// RecoverRead keeps its state in memory (first contact, 2.7).
		return nil
	}
	if saveHook != nil {
		if err := saveHook(c.dirty); err != nil {
			return err
		}
	}
	return saveState(c.cfg.statePath(), c.state)
}

// open returns ErrClosed after Close. Every exported method that
// returns an error calls it first.
func (c *Client) open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	return nil
}

// writable rejects changes by a client opened with RecoverRead.
func (c *Client) writable() error {
	if c.rk != nil {
		return ErrReadOnly
	}
	return nil
}

func (c *Client) mailboxState(id store.ID) *mailboxState {
	ms := c.state.Mailboxes[id.String()]
	if ms == nil {
		ms = &mailboxState{Versions: map[string]uint32{}, Epochs: map[string]*epochMemo{}}
		c.state.Mailboxes[id.String()] = ms
	}
	if ms.Versions == nil {
		ms.Versions = map[string]uint32{}
	}
	if ms.Epochs == nil {
		ms.Epochs = map[string]*epochMemo{}
	}
	if ms.Recovery == nil {
		ms.Recovery = map[string]string{}
	}
	if ms.Folders == nil {
		ms.Folders = map[string]uint32{}
	}
	for k, b := range ms.Begins {
		if _, ok := ms.Epochs[k]; !ok {
			ms.Epochs[k] = &epochMemo{Begin: b}
		}
	}
	ms.Begins = nil
	for k, m := range ms.Epochs {
		if m == nil {
			// A damaged entry is dropped; the chain fills it in again.
			delete(ms.Epochs, k)
		}
	}
	return ms
}

// Mailboxes returns the mailboxes this client knows.
func (c *Client) Mailboxes() []store.ID {
	var out []store.ID
	for k := range c.state.Mailboxes {
		if id, err := store.ParseID(k); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// lockAttempts bounds the attempts of lockClientDir.
const lockAttempts = 8

// dirLockHook, if set, is called by lockClientDir after every lock taken,
// before the path is compared, with the number of the attempt (from 1).
// It is nil in production and set only by tests of this package.
var dirLockHook func(attempt int)

// lockClientDir takes the lock of the client directory (store.LockFile
// on path, the lock file in it) and checks, as far as it can without the
// descriptor, that the file locked is the one path names once the lock
// is held (task 20h point 5, F2 of the attack review of task 20e). A
// concurrent keygen or restore removes the lock file of a directory that
// holds nothing else, under its lock, and replaces the directory
// (lockOnlyDir); a run that opened that file before and gets the lock
// after it was released would hold a lock on a file no other run sees,
// and a third run would make a new lock file and lock it as well.
//
// store.LockFile does not hand out its descriptor, so the file locked is
// not compared itself: path is looked up with os.Stat right before
// store.LockFile and right after it, and the lock is kept only if both
// lookups succeed and name the same file (os.SameFile: device and inode
// number). What this rules out: the file locked, F, is open from the
// open inside store.LockFile until the unlock, so no other file gets its
// inode number meanwhile. If F is still at path after the lock, the
// second lookup names F. If F was removed (or replaced) before the lock
// was granted, the second lookup names another file B or nothing; this
// run then keeps the lock only if the first lookup named a file with
// the same device and inode number as B. A lock file is removed only
// under its lock, so while this run holds a lock on the file path
// names, that file stays at path.
//
// Known limit (task 20i point 1; AUDIT R33, F2 of the attack review of
// task 20e): the first lookup reads only an inode number, it holds no
// file open. If the file it named, A, is removed and closed by everyone
// after the first lookup, its inode number may be given again at once
// (ext4 does so) to a file created later. The comparison is then fooled
// if, between the two lookups (some six system calls apart), A is
// removed, F is opened (or created) here, then locked and removed by
// another run, and a new lock file B created at path gets the inode
// number of A: this run holds a lock on F, which no other run sees, and
// keeps it. That takes three further runs of the same user on the same
// client directory (keygen or restore, which remove a lock file, and
// Open, which creates one) falling into that window; the consequence is
// what the lock exists to prevent, two processes working on the client
// directory at once. A check of the locked descriptor itself would close
// the gap (a store function that returns it; not built).
//
// If a lookup fails or the two differ, the lock is released and taken
// again, at most lockAttempts times (the first lock of a new directory
// creates the file and takes two); then store.ErrLocked. A symbolic link
// is followed, as by the open of the lock file. Open, openForDeviceLost,
// Register and lockOnlyDir take the lock of a client directory this
// way.
//
// Unresolved paths (L7 of the review of the client directories, task 20o
// point 5): the lock registry of the process in store (lockPath in
// lock_unix.go) is keyed by path made absolute with filepath.Abs, not by
// the file, and symbolic links are not resolved. One client directory
// named by two paths (through a symbolic link) in one process gets two
// entries. On Linux the two locks still conflict (open file description
// locks); on the other Unix systems, which have only process locks, a
// process never conflicts with itself, so two clients of one process on
// the same client directory under different paths both get the lock, and
// releasing one releases the other's. gomailctl opens one client
// directory per process; a program that opens several in one process
// names each by one path.
func lockClientDir(path string) (func(), error) {
	for attempt := 1; attempt <= lockAttempts; attempt++ {
		before, berr := os.Stat(path)
		unlock, err := store.LockFile(path)
		if err != nil {
			return nil, err
		}
		if dirLockHook != nil {
			dirLockHook(attempt)
		}
		after, aerr := os.Stat(path)
		if berr == nil && aerr == nil && os.SameFile(before, after) {
			return unlock, nil
		}
		unlock()
	}
	return nil, fmt.Errorf("%w: the lock file of the client directory changed in every attempt", store.ErrLocked)
}

// errIncompleteDir is the error of Open, Register and DeviceLost on a
// directory that holds the marker .incomplete (L2 of the review of the
// client directories, task 20o point 1): it is the temporary directory of
// a keygen or restore that has not finished, never a client directory,
// which loses the marker before its rename (createClientDir). Nothing is
// written into it, not even the lock file.
var errIncompleteDir = errors.New("client: this is the temporary directory of an unfinished keygen or restore (it holds the marker .incomplete), not a client directory")

// refuseIncomplete reports errIncompleteDir if dir holds an entry named
// .incomplete, of any type. A missing dir or marker is nil; any other
// error of os.Lstat is returned (fail closed).
func refuseIncomplete(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, incompleteMarker))
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s", errIncompleteDir, dir)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return err
}

func mkdirClient(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
