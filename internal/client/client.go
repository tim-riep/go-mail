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
package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Errors of the client. Every rejection of a file is reported through
// Config.Warn as well.
var (
	ErrNotRegistered = errors.New("client: no registered user in this client directory")
	ErrRegistered    = errors.New("client: this client directory already has a user")
	ErrConfirm       = errors.New("client: the seed words were not confirmed")
	ErrDevIdentity   = errors.New("client: a development platform identity is accepted only with --insecure-no-log")
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
	// both stay the same over all versions (section 7, task 09).
	ErrMetaChanged = errors.New("client: metadata version changes receipt time or mail hash")
	// ErrConflict reports a flag change that lost the race for the next
	// metadata version in every attempt (K4 point 2).
	ErrConflict = errors.New("client: metadata changed concurrently in every attempt")
	// ErrQuery rejects a search term that is not one of the terms of 5.4.
	// It never contains the term.
	ErrQuery = errors.New("client: invalid search term")
)

// Config configures a client.
type Config struct {
	// Store is the data directory (shared file system in the PoC, 9.1).
	Store *store.Store
	// Dir is the client directory (default ~/.config/gomailctl): key
	// store, own user.rec and local state. It must not be inside the data
	// directory.
	Dir string
	// Pin is the trusted platform identity (2.3).
	Pin *store.PlatformPin
	// Log is the transparency log (phase 1: translogtest.Unverified).
	Log translog.Log
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
	if rel, err := filepath.Rel(cfg.Store.Root, dir); err == nil && filepath.IsLocal(rel) || dir == cfg.Store.Root {
		return fmt.Errorf("client: the client directory must not be inside the data directory")
	}
	cfg.Dir = dir
	return nil
}

// checkReader checks everything but the client directory, which a
// client opened with RecoverRead does not use.
func (cfg *Config) checkReader() error {
	if cfg.Store == nil || cfg.Pin == nil || cfg.Log == nil {
		return fmt.Errorf("client: incomplete configuration")
	}
	if cfg.Pin.Dev && cfg.Log.Verified() {
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
	// state exists. TODO(task-14): cleared once a tree head with witness
	// signatures has been checked.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
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
// it is set and cleared.
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
	// S13): per file ("folders/<n>") the hash, signer and generation of the
	// last version this client verified while the signer's generation was
	// valid. Only hashes, IDs and numbers.
	Checked map[string]*checkMemo `json:"checked,omitempty"`
	// Reissue is set by DeviceLost to the new generation if it could not
	// issue every file of this mailbox again (ErrPartial); DeviceLost run
	// again then continues instead of creating a generation, and Sync
	// clears it once nothing signed by the revoked generation is left
	// (syncGenerations). Only a number.
	Reissue uint32 `json:"reissue,omitempty"`
	// Mails holds, per mail, the epoch, the receipt time and the SHA-256
	// of the mail file of the first metadata version seen: every later version
	// must carry the same (section 7, task 09). Only hashes over
	// ciphertext and times that stand in clear in the header.
	Mails map[string]*mailMemo `json:"mails,omitempty"`
	// IndexSeq holds, per epoch, the next sequence number of this
	// device's index segments (6.2, K5); it is checked against the
	// existing files before a segment is created.
	IndexSeq map[string]uint64 `json:"index_seq,omitempty"`
}

// mailMemo is what the client remembers of one mail besides its version.
type mailMemo struct {
	Epoch    uint32 `json:"epoch"`
	Received int64  `json:"received"`
	MailHash string `json:"mail_hash"`
}

// epochMemo is what the client remembers of one epoch.
type epochMemo struct {
	Begin     int64 `json:"begin"`
	Immediate bool  `json:"immediate"`
	Discarded bool  `json:"discarded"`
}

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
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return store.WritePrivateFileAtomic(path, data)
}

// Client is an unlocked client.
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
	next      *nextEpoch
	mu        sync.Mutex
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
	// dirty is set when a metadata version or mail memo was noted in the
	// state but not yet saved (checkMeta); saveSeen writes it once per
	// List, Read, Search, Index or SetFlags.
	dirty bool
}

type ingestKey struct {
	pub       ed25519.PublicKey
	validFrom int64
}

type epochRef struct {
	mailbox store.ID
	epoch   uint32
}

// Open unlocks the key store with passphrase and loads the registered
// user. It warns on every start without a verifying log (translog).
func Open(cfg Config, passphrase []byte) (c *Client, err error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	// One client process per client directory: the local state (highest
	// epoch, versions) must not be overwritten by a concurrent run.
	if err := mkdirClient(cfg.Dir); err != nil {
		return nil, err
	}
	unlock, err := store.LockFile(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			unlock()
		}
	}()
	if !cfg.Log.Verified() {
		cfg.Warn(translog.Warning)
	}
	// TODO(phase3-translog): tree head with witness signature at most 24 hours old (2.3).
	if err := cfg.Log.CheckFresh(cfg.Now()); err != nil {
		return nil, err
	}
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
	// TODO(phase3-translog): own user.rec included in the log (2.7).
	if err := cfg.Log.CheckUser(me, local); err != nil {
		return nil, err
	}
	ksData, err := keys.ReadKeystoreFile(cfg.keystorePath())
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
	warnUnconfirmed(cfg, st)
	return &Client{cfg: cfg, st: cfg.Store, ks: ks, user: user, me: me, state: st, unlock: unlock,
		ingest: map[uint32]ingestKey{}, epochKeys: map[epochRef]*store.EpochKeys{}}, nil
}

// UserID returns the user's ID.
func (c *Client) UserID() store.ID { return c.me }

// Close wipes the keys.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.epochKeys {
		k.Zero()
	}
	c.epochKeys = map[epochRef]*store.EpochKeys{}
	if c.ks != nil {
		c.ks.Zero()
		c.ks = nil
	}
	c.rk = nil
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
	return saveState(c.cfg.statePath(), c.state)
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

func mkdirClient(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
