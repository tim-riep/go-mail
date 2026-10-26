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
	ErrReplay        = errors.New("client: older metadata version than already seen")
	ErrMailHash      = errors.New("client: mail file does not match its signed metadata")
	ErrMismatch      = errors.New("client: file does not match its location or metadata")
	ErrSigner        = errors.New("client: file not signed by an accepted key")
	ErrWrap          = errors.New("client: epoch keys not available")
	ErrNotFound      = errors.New("client: mail not found")
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
	// Log is the transparency log (phase 1: translog.Unverified).
	Log translog.Log
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Warn receives warnings for the user (stderr in gomailctl).
	Warn func(string)
}

func (cfg *Config) check() error {
	if cfg.Store == nil || cfg.Dir == "" || cfg.Pin == nil || cfg.Log == nil {
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
}

type mailboxState struct {
	Epoch     uint32            `json:"epoch"`
	EpochHash string            `json:"epoch_hash"`
	Versions  map[string]uint32 `json:"versions"`
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
	return store.WriteFileAtomic(path, data)
}

// Client is an unlocked client.
type Client struct {
	cfg   Config
	st    *store.Store
	ks    *keys.Keystore
	user  *store.User
	me    store.ID
	state *state

	mu        sync.Mutex
	ingest    map[uint32]ingestKey
	epochKeys map[epochRef]*store.EpochKeys
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
func Open(cfg Config, passphrase []byte) (*Client, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if !cfg.Log.Verified() {
		cfg.Warn(translog.Warning)
	}
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
	if err != nil || string(remote) != string(local) {
		cfg.Warn("WARNUNG: user.rec im Datenverzeichnis weicht vom registrierten Stand ab.")
		return nil, ErrUserRecord
	}
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
		return nil, fmt.Errorf("client: the key store does not hold the current generation of the user")
	}
	return &Client{cfg: cfg, st: cfg.Store, ks: ks, user: user, me: me, state: st,
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
}

func (c *Client) warn(format string, args ...any) { c.cfg.Warn(fmt.Sprintf(format, args...)) }

func (c *Client) save() error { return saveState(c.cfg.statePath(), c.state) }

func (c *Client) mailboxState(id store.ID) *mailboxState {
	ms := c.state.Mailboxes[id.String()]
	if ms == nil {
		ms = &mailboxState{Versions: map[string]uint32{}}
		c.state.Mailboxes[id.String()] = ms
	}
	if ms.Versions == nil {
		ms.Versions = map[string]uint32{}
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
