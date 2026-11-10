package client

import (
	"encoding/json"
	"errors"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Hooks for the fuzz targets of task 26E (fuzz_test.go): they reach the
// checks of the client below Open, so that a target needs neither the
// passphrase (Argon2id) nor a new client per input.

// ChainView is what loadChain made of a mailbox of the data directory.
type ChainView struct {
	// Data holds the encodings of the epochs of the chain, from epoch 1,
	// adopted ones after the head included.
	Data [][]byte
	// Err is why the chain ends before the head (ErrRollback,
	// store.ErrChain), nil for a whole chain.
	Err error
	// Next reports an epoch.rec after the chain that was not adopted.
	Next bool
}

// LoadChainView runs loadChain on mbx; with adopt as a change or Sync
// does, without changing anything afterwards.
func (c *Client) LoadChainView(mbx store.ID, adopt bool) (*ChainView, error) {
	ch, err := c.loadChain(mbx, adopt)
	if err != nil {
		return nil, err
	}
	return &ChainView{Data: ch.data, Err: ch.err, Next: ch.next != nil}, nil
}

// Remembered returns the highest epoch c remembers for mbx and the
// SHA-256 (hex) of its epoch.rec (state.json, section 7).
func (c *Client) Remembered(mbx store.ID) (uint32, string) {
	ms := c.state.Mailboxes[mbx.String()]
	if ms == nil {
		return 0, ""
	}
	return ms.Epoch, ms.EpochHash
}

// StateData returns the state of c as state.json would hold it.
func (c *Client) StateData() ([]byte, error) { return stateData(c.state) }

// SetStateData replaces the state of c in memory by data (from
// StateData) and forgets the checkpoints seen, so that every input of a
// fuzz target starts from the same state.
func (c *Client) SetStateData(data []byte) error {
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	c.state = &s
	c.cpSeen = nil
	return nil
}

// ReferenceHead returns the reference head of the client log of c.
func (c *Client) ReferenceHead() *translog.Head {
	c.lg.mu.Lock()
	defer c.lg.mu.Unlock()
	return c.lg.v.Last
}

// CheckpointChecker verifies the chain of mbx once and returns
// checkCheckpoint against its head, for the checkpoint file data of
// device of user.
func (c *Client) CheckpointChecker(mbx store.ID) (func(user, device store.ID, data []byte) error, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	if ch.err != nil {
		return nil, ch.err
	}
	head, _ := ch.head()
	if head == nil {
		return nil, errors.New("client: empty chain")
	}
	return func(user, device store.ID, data []byte) error {
		return c.checkCheckpoint(head, store.CheckpointRef{User: user, Device: device}, data)
	}, nil
}

// OpenWithState opens the client of c once more in dir, whose
// state.json the caller wrote, as Open does from the state file on:
// loadState, the registration, the client log with the reference head
// and the pending entries of the state (openLog, refresh) and the check
// of the own user.rec. The key store and user.rec are those of c (Open
// takes them from the passphrase and the client directory). Unlike Open
// it writes no checkpoints, completes no interrupted mailbox and takes no
// lock; warn receives the warnings. The returned client shares the key
// store of c: it is never closed, only dropped.
func (c *Client) OpenWithState(dir string, warn func(string)) (*Client, error) {
	cfg := c.cfg
	cfg.Dir, cfg.Warn = dir, warn
	if err := cfg.check(); err != nil {
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
	if err != nil || me != c.me {
		return nil, ErrNotRegistered
	}
	local, err := store.ReadFileLimited(c.cfg.userPath(), store.MaxUserFile)
	if err != nil {
		return nil, err
	}
	nc := &Client{cfg: cfg, st: cfg.Store, user: c.user, me: me, state: st, ks: c.ks,
		ingest: map[uint32]ingestKey{}, epochKeys: map[epochRef]*store.EpochKeys{}}
	lc, err := openLog(&nc.cfg, st, false)
	if err != nil {
		return nil, err
	}
	nc.lg = lc
	if _, err := lc.refresh(); err != nil {
		return nil, err
	}
	if err := nc.checkOwnUser(local); err != nil {
		return nil, err
	}
	warnUnconfirmed(cfg, st)
	return nc, nil
}
