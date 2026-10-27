package ingest

import (
	"crypto/sha256"
	"sync"

	"github.com/tim-riep/go-mail/internal/store"
)

// chainCacheSize bounds the number of mailboxes whose verified chain is
// kept in memory.
const chainCacheSize = 1024

// chainCache keeps the verified epoch chain of each mailbox, so that DATA
// and the commit need not check every signature of the chain again. An
// entry is bound to the exact bytes it was verified from: the head of
// mailbox.rec, the SHA-256 of every epoch.rec from 1 to the head and the
// SHA-256 of the user.rec of the signer of every epoch, as read for that
// epoch. It is used only if every one of these files still has the same
// bytes; any change, a missing file or a read error leads to a full
// verification. The log checks are not a function of these bytes and are
// run again on every use. So the cache skips only work whose result is
// fixed by the bytes: decoding, the structural chain rules and the
// Ed25519 signatures of the epochs.
type chainCache struct {
	mu      sync.Mutex
	off     bool // tests and benchmarks: always verify in full
	entries map[store.ID]*chainEntry
	full    int // number of full verifications (tests)
}

// chainEntry is one verified chain. It is never changed after it was
// stored; the chain and its epochs are only read.
type chainEntry struct {
	head     uint32
	epochs   []epochCheck // epochs[n-1] is epoch n
	chain    *store.Chain
	headHash [32]byte
}

// epochCheck is what the full verification of one epoch relied on.
type epochCheck struct {
	hash     [32]byte // SHA-256 of epoch.rec
	signer   store.ID
	gen      uint32
	userHash [32]byte // SHA-256 of the signer's user.rec as read for this epoch
	revoked  bool     // gen was not the signer's current generation
}

func (c *chainCache) init() { c.entries = map[store.ID]*chainEntry{} }

func (c *chainCache) get(id store.ID) *chainEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.off {
		return nil
	}
	return c.entries[id]
}

func (c *chainCache) put(id store.ID, e *chainEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.full++
	if c.off {
		return
	}
	if _, ok := c.entries[id]; !ok && len(c.entries) >= chainCacheSize {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[id] = e
}

func (c *chainCache) drop(id store.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.full++
	delete(c.entries, id)
}

// fullChecks returns the number of full verifications so far.
func (c *chainCache) fullChecks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.full
}

// cachedChain returns the cached chain of mbx if every file it was
// verified from still has the same bytes and the log checks pass again.
// The caller holds the mailbox lock and read mbx under it (K8).
func (in *Ingest) cachedChain(mbx *store.Mailbox) (*store.Chain, [32]byte, bool) {
	e := in.chains.get(mbx.ID)
	if e == nil || e.head != mbx.Epoch || len(e.epochs) != int(mbx.Epoch) {
		return nil, [32]byte{}, false
	}
	datas := make([][]byte, len(e.epochs))
	for i := range e.epochs {
		data, err := store.ReadFileLimited(in.st.EpochFile(mbx.ID, uint32(i+1)), store.MaxRecordFile)
		if err != nil || sha256.Sum256(data) != e.epochs[i].hash {
			return nil, [32]byte{}, false
		}
		datas[i] = data
	}
	users := map[store.ID][]byte{}
	for _, ec := range e.epochs {
		raw, ok := users[ec.signer]
		if !ok {
			var err error
			raw, err = store.ReadFileLimited(in.st.UserFile(ec.signer), store.MaxUserFile)
			if err != nil {
				return nil, [32]byte{}, false
			}
			users[ec.signer] = raw
		}
		if sha256.Sum256(raw) != ec.userHash {
			return nil, [32]byte{}, false
		}
	}
	// The same log checks as verifyChainFull and userKey, in their order.
	log := in.cfg.Log
	for i, ec := range e.epochs {
		if log.CheckUser(ec.signer, users[ec.signer]) != nil || log.CheckGeneration(ec.signer, ec.gen) != nil {
			return nil, [32]byte{}, false
		}
		if ec.revoked && log.CheckRevokedSignature(ec.signer, ec.gen, datas[i]) != nil {
			return nil, [32]byte{}, false
		}
		if log.CheckEpoch(mbx.ID, uint32(i+1), datas[i]) != nil {
			return nil, [32]byte{}, false
		}
	}
	return e.chain, e.headHash, true
}
