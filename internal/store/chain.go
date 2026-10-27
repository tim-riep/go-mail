package store

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tim-riep/go-mail/internal/envelope"
)

// ErrChain reports a broken epoch chain (2.4).
var ErrChain = errors.New("store: broken epoch chain")

// Chain checks the epoch chain of one mailbox (2.4, K1, K2) without any
// input or output; client and server share it. Epochs are added in order
// from 1; Add rejects the first epoch that breaks a rule and leaves the
// chain unchanged then, so the chain always holds the valid prefix.
//
// Chain checks structure only. The signatures (with the signer's key from
// user.rec, valid generation) and the log are checked by the caller.
type Chain struct {
	epochs    []*Epoch // epochs[i] is epoch i+1
	hashes    [][32]byte
	discarded map[uint32]bool
}

// NewChain returns an empty chain.
func NewChain() *Chain { return &Chain{discarded: map[uint32]bool{}} }

// Head returns the newest epoch, nil for an empty chain. The head is never
// discarded: only a later epoch can discard it.
func (c *Chain) Head() *Epoch {
	if len(c.epochs) == 0 {
		return nil
	}
	return c.epochs[len(c.epochs)-1]
}

// Epoch returns epoch n of the chain, discarded or not; nil if the chain
// does not hold it.
func (c *Chain) Epoch(n uint32) *Epoch {
	if n == 0 || uint64(n) > uint64(len(c.epochs)) {
		return nil
	}
	return c.epochs[n-1]
}

// Discarded reports whether a later epoch of the chain discarded epoch n.
// A discarded epoch is never used again (2.4 rule 3, K1 point 3).
func (c *Chain) Discarded(n uint32) bool { return c.discarded[n] }

// Begin returns the begin of epoch n. It reports false if the chain does
// not hold n or n is discarded: a discarded epoch never begins.
func (c *Chain) Begin(n uint32) (int64, bool) {
	e := c.Epoch(n)
	if e == nil || c.discarded[n] {
		return 0, false
	}
	return e.Begin, true
}

// Add appends e, whose canonical encoding is data. It checks, in this
// order, and stops at the first violation (ErrChain):
//
//  1. the same mailbox as the chain;
//  2. number = head + 1, the first epoch is 1;
//  3. prev_hash = SHA-256 of the encoding of the predecessor (none for 1);
//  4. suite not older than the predecessor's (3.5);
//  5. the signer is a user member of the predecessor and of e, and its
//     entry in e carries exactly signer_gen (K2 rules 1 and 2: a removed
//     member is not in e and so cannot sign the epoch that removes it);
//  6. discards names exactly the epochs of the chain that are not yet
//     discarded and begin later than e, no more and no fewer (2.4 rule 1);
//     a number that is already discarded is never named again; a regular
//     epoch discards nothing, so no epoch that is not discarded may begin
//     later than it (rule 2);
//  7. e does not begin before the last predecessor that is not discarded,
//     counting the ones e discards (rule 4: discarded epochs are skipped).
//
// Rules 6 and 7 overlap. Once rule 6 holds, every predecessor that is not
// discarded and not named in discards begins no later than e, so rule 7
// can no longer fail: a decreasing begin is always reported by rule 6
// ("regular epoch ... begins before" for a regular epoch, "does not
// discard ..., which begins later" for an immediate one). Rule 7 is kept
// as a second line: mutation tests showed that each of the two rules
// alone rejects a decreasing begin, so removing one of them would go
// unnoticed by a test that only expects ErrChain; the tests therefore pin
// the texts of rule 6. Likewise a number that is already discarded
// ("discards epoch ... again") would otherwise be caught by the check that
// a named epoch begins later, because a discarded epoch is never counted
// as beginning later; its own text is pinned as well.
func (c *Chain) Add(e *Epoch, data []byte) error {
	if e == nil {
		return fmt.Errorf("%w: no epoch", ErrChain)
	}
	enc, err := e.Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChain, err)
	}
	if !bytes.Equal(enc, data) {
		return fmt.Errorf("%w: epoch %d does not match its encoding", ErrChain, e.Number)
	}
	prev := c.Head()
	if prev != nil && e.MailboxID != prev.MailboxID {
		return fmt.Errorf("%w: epoch %d belongs to another mailbox", ErrChain, e.Number)
	}
	if uint64(e.Number) != uint64(len(c.epochs))+1 {
		return fmt.Errorf("%w: epoch %d follows epoch %d", ErrChain, e.Number, len(c.epochs))
	}
	if prev == nil {
		if e.PrevHash != [32]byte{} {
			return fmt.Errorf("%w: epoch 1 names a predecessor", ErrChain)
		}
	} else {
		if e.PrevHash != c.hashes[len(c.hashes)-1] {
			return fmt.Errorf("%w: epoch %d does not name epoch %d", ErrChain, e.Number, prev.Number)
		}
		if err := envelope.CheckSuiteTransition(prev.Suite, e.Suite); err != nil {
			return fmt.Errorf("%w: %v", ErrChain, err)
		}
		if _, ok := prev.Member(e.SignerID); !ok {
			return fmt.Errorf("%w: epoch %d signed by a non-member of epoch %d", ErrChain, e.Number, prev.Number)
		}
	}
	if m, ok := e.Member(e.SignerID); !ok || m.Gen != e.SignerGen {
		return fmt.Errorf("%w: epoch %d signed by a non-member of itself or with another generation", ErrChain, e.Number)
	}
	// Rule 6: the discards.
	named := make(map[uint32]bool, len(e.Discards))
	for _, n := range e.Discards {
		if c.discarded[n] {
			return fmt.Errorf("%w: epoch %d discards epoch %d again", ErrChain, e.Number, n)
		}
		named[n] = true
	}
	for _, p := range c.epochs {
		if c.discarded[p.Number] || p.Begin <= e.Begin {
			if named[p.Number] {
				return fmt.Errorf("%w: epoch %d discards epoch %d, which does not begin later", ErrChain, e.Number, p.Number)
			}
			continue
		}
		if !named[p.Number] {
			if !e.Reason.Immediate() {
				return fmt.Errorf("%w: regular epoch %d begins before epoch %d", ErrChain, e.Number, p.Number)
			}
			return fmt.Errorf("%w: epoch %d does not discard epoch %d, which begins later", ErrChain, e.Number, p.Number)
		}
	}
	// Rule 7: begin never decreases along the epochs that are not
	// discarded.
	for i := len(c.epochs) - 1; i >= 0; i-- {
		p := c.epochs[i]
		if c.discarded[p.Number] || named[p.Number] {
			continue
		}
		if e.Begin < p.Begin {
			return fmt.Errorf("%w: epoch %d begins before epoch %d", ErrChain, e.Number, p.Number)
		}
		break
	}
	c.epochs = append(c.epochs, e)
	c.hashes = append(c.hashes, EpochHash(data))
	for n := range named {
		c.discarded[n] = true
	}
	return nil
}
