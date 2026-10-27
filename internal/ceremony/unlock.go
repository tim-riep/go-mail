package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/words"
)

// maxSplitTries bounds the redraws of a split whose identifier equals
// the old one (Reshare); with crypto/rand a second draw practically
// always differs.
const maxSplitTries = 8

func randOrDefault(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// pick returns k distinct share indices from 1..n in random order
// (partial Fisher-Yates shuffle with uniform draws from r).
func pick(r io.Reader, k, n int) ([]int, error) {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i + 1
	}
	for i := 0; i < k; i++ {
		j, err := rand.Int(r, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, fmt.Errorf("ceremony: reading randomness: %w", err)
		}
		t := i + int(j.Int64())
		idx[i], idx[t] = idx[t], idx[i]
	}
	return idx[:k], nil
}

// readShare asks for a share and decodes it strictly after the lenient
// normalization of the command line (words.Normalize, idempotent); want
// is the index asked for or 0 for any. Errors name word positions only.
func readShare(p Prompter, want int) (*shamir.Share, error) {
	ws, err := p.AskShare(want)
	if err != nil {
		return nil, err
	}
	ws = words.Normalize(strings.Join(ws, " "))
	s, err := shamir.ShareFromWords(ws)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShares, err)
	}
	if want != 0 && int(s.Index) != want {
		idx := s.Index
		s.Zero()
		return nil, fmt.Errorf("%w: share %d entered, share %d asked for", ErrShares, idx, want)
	}
	return s, nil
}

func zeroShares(ss []*shamir.Share) {
	for _, s := range ss {
		s.Zero()
	}
}

// identityPub derives the public identity key of generation gen from a
// root given as bytes.
func identityPub(secret []byte, gen uint32) (ed25519.PublicKey, error) {
	var seed keys.Seed
	defer seed.Zero()
	if len(secret) != len(seed) {
		return nil, fmt.Errorf("%w: root has wrong length", ErrShares)
	}
	copy(seed[:], secret)
	p := keys.DerivePlatform(&seed)
	defer p.Zero()
	k, err := p.IdentityKey(gen)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(k)
	return bytes.Clone(k.Public().(ed25519.PublicKey)), nil
}

// checkUnlock checks the options shared by the ceremonies that rebuild
// the root, before any share is asked.
func checkUnlock(o *UnlockOptions) error {
	if o.Prompter == nil {
		return fmt.Errorf("%w: no prompter", ErrOptions)
	}
	if o.IdentityGen == 0 || len(o.IdentityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: no valid current identity", ErrIdentity)
	}
	return nil
}

// unlock rebuilds the root from shares asked with AskShare(0) until the
// threshold of the first share is reached and checks that it derives
// IdentityPub as identity generation IdentityGen (ErrIdentity). It
// returns the root and the identifier of the split the shares came from.
func unlock(o *UnlockOptions) (*keys.Seed, uint16, error) {
	if err := checkUnlock(o); err != nil {
		return nil, 0, err
	}
	first, err := readShare(o.Prompter, 0)
	if err != nil {
		return nil, 0, err
	}
	got := []*shamir.Share{first}
	defer func() { zeroShares(got) }()
	t := int(first.Threshold)
	if t > MaxShareCount {
		return nil, 0, fmt.Errorf("%w: threshold %d above %d", ErrShares, t, MaxShareCount)
	}
	for len(got) < t {
		s, err := readShare(o.Prompter, 0)
		if err != nil {
			return nil, 0, err
		}
		if s.ID != first.ID || s.Threshold != first.Threshold {
			s.Zero()
			return nil, 0, fmt.Errorf("%w: %w", ErrShares, shamir.ErrMismatch)
		}
		for _, g := range got {
			if g.Index == s.Index {
				idx := s.Index
				s.Zero()
				return nil, 0, fmt.Errorf("%w: %w: %d", ErrShares, shamir.ErrDuplicate, idx)
			}
		}
		got = append(got, s)
	}
	secret, err := shamir.Combine(got)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrShares, err)
	}
	defer keys.Wipe(secret)
	pub, err := identityPub(secret, o.IdentityGen)
	if err != nil {
		return nil, 0, err
	}
	if !pub.Equal(o.IdentityPub) {
		return nil, 0, ErrIdentity
	}
	seed := new(keys.Seed)
	copy(seed[:], secret)
	return seed, first.ID, nil
}

// splitAndProbe splits seed with sh (2.3 step 3), shows every share on
// d after p.Handover, and runs the trial reconstruction (step 4): sh.Threshold
// share indices chosen at random from r, asked back with AskShare(index)
// and combined; the root must derive idPub as identity generation idGen
// (ErrProbe). avoidID >= 0 is the identifier of the old split, which the
// new one must not reuse (Reshare). Every failure of the probe wraps
// ErrProbe.
func splitAndProbe(seed *keys.Seed, sh Shares, avoidID int, r io.Reader, p Prompter, d io.Writer, idGen uint32, idPub ed25519.PublicKey) error {
	var shares []*shamir.Share
	defer func() { zeroShares(shares) }()
	for try := 0; ; try++ {
		var err error
		shares, err = shamir.Split(seed[:], sh.Threshold, sh.Count, r)
		if err != nil {
			return err
		}
		if avoidID < 0 || int(shares[0].ID) != avoidID {
			break
		}
		zeroShares(shares)
		if try+1 == maxSplitTries {
			return fmt.Errorf("%w: no new split identifier", ErrShares)
		}
	}
	for i, s := range shares {
		if err := p.Handover(i+1, len(shares)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(d, "Anteil %d/%d: %s\n", s.Index, len(shares), strings.Join(s.Words(), " ")); err != nil {
			return err
		}
	}

	idx, err := pick(r, sh.Threshold, sh.Count)
	if err != nil {
		return err
	}
	got := make([]*shamir.Share, 0, len(idx))
	defer func() { zeroShares(got) }()
	for _, i := range idx {
		s, err := readShare(p, i)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrProbe, err)
		}
		got = append(got, s)
		if s.ID != shares[0].ID || s.Threshold != shares[0].Threshold {
			return fmt.Errorf("%w: %w: %w", ErrProbe, ErrShares, shamir.ErrMismatch)
		}
	}
	secret, err := shamir.Combine(got)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProbe, err)
	}
	defer keys.Wipe(secret)
	pub, err := identityPub(secret, idGen)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProbe, err)
	}
	if !pub.Equal(idPub) {
		return ErrProbe
	}
	return nil
}
