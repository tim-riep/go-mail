package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Prompter shows the seed words and asks for three of them (2.2).
type Prompter interface {
	// ShowWords displays the 24 words once.
	ShowWords(words []string) error
	// AskWord asks for the word at position (1-based).
	AskWord(position int) (string, error)
}

// ConfirmWords is the number of words asked back (2.2).
const ConfirmWords = 3

// Keygen creates a new user in cfg.Dir (2.2): a seed from crypto/rand,
// shown as 24 words, three of them asked back; only then the root key,
// generation 1 and its certificate are derived, the key store is written
// with passphrase and the seed and root are wiped. The user exists only
// locally until Register.
func Keygen(cfg Config, passphrase []byte, p Prompter) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if len(passphrase) == 0 {
		return store.ID{}, fmt.Errorf("client: empty passphrase")
	}
	if _, err := os.Stat(cfg.keystorePath()); err == nil {
		return store.ID{}, ErrRegistered
	}
	seed, err := keys.NewSeed(nil)
	if err != nil {
		return store.ID{}, err
	}
	defer seed.Zero()
	words, err := seed.Words()
	if err != nil {
		return store.ID{}, err
	}
	defer func() {
		for i := range words {
			words[i] = ""
		}
	}()
	if err := p.ShowWords(words); err != nil {
		return store.ID{}, err
	}
	positions, err := choosePositions(len(words), ConfirmWords)
	if err != nil {
		return store.ID{}, err
	}
	for _, pos := range positions {
		got, err := p.AskWord(pos + 1)
		if err != nil {
			return store.ID{}, err
		}
		// TODO(S11): the input is compared exactly, without trimming or
		// case folding, until the normalization of seed word input is
		// decided (SPEC-ISSUES S11).
		if subtle.ConstantTimeCompare([]byte(got), []byte(words[pos])) != 1 {
			return store.ID{}, ErrConfirm
		}
	}

	u := keys.DeriveUser(seed)
	defer u.Zero()
	root, err := u.RootKey()
	if err != nil {
		return store.ID{}, err
	}
	defer keys.Wipe(root)
	identity, err := u.IdentityKey(1)
	if err != nil {
		return store.ID{}, err
	}
	unwrap, err := u.UnwrapKey(1)
	if err != nil {
		keys.Wipe(identity)
		return store.ID{}, err
	}
	ks := &keys.Keystore{Generation: 1, Identity: identity, Unwrap: unwrap}
	defer ks.Zero()
	cert, err := keys.NewGenerationCert(root, 1, identity.Public().(ed25519.PublicKey), unwrap.PublicKey(), cfg.Now().UnixMilli())
	if err != nil {
		return store.ID{}, err
	}
	id, err := store.NewID(nil)
	if err != nil {
		return store.ID{}, err
	}
	user := &store.User{ID: id, RootPub: root.Public().(ed25519.PublicKey), Generations: []*keys.GenerationCert{cert}}
	userData, err := user.Encode()
	if err != nil {
		return store.ID{}, err
	}
	ksData, err := ks.Seal(passphrase, nil)
	if err != nil {
		return store.ID{}, err
	}
	if err := mkdirClient(cfg.Dir); err != nil {
		return store.ID{}, err
	}
	if err := store.WriteFileAtomic(cfg.userPath(), userData); err != nil {
		return store.ID{}, err
	}
	if err := keys.WriteKeystoreFile(cfg.keystorePath(), ksData); err != nil {
		return store.ID{}, err
	}
	if err := saveState(cfg.statePath(), &state{UserID: id.String(), Mailboxes: map[string]*mailboxState{}}); err != nil {
		return store.ID{}, err
	}
	return id, nil
}

// choosePositions draws k distinct positions below n from crypto/rand.
func choosePositions(n, k int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for len(out) < k {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return nil, err
		}
		if p := int(v.Int64()); !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

// Register publishes the user created by Keygen (2.2): it takes the
// invitation code out of use, writes users/<id>/user.rec and appends it
// to the log. The invitation is consumed first, so a code can never
// register two users.
func Register(cfg Config, code store.ID) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	st, err := loadState(cfg.statePath())
	if err != nil {
		return store.ID{}, err
	}
	if st.UserID == "" {
		return store.ID{}, ErrNotRegistered
	}
	if st.Registered {
		return store.ID{}, ErrRegistered
	}
	data, err := store.ReadFileLimited(cfg.userPath(), store.MaxUserFile)
	if err != nil {
		return store.ID{}, ErrNotRegistered
	}
	user, err := store.DecodeUser(data)
	if err != nil {
		return store.ID{}, err
	}
	if err := cfg.Store.ConsumeInvite(code); err != nil {
		return store.ID{}, err
	}
	if err := cfg.Store.CreateUser(user); err != nil {
		if errors.Is(err, store.ErrExists) {
			return store.ID{}, fmt.Errorf("client: user ID already taken: %w", err)
		}
		return store.ID{}, err
	}
	// TODO(phase3-translog): user.rec into the log; the generation is valid only from then on (2.2 rule 3).
	if err := cfg.Log.AppendUser(user.ID, data); err != nil {
		return store.ID{}, err
	}
	st.Registered = true
	if err := saveState(cfg.statePath(), st); err != nil {
		return store.ID{}, err
	}
	return user.ID, nil
}
