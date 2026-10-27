package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Prompter shows the seed words and asks for three of them (2.2).
type Prompter interface {
	// ShowWords displays the 24 words once.
	ShowWords(words []string) error
	// AskWord asks for the word at position (1-based).
	AskWord(position int) (string, error)
}

// SharePrompter is a Prompter that also shows the Shamir shares of the
// seed (2.2 "Wiederherstellung", gomailctl keygen --shares). The shares
// are shown only through ShowShares and never written to a file.
//
// TODO(task-13): ShowShares belongs to Prompter; it is a separate
// interface only because cmd/gomailctl, which implements Prompter, is
// changed by task 13 and not by this task.
type SharePrompter interface {
	Prompter
	// ShowShares displays the shares once: shares[i] are the 30 words of
	// the share with index i+1 (shamir.Share.Words).
	ShowShares(shares [][]string) error
}

// Shares is a split "k-of-n" of the seed: Threshold of Count shares
// rebuild it.
type Shares struct {
	Threshold int
	Count     int
}

// KeygenOptions are the options of KeygenWithOptions.
type KeygenOptions struct {
	// Shares splits the seed additionally into shares (2.2
	// "Wiederherstellung", e.g. 2-of-3); zero means no split. 2 <=
	// Threshold <= Count <= 255 (shamir.Split).
	Shares Shares
}

// ConfirmWords is the number of words asked back (2.2).
const ConfirmWords = 3

// Keygen creates a new user in cfg.Dir (2.2): a seed from crypto/rand,
// shown as 24 words, three of them asked back; only then the root key,
// generation 1 and its certificate are derived, the key store is written
// with passphrase and the seed and root are wiped. The user exists only
// locally until Register.
func Keygen(cfg Config, passphrase []byte, p Prompter) (store.ID, error) {
	return KeygenWithOptions(cfg, passphrase, p, KeygenOptions{})
}

// KeygenWithOptions is Keygen with options. With opts.Shares the seed is
// split with shamir.Split after the words are confirmed, each share is
// shown as 30 words through SharePrompter.ShowShares (p must implement
// it), and the shares are wiped; the platform gets no share (2.2). A
// split that does not rebuild the seed from its first Threshold shares
// stops Keygen before anything is written.
func KeygenWithOptions(cfg Config, passphrase []byte, p Prompter, opts KeygenOptions) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if len(passphrase) == 0 {
		return store.ID{}, fmt.Errorf("client: empty passphrase")
	}
	var sp SharePrompter
	if opts.Shares != (Shares{}) {
		if err := checkShares(opts.Shares); err != nil {
			return store.ID{}, err
		}
		var ok bool
		if sp, ok = p.(SharePrompter); !ok {
			return store.ID{}, fmt.Errorf("%w: the prompter cannot show shares", ErrArgument)
		}
	}
	if _, err := os.Stat(cfg.keystorePath()); err == nil {
		return store.ID{}, ErrRegistered
	}
	seed, err := keys.NewSeed(nil)
	if err != nil {
		return store.ID{}, err
	}
	defer seed.Zero()
	if err := showAndConfirm(seed, p); err != nil {
		return store.ID{}, err
	}
	if sp != nil {
		if err := showShares(seed, opts.Shares, sp); err != nil {
			return store.ID{}, err
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
	// user.rec is signed by the root here, the only moment the root exists
	// (2.2, 3.7 "user"); Register publishes the signed file.
	if err := user.Sign(root); err != nil {
		return store.ID{}, err
	}
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
	if err := store.WritePrivateFileAtomic(cfg.userPath(), userData); err != nil {
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

// showAndConfirm shows the 24 words of seed through p and asks three
// randomly chosen ones back (2.2); ErrConfirm if one differs.
func showAndConfirm(seed *keys.Seed, p Prompter) error {
	words, err := seed.Words()
	if err != nil {
		return err
	}
	defer func() {
		for i := range words {
			words[i] = ""
		}
	}()
	if err := p.ShowWords(words); err != nil {
		return err
	}
	positions, err := choosePositions(len(words), ConfirmWords)
	if err != nil {
		return err
	}
	for _, pos := range positions {
		got, err := p.AskWord(pos + 1)
		if err != nil {
			return err
		}
		// The answer is normalized like every word input (2.2 "Eingabe
		// von Wörtern", S11) and must then be exactly the word.
		w, err := oneWord(got)
		if err != nil {
			return fmt.Errorf("%w: position %d: %w", ErrConfirm, pos+1, err)
		}
		if subtle.ConstantTimeCompare([]byte(w), []byte(words[pos])) != 1 {
			return ErrConfirm
		}
	}
	return nil
}

// checkShares checks a split k-of-n before any secret exists.
func checkShares(s Shares) error {
	if s.Threshold < 2 || s.Count < s.Threshold || s.Count > 255 {
		return fmt.Errorf("%w: shares %d-of-%d: %w", ErrArgument, s.Threshold, s.Count, shamir.ErrParams)
	}
	return nil
}

// showShares splits seed into s.Count shares of which s.Threshold rebuild
// it (shamir.Split, randomness from crypto/rand), checks that the first
// s.Threshold of them do, shows them as words through p and wipes them.
func showShares(seed *keys.Seed, s Shares, p SharePrompter) error {
	shares, err := shamir.Split(seed[:], s.Threshold, s.Count, nil)
	if err != nil {
		return err
	}
	defer func() {
		for _, sh := range shares {
			sh.Zero()
		}
	}()
	back, err := shamir.Combine(shares[:s.Threshold])
	if err != nil {
		return err
	}
	same := subtle.ConstantTimeCompare(back, seed[:]) == 1
	keys.Wipe(back)
	if !same {
		return fmt.Errorf("client: the shares do not rebuild the seed")
	}
	out := make([][]string, len(shares))
	defer func() {
		for _, w := range out {
			clear(w)
		}
	}()
	for i, sh := range shares {
		out[i] = sh.Words()
	}
	return p.ShowShares(out)
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

// Register publishes the user created by Keygen (2.2). The user entry
// of generation 1 is the first entry of the user ID in the log, bound to
// nothing but its own content, so the order is (translog doc.go "Who
// writes", findings 03c-1 and 03d-5): the record is the user.rec that
// Keygen keeps in the client directory (step 1); the invitation is
// consumed (store.ConsumeInvite, a code never registers two users) and
// right after it InviteUsed is set in state.json; the user.rec is
// appended to the log (step 2, Append is idempotent) and its pending
// entry kept in state.json; only then users/<id>/user.rec is written to
// the data directory (step 3, store.EnsureUser) and Registered is set.
// A Register run again after a crash skips ConsumeInvite once InviteUsed
// is set and continues with step 2. ErrDuplicate means that somebody
// else logged the user ID first: Register stops before step 3. The error
// names the whole remedy (task 14b point 10): the client directory holds
// a user that can never be registered and the invitation is used up, so
// the user deletes the client directory, runs keygen again (a new ID
// needs a user.rec signed by the root, which exists only during keygen;
// Keygen refuses a directory with a key store, ErrRegistered, so that it
// never overwrites the keys of a user that may be registered) and
// registers with a new invitation code.
func Register(cfg Config, code store.ID) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if _, err := os.Stat(cfg.statePath()); err != nil {
		return store.ID{}, ErrNotRegistered
	}
	unlock, err := store.LockFile(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return store.ID{}, err
	}
	defer unlock()
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
	if len(user.Generations) != 1 {
		return store.ID{}, ErrNotRegistered
	}
	if _, err := os.Lstat(cfg.Store.UserFile(user.ID)); err == nil && !st.InviteUsed {
		return store.ID{}, fmt.Errorf("client: user ID already taken: %w", store.ErrExists)
	}
	if !st.InviteUsed {
		if err := cfg.Store.ConsumeInvite(code); err != nil {
			return store.ID{}, err
		}
		st.InviteUsed = true
		if err := saveState(cfg.statePath(), st); err != nil {
			return store.ID{}, err
		}
	}
	if crash("register-invite") {
		return store.ID{}, errCrashed
	}
	lc, err := openLog(&cfg, st, false)
	if err != nil {
		return store.ID{}, err
	}
	defer lc.close()
	if _, err := lc.appendRecord(translog.KindUser, data); err != nil {
		if errors.Is(err, translog.ErrDuplicate) {
			return store.ID{}, fmt.Errorf("client: the user ID is already taken in the transparency log, so this client directory can never be registered and its invitation code is used up; delete the client directory %s, run keygen again and register with a new invitation code: %w", cfg.Dir, err)
		}
		return store.ID{}, err
	}
	if crash("register-logged") {
		return store.ID{}, errCrashed
	}
	if err := cfg.Store.EnsureUser(user); err != nil {
		if errors.Is(err, store.ErrExists) {
			return store.ID{}, fmt.Errorf("client: user ID already taken: %w", err)
		}
		return store.ID{}, err
	}
	st.Registered = true
	if err := saveState(cfg.statePath(), st); err != nil {
		return store.ID{}, err
	}
	return user.ID, nil
}
