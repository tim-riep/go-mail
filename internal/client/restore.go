package client

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/shamir"
	"github.com/tim-riep/go-mail/internal/store"
)

// Restoring a user from the seed (2.2 "Wiederherstellung", 2.7 "Neue
// Geräte und Wiederherstellung", task 06b C).

// warnUnconfirmedState is shown on every start of a restored client.
const warnUnconfirmedState = "WARNUNG: Noch kein bestätigter Zustand: Sicht noch nicht mit einem anderen Mitglied abgeglichen. Dieser Client wurde aus dem Seed wiederhergestellt und vertraut den Daten beim ersten Kontakt; ein Server könnte ihm einen abweichenden Zustand zeigen, bis der Vermerk eines anderen Benutzer-Mitglieds mit dem eigenen Baumkopf übereinstimmt (ein alleiniges Mitglied bleibt markiert)."

// warnUnconfirmed warns on every start while the state of the client is
// not confirmed (2.7: "Der Client zeigt deutlich an, dass er noch keinen
// bestätigten Zustand hat").
func warnUnconfirmed(cfg Config, st *state) {
	if st.Unconfirmed {
		cfg.Warn(warnUnconfirmedState)
	}
}

// RestoreOptions selects the seed of Restore: exactly one of Words and
// Shares.
type RestoreOptions struct {
	// Words are the 24 seed words; each element may hold one or several
	// words, they are normalized like every word input (S11).
	Words []string
	// Shares are at least the threshold of the shares of a split made by
	// keygen --shares, each the 30 words of one share (normalized).
	Shares [][]string
	// UserID names the user; zero means the one user whose user.rec in
	// the data directory holds the root key of the seed.
	UserID store.ID
}

// Restore sets up the client directory cfg.Dir for a user from its seed,
// given as words or as shares (shamir.Combine): the user.rec of the data
// directory whose root key is the root derived from the seed (ErrSeed if
// there is none), a key store with passphrase holding the current
// generation of that user.rec (derived from the seed, and it must be the
// one certified there), the user.rec itself, and a state.json without any
// trusted state: no epoch heads and no versions, only the mailboxes the
// user appears in (their chains are trusted on first contact, 2.7). Every
// start of the restored client warns that it has no confirmed state yet.
// A device lost is possible right afterwards.
//
// Nothing is written unless the seed matches: wrong shares, a share of
// another split or words of another seed leave cfg.Dir as it was. A
// client directory that already holds a key store, user.rec or state.json
// is ErrRegistered.
func Restore(cfg Config, opts RestoreOptions, passphrase []byte) (store.ID, error) {
	if err := cfg.check(); err != nil {
		return store.ID{}, err
	}
	if len(passphrase) == 0 {
		return store.ID{}, fmt.Errorf("client: empty passphrase")
	}
	if err := emptyClientDir(cfg); err != nil {
		return store.ID{}, err
	}
	seed, err := restoreSeed(opts)
	if err != nil {
		return store.ID{}, err
	}
	defer seed.Zero()
	d := keys.DeriveUser(seed)
	defer d.Zero()
	root, err := d.RootKey()
	if err != nil {
		return store.ID{}, err
	}
	rootPub := root.Public().(ed25519.PublicKey)
	keys.Wipe(root)
	user, raw, err := findUser(cfg.Store, opts.UserID, rootPub)
	if err != nil {
		return store.ID{}, err
	}
	// The first contact (2.7 "Neue Geräte und Wiederherstellung"): the
	// client log is opened without a reference head, takes the newest
	// head with witness cosignatures (Refresh, CheckFresh), and user.rec
	// must be the one in the log (CheckUser, not outdated). The audit
	// index lies in a directory of its own until the client directory is
	// written (nothing is written there unless the seed matches); Open
	// builds it again in the client directory. The head goes into
	// state.json; Unconfirmed stays until the view agrees with a
	// checkpoint of another user member (TODO(Q20), checkCheckpoints).
	st := &state{UserID: user.ID.String(), Registered: true, Unconfirmed: true, Mailboxes: map[string]*mailboxState{}}
	lcfg := cfg
	lcfg.Dir = ""
	lc, err := openLog(&lcfg, st, true)
	if err != nil {
		return store.ID{}, err
	}
	defer lc.close()
	if _, err := lc.refresh(); err != nil {
		return store.ID{}, err
	}
	rc := &Client{cfg: lcfg, st: cfg.Store, me: user.ID, state: st, lg: lc}
	if err := rc.checkUser(user.ID, raw); err != nil {
		return store.ID{}, err
	}
	g := user.Current()
	identity, err := d.IdentityKey(g.Gen)
	if err != nil {
		return store.ID{}, err
	}
	unwrap, err := d.UnwrapKey(g.Gen)
	if err != nil {
		keys.Wipe(identity)
		return store.ID{}, err
	}
	ks := &keys.Keystore{Generation: g.Gen, Identity: identity, Unwrap: unwrap}
	defer ks.Zero()
	if !g.IdentityPub.Equal(identity.Public()) || !g.UnwrapPub.Equal(unwrap.PublicKey()) {
		return store.ID{}, fmt.Errorf("%w: generation %d is not derived from this seed", ErrSeed, g.Gen)
	}
	ksData, err := ks.Seal(passphrase, nil)
	if err != nil {
		return store.ID{}, err
	}
	defer keys.Wipe(ksData)
	boxes, err := userMailboxes(cfg.Store, user.ID)
	if err != nil {
		return store.ID{}, err
	}
	// Everything checked: now the client directory.
	if err := mkdirClient(cfg.Dir); err != nil {
		return store.ID{}, err
	}
	unlock, err := store.LockFile(filepath.Join(cfg.Dir, "lock"))
	if err != nil {
		return store.ID{}, err
	}
	defer unlock()
	if err := emptyClientDir(cfg); err != nil {
		return store.ID{}, err
	}
	for _, id := range boxes {
		st.Mailboxes[id.String()] = &mailboxState{Versions: map[string]uint32{}, Epochs: map[string]*epochMemo{}}
	}
	if err := store.WritePrivateFileAtomic(cfg.userPath(), raw); err != nil {
		return store.ID{}, err
	}
	if err := keys.WriteKeystoreFile(cfg.keystorePath(), ksData); err != nil {
		return store.ID{}, err
	}
	if err := saveState(cfg.statePath(), st); err != nil {
		return store.ID{}, err
	}
	cfg.Warn(warnUnconfirmedState)
	return user.ID, nil
}

// emptyClientDir reports ErrRegistered if cfg.Dir holds a key store,
// user.rec or state.json.
func emptyClientDir(cfg Config) error {
	for _, p := range []string{cfg.keystorePath(), cfg.userPath(), cfg.statePath()} {
		if _, err := os.Lstat(p); err == nil {
			return ErrRegistered
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// restoreSeed rebuilds the seed from exactly one of opts.Words and
// opts.Shares. Errors name positions and share numbers, never words.
func restoreSeed(opts RestoreOptions) (*keys.Seed, error) {
	switch {
	case len(opts.Words) > 0 && len(opts.Shares) > 0, len(opts.Words) == 0 && len(opts.Shares) == 0:
		return nil, fmt.Errorf("%w: either the seed words or the shares", ErrArgument)
	case len(opts.Words) > 0:
		words, err := normalizeList(opts.Words)
		if err != nil {
			return nil, err
		}
		return keys.SeedFromWords(words)
	}
	if len(opts.Shares) > 255 {
		return nil, fmt.Errorf("%w: %d shares", ErrArgument, len(opts.Shares))
	}
	shares := make([]*shamir.Share, 0, len(opts.Shares))
	defer func() {
		for _, s := range shares {
			s.Zero()
		}
	}()
	for i, w := range opts.Shares {
		words, err := normalizeList(w)
		if err != nil {
			return nil, fmt.Errorf("client: share %d: %w", i+1, err)
		}
		s, err := shamir.ShareFromWords(words)
		if err != nil {
			return nil, fmt.Errorf("client: share %d: %w", i+1, err)
		}
		shares = append(shares, s)
	}
	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(secret)
	if len(secret) != keys.SeedSize {
		return nil, fmt.Errorf("%w: secret of %d bytes", ErrSeed, len(secret))
	}
	seed := new(keys.Seed)
	copy(seed[:], secret)
	return seed, nil
}

// findUser returns the user.rec of id, or with a zero id of the only user
// of the data directory, whose root key is rootPub (ErrSeed otherwise).
func findUser(st *store.Store, id store.ID, rootPub ed25519.PublicKey) (*store.User, []byte, error) {
	var ids []store.ID
	if !id.IsZero() {
		ids = []store.ID{id}
	} else {
		entries, err := os.ReadDir(st.Path("users"))
		if err != nil {
			return nil, nil, err
		}
		for _, ent := range entries {
			if x, err := store.ParseID(ent.Name()); err == nil && ent.IsDir() {
				ids = append(ids, x)
			}
		}
	}
	var found *store.User
	var data []byte
	for _, x := range ids {
		u, raw, err := st.ReadUser(x)
		if err != nil || !u.RootPub.Equal(rootPub) {
			continue
		}
		if found != nil {
			return nil, nil, fmt.Errorf("%w: several users have the root key of this seed; name the user", ErrArgument)
		}
		found, data = u, raw
	}
	if found == nil {
		return nil, nil, fmt.Errorf("%w: no user.rec in the data directory has the root key of this seed", ErrSeed)
	}
	return found, data, nil
}

// userMailboxes returns the mailboxes of the data directory whose newest
// epoch names user (not as recovery recipient) or that hold a wrap for it
// in any epoch. Nothing is verified here; the chains are checked on first
// use.
func userMailboxes(st *store.Store, user store.ID) ([]store.ID, error) {
	entries, err := os.ReadDir(st.Path("mailboxes"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []store.ID
	for _, ent := range entries {
		id, err := store.ParseID(ent.Name())
		if err != nil || !ent.IsDir() {
			continue
		}
		if mailboxNames(st, id, user) {
			out = append(out, id)
		}
	}
	return out, nil
}

func mailboxNames(st *store.Store, id, user store.ID) bool {
	if m, err := st.ReadMailbox(id); err == nil {
		if e, _, err := st.ReadEpoch(id, m.Epoch); err == nil {
			for _, mm := range e.Members {
				if mm.ID == user && mm.Kind != store.MemberRecovery {
					return true
				}
			}
		}
	}
	epochs, err := st.ListEpochs(id)
	if err != nil {
		return false
	}
	for _, n := range epochs {
		if _, err := os.Lstat(st.WrapFile(id, n, user)); err == nil {
			return true
		}
	}
	return false
}
