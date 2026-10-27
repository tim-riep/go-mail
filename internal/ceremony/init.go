package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Paths inside an export directory ("/"-separated, relative to Out).
func exportPlatform(role string, gen uint32, ext string) string {
	return "platform/" + store.PlatformFileName(role, gen, ext)
}

func exportPin(gen uint32) string { return store.PlatformFileName("identity", gen, "pin") }

// WitnessesFile is the server's working copy of the witnesses in
// platform/ (section 4).
const WitnessesFile = "witnesses.rec"

func nowOrDefault(now func() time.Time) func() time.Time {
	if now == nil {
		return time.Now
	}
	return now
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return bytes.Clone(k.Public().(ed25519.PublicKey))
}

// certFiles returns the public key and certificate of a platform key for
// the export.
func certFiles(files map[string][]byte, identity ed25519.PrivateKey, identityGen uint32, role keys.Role, gen uint32, pub ed25519.PublicKey, validFrom int64) error {
	name := "admin"
	if role == keys.RoleIngest {
		name = "ingest"
	}
	c, err := keys.NewPlatformCert(identity, identityGen, role, gen, pub, validFrom)
	if err != nil {
		return err
	}
	cd, err := c.Encode()
	if err != nil {
		return err
	}
	files[exportPlatform(name, gen, "pub")] = pub
	files[exportPlatform(name, gen, "cert")] = cd
	return nil
}

// guardOf returns p as a CommitGuard, or nil.
func guardOf(p Prompter) CommitGuard {
	g, _ := p.(CommitGuard)
	return g
}

// checkValidFrom refuses a valid_from of a new ingest certificate before
// the current time of the ceremony clock (task 10c finding 7): by the
// rule of the log (ingest generation g is valid only until valid_from of
// g+1) it would invalidate ingest signatures of the old generation made
// since then. The zero time stands for Now and passes.
func checkValidFrom(validFrom time.Time, now func() time.Time) error {
	if !validFrom.IsZero() && validFrom.Before(now()) {
		return fmt.Errorf("%w: valid_from %s is before the current time of the ceremony",
			ErrOptions, validFrom.UTC().Format(time.RFC3339))
	}
	return nil
}

func runInit(opts InitOptions) (*Result, error) {
	// The quorum first (InitOptions, task 03b finding S1).
	wrec, err := checkTrust(opts.Origin, opts.Witnesses, opts.MinWitnesses)
	if err != nil {
		return nil, err
	}
	if err := opts.Shares.check(); err != nil {
		return nil, err
	}
	if opts.Display == nil || opts.Prompter == nil {
		return nil, fmt.Errorf("%w: Display and Prompter are required", ErrOptions)
	}
	if opts.KeyDir == "" {
		return nil, fmt.Errorf("%w: no key directory", ErrKeyDir)
	}
	out, keyDir, err := checkDirs(opts.Out, opts.KeyDir)
	if err != nil {
		return nil, err
	}
	adminKey := keyFile{role: store.KeyRoleAdmin, name: "admin", gen: 1}
	ingestKey := keyFile{role: store.KeyRoleIngest, name: "ingest", gen: 1}
	if err := checkKeyFiles(keyDir, adminKey.fileName(), ingestKey.fileName()); err != nil {
		return nil, err
	}
	now := nowOrDefault(opts.Now)
	rnd := randOrDefault(opts.Rand)

	// 1. root
	seed, err := keys.NewSeed(rnd)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	// 2. keys and certificates
	p := keys.DerivePlatform(seed)
	defer p.Zero()
	identity, err := p.IdentityKey(1)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(identity)
	if adminKey.key, err = p.AdminKey(1); err != nil {
		return nil, err
	}
	defer keys.Wipe(adminKey.key)
	if ingestKey.key, err = p.IngestKey(1); err != nil {
		return nil, err
	}
	defer keys.Wipe(ingestKey.key)
	idPub := pubOf(identity)
	validFrom := now().UnixMilli()
	files := map[string][]byte{
		exportPlatform("identity", 1, "pub"): idPub,
		"platform/" + WitnessesFile:          wrec,
	}
	if err := certFiles(files, identity, 1, keys.RoleAdmin, 1, pubOf(adminKey.key), validFrom); err != nil {
		return nil, err
	}
	if err := certFiles(files, identity, 1, keys.RoleIngest, 1, pubOf(ingestKey.key), validFrom); err != nil {
		return nil, err
	}
	ids := []translog.Identity{{Gen: 1, Pub: idPub}}
	pin, pinBytes, err := newPin(&pinData{Identities: ids, Origin: opts.Origin, Witnesses: opts.Witnesses, MinWitnesses: opts.MinWitnesses})
	if err != nil {
		return nil, err
	}
	files[exportPin(1)] = pinBytes

	// 3. and 4. shares and trial reconstruction
	if err := splitAndProbe(seed, opts.Shares, -1, rnd, opts.Prompter, opts.Display, 1, idPub); err != nil {
		return nil, err
	}
	// 5. files
	if err := commit(out, files, keyDir, []keyFile{adminKey, ingestKey}, guardOf(opts.Prompter)); err != nil {
		return nil, err
	}
	return &Result{KeyDir: keyDir, IdentityPub: idPub, Pin: pin, Out: out, Identities: ids}, nil
}

func runRotate(opts RotateOptions) (*RotateResult, error) {
	if opts.Gen < 2 {
		return nil, fmt.Errorf("%w: a new ingest generation is at least 2", keys.ErrGeneration)
	}
	if err := checkUnlock(&opts.UnlockOptions); err != nil {
		return nil, err
	}
	if opts.KeyDir == "" {
		return nil, fmt.Errorf("%w: no key directory", ErrKeyDir)
	}
	out, keyDir, err := checkDirs(opts.Out, opts.KeyDir)
	if err != nil {
		return nil, err
	}
	ingestKey := keyFile{role: store.KeyRoleIngest, name: "ingest", gen: opts.Gen}
	if err := checkKeyFiles(keyDir, ingestKey.fileName()); err != nil {
		return nil, err
	}
	now := nowOrDefault(opts.Now)
	if err := checkValidFrom(opts.ValidFrom, now); err != nil {
		return nil, err
	}

	seed, _, err := unlock(&opts.UnlockOptions)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	// Entering the shares takes time: checked again, and the default
	// read only now.
	if err := checkValidFrom(opts.ValidFrom, now); err != nil {
		return nil, err
	}
	validFrom := opts.ValidFrom
	if validFrom.IsZero() {
		validFrom = now()
	}
	p := keys.DerivePlatform(seed)
	defer p.Zero()
	identity, err := p.IdentityKey(opts.IdentityGen)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(identity)
	if ingestKey.key, err = p.IngestKey(opts.Gen); err != nil {
		return nil, err
	}
	defer keys.Wipe(ingestKey.key)
	pub := pubOf(ingestKey.key)
	files := map[string][]byte{}
	if err := certFiles(files, identity, opts.IdentityGen, keys.RoleIngest, opts.Gen, pub, validFrom.UnixMilli()); err != nil {
		return nil, err
	}
	if err := commit(out, files, keyDir, []keyFile{ingestKey}, guardOf(opts.Prompter)); err != nil {
		return nil, err
	}
	return &RotateResult{Gen: opts.Gen, Pub: pub}, nil
}

func runReshare(opts ReshareOptions) error {
	if err := opts.Shares.check(); err != nil {
		return err
	}
	if opts.Display == nil {
		return fmt.Errorf("%w: no display", ErrOptions)
	}
	seed, oldID, err := unlock(&opts.UnlockOptions)
	if err != nil {
		return err
	}
	defer seed.Zero()
	return splitAndProbe(seed, opts.Shares, int(oldID), randOrDefault(opts.Rand), opts.Prompter, opts.Display, opts.IdentityGen, opts.IdentityPub)
}

func runSucceed(opts SucceedOptions) (*Result, error) {
	// The quorum rule of InitOptions applies, first.
	if _, err := checkTrust(opts.Origin, opts.Witnesses, opts.MinWitnesses); err != nil {
		return nil, err
	}
	if err := checkUnlock(&opts.UnlockOptions); err != nil {
		return nil, err
	}
	cur := translog.Identity{Gen: opts.IdentityGen, Pub: opts.IdentityPub}
	if err := translog.CheckIdentities(opts.Identities, cur); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	if opts.IdentityGen == math.MaxUint32 || len(opts.Identities) >= translog.MaxIdentities {
		return nil, fmt.Errorf("%w: no further identity generation", ErrIdentity)
	}
	out, _, err := checkDirs(opts.Out, "")
	if err != nil {
		return nil, err
	}
	now := nowOrDefault(opts.Now)

	seed, _, err := unlock(&opts.UnlockOptions)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	p := keys.DerivePlatform(seed)
	defer p.Zero()
	// Every generation of the list derives from this root.
	for _, id := range opts.Identities {
		k, err := p.IdentityKey(id.Gen)
		if err != nil {
			return nil, err
		}
		same := pubOf(k).Equal(id.Pub)
		keys.Wipe(k)
		if !same {
			return nil, fmt.Errorf("%w: identity generation %d of the list", ErrIdentity, id.Gen)
		}
	}
	g := opts.IdentityGen + 1
	prev, err := p.IdentityKey(opts.IdentityGen)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(prev)
	next, err := p.IdentityKey(g)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(next)
	nextPub := pubOf(next)

	ids := make([]translog.Identity, 0, len(opts.Identities)+1)
	for _, id := range opts.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: bytes.Clone(id.Pub)})
	}
	ids = append(ids, translog.Identity{Gen: g, Pub: nextPub})
	pin, pinBytes, err := newPin(&pinData{Identities: ids, Origin: opts.Origin, Witnesses: opts.Witnesses, MinWitnesses: opts.MinWitnesses})
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{exportPin(g): pinBytes}
	if !opts.Compromised {
		s, err := keys.NewPlatformSuccession(prev, g, nextPub, now().UnixMilli())
		if err != nil {
			return nil, err
		}
		sd, err := s.Encode()
		if err != nil {
			return nil, err
		}
		files[exportPlatform("identity", g, "pub")] = nextPub
		files[exportPlatform("identity", g, "succ")] = sd
	}
	if err := commit(out, files, "", nil, guardOf(opts.Prompter)); err != nil {
		return nil, err
	}
	return &Result{IdentityPub: nextPub, Pin: pin, Out: out, Identities: ids}, nil
}
