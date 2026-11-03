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
	"github.com/tim-riep/go-mail/internal/witness"
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
//
// b describes a revocation of the predecessor in the pin of the rotation
// (rotationBound, D93): with b.exact the predecessor itself is revoked
// at b.at (its revoked_at_time) and valid_from must be exactly b.at
// (D93 addendum: not later, else no ingest generation signs between
// b.at and valid_from; not earlier, else signatures of the predecessor
// before its boundary would become invalid); the zero time stands for
// b.at. With b.floor (the pin revokes the identity generation before the
// current one: succeed --compromised) valid_from may lie in the past down
// to b.at, not before; Publish refuses a successor of an ingest
// generation that the revoked identity certified whose valid_from lies
// after b.at (checkSuccessors).
//
// With b.alt set (both revocations above, the identity's earlier) the
// ceremony cannot tell which applies (it does not know which identity
// generation certified the predecessor): valid_from must be given and be
// b.alt or b.at, anything else is ErrRevocation naming both.
func checkValidFrom(validFrom time.Time, now func() time.Time, b rotationBound) (time.Time, error) {
	at := time.UnixMilli(b.at).UTC()
	switch {
	case b.exact && b.alt != 0 && (validFrom.IsZero() || validFrom.UnixMilli() != b.at && validFrom.UnixMilli() != b.alt):
		return time.Time{}, fmt.Errorf("%w: the pin revokes the predecessor from %d (%s) and the identity generation before the current one from %d (%s): valid_from must be %s if the predecessor's certificate was issued by that identity generation (the earlier time applies), else %s (D93); give it explicitly",
			ErrRevocation, b.at, at.Format(time.RFC3339Nano), b.alt, rfc3339(b.alt), rfc3339(b.alt), at.Format(time.RFC3339Nano))
	case b.exact && b.alt != 0:
		return validFrom, nil
	case b.exact && validFrom.IsZero():
		return at, nil
	case b.exact && validFrom.UnixMilli() != b.at:
		return time.Time{}, fmt.Errorf("%w: valid_from %s must be revoked_at_time %d (%s) of the revoked predecessor (D93)",
			ErrRevocation, validFrom.UTC().Format(time.RFC3339Nano), b.at, at.Format(time.RFC3339Nano))
	case b.exact:
		return validFrom, nil
	case validFrom.IsZero():
		return validFrom, nil
	case b.floor && validFrom.UnixMilli() < b.at:
		return time.Time{}, fmt.Errorf("%w: valid_from %s is before revoked_at_time %d (%s) of the compromised identity generation",
			ErrOptions, validFrom.UTC().Format(time.RFC3339Nano), b.at, at.Format(time.RFC3339Nano))
	case b.floor:
		return validFrom, nil
	case validFrom.Before(now()):
		return time.Time{}, fmt.Errorf("%w: valid_from %s is before the current time of the ceremony",
			ErrOptions, validFrom.UTC().Format(time.RFC3339))
	}
	return validFrom, nil
}

// rotationBound is what field 7 of the pin of a rotation says about
// valid_from of the new ingest generation (checkValidFrom).
type rotationBound struct {
	exact, floor bool
	at           int64
	// alt, when not 0, is a second admissible exact valid_from, earlier
	// than at: revoked_at_time of the identity generation before the
	// current one, which applies instead of at when that generation
	// certified the predecessor (the cascade of D93).
	alt int64
}

// boundOf returns the rotationBound of ingest generation gen under
// identity generation idGen for the revocation list rev: exact when rev
// revokes ingest generation gen-1, floor when it revokes identity
// generation idGen-1 (the compromise that made idGen). When rev revokes
// both, the predecessor is revoked from the earlier of the two times if
// identity generation idGen-1 certified it, else from its own (spec
// review 21c Low-2; Publish's checkSuccessors takes the earlier one, as
// translog does): with the identity's time not earlier the own time is
// the earlier one in either case; with the identity's time earlier the
// ceremony, offline, cannot tell, and checkValidFrom takes exactly one
// of the two, given explicitly (alt).
func boundOf(rev []store.PlatformRevoked, gen, idGen uint32) rotationBound {
	list := revokedOf(rev)
	own, hasOwn := translog.FindRevoked(list, store.KeyRoleIngest, gen-1)
	id, hasID := translog.FindRevoked(list, store.KeyRoleIdentity, idGen-1)
	hasID = hasID && idGen > 1
	switch {
	case hasOwn && hasID && id.AtTime < own.AtTime:
		return rotationBound{exact: true, at: own.AtTime, alt: id.AtTime}
	case hasOwn:
		return rotationBound{exact: true, at: own.AtTime}
	case hasID:
		return rotationBound{floor: true, at: id.AtTime}
	}
	return rotationBound{}
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
	return &Result{KeyDir: keyDir, IdentityPub: idPub, Pin: pin, Out: out}, nil
}

// runRotate is IngestRotate (role store.KeyRoleIngest) and AdminRotate
// (store.KeyRoleAdmin).
func runRotate(opts RotateOptions, role uint8) (*RotateResult, error) {
	name := RoleName(role)
	if role != store.KeyRoleIngest && role != store.KeyRoleAdmin {
		return nil, fmt.Errorf("%w: no admin or ingest role", ErrOptions)
	}
	if opts.Gen < 2 {
		return nil, fmt.Errorf("%w: a new %s generation is at least 2", keys.ErrGeneration, name)
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
	newKey := keyFile{role: role, name: name, gen: opts.Gen}
	if err := checkKeyFiles(keyDir, newKey.fileName()); err != nil {
		return nil, err
	}
	now := nowOrDefault(opts.Now)
	// Never certify a revoked key again (D93 addendum): the key of a
	// generation derives from the root and its number, so the stolen key
	// of a revoked generation is exactly the one of that number.
	if r, ok := translog.FindRevoked(revokedOf(opts.Revoked), role, opts.Gen); ok {
		return nil, fmt.Errorf("%w: the pin revokes %s generation %d (from log index %d): its key is the stolen one; the new generation is the highest existing one + 1",
			ErrRevocation, name, opts.Gen, r.AtSize)
	}
	var bound rotationBound
	if role == store.KeyRoleIngest {
		bound = boundOf(opts.Revoked, opts.Gen, opts.IdentityGen)
	}
	if _, err := checkValidFrom(opts.ValidFrom, now, bound); err != nil {
		return nil, err
	}

	seed, _, err := unlock(&opts.UnlockOptions)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	// Entering the shares takes time: checked again, and the default
	// read only now.
	validFrom, err := checkValidFrom(opts.ValidFrom, now, bound)
	if err != nil {
		return nil, err
	}
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
	keyRole := keys.RoleIngest
	if role == store.KeyRoleAdmin {
		keyRole = keys.RoleAdmin
		newKey.key, err = p.AdminKey(opts.Gen)
	} else {
		newKey.key, err = p.IngestKey(opts.Gen)
	}
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(newKey.key)
	pub := pubOf(newKey.key)
	files := map[string][]byte{}
	if err := certFiles(files, identity, opts.IdentityGen, keyRole, opts.Gen, pub, validFrom.UnixMilli()); err != nil {
		return nil, err
	}
	if err := commit(out, files, keyDir, []keyFile{newKey}, guardOf(opts.Prompter)); err != nil {
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

// succeedTrust returns origin, witnesses and quorum of the new pin: those
// of the current pin, the witnesses and the quorum replaced only where
// opts sets them (an explicit change); a different origin is ErrOptions
// (the origin of a log never changes; a new origin is a new log, Q10
// point 4).
func succeedTrust(opts *SucceedOptions) (string, []witness.Key, int, error) {
	origin := opts.Pin.Origin
	if opts.Origin != "" && opts.Origin != origin {
		return "", nil, 0, fmt.Errorf("%w: the origin of the log does not change with a succession", ErrOptions)
	}
	ws, min := pinWitnesses(opts.Pin), opts.Pin.MinWitnesses
	if opts.Witnesses != nil {
		ws = opts.Witnesses
	}
	if opts.MinWitnesses != 0 {
		min = opts.MinWitnesses
	}
	return origin, ws, min, nil
}

func runSucceed(opts SucceedOptions) (*Result, error) {
	// The boundary of a compromise first, before anything else is
	// checked or asked (D93 (4)).
	now := nowOrDefault(opts.Now)
	switch {
	case opts.Compromised && opts.HeadSize == 0 && opts.HeadTime == 0:
		return nil, fmt.Errorf("%w: %w", ErrRevocation, ErrCompromised)
	case opts.Compromised:
		if err := checkBoundary(opts.HeadSize, opts.HeadTime, now); err != nil {
			return nil, err
		}
	case opts.HeadSize != 0 || opts.HeadTime != 0:
		return nil, fmt.Errorf("%w: a boundary of a revocation only with Compromised", ErrOptions)
	}
	if opts.Pin == nil {
		return nil, fmt.Errorf("%w: no pin", ErrOptions)
	}
	ids, err := PinIdentities(opts.Pin)
	if err != nil {
		return nil, err
	}
	// Field 7 of the current pin is carried over (D93 (4)); after a
	// compromise it revokes the current generation as well.
	revoked := append([]store.PlatformRevoked(nil), opts.Pin.Revoked...)
	if opts.Compromised {
		if revoked, err = addRevoked(revoked, store.PlatformRevoked{Role: store.KeyRoleIdentity, Gen: opts.IdentityGen,
			AtSize: opts.HeadSize, AtTime: opts.HeadTime + 1}); err != nil {
			return nil, err
		}
	}
	origin, witnesses, minWitnesses, err := succeedTrust(&opts)
	if err != nil {
		return nil, err
	}
	// The quorum rule of InitOptions applies, first.
	if _, err := checkTrust(origin, witnesses, minWitnesses); err != nil {
		return nil, err
	}
	if err := checkUnlock(&opts.UnlockOptions); err != nil {
		return nil, err
	}
	if opts.Pin.Gen != opts.IdentityGen || !opts.Pin.Pub.Equal(opts.IdentityPub) {
		return nil, fmt.Errorf("%w: the pin is not the one of the current identity", ErrIdentity)
	}
	if opts.IdentityGen == math.MaxUint32 || len(ids) >= translog.MaxIdentities {
		return nil, fmt.Errorf("%w: no further identity generation", ErrIdentity)
	}
	out, _, err := checkDirs(opts.Out, "")
	if err != nil {
		return nil, err
	}

	seed, _, err := unlock(&opts.UnlockOptions)
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	p := keys.DerivePlatform(seed)
	defer p.Zero()
	if err := checkList(p, ids); err != nil {
		return nil, err
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

	// The new list: the list of the current pin plus the new generation
	// (translog doc.go "Pin", store.CheckPinIdentities).
	ids = append(ids, translog.Identity{Gen: g, Pub: bytes.Clone(nextPub)})
	pin, pinBytes, err := newPin(&pinData{Identities: ids, Origin: origin, Witnesses: witnesses, MinWitnesses: minWitnesses, Revoked: revoked})
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{exportPin(g): pinBytes, exportPlatform("identity", g, "pub"): nextPub}
	// After a compromise no succession: the thief could sign one himself,
	// and the pin alone carries generation g (D93 (4)).
	if !opts.Compromised {
		s, err := keys.NewPlatformSuccession(prev, g, nextPub, now().UnixMilli())
		if err != nil {
			return nil, err
		}
		sd, err := s.Encode()
		if err != nil {
			return nil, err
		}
		files[exportPlatform("identity", g, "succ")] = sd
	}
	if err := commit(out, files, "", nil, guardOf(opts.Prompter)); err != nil {
		return nil, err
	}
	return &Result{IdentityPub: nextPub, Pin: pin, Out: out}, nil
}

// checkList checks that every generation of the identity list ids
// derives from the root of p (ErrIdentity otherwise).
func checkList(p *keys.PlatformRoot, ids []translog.Identity) error {
	for _, id := range ids {
		k, err := p.IdentityKey(id.Gen)
		if err != nil {
			return err
		}
		same := pubOf(k).Equal(id.Pub)
		keys.Wipe(k)
		if !same {
			return fmt.Errorf("%w: identity generation %d of the list", ErrIdentity, id.Gen)
		}
	}
	return nil
}
