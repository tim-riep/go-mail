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

// minHeadTime is the earliest head time (ms since 1970 UTC,
// 2025-01-01T00:00:00Z) a revocation boundary may name (checkBoundary,
// and checkRevocations for every element of field 7). No log of this
// software has a head before it: the formats were fixed in 2026. It
// catches a time typed in seconds instead of milliseconds (attack review
// 21c F2): a time in seconds of any date up to the year 56000 is below
// it (as milliseconds it lies in January 1970), and such a boundary
// would make every head and metadata signature of the generation
// invalid. A time in microseconds or nanoseconds lies after the clock
// and is refused by the upper bound.
const minHeadTime int64 = 1735689600000

// checkBoundary checks the boundary of a revocation (D93 (2)) as far as
// the ceremony, offline, can: size and time of a witness-confirmed head,
// read by the operator before the ceremony. The size is that of a signed
// head (1 to translog.MaxTreeSize), the time in milliseconds since 1970
// UTC at least minHeadTime, below math.MaxInt64 (the pin takes it + 1)
// and not after the clock of the ceremony plus translog.MaxClockSkew (the
// head was signed before the ceremony; the tolerance is the one of every
// head time). Everything else is ErrRevocation. The comparison with the
// log itself is Publish's (checkRevocations): only there is the head
// known.
//
// The element of field 7 is (size, at + 1) (D93 addendum):
// revoked_at_size is the size of the head, revoked_at_time its time plus
// 1 ms, so that the confirmed head itself and every entry below its size
// stay valid.
func checkBoundary(size, at int64, now func() time.Time) error {
	if size < 1 || size > translog.MaxTreeSize {
		return fmt.Errorf("%w: head size %d is not the size of a signed head (1 to %d)", ErrRevocation, size, translog.MaxTreeSize)
	}
	if at < 1 || at == math.MaxInt64 {
		return fmt.Errorf("%w: head time %d is not the time of a signed head", ErrRevocation, at)
	}
	if at < minHeadTime {
		return fmt.Errorf("%w: head time %d (%s) lies before %d (%s), the earliest head time: the time of the head is in milliseconds since 1970, not in seconds",
			ErrRevocation, at, time.UnixMilli(at).UTC().Format(time.RFC3339Nano), minHeadTime, time.UnixMilli(minHeadTime).UTC().Format(time.RFC3339))
	}
	if limit := now().Add(translog.MaxClockSkew); at > limit.UnixMilli() {
		return fmt.Errorf("%w: head time %d (%s) lies after the clock of the ceremony (%s); a head read before the ceremony cannot",
			ErrRevocation, at, time.UnixMilli(at).UTC().Format(time.RFC3339), now().UTC().Format(time.RFC3339))
	}
	return nil
}

func runRevoke(opts RevokeOptions) (*Result, error) {
	now := nowOrDefault(opts.Now)
	if opts.Role != store.KeyRoleAdmin && opts.Role != store.KeyRoleIngest {
		return nil, fmt.Errorf("%w: only an admin or ingest generation is revoked here; an identity generation with Succeed (Compromised)", ErrRevocation)
	}
	if opts.Gen == 0 {
		return nil, fmt.Errorf("%w: generation 0", ErrRevocation)
	}
	if err := checkBoundary(opts.HeadSize, opts.HeadTime, now); err != nil {
		return nil, err
	}
	if opts.Pin == nil {
		return nil, fmt.Errorf("%w: no pin", ErrOptions)
	}
	ids, err := PinIdentities(opts.Pin)
	if err != nil {
		return nil, err
	}
	revoked, err := addRevoked(opts.Pin.Revoked, store.PlatformRevoked{Role: opts.Role, Gen: opts.Gen,
		AtSize: opts.HeadSize, AtTime: opts.HeadTime + 1})
	if err != nil {
		return nil, err
	}
	// Origin, witnesses and quorum stay those of the pin.
	ws := pinWitnesses(opts.Pin)
	if _, err := checkTrust(opts.Pin.Origin, ws, opts.Pin.MinWitnesses); err != nil {
		return nil, err
	}
	if err := checkUnlock(&opts.UnlockOptions); err != nil {
		return nil, err
	}
	if opts.Pin.Gen != opts.IdentityGen || !opts.Pin.Pub.Equal(opts.IdentityPub) {
		return nil, fmt.Errorf("%w: the pin is not the one of the current identity", ErrIdentity)
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
	pin, pinBytes, err := newPin(&pinData{Identities: ids, Origin: opts.Pin.Origin, Witnesses: ws,
		MinWitnesses: opts.Pin.MinWitnesses, Revoked: revoked})
	if err != nil {
		return nil, err
	}
	if err := commit(out, map[string][]byte{exportPin(opts.IdentityGen): pinBytes}, "", nil, guardOf(opts.Prompter)); err != nil {
		return nil, err
	}
	return &Result{IdentityPub: ed25519.PublicKey(bytes.Clone(opts.IdentityPub)), Pin: pin, Out: out}, nil
}
