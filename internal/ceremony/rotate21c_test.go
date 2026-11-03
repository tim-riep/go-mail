package ceremony

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// TestRotateAfterRevocation (D93 addendum, task 21a review F4): with a
// pin that revokes ingest generation Gen-1 at time A, IngestRotate takes
// valid_from = A only (the zero time means A, also in the past); with
// the pin of succeed --compromised (identity IdentityGen-1 revoked at A)
// a valid_from in the past down to A; without either the usual rule. A
// generation the pin revokes is never certified again (admin or
// ingest), before any share is asked. Publish reports a revoked ingest
// generation whose successor was logged before with a later valid_from
// or that has none yet (IngestGap).
func TestRotateAfterRevocation(t *testing.T) {
	f := newFixture(t)
	A := testNow.Add(-time.Hour)
	revI := []store.PlatformRevoked{{Role: store.KeyRoleIngest, Gen: 1, AtSize: 2, AtTime: A.UnixMilli()}}
	revA := []store.PlatformRevoked{{Role: store.KeyRoleAdmin, Gen: 1, AtSize: 2, AtTime: A.UnixMilli()}}
	revID := []store.PlatformRevoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 2, AtTime: A.UnixMilli()}}
	kd := filepath.Join(f.base, "keys")
	fresh := filepath.Join(f.base, "fresh")
	for i, c := range []struct {
		role  uint8
		gen   uint32
		idGen uint32
		rev   []store.PlatformRevoked
		valid time.Time
		want  error
	}{
		{store.KeyRoleIngest, 2, 1, revI, A.Add(-time.Millisecond), ErrRevocation},
		{store.KeyRoleIngest, 2, 1, revI, A.Add(time.Millisecond), ErrRevocation},
		{store.KeyRoleIngest, 2, 1, revI, testNow.Add(time.Hour), ErrRevocation},
		{store.KeyRoleIngest, 2, 1, nil, A, ErrOptions},
		{store.KeyRoleIngest, 3, 1, revI, A, ErrOptions},
		{store.KeyRoleAdmin, 2, 1, revA, A, ErrOptions},
		{store.KeyRoleIngest, 2, 2, revID, A.Add(-time.Millisecond), ErrOptions},
		{store.KeyRoleIngest, 3, 1, []store.PlatformRevoked{{Role: store.KeyRoleIngest, Gen: 3, AtSize: 2, AtTime: 1}}, time.Time{}, ErrRevocation},
		{store.KeyRoleAdmin, 2, 1, []store.PlatformRevoked{{Role: store.KeyRoleAdmin, Gen: 2, AtSize: 2, AtTime: 1}}, time.Time{}, ErrRevocation},
	} {
		u, p := f.unlock(1, 2, 3)
		if c.idGen == 2 {
			u.IdentityGen, u.IdentityPub = 2, identityOf(t, f.root[:], 2)
		}
		_, err := runRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: c.gen, ValidFrom: c.valid, Revoked: c.rev}, c.role)
		if !errors.Is(err, c.want) || len(p.asked) != 0 {
			t.Fatalf("%d %+v: %v, want %v", i, c, err, c.want)
		}
	}
	assertNothing(t, fresh, "")
	// Exact: the zero time means A.
	u, _ := f.unlock(1, 2, 3)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: fresh, KeyDir: kd, Gen: 2, Revoked: revI}); err != nil {
		t.Fatal(err)
	}
	cert, err := keys.DecodePlatformCert(mustReadFile(t, filepath.Join(fresh, "platform", "ingest-2.cert")))
	if err != nil || cert.ValidFrom != A.UnixMilli() {
		t.Fatalf("valid_from: %v", err)
	}
	// Floor after a compromise: A itself and later.
	for i, v := range []time.Time{A, testNow.Add(time.Hour)} {
		u, _ := f.unlock(1, 2, 3)
		u.IdentityGen, u.IdentityPub = 2, identityOf(t, f.root[:], 2)
		out := filepath.Join(f.base, fmt.Sprint("floor", i))
		if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: filepath.Join(f.base, fmt.Sprint("kf", i)), Gen: 3, ValidFrom: v, Revoked: revID}); err != nil {
			t.Fatalf("floor %v: %v", v, err)
		}
	}

	// IngestGap: no successor; a successor logged before the revocation
	// with a later valid_from; none for a successor at the boundary.
	st, h := f.published(t, "data")
	u, _ = f.unlock(1, 2, 3)
	r, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rev"), Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1,
		HeadSize: h.Size, HeadTime: h.Time})
	if err != nil {
		t.Fatal(err)
	}
	var gaps []string
	report := func(gen uint32, at, vf int64) { gaps = append(gaps, fmt.Sprint(gen, at, vf)) }
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: r.Pin, IngestGap: report}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(gaps) != fmt.Sprintf("[1 %d 0]", h.Time+1) {
		t.Fatalf("no successor: %v", gaps)
	}
	st2, h2 := f.published(t, "data2")
	late := filepath.Join(f.base, "late")
	u, _ = f.unlock(1, 2, 3)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: late, KeyDir: filepath.Join(f.base, "k2"), Gen: 2, ValidFrom: headAt.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: late, Data: st2, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	f.signHead(t, st2, f.res.Pin, 1, headAt.Add(time.Second), f.ws...)
	u, _ = f.unlock(1, 2, 3)
	r2, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rev2"), Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1,
		HeadSize: h2.Size, HeadTime: h2.Time})
	if err != nil {
		t.Fatal(err)
	}
	gaps = nil
	// The successor in the export again: logged before, not refused.
	if err := Publish(PublishOptions{From: late, Data: st2, Pin: r2.Pin, IngestGap: report}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(gaps) != fmt.Sprintf("[1 %d %d]", h2.Time+1, headAt.Add(time.Hour).UnixMilli()) {
		t.Fatalf("late successor: %v", gaps)
	}
	// A successor valid from the boundary on: no report.
	st3, h3 := f.published(t, "data3")
	u, _ = f.unlock(1, 2, 3)
	r3, err := Revoke(RevokeOptions{UnlockOptions: u, Out: filepath.Join(f.base, "rev3"), Pin: f.res.Pin, Role: store.KeyRoleIngest, Gen: 1,
		HeadSize: h3.Size, HeadTime: h3.Time})
	if err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(f.base, "exact")
	u, _ = f.unlock(1, 2, 3)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: exact, KeyDir: filepath.Join(f.base, "k4"), Gen: 2, Revoked: r3.Pin.Revoked}); err != nil {
		t.Fatal(err)
	}
	gaps = nil
	if err := Publish(PublishOptions{From: exact, Data: st3, Pin: r3.Pin, IngestGap: report}); err != nil || len(gaps) != 0 {
		t.Fatalf("successor at the boundary: %v %v", err, gaps)
	}
	// The server goes on at revoked_at_time with the new generation; the
	// confirmed head stays valid (D93 addendum).
	f.signHead(t, st3, r3.Pin, 2, time.UnixMilli(h3.Time+1), f.ws...)
}
