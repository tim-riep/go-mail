package ingest

import (
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// TestRevokedGeneration (task 21b, D93): New refuses an ingest generation
// that the revocation list of the pin (Config.Revoked, field 7) names,
// and one whose certificate a listed identity generation issued (the
// cascade of the addendum on task 21a: ingest-1.cert is issued by
// identity 1), whatever its revoked_at_time (ErrRevoked with ErrConfig),
// and takes no server lock then; a list that names other generations
// (ingest 2, admin 1, identity 2) does not stop it.
func TestRevokedGeneration(t *testing.T) {
	env := testenv.New(t)
	now := env.Clock.Now().UnixMilli()
	for _, role := range []uint8{store.KeyRoleIngest, store.KeyRoleIdentity} {
		for _, at := range []int64{0, now, now + 1} {
			_, err := New(Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now,
				Revoked: []translog.Revoked{{Role: role, Gen: 1, AtSize: 1, AtTime: at}}})
			if !errors.Is(err, ErrRevoked) || !errors.Is(err, ErrConfig) {
				t.Fatalf("role %d revoked at %d: %v", role, at, err)
			}
			release, err := env.Store.HoldRoleLock(store.RoleServer)
			if err != nil {
				t.Fatalf("role %d revoked at %d: server lock taken: %v", role, at, err)
			}
			release()
		}
	}
	in := newIngest(t, env, func(c *Config) {
		c.Revoked = []translog.Revoked{{Role: store.KeyRoleIdentity, Gen: 2, AtSize: 1, AtTime: now},
			{Role: store.KeyRoleAdmin, Gen: 1, AtSize: 1, AtTime: now}, {Role: store.KeyRoleIngest, Gen: 2, AtSize: 1, AtTime: now}}
	})
	in.Close()
}
