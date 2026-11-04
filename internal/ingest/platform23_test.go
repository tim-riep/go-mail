package ingest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// TestPlatformCertReadOnce (task 23): New reads ingest-<gen>.cert once;
// the key, identity_gen, valid_from and the comparison with the log
// (Log.CheckPlatform) work on the same bytes. The pin revokes identity
// generation 1, which issued the logged ingest-1.cert, so New must
// refuse generation 1 (the cascade of D93). When New reads it,
// ingest-1.cert holds a certificate for the same key that names identity
// generation 2 and is not in the log; right after the read (the test
// hook) the logged file is back. New fails with ErrConfig, because the
// certificate it read is not in the log; it never starts. The other way
// round (the logged certificate when read, the other one right after)
// it refuses the generation with ErrRevoked, from the logged
// certificate.
func TestPlatformCertReadOnce(t *testing.T) {
	env := testenv.NewLogged(t)
	certPath := env.Store.Path("platform", store.PlatformFileName("ingest", 1, "cert"))
	logged, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	lc, err := keys.DecodePlatformCert(logged)
	if err != nil {
		t.Fatal(err)
	}
	// New does not check the signature (the clients do); any key will
	// do for the certificate that is not in the log.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := keys.NewPlatformCert(other, 2, keys.RoleIngest, 1, lc.Pub, lc.ValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := fc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(forged, logged) {
		t.Fatal("the certificates are the same")
	}
	revoked := []translog.Revoked{{Role: store.KeyRoleIdentity, Gen: 1, AtSize: 1, AtTime: env.Clock.Now().UnixMilli()}}
	for _, tc := range []struct {
		name          string
		first, second []byte
		want          error
	}{
		{"forged then logged", forged, logged, ErrConfig},
		{"logged then forged", logged, forged, ErrRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.WriteFileAtomic(certPath, tc.first); err != nil {
				t.Fatal(err)
			}
			calls := 0
			certReadHook = func() {
				calls++
				if calls == 1 {
					if err := store.WriteFileAtomic(certPath, tc.second); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { certReadHook = nil })
			in, err := New(Config{Store: env.Store, Log: env.Log, IngestKey: env.IngestKey, IngestGen: 1, Now: env.Clock.Now, Revoked: revoked,
				DiskSpace: func(string) (uint64, uint64, error) { return 50, 100, nil }})
			if err == nil {
				in.Close()
				t.Fatal("New started with the generation the pin revokes through its identity generation")
			}
			if !errors.Is(err, tc.want) || !errors.Is(err, ErrConfig) {
				t.Fatalf("New: %v", err)
			}
			if calls != 1 {
				t.Fatalf("hook called %d times", calls)
			}
			// No server lock is left behind.
			release, err := env.Store.HoldRoleLock(store.RoleServer)
			if err != nil {
				t.Fatal(err)
			}
			release()
		})
	}
	// Without the swap the logged certificate starts the server when the
	// pin revokes nothing.
	if err := store.WriteFileAtomic(certPath, logged); err != nil {
		t.Fatal(err)
	}
	newIngest(t, env)
}
