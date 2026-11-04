package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
)

// TestReadPlatformCertRaw (task 23): ReadPlatformCertRaw returns the
// bytes of <role>-<gen>.cert it decoded and checked, under the same
// rules as ReadPlatformCert (role, generation, .pub the same key); on
// any error it returns no bytes.
func TestReadPlatformCertRaw(t *testing.T) {
	s, _ := Init(t.TempDir())
	var seed keys.Seed
	seed[0] = 23
	p := keys.DerivePlatform(&seed)
	defer p.Zero()
	id, _ := p.IdentityKey(1)
	ingest, _ := p.IngestKey(1)
	admin, _ := p.AdminKey(1)
	c, _ := keys.NewPlatformCert(id, 1, keys.RoleIngest, 1, ingest.Public().(ed25519.PublicKey), 7)
	cd, _ := c.Encode()
	if err := s.WritePlatformFile(PlatformFileName("ingest", 1, "cert"), cd); err != nil {
		t.Fatal(err)
	}
	if got, raw, err := s.ReadPlatformCertRaw(keys.RoleIngest, 1); !errors.Is(err, ErrNotFound) || got != nil || raw != nil {
		t.Fatal("cert without pub", err)
	}
	if err := s.WritePlatformFile(PlatformFileName("ingest", 1, "pub"), ingest.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	got, raw, err := s.ReadPlatformCertRaw(keys.RoleIngest, 1)
	if err != nil || !bytes.Equal(raw, cd) || !got.Pub.Equal(c.Pub) || got.ValidFrom != 7 || got.Verify(id.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("raw", err)
	}
	dec, err := keys.DecodePlatformCert(raw)
	if err != nil || !dec.Pub.Equal(got.Pub) || dec.IdentityGen != got.IdentityGen || dec.ValidFrom != got.ValidFrom {
		t.Fatal("the bytes are not those of the certificate", err)
	}
	if old, err := s.ReadPlatformCert(keys.RoleIngest, 1); err != nil || !old.Pub.Equal(got.Pub) || old.ValidFrom != got.ValidFrom {
		t.Fatal("ReadPlatformCert", err)
	}
	// Another role under this name, a .pub with another key.
	if err := s.WritePlatformFile(PlatformFileName("admin", 1, "cert"), cd); err != nil {
		t.Fatal(err)
	}
	if got, raw, err := s.ReadPlatformCertRaw(keys.RoleAdmin, 1); !errors.Is(err, ErrRecord) || got != nil || raw != nil {
		t.Fatal("ingest cert accepted as admin cert", err)
	}
	a, _ := keys.NewPlatformCert(id, 1, keys.RoleAdmin, 2, admin.Public().(ed25519.PublicKey), 0)
	ad, _ := a.Encode()
	if err := s.WritePlatformFile(PlatformFileName("admin", 2, "cert"), ad); err != nil {
		t.Fatal(err)
	}
	if err := s.WritePlatformFile(PlatformFileName("admin", 2, "pub"), ingest.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if got, raw, err := s.ReadPlatformCertRaw(keys.RoleAdmin, 2); !errors.Is(err, ErrRecord) || got != nil || raw != nil {
		t.Fatal("pub differs from cert", err)
	}
}
