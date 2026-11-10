package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
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

// TestReadPlatformCertRawReadsOnce (backlog 59, mutant M4 of task 23):
// ReadPlatformCertRaw reads <role>-<gen>.cert exactly once, and the
// certificate it returns is decoded from the bytes it returns. The hook
// counts the reads and replaces the file after the first one with
// another valid certificate of the same key; a version that reads the
// file a second time (ReadPlatformCert, then ReadPlatformFile for the
// bytes) counts two reads and returns the bytes of another certificate.
//
// Task 26, package 26D, point 2 (backlog item 69, mutant M4direct of the
// review of task 24 E): the hook sees only reads through
// ReadPlatformFile. A version that reads the file a second time past it
// (ReadFileLimited on the path, then ReadPlatformCert) counts one read
// at the hook and returns the bytes of the first read, which the swap
// after the hooked read does not change. On Linux the test therefore
// also counts every open and every close of the file with inotify
// (watchOpens), whatever path opens it: exactly one of each. The kernel
// merges equal events queued one after the other; the closes find a
// second open that such a merge hides (a descriptor held open across
// the second read).
//
// Task 27, package 27D, point 1 (backlog item 84): the events do not
// show a descriptor that is never closed. A version that opens the file
// a second time and leaves that descriptor open, or keeps it to read
// later, counts one open and one close when its open merges with the
// first. After each call the test therefore also looks in /proc/self/fd
// (heldFDs): no descriptor may still refer to the .cert, neither to the
// file read first nor to the one the swap put in its place. What stays
// hidden on Linux is a second open whose descriptors are all closed
// again when the call returns and that overlaps the first concurrently,
// from a second goroutine, or goes through another name of the file
// outside platform/ (watchOpens). Elsewhere only the reads through
// ReadPlatformFile count.
func TestReadPlatformCertRawReadsOnce(t *testing.T) {
	s, _ := Init(t.TempDir())
	var seed keys.Seed
	seed[0] = 59
	p := keys.DerivePlatform(&seed)
	defer p.Zero()
	id, _ := p.IdentityKey(1)
	ingest, _ := p.IngestKey(1)
	pub := ingest.Public().(ed25519.PublicKey)
	c1, _ := keys.NewPlatformCert(id, 1, keys.RoleIngest, 1, pub, 7)
	cd1, _ := c1.Encode()
	c2, _ := keys.NewPlatformCert(id, 1, keys.RoleIngest, 1, pub, 9)
	cd2, _ := c2.Encode()
	certName := PlatformFileName("ingest", 1, "cert")
	if err := s.WritePlatformFile(certName, cd1); err != nil {
		t.Fatal(err)
	}
	if err := s.WritePlatformFile(PlatformFileName("ingest", 1, "pub"), pub); err != nil {
		t.Fatal(err)
	}
	reads := map[string]int{}
	swap := true
	platformReadHook = func(name string) {
		reads[name]++
		if name == certName && swap {
			swap = false
			if err := WriteFileAtomic(s.platformFile(certName), cd2); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { platformReadHook = nil })
	opens := watchOpens(t, s.Path("platform"))
	var certFiles []os.FileInfo
	addCert := func() {
		t.Helper()
		fi, err := os.Lstat(s.platformFile(certName))
		if err != nil {
			t.Fatal(err)
		}
		certFiles = append(certFiles, fi)
	}
	addCert() // the file the first call reads
	checkOpens := func(what string) {
		t.Helper()
		if opens == nil {
			return // not Linux; watchOpens has logged it
		}
		opened, closed := opens()
		if n, c := opened[certName], closed[certName]; n != 1 || c != 1 {
			t.Fatalf("%s: %s opened %d, closed %d times, want once", what, certName, n, c)
		}
		if held := heldFDs(t, certFiles...); len(held) != 0 {
			t.Fatalf("%s: descriptors of %s still open after the call: %v", what, certName, held)
		}
	}

	got, raw, err := s.ReadPlatformCertRaw(keys.RoleIngest, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reads[certName] != 1 {
		t.Fatalf("%s read %d times, want once", certName, reads[certName])
	}
	addCert() // the file the swap put in its place
	checkOpens("ReadPlatformCertRaw")
	if !bytes.Equal(raw, cd1) || got.ValidFrom != 7 {
		t.Fatalf("returned certificate (valid_from %d) and bytes are not those of the one read", got.ValidFrom)
	}
	dec, err := keys.DecodePlatformCert(raw)
	if err != nil || dec.ValidFrom != got.ValidFrom || !dec.Pub.Equal(got.Pub) {
		t.Fatal("the bytes decode to another certificate", err)
	}

	// ReadPlatformCert goes the same way: one read, of the replaced file.
	clear(reads)
	if c, err := s.ReadPlatformCert(keys.RoleIngest, 1); err != nil || c.ValidFrom != 9 || reads[certName] != 1 {
		t.Fatalf("ReadPlatformCert: %v, %d reads", err, reads[certName])
	}
	checkOpens("ReadPlatformCert")
}
