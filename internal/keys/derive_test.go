package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// deriveVectors mirrors testdata/derive_vectors.json written by testdata/gen.
type deriveVectors struct {
	Seeds []struct {
		Name  string `json:"name"`
		Seed  string `json:"seed"`
		Words string `json:"words"`
		User  struct {
			Root     keyVector   `json:"root"`
			Identity []keyVector `json:"identity"`
			Unwrap   []keyVector `json:"unwrap"`
		} `json:"user"`
		Platform struct {
			Identity []keyVector `json:"identity"`
			Admin    []keyVector `json:"admin"`
			Ingest   []keyVector `json:"ingest"`
		} `json:"platform"`
	} `json:"seeds"`
}

type keyVector struct {
	Gen    uint32 `json:"gen,omitempty"`
	Secret string `json:"secret"`
	Public string `json:"public"`
}

func loadDeriveVectors(t *testing.T) deriveVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/derive_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v deriveVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Seeds) < 3 {
		t.Fatalf("need at least three seeds, got %d", len(v.Seeds))
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeriveVectors(t *testing.T) {
	vecs := loadDeriveVectors(t)
	for _, sv := range vecs.Seeds {
		t.Run(sv.Name, func(t *testing.T) {
			var seed Seed
			copy(seed[:], unhex(t, sv.Seed))
			words, err := seed.Words()
			if err != nil {
				t.Fatal(err)
			}
			if got := joinWords(words); got != sv.Words {
				t.Errorf("words: got %q", got)
			}
			u := DeriveUser(&seed)
			root, err := u.RootKey()
			if err != nil {
				t.Fatal(err)
			}
			checkEd(t, "user/root", root, sv.User.Root)
			if len(sv.User.Identity) < 2 || len(sv.User.Unwrap) < 2 {
				t.Fatal("vectors must contain generations 1 and 2")
			}
			for _, kv := range sv.User.Identity {
				k, err := u.IdentityKey(kv.Gen)
				if err != nil {
					t.Fatal(err)
				}
				checkEd(t, "user/identity", k, kv)
			}
			for _, kv := range sv.User.Unwrap {
				k, err := u.UnwrapKey(kv.Gen)
				if err != nil {
					t.Fatal(err)
				}
				checkX(t, "user/unwrap", k, kv)
			}
			p := DerivePlatform(&seed)
			for _, kv := range sv.Platform.Identity {
				k, err := p.IdentityKey(kv.Gen)
				if err != nil {
					t.Fatal(err)
				}
				checkEd(t, "platform/identity", k, kv)
			}
			for _, kv := range sv.Platform.Admin {
				k, err := p.AdminKey(kv.Gen)
				if err != nil {
					t.Fatal(err)
				}
				checkEd(t, "platform/admin", k, kv)
			}
			for _, kv := range sv.Platform.Ingest {
				k, err := p.IngestKey(kv.Gen)
				if err != nil {
					t.Fatal(err)
				}
				checkEd(t, "platform/ingest", k, kv)
			}
		})
	}
}

func checkEd(t *testing.T, what string, k ed25519.PrivateKey, v keyVector) {
	t.Helper()
	if !bytes.Equal(k.Seed(), unhex(t, v.Secret)) {
		t.Errorf("%s gen %d: secret differs", what, v.Gen)
	}
	if !bytes.Equal(k.Public().(ed25519.PublicKey), unhex(t, v.Public)) {
		t.Errorf("%s gen %d: public key differs", what, v.Gen)
	}
}

func checkX(t *testing.T, what string, k *ecdh.PrivateKey, v keyVector) {
	t.Helper()
	if !bytes.Equal(k.Bytes(), unhex(t, v.Secret)) {
		t.Errorf("%s gen %d: secret differs", what, v.Gen)
	}
	if !bytes.Equal(k.PublicKey().Bytes(), unhex(t, v.Public)) {
		t.Errorf("%s gen %d: public key differs", what, v.Gen)
	}
}

// TestDeriveMatchesSpecFormula recomputes one derivation by hand with the
// HKDF calls from the specification, independent of the package's code.
func TestDeriveMatchesSpecFormula(t *testing.T) {
	var seed Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	prk, err := hkdf.Extract(sha256.New, seed[:], []byte("gomail/v1/user-seed"))
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("gomail/v1/user/identity"), 0)
	info = binary.BigEndian.AppendUint32(info, 2)
	want, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	k, err := DeriveUser(&seed).IdentityKey(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Seed(), want) {
		t.Fatal("identity derivation differs from the specification formula")
	}
	rootWant, err := hkdf.Expand(sha256.New, prk, "gomail/v1/user/root", 32)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := DeriveUser(&seed).RootKey()
	if !bytes.Equal(root.Seed(), rootWant) {
		t.Fatal("root derivation differs from the specification formula")
	}
	pprk, _ := hkdf.Extract(sha256.New, seed[:], []byte("gomail/v1/platform-root"))
	pinfo := append([]byte("gomail/v1/platform/ingest"), 0)
	pinfo = binary.BigEndian.AppendUint32(pinfo, 1)
	pwant, _ := hkdf.Expand(sha256.New, pprk, string(pinfo), 32)
	ing, _ := DerivePlatform(&seed).IngestKey(1)
	if !bytes.Equal(ing.Seed(), pwant) {
		t.Fatal("platform derivation differs from the specification formula")
	}
}

func TestDeriveRejectsGenerationZero(t *testing.T) {
	var seed Seed
	u := DeriveUser(&seed)
	if _, err := u.IdentityKey(0); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 0 must be rejected")
	}
	if _, err := u.UnwrapKey(0); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 0 must be rejected")
	}
	p := DerivePlatform(&seed)
	for _, f := range []func(uint32) (ed25519.PrivateKey, error){p.IdentityKey, p.AdminKey, p.IngestKey} {
		if _, err := f(0); !errors.Is(err, ErrGeneration) {
			t.Fatal("generation 0 must be rejected")
		}
	}
}

func TestDerivedKeysAreDistinct(t *testing.T) {
	var seed Seed
	u := DeriveUser(&seed)
	p := DerivePlatform(&seed)
	seen := map[string]string{}
	add := func(name string, b []byte) {
		if prev, ok := seen[string(b)]; ok {
			t.Fatalf("%s equals %s", name, prev)
		}
		seen[string(b)] = name
	}
	root, _ := u.RootKey()
	add("root", root.Seed())
	for g := uint32(1); g <= 3; g++ {
		id, _ := u.IdentityKey(g)
		add("user/identity", id.Seed())
		uw, _ := u.UnwrapKey(g)
		add("user/unwrap", uw.Bytes())
		pid, _ := p.IdentityKey(g)
		add("platform/identity", pid.Seed())
		pa, _ := p.AdminKey(g)
		add("platform/admin", pa.Seed())
		pi, _ := p.IngestKey(g)
		add("platform/ingest", pi.Seed())
	}
}

func TestZeroDerivers(t *testing.T) {
	var seed Seed
	seed[0] = 1
	u := DeriveUser(&seed)
	u.Zero()
	if _, err := u.RootKey(); !errors.Is(err, ErrZeroed) {
		t.Fatal("zeroed deriver must refuse to derive")
	}
	if _, err := u.IdentityKey(1); !errors.Is(err, ErrZeroed) {
		t.Fatal("zeroed deriver must refuse to derive")
	}
	p := DerivePlatform(&seed)
	p.Zero()
	if _, err := p.IngestKey(1); !errors.Is(err, ErrZeroed) {
		t.Fatal("zeroed deriver must refuse to derive")
	}
}

func joinWords(w []string) string {
	out := ""
	for i, s := range w {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
