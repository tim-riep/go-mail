package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
)

func TestCertVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/cert_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed                string
		RootPub             string `json:"root_pub"`
		Generations         []string
		PlatformIdentityPub string `json:"platform_identity_pub"`
		IngestCert          string `json:"ingest_cert"`
		AdminCert           string `json:"admin_cert"`
		IdentitySuccession  string `json:"identity_succession"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	rootPub := ed25519.PublicKey(unhex(t, v.RootPub))
	var seed Seed
	copy(seed[:], unhex(t, v.Seed))
	u := DeriveUser(&seed)
	root, _ := u.RootKey()
	if !bytes.Equal(root.Public().(ed25519.PublicKey), rootPub) {
		t.Fatal("root public key differs from vector")
	}
	var chain []*GenerationCert
	for i, h := range v.Generations {
		enc := unhex(t, h)
		c, err := DecodeGenerationCert(enc)
		if err != nil {
			t.Fatalf("generation %d: %v", i+1, err)
		}
		if err := c.Verify(rootPub); err != nil {
			t.Fatalf("generation %d: %v", i+1, err)
		}
		re, _ := c.Encode()
		if !bytes.Equal(re, enc) {
			t.Fatalf("generation %d: re-encoding differs", i+1)
		}
		// The certified keys are the derived ones.
		id, _ := u.IdentityKey(c.Gen)
		uw, _ := u.UnwrapKey(c.Gen)
		if !bytes.Equal(c.IdentityPub, id.Public().(ed25519.PublicKey)) || !bytes.Equal(c.UnwrapPub.Bytes(), uw.PublicKey().Bytes()) {
			t.Fatalf("generation %d certifies other keys", i+1)
		}
		chain = append(chain, c)
	}
	if err := VerifyGenerationChain(rootPub, chain); err != nil {
		t.Fatal(err)
	}
	idPub := ed25519.PublicKey(unhex(t, v.PlatformIdentityPub))
	for name, h := range map[string]string{"ingest": v.IngestCert, "admin": v.AdminCert} {
		enc := unhex(t, h)
		c, err := DecodePlatformCert(enc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Verify(idPub); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if re, _ := c.Encode(); !bytes.Equal(re, enc) {
			t.Fatalf("%s: re-encoding differs", name)
		}
	}
	enc := unhex(t, v.IdentitySuccession)
	s, err := DecodeIdentitySuccession(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(idPub, 1); err != nil {
		t.Fatal(err)
	}
	if re, _ := s.Encode(); !bytes.Equal(re, enc) {
		t.Fatal("succession re-encoding differs")
	}
}

func TestKeystoreVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/keystore_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Passphrase string
		Generation uint32
		Identity   string `json:"identity_seed"`
		Unwrap     string `json:"unwrap_priv"`
		Random     string
		File       string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	file := unhex(t, v.File)
	k, err := OpenKeystore(file, []byte(v.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if k.Generation != v.Generation || !bytes.Equal(k.Identity.Seed(), unhex(t, v.Identity)) || !bytes.Equal(k.Unwrap.Bytes(), unhex(t, v.Unwrap)) {
		t.Fatal("key store content differs from vector")
	}
	// Sealing again with the same randomness reproduces the file exactly.
	again, err := k.Seal([]byte(v.Passphrase), bytes.NewReader(unhex(t, v.Random)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, file) {
		t.Fatal("sealing with the fixed randomness does not reproduce the vector")
	}
}
