package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fastKDF replaces Argon2id in tests that exercise the file format rather
// than the password hashing. It is never used outside tests.
func fastKDF(pass, salt []byte, p KDFParams) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i) ^ salt[i%len(salt)]
	}
	for i, b := range pass {
		out[i%32] ^= b
	}
	return out
}

func testKeystore(t *testing.T) *Keystore {
	t.Helper()
	var seed Seed
	seed[0] = 42
	u := DeriveUser(&seed)
	id, _ := u.IdentityKey(3)
	uw, _ := u.UnwrapKey(3)
	return &Keystore{Generation: 3, Identity: id, Unwrap: uw}
}

func sealFast(t *testing.T, k *Keystore, pass []byte) []byte {
	t.Helper()
	data, err := k.seal(pass, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)), DefaultKDFParams, fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKeystoreRoundTripArgon2(t *testing.T) {
	k := testKeystore(t)
	pass := []byte("correct horse battery staple")
	data, err := k.Seal(pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(KeystoreMagic)) {
		t.Fatal("magic missing")
	}
	got, err := OpenKeystore(data, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != 3 || !bytes.Equal(got.Identity, k.Identity) || !bytes.Equal(got.Unwrap.Bytes(), k.Unwrap.Bytes()) {
		t.Fatal("keys differ after round trip")
	}
	if _, err := OpenKeystore(data, []byte("wrong")); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// Two seals of the same keystore differ (random salt and nonce).
	data2, _ := k.Seal(pass, nil)
	if bytes.Equal(data, data2) {
		t.Fatal("salt and nonce must be random")
	}
	got.Zero()
	if !bytes.Equal(got.Identity, make([]byte, ed25519.PrivateKeySize)) || got.Unwrap != nil {
		t.Fatal("Zero must clear the keys")
	}
}

func TestKeystoreHeaderParams(t *testing.T) {
	k := testKeystore(t)
	pass := []byte("pw")
	data := sealFast(t, k, pass)
	hdr, _, err := parseKeystore(data)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.U8(1) != KeystoreVersion || hdr.U8(2) != kdfArgon2id || hdr.U32(3) != DefaultKDFParams.MemoryKiB || hdr.U32(4) != DefaultKDFParams.Passes || hdr.U8(5) != DefaultKDFParams.Threads {
		t.Fatal("header does not carry the KDF parameters")
	}
	if len(hdr.Bytes(6)) != 16 || len(hdr.Bytes(7)) != 12 {
		t.Fatal("salt and nonce sizes")
	}
	if _, err := openKeystore(data, pass, fastKDF); err != nil {
		t.Fatal(err)
	}
}

// rewriteHeader re-encodes the header of a sealed keystore after f changed
// it, without touching the ciphertext. The AEAD must then fail because
// the header is authenticated as AAD.
func rewriteHeader(t *testing.T, data []byte, f func(h *keystoreHeader)) []byte {
	t.Helper()
	hdr, ct, err := parseKeystore(data)
	if err != nil {
		t.Fatal(err)
	}
	h := headerFromRecord(hdr)
	f(h)
	hb, err := h.record().Encode()
	if err != nil {
		t.Fatal(err)
	}
	out := []byte(KeystoreMagic)
	out = binary.BigEndian.AppendUint32(out, uint32(len(hb)))
	out = append(out, hb...)
	return append(out, ct...)
}

func TestKeystoreRejects(t *testing.T) {
	k := testKeystore(t)
	pass := []byte("pw")
	data := sealFast(t, k, pass)
	kdfCalled := false
	spy := func(p, s []byte, kp KDFParams) []byte { kdfCalled = true; return fastKDF(p, s, kp) }

	cases := []struct {
		name string
		data []byte
		err  error
		kdf  bool // the KDF may run before the rejection
	}{
		{"empty", nil, ErrKeystore, false},
		{"bad magic", append([]byte("GMKX"), data[4:]...), ErrKeystore, false},
		{"header length beyond data", append([]byte(KeystoreMagic), 0xff, 0xff, 0xff, 0xff), ErrKeystore, false},
		{"header length huge", func() []byte { d := append([]byte(nil), data...); binary.BigEndian.PutUint32(d[4:], 1<<30); return d }(), ErrKeystore, false},
		{"truncated header", data[:20], ErrKeystore, false},
		{"no ciphertext", func() []byte { n := 8 + int(binary.BigEndian.Uint32(data[4:8])); return data[:n] }(), ErrKeystore, false},
		{"ciphertext too short", func() []byte { n := 8 + int(binary.BigEndian.Uint32(data[4:8])); return data[:n+10] }(), ErrKeystore, false},
		{"ciphertext too long", append(append([]byte(nil), data...), make([]byte, MaxKeystoreSize)...), ErrKeystore, false},
		{"version 2", rewriteHeader(t, data, func(h *keystoreHeader) { h.version = 2 }), ErrKeystore, false},
		{"unknown kdf", rewriteHeader(t, data, func(h *keystoreHeader) { h.kdf = 2 }), ErrKeystore, false},
		{"memory below floor", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.MemoryKiB = 65535 }), ErrKDFParams, false},
		{"memory above ceiling", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.MemoryKiB = MaxKDFMemoryKiB + 1 }), ErrKDFParams, false},
		{"passes below floor", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.Passes = 2 }), ErrKDFParams, false},
		{"passes above ceiling", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.Passes = MaxKDFPasses + 1 }), ErrKDFParams, false},
		{"threads zero", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.Threads = 0 }), ErrKDFParams, false},
		{"threads above ceiling", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.Threads = MaxKDFThreads + 1 }), ErrKDFParams, false},
		{"passes raised (AAD)", rewriteHeader(t, data, func(h *keystoreHeader) { h.params.Passes = 4 }), ErrPassphrase, true},
		{"salt changed", rewriteHeader(t, data, func(h *keystoreHeader) { h.salt[0] ^= 1 }), ErrPassphrase, true},
		{"nonce changed", rewriteHeader(t, data, func(h *keystoreHeader) { h.nonce[0] ^= 1 }), ErrPassphrase, true},
		{"ciphertext bit flipped", func() []byte { d := append([]byte(nil), data...); d[len(d)-20] ^= 1; return d }(), ErrPassphrase, true},
		{"tag bit flipped", func() []byte { d := append([]byte(nil), data...); d[len(d)-1] ^= 1; return d }(), ErrPassphrase, true},
		{"ciphertext extended", append(append([]byte(nil), data...), 0), ErrPassphrase, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kdfCalled = false
			got, err := openKeystore(tc.data, pass, spy)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if got != nil {
				t.Fatal("no keystore on error")
			}
			if kdfCalled && !tc.kdf {
				t.Fatal("the KDF ran before the parameters were checked")
			}
		})
	}
	// Every single bit flip anywhere in the file must be rejected.
	for i := range data {
		for bit := 0; bit < 8; bit++ {
			d := append([]byte(nil), data...)
			d[i] ^= 1 << bit
			if got, err := openKeystore(d, pass, fastKDF); err == nil || got != nil {
				t.Fatalf("bit %d of byte %d flipped: accepted", bit, i)
			}
		}
	}
}

func TestKeystoreContentRejects(t *testing.T) {
	// A keystore whose authenticated content is malformed must still be
	// rejected: generation 0, wrong record type, extra bytes.
	k := testKeystore(t)
	pass := []byte("pw")
	bad := []struct {
		name string
		body func() ([]byte, error)
		err  error
	}{
		{"generation 0", func() ([]byte, error) {
			return keystoreContent(0, k.Identity.Seed(), k.Unwrap.Bytes())
		}, ErrGeneration},
		{"wrong record", func() ([]byte, error) {
			return GenerationCertSchema.Prefix(), nil
		}, ErrKeystore},
		{"trailing byte", func() ([]byte, error) {
			b, err := keystoreContent(1, k.Identity.Seed(), k.Unwrap.Bytes())
			return append(b, 0), err
		}, ErrKeystore},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			body, err := tc.body()
			if err != nil {
				t.Fatal(err)
			}
			data, err := sealBody(body, pass, bytes.NewReader(make([]byte, 64)), DefaultKDFParams, fastKDF)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := openKeystore(data, pass, fastKDF); !errors.Is(err, tc.err) || got != nil {
				t.Fatalf("expected %v, got %v %v", tc.err, got, err)
			}
		})
	}
}

func TestKeystoreSealRejects(t *testing.T) {
	k := testKeystore(t)
	if _, err := (&Keystore{}).Seal([]byte("pw"), nil); !errors.Is(err, ErrGeneration) {
		t.Fatal("generation 0 must not be sealed")
	}
	if _, err := (&Keystore{Generation: 1, Identity: k.Identity}).Seal([]byte("pw"), nil); !errors.Is(err, ErrKeystore) {
		t.Fatal("missing unwrap key must be rejected")
	}
	if _, err := (&Keystore{Generation: 1, Identity: k.Identity[:5], Unwrap: k.Unwrap}).Seal([]byte("pw"), nil); !errors.Is(err, ErrKeystore) {
		t.Fatal("short identity key must be rejected")
	}
	if _, err := k.Seal(nil, nil); !errors.Is(err, ErrPassphrase) {
		t.Fatal("empty passphrase must be rejected")
	}
	if _, err := k.seal([]byte("pw"), bytes.NewReader([]byte{1}), DefaultKDFParams, fastKDF); err == nil {
		t.Fatal("short random source must fail")
	}
	if _, err := k.seal([]byte("pw"), nil, KDFParams{MemoryKiB: 1, Passes: 1, Threads: 1}, fastKDF); !errors.Is(err, ErrKDFParams) {
		t.Fatal("weak parameters must not be used for sealing")
	}
}

func TestKeystoreFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	data := []byte("GMKS test data")
	if err := WriteKeystoreFile(path, data); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
	got, err := ReadKeystoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
	// Overwrite is atomic and keeps the permissions.
	if err := WriteKeystoreFile(path, []byte("GMKS new")); err != nil {
		t.Fatal(err)
	}
	got, _ = ReadKeystoreFile(path)
	if string(got) != "GMKS new" {
		t.Fatal("overwrite failed")
	}
	if _, err := ReadKeystoreFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail")
	}
	big := filepath.Join(dir, "big")
	os.WriteFile(big, make([]byte, MaxKeystoreSize+1), 0o600)
	if _, err := ReadKeystoreFile(big); !errors.Is(err, ErrKeystore) {
		t.Fatal("oversized file must be rejected")
	}
	if _, err := ReadKeystoreFile(dir); err == nil {
		t.Fatal("directory must be rejected")
	}
	if err := WriteKeystoreFile(filepath.Join(dir, "nodir", "x"), data); err == nil {
		t.Fatal("missing directory must fail")
	}
}

var _ = ecdh.X25519
