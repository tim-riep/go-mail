package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestHPKEVectors is a regression test of the crypto/hpke integration for
// exactly the suite in use: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM, base mode. The vector comes from the CFRG repository
// referenced by RFC 9180 (see testdata/hpke/*.json, field "source"); the
// RFC's own appendix prints only the AES-128-GCM and ChaCha20-Poly1305
// variants for X25519.
func TestHPKEVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/hpke/rfc9180_x25519_hkdfsha256_aes256gcm_base.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Mode        int    `json:"mode"`
		KEM         int    `json:"kem_id"`
		KDF         int    `json:"kdf_id"`
		AEAD        int    `json:"aead_id"`
		Info        string `json:"info"`
		IKMR        string `json:"ikmR"`
		SKR         string `json:"skRm"`
		PKR         string `json:"pkRm"`
		Enc         string `json:"enc"`
		Encryptions []struct{ AAD, CT, Nonce, PT string }
		Exports     []struct {
			Context string `json:"exporter_context"`
			L       int    `json:"L"`
			Value   string `json:"exported_value"`
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Mode != 0 || v.KEM != 0x20 || v.KDF != 1 || v.AEAD != 2 {
		t.Fatalf("vector is for another suite: %+v", v)
	}
	kem := hpke.DHKEM(ecdh.X25519())
	if kem.ID() != 0x20 || hpke.HKDFSHA256().ID() != 1 || hpke.AES256GCM().ID() != 2 {
		t.Fatal("suite identifiers differ from RFC 9180")
	}
	// Key derivation of the recipient from its IKM.
	sk, err := kem.DeriveKeyPair(unhex(t, v.IKMR))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk.PublicKey().Bytes(), unhex(t, v.PKR)) {
		t.Fatal("DeriveKeyPair differs from the vector")
	}
	// PrivateKey.Bytes applies the X25519 clamping of RFC 9180 section
	// 7.1.2, so it need not equal the vector's raw scalar; the scalar
	// itself must still produce the same public key.
	skRaw, err := kem.NewPrivateKey(unhex(t, v.SKR))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skRaw.PublicKey().Bytes(), unhex(t, v.PKR)) {
		t.Fatal("vector private key does not produce the vector public key")
	}
	skb, _ := sk.Bytes()
	skRawB, _ := skRaw.Bytes()
	if !bytes.Equal(skb, skRawB) {
		t.Fatal("derived and deserialized private keys differ")
	}
	// The recipient side with the vector's enc.
	r, err := hpke.NewRecipient(unhex(t, v.Enc), sk, hpke.HKDFSHA256(), hpke.AES256GCM(), unhex(t, v.Info))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range v.Encryptions {
		pt, err := r.Open(unhex(t, e.AAD), unhex(t, e.CT))
		if err != nil {
			t.Fatalf("encryption %d: %v", i, err)
		}
		if !bytes.Equal(pt, unhex(t, e.PT)) {
			t.Fatalf("encryption %d: plaintext differs", i)
		}
	}
	for i, e := range v.Exports {
		got, err := r.Export(string(unhex(t, e.Context)), e.L)
		if err != nil {
			t.Fatalf("export %d: %v", i, err)
		}
		if !bytes.Equal(got, unhex(t, e.Value)) {
			t.Fatalf("export %d differs", i)
		}
	}
	// The same key through the ecdh path used by this package.
	ecdhKey, err := ecdh.X25519().NewPrivateKey(unhex(t, v.SKR))
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := hpke.NewDHKEMPrivateKey(ecdhKey)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := hpke.NewRecipient(unhex(t, v.Enc), sk2, hpke.HKDFSHA256(), hpke.AES256GCM(), unhex(t, v.Info))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r2.Open(unhex(t, v.Encryptions[0].AAD), unhex(t, v.Encryptions[0].CT))
	if err != nil || !bytes.Equal(pt, unhex(t, v.Encryptions[0].PT)) {
		t.Fatal("ecdh-based private key differs")
	}
	// A tampered ciphertext or aad fails.
	if _, err := r2.Open(unhex(t, v.Encryptions[1].AAD), unhex(t, v.Encryptions[1].CT)); err != nil {
		t.Fatal(err)
	}
	ct := unhex(t, v.Encryptions[2].CT)
	ct[0] ^= 1
	if _, err := r2.Open(unhex(t, v.Encryptions[2].AAD), ct); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

// TestHPKELowOrderPoints: both sides must fail on small-order X25519
// points instead of deriving an all-zero shared secret.
func TestHPKELowOrderPoints(t *testing.T) {
	lowOrder := [][]byte{
		make([]byte, 32),
		append([]byte{1}, make([]byte, 31)...),
		unhex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		unhex(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		unhex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
	sk := x25519Key(t, "low order test")
	for i, p := range lowOrder {
		pub, err := ecdh.X25519().NewPublicKey(p)
		if err != nil {
			continue // some encodings are rejected already
		}
		pk, err := hpke.NewDHKEMPublicKey(pub)
		if err != nil {
			continue
		}
		if _, _, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), nil); err == nil {
			t.Fatalf("point %d: sender accepted a low-order recipient key", i)
		}
		rk, _ := hpke.NewDHKEMPrivateKey(sk)
		if _, err := hpke.NewRecipient(p, rk, hpke.HKDFSHA256(), hpke.AES256GCM(), nil); err == nil {
			t.Fatalf("point %d: recipient accepted a low-order enc", i)
		}
	}
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
