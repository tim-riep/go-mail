package keys

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func FuzzParseWordlist(f *testing.F) {
	f.Add(wordlistData)
	f.Add([]byte("a\nb\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		words, err := parseWordlist(data)
		if err != nil {
			if words != nil {
				t.Fatal("words returned with error")
			}
			return
		}
		if len(words) != 2048 {
			t.Fatal("accepted list of wrong size")
		}
		for i := 1; i < len(words); i++ {
			if words[i] <= words[i-1] {
				t.Fatal("accepted unsorted list")
			}
		}
		joined := strings.Join(words, "\n")
		if string(data) != joined && string(data) != joined+"\n" {
			t.Fatal("accepted list does not re-join to its input")
		}
	})
}

func FuzzSeedFromWords(f *testing.F) {
	f.Add("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	f.Add("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		words := strings.Fields(s)
		seed, err := SeedFromWords(words)
		if err != nil {
			if seed != nil {
				t.Fatal("seed returned with error")
			}
			return
		}
		back, err := seed.Words()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(back, " ") != strings.Join(words, " ") {
			t.Fatal("accepted words do not round-trip")
		}
	})
}

func FuzzDecodeGenerationCert(f *testing.F) {
	var seed Seed
	u := DeriveUser(&seed)
	root, _ := u.RootKey()
	for g := uint32(1); g <= 2; g++ {
		id, _ := u.IdentityKey(g)
		uw, _ := u.UnwrapKey(g)
		c, _ := NewGenerationCert(root, g, id.Public().(ed25519.PublicKey), uw.PublicKey(), 1)
		enc, _ := c.Encode()
		f.Add(enc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeGenerationCert(data)
		if err != nil {
			if c != nil {
				t.Fatal("certificate returned with error")
			}
			return
		}
		enc, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(enc, data) {
			t.Fatal("accepted certificate does not re-encode identically")
		}
	})
}

func FuzzOpenKeystore(f *testing.F) {
	var seed Seed
	seed[1] = 1
	u := DeriveUser(&seed)
	id, _ := u.IdentityKey(1)
	uw, _ := u.UnwrapKey(1)
	k := &Keystore{Generation: 1, Identity: id, Unwrap: uw}
	pass := []byte("fuzz")
	data, err := k.seal(pass, bytes.NewReader(make([]byte, 64)), DefaultKDFParams, fastKDF)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add(data[:8])
	f.Add([]byte(KeystoreMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := openKeystore(data, pass, fastKDF)
		if err != nil {
			if got != nil {
				t.Fatal("keystore returned with error")
			}
			return
		}
		// Only the untouched seed can authenticate; anything accepted must
		// hold exactly its keys and have a byte-identical header.
		if got.Generation != 1 || !bytes.Equal(got.Identity, id) || !bytes.Equal(got.Unwrap.Bytes(), uw.Bytes()) {
			t.Fatal("accepted keystore with different content")
		}
		hdr, _, err := parseKeystore(data)
		if err != nil {
			t.Fatal(err)
		}
		hb, _ := hdr.Encode()
		if !bytes.Equal(hb, data[8:8+len(hb)]) {
			t.Fatal("header does not re-encode identically")
		}
	})
}
