package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseAndOpen checks on arbitrary input that Parse never panics,
// that an accepted file re-serializes to the identical bytes, and that
// decryption of anything but an untouched vector file fails, or yields
// exactly the vector's plaintext when only another recipient's entry was
// touched (there is none in the vectors, so success must reproduce the
// recorded plaintext of the file id).
func FuzzParseAndOpen(f *testing.F) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	t := &testing.T{}
	_ = t
	var v vectorFile
	if err := jsonUnmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	expected := map[[16]byte]string{}
	for _, fv := range v.Files {
		data, err := os.ReadFile(filepath.Join("testdata", fv.File))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
		var id [16]byte
		b, _ := hex.DecodeString(fv.FileID)
		copy(id[:], b)
		expected[id] = fv.PlaintextSHA
	}
	f.Add([]byte("GOML\x01\x01"))
	f.Add([]byte{})
	priv, _ := hexKey(v.RecipientPriv)
	key := RecipientKey{Type: RecipientEpochContent, Gen: v.RecipientGen, PrivateKey: priv}
	idb, _ := hex.DecodeString(v.RecipientID)
	copy(key.ID[:], idb)
	signerPub := signerPublic(v.SignerSeed)
	var signerID [16]byte
	sb, _ := hex.DecodeString(v.SignerID)
	copy(signerID[:], sb)

	f.Fuzz(func(t *testing.T, data []byte) {
		pf, err := Parse(data)
		if err != nil {
			if pf != nil {
				t.Fatal("file returned with error")
			}
			return
		}
		if !bytes.Equal(pf.Bytes(), data) {
			t.Fatal("accepted file does not re-serialize identically")
		}
		if pf.Trailer != nil {
			if pf.Trailer.Signer.Type == SignerIngest && pf.Trailer.Signer.ID == signerID && pf.Trailer.Signer.Gen == v.SignerGen {
				if err := pf.VerifySignature(signerPub, nil); err == nil {
					// A valid signature only exists on untouched vectors.
					want, ok := expected[pf.Header.FileID]
					if !ok {
						t.Fatal("valid signature on an unknown file")
					}
					pt, err := pf.Decrypt(key)
					if err != nil {
						t.Fatal("signed vector does not decrypt")
					}
					if sum := sha256.Sum256(pt); hex.EncodeToString(sum[:]) != want {
						t.Fatal("signed vector decrypts to other content")
					}
				}
			}
		}
		pt, err := pf.Decrypt(key)
		if err != nil {
			if pt != nil {
				t.Fatal("plaintext returned with error")
			}
			return
		}
		want, ok := expected[pf.Header.FileID]
		if !ok {
			t.Fatalf("decryption succeeded for an unknown file id")
		}
		if sum := sha256.Sum256(pt); hex.EncodeToString(sum[:]) != want {
			t.Fatal("manipulated file decrypted to different content")
		}
		// A wrong key never decrypts.
		wrong := key
		wrong.Gen++
		if _, err := pf.Decrypt(wrong); err == nil {
			t.Fatal("wrong generation decrypted")
		}
	})
}
