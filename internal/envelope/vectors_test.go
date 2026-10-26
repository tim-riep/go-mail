package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorFile mirrors testdata/vectors.json written by testdata/gen.
type vectorFile struct {
	RecipientPriv string `json:"recipient_priv"`
	RecipientID   string `json:"recipient_id"`
	RecipientGen  uint32 `json:"recipient_gen"`
	SignerSeed    string `json:"signer_seed"`
	SignerID      string `json:"signer_id"`
	SignerGen     uint32 `json:"signer_gen"`
	Files         []struct {
		Name         string `json:"name"`
		File         string `json:"file"`
		Size         int    `json:"size"`
		Signed       bool   `json:"signed"`
		Kind         uint8  `json:"kind"`
		MailboxID    string `json:"mailbox_id"`
		Epoch        uint32 `json:"epoch"`
		FileID       string `json:"file_id"`
		Created      int64  `json:"created"`
		Version      uint32 `json:"version"`
		Random       string `json:"random"`
		PlaintextSHA string `json:"plaintext_sha256"`
		NoncePrefix  string `json:"nonce_prefix"`
		Blocks       int    `json:"blocks"`
		BlockSHA256  string `json:"blocks_sha256"`
		HeaderBytes  string `json:"header"`
	} `json:"files"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Files) < 5 {
		t.Fatalf("expected at least five vector files, got %d", len(v.Files))
	}
	return v
}

func vectorKeys(t *testing.T, v vectorFile) (RecipientKey, func(SignerRef) (ed25519.PublicKey, error)) {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(unhex(t, v.RecipientPriv))
	if err != nil {
		t.Fatal(err)
	}
	key := RecipientKey{Type: RecipientEpochContent, Gen: v.RecipientGen, PrivateKey: priv}
	copy(key.ID[:], unhex(t, v.RecipientID))
	signer := ed25519.NewKeyFromSeed(unhex(t, v.SignerSeed))
	var signerID [16]byte
	copy(signerID[:], unhex(t, v.SignerID))
	resolve := func(ref SignerRef) (ed25519.PublicKey, error) {
		if ref.Type == SignerIngest && ref.ID == signerID && ref.Gen == v.SignerGen {
			return signer.Public().(ed25519.PublicKey), nil
		}
		return nil, ErrSigner
	}
	return key, resolve
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	key, resolve := vectorKeys(t, v)
	for _, fv := range v.Files {
		t.Run(fv.Name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", fv.File))
			if err != nil {
				t.Fatal(err)
			}
			f, pt, err := Open(data, OpenOptions{ExpectedSuite: Suite1, Key: key, ResolveSigner: resolve, AllowUnsigned: !fv.Signed})
			if err != nil {
				t.Fatal(err)
			}
			if len(pt) != fv.Size {
				t.Fatalf("plaintext size %d, want %d", len(pt), fv.Size)
			}
			if sum := sha256.Sum256(pt); hex.EncodeToString(sum[:]) != fv.PlaintextSHA {
				t.Fatal("plaintext differs")
			}
			if !bytes.Equal(pt, pattern(fv.Size)) {
				t.Fatal("plaintext is not the documented pattern")
			}
			if uint8(f.Header.Kind) != fv.Kind || f.Header.Epoch != fv.Epoch || f.Header.Created != fv.Created || f.Header.Version != fv.Version ||
				hex.EncodeToString(f.Header.MailboxID[:]) != fv.MailboxID || hex.EncodeToString(f.Header.FileID[:]) != fv.FileID ||
				hex.EncodeToString(f.Header.NoncePrefix[:]) != fv.NoncePrefix {
				t.Fatalf("header differs: %+v", f.Header)
			}
			if hex.EncodeToString(f.headerBytes) != fv.HeaderBytes {
				t.Fatal("header encoding differs")
			}
			if len(f.blocks) != fv.Blocks {
				t.Fatalf("%d blocks, want %d", len(f.blocks), fv.Blocks)
			}
			h := sha256.New()
			for _, b := range f.blocks {
				h.Write(b)
			}
			if hex.EncodeToString(h.Sum(nil)) != fv.BlockSHA256 {
				t.Fatal("block ciphertexts differ")
			}
			if (f.Trailer != nil) != fv.Signed {
				t.Fatal("signature presence")
			}
			if !bytes.Equal(f.Bytes(), data) {
				t.Fatal("re-serialization differs")
			}
			// Re-sealing with the recorded randomness reproduces the
			// deterministic parts (header and blocks); the recipient
			// entries differ because HPKE's ephemeral key is random.
			var sealOpts SealOptions
			sealOpts.Rand = bytes.NewReader(unhex(t, fv.Random))
			if fv.Signed {
				sealOpts.Signer = &Signer{Type: SignerIngest, Gen: v.SignerGen, Key: ed25519.NewKeyFromSeed(unhex(t, v.SignerSeed))}
				copy(sealOpts.Signer.ID[:], unhex(t, v.SignerID))
			}
			hdr := Header{Kind: Kind(fv.Kind), Epoch: fv.Epoch, Created: fv.Created, Version: fv.Version}
			copy(hdr.MailboxID[:], unhex(t, fv.MailboxID))
			copy(hdr.FileID[:], unhex(t, fv.FileID))
			again, err := Seal(hdr, []Recipient{{Type: key.Type, ID: key.ID, Gen: key.Gen, PublicKey: key.PrivateKey.PublicKey()}}, pt, &sealOpts)
			if err != nil {
				t.Fatal(err)
			}
			fa, _ := Parse(again)
			if !bytes.Equal(fa.headerBytes, f.headerBytes) {
				t.Fatal("re-sealed header differs")
			}
			for i := range f.blocks {
				if !bytes.Equal(fa.blocks[i], f.blocks[i]) {
					t.Fatalf("re-sealed block %d differs", i)
				}
			}
		})
	}
}
