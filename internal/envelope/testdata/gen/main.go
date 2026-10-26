// Command gen writes the .gml test vectors of package envelope into the
// testdata directory. Run it from internal/envelope:
//
//	go run ./testdata/gen
//
// Keys, header fields and the randomness for nonce prefix and file key
// are fixed, so header and content blocks are reproducible. The files
// use the element framing of specification 1.1 (type byte, length,
// payload after the recipient section); the phase 0 files without type
// bytes are kept under testdata/phase0 as rejection cases. The HPKE
// encapsulation in the recipient section draws its ephemeral key from
// crypto/rand inside crypto/hpke and cannot be injected; the recipient
// section and the signature (which covers it) therefore differ between
// runs. Tests compare the deterministic parts and decrypt the rest.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tim-riep/go-mail/internal/envelope"
)

type fileVector struct {
	Name         string `json:"name"`
	File         string `json:"file"`
	Size         int    `json:"size"`
	Signed       bool   `json:"signed"`
	Kind         uint8  `json:"kind"`
	MailboxID    string `json:"mailbox_id"`
	Epoch        uint32 `json:"epoch"`
	FileID       string `json:"file_id"`
	Created      int64  `json:"created"`
	Random       string `json:"random"`
	PlaintextSHA string `json:"plaintext_sha256"`
	NoncePrefix  string `json:"nonce_prefix"`
	Blocks       int    `json:"blocks"`
	BlockSHA256  string `json:"blocks_sha256"`
	HeaderBytes  string `json:"header"`
}

// pattern must match the function of the same name in the tests.
func pattern(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i += 32 {
		block := sha256.Sum256(binary.BigEndian.AppendUint32([]byte("envelope pattern"), uint32(i/32)))
		copy(out[i:], block[:])
	}
	return out
}

func id16(label string) (out [16]byte) {
	s := sha256.Sum256([]byte("envelope vector id " + label))
	copy(out[:], s[:16])
	return
}

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()

	recipientSeed := sha256.Sum256([]byte("envelope vector recipient key"))
	priv, err := ecdh.X25519().NewPrivateKey(recipientSeed[:])
	check(err)
	signerSeed := sha256.Sum256([]byte("envelope vector signer key"))
	signerKey := ed25519.NewKeyFromSeed(signerSeed[:])

	var vectors struct {
		Comment       string       `json:"comment"`
		RecipientPriv string       `json:"recipient_priv"`
		RecipientID   string       `json:"recipient_id"`
		RecipientGen  uint32       `json:"recipient_gen"`
		SignerSeed    string       `json:"signer_seed"`
		SignerID      string       `json:"signer_id"`
		SignerGen     uint32       `json:"signer_gen"`
		Files         []fileVector `json:"files"`
	}
	vectors.Comment = "Complete .gml files with fixed keys and fixed randomness (nonce prefix, then file key). Plaintext is pattern(size): SHA-256(\"envelope pattern\" || uint32 block index) per 32 bytes. Recipient entries and signatures are not reproducible because crypto/hpke draws ephemeral keys from crypto/rand."
	vectors.RecipientPriv = hex.EncodeToString(priv.Bytes())
	epochID := id16("epoch")
	vectors.RecipientID = hex.EncodeToString(epochID[:])
	vectors.RecipientGen = 1
	vectors.SignerSeed = hex.EncodeToString(signerSeed[:])
	signerID := id16("ingest")
	vectors.SignerID = hex.EncodeToString(signerID[:])
	vectors.SignerGen = 1

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one-byte", 1},
		{"one-block", envelope.ChunkSize},
		{"two-blocks", 2 * envelope.ChunkSize},
		{"two-blocks-plus-one", 2*envelope.ChunkSize + 1},
	}
	for i, s := range sizes {
		for _, signed := range []bool{false, true} {
			name := s.name
			kind := envelope.KindMail
			if signed {
				name += "-signed"
				kind = envelope.KindMeta
			}
			random := make([]byte, 7+32)
			for j := range random {
				random[j] = byte(i*37 + j*11 + 3)
				if signed {
					random[j] ^= 0x80
				}
			}
			hdr := envelope.Header{Kind: kind, MailboxID: id16("mailbox"), Epoch: 12, FileID: id16(name), Created: 1761400000000 + int64(i)}
			opts := &envelope.SealOptions{Rand: bytes.NewReader(random)}
			if signed {
				opts.Signer = &envelope.Signer{Type: envelope.SignerIngest, ID: signerID, Gen: 1, Key: signerKey}
			}
			pt := pattern(s.size)
			data, err := envelope.Seal(hdr, []envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: epochID, Gen: 1, PublicKey: priv.PublicKey()}}, pt, opts)
			check(err)
			f, err := envelope.Parse(data)
			check(err)
			fileName := name + ".gml"
			check(os.WriteFile(filepath.Join(*out, fileName), data, 0o644))
			ptSum := sha256.Sum256(pt)
			bh := sha256.New()
			nblocks := 0
			for _, b := range blocksOf(data, f) {
				bh.Write(b)
				nblocks++
			}
			vectors.Files = append(vectors.Files, fileVector{
				Name: name, File: fileName, Size: s.size, Signed: signed, Kind: uint8(kind),
				MailboxID: hex.EncodeToString(hdr.MailboxID[:]), Epoch: hdr.Epoch, FileID: hex.EncodeToString(hdr.FileID[:]),
				Created: hdr.Created, Random: hex.EncodeToString(random), PlaintextSHA: hex.EncodeToString(ptSum[:]),
				NoncePrefix: hex.EncodeToString(f.Header.NoncePrefix[:]), Blocks: nblocks, BlockSHA256: hex.EncodeToString(bh.Sum(nil)),
				HeaderBytes: hex.EncodeToString(headerOf(data)),
			})
			fmt.Println("wrote", fileName, len(data), "bytes")
		}
	}
	b, err := json.MarshalIndent(vectors, "", " ")
	check(err)
	check(os.WriteFile(filepath.Join(*out, "vectors.json"), append(b, '\n'), 0o644))
	fmt.Println("wrote vectors.json")
}

// headerOf extracts the header record from a file by its length field.
func headerOf(data []byte) []byte {
	n := binary.BigEndian.Uint32(data[6:10])
	return data[10 : 10+n]
}

// blocksOf walks the element sequence after the recipient section by
// its type bytes (ElemBlock* ElemLastBlock ElemTrailer?) and returns the
// block payloads.
func blocksOf(data []byte, f *envelope.File) [][]byte {
	pos := 10 + int(binary.BigEndian.Uint32(data[6:10]))
	pos += 4 + int(binary.BigEndian.Uint32(data[pos:]))
	var blocks [][]byte
	for pos < len(data) {
		typ := data[pos]
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		payload := data[pos+5 : pos+5+n]
		if typ == envelope.ElemBlock || typ == envelope.ElemLastBlock {
			blocks = append(blocks, payload)
		}
		pos += 5 + n
	}
	return blocks
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
