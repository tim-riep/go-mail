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
//
// Because of that, an existing file is kept byte for byte when it still
// opens with the vector keys (signature included) and its header and
// block ciphertexts equal those of a fresh seal; only files whose
// deterministic parts change are rewritten. Since specification 1.4 the
// signed files (kind meta) carry header field 8 version; the files of
// version 1.2 without it are kept under testdata/v12 as rejection cases.
// The unsigned files (kind mail) have no field 8 and stay unchanged.
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
	Version      uint32 `json:"version"`
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
	vectors.Comment = "Complete .gml files with fixed keys and fixed randomness (nonce prefix, then file key). Plaintext is pattern(size): SHA-256(\"envelope pattern\" || uint32 block index) per 32 bytes. Recipient entries and signatures are not reproducible because crypto/hpke draws ephemeral keys from crypto/rand. version is header field 8 (specification 1.4): set for kind meta, 0 meaning absent for kind mail."
	vectors.RecipientPriv = hex.EncodeToString(priv.Bytes())
	epochID := id16("epoch")
	vectors.RecipientID = hex.EncodeToString(epochID[:])
	vectors.RecipientGen = 1
	vectors.SignerSeed = hex.EncodeToString(signerSeed[:])
	signerID := id16("ingest")
	vectors.SignerID = hex.EncodeToString(signerID[:])
	vectors.SignerGen = 1

	// version is header field 8 of the signed (meta) file of each size.
	// The values cover 1, small counters, every byte position and the
	// maximum.
	sizes := []struct {
		name    string
		size    int
		version uint32
	}{
		{"empty", 0, 1},
		{"one-byte", 1, 2},
		{"one-block", envelope.ChunkSize, 3},
		{"two-blocks", 2 * envelope.ChunkSize, 0x01020304},
		{"two-blocks-plus-one", 2*envelope.ChunkSize + 1, 0xffffffff},
	}
	recipientKey := envelope.RecipientKey{Type: envelope.RecipientEpochContent, ID: epochID, Gen: 1, PrivateKey: priv}
	resolve := func(ref envelope.SignerRef) (ed25519.PublicKey, error) {
		if ref.Type == envelope.SignerIngest && ref.ID == signerID && ref.Gen == 1 {
			return signerKey.Public().(ed25519.PublicKey), nil
		}
		return nil, fmt.Errorf("unknown signer")
	}
	for i, s := range sizes {
		for _, signed := range []bool{false, true} {
			name := s.name
			kind := envelope.KindMail
			var version uint32
			if signed {
				name += "-signed"
				kind = envelope.KindMeta
				version = s.version
			}
			random := make([]byte, 7+32)
			for j := range random {
				random[j] = byte(i*37 + j*11 + 3)
				if signed {
					random[j] ^= 0x80
				}
			}
			hdr := envelope.Header{Kind: kind, MailboxID: id16("mailbox"), Epoch: 12, FileID: id16(name), Created: 1761400000000 + int64(i), Version: version}
			opts := &envelope.SealOptions{Rand: bytes.NewReader(random)}
			if signed {
				opts.Signer = &envelope.Signer{Type: envelope.SignerIngest, ID: signerID, Gen: 1, Key: signerKey}
			}
			pt := pattern(s.size)
			data, err := envelope.Seal(hdr, []envelope.Recipient{{Type: envelope.RecipientEpochContent, ID: epochID, Gen: 1, PublicKey: priv.PublicKey()}}, pt, opts)
			check(err)
			fileName := name + ".gml"
			path := filepath.Join(*out, fileName)
			if old, err := os.ReadFile(path); err == nil && sameVector(old, data, envelope.OpenOptions{ExpectedSuite: envelope.Suite1, Key: recipientKey, ResolveSigner: resolve, AllowUnsigned: !signed}) {
				data = old
				fmt.Println("kept", fileName, len(data), "bytes")
			} else {
				check(os.WriteFile(path, data, 0o644))
				fmt.Println("wrote", fileName, len(data), "bytes")
			}
			f, err := envelope.Parse(data)
			check(err)
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
				Created: hdr.Created, Version: f.Header.Version, Random: hex.EncodeToString(random), PlaintextSHA: hex.EncodeToString(ptSum[:]),
				NoncePrefix: hex.EncodeToString(f.Header.NoncePrefix[:]), Blocks: nblocks, BlockSHA256: hex.EncodeToString(bh.Sum(nil)),
				HeaderBytes: hex.EncodeToString(headerOf(data)),
			})
		}
	}
	b, err := json.MarshalIndent(vectors, "", " ")
	check(err)
	check(os.WriteFile(filepath.Join(*out, "vectors.json"), append(b, '\n'), 0o644))
	fmt.Println("wrote vectors.json")
}

// sameVector reports whether the existing file old is still a valid
// vector for the freshly sealed file fresh: it opens with the vector keys
// (and signature, if any) and has the same preamble, header and block
// ciphertexts. Only the recipient section and the trailer may differ;
// they are not reproducible.
func sameVector(old, fresh []byte, opts envelope.OpenOptions) bool {
	fo, _, err := envelope.Open(old, opts)
	if err != nil {
		return false
	}
	fn, err := envelope.Parse(fresh)
	if err != nil || len(old) < 6 || !bytes.Equal(old[:6], fresh[:6]) || !bytes.Equal(headerOf(old), headerOf(fresh)) {
		return false
	}
	ob, nb := blocksOf(old, fo), blocksOf(fresh, fn)
	if len(ob) != len(nb) {
		return false
	}
	for i := range ob {
		if !bytes.Equal(ob[i], nb[i]) {
			return false
		}
	}
	return true
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
