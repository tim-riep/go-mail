// Command gen writes testdata/records.json: one canonical encoding for
// every record schema that phase 0 uses, built from fixed values. Run it
// from internal/rec:
//
//	go run ./testdata/gen
//
// The schemas live in the packages that own them (keys and envelope);
// this program only pulls them together so that the encoding rules of
// specification 3.6 are pinned for every record type in one place.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

type vector struct {
	Schema      string `json:"schema"`
	Description string `json:"description"`
	Hex         string `json:"hex"`
}

func fill(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()

	recipient := func(seed byte, gen uint32) *rec.Record {
		return rec.New(envelope.RecipientSchema).
			SetU8(1, 1).SetBytes(2, fill(16, seed)).SetU32(3, gen).SetBytes(4, fill(32, seed+0x10)).SetBytes(5, fill(48, seed+0x20))
	}
	records := []struct {
		desc string
		r    *rec.Record
	}{
		{"generation certificate, generation 1 (no revokes)", rec.New(keys.GenerationCertSchema).
			SetU32(1, 1).SetBytes(2, fill(32, 0x10)).SetBytes(3, fill(32, 0x30)).SetI64(4, 1761400000001).SetBytes(6, fill(64, 0x50))},
		{"generation certificate, generation 2 (revokes 1)", rec.New(keys.GenerationCertSchema).
			SetU32(1, 2).SetBytes(2, fill(32, 0x11)).SetBytes(3, fill(32, 0x31)).SetI64(4, 1761400000002).SetU32(5, 1).SetBytes(6, fill(64, 0x51))},
		{"platform certificate (ingest, generation 1, issued by identity generation 1, valid from 1761400000000)", rec.New(keys.PlatformCertSchema).
			SetU8(1, 2).SetU32(2, 1).SetBytes(3, fill(32, 0x60)).SetU32(4, 1).SetI64(5, 1761400000000).SetBytes(6, fill(64, 0x70))},
		{"platform succession to generation 2", rec.New(keys.PlatformSuccessionSchema).
			SetU32(1, 2).SetBytes(2, fill(32, 0x80)).SetI64(3, 1761400000000).SetBytes(4, fill(64, 0x90))},
		{"key store header (Argon2id 64 MiB, 3 passes, 4 threads)", rec.New(keys.KeystoreHeaderSchema).
			SetU8(1, 1).SetU8(2, 1).SetU32(3, 65536).SetU32(4, 3).SetU8(5, 4).SetBytes(6, fill(16, 0xa0)).SetBytes(7, fill(12, 0xb0))},
		{"key store content (dummy key bytes)", rec.New(keys.KeystoreContentSchema).
			SetU32(1, 3).SetBytes(2, fill(32, 0xc0)).SetBytes(3, fill(32, 0xd0))},
		{".gml header (kind mail, epoch 12)", rec.New(envelope.HeaderSchema).
			SetU8(1, 1).SetBytes(2, fill(16, 0x01)).SetU32(3, 12).SetBytes(4, fill(16, 0x21)).SetBytes(5, fill(7, 0x41)).SetU32(6, 65536).SetI64(7, 1761400000000)},
		{".gml recipient entry", recipient(0x02, 1)},
		{".gml recipient section with two entries", rec.New(envelope.RecipientsSchema).SetList(1, []*rec.Record{recipient(0x02, 1), recipient(0x03, 2)})},
		{".gml trailer (ingest signer)", rec.New(envelope.TrailerSchema).
			SetU8(1, 1).SetBytes(2, fill(16, 0xe0)).SetU32(3, 1).SetBytes(4, fill(64, 0xf0))},
		{".gml signed structure without extra", rec.New(envelope.SignedSchema).
			SetBytes(1, fill(32, 0x05)).SetU8(2, 1).SetBytes(3, fill(16, 0xe0)).SetU32(4, 1)},
		{".gml signed structure with extra", rec.New(envelope.SignedSchema).
			SetBytes(1, fill(32, 0x05)).SetU8(2, 2).SetBytes(3, fill(16, 0xe1)).SetU32(4, 7).SetBytes(5, []byte("extra"))},
	}
	var vectors []vector
	for _, r := range records {
		b, err := r.r.Encode()
		check(err)
		vectors = append(vectors, vector{Schema: r.r.Schema().Type, Description: r.desc, Hex: hex.EncodeToString(b)})
	}
	data, err := json.MarshalIndent(vectors, "", " ")
	check(err)
	path := filepath.Join(*out, "records.json")
	check(os.WriteFile(path, append(data, '\n'), 0o644))
	fmt.Println("wrote", path, len(vectors), "records")
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
