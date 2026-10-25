package rec_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
)

// phase0Schemas lists every record schema used in phase 0.
var phase0Schemas = []*rec.Schema{
	keys.GenerationCertSchema,
	keys.PlatformCertSchema,
	keys.IdentitySuccessionSchema,
	keys.KeystoreHeaderSchema,
	keys.KeystoreContentSchema,
	envelope.HeaderSchema,
	envelope.RecipientSchema,
	envelope.RecipientsSchema,
	envelope.TrailerSchema,
	envelope.SignedSchema,
}

// TestRecordVectors decodes the pinned encoding of every phase 0 record
// type with its schema, re-encodes it byte-identically, and checks that
// no other schema accepts it.
func TestRecordVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Schema, Description, Hex string }
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	byType := map[string]*rec.Schema{}
	for _, s := range phase0Schemas {
		byType[s.Type] = s
	}
	covered := map[string]bool{}
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			s := byType[v.Schema]
			if s == nil {
				t.Fatalf("unknown schema %q", v.Schema)
			}
			covered[v.Schema] = true
			data, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(data, s.Prefix()) {
				t.Fatal("encoding does not start with the type string and NUL")
			}
			r, err := rec.Decode(s, data)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := r.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(enc, data) {
				t.Fatal("re-encoding differs")
			}
			for _, other := range phase0Schemas {
				if other == s {
					continue
				}
				if _, err := rec.Decode(other, data); err == nil {
					t.Fatalf("schema %q accepted a %q record", other.Type, s.Type)
				}
			}
		})
	}
	for _, s := range phase0Schemas {
		if !covered[s.Type] {
			t.Errorf("no vector for schema %q", s.Type)
		}
	}
}
