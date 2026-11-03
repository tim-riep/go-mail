package rec_test

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Tests of task 20f for PLAN 10.1 "Kodieren und Dekodieren ist für alle
// Datensätze byte-identisch". TestRecordVectors pins the phase 0 record
// types, store.FuzzDecodeRecords the typed decoders of store; these tests
// cover every schema of the module and check that the list is complete.

// allSchemas lists every record schema of the module (3.6), the element
// schemas of lists included.
var allSchemas = []*rec.Schema{
	keys.GenerationCertSchema,
	keys.PlatformCertSchema,
	keys.PlatformSuccessionSchema,
	keys.KeystoreHeaderSchema,
	keys.KeystoreContentSchema,
	envelope.HeaderSchema,
	envelope.RecipientSchema,
	envelope.RecipientsSchema,
	envelope.TrailerSchema,
	envelope.SignedSchema,
	store.UserSchema,
	store.WrapAcceptSchema,
	store.RecoveryPubSchema,
	store.MailboxSchema,
	store.FolderSchema,
	store.FoldersSchema,
	store.PostingSchema,
	store.IndexSegmentSchema,
	store.CheckpointSchema,
	store.EpochKeysSchema,
	store.RcptSchema,
	store.MailMetaSchema,
	store.MetaSignedSchema,
	store.TermSchema,
	store.PendingEntrySchema,
	store.PendingSchema,
	store.EpochNoteSchema,
	store.MoveSchema,
	store.JournalSchema,
	store.PlatformKeySchema,
	store.WitnessSchema,
	store.PlatformIdentitySchema,
	store.PlatformPinSchema,
	store.AddressSchema,
	store.MemberSchema,
	store.DiscardSchema,
	store.EpochSchema,
	translog.EntrySchema,
	translog.TreeSchema,
	witness.WitnessesSchema,
}

var schemaDef = regexp.MustCompile(`rec\.(MustSchema|NewSchema)\(\s*("[^"]*")?`)

// TestAllSchemasListed: allSchemas names every schema that the production
// code of the module defines (rec.MustSchema or rec.NewSchema outside
// tests and outside package rec), each once, so that
// TestAllSchemasRoundTrip cannot miss a record type added later.
func TestAllSchemasListed(t *testing.T) {
	listed := map[string]bool{}
	for _, s := range allSchemas {
		if listed[s.Type] {
			t.Errorf("schema %q listed twice", s.Type)
		}
		listed[s.Type] = true
	}
	defined := map[string]string{}
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || filepath.Dir(p) == filepath.Clean("../../internal/rec") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range schemaDef.FindAllSubmatch(src, -1) {
				if len(m[2]) == 0 {
					t.Errorf("%s: schema without a literal type string; list it by hand and adapt this test", p)
					continue
				}
				typ := strings.Trim(string(m[2]), `"`)
				if prev, ok := defined[typ]; ok {
					t.Errorf("type %q defined twice (%s, %s)", typ, prev, p)
				}
				defined[typ] = p
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(defined) < 30 {
		t.Fatalf("only %d schema definitions found; the scan is broken", len(defined))
	}
	for typ, p := range defined {
		if !listed[typ] {
			t.Errorf("schema %q (%s) is not in allSchemas", typ, p)
		}
	}
	for typ := range listed {
		if _, ok := defined[typ]; !ok {
			t.Errorf("schema %q in allSchemas has no definition in the production code", typ)
		}
	}
}

// variant selects how sample fills a record.
type variant int

const (
	required variant = iota // required fields only, smallest values
	full                    // every field, extreme integers, several list elements
)

// sample builds a valid record of s. Values depend on the field number so
// that fields of the same kind differ.
func sample(t *testing.T, s *rec.Schema, v variant, reverse bool) *rec.Record {
	t.Helper()
	fields := append([]rec.Field(nil), s.Fields...)
	if reverse {
		sort.Slice(fields, func(i, j int) bool { return fields[i].Num > fields[j].Num })
	}
	r := rec.New(s)
	for _, f := range fields {
		if v == required && !f.Required {
			continue
		}
		switch f.Kind {
		case rec.U8:
			if v == full {
				r.SetU8(f.Num, math.MaxUint8)
			} else {
				r.SetU8(f.Num, 0)
			}
		case rec.U32:
			if v == full {
				r.SetU32(f.Num, math.MaxUint32-uint32(f.Num))
			} else {
				r.SetU32(f.Num, 0)
			}
		case rec.I64:
			if v == full {
				r.SetI64(f.Num, math.MinInt64+int64(f.Num))
			} else {
				r.SetI64(f.Num, -1)
			}
		case rec.Bytes:
			n := f.Size
			if n == 0 {
				n = 1
				if v == full {
					n = min(f.MaxLen, 300)
				}
			}
			r.SetBytes(f.Num, bytes.Repeat([]byte{f.Num, 0}, n)[:n])
		case rec.String:
			str := "a"
			if v == full {
				str = "Grüße ✉ " + strings.Repeat("x", 40)
				for len(str) > f.MaxLen {
					// Cut at a rune boundary; the string stays NFC.
					str = string([]rune(str)[:len([]rune(str))-1])
				}
			}
			r.SetString(f.Num, str)
		case rec.List:
			n := 1
			if v == full {
				n = min(f.MaxCount, 3)
			}
			var l []*rec.Record
			for i := 0; i < n; i++ {
				l = append(l, sample(t, f.Elem, v, reverse))
			}
			r.SetList(f.Num, l)
		default:
			t.Fatalf("%s field %d: unknown kind %v", s.Type, f.Num, f.Kind)
		}
	}
	if err := r.Err(); err != nil {
		t.Fatalf("%s: %v", s.Type, err)
	}
	return r
}

// TestAllSchemasRoundTrip: for every schema of the module, a record with
// the required fields and one with every field encode, decode and encode
// again to exactly the same bytes; the encoding does not depend on the
// order in which fields were set; no other schema decodes it.
func TestAllSchemasRoundTrip(t *testing.T) {
	for _, s := range allSchemas {
		t.Run(s.Type, func(t *testing.T) {
			for _, v := range []variant{required, full} {
				enc, err := sample(t, s, v, false).Encode()
				if err != nil {
					t.Fatalf("variant %d: encode: %v", v, err)
				}
				if !bytes.HasPrefix(enc, s.Prefix()) {
					t.Fatalf("variant %d: encoding does not start with the type string and NUL", v)
				}
				rev, err := sample(t, s, v, true).Encode()
				if err != nil || !bytes.Equal(rev, enc) {
					t.Fatalf("variant %d: encoding depends on the order of the Set calls: %v", v, err)
				}
				dec, err := rec.Decode(s, enc)
				if err != nil {
					t.Fatalf("variant %d: decode: %v", v, err)
				}
				again, err := dec.Encode()
				if err != nil {
					t.Fatalf("variant %d: re-encode: %v", v, err)
				}
				if !bytes.Equal(again, enc) {
					t.Fatalf("variant %d: re-encoding differs", v)
				}
				for _, other := range allSchemas {
					if other.Type == s.Type {
						continue
					}
					if _, err := rec.Decode(other, enc); err == nil {
						t.Fatalf("variant %d: schema %q decodes a %q record", v, other.Type, s.Type)
					}
				}
			}
		})
	}
}

// TestTypedRoundTripOutsideStore: the typed decoders outside rec, keys,
// envelope and store (log entries of the four kinds a client checks,
// witnesses.rec) give back exactly the bytes they read.
func TestTypedRoundTripOutsideStore(t *testing.T) {
	key := func(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
	pub := func(b byte) ed25519.PublicKey { return key(b).Public().(ed25519.PublicKey) }

	// Log entries: an address assignment and a platform certificate.
	a := &store.AddressAssignment{Address: "info@example.org", MailboxID: store.ID{1, 2, 3}, ValidFrom: 1_800_000_000_000, AdminGen: 1}
	if err := a.Sign(key(1)); err != nil {
		t.Fatal(err)
	}
	addr, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.NewPlatformCert(key(2), 1, keys.RoleIngest, 2, pub(3), 1_800_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	certEnc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kind    translog.Kind
		content []byte
	}{
		"address":  {translog.KindAddress, addr},
		"platform": {translog.KindPlatform, certEnc},
	} {
		e, err := translog.NewEntry(c.kind, c.content)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		enc, err := e.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d, err := translog.DecodeEntry(enc, 7)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		again, err := d.Encode()
		if err != nil || !bytes.Equal(again, enc) {
			t.Fatalf("%s: re-encoding differs: %v", name, err)
		}
		if !bytes.Equal(d.Content, c.content) {
			t.Fatalf("%s: content differs", name)
		}
	}

	// witnesses.rec with three witnesses and a quorum of two.
	w := &witness.Witnesses{Min: 2, List: []witness.Key{{Name: "w1", Pub: pub(4)}, {Name: "w2", Pub: pub(5)}, {Name: "zeuge-3", Pub: pub(6)}}}
	enc, err := w.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := witness.DecodeWitnesses(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.Encode()
	if err != nil || !bytes.Equal(again, enc) {
		t.Fatalf("witnesses.rec: re-encoding differs: %v", err)
	}
}
