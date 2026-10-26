package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// inspectSchemas are the record types Inspect decodes. Records that only
// exist inside encrypted files are not listed: their plaintext is never
// in a file.
var inspectSchemas = func() map[string]*rec.Schema {
	m := map[string]*rec.Schema{}
	for _, s := range []*rec.Schema{
		store.UserSchema, store.MailboxSchema, store.EpochSchema, store.EpochNoteSchema, store.JournalSchema,
		store.AddressSchema, store.PlatformPinSchema, store.PlatformKeySchema,
		keys.GenerationCertSchema, keys.PlatformCertSchema, keys.PlatformSuccessionSchema,
	} {
		m[s.Type] = s
	}
	return m
}()

// secretFields are never printed.
var secretFields = map[string]map[string]bool{
	store.PlatformKeySchema.Type: {"seed": true},
}

// Inspect returns a JSON view of a record (3.6) or of the readable parts
// of a .gml file (3.1): header, recipients, trailer and the hash of the
// file before the trailer. Content is never decrypted; private key
// material is never shown. JSON is only a view; the binary form is what
// is verified and signed.
func Inspect(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte(envelope.Magic)) {
		return inspectGML(data)
	}
	i := bytes.IndexByte(data, 0)
	if i <= 0 {
		return nil, fmt.Errorf("client: neither a record nor a .gml file")
	}
	s, ok := inspectSchemas[string(data[:i])]
	if !ok {
		return nil, fmt.Errorf("client: unknown record type")
	}
	r, err := rec.Decode(s, data)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(recordJSON(r), "", "  ")
}

func recordJSON(r *rec.Record) map[string]any {
	s := r.Schema()
	out := map[string]any{"_type": s.Type}
	for _, f := range s.Fields {
		if !r.Has(f.Num) {
			continue
		}
		if secretFields[s.Type][f.Name] {
			out[f.Name] = "(geheim, nicht angezeigt)"
			continue
		}
		switch f.Kind {
		case rec.U8:
			out[f.Name] = r.U8(f.Num)
		case rec.U32:
			out[f.Name] = r.U32(f.Num)
		case rec.I64:
			out[f.Name] = r.I64(f.Num)
		case rec.Bytes:
			if f.Size == 16 {
				out[f.Name] = store.ID(r.Bytes(f.Num)).String()
			} else {
				out[f.Name] = hex.EncodeToString(r.Bytes(f.Num))
			}
		case rec.String:
			out[f.Name] = r.String(f.Num)
		case rec.List:
			var list []map[string]any
			for _, e := range r.List(f.Num) {
				list = append(list, recordJSON(e))
			}
			out[f.Name] = list
		}
	}
	return out
}

func inspectGML(data []byte) ([]byte, error) {
	f, err := envelope.Parse(data)
	if err != nil {
		return nil, err
	}
	h := f.Header
	out := map[string]any{
		"suite": f.Suite,
		"header": map[string]any{
			"kind": h.Kind.String(), "mailbox_id": store.ID(h.MailboxID).String(), "epoch": h.Epoch,
			"file_id": store.ID(h.FileID).String(), "nonce_prefix": hex.EncodeToString(h.NoncePrefix[:]),
			"chunk_size": h.ChunkSize, "created": h.Created,
		},
	}
	var rs []map[string]any
	for _, r := range f.Recipients {
		rs = append(rs, map[string]any{"type": r.Type, "id": store.ID(r.ID).String(), "gen": r.Gen})
	}
	out["recipients"] = rs
	fh := f.FileHash()
	out["hash_before_trailer"] = hex.EncodeToString(fh[:])
	if f.Trailer != nil {
		out["trailer"] = map[string]any{
			"signer_type": f.Trailer.Signer.Type, "signer_id": store.ID(f.Trailer.Signer.ID).String(),
			"signer_gen": f.Trailer.Signer.Gen, "sig": hex.EncodeToString(f.Trailer.Signature),
		}
	}
	return json.MarshalIndent(out, "", "  ")
}
