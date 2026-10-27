package witness

import (
	"bytes"
	"testing"
)

// FuzzParseProof: no panic, and every accepted body formats back to the
// identical bytes.
func FuzzParseProof(f *testing.F) {
	f.Add([]byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseProof(b)
		if err != nil {
			return
		}
		if again := FormatProof(p); !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, formats as %q", b, again)
		}
	})
}

// FuzzDecodeWitnesses: no panic, and every accepted list encodes back
// to the identical bytes.
func FuzzDecodeWitnesses(f *testing.F) {
	f.Add([]byte("gomail/v1/rec/witnesses\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		w, err := DecodeWitnesses(b)
		if err != nil {
			return
		}
		again, err := w.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %v", err)
		}
	})
}
