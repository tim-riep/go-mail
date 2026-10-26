package rec

import (
	"bytes"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// FuzzDecode checks the decoder on arbitrary input: it must never panic,
// never allocate beyond the schema's limits (enforced by construction and
// by the size check), and whatever it accepts must re-encode to exactly
// the input bytes.
func FuzzDecode(f *testing.F) {
	f.Add(mustEncode(f, fullRecord(f)))
	f.Add(minimal())
	f.Add([]byte("gomail/test/all\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Decode(testSchema, data)
		if err != nil {
			if r != nil {
				t.Fatal("record returned together with an error")
			}
			return
		}
		enc, err := r.Encode()
		if err != nil {
			t.Fatalf("decoded record does not encode: %v", err)
		}
		if !bytes.Equal(enc, data) {
			t.Fatalf("re-encoding differs:\n in %x\nout %x", data, enc)
		}
		// Decoding the re-encoding must give the same record again.
		r2, err := Decode(testSchema, enc)
		if err != nil {
			t.Fatal(err)
		}
		enc2, _ := r2.Encode()
		if !bytes.Equal(enc, enc2) {
			t.Fatal("second round trip differs")
		}
	})
}

// FuzzIsNFC checks that the NFC check never panics and agrees with a full
// normalization of its input: a valid UTF-8 string is accepted if and
// only if normalizing it with x/text changes nothing, and invalid UTF-8
// is never accepted.
func FuzzIsNFC(f *testing.F) {
	for _, s := range []string{"", "abc", rs('e', 0x0301), rs(0x00e9), rs(0x1100, 0x1161), rs(0xac00, 0x11a8),
		rs('q', 0x0323, 0x0301), rs(0x1e0b, 0x0323), rs(0x0f71, 0x0f72, 0x0f74), "\xff", "a\xffb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := isNFC(s)
		if !validUTF8(s) {
			if got {
				t.Fatal("invalid UTF-8 accepted")
			}
			return
		}
		want := norm.NFC.String(s) == s
		if got != want {
			t.Fatalf("isNFC(%+q) = %v, normalization says %v", s, got, want)
		}
	})
}
