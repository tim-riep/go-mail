package translog

import (
	"bytes"
	"testing"
)

// FuzzParseHeadText: no panic, and every accepted text formats back to
// the identical bytes (one text per head).
func FuzzParseHeadText(f *testing.F) {
	text, _ := testHead().Text()
	f.Add(text)
	f.Add([]byte("o\n1\nAAAA\ntime 0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeadText(b)
		if err != nil {
			return
		}
		again, err := h.Text()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %q, formats as %q (%v)", b, again, err)
		}
	})
}

// FuzzDecodeEntry: no panic, and every accepted entry encodes back to
// the identical bytes.
func FuzzDecodeEntry(f *testing.F) {
	f.Add([]byte("gomail/v1/rec/log-entry\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEntry(b, 0)
		if err != nil {
			return
		}
		again, err := e.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %v", err)
		}
	})
}
