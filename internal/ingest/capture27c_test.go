package ingest

import (
	"bytes"
	"testing"

	"github.com/tim-riep/go-mail/internal/terms"
)

// TestCaptureMatchesHeaderOf: the header the server captures from the
// received stream, in pieces of any size, is the header terms.HeaderOf
// takes from the whole content, with which a client evaluates a mail
// marked unprocessed (task 27, Nr. 47): the same bytes, and either both
// or neither.
func TestCaptureMatchesHeaderOf(t *testing.T) {
	// filled returns n bytes that end in the first empty line, then rest.
	filled := func(n int, rest string) []byte {
		b := bytes.Repeat([]byte("X"), n)
		copy(b[n-4:], "\r\n\r\n")
		return append(b, rest...)
	}
	inputs := map[string][]byte{
		"plain":            []byte("Received: x\r\nSubject: a\r\n\r\nbody\r\n\r\nmore\r\n"),
		"no end":           []byte("Subject: a\r\nX: b\r\n"),
		"empty header":     []byte("\r\n\r\nbody"),
		"bare LF":          []byte("Subject: a\n\nbody\r\n"),
		"ends at limit":    filled(MaxHeaderBytes, "body\r\n"),
		"one beyond limit": filled(MaxHeaderBytes+1, "body\r\n"),
		"across the limit": filled(MaxHeaderBytes+2, ""),
		"limit, no end":    bytes.Repeat([]byte("Y"), MaxHeaderBytes+10),
	}
	ends := 0
	for name, in := range inputs {
		want, ok := terms.HeaderOf(in)
		if ok {
			ends++
		}
		for _, size := range []int{1, 3, 4096, 65536, len(in)} {
			if size == 1 && len(in) > 1<<16 {
				continue
			}
			d := &delivery{}
			for off := 0; off < len(in) && !d.headerDone; off += size {
				d.captureHeader(in[off:min(off+size, len(in))])
			}
			if d.headerOK != ok || ok && !bytes.Equal(d.header.Bytes(), want) {
				t.Fatalf("%s, pieces of %d: server %v (%d bytes), HeaderOf %v (%d bytes)", name, size, d.headerOK, d.header.Len(), ok, len(want))
			}
		}
	}
	if ends != 3 {
		t.Fatalf("%d inputs with a header, want 3", ends)
	}
}
