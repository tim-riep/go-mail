package ingest

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tim-riep/go-mail/internal/store"
)

// FuzzTerms feeds arbitrary headers to the header parser and the term
// list (5.3, 5.4). Nothing may panic; every term and every metadata field
// must be storable (valid UTF-8, NFC, no NUL, lower case for terms,
// within the limits).
func FuzzTerms(f *testing.F) {
	for _, s := range []string{
		"From: a <b@c.de>\r\nTo: x@y.de, z@w.de\r\nCc: q@r.de\r\nSubject: hi\r\nReferences: <a@b> <c@d>\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n",
		"From: =?UTF-8?Q?M=C3=BCller?= <m@x.de>\r\nSubject: =?ISO-8859-1?Q?Gr=FC=DFe?=\r\n\r\n",
		"Subject: \xff\xfe\x00\r\n\r\n",
		"From: \"क़\" <Á@B.DE>\r\n\r\n",
		"X: y\r\n z\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, h []byte) {
		terms, ok := Terms(h, now, "env@x.example", []string{"rcpt@y.example"})
		if !ok {
			return
		}
		if len(terms) > store.MaxTerms {
			t.Fatal("too many terms")
		}
		seen := map[string]bool{}
		for _, term := range terms {
			if term == "" || len(term) > store.MaxTermLen || !utf8.ValidString(term) || !norm.NFC.IsNormalString(term) || strings.ContainsRune(term, 0) {
				t.Fatalf("bad term %q", term)
			}
			if seen[term] {
				t.Fatalf("duplicate term %q", term)
			}
			seen[term] = true
		}
		fl, _ := parseHeader(h)
		m := &store.MailMeta{Version: 1, MailID: store.ID{1}, Folder: store.ID{2}, Recipients: []string{"a@b"},
			From: fl.from, To: fl.to, Cc: fl.cc, Subject: fl.subject, Date: fl.date, MessageID: fl.messageID, HeadersParsed: true}
		if _, err := m.Encode(); err != nil {
			t.Fatalf("metadata fields not storable: %v", err)
		}
	})
}
