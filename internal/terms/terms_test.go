package terms

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var received = time.Date(2026, 10, 25, 23, 30, 0, 0, time.FixedZone("x", 2*3600))

func TestList(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Mail
		want string
	}{
		{"all kinds", Mail{FromAddr: "Rechnung@Lieferant.DE", EnvelopeFrom: "bounce@x.example", EnvelopeTo: []string{"Info@BrownBear.de"},
			HeaderTo: []string{"info@brownbear.de", "Cc@Other.example"}, Received: received, Attachment: true, Thread: "<Root@X>"},
			"from:rechnung@lieferant.de fromdomain:lieferant.de day:2026-10-25 month:2026-10 has:attachment thread:<root@x> to:info@brownbear.de to:cc@other.example"},
		{"envelope sender stands in", Mail{EnvelopeFrom: "Sender@S.example", Received: received},
			"from:sender@s.example fromdomain:s.example day:2026-10-25 month:2026-10"},
		{"no sender", Mail{Received: received, EnvelopeTo: []string{"a@example.org"}},
			"day:2026-10-25 month:2026-10 to:a@example.org"},
		{"address without domain", Mail{FromAddr: "local@", Received: received},
			"from:local@ day:2026-10-25 month:2026-10"},
		{"address without at", Mail{FromAddr: "nobody", Received: received},
			"from:nobody day:2026-10-25 month:2026-10"},
		{"unicode", Mail{FromAddr: "ÄRGER@Bücher.example", Received: received, Thread: "<Á@x>"},
			"from:ärger@bücher.example fromdomain:bücher.example day:2026-10-25 month:2026-10 thread:<á@x>"},
		{"control characters", Mail{FromAddr: "a\x00b@x.example", Received: received},
			"from:a b@x.example fromdomain:x.example day:2026-10-25 month:2026-10"},
	} {
		if got := strings.Join(List(&tc.in), " "); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Recipients come last and are cut first at MaxTerms; every term is
// normalized and at most MaxTermLen bytes.
func TestListLimits(t *testing.T) {
	var to []string
	for i := 0; i < 2*MaxTerms; i++ {
		to = append(to, strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)+"@d.de")
	}
	got := List(&Mail{FromAddr: "a@b.c", EnvelopeTo: to[:3], HeaderTo: to, Received: received, Thread: "<m@x>"})
	if len(got) != MaxTerms || got[0] != "from:a@b.c" || got[4] != "thread:<m@x>" || got[5] != "to:"+to[0] {
		t.Fatalf("%d terms: %q", len(got), got[:6])
	}
	long := List(&Mail{FromAddr: strings.Repeat("é", MaxTermLen) + "@x.example", Received: received})
	for _, term := range long {
		if term == "" || len(term) > MaxTermLen || !utf8.ValidString(term) || !norm.NFC.IsNormalString(term) {
			t.Fatalf("term of %d bytes", len(term))
		}
	}
}

func TestQuery(t *testing.T) {
	for q, want := range map[string]string{
		"  From:Rechnung@Lieferant.DE ": "from:rechnung@lieferant.de",
		"fromdomain:Lieferant.de":       "fromdomain:lieferant.de",
		"TO:info@x":                     "to:info@x",
		"day:2026-10-25":                "day:2026-10-25",
		"month:2026-10":                 "month:2026-10",
		"thread:<A@B>":                  "thread:<a@b>",
		"HAS:ATTACHMENT":                "has:attachment",
	} {
		if got, ok := Query(q); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", q, got, ok, want)
		}
	}
	for _, q := range []string{"", "from:", "from:   ", "subject:x", "has:attachments", "plain words", "to"} {
		if got, ok := Query(q); ok || got != "" {
			t.Errorf("%q accepted: %q", q, got)
		}
	}
}

func TestFirstMsgID(t *testing.T) {
	for in, want := range map[string]string{
		"<abc":          "",
		"none":          "",
		"":              "",
		"x <a@b> <c@d>": "<a@b>",
		"<>":            "<>",
	} {
		if got := FirstMsgID(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// TestThreadRoot: References first, then In-Reply-To, then Message-ID;
// a value without a "<...>" token does not count.
func TestThreadRoot(t *testing.T) {
	for _, c := range []struct{ refs, reply, id, want string }{
		{"<r1@x> <r2@x>", "<p@x>", "<m@x>", "<r1@x>"},
		{"", "<p@x> <q@x>", "<m@x>", "<p@x>"},
		{"none", "", "<m@x>", "<m@x>"},
		{"", "broken <p@x", "<m@x>", "<m@x>"},
		{"", "", "", ""},
		{"", "", "no id", ""},
	} {
		if got := ThreadRoot(c.refs, c.reply, c.id); got != c.want {
			t.Errorf("%q %q %q: %q, want %q", c.refs, c.reply, c.id, got, c.want)
		}
	}
}

// TestHasAttachment: only multipart/mixed at the top level, case and
// parameters do not matter, a value that does not parse is none.
func TestHasAttachment(t *testing.T) {
	for in, want := range map[string]bool{
		"multipart/mixed; boundary=x":   true,
		"Multipart/Mixed":               true,
		"multipart/mixed":               true,
		"multipart/alternative; b=x":    false,
		"text/plain":                    false,
		"":                              false,
		"multipart/mixed; boundary=\"x": false,
		"multipart/mixedx":              false,
	} {
		if got := HasAttachment(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("ÁB"); got != "áb" {
		t.Fatalf("%q", got)
	}
	if got := Normalize(strings.Repeat("x", MaxTermLen+10)); len(got) != MaxTermLen {
		t.Fatalf("%d bytes", len(got))
	}
}
