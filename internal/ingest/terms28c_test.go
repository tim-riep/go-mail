package ingest

import (
	"net/mail"
	"slices"
	"testing"

	"github.com/tim-riep/go-mail/internal/testenv"
)

// TestTermsAddressesFromRawHeader: the server takes the addresses for
// from: and to: from the header as received, not from the values it
// decodes for the metadata (task 28, Nr. 107; DECISIONS D91 Nachtrag
// 27 C). A display name in an encoded word whose text holds a comma
// parses as one address in the raw value, but its decoded value no longer
// parses as an address list: decoding first would lose from: and to:.
func TestTermsAddressesFromRawHeader(t *testing.T) {
	h := []byte("From: =?UTF-8?Q?Doe=2C_John?= <John@X.example>\r\n" +
		"To: =?UTF-8?Q?M=C3=BCller=2C_Hans?= <hans@a.example>, b@b.example\r\n" +
		"Cc: =?UTF-8?B?THVkd2lnLCBDYXJs?= <carl@c.example>\r\n" +
		"Subject: s\r\nMessage-ID: <m@x.example>\r\n\r\nbody\r\n")
	f, ok := parseHeader(h)
	if !ok {
		t.Fatal("header not evaluated")
	}
	// The metadata keep the decoded values, with the comma.
	if f.from != "Doe, John <John@X.example>" || f.to != "Müller, Hans <hans@a.example>, b@b.example" || f.cc != "Ludwig, Carl <carl@c.example>" {
		t.Fatalf("decoded values %q %q %q", f.from, f.to, f.cc)
	}
	// Decoded, the values are no address (list) any more.
	if _, err := mail.ParseAddress(f.from); err == nil {
		t.Fatal("decoded From parses: the test would not tell raw from decoded")
	}
	for _, v := range []string{f.to, f.cc} {
		if _, err := mail.ParseAddressList(v); err == nil {
			t.Fatalf("decoded %q parses: the test would not tell raw from decoded", v)
		}
	}
	list, ok := Terms(h, testenv.Start, "env@e.example", []string{"rcpt@r.example"})
	if !ok {
		t.Fatal("header not evaluated")
	}
	for _, want := range []string{"from:john@x.example", "fromdomain:x.example", "to:hans@a.example", "to:b@b.example", "to:carl@c.example", "to:rcpt@r.example"} {
		if !slices.Contains(list, want) {
			t.Errorf("term %q missing in %q", want, list)
		}
	}
	for _, not := range []string{"from:env@e.example", "fromdomain:e.example"} {
		if slices.Contains(list, not) {
			t.Errorf("term %q: From taken from the envelope", not)
		}
	}
}
