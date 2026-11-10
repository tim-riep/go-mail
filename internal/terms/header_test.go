package terms

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// TestParseHeaderLimits: at most MaxHeaderFields fields and
// MaxHeaderBytes bytes; folded lines do not count as fields.
func TestParseHeaderLimits(t *testing.T) {
	fields := func(n int) []byte {
		return []byte("To: a@x.example,\r\n b@x.example\r\n" + strings.Repeat("X-A: b\r\n", n-1) + "\r\n")
	}
	if _, ok := ParseHeader(fields(MaxHeaderFields)); !ok {
		t.Fatal("500 fields refused")
	}
	if _, ok := ParseHeader(fields(MaxHeaderFields + 1)); ok {
		t.Fatal("501 fields evaluated")
	}
	big := []byte("Subject: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\n")
	if _, ok := ParseHeader(big); ok {
		t.Fatal("header beyond MaxHeaderBytes evaluated")
	}
	if _, ok := ParseHeader(nil); ok {
		t.Fatal("empty header evaluated")
	}
	if _, ok := ParseHeader([]byte("no colon\r\n\r\n")); ok {
		t.Fatal("malformed header evaluated")
	}
}

// TestAddresses: the addresses of From, To and Cc as received, encoded
// words in display names included; a value that does not parse adds
// none.
func TestAddresses(t *testing.T) {
	for _, tc := range []struct {
		header string
		from   string
		to     []string
	}{
		{"From: =?utf-8?q?M=C3=BCller=2C_Hans?= <h@x.de>\r\nTo: =?utf-8?q?Doe=2C_John?= <j@x.example>, k@y.example\r\nCc: C <c@z.example>\r\n\r\n",
			"h@x.de", []string{"j@x.example", "k@y.example", "c@z.example"}},
		{"From: no address here\r\nTo: undisclosed-recipients:;\r\nCc: broken <<\r\n\r\n", "", nil},
		{"From: a@x.example, b@x.example\r\nTo: t@x.example\r\n\r\n", "", []string{"t@x.example"}},
	} {
		hd, ok := ParseHeader([]byte(tc.header))
		if !ok {
			t.Fatalf("%q not evaluated", tc.header)
		}
		from, to := Addresses(hd)
		if from != tc.from || !reflect.DeepEqual(to, tc.to) {
			t.Fatalf("%q: %q %q", tc.header, from, to)
		}
	}
}

// TestHeaderOfLimit: HeaderOf finds the end of the header only within the
// first MaxHeaderBytes bytes, as the server's capture does: a header that
// ends there is returned up to and including its empty line, one whose
// empty line ends a byte later, or is missing, is not.
func TestHeaderOfLimit(t *testing.T) {
	// filled returns n bytes that end in the first empty line, then a
	// body.
	filled := func(n int) []byte {
		b := bytes.Repeat([]byte("X"), n)
		copy(b[n-4:], "\r\n\r\n")
		return append(b, "body\r\n\r\nmore\r\n"...)
	}
	h, ok := HeaderOf(filled(MaxHeaderBytes))
	if !ok || len(h) != MaxHeaderBytes || !bytes.HasSuffix(h, []byte("\r\n\r\n")) {
		t.Fatalf("header of MaxHeaderBytes bytes: %v, %d bytes", ok, len(h))
	}
	for _, in := range [][]byte{filled(MaxHeaderBytes + 1), filled(MaxHeaderBytes + 3), bytes.Repeat([]byte("Y"), MaxHeaderBytes+10)} {
		if h, ok := HeaderOf(in); ok {
			t.Fatalf("header beyond MaxHeaderBytes taken: %d bytes", len(h))
		}
	}
	if h, ok := HeaderOf([]byte("Subject: a\r\n\r\nbody\r\n\r\n")); !ok || string(h) != "Subject: a\r\n\r\n" {
		t.Fatalf("short header: %v %q", ok, h)
	}
}
