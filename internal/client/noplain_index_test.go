package client_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
)

// TestNoPlaintextIndex: neither the terms nor the subject of a mail
// appear in index/, anywhere else on disk (data and client directory), in
// warnings or in errors after indexing, searching and changing flags.
func TestNoPlaintextIndex(t *testing.T) {
	f := newFixture(t)
	const marker = "XQZMARKER-5e7d"
	lower := strings.ToLower(marker)
	msg := "From: " + marker + " <" + lower + "@sender.example>\r\nTo: a@example.org\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@sender.example>\r\n\r\nbody\r\n"
	f.send(t, lower+"@sender.example", msg)
	f.flush(t)
	f.send(t, lower+"@sender.example", msg) // stays a marker
	var warnings []string
	check := func(stage string) {
		t.Helper()
		warnings = append(warnings, f.env.Warnings.Take()...)
		for _, w := range warnings {
			if strings.Contains(strings.ToLower(w), lower) {
				t.Fatalf("%s: marker in a warning: %q", stage, w)
			}
		}
		filepath.Walk(f.env.Base, func(p string, fi os.FileInfo, err error) error {
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			b, _ := os.ReadFile(p)
			if bytes.Contains(bytes.ToLower(b), []byte(lower)) {
				t.Fatalf("%s: marker in %s", stage, p)
			}
			return nil
		})
	}
	c := f.u.Client
	q := "from:" + lower + "@sender.example"
	if got := search(t, c, f.mbx, q, ""); got != marker+","+marker {
		t.Fatalf("before indexing: %q", got)
	}
	check("after searching pending/")
	if n, err := c.Index(f.mbx); err != nil || n != 2 {
		t.Fatalf("index: %d: %v", n, err)
	}
	if segmentCount(t, f.env, f.mbx, 1) != 1 {
		t.Fatal("no segment")
	}
	check("after indexing")
	list, err := c.Search(f.mbx, q, client.SearchOptions{})
	if err != nil || len(list) != 2 {
		t.Fatal(err)
	}
	if _, err := c.SetFlags(f.mbx, list[0].ID, []string{"seen"}, nil); err != nil {
		t.Fatal(err)
	}
	// Rejections on the way produce warnings: a forged segment, a
	// replayed version.
	dev, _ := c.Device()
	data, _ := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, 1)
	data[len(data)-1] ^= 1
	f.env.Store.WriteIndexSegment(f.mbx, 1, dev, 9, data)
	if got := search(t, c, f.mbx, q, ""); got != marker+","+marker {
		t.Fatalf("after flags: %q", got)
	}
	for _, bad := range []string{"subject:" + marker, marker, "from:" + marker + "\x00"} {
		_, err := c.Search(f.mbx, bad, client.SearchOptions{})
		if err != nil && strings.Contains(strings.ToLower(err.Error()), lower) {
			t.Fatalf("marker in an error: %v", err)
		}
		if bad != "from:"+marker+"\x00" && !errors.Is(err, client.ErrQuery) {
			t.Fatalf("query accepted: %v", err)
		}
	}
	check("after searching and flags")
	if len(warnings) == 0 {
		t.Fatal("expected warnings for the forged segment")
	}
	// The state file holds no term either (checked by the walk above) and
	// the segment no readable mark of the term.
	mk, _ := c.TermMark(f.mbx, 1, q)
	raw, _ := f.env.Store.ReadIndexSegment(f.mbx, 1, dev, 1)
	if bytes.Contains(raw, mk[:]) {
		t.Fatal("mark in clear in the segment file")
	}
	_ = store.ID{}
}
