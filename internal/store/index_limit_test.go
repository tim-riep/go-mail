package store

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestListIndexSegmentsLimit (task 20b point 4): below and at
// MaxListedIndexSegments every segment is listed, sorted; above it the
// listing stops at one segment beyond the limit (len > limit tells that
// there are more), every segment listed exists, and the order is sorted.
// Other names, also between the segments, do not count.
func TestListIndexSegmentsLimit(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mbx, dev, dev2 := ID{9}, ID{3}, ID{1}
	dir := s.IndexDir(mbx, 1)
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	exists := map[IndexSegmentRef]bool{}
	add := func(r IndexSegmentRef) {
		t.Helper()
		if err := os.WriteFile(s.IndexSegmentFile(mbx, 1, r.Device, r.Seq), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		exists[r] = true
	}
	// Names that are not segments, many of them.
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(dir, tmpPrefix+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// fulltext.gml and a name of the right shape whose device is no ID.
	for _, name := range []string{"fulltext.gml", strings.Repeat("!", IDLen) + "-1.gml"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want int) {
		t.Helper()
		refs, err := s.ListIndexSegments(mbx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != want {
			t.Fatalf("%d segments in the directory: %d listed, want %d", len(exists), len(refs), want)
		}
		if !sort.SliceIsSorted(refs, func(i, j int) bool {
			if refs[i].Device != refs[j].Device {
				return string(refs[i].Device[:]) < string(refs[j].Device[:])
			}
			return refs[i].Seq < refs[j].Seq
		}) {
			t.Fatal("listing not sorted")
		}
		seen := map[IndexSegmentRef]bool{}
		for _, r := range refs {
			if !exists[r] || seen[r] {
				t.Fatalf("listed %v, which is not a segment or listed twice", r)
			}
			seen[r] = true
		}
	}
	// Below the limit: two devices, every segment.
	for i := range MaxListedIndexSegments - 1 {
		d := dev
		if i%2 == 1 {
			d = dev2
		}
		add(IndexSegmentRef{Device: d, Seq: uint64(i)})
	}
	check(MaxListedIndexSegments - 1)
	// At the limit: every segment.
	add(IndexSegmentRef{Device: dev, Seq: 1 << 40})
	check(MaxListedIndexSegments)
	// Above it: one beyond the limit, no matter how many more there are.
	add(IndexSegmentRef{Device: dev2, Seq: 1 << 40})
	check(MaxListedIndexSegments + 1)
	for i := range 2 * listIndexChunk {
		add(IndexSegmentRef{Device: dev, Seq: 1<<41 + uint64(i)})
	}
	check(MaxListedIndexSegments + 1)
}
