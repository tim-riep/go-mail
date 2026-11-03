package client

import (
	"fmt"

	"github.com/tim-riep/go-mail/internal/store"
)

// MetaTerms is metaTerms, for tests.
var MetaTerms = metaTerms

// TermMark returns the search mark of term in epoch n of mbx (6.1), for
// tests.
func (c *Client) TermMark(mbx store.ID, n uint32, term string) ([32]byte, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return [32]byte{}, err
	}
	e, err := ch.usable(n)
	if err != nil {
		return [32]byte{}, err
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return [32]byte{}, err
	}
	return mark(k, term), nil
}

// Segments returns the accepted index segments of epoch n of mbx, for
// tests; rejected ones are warned about.
func (c *Client) Segments(mbx store.ID, n uint32) ([]*store.IndexSegment, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	e, err := ch.usable(n)
	if err != nil {
		return nil, err
	}
	run, err := c.readSegments(ch, e, false)
	if err != nil {
		return nil, err
	}
	out := make([]*store.IndexSegment, 0, len(run.segs))
	for _, s := range run.segs {
		out = append(out, s.seg)
	}
	return out, nil
}

// Device returns the device ID of the client directory (created on first
// use), for tests.
func (c *Client) Device() (store.ID, error) { return c.device() }

// SetFlagsHook sets the hook that runs between preparing and writing a
// new metadata version (see flagsHook) until the test ends.
func SetFlagsHook(t interface{ Cleanup(func()) }, f func()) {
	flagsHook = f
	t.Cleanup(func() { flagsHook = nil })
}

// SplitPostings splits postings of n marks with ids mail IDs each into
// segments as Index does and returns the number of postings per segment,
// for tests of the limits.
func SplitPostings(mbx store.ID, marks, ids int) [][]int {
	p := postings{}
	for i := 0; i < marks; i++ {
		var mk [32]byte
		mk[0], mk[1], mk[2] = byte(i>>16), byte(i>>8), byte(i)
		for j := 0; j < ids; j++ {
			var id store.ID
			id[0], id[1], id[2], id[15] = byte(j>>16), byte(j>>8), byte(j), 1
			p.add(mk, id)
		}
	}
	var out [][]int
	for _, seg := range p.segments(mbx, 1) {
		var counts []int
		for _, ps := range seg.Postings {
			counts = append(counts, len(ps.MailIDs))
		}
		if _, err := store.EncodeIndexSegment(seg); err != nil {
			return nil
		}
		out = append(out, counts)
	}
	return out
}

// SetMergeHook sets the hook that runs in mergeSegments right before the
// mailbox lock is taken (see mergeHook) until the test ends.
func SetMergeHook(t interface{ Cleanup(func()) }, f func()) {
	mergeHook = f
	t.Cleanup(func() { mergeHook = nil })
}

// SetSaveHook sets the hook that runs before every save of the state
// (see saveHook) until the test ends.
func SetSaveHook(t interface{ Cleanup(func()) }, f func(dirty bool) error) {
	saveHook = f
	t.Cleanup(func() { saveHook = nil })
}

// SetResignHook sets the hook that runs in resignSegment right before the
// mailbox lock is taken (see resignHook) until the test ends.
func SetResignHook(t interface{ Cleanup(func()) }, f func()) {
	resignHook = f
	t.Cleanup(func() { resignHook = nil })
}

// SetSegmentLimits sets the limits of one run of readSegments (see
// maxReadSegments, maxReadBytes) until the test ends.
func SetSegmentLimits(t interface{ Cleanup(func()) }, files int, bytes int64) {
	of, ob := maxReadSegments, maxReadBytes
	maxReadSegments, maxReadBytes = files, bytes
	t.Cleanup(func() { maxReadSegments, maxReadBytes = of, ob })
}

// SegmentMemoKey returns the key of the check record of the index
// segment data of device dev in epoch n (segmentMemo), for tests.
func SegmentMemoKey(n uint32, dev store.ID, data []byte) string { return segmentMemo(n, dev, data) }

// SetResignMetaHook sets the hook that runs in resignMeta before the new
// version is sealed (see resignMetaHook) until the test ends.
func SetResignMetaHook(t interface{ Cleanup(func()) }, f func()) {
	resignMetaHook = f
	t.Cleanup(func() { resignMetaHook = nil })
}

// SetLockHook sets the hook that runs in withMailboxLock right before the
// lock is taken (see lockHook) until the test ends.
func SetLockHook(t interface{ Cleanup(func()) }, f func(mbx store.ID)) {
	lockHook = f
	t.Cleanup(func() { lockHook = nil })
}

// WriteSegment writes one new index segment of epoch n of mbx with the
// postings of term for ids, signed by c, as Index does, and returns its
// reference, for tests that need different segments.
func (c *Client) WriteSegment(mbx store.ID, n uint32, term string, ids ...store.ID) (store.IndexSegmentRef, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return store.IndexSegmentRef{}, err
	}
	e, err := ch.usable(n)
	if err != nil {
		return store.IndexSegmentRef{}, err
	}
	k, err := c.keysFor(ch, e)
	if err != nil {
		return store.IndexSegmentRef{}, err
	}
	dev, err := c.device()
	if err != nil {
		return store.IndexSegmentRef{}, err
	}
	p := postings{}
	for _, id := range ids {
		p.add(mark(k, term), id)
	}
	w, err := c.writeSegments(ch, e, dev, p)
	if err != nil || len(w) != 1 {
		return store.IndexSegmentRef{}, fmt.Errorf("write segment: %d %v", len(w), err)
	}
	return w[0].ref, nil
}

// RecordChecked is recordChecked (the check record of file key noted in
// the state in memory, not saved), for tests.
func (c *Client) RecordChecked(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) bool {
	return c.recordChecked(mbx, key, data, signer, gen)
}

// Reissuing reports whether c works as in step 4 of DeviceLost or its
// continuation (see reissuing), for tests.
func (c *Client) Reissuing() bool { return c.reissuing }
