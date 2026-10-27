package client

import "github.com/tim-riep/go-mail/internal/store"

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
	segs, err := c.readSegments(ch, e)
	if err != nil {
		return nil, err
	}
	out := make([]*store.IndexSegment, 0, len(segs))
	for _, s := range segs {
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
