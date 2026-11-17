package client

import "github.com/tim-riep/go-mail/internal/store"

// MetaCut is metaCut, for tests.
var MetaCut = metaCut

// ErrResign is errResign, for tests (TestWarnCause).
var ErrResign = errResign

// UnprocessedTerms returns the terms unprocessedTerms derives for mail id
// of mbx, its metadata checked as in List, for tests.
func (c *Client) UnprocessedTerms(mbx, id store.ID) ([]string, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	folder, err := c.findFolder(mbx, id)
	if err != nil {
		return nil, err
	}
	m, err := c.checkMeta(ch, folder, id)
	if err != nil {
		return nil, err
	}
	var un unreadable
	defer c.warnUnreadable(&un)
	return c.unprocessedTerms(ch, folder, m, &un)
}

// SetUnprocessedOpenHook sets the hook that runs each time
// unprocessedTerms opens a mail (see unprocessedOpenHook) until the test
// ends.
func SetUnprocessedOpenHook(t interface{ Cleanup(func()) }, f func(id store.ID)) {
	unprocessedOpenHook = f
	t.Cleanup(func() { unprocessedOpenHook = nil })
}
