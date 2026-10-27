package client

import "github.com/tim-riep/go-mail/internal/store"

// FoldersOfEpoch opens folders.gml of epoch n of the verified chain, for
// tests: the folders of a discarded epoch are never read.
func (c *Client) FoldersOfEpoch(mbx store.ID, n uint32) (*store.FolderList, error) {
	ch, err := c.verifyChain(mbx)
	if err != nil {
		return nil, err
	}
	l, _, err := c.foldersOf(ch, n)
	return l, err
}
