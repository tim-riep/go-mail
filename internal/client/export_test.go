package client

import (
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

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

// SetCrashHook sets the crash hook of the package (see crashHook) until
// the test ends.
func SetCrashHook(t interface{ Cleanup(func()) }, f func(point string) bool) {
	crashHook = f
	t.Cleanup(func() { crashHook = nil })
}

// ErrCrashed is the error of a simulated crash.
var ErrCrashed = errCrashed

// ErrKept is the cause of a lost race for an epoch.rec beyond the head
// that did not verify but is not known to be invalid for good.
var ErrKept = errKept

// MaxEpochAttempts is the number of attempts of a change that loses the
// race for an epoch number (K2 rule 3).
const MaxEpochAttempts = maxEpochAttempts

// WithoutMailboxLock makes c skip the mailbox lock, as if the lock were
// not in force between two machines, so that a test can let two clients
// create the same epoch (K2 rule 3).
func (c *Client) WithoutMailboxLock() { c.skipLock = true }

// WarnCause is warnCause for the tests of package client_test.
var WarnCause = warnCause

// SetLogHook wraps the client log of every client opened (Open,
// openForDeviceLost, Restore, RecoverRead) until the test ends, so that
// a check of the real log can be made to fail.
func SetLogHook(t interface{ Cleanup(func()) }, f func(translog.Log) translog.Log) {
	logHook = f
	t.Cleanup(func() { logHook = nil })
}
