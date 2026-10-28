// Package translogtest holds Unverified, the log that accepts
// everything. It was translog.Unverified until task 07, which moved it
// here: it is for tests and testenv only (the server side of testenv,
// for ingest). No command uses it: task 15 built the real log into
// server, ingest and ceremony, task 14 into the client, and the switch
// --insecure-no-log is a usage error everywhere. NewUnverified keeps
// translog.ErrNoLog for a caller that did not accept running without a
// log.
package translogtest

import (
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// NoIndex is the index Unverified returns for an append.
const NoIndex int64 = -1

// Unverified accepts everything. It exists so that phase 1 can run
// before the log is built into the programs; every method is a
// placeholder for phase 3.
type Unverified struct{}

var _ translog.Log = (*Unverified)(nil)

// NewUnverified returns the accepting placeholder if insecureNoLog is
// set, and translog.ErrNoLog otherwise.
func NewUnverified(insecureNoLog bool) (*Unverified, error) {
	if !insecureNoLog {
		return nil, translog.ErrNoLog
	}
	return &Unverified{}, nil
}

// Verified is false.
func (*Unverified) Verified() bool { return false }

// TODO(phase3-translog): append user.rec to the log.
func (*Unverified) AppendUser(store.ID, []byte) error { return nil }

// TODO(phase3-translog): append epoch.rec to the log.
func (*Unverified) AppendEpoch(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): append the signed address assignment.
func (*Unverified) AppendAddress([]byte) error { return nil }

// TODO(phase3-translog): append certificates and successions.
func (*Unverified) AppendPlatform(string, []byte) error { return nil }

// TODO(phase3-translog): inclusion proof for user.rec.
func (*Unverified) CheckUser(store.ID, []byte) error { return nil }

// TODO(phase3-translog): a generation is valid only from its log entry on.
func (*Unverified) CheckGeneration(store.ID, uint32) error { return nil }

// TODO(phase3-translog): signature of a revoked generation logged before the revocation.
func (*Unverified) CheckRevokedSignature(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): inclusion proof for epoch.rec.
func (*Unverified) CheckEpoch(store.ID, uint32, []byte) error { return nil }

// TODO(phase3-translog): address assignment at the time of receipt.
func (*Unverified) CheckAddress(string, store.ID, int64) error { return nil }

// TODO(phase3-translog): certificate in the log, generation not compromised.
func (*Unverified) CheckPlatform(string, []byte) error { return nil }

// TODO(phase3-translog): tree head with witness signature at most 24 hours old.
func (*Unverified) CheckFresh(time.Time) error { return nil }

// Append accepts the record and logs nothing (NoIndex).
func (*Unverified) Append(translog.Kind, []byte) (int64, error) { return NoIndex, nil }

// Refresh has no head to return.
func (*Unverified) Refresh(time.Time) (*translog.Head, error) { return nil, nil }

// Head reports that there is no log.
func (*Unverified) Head() (*translog.Head, error) { return nil, translog.ErrNoLog }

// Entry reports that there is no log.
func (*Unverified) Entry(int64) (*translog.Entry, error) { return nil, translog.ErrNoLog }

// InclusionProof reports that there is no log.
func (*Unverified) InclusionProof(int64, int64) (tlog.RecordProof, error) {
	return nil, translog.ErrNoLog
}

// ConsistencyProof reports that there is no log.
func (*Unverified) ConsistencyProof(int64, int64) (tlog.TreeProof, error) {
	return nil, translog.ErrNoLog
}

// Lookup finds nothing.
func (*Unverified) Lookup(translog.Kind, []byte) ([]translog.Entry, error) { return nil, nil }
