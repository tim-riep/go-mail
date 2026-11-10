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

// Unverified accepts everything: every Append and Check method returns
// nil without looking at its arguments, and the reading methods report
// that there is no log. It comes from phase 1, when the programs ran
// before the log was built. Since task 15 (server, ingest, ceremony) and
// task 14 (client) every command runs with the verifying log of
// translog.Open, and no production build links this package
// (cmd/gomail-ceremony build_test.go checks that for the ceremony). It
// stays for tests that need a translog.Log where the log is not what
// they test, such as the server side of testenv for ingest or the
// receipt benchmarks. A test of a rule of the log uses the real log
// (testenv.NewLogged, translog.Open), never Unverified.
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

// AppendUser accepts user.rec and logs nothing (the real log appends a
// KindUser entry).
func (*Unverified) AppendUser(store.ID, []byte) error { return nil }

// AppendEpoch accepts epoch.rec and logs nothing (the real log appends a
// KindEpoch entry).
func (*Unverified) AppendEpoch(store.ID, uint32, []byte) error { return nil }

// AppendAddress accepts the signed address assignment and logs nothing
// (the real log appends a KindAddress entry).
func (*Unverified) AppendAddress([]byte) error { return nil }

// AppendPlatform accepts a certificate or succession and logs nothing
// (the real log appends a KindPlatform entry).
func (*Unverified) AppendPlatform(string, []byte) error { return nil }

// CheckUser accepts every user.rec (the real log requires its inclusion).
func (*Unverified) CheckUser(store.ID, []byte) error { return nil }

// CheckGeneration accepts every generation (the real log accepts a
// generation only from its log entry on).
func (*Unverified) CheckGeneration(store.ID, uint32) error { return nil }

// CheckRevokedSignature accepts every signature (the real log accepts a
// signature of a revoked generation only if it was logged before the
// revocation).
func (*Unverified) CheckRevokedSignature(store.ID, uint32, []byte) error { return nil }

// CheckEpoch accepts every epoch.rec (the real log requires its
// inclusion).
func (*Unverified) CheckEpoch(store.ID, uint32, []byte) error { return nil }

// CheckAddress accepts every assignment (the real log checks the
// assignment valid at the time of receipt).
func (*Unverified) CheckAddress(string, store.ID, int64) error { return nil }

// CheckPlatform accepts every certificate (the real log requires it in
// the log, of a generation that is not revoked).
func (*Unverified) CheckPlatform(string, []byte) error { return nil }

// CheckFresh accepts every time (the real log requires a tree head with
// witness cosignatures at most 24 hours old).
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
