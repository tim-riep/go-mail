// Package translog is the interface to the transparency log (2.7).
//
// Several rules of the specification depend on the log: a user generation
// is valid only from its log entry on (2.2 rule 3), signatures of a
// revoked generation count only if they were logged before the revocation
// (2.2 rule 4), address assignments are checked against the log (2.3),
// epochs and certificates are logged, and a client stops processing new
// signatures when its last verified tree head is older than 24 hours
// (2.3). Every one of these checks goes through Log, so that nothing is
// weakened silently.
//
// The log itself (golang.org/x/mod/sumdb/tlog, witnesses) is built in
// phase 3. Phase 1 has exactly one implementation, Unverified, which
// accepts everything. It can only be created with an explicit
// insecureNoLog switch (command line flag --insecure-no-log), and clients
// print Warning on every start.
package translog

import (
	"errors"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// ErrNoLog is returned when no verifying log is available and the caller
// did not explicitly accept running without one.
var ErrNoLog = errors.New("translog: no transparency log available; refusing to start (development only: --insecure-no-log)")

// Warning is printed by clients on every start with Unverified.
const Warning = "WARNUNG: Ohne Transparenzlog (--insecure-no-log). Generationen, Widerrufe, Epochen, " +
	"Zertifikate und Adresszuordnungen werden NICHT gegen ein Log geprüft. Ein Server kann " +
	"unbemerkt abweichende Zustände zeigen. Nur für die Entwicklung, nie mit echten Mails."

// Log is every operation that involves the transparency log.
type Log interface {
	// Verified reports whether the checks are backed by a real log.
	Verified() bool

	// AppendUser logs a new or extended user.rec (2.2 rule 3).
	AppendUser(user store.ID, userRec []byte) error
	// AppendEpoch logs an epoch.rec (2.7).
	AppendEpoch(mailbox store.ID, number uint32, epochRec []byte) error
	// AppendAddress logs a signed address assignment (2.3).
	AppendAddress(addressRec []byte) error
	// AppendPlatform logs a platform certificate or succession (2.7).
	AppendPlatform(name string, data []byte) error

	// CheckUser verifies that this user.rec is the one in the log
	// (inclusion proof, 2.7).
	CheckUser(user store.ID, userRec []byte) error
	// CheckGeneration verifies that generation gen of user is in the log
	// and therefore valid (2.2 rule 3).
	CheckGeneration(user store.ID, gen uint32) error
	// CheckRevokedSignature verifies that a record signed by the revoked
	// generation gen of user was logged before the revocation (2.2
	// rule 4, SPEC-ISSUES S13).
	CheckRevokedSignature(user store.ID, gen uint32, signed []byte) error
	// CheckEpoch verifies that epoch.rec is in the log (2.7).
	CheckEpoch(mailbox store.ID, number uint32, epochRec []byte) error
	// CheckAddress verifies that address was assigned to mailbox at time
	// at (milliseconds) according to the log (2.3).
	CheckAddress(address string, mailbox store.ID, at int64) error
	// CheckPlatform verifies that a platform certificate or succession is
	// in the log and its generation is not marked compromised (2.3).
	CheckPlatform(name string, data []byte) error
	// CheckFresh verifies that the last verified tree head with witness
	// signature is at most 24 hours old (2.3, 2.7).
	CheckFresh(now time.Time) error
}

// Unverified accepts everything. It exists so that phase 1 can run
// before the log is built; every method is a placeholder for phase 3.
type Unverified struct{}

// NewUnverified returns the accepting placeholder if insecureNoLog is
// set, and ErrNoLog otherwise.
func NewUnverified(insecureNoLog bool) (*Unverified, error) {
	if !insecureNoLog {
		return nil, ErrNoLog
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
