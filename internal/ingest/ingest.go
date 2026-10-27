// Package ingest accepts mail for the SMTP server (specification 5.2 to
// 5.4): it resolves recipients to mailboxes, chooses the current epoch,
// encrypts the stream per mailbox into spool/, writes signed metadata and
// the "unprocessed" marker, moves everything into the mailboxes in one
// journaled transaction before the SMTP server answers 250, and
// preprocesses the headers into term lists with an ephemeral key.
//
// Plaintext exists only in memory: the encryption writers' block buffers,
// the captured header (at most 1 MB) and the preprocessing queue. Queue
// entries that do not fit in memory are encrypted with a key that exists
// only in this process before they go to work/. Logs carry only IDs,
// sizes and status codes.
package ingest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Defaults of 5.1 to 5.4.
const (
	DefaultMinFree       = 0.10 // 5.1: below 10 % free, 452 4.3.1
	DefaultQueueMemory   = 32 << 20
	DefaultWorkLimit     = 256 << 20
	DefaultBatchSize     = 100              // 5.4
	DefaultBatchAge      = 60 * time.Second // 5.4
	MaxHeaderBytes       = 1_000_000        // 5.2, 5.3: 1 MB
	MaxHeaderFields      = 500              // 5.3
	maxBatchEncodedBytes = 512 << 10        // keeps a batch far below rec.MaxRecordSize
)

// Config configures the ingest backend.
type Config struct {
	Store     *store.Store
	Log       translog.Log
	IngestKey ed25519.PrivateKey
	IngestGen uint32
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Logger receives IDs, sizes and status codes only.
	Logger *slog.Logger
	// MinFree is the fraction of free space below which no mail is
	// accepted; 0 means DefaultMinFree.
	MinFree float64
	// DiskSpace reports free and total bytes of the data directory; nil
	// means the file system's statistics.
	DiskSpace func(path string) (free, total uint64, err error)
	// QueueMemory and WorkLimit bound the preprocessing queue (5.1).
	QueueMemory int64
	WorkLimit   int64
	// BatchSize and BatchAge decide when a term list is written (5.4).
	BatchSize int
	BatchAge  time.Duration
	// PeerCheck makes New check, after taking the server lock, that a
	// client holds its lock on locks/client and that this lock is in
	// force here (9.1, "Testsperre"); without a running client New fails
	// with store.ErrPeerLock. The default false only takes the server
	// lock. Whether the server requires a running client is decided by
	// the program (gomail-server), not by this package.
	PeerCheck bool
}

// Ingest is the backend of the SMTP server.
type Ingest struct {
	cfg    Config
	st     *store.Store
	log    *slog.Logger
	now    func() time.Time
	signer ed25519.PrivateKey
	pub    ed25519.PublicKey // of ingest-<gen>.cert, for the self-check (section 7)

	addrMu    sync.Mutex
	addrStamp addrStamp
	addrs     store.Addresses

	queue *queue

	chains chainCache

	releaseOnce sync.Once
	release     func() // the server lock of 9.1, held from New to Close
}

type addrStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

// ErrConfig reports an unusable configuration.
var ErrConfig = errors.New("ingest: invalid configuration")

// Errors of the log checks (task 15). Deliveries that fail them are
// refused with 451 (smtpd.ErrTemporary); the log lines carry IDs only.
var (
	// ErrRollback: mailbox.rec names a lower head than the newest valid
	// epoch of the mailbox in the log (translog Log.CheckEpoch: "a lower
	// head is a rollback", 2.4). The server does not encrypt for an
	// older epoch then (D71: the residual risk of a server without
	// memory, closed by the log).
	ErrRollback = errors.New("ingest: mailbox.rec is behind the epochs in the log")
	// ErrSuperseded: ingest-<gen+1>.cert is a valid entry of the log and
	// the receipt time is not before its valid_from; generation gen
	// signs no metadata from then on (translog doc.go "Platform
	// generations"), every client would reject it.
	ErrSuperseded = errors.New("ingest: the ingest generation is superseded in the log")
)

// New checks the ingest key against platform/ingest-<gen>.cert in the
// data directory and returns the backend. The key file lives outside the
// data directory (section 4). Call Recover before serving and Start to
// run the preprocessing.
//
// The certificate must be in the log with exactly the bytes in platform/
// (Log.CheckPlatform against the identity list of the log's anchor), and
// generation gen must not be superseded at the time of the start
// (ErrSuperseded, see checkGeneration); both fail with ErrConfig.
// Config.BatchSize must lie between 0 (DefaultBatchSize) and
// store.MaxBatch, the most entries a term list can hold (ErrConfig).
//
// New takes the server lock locks/server (9.1) without waiting and holds
// it until Close; a second server on the same data directory fails with
// store.ErrLocked. With Config.PeerCheck it then requires the lock of a
// running client (store.CheckPeerLock) and fails with store.ErrPeerLock
// otherwise, releasing its own lock.
func New(cfg Config) (*Ingest, error) {
	if cfg.Store == nil || cfg.Log == nil {
		return nil, fmt.Errorf("%w: store and log are required", ErrConfig)
	}
	if len(cfg.IngestKey) != ed25519.PrivateKeySize || cfg.IngestGen == 0 || cfg.IngestGen == math.MaxUint32 {
		return nil, fmt.Errorf("%w: ingest key", ErrConfig)
	}
	if cfg.BatchSize < 0 || cfg.BatchSize > store.MaxBatch {
		return nil, fmt.Errorf("%w: batch size %d: 0 (default %d) or 1 to %d", ErrConfig, cfg.BatchSize, DefaultBatchSize, store.MaxBatch)
	}
	cert, err := cfg.Store.ReadPlatformCert(keys.RoleIngest, cfg.IngestGen)
	if err != nil {
		return nil, fmt.Errorf("%w: ingest certificate: %v", ErrConfig, err)
	}
	if !cert.Pub.Equal(cfg.IngestKey.Public()) {
		return nil, fmt.Errorf("%w: the ingest key does not match ingest-%d.cert", ErrConfig, cfg.IngestGen)
	}
	certName := store.PlatformFileName("ingest", cfg.IngestGen, "cert")
	certData, err := cfg.Store.ReadPlatformFile(certName)
	if err != nil {
		return nil, fmt.Errorf("%w: ingest certificate: %v", ErrConfig, err)
	}
	// The own certificate is in the log (2.7, translog doc.go "Tasks"
	// point 15): a certificate the log does not hold signs nothing a
	// client accepts.
	if err := cfg.Log.CheckPlatform(certName, certData); err != nil {
		return nil, fmt.Errorf("%w: %s is not in the log: %w", ErrConfig, certName, err)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.MinFree == 0 {
		cfg.MinFree = DefaultMinFree
	}
	if cfg.DiskSpace == nil {
		cfg.DiskSpace = diskSpace
	}
	if cfg.QueueMemory == 0 {
		cfg.QueueMemory = DefaultQueueMemory
	}
	if cfg.WorkLimit == 0 {
		cfg.WorkLimit = DefaultWorkLimit
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.BatchAge == 0 {
		cfg.BatchAge = DefaultBatchAge
	}
	release, err := cfg.Store.HoldRoleLock(store.RoleServer)
	if err != nil {
		return nil, fmt.Errorf("ingest: server lock: %w", err)
	}
	if cfg.PeerCheck {
		if err := cfg.Store.CheckPeerLock(store.RoleClient); err != nil {
			release()
			return nil, fmt.Errorf("ingest: client lock: %w", err)
		}
	}
	in := &Ingest{cfg: cfg, st: cfg.Store, log: cfg.Logger, now: cfg.Now, signer: cfg.IngestKey, pub: cert.Pub, release: release}
	if err := in.checkGeneration(cfg.Now()); err != nil {
		release()
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	in.chains.init()
	q, err := newQueue(in)
	if err != nil {
		release()
		return nil, err
	}
	in.queue = q
	return in, nil
}

// Recover runs at server start (5.2, 5.3): it rolls back every spool
// transaction whose journal exists (renames into mailboxes that were not
// committed), deletes the whole content of spool/ and work/, and removes
// temporary files of interrupted writes in the mailboxes. Mails already
// committed keep their "unprocessed" marker.
func (in *Ingest) Recover() error {
	spool := in.st.SpoolDir()
	entries, err := os.ReadDir(spool)
	if err != nil {
		return err
	}
	for _, e := range entries {
		dir := filepath.Join(spool, e.Name())
		if e.IsDir() {
			if err := in.rollback(dir); err != nil {
				return err
			}
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := store.SyncDir(spool); err != nil {
		return err
	}
	work := in.st.WorkDir()
	wentries, err := os.ReadDir(work)
	if err != nil {
		return err
	}
	for _, e := range wentries {
		if err := os.RemoveAll(filepath.Join(work, e.Name())); err != nil {
			return err
		}
	}
	if err := store.SyncDir(work); err != nil {
		return err
	}
	// Temporary files of interrupted atomic writes anywhere in the data
	// directory are never valid data.
	if err := in.st.RemoveTempFiles(); err != nil {
		return err
	}
	in.log.Info("ingest recovered", "spool_entries", len(entries), "work_entries", len(wentries))
	return nil
}

// rollback undoes the renames of an uncommitted transaction.
func (in *Ingest) rollback(txnDir string) error {
	data, err := store.ReadFileLimited(filepath.Join(txnDir, journalName), store.MaxJournalFile)
	if errors.Is(err, store.ErrNotFound) {
		return nil // never reached the journal: nothing left spool/
	}
	if err != nil {
		return err
	}
	moves, err := store.DecodeJournal(data)
	if err != nil {
		// A damaged journal cannot be trusted to name our files; the
		// journal is written atomically, so this means tampering.
		return fmt.Errorf("ingest: damaged journal in spool: %w", err)
	}
	rolled := 0
	for _, m := range moves {
		dst, err := in.st.Abs(m.Dst)
		if err != nil {
			return err
		}
		if err := store.RemoveDurable(dst); err != nil {
			return err
		}
		rolled++
	}
	in.log.Info("ingest rolled back an uncommitted delivery", "files", rolled)
	return nil
}

// Start runs the preprocessing worker; Close stops it and flushes.
func (in *Ingest) Start() { in.queue.start() }

// Close flushes open term lists and stops the worker. The ephemeral key
// is wiped; spilled entries in work/ become unreadable. Then the server
// lock is released. Close may be called more than once.
func (in *Ingest) Close() error {
	err := in.queue.close()
	in.releaseLock()
	return err
}

// releaseLock releases the server lock once.
func (in *Ingest) releaseLock() { in.releaseOnce.Do(in.release) }

// Flush writes all open term lists now (tests, shutdown).
func (in *Ingest) Flush() error { return in.queue.flushAll() }

// Accepting implements smtpd.Backend: below MinFree free space the server
// accepts nothing (5.1).
func (in *Ingest) Accepting() error {
	free, total, err := in.cfg.DiskSpace(in.st.Root)
	if err != nil {
		return smtpd.ErrTemporary
	}
	if total == 0 || float64(free) < in.cfg.MinFree*float64(total) {
		in.log.Info("ingest refuses mail", "status", 452, "reason", "disk space")
		return smtpd.ErrDiskFull
	}
	return nil
}

// DiskSpace reports the free and total bytes of the data directory as
// Accepting sees them (Config.DiskSpace, else the file system's
// statistics). An error means that Accepting refuses every mail (5.1,
// fail closed): on platforms where package syscall cannot tell the free
// space (NetBSD, Windows) until Config.DiskSpace is set. gomail-server
// reports that at its start.
func (in *Ingest) DiskSpace() (free, total uint64, err error) {
	return in.cfg.DiskSpace(in.st.Root)
}

// addresses returns addresses.json, reloaded when it changed.
func (in *Ingest) addresses() (store.Addresses, error) {
	in.addrMu.Lock()
	defer in.addrMu.Unlock()
	var stamp addrStamp
	if fi, err := os.Stat(in.st.AddressesFile()); err == nil {
		stamp = addrStamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
	}
	if in.addrs != nil && stamp == in.addrStamp {
		return in.addrs, nil
	}
	a, err := in.st.LoadAddresses()
	if err != nil {
		return nil, err
	}
	in.addrs, in.addrStamp = a, stamp
	return a, nil
}

// lookup resolves an address to a mailbox (5.2 step 1) for a mail
// received at at: addresses.json, the server's working copy, names the
// mailbox, and the log must assign the address to that mailbox at at
// (checkAddress).
func (in *Ingest) lookup(address string, at time.Time) (store.ID, string, error) {
	a, err := store.NormalizeAddress(address)
	if err != nil {
		return store.ID{}, "", smtpd.ErrUnknownRecipient
	}
	table, err := in.addresses()
	if err != nil {
		return store.ID{}, "", smtpd.ErrTemporary
	}
	id, ok := table[a]
	if !ok {
		return store.ID{}, "", smtpd.ErrUnknownRecipient
	}
	if err := in.checkAddress(a, id, at); err != nil {
		return store.ID{}, "", err
	}
	return id, a, nil
}

// checkAddress checks the assignment of the normalized address a to
// mailbox id against the log (2.3, Log.CheckAddress): the valid entry of
// the address with the greatest valid_from <= at must name id (Q9
// reading, translog doc.go "Address assignments"). An assignment the log
// does not hold or that names another mailbox is refused like an unknown
// address (550): addresses.json alone assigns nothing ("stilles
// Umleiten", 2.7). Any other failure of the log is temporary (451). The
// log line names the mailbox, never the address.
func (in *Ingest) checkAddress(a string, id store.ID, at time.Time) error {
	err := in.cfg.Log.CheckAddress(a, id, at.UnixMilli())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, translog.ErrPending):
		in.log.Info("ingest refused a recipient: assignment not yet covered by the log", "mailbox", id.String(), "status", 451)
		return smtpd.ErrTemporary
	case errors.Is(err, translog.ErrNotInLog), errors.Is(err, translog.ErrMismatch):
		in.log.Info("ingest refused a recipient: assignment not in the log", "mailbox", id.String(), "status", 550)
		return smtpd.ErrUnknownRecipient
	}
	in.log.Info("ingest refused a recipient: log check failed", "mailbox", id.String(), "status", 451)
	return smtpd.ErrTemporary
}

// checkGeneration refuses to sign with the configured ingest generation
// g at time at once ingest-<g+1>.cert is a valid entry of the log and at
// is not before its valid_from (translog doc.go "Platform generations",
// strictest reading without Q8): clients accept metadata of generation g
// only for receipt times before it (ErrSuperseded). The operator starts
// the server with the new key (ceremony.IngestRotate). It runs in New,
// in Begin for the receipt time and again in the commit under the
// mailbox locks, before anything is moved into a mailbox (task 15c
// finding 1: the certificate may be logged while the data arrive).
func (in *Ingest) checkGeneration(at time.Time) error {
	name := store.PlatformFileName("ingest", in.cfg.IngestGen+1, "cert")
	es, err := in.cfg.Log.Lookup(translog.KindPlatform, []byte(name))
	if err != nil {
		return err
	}
	for _, e := range es {
		c, err := keys.DecodePlatformCert(e.Content)
		if err != nil {
			return err
		}
		if at.UnixMilli() >= c.ValidFrom {
			return fmt.Errorf("%w: %s valid from %d", ErrSuperseded, name, c.ValidFrom)
		}
	}
	return nil
}

// Recipient implements smtpd.Backend.
func (in *Ingest) Recipient(address string) error {
	_, _, err := in.lookup(address, in.now())
	return err
}
