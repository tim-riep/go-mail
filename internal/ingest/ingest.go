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
}

// Ingest is the backend of the SMTP server.
type Ingest struct {
	cfg    Config
	st     *store.Store
	log    *slog.Logger
	now    func() time.Time
	signer ed25519.PrivateKey

	addrMu    sync.Mutex
	addrStamp addrStamp
	addrs     store.Addresses

	queue *queue
}

type addrStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

// ErrConfig reports an unusable configuration.
var ErrConfig = errors.New("ingest: invalid configuration")

// New checks the ingest key against platform/ingest-<gen>.cert in the
// data directory and returns the backend. The key file lives outside the
// data directory (section 4). Call Recover before serving and Start to
// run the preprocessing.
func New(cfg Config) (*Ingest, error) {
	if cfg.Store == nil || cfg.Log == nil {
		return nil, fmt.Errorf("%w: store and log are required", ErrConfig)
	}
	if len(cfg.IngestKey) != ed25519.PrivateKeySize || cfg.IngestGen == 0 {
		return nil, fmt.Errorf("%w: ingest key", ErrConfig)
	}
	cert, err := cfg.Store.ReadPlatformCert(keys.RoleIngest, cfg.IngestGen)
	if err != nil {
		return nil, fmt.Errorf("%w: ingest certificate: %v", ErrConfig, err)
	}
	if !cert.Pub.Equal(cfg.IngestKey.Public()) {
		return nil, fmt.Errorf("%w: the ingest key does not match ingest-%d.cert", ErrConfig, cfg.IngestGen)
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
	in := &Ingest{cfg: cfg, st: cfg.Store, log: cfg.Logger, now: cfg.Now, signer: cfg.IngestKey}
	q, err := newQueue(in)
	if err != nil {
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
// is wiped; spilled entries in work/ become unreadable.
func (in *Ingest) Close() error { return in.queue.close() }

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

// lookup resolves an address to a mailbox (5.2 step 1).
func (in *Ingest) lookup(address string) (store.ID, string, error) {
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
	return id, a, nil
}

// Recipient implements smtpd.Backend.
func (in *Ingest) Recipient(address string) error {
	_, _, err := in.lookup(address)
	return err
}
