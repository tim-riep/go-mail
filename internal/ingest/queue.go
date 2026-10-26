package ingest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

// job is one mail waiting for preprocessing (5.3): the plaintext header,
// in memory or encrypted in work/.
type job struct {
	mailbox  store.ID
	epoch    uint32
	metaPub  *ecdh.PublicKey
	mail     store.ID
	received time.Time
	header   []byte // nil if spilled
	spill    string // file in work/
	size     int64
}

type batchKey struct {
	mailbox store.ID
	epoch   uint32
}

type batch struct {
	metaPub *ecdh.PublicKey
	entries []store.PendingEntry
	bytes   int
	started time.Time
}

// queue is the preprocessing queue with its ephemeral key (5.3).
type queue struct {
	in   *Ingest
	key  []byte
	aead cipher.AEAD

	mu      sync.Mutex
	jobs    []job
	mem     int64
	work    int64
	closed  bool
	wake    chan struct{}
	stop    chan struct{}
	stopped chan struct{}
	started bool

	procMu  sync.Mutex // serializes processing and flushing
	batches map[batchKey]*batch
}

func newQueue(in *Ingest) (*queue, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	// The key never leaves memory; it is locked against swapping (5.3).
	if err := mlock(key); err != nil {
		in.log.Info("ingest could not lock the ephemeral key in memory", "reason", "mlock failed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &queue{in: in, key: key, aead: aead, wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}), batches: map[batchKey]*batch{}}, nil
}

// enqueue adds a mail's header. If the memory bound would be exceeded,
// the header is encrypted with the ephemeral key into work/; if work/ is
// full too, the mail is not preprocessed and keeps its marker (5.1).
func (q *queue) enqueue(j job) {
	j.header = append([]byte(nil), j.header...)
	j.size = int64(len(j.header))
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		wipe(j.header)
		return
	}
	if q.mem+j.size > q.in.cfg.QueueMemory {
		if q.work+j.size > q.in.cfg.WorkLimit {
			wipe(j.header)
			q.in.log.Info("ingest preprocessing queue full", "mail", j.mail.String(), "status", "unprocessed")
			return
		}
		name, err := q.spill(&j)
		wipe(j.header)
		j.header = nil
		if err != nil {
			q.in.log.Info("ingest could not spill to work", "mail", j.mail.String(), "status", "unprocessed")
			return
		}
		j.spill = name
		q.work += j.size
	} else {
		q.mem += j.size
	}
	q.jobs = append(q.jobs, j)
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// spillAAD binds a spilled entry to its mail.
func spillAAD(j *job) []byte {
	aad := append([]byte("gomail/v1/work\x00"), j.mailbox[:]...)
	aad = binary.BigEndian.AppendUint32(aad, j.epoch)
	return append(aad, j.mail[:]...)
}

func (q *queue) spill(j *job) (string, error) {
	nonce := make([]byte, q.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := q.aead.Seal(append([]byte(nil), nonce...), nonce, j.header, spillAAD(j))
	var rnd [16]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return "", err
	}
	name := filepath.Join(q.in.st.WorkDir(), hex.EncodeToString(rnd[:])+".bin")
	if err := os.WriteFile(name, ct, 0o600); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func (q *queue) unspill(j *job) ([]byte, error) {
	data, err := store.ReadFileLimited(j.spill, MaxHeaderBytes+64)
	os.Remove(j.spill)
	if err != nil {
		return nil, err
	}
	ns := q.aead.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ingest: short work file")
	}
	return q.aead.Open(nil, data[:ns], data[ns:], spillAAD(j))
}

func (q *queue) start() {
	q.mu.Lock()
	if q.started || q.closed {
		q.mu.Unlock()
		return
	}
	q.started = true
	q.mu.Unlock()
	go q.run()
}

func (q *queue) run() {
	defer close(q.stopped)
	tick := q.in.cfg.BatchAge / 4
	if tick > time.Second {
		tick = time.Second
	}
	if tick <= 0 {
		tick = time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-q.stop:
			return
		case <-q.wake:
		case <-t.C:
		}
		q.processJobs()
		q.flushOld()
	}
}

// pop takes the next job.
func (q *queue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		return job{}, false
	}
	j := q.jobs[0]
	q.jobs = q.jobs[1:]
	if j.spill != "" {
		q.work -= j.size
	} else {
		q.mem -= j.size
	}
	return j, true
}

// processJobs turns all queued headers into term list entries.
func (q *queue) processJobs() {
	q.procMu.Lock()
	defer q.procMu.Unlock()
	for {
		j, ok := q.pop()
		if !ok {
			return
		}
		h := j.header
		if j.spill != "" {
			var err error
			if h, err = q.unspill(&j); err != nil {
				q.in.log.Info("ingest lost a spilled entry", "mail", j.mail.String(), "status", "unprocessed")
				continue
			}
		}
		terms, ok := Terms(h, j.received)
		wipe(h)
		if !ok {
			continue // the marker stays: a client processes the mail
		}
		k := batchKey{j.mailbox, j.epoch}
		b := q.batches[k]
		if b == nil {
			b = &batch{metaPub: j.metaPub, started: q.in.now()}
			q.batches[k] = b
		}
		size := 32
		for _, t := range terms {
			size += len(t) + 16
		}
		if len(b.entries) > 0 && b.bytes+size > maxBatchEncodedBytes {
			q.flushLocked(k)
			b = &batch{metaPub: j.metaPub, started: q.in.now()}
			q.batches[k] = b
		}
		b.entries = append(b.entries, store.PendingEntry{MailID: j.mail, Terms: terms})
		b.bytes += size
		if len(b.entries) >= q.in.cfg.BatchSize {
			q.flushLocked(k)
		}
	}
}

// flushOld writes term lists older than BatchAge (5.4: 60 seconds).
func (q *queue) flushOld() {
	q.procMu.Lock()
	defer q.procMu.Unlock()
	now := q.in.now()
	for k, b := range q.batches {
		if now.Sub(b.started) >= q.in.cfg.BatchAge {
			q.flushLocked(k)
		}
	}
}

func (q *queue) flushAll() error {
	q.processJobs()
	q.procMu.Lock()
	defer q.procMu.Unlock()
	var first error
	for k := range q.batches {
		if err := q.flushLocked(k); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// flushLocked writes one term list as pending/<n>/<batch-id>.gml, signed
// with the ingest key, and then deletes the markers it replaces (5.2
// step 5). A crash in between leaves both; a client handles a mail twice
// harmlessly.
func (q *queue) flushLocked(k batchKey) error {
	b := q.batches[k]
	delete(q.batches, k)
	if b == nil || len(b.entries) == 0 {
		return nil
	}
	in := q.in
	id, err := store.NewID(nil)
	if err != nil {
		return err
	}
	p := &store.Pending{MailboxID: k.mailbox, Epoch: k.epoch, Entries: b.entries}
	data, err := in.sealPending(p, id, &store.Epoch{MetaPub: b.metaPub})
	for i := range b.entries {
		b.entries[i].Terms = nil
	}
	if err != nil {
		in.log.Info("ingest could not seal a term list", "mailbox", k.mailbox.String(), "entries", len(p.Entries))
		return err
	}
	unlock, err := in.st.LockMailbox(k.mailbox)
	if err != nil {
		return err
	}
	defer unlock()
	if err := store.MkdirAll(in.st.PendingDir(k.mailbox, k.epoch)); err != nil {
		return err
	}
	if err := store.CreateFileAtomic(in.st.PendingFile(k.mailbox, k.epoch, id), data); err != nil {
		in.log.Info("ingest could not write a term list", "mailbox", k.mailbox.String())
		return err
	}
	if crash("batch-written") {
		return errCrashed
	}
	for i, e := range p.Entries {
		if err := store.RemoveDurable(in.st.PendingFile(k.mailbox, k.epoch, e.MailID)); err != nil {
			return err
		}
		if i == 0 && crash("marker-removed") {
			return errCrashed
		}
	}
	in.log.Info("ingest wrote a term list", "mailbox", k.mailbox.String(), "epoch", k.epoch, "batch", id.String(), "entries", len(p.Entries))
	return nil
}

func (q *queue) close() error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	started := q.started
	q.mu.Unlock()
	if started {
		close(q.stop)
		<-q.stopped
	}
	err := q.flushAll()
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	wipe(q.key)
	munlock(q.key)
	return err
}
