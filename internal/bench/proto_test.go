package bench

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
)

// protoSizes are the sizes of the files ingest writes for one mail of a
// size class, read from a real delivery (ingestSizes).
type protoSizes struct {
	mailHead int // mail.gml without its blocks: preamble, header, recipients
	meta     int // meta.gml
	marker   int // the "unprocessed" marker in pending/
	terms    int // the term list of a batch of ingest.DefaultBatchSize mails

	// The delivery they were read from: content bytes (the message with
	// the Received header of smtpd) and size of mail.gml.
	content, mail int
}

// protoBlock is the size of one block element of the envelope (3.3) for
// n bytes of content: element type and length (5 bytes), ciphertext and
// tag.
func protoBlock(n int) int { return 5 + n + envelope.TagSize }

// protoMailSize is the size of mail.gml for n bytes of content: every
// full chunk followed by more data is a block, the rest (possibly a full
// chunk, possibly empty) is the last block.
func protoMailSize(head, n int) int {
	size := head
	for n > envelope.ChunkSize {
		size += protoBlock(envelope.ChunkSize)
		n -= envelope.ChunkSize
	}
	return size + protoBlock(n)
}

// headerOnly returns the header of msg (up to and including the empty
// line) with a one-line body: a mail whose term list entry is the one
// of msg, since the terms come from the header alone.
func headerOnly(msg []byte) ([]byte, error) {
	i := bytes.Index(msg, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, errors.New("bench: message without an empty line")
	}
	return append(msg[:i+4:i+4], "x\r\n"...), nil
}

var (
	calibMu sync.Mutex
	calib   = map[string]protoSizes{}
)

// ingestSizes delivers one copy of msg (size class name) through smtpd +
// ingest and returns the sizes of the files ingest wrote for it. Then it
// fills the worker's batch with ingest.DefaultBatchSize-1 mails of the
// same header and reads the size of the term list the worker writes for
// the batch. The result is kept per size class for the rest of the
// process.
func ingestSizes(tb testing.TB, name string, msg []byte) protoSizes {
	tb.Helper()
	calibMu.Lock()
	defer calibMu.Unlock()
	if s, ok := calib[name]; ok {
		return s
	}
	r := newEnvRig(tb, BenchTo)
	r.startIngest(tb)
	cb := &countingBackend{Backend: r.in}
	r.serve(tb, cb)
	s, err := dialSender(r.addr)
	if err != nil {
		tb.Fatal(err)
	}
	err = s.send(BenchFrom, []string{BenchTo}, msg)
	s.close()
	if err != nil {
		tb.Fatal(err)
	}
	st := r.env.Store
	inbox := mailboxInbox(tb, r)
	mails, err := st.ListMails(r.mbx, inbox)
	if err != nil || len(mails) != 1 {
		tb.Fatalf("calibration: %d mails: %v", len(mails), err)
	}
	// The marker stays in pending/<epoch>/ until the term list replaces
	// it at the flush of its batch; the batch holds one mail so far.
	epochs, err := st.ListPendingEpochs(r.mbx)
	if err != nil || len(epochs) != 1 {
		tb.Fatalf("calibration: pending epochs %v: %v", epochs, err)
	}
	pend, err := st.ListPending(r.mbx, epochs[0])
	if err != nil || len(pend) != 1 {
		tb.Fatalf("calibration: %d pending files: %v", len(pend), err)
	}
	size := func(p string) int {
		fi, err := os.Stat(p)
		if err != nil {
			tb.Fatal(err)
		}
		return int(fi.Size())
	}
	mail := size(st.MailFile(r.mbx, inbox, mails[0]))
	// The content is the message with the Received header of smtpd.
	n := int(cb.bytes.Load())
	res := protoSizes{
		mailHead: mail - protoMailSize(0, n),
		meta:     size(st.MetaFile(r.mbx, inbox, mails[0])),
		marker:   size(st.PendingFile(r.mbx, epochs[0], pend[0])),
		content:  n,
		mail:     mail,
	}
	if res.mailHead <= 0 {
		tb.Fatalf("calibration: mail.gml has %d bytes for %d bytes of content", mail, n)
	}
	// The term list. The clock of the platform stands still, so every
	// mail of the batch has the same receipt and the same terms; the
	// worker writes the list when the batch is full (or at the flush),
	// and the list replaces all markers.
	head, err := headerOnly(msg)
	if err != nil {
		tb.Fatal(err)
	}
	ss, err := dialSenders(r.addr, 4)
	if err != nil {
		tb.Fatal(err)
	}
	err = sendAll(ss, ingest.DefaultBatchSize-1, BenchFrom, []string{BenchTo}, head)
	closeSenders(ss)
	if err != nil {
		tb.Fatal(err)
	}
	if err := r.in.Flush(); err != nil {
		tb.Fatal(err)
	}
	pend, err = st.ListPending(r.mbx, epochs[0])
	if err != nil || len(pend) != 1 {
		tb.Fatalf("calibration: %d files in pending/ after a batch of %d mails, want one term list: %v", len(pend), ingest.DefaultBatchSize, err)
	}
	res.terms = size(st.PendingFile(r.mbx, epochs[0], pend[0]))
	r.srv.Close()
	r.stopIngest(tb)
	calib[name] = res
	return res
}

// countingBackend passes everything to Backend and counts the bytes of
// the message stream smtpd delivers.
type countingBackend struct {
	smtpd.Backend
	bytes atomic.Int64
}

func (c *countingBackend) Begin(s smtpd.Session, from string, rcpts []string) (smtpd.Delivery, error) {
	d, err := c.Backend.Begin(s, from, rcpts)
	if err != nil {
		return nil, err
	}
	return countingDelivery{Delivery: d, n: &c.bytes}, nil
}

type countingDelivery struct {
	smtpd.Delivery
	n *atomic.Int64
}

func (d countingDelivery) Write(p []byte) (int, error) {
	n, err := d.Delivery.Write(p)
	d.n.Add(int64(n))
	return n, err
}

// newProtoRig is smtpd with the protocol sink (mode proto) for mails of
// size class sz: the files have the sizes ingest writes for msg.
func newProtoRig(tb testing.TB, sz Size, msg []byte) *rig {
	tb.Helper()
	sizes := ingestSizes(tb, sz.Name, msg)
	p, err := newProtoSink(filepath.Join(tb.TempDir(), "data"), sizes)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(p.close)
	r := &rig{proto: p}
	r.serve(tb, p)
	return r
}

// protoSink is the benchmark backend of mode proto: the file and fsync
// protocol of ingest (internal/ingest/ingest.go, delivery.go and
// queue.go) without any cryptography.
//
// Per mail it does what ingest does: the space check (Accepting, a
// statfs of the data directory; smtpd asks at MAIL and at DATA); a
// transaction directory in spool/ with a directory for the mailbox;
// mail.gml written block by block as the envelope writer does and
// synced; meta.gml and the marker with CreateFileAtomic; SyncDir of the
// transaction; the journal with CreateFileAtomic under the mailbox lock;
// the three renames with RenameDurable; RemoveDurable of the journal;
// the hand-over of the mail to the worker; removal of the transaction
// and SyncDir of spool/. That is 16 fsync, 3 renameat and 3 linkat per
// mail, the same as ingest.
//
// The worker is a goroutine as in ingest: it takes the committed mails
// from a queue and, whenever ingest.DefaultBatchSize of them are
// together (and at the flush after a run), writes a term list of the
// size ingest writes for the batch with CreateFileAtomic and removes the
// batch's markers with RemoveDurable, under the mailbox lock and
// serialized with the flush as in ingest: 2 fsync and 1 linkat per batch
// and 1 fsync per mail.
//
// Left out are the address lookup (addresses.json), the reads of
// mailbox.rec and the epochs with the verification of the chain, the
// epoch choice, the header evaluation and the term extraction, the
// signatures and the self-check.
//
// No byte of a message reaches the disk: every file is filled from a
// random buffer of the right size. The files live below the test's
// temporary directory; mail.gml, meta.gml and the term lists are
// collected and deleted at the flush after the run (after the measured
// window), the markers by the worker as in ingest.
type protoSink struct {
	st      *store.Store
	mbx     store.ID
	folder  store.ID
	sizes   protoSizes
	filler  []byte // random, as large as the largest file
	open    atomic.Int64
	mails   atomic.Int64
	bytes   atomic.Int64 // message bytes received
	written atomic.Int64 // bytes of every mail.gml written
	lists   atomic.Int64 // term lists written

	mu    sync.Mutex
	jobs  []string // markers of committed mails, not yet taken by the worker
	files []string // mail.gml, meta.gml and term lists of the run

	wake      chan struct{}
	stop      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once

	procMu sync.Mutex // serializes processing and flushing, as in ingest
	batch  []string   // markers of the open batch
	werr   error      // first error of the worker since the last flush
}

// protoEpoch is the epoch number of the protocol sink's pending/ dir.
const protoEpoch = 1

// newProtoSink creates a data directory at root and starts the worker.
func newProtoSink(root string, sizes protoSizes) (*protoSink, error) {
	st, err := store.Init(root)
	if err != nil {
		return nil, err
	}
	mbx, err := store.NewID(nil)
	if err != nil {
		return nil, err
	}
	folder, err := store.NewID(nil)
	if err != nil {
		return nil, err
	}
	if sizes.terms <= 0 {
		return nil, errors.New("bench: no size of the term list")
	}
	n := max(protoBlock(envelope.ChunkSize), sizes.mailHead, sizes.meta, sizes.marker, sizes.terms)
	filler := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, filler); err != nil {
		return nil, err
	}
	s := &protoSink{st: st, mbx: mbx, folder: folder, sizes: sizes, filler: filler,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{})}
	go s.run()
	return s, nil
}

// Accepting is the space check of ingest (5.1) with the MinFree of the
// benchmark (benchMinFree).
func (s *protoSink) Accepting() error {
	free, total, err := benchDiskSpace(s.st.Root)
	if err != nil {
		return smtpd.ErrTemporary
	}
	if total == 0 || float64(free) < benchMinFree*float64(total) {
		return smtpd.ErrDiskFull
	}
	return nil
}

func (s *protoSink) Recipient(string) error { return nil }

// mkdirSpool is the directory creation of ingest in spool/: mode 0700,
// then DirPerm.
func mkdirSpool(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, store.DirPerm); err != nil {
		os.Remove(dir)
		return err
	}
	return nil
}

func (s *protoSink) Begin(smtpd.Session, string, []string) (smtpd.Delivery, error) {
	txn, err := store.NewID(nil)
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	d := &protoDelivery{s: s, txnDir: filepath.Join(s.st.SpoolDir(), txn.String())}
	if err := mkdirSpool(d.txnDir); err != nil {
		return nil, smtpd.ErrTemporary
	}
	s.open.Add(1)
	// Ingest chooses the epoch under the mailbox lock.
	unlock, err := s.st.LockMailbox(s.mbx)
	if err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	unlock()
	if d.mailID, err = store.NewID(nil); err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	d.dir = filepath.Join(d.txnDir, s.mbx.String())
	if err := mkdirSpool(d.dir); err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	f, err := os.OpenFile(filepath.Join(d.dir, "mail.gml"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	d.f = f
	if err := f.Chmod(store.FilePerm); err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	// The envelope writer emits preamble, header and recipients at once.
	if err := d.emit(s.sizes.mailHead); err != nil {
		d.Abort()
		return nil, smtpd.ErrTemporary
	}
	return d, nil
}

type protoDelivery struct {
	s      *protoSink
	mailID store.ID
	txnDir string
	dir    string
	f      *os.File
	buf    int // content bytes of the current chunk
	moved  []string
	done   bool
}

// emit writes n filler bytes to mail.gml.
func (d *protoDelivery) emit(n int) error {
	_, err := d.f.Write(d.s.filler[:n])
	if err == nil {
		d.s.written.Add(int64(n))
	}
	return err
}

// Write counts the content and writes a block for every full chunk that
// more data follows, as envelope.Writer does.
func (d *protoDelivery) Write(p []byte) (int, error) {
	if d.done {
		return 0, smtpd.ErrTemporary
	}
	n := len(p)
	for len(p) > 0 {
		if d.buf == envelope.ChunkSize {
			if err := d.emit(protoBlock(envelope.ChunkSize)); err != nil {
				return 0, smtpd.ErrTemporary
			}
			d.buf = 0
		}
		k := min(envelope.ChunkSize-d.buf, len(p))
		d.buf += k
		p = p[k:]
	}
	d.s.bytes.Add(int64(n))
	return n, nil
}

func (d *protoDelivery) Commit() error {
	if d.done {
		return smtpd.ErrTemporary
	}
	if err := d.commit(); err != nil {
		d.Abort()
		return smtpd.ErrTemporary
	}
	d.done = true
	d.s.open.Add(-1)
	d.s.mails.Add(1)
	os.RemoveAll(d.txnDir)
	store.SyncDir(d.s.st.SpoolDir())
	// Ingest keeps the mail and its metadata; the sink deletes them at
	// the flush after the run, outside the measured window.
	d.s.mu.Lock()
	d.s.files = append(d.s.files, d.moved[1:]...)
	d.s.mu.Unlock()
	return nil
}

func (d *protoDelivery) commit() error {
	s := d.s
	if err := d.emit(protoBlock(d.buf)); err != nil {
		return err
	}
	if err := d.f.Sync(); err != nil {
		return err
	}
	err := d.f.Close()
	d.f = nil
	if err != nil {
		return err
	}
	if err := store.CreateFileAtomic(filepath.Join(d.dir, "meta.gml"), s.filler[:s.sizes.meta]); err != nil {
		return err
	}
	if err := store.CreateFileAtomic(filepath.Join(d.dir, "marker.gml"), s.filler[:s.sizes.marker]); err != nil {
		return err
	}
	if err := store.SyncDir(d.txnDir); err != nil {
		return err
	}
	unlock, err := s.st.LockMailboxes([]store.ID{s.mbx})
	if err != nil {
		return err
	}
	defer unlock()
	pairs := [][2]string{
		{filepath.Join(d.dir, "marker.gml"), s.st.PendingFile(s.mbx, protoEpoch, d.mailID)},
		{filepath.Join(d.dir, "meta.gml"), s.st.MetaFile(s.mbx, s.folder, d.mailID)},
		{filepath.Join(d.dir, "mail.gml"), s.st.MailFile(s.mbx, s.folder, d.mailID)},
	}
	moves := make([]store.Move, 0, len(pairs))
	for _, p := range pairs {
		src, err1 := s.st.Rel(p[0])
		dst, err2 := s.st.Rel(p[1])
		if err1 != nil || err2 != nil {
			return errors.New("bench: path outside the data directory")
		}
		moves = append(moves, store.Move{Src: src, Dst: dst})
	}
	jdata, err := store.EncodeJournal(moves)
	if err != nil {
		return err
	}
	journal := filepath.Join(d.txnDir, "journal.rec")
	if err := store.CreateFileAtomic(journal, jdata); err != nil {
		return err
	}
	for _, p := range pairs {
		if err := store.MkdirAll(filepath.Dir(p[1])); err != nil {
			return err
		}
		if _, err := os.Lstat(p[1]); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("bench: target exists")
		}
		if err := store.RenameDurable(p[0], p[1]); err != nil {
			return err
		}
		d.moved = append(d.moved, p[1])
	}
	// The commit point of ingest.
	if err := store.RemoveDurable(journal); err != nil {
		return err
	}
	// Ingest hands the mail to its worker here, still under the lock.
	s.enqueue(d.moved[0])
	return nil
}

// Abort removes everything the delivery wrote.
func (d *protoDelivery) Abort() {
	if d.done {
		return
	}
	d.done = true
	d.s.open.Add(-1)
	if d.f != nil {
		d.f.Close()
		d.f = nil
	}
	for _, p := range d.moved {
		os.Remove(p)
	}
	os.RemoveAll(d.txnDir)
	store.SyncDir(d.s.st.SpoolDir())
}

// enqueue hands the marker of a committed mail to the worker.
func (s *protoSink) enqueue(marker string) {
	s.mu.Lock()
	s.jobs = append(s.jobs, marker)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run is the worker goroutine.
func (s *protoSink) run() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stop:
			return
		case <-s.wake:
		}
		s.processJobs()
	}
}

// processJobs adds every queued mail to the batch and writes the batch
// when it holds ingest.DefaultBatchSize mails, as ingest's worker does.
func (s *protoSink) processJobs() {
	s.procMu.Lock()
	defer s.procMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.jobs) == 0 {
			s.mu.Unlock()
			return
		}
		m := s.jobs[0]
		s.jobs = s.jobs[1:]
		s.mu.Unlock()
		s.batch = append(s.batch, m)
		if len(s.batch) >= ingest.DefaultBatchSize {
			if err := s.flushLocked(); err != nil && s.werr == nil {
				s.werr = err
			}
		}
	}
}

// flushLocked writes the term list of the open batch, a random file of
// the size ingest writes for a full batch, under the mailbox lock and
// then removes the batch's markers, as ingest does when the term list
// replaces them. The caller holds procMu.
func (s *protoSink) flushLocked() error {
	markers := s.batch
	s.batch = nil
	if len(markers) == 0 {
		return nil
	}
	id, err := store.NewID(nil)
	if err != nil {
		return err
	}
	unlock, err := s.st.LockMailbox(s.mbx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := store.MkdirAll(s.st.PendingDir(s.mbx, protoEpoch)); err != nil {
		return err
	}
	list := s.st.PendingFile(s.mbx, protoEpoch, id)
	if err := store.CreateFileAtomic(list, s.filler[:s.sizes.terms]); err != nil {
		return err
	}
	s.lists.Add(1)
	s.mu.Lock()
	s.files = append(s.files, list)
	s.mu.Unlock()
	for _, p := range markers {
		if err := store.RemoveDurable(p); err != nil {
			return err
		}
	}
	return nil
}

// drain lets the worker's queue run dry now: the full batches are
// written, an incomplete one stays open.
func (s *protoSink) drain() error {
	s.processJobs()
	s.procMu.Lock()
	defer s.procMu.Unlock()
	return s.werr
}

// flush ends a run, after the measured window: like Ingest.Flush it
// processes the queue and writes the open batch, and then it deletes
// every file the run left (mail.gml, meta.gml, the term lists). It
// returns the first error of the worker since the last flush.
func (s *protoSink) flush() error {
	s.processJobs()
	s.procMu.Lock()
	err := s.flushLocked()
	if s.werr != nil {
		err = s.werr
	}
	s.werr = nil
	s.procMu.Unlock()
	s.mu.Lock()
	files := s.files
	s.files = nil
	s.mu.Unlock()
	for _, p := range files {
		if rerr := os.Remove(p); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// close stops the worker.
func (s *protoSink) close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.stopped
	})
}

// assertNoFiles fails tb if a regular file other than a lock file is
// left below dir.
func assertNoFiles(tb testing.TB, dir string) {
	tb.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() != "lock" {
			return fmt.Errorf("file left: %s", p)
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
}

// countFiles returns the number of regular files in dir.
func countFiles(tb testing.TB, dir string) int {
	tb.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n
}

// TestProtoSizes checks the size model of the protocol sink against what
// ingest writes, and that a delivery of the sink writes mail.gml in the
// size of ingest's.
func TestProtoSizes(t *testing.T) {
	sizes := Sizes[:2]
	if !testing.Short() {
		sizes = Sizes
	}
	for _, sz := range sizes {
		t.Run(sz.Name, func(t *testing.T) {
			msg, err := Mail(sz, 1)
			if err != nil {
				t.Fatal(err)
			}
			want := ingestSizes(t, sz.Name, msg)
			if want.meta <= 0 || want.marker <= 0 || want.terms <= want.marker {
				t.Fatalf("sizes %+v", want)
			}
			t.Logf("ingest wrote mail.gml %d, meta.gml %d, marker %d, term list of %d mails %d bytes",
				want.mail, want.meta, want.marker, ingest.DefaultBatchSize, want.terms)
			r := newProtoRig(t, sz, msg)
			runReceive(t, r, 1, 1, msg, func(bool) {})
			// smtpd adds its Received header to the message.
			n := int(r.proto.bytes.Load())
			if n <= len(msg) || n > len(msg)+1000 {
				t.Fatalf("received %d bytes, sent %d", n, len(msg))
			}
			if got, w := r.proto.written.Load(), int64(protoMailSize(want.mailHead, n)); got != w {
				t.Fatalf("mail.gml has %d bytes, the model says %d", got, w)
			}
			// The Received header has the same length in both servers, so
			// the files are of the same size.
			if n == want.content && r.proto.written.Load() != int64(want.mail) {
				t.Fatalf("mail.gml has %d bytes, ingest wrote %d", r.proto.written.Load(), want.mail)
			}
		})
	}
	// Chunk boundaries: a full last chunk and an empty last block.
	if got := protoMailSize(0, envelope.ChunkSize); got != protoBlock(envelope.ChunkSize) {
		t.Fatalf("one chunk: %d", got)
	}
	if got := protoMailSize(0, 0); got != protoBlock(0) {
		t.Fatalf("empty: %d", got)
	}
}

// TestProtoWorker checks the worker of the protocol sink: after
// ingest.DefaultBatchSize+1 mails, one term list of the calibrated size
// has replaced the markers of the first batch and the last marker
// waits; the flush after the run writes the last batch and leaves no
// file behind.
func TestProtoWorker(t *testing.T) {
	sz := Sizes[0]
	msg, err := Mail(sz, 1)
	if err != nil {
		t.Fatal(err)
	}
	r := newProtoRig(t, sz, msg)
	p := r.proto
	ss, err := dialSenders(r.addr, 4)
	if err != nil {
		t.Fatal(err)
	}
	err = sendAll(ss, ingest.DefaultBatchSize+1, BenchFrom, []string{BenchTo}, msg)
	closeSenders(ss)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.drain(); err != nil {
		t.Fatal(err)
	}
	pend := p.st.PendingDir(p.mbx, protoEpoch)
	ids, err := p.st.ListPending(p.mbx, protoEpoch)
	if err != nil || len(ids) != 2 || p.lists.Load() != 1 {
		t.Fatalf("%d files in pending/, %d term lists: %v", len(ids), p.lists.Load(), err)
	}
	var listSize, markerSize int
	for _, id := range ids {
		fi, err := os.Stat(p.st.PendingFile(p.mbx, protoEpoch, id))
		if err != nil {
			t.Fatal(err)
		}
		if int(fi.Size()) == p.sizes.terms {
			listSize = int(fi.Size())
		} else {
			markerSize = int(fi.Size())
		}
	}
	if listSize != p.sizes.terms || markerSize != p.sizes.marker {
		t.Fatalf("term list %d bytes (want %d), marker %d bytes (want %d)", listSize, p.sizes.terms, markerSize, p.sizes.marker)
	}
	// Until the flush, the mails and their metadata stay.
	if n := countFiles(t, p.st.MailDir(p.mbx, p.folder)); n != 2*(ingest.DefaultBatchSize+1) {
		t.Fatalf("%d files in the folder before the flush", n)
	}
	if err := p.flush(); err != nil {
		t.Fatal(err)
	}
	if p.lists.Load() != 2 || countFiles(t, pend) != 0 {
		t.Fatalf("%d term lists, %d files in pending/ after the flush", p.lists.Load(), countFiles(t, pend))
	}
	assertNoFiles(t, p.st.Root)
}
