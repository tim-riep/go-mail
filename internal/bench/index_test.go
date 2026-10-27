package bench

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// indexMails is the number of corpus mails client.Index processes per
// operation of BenchmarkIndex.
const indexMails = 1000

// indexKinds are the contents of pending/ of point 2: term lists of the
// ingest worker (terms) or markers only (unprocessed).
var indexKinds = []string{"terms", "unprocessed"}

// pendingFiles are the files of pending/ of a mailbox (term lists and
// markers, sealed and signed by ingest) by epoch and file ID, kept to
// put pending/ back into the state ingest left it in.
type pendingFiles map[uint32]map[store.ID][]byte

func (p pendingFiles) count() int {
	n := 0
	for _, files := range p {
		n += len(files)
	}
	return n
}

// snapshotPending reads every file of pending/ of mailbox mbx.
func snapshotPending(tb testing.TB, st *store.Store, mbx store.ID) pendingFiles {
	tb.Helper()
	epochs, err := st.ListPendingEpochs(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	out := pendingFiles{}
	for _, n := range epochs {
		ids, err := st.ListPending(mbx, n)
		if err != nil {
			tb.Fatal(err)
		}
		for _, id := range ids {
			data, err := st.ReadPending(mbx, n, id)
			if err != nil {
				tb.Fatal(err)
			}
			if out[n] == nil {
				out[n] = map[store.ID][]byte{}
			}
			out[n][id] = data
		}
	}
	return out
}

// restorePending replaces the content of pending/ of mailbox mbx with p.
func restorePending(tb testing.TB, st *store.Store, mbx store.ID, p pendingFiles) {
	tb.Helper()
	epochs, err := st.ListPendingEpochs(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	for _, n := range epochs {
		ids, err := st.ListPending(mbx, n)
		if err != nil {
			tb.Fatal(err)
		}
		for _, id := range ids {
			if err := os.Remove(st.PendingFile(mbx, n, id)); err != nil {
				tb.Fatal(err)
			}
		}
	}
	for n, files := range p {
		if err := store.MkdirAll(st.PendingDir(mbx, n)); err != nil {
			tb.Fatal(err)
		}
		for id, data := range files {
			if err := store.CreateFileAtomic(st.PendingFile(mbx, n, id), data); err != nil {
				tb.Fatal(err)
			}
		}
	}
}

// headEpoch returns the number of the head epoch of mailbox mbx.
func headEpoch(tb testing.TB, st *store.Store, mbx store.ID) uint32 {
	tb.Helper()
	m, err := st.ReadMailbox(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	return m.Epoch
}

// removeSegments deletes every index segment of mailbox mbx.
func removeSegments(tb testing.TB, st *store.Store, mbx store.ID) {
	tb.Helper()
	for n := uint32(1); n <= headEpoch(tb, st, mbx); n++ {
		refs, err := st.ListIndexSegments(mbx, n)
		if err != nil {
			tb.Fatal(err)
		}
		for _, r := range refs {
			if err := os.Remove(st.IndexSegmentFile(mbx, n, r.Device, r.Seq)); err != nil {
				tb.Fatal(err)
			}
		}
	}
}

// segmentStat is the state of index/ of a mailbox: the number of
// segments and their bytes on the disk, over all epochs.
type segmentStat struct {
	Mails    int // mails client.Index put into segments in this run
	Segments int
	Bytes    int64
}

// segmentStats reads the segments of every epoch of mailbox mbx through
// store (ListIndexSegments, IndexSegmentFile).
func segmentStats(tb testing.TB, st *store.Store, mbx store.ID) segmentStat {
	tb.Helper()
	var s segmentStat
	for n := uint32(1); n <= headEpoch(tb, st, mbx); n++ {
		refs, err := st.ListIndexSegments(mbx, n)
		if err != nil {
			tb.Fatal(err)
		}
		for _, r := range refs {
			fi, err := os.Stat(st.IndexSegmentFile(mbx, n, r.Device, r.Seq))
			if err != nil {
				tb.Fatal(err)
			}
			s.Segments++
			s.Bytes += fi.Size()
		}
	}
	return s
}

// mailIDs returns the IDs of every mail of mailbox mbx.
func mailIDs(tb testing.TB, st *store.Store, mbx store.ID) map[store.ID]bool {
	tb.Helper()
	folders, err := st.ListFolders(mbx)
	if err != nil {
		tb.Fatal(err)
	}
	out := map[store.ID]bool{}
	for _, f := range folders {
		ids, err := st.ListMails(mbx, f)
		if err != nil {
			tb.Fatal(err)
		}
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

// newIndexRig delivers n mails of the corpus into a fresh mailbox and
// stops ingest again. pending/ then holds what client.Index of point 2
// processes, returned as a snapshot:
//
//   - terms: the term lists of the ingest worker (5.4: one every
//     ingest.DefaultBatchSize mails, by age when the delivery moves the
//     clock to the next day, the rest at the final flush), no markers;
//   - unprocessed: only the markers ingest writes for every mail at the
//     commit. A high BatchAge alone does not keep them: the worker writes
//     a term list every ingest.DefaultBatchSize mails, and a larger
//     BatchSize is no way out, since a term list holds at most
//     store.MaxBatch (100) entries. So the worker does not run during the
//     delivery and nothing is flushed; the snapshot is taken before
//     ingest closes (Close turns the queued headers into term lists), and
//     pending/ is put back to it afterwards.
func newIndexRig(tb testing.TB, n int, kind string) (*rig, pendingFiles) {
	tb.Helper()
	r := newEnvRig(tb, CorpusRecipients...)
	corpus := Corpus(1, n, testenv.Start)
	var snap pendingFiles
	switch kind {
	case "terms":
		r.startIngest(tb)
		deliverCorpus(tb, r, corpus, true)
		r.stopIngest(tb)
		snap = snapshotPending(tb, r.st, r.mbx)
	case "unprocessed":
		r.startIngestWith(tb, false)
		deliverCorpus(tb, r, corpus, false)
		snap = snapshotPending(tb, r.st, r.mbx)
		r.stopIngest(tb)
		restorePending(tb, r.st, r.mbx, snap)
	default:
		tb.Fatalf("unknown kind %q", kind)
	}
	// A marker is named by the ID of its mail, a term list by a fresh ID.
	ids := mailIDs(tb, r.st, r.mbx)
	markers := 0
	for _, files := range snap {
		for id := range files {
			if ids[id] {
				markers++
			}
		}
	}
	if len(ids) != n || kind == "terms" && markers != 0 || kind == "unprocessed" && (markers != n || snap.count() != n) {
		tb.Fatalf("%s: %d mails, %d pending files, %d markers", kind, len(ids), snap.count(), markers)
	}
	return r, snap
}

// BenchmarkIndex is point 2 of docs/tasks/12: the cost of client.Index
// per mail over pending/ with term lists (terms) and with markers only
// (unprocessed, the client derives the terms from the metadata it reads
// and checks), µs/mail and allocations. One operation is client.Index
// over indexMails mails of the corpus; before every operation, outside
// the measured time, the segments are deleted and pending/ is put back
// as ingest left it. A first client.Index before the measurement
// creates the device ID of the client.
func BenchmarkIndex(b *testing.B) {
	for _, kind := range indexKinds {
		b.Run("pending="+kind, func(b *testing.B) {
			r, snap := newIndexRig(b, indexMails, kind)
			c := r.user.Client
			index := func() {
				if n, err := c.Index(r.mbx); err != nil || n != indexMails {
					b.Fatalf("indexed %d of %d: %v %v", n, indexMails, err, r.env.Warnings.Take())
				}
			}
			reset := func() {
				removeSegments(b, r.st, r.mbx)
				restorePending(b, r.st, r.mbx, snap)
			}
			index()
			reset()
			b.ReportAllocs()
			var m0, m1 runtime.MemStats
			var mallocs, bytes uint64
			for b.Loop() {
				b.StopTimer()
				runtime.ReadMemStats(&m0)
				b.StartTimer()
				index()
				b.StopTimer()
				runtime.ReadMemStats(&m1)
				mallocs += m1.Mallocs - m0.Mallocs
				bytes += m1.TotalAlloc - m0.TotalAlloc
				reset()
				b.StartTimer()
			}
			mails := float64(b.N * indexMails)
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/1e3/mails, "µs/mail")
			b.ReportMetric(float64(mallocs)/mails, "allocs/mail")
			b.ReportMetric(float64(bytes)/mails, "B/mail")
		})
	}
}

// TestIndex runs the setup of BenchmarkIndex with few mails and checks
// that client.Index takes every mail in both kinds, and that putting
// pending/ back makes it take them again.
func TestIndex(t *testing.T) {
	n := 40
	if !testing.Short() {
		n = 200
	}
	for _, kind := range indexKinds {
		t.Run(kind, func(t *testing.T) {
			r, snap := newIndexRig(t, n, kind)
			for round := range 2 {
				got, err := r.user.Client.Index(r.mbx)
				if err != nil || got != n {
					t.Fatalf("round %d: indexed %d of %d: %v %v", round, got, n, err, r.env.Warnings.Take())
				}
				if left := snapshotPending(t, r.st, r.mbx).count(); left != 0 {
					t.Fatalf("round %d: %d pending files left", round, left)
				}
				if s := segmentStats(t, r.st, r.mbx); s.Segments == 0 || s.Bytes == 0 {
					t.Fatalf("round %d: %+v", round, s)
				}
				removeSegments(t, r.st, r.mbx)
				restorePending(t, r.st, r.mbx, snap)
			}
		})
	}
}

// segmentsStart is the start of the corpus of point 3: its 30 days are
// November 2026, one epoch of the mailbox (the client creates the
// epochs of the next months with the mailbox), so all segments belong
// to one epoch and the merge sets in at client.MergeThreshold segments.
var segmentsStart = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// indexSegmentRuns delivers n mails of the corpus in
// client.MergeThreshold-1 parts in the order of receipt, each through
// ingest with the worker and a final flush, and runs client.Index after
// each part: index/ then holds one segment per part, all n mails
// unmerged. Run client.MergeThreshold indexes the term lists of part 1
// once more (pending/ put back as after the delivery of part 1, the same
// mails), so its segment is the MergeThreshold-th and the client merges
// them in the same run; the merge drops the duplicate mail IDs, so the
// merged segments hold the same n mails. It returns the state of index/
// after every run (bytes of all index/<n>/<device>-<seq>.gml).
func indexSegmentRuns(tb testing.TB, n int) []segmentStat {
	tb.Helper()
	parts := client.MergeThreshold - 1
	if n < parts {
		tb.Fatalf("%d mails for %d parts", n, parts)
	}
	r := newEnvRig(tb, CorpusRecipients...)
	r.startIngest(tb)
	corpus := Corpus(1, n, segmentsStart)
	var first pendingFiles
	var out []segmentStat
	index := func(want int) {
		got, err := r.user.Client.Index(r.mbx)
		if err != nil || got != want {
			tb.Fatalf("run %d: indexed %d of %d: %v %v", len(out)+1, got, want, err, r.env.Warnings.Take())
		}
		s := segmentStats(tb, r.st, r.mbx)
		s.Mails = got
		out = append(out, s)
	}
	for p := range parts {
		part := corpus[p*n/parts : (p+1)*n/parts]
		deliverCorpus(tb, r, part, true)
		if p == 0 {
			first = snapshotPending(tb, r.st, r.mbx)
		}
		index(len(part))
	}
	restorePending(tb, r.st, r.mbx, first)
	index(n / parts)
	return out
}

// BenchmarkIndexSegments is point 3 of docs/tasks/12: bytes on the disk
// of the index segments per 1,000 mails of the corpus (10 senders, 3
// recipients, 30 days, 20 % attachments, threads), per segment and
// merged (indexSegmentRuns). One operation is the whole procedure; run
// it with -benchtime=1x. The sizes do not depend on the machine.
func BenchmarkIndexSegments(b *testing.B) {
	const n = 1000
	b.Run("mails=1000", func(b *testing.B) {
		var runs []segmentStat
		for b.Loop() {
			runs = indexSegmentRuns(b, n)
		}
		before, merged := runs[len(runs)-2], runs[len(runs)-1]
		b.ReportMetric(float64(before.Segments), "segments")
		b.ReportMetric(float64(before.Bytes)/float64(before.Segments), "B/segment")
		b.ReportMetric(float64(before.Bytes), "B-unmerged")
		b.ReportMetric(float64(merged.Segments), "segments-merged")
		b.ReportMetric(float64(merged.Bytes), "B-merged")
	})
}

// TestIndexSegments runs indexSegmentRuns briefly and checks it: one new
// segment per run before the merge, growing bytes, the sizes read
// through store equal to those of every *.gml in index/<n>/ and to the
// length ReadIndexSegment returns, and after run MergeThreshold fewer
// segments with fewer bytes than the unmerged ones.
func TestIndexSegments(t *testing.T) {
	n := 160
	if !testing.Short() {
		n = 1000
	}
	runs := indexSegmentRuns(t, n)
	if len(runs) != client.MergeThreshold {
		t.Fatalf("%d runs", len(runs))
	}
	mails := 0
	for i, s := range runs[:len(runs)-1] {
		mails += s.Mails
		if s.Segments != i+1 || i > 0 && s.Bytes <= runs[i-1].Bytes {
			t.Fatalf("run %d: %+v after %+v", i+1, s, runs[max(i-1, 0)])
		}
	}
	before, merged := runs[len(runs)-2], runs[len(runs)-1]
	if mails != n || merged.Segments == 0 || merged.Segments >= before.Segments || merged.Bytes >= before.Bytes {
		t.Fatalf("%d mails; before the merge %+v, after %+v", mails, before, merged)
	}
	t.Logf("%d mails: %d segments with %d bytes (%d per segment), merged %d segments with %d bytes",
		n, before.Segments, before.Bytes, before.Bytes/int64(before.Segments), merged.Segments, merged.Bytes)
}

// TestSegmentStats checks segmentStats against the files of index/<n>/
// and against ReadIndexSegment.
func TestSegmentStats(t *testing.T) {
	r, _ := newIndexRig(t, 30, "terms")
	if _, err := r.user.Client.Index(r.mbx); err != nil {
		t.Fatal(err)
	}
	s := segmentStats(t, r.st, r.mbx)
	var glob, read int64
	files := 0
	for n := uint32(1); n <= headEpoch(t, r.st, r.mbx); n++ {
		names, err := filepath.Glob(filepath.Join(r.st.IndexDir(r.mbx, n), "*.gml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range names {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			glob += fi.Size()
			files++
		}
		refs, err := r.st.ListIndexSegments(r.mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range refs {
			data, err := r.st.ReadIndexSegment(r.mbx, n, ref.Device, ref.Seq)
			if err != nil {
				t.Fatal(err)
			}
			read += int64(len(data))
		}
	}
	if s.Segments == 0 || s.Segments != files || s.Bytes != glob || s.Bytes != read {
		t.Fatalf("%+v; %d files with %d bytes, %d bytes read", s, files, glob, read)
	}
}
