package bench

import (
	"fmt"
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

// segmentMails is the number of corpus mails of BenchmarkIndexSegments
// (its sub-benchmark mails=<segmentMails>).
const segmentMails = 1000

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
// pending/ back makes it take them again. The client stays open and its
// directory as it is: since task 09g it indexes every pending entry that
// checks and writes what no segment holds, so with the segments deleted
// each round indexes every mail again, as in the first round (tasks 09d
// to 09f noted the mails as indexed, and task 09f put the client
// directory back for that).
func TestIndex(t *testing.T) {
	n := 40
	if !testing.Short() {
		n = 200
	}
	for _, kind := range indexKinds {
		t.Run(kind, func(t *testing.T) {
			r, snap := newIndexRig(t, n, kind)
			for round := range 3 {
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
// client.MergeThreshold parts in the order of receipt, each through
// ingest with the worker and a final flush, and runs client.Index after
// each part: index/ then holds one segment per part. The Index of the
// last part writes the client.MergeThreshold-th segment and merges the
// segments in the same run. To see index/ right before the merge, the
// test holds the mailbox lock during that Index: the client writes its
// segment (Index takes no lock for that) and then waits for the lock in
// the merge; once the segments of all n mails are there, their sizes are
// taken and the lock is released. It returns the state of index/ after
// every run before the last, right before the merge (all n mails
// unmerged in client.MergeThreshold segments) and after the merge (bytes
// of all index/<n>/<device>-<seq>.gml).
//
// Before task 09d, run client.MergeThreshold indexed the term lists of
// part 1 once more to get the segment that starts the merge. Since then
// the client writes no posting a segment holds, and the segment of part
// 1 is there, so the merge needs a segment with new mails, as in
// production.
func indexSegmentRuns(tb testing.TB, n int) []segmentStat {
	tb.Helper()
	parts := client.MergeThreshold
	if n < parts {
		tb.Fatalf("%d mails for %d parts", n, parts)
	}
	r := newEnvRig(tb, CorpusRecipients...)
	r.startIngest(tb)
	corpus := Corpus(1, n, segmentsStart)
	var out []segmentStat
	for p := range parts {
		part := corpus[p*n/parts : (p+1)*n/parts]
		deliverCorpus(tb, r, part, true)
		if p < parts-1 {
			got, err := r.user.Client.Index(r.mbx)
			if err != nil || got != len(part) {
				tb.Fatalf("run %d: indexed %d of %d: %v %v", p+1, got, len(part), err, r.env.Warnings.Take())
			}
			s := segmentStats(tb, r.st, r.mbx)
			s.Mails = got
			out = append(out, s)
			continue
		}
		before, after, got := indexHeld(tb, r, parts)
		if got != len(part) {
			tb.Fatalf("run %d: indexed %d of %d: %v", p+1, got, len(part), r.env.Warnings.Take())
		}
		before.Mails, after.Mails = got, got
		out = append(out, before, after)
	}
	return out
}

// indexHeld runs client.Index while the test holds the mailbox lock and
// returns the state of index/ once it holds segments segments (the
// client waits for the lock in the merge then), the state after the
// Index, and the number of entries it indexed.
func indexHeld(tb testing.TB, r *rig, segments int) (before, after segmentStat, got int) {
	tb.Helper()
	unlock, err := r.st.LockMailbox(r.mbx)
	if err != nil {
		tb.Fatal(err)
	}
	locked := true
	release := func() {
		if locked {
			locked = false
			unlock()
		}
	}
	defer release()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := r.user.Client.Index(r.mbx)
		done <- result{n, err}
	}()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if before = segmentStats(tb, r.st, r.mbx); before.Segments >= segments {
			break
		}
		select {
		case res := <-done:
			tb.Fatalf("Index returned before the merge: %d %v, %+v", res.n, res.err, before)
		default:
		}
		if time.Now().After(deadline) {
			release()
			<-done
			tb.Fatalf("no segment %d within the deadline: %+v", segments, before)
		}
		time.Sleep(time.Millisecond)
	}
	release()
	res := <-done
	if res.err != nil {
		tb.Fatal(res.err)
	}
	return before, segmentStats(tb, r.st, r.mbx), res.n
}

// BenchmarkIndexSegments is point 3 of docs/tasks/12: bytes on the disk
// of the index segments per 1,000 mails of the corpus (10 senders, 3
// recipients, 30 days, 20 % attachments, threads), per segment and
// merged (indexSegmentRuns): unmerged are the client.MergeThreshold
// segments of all mails right before the merge. One operation is the
// whole procedure; run it with -benchtime=1x. The sizes do not depend on
// the machine.
func BenchmarkIndexSegments(b *testing.B) {
	const n = segmentMails
	b.Run(fmt.Sprintf("mails=%d", n), func(b *testing.B) {
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
// segment per run up to the merge, growing bytes, client.Index took n
// entries over all runs, and after the merge fewer segments with fewer
// bytes than the unmerged ones. Which mails a segment holds is not read
// here. TestSegmentStats checks the sizes against the files and
// ReadIndexSegment.
func TestIndexSegments(t *testing.T) {
	n := 160
	if !testing.Short() {
		n = 1000
	}
	runs := indexSegmentRuns(t, n)
	if len(runs) != client.MergeThreshold+1 {
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
