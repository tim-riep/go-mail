package bench

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// deliverWorkers deliver the corpus of the Sync benchmark in parallel.
const deliverWorkers = 8

// mailboxInbox returns the inbox folder of the rig's mailbox.
func mailboxInbox(tb testing.TB, r *rig) store.ID {
	tb.Helper()
	m, err := r.env.Store.ReadMailbox(r.mbx)
	if err != nil {
		tb.Fatal(err)
	}
	return m.Inbox
}

func assertEmptyDir(tb testing.TB, dir string) {
	tb.Helper()
	e, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatal(err)
	}
	if len(e) != 0 {
		tb.Fatalf("%d files left in %s", len(e), dir)
	}
}

// deliverCorpus delivers the corpus through ingest directly (the setup
// of the Sync and index benchmarks, not a measurement): day by day, with
// the clock set to the receipt time of the day's first mail, the mails
// of a day in parallel. With flush, the open term lists of the worker
// are written at the end (ingest.Flush).
func deliverCorpus(tb testing.TB, r *rig, mails []CorpusMail, flush bool) {
	tb.Helper()
	for i := 0; i < len(mails); {
		j := i
		y, m, d := mails[i].Received.Date()
		for j < len(mails) {
			y2, m2, d2 := mails[j].Received.Date()
			if y2 != y || m2 != m || d2 != d {
				break
			}
			j++
		}
		r.env.Clock.Set(mails[i].Received)
		day := mails[i:j]
		var wg sync.WaitGroup
		errs := make([]error, deliverWorkers)
		for w := range deliverWorkers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := w; k < len(day); k += deliverWorkers {
					if err := deliverOne(r, &day[k]); err != nil {
						errs[w] = fmt.Errorf("mail %d: %w", k, err)
						return
					}
				}
			}()
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			tb.Fatal(err)
		}
		i = j
	}
	if !flush {
		return
	}
	if err := r.in.Flush(); err != nil {
		tb.Fatal(err)
	}
}

func deliverOne(r *rig, m *CorpusMail) error {
	d, err := r.in.Begin(smtpd.Session{ID: "bench", Helo: "client.bench.example", RemoteIP: "127.0.0.1"}, m.EnvelopeFrom, m.Rcpts)
	if err != nil {
		return err
	}
	if _, err := d.Write(m.Data); err != nil {
		d.Abort()
		return err
	}
	return d.Commit()
}

// newSyncRig builds a mailbox holding the n mails of the corpus and
// stops ingest again; the client of r.user is open and has synced, so
// every mail is indexed and pending/ is empty. It also returns pending/
// as ingest left it after the delivery (the term lists of all mails).
func newSyncRig(tb testing.TB, n int) (*rig, pendingFiles) {
	tb.Helper()
	r := newEnvRig(tb, CorpusRecipients...)
	r.startIngest(tb)
	deliverCorpus(tb, r, Corpus(1, n, testenv.Start), true)
	r.stopIngest(tb)
	snap := snapshotPending(tb, r.st, r.mbx)
	if err := r.user.Client.Sync(); err != nil {
		tb.Fatal(err)
	}
	if w := r.env.Warnings.Take(); len(w) > 1 { // the --insecure-no-log warning
		tb.Fatalf("warnings after delivery: %d", len(w))
	}
	if left := snapshotPending(tb, r.st, r.mbx).count(); snap.count() == 0 || left != 0 {
		tb.Fatalf("pending files: %d after the delivery, %d after Sync", snap.count(), left)
	}
	return r, snap
}

// BenchmarkSync measures point 4 of docs/tasks/12: the duration of a
// client Sync of a mailbox holding GOMAIL_BENCH_SYNC_MAILS mails
// (default 10,000) of the corpus. Sync keeps the epoch supply and then
// runs client.Index. index=off is Sync with pending/ empty (the setup
// indexed every mail already): the supply and an Index that finds
// nothing to do. index=on is Sync with pending/ as ingest left it after
// the delivery (the term lists of all mails), so it indexes every mail;
// before every operation, outside the measured time, the segments are
// deleted and pending/ is put back. list is List over all mails of the
// inbox, the step whose cost grows with the number of mails as long as
// Sync does not read mails.
func BenchmarkSync(b *testing.B) {
	n := envInt(b, "GOMAIL_BENCH_SYNC_MAILS", 10_000)
	b.Run(fmt.Sprintf("mails=%d", n), func(b *testing.B) {
		r, snap := newSyncRig(b, n)
		b.Run("index=off", func(b *testing.B) {
			for b.Loop() {
				if err := r.user.Client.Sync(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(b.Elapsed().Seconds()/float64(b.N), "s/sync")
		})
		b.Run("index=on", func(b *testing.B) {
			reset := func() {
				removeSegments(b, r.st, r.mbx)
				restorePending(b, r.st, r.mbx, snap)
			}
			reset()
			for b.Loop() {
				if err := r.user.Client.Sync(); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if left := snapshotPending(b, r.st, r.mbx).count(); left != 0 {
					b.Fatalf("%d pending files left after Sync", left)
				}
				reset()
				b.StartTimer()
			}
			b.ReportMetric(b.Elapsed().Seconds()/float64(b.N), "s/sync")
			// The benchmarks after this one start from an indexed mailbox
			// again.
			if err := r.user.Client.Sync(); err != nil {
				b.Fatal(err)
			}
		})
		b.Run("list", func(b *testing.B) {
			for b.Loop() {
				l, err := r.user.Client.List(r.mbx, store.ID{})
				if err != nil || len(l) != n {
					b.Fatalf("listed %d of %d: %v", len(l), n, err)
				}
			}
			b.ReportMetric(b.Elapsed().Seconds()/float64(b.N), "s/list")
		})
	})
}

// TestSync runs the setup of BenchmarkSync with few mails and checks
// that every mail is listed, that Sync succeeds, and that Sync with
// pending/ put back (index=on) indexes every mail again.
func TestSync(t *testing.T) {
	n := 60
	if !testing.Short() {
		n = 300
	}
	r, snap := newSyncRig(t, n)
	if err := r.user.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	l, err := r.user.Client.List(r.mbx, store.ID{})
	if err != nil || len(l) != n {
		t.Fatalf("listed %d of %d: %v %v", len(l), n, err, r.env.Warnings.Take())
	}
	removeSegments(t, r.st, r.mbx)
	restorePending(t, r.st, r.mbx, snap)
	if err := r.user.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	if left := snapshotPending(t, r.st, r.mbx).count(); left != 0 {
		t.Fatalf("%d pending files left after Sync", left)
	}
	if s := segmentStats(t, r.st, r.mbx); s.Segments == 0 {
		t.Fatalf("no segments after Sync: %+v", s)
	}
}
