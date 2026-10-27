package bench

import (
	"testing"

	"github.com/tim-riep/go-mail/internal/testenv"
)

// skipIndex is the reason of the placeholders below: client.Index comes
// with task 09; task 12b fills them in.
const skipIndex = "client.Index: task 09"

// BenchmarkIndex is point 2 of docs/tasks/12: the cost of client.Index
// per mail over pending/ with term lists (terms) and with "unprocessed"
// markers (unprocessed), µs/mail and allocations. The corpus is built
// already, so its cost never shows up in a later measurement.
func BenchmarkIndex(b *testing.B) {
	for _, kind := range []string{"terms", "unprocessed"} {
		b.Run("pending="+kind, func(b *testing.B) {
			_ = Corpus(1, 1000, testenv.Start)
			b.Skip(skipIndex)
		})
	}
}

// BenchmarkIndexSegments is point 3 of docs/tasks/12: bytes on the disk
// per index segment and merged, per 1,000 mails of the corpus (10
// senders, 3 recipients, 30 days, 20 % attachments, threads).
func BenchmarkIndexSegments(b *testing.B) {
	b.Run("mails=1000", func(b *testing.B) {
		_ = Corpus(1, 1000, testenv.Start)
		b.Skip(skipIndex)
	})
}

// TestIndexSegments will check the segment sizes of BenchmarkIndexSegments
// against the corpus in short form.
func TestIndexSegments(t *testing.T) {
	t.Skip(skipIndex)
}
