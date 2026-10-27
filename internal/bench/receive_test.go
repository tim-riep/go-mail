package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// receiveConns are the numbers of simultaneous connections of point 1.
var receiveConns = []int{1, 4}

// receiveModes are the modes of point 1: enc is smtpd + ingest
// (everything), proto the same file and fsync protocol, including the
// space check and the term lists of the worker, without cryptography
// (protoSink), plain the minimal sink (fileSink). The costs of the
// encryption are enc - proto, those of the protocol proto - plain.
var receiveModes = []string{"enc", "proto", "plain"}

// newReceiveRig starts the server of mode for mails of size class sz.
func newReceiveRig(tb testing.TB, mode string, sz Size, msg []byte) *rig {
	tb.Helper()
	switch mode {
	case "enc":
		return newIngestRig(tb, BenchTo)
	case "proto":
		return newProtoRig(tb, sz, msg)
	case "plain":
		return newPlainRig(tb)
	}
	tb.Fatalf("unknown mode %q", mode)
	return nil
}

// traceMarkEnv names a path that runReceive looks up with os.Stat (the
// file need not exist) as <path>.start right before and <path>.stop
// right after the measured window, so that a system call trace (strace
// -e trace=newfstatat,...) can cut the window out. Unset, nothing is
// looked up.
const traceMarkEnv = "GOMAIL_BENCH_TRACE_MARK"

// runReceive sends n copies of msg over conns connections and returns
// the time from the first MAIL FROM to the last 250.
func runReceive(tb testing.TB, r *rig, conns, n int, msg []byte, timer func(on bool)) time.Duration {
	tb.Helper()
	ss, err := dialSenders(r.addr, conns)
	if err != nil {
		tb.Fatal(err)
	}
	defer closeSenders(ss)
	mark := os.Getenv(traceMarkEnv)
	timer(true)
	if mark != "" {
		os.Stat(mark + ".start")
	}
	start := time.Now()
	err = sendAll(ss, n, BenchFrom, []string{BenchTo}, msg)
	d := time.Since(start)
	if mark != "" {
		os.Stat(mark + ".stop")
	}
	timer(false)
	if err != nil {
		tb.Fatal(err)
	}
	// The preprocessing of this run (the open term list and the removal
	// of its markers) must not spill into the next; the protocol sink
	// also deletes the files of the run here.
	if r.in != nil {
		if err := r.in.Flush(); err != nil {
			tb.Fatal(err)
		}
	}
	if r.proto != nil {
		if err := r.proto.flush(); err != nil {
			tb.Fatal(err)
		}
	}
	return d
}

// BenchmarkReceive measures point 1 of docs/tasks/12: mails per second
// and MiB/s through smtpd over net/smtp on 127.0.0.1, with encryption
// (ingest, mode=enc), with the same file and fsync protocol but without
// cryptography (mode=proto) and with a minimal file sink (mode=plain),
// all in the benchmark's temporary directory, per size class and for 1
// and 4 simultaneous connections. One operation is one mail; the
// connections stay open across mails. With GOMAIL_BENCH_TRACE_MARK set,
// the measured window is marked for a system call trace (traceMarkEnv).
func BenchmarkReceive(b *testing.B) {
	for _, mode := range receiveModes {
		b.Run("mode="+mode, func(b *testing.B) {
			for _, sz := range Sizes {
				b.Run("size="+sz.Name, func(b *testing.B) {
					msg, err := Mail(sz, 1)
					if err != nil {
						b.Fatal(err)
					}
					// One server per size class: the data directory and
					// its mails go away after the class.
					r := newReceiveRig(b, mode, sz, msg)
					for _, conns := range receiveConns {
						b.Run(fmt.Sprintf("conns=%d", conns), func(b *testing.B) {
							b.SetBytes(int64(len(msg)))
							b.StopTimer()
							b.ResetTimer()
							d := runReceive(b, r, conns, b.N, msg, func(on bool) {
								if on {
									b.StartTimer()
								} else {
									b.StopTimer()
								}
							})
							b.ReportMetric(rate(float64(b.N), d), "mails/s")
							b.ReportMetric(rate(float64(b.N)*float64(len(msg))/(1<<20), d), "MiB/s")
						})
					}
				})
			}
		})
	}
}

// TestReceive runs the harness of BenchmarkReceive briefly in every mode
// and checks that every mail arrived (enc), went through the protocol
// and left no file behind (proto) or was written and unlinked (plain).
// The sinks write only below the test's temporary directory.
func TestReceive(t *testing.T) {
	sizes := Sizes[:2]
	if !testing.Short() {
		sizes = Sizes
	}
	for _, mode := range receiveModes {
		t.Run(mode, func(t *testing.T) {
			// Every t.TempDir of this test lies below tmp, which the
			// test removes at its end.
			tmp := filepath.Dir(t.TempDir())
			for _, sz := range sizes {
				msg, err := Mail(sz, 1)
				if err != nil {
					t.Fatal(err)
				}
				r := newReceiveRig(t, mode, sz, msg)
				want := 0
				for _, conns := range receiveConns {
					runReceive(t, r, conns, conns, msg, func(bool) {})
					want += conns
				}
				switch mode {
				case "enc":
					mails, err := r.env.Store.ListMails(r.mbx, mailboxInbox(t, r))
					if err != nil || len(mails) != want {
						t.Fatalf("delivered %d of %d: %v", len(mails), want, err)
					}
				case "proto":
					p := r.proto
					if n := p.open.Load(); n != 0 {
						t.Fatalf("%d deliveries left open", n)
					}
					if n := p.mails.Load(); n != int64(want) {
						t.Fatalf("committed %d of %d", n, want)
					}
					if n := p.bytes.Load(); n < int64(want*len(msg)) {
						t.Fatalf("received %d bytes, sent %d", n, want*len(msg))
					}
					inTemp(t, p.st.Root, tmp)
					assertNoFiles(t, p.st.Root)
				case "plain":
					if n := r.sink.open.Load(); n != 0 {
						t.Fatalf("%d deliveries left open", n)
					}
					if r.sink.bytes.Load() == 0 {
						t.Fatal("nothing written")
					}
					inTemp(t, r.sink.dir, tmp)
					assertEmptyDir(t, r.sink.dir)
				}
			}
		})
	}
}

// inTemp fails tb unless dir lies below tmp.
func inTemp(tb testing.TB, dir, tmp string) {
	tb.Helper()
	rel, err := filepath.Rel(tmp, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		tb.Fatalf("%s is not below the temporary directory %s", dir, tmp)
	}
}
