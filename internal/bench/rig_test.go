package bench

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
)

// benchMinFree replaces the 10 % free space limit of ingest (5.1,
// ingest.DefaultMinFree) in the benchmarks: a shared build machine often
// has less free space than that, and the limit is not what is measured.
// The file system's statistics are still read at MAIL and at DATA as in
// production, by ingest and by the protocol sink.
const benchMinFree = 0.01

// benchMaxConns is MaxConns and MaxConnsPerIP of the benchmark server.
// It loosens 5.1: the default is 20 connections in total
// (smtpd.DefaultMaxConns) and 5 per IP (smtpd.DefaultMaxConnsPerIP).
// GOMAIL_BENCH_MEM_CONNS is bounded by it (memConns).
const benchMaxConns = 64

// smtpConfig are the limits of the benchmark server: the defaults of 5.1
// with three loosenings, all named in the table of scripts/bench.sh:
// MaxConns 64 instead of 20 in total, MaxConnsPerIP 64 instead of 5 and
// no hourly mail limit per IP; the limits per IP would refuse a load
// generator on 127.0.0.1. The fourth loosening of 5.1 is in ingestConfig:
// MinFree 1 % instead of 10 % (benchMinFree).
func smtpConfig() smtpd.Config {
	return smtpd.Config{
		Hostname: "mx.bench.example", MaxConns: benchMaxConns, MaxConnsPerIP: benchMaxConns,
		MaxMailsPerIP: math.MaxInt32, Logger: slog.New(slog.DiscardHandler),
	}
}

// rig is a running SMTP server on 127.0.0.1 with its backend.
type rig struct {
	env  *testenv.Env  // nil for the sinks and newPlatformRig
	user *testenv.User // owner of mbx, with env
	mbx  store.ID      // mailbox of the recipient addresses, with env

	// What ingest needs; set by newEnvRig and newPlatformRig.
	st        *store.Store
	log       translog.Log
	ingestKey ed25519.PrivateKey
	now       func() time.Time

	in    *ingest.Ingest // set for mode enc
	sink  *fileSink      // set for mode plain
	proto *protoSink     // set for mode proto
	srv   *smtpd.Server
	addr  string
}

// newEnvRig builds a development platform with one user and one mailbox
// holding addrs, without a server.
func newEnvRig(tb testing.TB, addrs ...string) *rig {
	tb.Helper()
	env := testenv.New(tb)
	u := env.NewUser("bench")
	mbx := env.Mailbox(u, "Bench", addrs...)
	return &rig{env: env, user: u, mbx: mbx, st: env.Store, log: env.Log, ingestKey: env.IngestKey, now: env.Clock.Now}
}

// ingestConfig is the configuration of ingest in the benchmarks: the
// defaults of 5.1 to 5.4 with one loosening, named in the table of
// scripts/bench.sh: MinFree 1 % instead of 10 % (benchMinFree). The
// worker writes a term list every ingest.DefaultBatchSize mails, as in
// production.
func (r *rig) ingestConfig() ingest.Config {
	return ingest.Config{
		Store: r.st, Log: r.log, IngestKey: r.ingestKey, IngestGen: 1,
		Now: r.now, Logger: slog.New(slog.DiscardHandler), MinFree: benchMinFree,
	}
}

// startIngest starts ingest on the rig's data directory with its worker.
// Only one ingest per data directory and process (server lock, 9.1).
func (r *rig) startIngest(tb testing.TB) {
	tb.Helper()
	r.startIngestWith(tb, true)
}

// startIngestWith is startIngest; without worker, ingest queues the
// headers but turns none into a term list before Flush or Close, so
// every mail keeps its marker in pending/ until then.
func (r *rig) startIngestWith(tb testing.TB, worker bool) {
	tb.Helper()
	in, err := ingest.New(r.ingestConfig())
	if err != nil {
		tb.Fatal(err)
	}
	if err := in.Recover(); err != nil {
		in.Close()
		tb.Fatal(err)
	}
	if worker {
		in.Start()
	}
	r.in = in
	tb.Cleanup(func() { r.stopIngest(tb) })
}

// stopIngest flushes and closes ingest; it may be called more than once.
func (r *rig) stopIngest(tb testing.TB) {
	if r.in == nil {
		return
	}
	if err := r.in.Flush(); err != nil {
		tb.Error(err)
	}
	if err := r.in.Close(); err != nil {
		tb.Error(err)
	}
	r.in = nil
}

// serve starts the SMTP server for backend b on 127.0.0.1.
func (r *rig) serve(tb testing.TB, b smtpd.Backend) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	r.srv = smtpd.NewServer(smtpConfig(), b)
	r.addr = ln.Addr().String()
	go r.srv.Serve(ln)
	// Registered after startIngest's cleanup, so it runs first.
	tb.Cleanup(func() { r.srv.Close() })
}

// newIngestRig is smtpd with ingest: the encrypted path of point 1.
func newIngestRig(tb testing.TB, addrs ...string) *rig {
	tb.Helper()
	r := newEnvRig(tb, addrs...)
	r.startIngest(tb)
	r.serve(tb, r.in)
	return r
}

// newPlainRig is smtpd with the file sink: the path without encryption.
func newPlainRig(tb testing.TB) *rig {
	tb.Helper()
	r := &rig{sink: &fileSink{dir: tb.TempDir()}}
	r.serve(tb, r.sink)
	return r
}

// fileSink is the benchmark backend without encryption: it writes the
// stream of every message into a file in the benchmark's temporary
// directory and syncs it at Commit, as ingest makes a mail durable
// before 250. The file is unlinked right after it is created, so no
// message ever stays on the disk, not even after a crash.
type fileSink struct {
	dir   string
	open  atomic.Int64 // deliveries not yet committed or aborted
	bytes atomic.Int64 // bytes written in total
}

func (s *fileSink) Accepting() error       { return nil }
func (s *fileSink) Recipient(string) error { return nil }

func (s *fileSink) Begin(smtpd.Session, string, []string) (smtpd.Delivery, error) {
	f, err := os.CreateTemp(s.dir, "plain-*")
	if err != nil {
		return nil, smtpd.ErrTemporary
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, smtpd.ErrTemporary
	}
	s.open.Add(1)
	// The buffer matches the block-wise writes of ingest; smtpd writes
	// line by line.
	return &fileDelivery{s: s, f: f, w: bufio.NewWriterSize(f, 64<<10)}, nil
}

type fileDelivery struct {
	s    *fileSink
	f    *os.File
	w    *bufio.Writer
	done bool
}

func (d *fileDelivery) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	d.s.bytes.Add(int64(n))
	return n, err
}

func (d *fileDelivery) finish() {
	if !d.done {
		d.done = true
		d.f.Close()
		d.s.open.Add(-1)
	}
}

func (d *fileDelivery) Commit() error {
	defer d.finish()
	if err := d.w.Flush(); err != nil {
		return smtpd.ErrTemporary
	}
	if err := d.f.Sync(); err != nil {
		return smtpd.ErrTemporary
	}
	return nil
}

func (d *fileDelivery) Abort() { d.finish() }

// sender is one SMTP client connection of the load generator.
type sender struct{ c *smtp.Client }

func dialSender(addr string) (*sender, error) {
	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, err
	}
	if err := c.Hello("client.bench.example"); err != nil {
		c.Close()
		return nil, err
	}
	return &sender{c: c}, nil
}

// send transmits one message and waits for the 250 after DATA.
func (s *sender) send(from string, to []string, msg []byte) error {
	if err := s.c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := s.c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := s.c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

func (s *sender) close() {
	s.c.Quit()
	s.c.Close()
}

// dialSenders opens conns connections to addr.
func dialSenders(addr string, conns int) ([]*sender, error) {
	out := make([]*sender, 0, conns)
	for range conns {
		s, err := dialSender(addr)
		if err != nil {
			closeSenders(out)
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func closeSenders(ss []*sender) {
	for _, s := range ss {
		s.close()
	}
}

// sendAll sends n copies of msg over the connections in ss at the same
// time; mail i goes over connection i mod len(ss).
func sendAll(ss []*sender, n int, from string, to []string, msg []byte) error {
	var wg sync.WaitGroup
	errs := make([]error, len(ss))
	for k, s := range ss {
		count := n / len(ss)
		if k < n%len(ss) {
			count++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range count {
				if err := s.send(from, to, msg); err != nil {
					errs[k] = fmt.Errorf("connection %d: %w", k, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// lookupEnvInt reads a positive integer from the environment; def if
// the variable is unset or empty.
func lookupEnvInt(name string, def int) (int, error) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 10_000_000 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}

// envInt is lookupEnvInt that fails tb on a malformed value.
func envInt(tb testing.TB, name string, def int) int {
	tb.Helper()
	n, err := lookupEnvInt(name, def)
	if err != nil {
		tb.Fatal(err)
	}
	return n
}

// memConnsEnv sets the number of connections of point 5.
const memConnsEnv = "GOMAIL_BENCH_MEM_CONNS"

// memConns reads GOMAIL_BENCH_MEM_CONNS (default 20, as in point 5) and
// refuses more connections than the benchmark server accepts, which
// would otherwise end in a dial error.
func memConns() (int, error) {
	n, err := lookupEnvInt(memConnsEnv, 20)
	if err != nil {
		return 0, err
	}
	if err := checkConns(n); err != nil {
		return 0, fmt.Errorf("%s=%d: %w", memConnsEnv, n, err)
	}
	return n, nil
}

// checkConns refuses more load connections than MaxConns.
func checkConns(n int) error {
	if n > benchMaxConns {
		return fmt.Errorf("conns > MaxConns (%d)", benchMaxConns)
	}
	return nil
}

// mib converts bytes to MiB.
func mib(b uint64) float64 { return float64(b) / (1 << 20) }

// rate returns count per second over d.
func rate(count float64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return count / d.Seconds()
}
