package bench

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/ingest"
	"github.com/tim-riep/go-mail/internal/smtpd"
)

// memSample is one reading of the process's memory.
type memSample struct {
	HeapInuse, Sys, RSS uint64
}

func readMem() memSample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return memSample{HeapInuse: ms.HeapInuse, Sys: ms.Sys, RSS: ReadVmRSS()}
}

func (m *memSample) max(o memSample) {
	m.HeapInuse = max(m.HeapInuse, o.HeapInuse)
	m.Sys = max(m.Sys, o.Sys)
	m.RSS = max(m.RSS, o.RSS)
}

// memInterval is the sampling interval of the peak; ReadMemStats stops
// the world briefly, so it is not much shorter.
const memInterval = 20 * time.Millisecond

// settleWait is how long the server idles before the base and before the
// resting value is read.
const settleWait = time.Second

// settle prepares the base and the resting value alike: the server idles
// for settleWait, then a garbage collection returns free memory to the
// system (debug.FreeOSMemory).
func settle() {
	time.Sleep(settleWait)
	debug.FreeOSMemory()
}

// memBaseNoiseMiB is how far the base values (HeapInuse, Sys and VmRSS)
// of separate runs of BenchmarkServerMemory may differ: the noise named
// in the table of scripts/bench.sh and checked by TestServerMemoryRuns.
// Sys grows in steps of 4 MiB (the heap's address space chunks): whether
// the setup of a run took one step more is chance, so the bound is one
// step and a little more.
const memBaseNoiseMiB = 5

// rssCarryTolMiB is the tolerance of the check that the base VmRSS of a
// run is not the peak of the run before (carriesPeak): VmRSS is read in
// pages and moves a little between readings, so a carried peak is not
// always the same number.
const rssCarryTolMiB = 1

// carriesPeak reports whether base, the base value of a run, is the peak
// of the run before within tol MiB: the sign of a run that started from
// the state the run before left.
func carriesPeak(base, peak, tol float64) bool { return math.Abs(base-peak) <= tol }

// rssRiseTolMiB bounds the rise of the base VmRSS from run 1 to run 2 of
// TestServerMemoryRuns: the bases of separate processes spread by less
// than 0.2 MiB (11.55, 11.40 and 11.51 MiB were read), while a run that
// shared the process of the run before started 1.5 MiB higher (11.88,
// then 13.40 MiB).
const rssRiseTolMiB = 1

// risesAbove reports whether base2, the base value of a run, lies more
// than tol MiB above base1, the base of the run before.
func risesAbove(base1, base2, tol float64) bool { return base2-base1 > tol }

// memResult holds the readings of one load run.
type memResult struct {
	Base, Peak, Rest memSample
	Elapsed          time.Duration
}

// runMemLoad starts smtpd + ingest on a platform built in a child
// process, sends mails copies of msg over conns connections and reads
// the memory before (base), during (peak) and after the load (rest);
// base and rest are both prepared by settle. The load generator runs in
// the same process; its share is the connections' buffers, msg itself is
// allocated before the base reading. BenchmarkServerMemory runs it in a
// process of its own (runMemLoadChild).
func runMemLoad(tb testing.TB, mails, conns int, msg []byte) memResult {
	tb.Helper()
	if err := checkConns(conns); err != nil {
		tb.Fatal(err)
	}
	r := newPlatformRig(tb)
	ss, err := dialSenders(r.addr, conns)
	if err != nil {
		tb.Fatal(err)
	}
	settle()
	var res memResult
	res.Base = readMem()
	res.Peak = res.Base
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(memInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				res.Peak.max(readMem())
			}
		}
	}()
	start := time.Now()
	err = sendAll(ss, mails, BenchFrom, []string{BenchTo}, msg)
	res.Elapsed = time.Since(start)
	closeSenders(ss)
	if err == nil {
		err = r.in.Flush()
	}
	close(stop)
	wg.Wait()
	if err != nil {
		tb.Fatal(err)
	}
	res.Peak.max(readMem())
	settle()
	res.Rest = readMem()
	return res
}

// Environment of the child process of runMemLoadChild: the file for the
// result and the load as "<size class> <mails> <conns>".
const (
	memLoadOutEnv  = "GOMAIL_BENCH_MEMLOAD_OUT"
	memLoadArgsEnv = "GOMAIL_BENCH_MEMLOAD_ARGS"
)

// runMemLoadChild runs runMemLoad in a new process of the test binary
// (TestMemLoadChild) and returns its readings. Every run starts from a
// fresh process, so Sys and VmRSS never carry the peak of an earlier run
// into the base of the next one (go test -count runs a benchmark several
// times in one process).
func runMemLoadChild(tb testing.TB, sz Size, mails, conns int) memResult {
	tb.Helper()
	out := filepath.Join(tb.TempDir(), "memload.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemLoadChild$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		memLoadOutEnv+"="+out,
		fmt.Sprintf("%s=%s %d %d", memLoadArgsEnv, sz.Name, mails, conns))
	if b, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("memory load in a child process: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		tb.Fatal(err)
	}
	var res memResult
	if err := json.Unmarshal(data, &res); err != nil {
		tb.Fatal(err)
	}
	return res
}

// TestMemLoadChild is the child process of runMemLoadChild, not a test
// of its own: it runs the load given in $GOMAIL_BENCH_MEMLOAD_ARGS and
// writes the readings (numbers only) as JSON into
// $GOMAIL_BENCH_MEMLOAD_OUT. It is skipped without them.
func TestMemLoadChild(t *testing.T) {
	out := os.Getenv(memLoadOutEnv)
	if out == "" {
		t.Skip("child process of BenchmarkServerMemory")
	}
	var name string
	var mails, conns int
	if n, err := fmt.Sscanf(os.Getenv(memLoadArgsEnv), "%s %d %d", &name, &mails, &conns); err != nil || n != 3 || mails <= 0 || conns <= 0 {
		t.Fatalf("%s: want \"<size> <mails> <conns>\"", memLoadArgsEnv)
	}
	sz, ok := SizeByName(name)
	if !ok {
		t.Fatalf("unknown size class %q", name)
	}
	msg, err := Mail(sz, 1)
	if err != nil {
		t.Fatal(err)
	}
	res := runMemLoad(t, mails, conns, msg)
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkServerMemory measures point 5 of docs/tasks/12: HeapInuse and
// Sys of runtime.MemStats and VmRSS of /proc/self/status while smtpd +
// ingest receive GOMAIL_BENCH_MEM_MAILS mails (default 1,000) over
// GOMAIL_BENCH_MEM_CONNS connections (default 20, at most MaxConns of
// the benchmark server): before the load (base), the peak during it
// (sampled every 20 ms) and the resting value after it (rest); base and
// rest are prepared alike (settle). One operation is the whole load in
// a process of its own (runMemLoadChild), so every run, also with
// -count, starts from the same state; run it with -benchtime=1x.
func BenchmarkServerMemory(b *testing.B) {
	mails := envInt(b, "GOMAIL_BENCH_MEM_MAILS", 1000)
	conns, err := memConns()
	if err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"64KiB", "1MiB"} {
		sz, _ := SizeByName(name)
		b.Run(fmt.Sprintf("size=%s/mails=%d/conns=%d", sz.Name, mails, conns), func(b *testing.B) {
			var peak, rest, base memSample
			var elapsed time.Duration
			for b.Loop() {
				res := runMemLoadChild(b, sz, mails, conns)
				base, rest = res.Base, res.Rest
				peak.max(res.Peak)
				elapsed += res.Elapsed
			}
			b.ReportMetric(rate(float64(b.N*mails), elapsed), "mails/s")
			b.ReportMetric(mib(base.HeapInuse), "heapinuse-base-MiB")
			b.ReportMetric(mib(peak.HeapInuse), "heapinuse-peak-MiB")
			b.ReportMetric(mib(rest.HeapInuse), "heapinuse-rest-MiB")
			b.ReportMetric(mib(base.Sys), "sys-base-MiB")
			b.ReportMetric(mib(peak.Sys), "sys-peak-MiB")
			b.ReportMetric(mib(rest.Sys), "sys-rest-MiB")
			b.ReportMetric(mib(base.RSS), "rss-base-MiB")
			b.ReportMetric(mib(peak.RSS), "rss-peak-MiB")
			b.ReportMetric(mib(rest.RSS), "rss-rest-MiB")
		})
	}
}

// TestServerMemory runs the load of BenchmarkServerMemory briefly in
// this process.
func TestServerMemory(t *testing.T) {
	mails := 40
	if !testing.Short() {
		mails = 200
	}
	msg, err := Mail(Sizes[0], 1)
	if err != nil {
		t.Fatal(err)
	}
	res := runMemLoad(t, mails, 20, msg)
	if res.Peak.HeapInuse < res.Base.HeapInuse || res.Peak.Sys == 0 || res.Rest.HeapInuse == 0 {
		t.Fatalf("readings %+v", res)
	}
	if runtime.GOOS == "linux" && (res.Peak.RSS == 0 || res.Rest.RSS == 0) {
		t.Fatalf("no VmRSS: %+v", res)
	}
}

// TestServerMemoryRuns runs BenchmarkServerMemory as go test -count=3
// -benchtime=1x with 20 mails of 1 MiB in a child process and checks
// that no run carries the memory of the one before.
//
// What the checks catch: Sys never shrinks within a process, so a run
// that shared the process of the run before has the Sys peak of that run
// as its base, exactly (21.18 MiB both were read); carriesPeak with
// tolerance 0 catches it. That is the check that detects carrying.
// HeapInuse and VmRSS go down again after a run (debug.FreeOSMemory), so
// a carried base lies only somewhat above a clean one, far below the peak
// of the run before (VmRSS 13.40 MiB after a peak above 20 MiB): the peak
// comparison does not see it, and the spread of the three bases
// (memBaseNoiseMiB) only from 5 MiB on. For VmRSS the rise of the base
// from run 1 to run 2 is bounded tighter, by rssRiseTolMiB (1 MiB):
// separate processes spread by less than 0.2 MiB, a carried run rose by
// 1.5 MiB. A carried HeapInuse below 5 MiB goes unnoticed.
func TestServerMemoryRuns(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkServerMemory$/^size=1MiB$",
		"-test.benchtime=1x", "-test.count=3")
	cmd.Env = append(os.Environ(), "GOMAIL_BENCH_MEM_MAILS=20", memConnsEnv+"=20")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("benchmark: %v\n%s", err, out)
	}
	runs := parseBenchLines(string(out), "BenchmarkServerMemory/size=1MiB/mails=20/conns=20")
	if len(runs) != 3 {
		t.Fatalf("%d runs in\n%s", len(runs), out)
	}
	for _, m := range []string{"heapinuse", "sys", "rss"} {
		lo, hi := runs[0][m+"-base-MiB"], runs[0][m+"-base-MiB"]
		for _, r := range runs {
			v, ok := r[m+"-base-MiB"]
			if !ok {
				t.Fatalf("no %s-base-MiB in %v", m, r)
			}
			lo, hi = min(lo, v), max(hi, v)
		}
		t.Logf("%s-base-MiB: %.2f %.2f %.2f; peak of run 1: %.2f", m,
			runs[0][m+"-base-MiB"], runs[1][m+"-base-MiB"], runs[2][m+"-base-MiB"], runs[0][m+"-peak-MiB"])
		if hi-lo > memBaseNoiseMiB {
			t.Errorf("%s-base-MiB of the runs spread by %.2f MiB, more than %d MiB", m, hi-lo, memBaseNoiseMiB)
		}
		tol := 0.0
		if m == "rss" {
			tol = rssCarryTolMiB
		}
		if carriesPeak(runs[1][m+"-base-MiB"], runs[0][m+"-peak-MiB"], tol) {
			t.Errorf("%s-base-MiB of run 2 (%.2f) is the peak of run 1 (%.2f) within %g MiB", m,
				runs[1][m+"-base-MiB"], runs[0][m+"-peak-MiB"], tol)
		}
	}
	if b1, b2 := runs[0]["rss-base-MiB"], runs[1]["rss-base-MiB"]; risesAbove(b1, b2, rssRiseTolMiB) {
		t.Errorf("rss-base-MiB rose from %.2f in run 1 to %.2f in run 2, more than %d MiB", b1, b2, rssRiseTolMiB)
	}
	// The load must show above the noise, or the checks above say
	// nothing: a base that carried the peak of the run before would lie
	// outside the noise.
	if d := runs[0]["rss-peak-MiB"] - runs[0]["rss-base-MiB"]; d <= memBaseNoiseMiB {
		t.Errorf("the load of run 1 raised VmRSS by %.2f MiB only", d)
	}
}

// TestCarriesPeak checks the checks of TestServerMemoryRuns with readings
// of this load (20 mails of 1 MiB over 20 connections; separate
// processes: VmRSS bases 11.70, 11.79 and 11.73 MiB after a peak of 22.86
// MiB, Sys bases 12.27 and 12.28 MiB after a peak of 21.18 MiB) and of
// runs that shared a process (VmRSS bases 11.88, 13.40 and 13.33 MiB, Sys
// bases 12.66, 21.18 and 25.18 MiB). A carried Sys is caught by the peak
// comparison, a carried VmRSS only by the rise from run 1 to run 2.
func TestCarriesPeak(t *testing.T) {
	for _, c := range []struct {
		name               string
		base1, base2, peak float64 // base of run 1 and 2, peak of run 1
		tol                float64 // tolerance of the peak comparison
		carried, rises     bool
	}{
		{"sys, separate processes", 12.27, 12.28, 21.18, 0, false, false},
		{"sys, one process", 12.66, 21.18, 21.18, 0, true, true},
		{"rss, separate processes", 11.70, 11.79, 22.86, rssCarryTolMiB, false, false},
		// The peak comparison misses a carried VmRSS; the rise catches it.
		{"rss, one process", 11.88, 13.40, 22.86, rssCarryTolMiB, false, true},
		{"rss, base read at the peak", 11.88, 22.40, 22.86, rssCarryTolMiB, true, true},
	} {
		if got := carriesPeak(c.base2, c.peak, c.tol); got != c.carried {
			t.Errorf("%s: carriesPeak(%.2f, %.2f, %g) = %v", c.name, c.base2, c.peak, c.tol, got)
		}
		if got := risesAbove(c.base1, c.base2, rssRiseTolMiB); got != c.rises {
			t.Errorf("%s: risesAbove(%.2f, %.2f) = %v", c.name, c.base1, c.base2, got)
		}
	}
}

// parseBenchLines returns the metrics (unit to value) of every result
// line of benchmark name in the output of go test -bench.
func parseBenchLines(out, name string) []map[string]float64 {
	var runs []map[string]float64
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || benchName(f[0]) != name {
			continue
		}
		m := map[string]float64{}
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				continue
			}
			m[f[i+1]] = v
		}
		runs = append(runs, m)
	}
	return runs
}

// benchName strips the -GOMAXPROCS suffix go test appends to the name
// of a benchmark result.
func benchName(s string) string {
	i := strings.LastIndexByte(s, '-')
	if i < 0 || i == len(s)-1 {
		return s
	}
	if _, err := strconv.Atoi(s[i+1:]); err != nil {
		return s
	}
	return s[:i]
}

// TestMemConns checks the bound of GOMAIL_BENCH_MEM_CONNS: more
// connections than MaxConns of the benchmark server are refused with a
// clear message instead of a dial error.
func TestMemConns(t *testing.T) {
	for _, c := range []struct {
		val  string
		want int
		err  string
	}{
		{"", 20, ""},
		{"1", 1, ""},
		{strconv.Itoa(benchMaxConns), benchMaxConns, ""},
		{strconv.Itoa(benchMaxConns + 1), 0, "conns > MaxConns (64)"},
		{"10000000", 0, "conns > MaxConns (64)"},
		{"0", 0, "positive integer"},
		{"x", 0, "positive integer"},
	} {
		t.Setenv(memConnsEnv, c.val)
		n, err := memConns()
		if c.err == "" {
			if err != nil || n != c.want {
				t.Errorf("%q: %d, %v; want %d", c.val, n, err, c.want)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%q: %d, %v; want an error with %q", c.val, n, err, c.err)
		}
	}
}

// TestBenchScriptLimits checks that the table of scripts/bench.sh names
// the limits of this package: MaxConns of the benchmark server, its
// missing hourly mail limit per IP, MinFree of ingest, the discarded
// logs, the term lists of mode proto and the noise of the base values;
// and that it has no row left that is still to come.
func TestBenchScriptLimits(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "bench.sh"))
	if err != nil {
		t.Fatal(err)
	}
	ic := (&rig{}).ingestConfig()
	if ic.MinFree != benchMinFree {
		t.Fatalf("ingestConfig has MinFree %g, the table names %g", ic.MinFree, benchMinFree)
	}
	c := smtpConfig()
	if c.MaxMailsPerIP != math.MaxInt32 {
		t.Fatalf("smtpConfig has MaxMailsPerIP %d, the table names no hourly limit", c.MaxMailsPerIP)
	}
	if c.Logger.Handler() != slog.DiscardHandler || ic.Logger.Handler() != slog.DiscardHandler {
		t.Fatal("the table says the logs are discarded")
	}
	for _, want := range []string{
		fmt.Sprintf("MaxConns %d statt %d", c.MaxConns, smtpd.DefaultMaxConns),
		fmt.Sprintf("MaxConnsPerIP %d statt %d", c.MaxConnsPerIP, smtpd.DefaultMaxConnsPerIP),
		"kein Mail-Limit je IP und Stunde",
		fmt.Sprintf("auf MaxConns (%d) begrenzt", benchMaxConns),
		fmt.Sprintf("MinFree %g %% statt %g %%", benchMinFree*100, ingest.DefaultMinFree*100),
		"Uhr eingefroren (kein Alters-Flush), Logausgabe verworfen",
		fmt.Sprintf("je %d Mails eine Begriffsliste", ingest.DefaultBatchSize),
		"Kettenprüfung über Cache (Hashvergleich von `epoch.rec` und `user.rec`, je Mail zweimal), Hash über den Mailstrom",
		fmt.Sprintf("höchstens %d MiB (Rauschanteil", memBaseNoiseMiB),
		fmt.Sprintf("höchstens %d MiB über dem von Lauf 1", rssRiseTolMiB),
		fmt.Sprintf("%v Leerlauf, dann debug.FreeOSMemory()", strings.Replace(settleWait.String(), "s", " s", 1)),
		fmt.Sprintf("ab %d Segmenten", client.MergeThreshold),
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("scripts/bench.sh does not say %q", want)
		}
	}
	if strings.Contains(string(script), "ausstehend") {
		t.Error("scripts/bench.sh still has a row that is to come (ausstehend)")
	}
}
