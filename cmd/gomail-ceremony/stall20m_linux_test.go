//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"fmt"
	"io"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Task 20m: the bounds of the tests on pseudo terminals (stuckLimit and
// the shorter ones next to it) hold in the time of the program; neither
// the program nor the test can keep them while it does not run. A wait
// that runs out is therefore measured: the time the program waited in
// the run queue and the time it ran on a CPU, the time the test itself
// kept it stopped, and the longest gap of the waiting loop and of the
// pollers of the terminals. Is one of them above stallLimit (the run
// queue only while the program ran no more than stallLimit), the run
// says nothing about the program: the subtest is repeated once
// (retryStalled), and skipped with the measures should the repetition
// stall as well. A wait that runs out
// without a stall fails as before, after a diagnosis of the program
// (diagnose). A program seen stopped without a stop of the test stopped
// itself (a job-control stop at its default action, which main.go rules
// out): a fault, never a stall.

// stallLimit is how long the program or the observing part of the test
// may not run within a wait before the wait counts as not meaningful. It
// is also the most CPU time the program may get within a wait whose run
// queue counts as a stall. A program kept from running by the machine
// runs less within a wait than one that is not, and that one ran 375 ms
// at most within a wait of the tests with stuckLimit up to their end
// (85 waits each without and with the race detector; the most, 18% of a
// CPU, while it restarts a blocked terminal every wakeEvery). A program
// that ran longer burnt the CPU itself: its threads wait in the run
// queue behind its own threads, or take the CPUs of the machine from the
// rest of it, and waits behind those count as well. The abort path
// itself takes a few milliseconds of CPU.
const stallLimit = 500 * time.Millisecond

// observeAfter is how long diagnose watches the program after a wait ran
// out without a stall.
const observeAfter = 10 * time.Second

// stall holds the measures of a wait.
type stall struct {
	// runWait is the time the threads of the program waited in the run
	// queue (sum over the threads, from /proc/<pid>/task/*/schedstat);
	// maxRunWait the longest wait of one of them, thread maxTID.
	runWait, maxRunWait time.Duration
	maxTID              int
	// onCPU is the time the threads of the program ran on a CPU (sum
	// over the threads, schedstat as well).
	onCPU time.Duration
	// stopped is the time the program was seen stopped by the test
	// (stopFor of TestStallDetect: SIGSTOP does not show as run-queue
	// wait).
	stopped time.Duration
	// selfStop: the program was seen stopped (state T) while the test did
	// not stop it, for selfStopped; a fault of the program.
	selfStop    bool
	selfStopped time.Duration
	// loopGap is the longest gap between two passes of the waiting loop.
	loopGap time.Duration
	// readGap is the longest gap between two passes of a poller of the
	// terminals, the time since its last pass included.
	readGap time.Duration
	// steal is the time the hypervisor took from all CPUs of the
	// machine (/proc/stat); for the record only.
	steal time.Duration
	// noRunWait: the run queue of the program could not be read.
	noRunWait bool
}

// stalled reports whether the program or the observing part of the test
// could not run for more than stallLimit within the wait. The run queue
// counts only while the program ran no more than stallLimit on a CPU
// (busy loops of its own wait there as well); a program that stopped
// itself is never stalled.
func (s stall) stalled() bool {
	if s.selfStop {
		return false
	}
	starved := s.runWait > stallLimit && s.onCPU <= stallLimit
	return starved || s.stopped > stallLimit || s.loopGap > stallLimit || s.readGap > stallLimit
}

func (s stall) String() string {
	run := fmt.Sprintf("run queue %v (longest of a thread %v, thread %d), on CPU %v", s.runWait.Round(time.Millisecond),
		s.maxRunWait.Round(time.Millisecond), s.maxTID, s.onCPU.Round(time.Millisecond))
	if s.noRunWait {
		run = "run queue and CPU not read"
	}
	self := ""
	if s.selfStop {
		self = fmt.Sprintf("; STOPPED ITSELF for %v (state T without a stop of the test)", s.selfStopped.Round(time.Millisecond))
	}
	return fmt.Sprintf("%s, stopped by the test %v, loop gap %v, reader gap %v (limit %v; steal of the machine %v)%s",
		run, s.stopped.Round(time.Millisecond), s.loopGap.Round(time.Millisecond), s.readGap.Round(time.Millisecond),
		stallLimit, s.steal.Round(time.Millisecond), self)
}

// schedTimes is what schedstat tells of a thread: the time it ran on a
// CPU (field 1) and the time it waited in the run queue (field 2).
type schedTimes struct {
	onCPU, runWait time.Duration
}

// threadSched returns the schedstat times of each thread of the process
// pid, by thread ID.
func threadSched(pid int) (map[int]schedTimes, error) {
	dir := fmt.Sprintf("/proc/%d/task", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	times := map[int]schedTimes{}
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "schedstat"))
		if err != nil {
			continue // the thread ended
		}
		f := strings.Fields(string(b))
		if len(f) < 2 {
			return nil, fmt.Errorf("schedstat of thread %d: %q", tid, b)
		}
		run, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return nil, err
		}
		wait, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return nil, err
		}
		times[tid] = schedTimes{onCPU: time.Duration(run), runWait: time.Duration(wait)}
	}
	return times, nil
}

// machineSteal returns the steal time of all CPUs of the machine (USER_HZ
// 100), 0 if it cannot be read.
func machineSteal() time.Duration {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 9 || f[0] != "cpu" {
		return 0
	}
	ticks, err := strconv.ParseInt(f[8], 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(ticks) * 10 * time.Millisecond
}

// procState returns the state of the process pid ('R', 'S', 'T', ...)
// from /proc/<pid>/stat, 0 if it cannot be read.
func procState(pid int) byte {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) {
		return b[i+2]
	}
	return 0
}

// window measures one wait of the test for the program pid, observed
// through the terminals vts. testStop is set while the test keeps the
// program stopped (nil: never).
type window struct {
	pid      int
	vts      []*vt
	testStop *atomic.Bool
	start    time.Time
	last     time.Time
	sched0   map[int]schedTimes
	steal0   time.Duration
	s        stall
}

// openWindow starts the measures of a wait: the run queue and the CPU
// time of the program and the gaps of the pollers of vts from now on.
func openWindow(pid int, vts []*vt, testStop *atomic.Bool) *window {
	for _, v := range vts {
		v.maxGap.Store(0)
	}
	w := &window{pid: pid, vts: vts, testStop: testStop, steal0: machineSteal()}
	w.sched0, _ = threadSched(pid)
	w.start = time.Now()
	w.last = w.start
	return w
}

// pass marks a pass of the waiting loop: the gap since the last one, and
// the gap counted as stopped when the program is stopped now, by the test
// or by itself.
func (w *window) pass() {
	now := time.Now()
	gap := now.Sub(w.last)
	w.last = now
	w.s.loopGap = max(w.s.loopGap, gap)
	// The flag first: it is cleared only after SIGCONT, which ends the
	// stop at once; a stop seen after a clear flag is not the test's.
	byTest := w.testStop != nil && w.testStop.Load()
	if st := procState(w.pid); st == 'T' || st == 't' {
		if byTest {
			w.s.stopped += gap
		} else {
			w.s.selfStop = true
			w.s.selfStopped += gap
		}
	}
}

// close ends the measures of the wait at its deadline.
func (w *window) close() stall {
	w.pass()
	if w.sched0 == nil {
		w.s.noRunWait = true
	} else if times, err := threadSched(w.pid); err != nil {
		w.s.noRunWait = true
	} else {
		// A thread that ended within the wait is not counted; one that
		// began within it is counted from its start.
		for tid, d := range times {
			wait := d.runWait - w.sched0[tid].runWait
			w.s.runWait += wait
			if wait > w.s.maxRunWait {
				w.s.maxRunWait, w.s.maxTID = wait, tid
			}
			w.s.onCPU += d.onCPU - w.sched0[tid].onCPU
		}
	}
	for _, v := range w.vts {
		w.s.readGap = max(w.s.readGap, v.gap())
	}
	w.s.steal = machineSteal() - w.steal0
	return w.s
}

// stallAbort ends an attempt of retryStalled whose wait ran out in a
// stall.
type stallAbort struct {
	what string
	d    time.Duration
	s    stall
}

func (a stallAbort) String() string {
	return fmt.Sprintf("%s: nothing within %v; %v", a.what, a.d, a.s)
}

// stallTries holds the tests that run as an attempt of retryStalled.
var stallTries sync.Map

// retryStalled runs body as a subtest whose waits are measured (task
// 20m): should a wait run out in a stall, the attempt ends and body runs
// once more; should the repetition stall as well, the subtest is skipped
// with the measures of both. Every other outcome of an attempt is the
// outcome of the subtest.
func retryStalled(body func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		first := attempt(t, body)
		if first == nil {
			return
		}
		t.Logf("attempt 1 not meaningful (%v); repeated once", first)
		second := attempt(t, body)
		if second == nil {
			return
		}
		t.Skipf("the program or the test did not run in both attempts: attempt 1 %v; attempt 2 %v", first, second)
	}
}

// attempt runs body once; it returns the stall that ended it, or nil.
func attempt(t *testing.T, body func(t *testing.T)) (s *stallAbort) {
	stallTries.Store(t, true)
	defer stallTries.Delete(t)
	defer func() {
		if r := recover(); r != nil {
			a, ok := r.(stallAbort)
			if !ok {
				panic(r)
			}
			s = &a
		}
	}()
	body(t)
	return nil
}

// poll waits at most d until one of conds holds and returns its index,
// or -1. A wait that runs out is measured (task 20m): in a stall within
// an attempt of retryStalled the program is killed and the attempt ends;
// without a stall diagnose reports on the program and poll returns -1,
// and the caller fails as before.
func (c *ceremony15n) poll(d time.Duration, what string, conds ...func() bool) int {
	c.t.Helper()
	w := openWindow(c.cmd.Process.Pid, c.vtList(), &c.testStop)
	for deadline := w.start.Add(d); ; time.Sleep(2 * time.Millisecond) {
		w.pass()
		for i, f := range conds {
			if f() {
				return i
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}
	s := w.close()
	c.t.Logf("%s: nothing within %v; %v", what, d, s)
	c.logThreads()
	if s.stalled() {
		if _, ok := stallTries.Load(c.t); ok {
			c.cmd.Process.Kill()
			<-c.exited
			panic(stallAbort{what: what, d: d, s: s})
		}
		return -1
	}
	c.diagnose(conds)
	return -1
}

// until waits at most d for a match of re on v after offset from (poll);
// it reports whether one came.
func (c *ceremony15n) until(v *vt, re interface{ Match([]byte) bool }, from int, d time.Duration, what string) bool {
	c.t.Helper()
	return c.poll(d, what, func() bool {
		out := v.output()
		return len(out) >= from && re.Match(out[from:])
	}) == 0
}

func (c *ceremony15n) vtList() []*vt {
	l := make([]*vt, 0, len(c.vts))
	for _, v := range c.vts {
		l = append(l, v)
	}
	return l
}

// logThreads logs the state of each thread of the program: /proc stat
// (state, CPU time, last CPU), wchan and the system call it is in.
func (c *ceremony15n) logThreads() {
	c.t.Helper()
	pid := c.cmd.Process.Pid
	dir := fmt.Sprintf("/proc/%d/task", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		c.t.Logf("program %d: %v", pid, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "program %d:", pid)
	for _, e := range ents {
		stat, err := os.ReadFile(filepath.Join(dir, e.Name(), "stat"))
		if err != nil {
			continue
		}
		wchan, _ := os.ReadFile(filepath.Join(dir, e.Name(), "wchan"))
		sc, _ := os.ReadFile(filepath.Join(dir, e.Name(), "syscall"))
		fmt.Fprintf(&b, "\n  thread %s %s wchan %q syscall %q", e.Name(), statSummary(stat), wchan, bytes.TrimSpace(sc))
	}
	c.t.Log(b.String())
}

// statSummary picks the state, the CPU time (utime, stime in ticks) and
// the last CPU from a /proc stat line.
func statSummary(stat []byte) string {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return fmt.Sprintf("%q", stat)
	}
	f := strings.Fields(string(stat[i+1:]))
	// f[0] is field 3 (state); utime and stime are fields 14 and 15, the
	// last CPU field 39.
	if len(f) < 37 {
		return fmt.Sprintf("%q", stat)
	}
	return fmt.Sprintf("%s state %s utime %s stime %s cpu %s", stat[:i+1], f[0], f[11], f[12], f[36])
}

// diagnose watches the program for observeAfter after a wait ran out
// without a stall: when it ends, and when each of conds holds (a clear,
// a prompt), with the time since the deadline.
func (c *ceremony15n) diagnose(conds []func() bool) {
	c.t.Helper()
	start := time.Now()
	seen := make([]bool, len(conds))
	ended := false
	for time.Since(start) < c.observe() {
		for i, f := range conds {
			if !seen[i] && f() {
				seen[i] = true
				c.t.Logf("condition %d of the wait holds %v after the deadline", i, time.Since(start).Round(time.Millisecond))
			}
		}
		if !ended && c.ended(0) {
			ended = true
			c.t.Logf("program ended %v after the deadline (%v)", time.Since(start).Round(time.Millisecond), c.werr)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ended {
		c.t.Logf("program still running %v after the deadline", c.observe())
		c.logThreads()
	}
}

func (c *ceremony15n) observe() time.Duration {
	if c.observeFor > 0 {
		return c.observeFor
	}
	return observeAfter
}

// stallChildEnv makes the test binary a child of TestStallDetect
// (TestStallChild): "<mode> <nice> <threads> [<cpu>...]".
const stallChildEnv = "GOMAIL_CEREMONY_TEST_STALL_CHILD"

// TestStallChild is a child of TestStallDetect, a program other than the
// ceremony: all its threads on the CPUs given (all if none) with the
// nice value given; mode "spin" keeps threads busy, mode "stop" stops
// the child itself (SIGSTOP). It writes "ready\n" to stdout once set up;
// it ends after a minute should nobody kill it.
func TestStallChild(t *testing.T) {
	arg := os.Getenv(stallChildEnv)
	if arg == "" {
		t.Skip("a child of TestStallDetect only")
	}
	f := strings.Fields(arg)
	if len(f) < 3 {
		t.Fatalf("%s=%q", stallChildEnv, arg)
	}
	mode := f[0]
	nice, err1 := strconv.Atoi(f[1])
	threads, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil {
		t.Fatalf("%s=%q", stallChildEnv, arg)
	}
	var mask [128]byte
	for _, s := range f[3:] {
		cpu, err := strconv.Atoi(s)
		if err != nil || cpu < 0 || cpu >= len(mask)*8 {
			t.Fatalf("%s=%q", stallChildEnv, arg)
		}
		mask[cpu/8] |= 1 << (cpu % 8)
	}
	// Set, the runtime keeps GOMAXPROCS whatever the affinity.
	runtime.GOMAXPROCS(threads + 1)
	// Each thread of the child gets the CPUs and the nice value; a thread
	// made later inherits both from its maker. Until a pass finds no new
	// thread.
	done := map[int]bool{}
	for again := true; again; {
		again = false
		ents, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			tid, err := strconv.Atoi(e.Name())
			if err != nil || done[tid] {
				continue
			}
			done[tid], again = true, true
			if len(f) > 3 {
				if _, _, e := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(tid), uintptr(len(mask)), uintptr(unsafe.Pointer(&mask))); e != 0 {
					t.Fatal(e)
				}
			}
			if nice != 0 {
				if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, nice); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	end := time.Now().Add(time.Minute)
	switch mode {
	case "spin":
		for i := 0; i < threads; i++ {
			go func() {
				for time.Now().Before(end) {
				}
			}()
		}
	case "stop":
	default:
		t.Fatalf("%s=%q", stallChildEnv, arg)
	}
	os.Stdout.WriteString("ready\n")
	if mode == "stop" {
		syscall.Kill(os.Getpid(), syscall.SIGSTOP)
	}
	time.Sleep(time.Until(end))
}

// startStallChild starts TestStallChild with arg as a program of its own,
// observed as the ceremony is (no terminals), and waits until it is set
// up.
func startStallChild(t *testing.T, arg string) *ceremony15n {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStallChild$")
	cmd.Env = append(os.Environ(), stallChildEnv+"="+arg)
	cmd.Stdout = w
	err = cmd.Start()
	w.Close()
	if err != nil {
		t.Fatal(err)
	}
	c := &ceremony15n{t: t, vts: map[byte]*vt{}, cmd: cmd, exited: make(chan struct{})}
	go func() {
		c.werr = cmd.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-c.exited
	})
	ready := make(chan error, 1)
	go func() {
		b := make([]byte, 6)
		_, err := io.ReadFull(r, b)
		if err == nil && string(b) != "ready\n" {
			err = fmt.Errorf("child wrote %q", b)
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("child %q: %v (%v)", arg, err, c.werr)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("child %q not ready within 20 s", arg)
	}
	return c
}

// affinityCPUs returns up to n CPUs of the affinity mask of the test.
func affinityCPUs(t *testing.T, n int) []int {
	t.Helper()
	var mask [128]byte
	if _, _, e := syscall.RawSyscall(syscall.SYS_SCHED_GETAFFINITY, 0, uintptr(len(mask)), uintptr(unsafe.Pointer(&mask))); e != 0 {
		t.Skip(e)
	}
	var cpus []int
	for i, b := range mask {
		for ; b != 0 && len(cpus) < n; b &= b - 1 {
			cpus = append(cpus, i*8+bits.TrailingZeros8(b))
		}
	}
	if len(cpus) == 0 {
		t.Skip("no CPU in the affinity mask")
	}
	return cpus
}

// spinOn keeps n threads of the test busy on cpu for d from the call of
// begin; wait waits until they are done and their threads ended.
func spinOn(t *testing.T, cpu, n int, d time.Duration) (begin, wait func()) {
	t.Helper()
	var one [128]byte
	one[cpu/8] = 1 << (cpu % 8)
	var ready, spun, gone sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		ready.Add(1)
		spun.Add(1)
		gone.Add(1)
		go func() {
			defer gone.Done()
			defer spun.Done()
			// The thread ends with the goroutine (locked at its end): its
			// affinity does not stay with the process.
			runtime.LockOSThread()
			_, _, e := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0, uintptr(len(one)), uintptr(unsafe.Pointer(&one)))
			if e != 0 {
				errs <- e
			}
			ready.Done()
			<-start
			for stop := time.Now().Add(d); e == 0 && time.Now().Before(stop); {
			}
		}()
	}
	ready.Wait()
	select {
	case e := <-errs:
		close(start)
		gone.Wait()
		t.Skip(e)
	default:
	}
	return func() { close(start) }, func() { spun.Wait(); gone.Wait() }
}

// TestStallDetect (task 20m point 4): the measures of a wait and the
// decision of poll.
//
// "stopped": the program, stopped by the test with SIGSTOP for 3 s
// within a wait, counts as stalled; without the stop it does not. "self
// stop": a program that stops itself does not count as stalled, and poll
// returns -1 without a repetition. "run queue": a program whose threads
// wait in the run queue behind those of the test, without CPU, counts as
// stalled. "spinning": a program whose own threads crowd its CPUs waits
// in the run queue as long, but ran on them: it does not count as
// stalled, and poll returns -1 without a repetition. "loop gap" and
// "reader gap": the waiting loop and a poller of a terminal that do not
// run for 700 ms count as stalled. "retry": a wait that runs out while
// the program is stopped by the test ends the attempt, the repetition
// without the stop passes; with the stop in both the subtest is skipped.
// "no stall": a wait that runs out without a stall returns -1 to fail
// the caller as before, without a repetition.
func TestStallDetect(t *testing.T) {
	w1 := witnessArg(t, "w1")
	ready := func(t *testing.T) *ceremony15n {
		c := start15n(t, w1, "ABA")
		if !c.errw.waitFor(holder1, c.exited) {
			t.Fatalf("exited early: stderr %q", c.errw.output())
		}
		return c
	}
	// stopFor stops the program for d from now on; the program counts as
	// stopped by the test until SIGCONT.
	stopFor := func(t *testing.T, c *ceremony15n, d time.Duration) {
		c.testStop.Store(true)
		if err := c.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		time.AfterFunc(d, func() {
			c.cmd.Process.Signal(syscall.SIGCONT)
			c.testStop.Store(false)
		})
	}
	measure := func(c *ceremony15n, d time.Duration) stall {
		w := openWindow(c.cmd.Process.Pid, c.vtList(), &c.testStop)
		for end := w.start.Add(d); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
			w.pass()
		}
		return w.close()
	}
	never := func() bool { return false }
	// failsOnce: poll on c runs out without a stall: -1, one attempt.
	failsOnce := func(t *testing.T, c *ceremony15n, what string) {
		attempts, got := 0, 0
		retryStalled(func(t *testing.T) {
			attempts++
			c.t = t
			c.observeFor = 300 * time.Millisecond
			got = c.poll(time.Second, what, never)
		})(t)
		if attempts != 1 || got != -1 {
			t.Fatalf("%s seen as stalled: %d attempts, poll %d", what, attempts, got)
		}
	}
	t.Run("stopped", func(t *testing.T) {
		c := ready(t)
		stopFor(t, c, 3*time.Second)
		s := measure(c, 3500*time.Millisecond)
		t.Logf("stopped 3 s: %v", s)
		if !s.stalled() || s.stopped < 2500*time.Millisecond || s.selfStop {
			t.Fatalf("a program stopped for 3 s by the test not seen as stalled: %v", s)
		}
		time.Sleep(200 * time.Millisecond)
		// Without a stop: the program is not seen stopped; should the
		// machine stall all the same, the measure is taken once more.
		for i := 0; ; i++ {
			s = measure(c, 3500*time.Millisecond)
			t.Logf("not stopped: %v", s)
			if s.stopped != 0 || s.selfStop {
				t.Fatalf("a program not stopped seen stopped: %v", s)
			}
			if !s.stalled() {
				break
			}
			if i == 1 {
				t.Skipf("the machine stalled twice without a stop: %v", s)
			}
		}
	})
	t.Run("self stop", func(t *testing.T) {
		c := startStallChild(t, "stop 0 0")
		for end := time.Now().Add(5 * time.Second); procState(c.cmd.Process.Pid) != 'T'; time.Sleep(2 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("child not stopped within 5 s: state %q", procState(c.cmd.Process.Pid))
			}
		}
		s := measure(c, 700*time.Millisecond)
		t.Logf("stopped itself: %v", s)
		if s.stalled() || !s.selfStop || s.selfStopped < 600*time.Millisecond || s.stopped != 0 {
			t.Fatalf("a program that stopped itself seen as stalled or not seen stopped: %v", s)
		}
		// Stopped by itself, the program is at fault whatever else the
		// wait measured.
		if (stall{runWait: time.Second, stopped: time.Second, loopGap: time.Second, readGap: time.Second, selfStop: true}).stalled() {
			t.Fatal("a stall with a stop of the program itself counts as stalled")
		}
		failsOnce(t, c, "stopped itself")
	})
	t.Run("run queue", func(t *testing.T) {
		// One thread of the child, nice 19, spins on a CPU on which three
		// threads of the test spin: it waits in the run queue nearly all
		// the time and runs on the CPU nearly never.
		cpu := affinityCPUs(t, 1)[0]
		c := startStallChild(t, fmt.Sprintf("spin 19 1 %d", cpu))
		begin, wait := spinOn(t, cpu, 3, 1200*time.Millisecond)
		begin()
		s := measure(c, time.Second)
		wait()
		t.Logf("child behind 3 threads spinning on CPU %d: %v", cpu, s)
		if !s.stalled() || s.runWait < 800*time.Millisecond || s.onCPU > stallLimit || s.maxRunWait <= 0 || s.maxRunWait > s.runWait {
			t.Fatalf("a program that waited in the run queue without CPU not seen as stalled: %v", s)
		}
	})
	t.Run("spinning", func(t *testing.T) {
		// Three threads of the child for each of up to two CPUs spin on
		// them: two of three wait in the run queue at any time, behind
		// threads of the same program (a busy loop in the abort path).
		cpus := affinityCPUs(t, 2)
		arg := fmt.Sprintf("spin 0 %d", 3*len(cpus))
		for _, cpu := range cpus {
			arg += fmt.Sprint(" ", cpu)
		}
		c := startStallChild(t, arg)
		s := measure(c, 1500*time.Millisecond)
		t.Logf("child spinning on CPUs %v: %v", cpus, s)
		if s.runWait <= stallLimit || s.onCPU <= stallLimit {
			t.Fatalf("a program spinning on its CPUs did not both wait in the run queue and run: %v", s)
		}
		if s.stalled() {
			t.Fatalf("a program spinning on its CPUs seen as stalled: %v", s)
		}
		// The bound of the CPU time.
		if (stall{runWait: 2 * time.Second, onCPU: stallLimit + time.Millisecond}).stalled() || !(stall{runWait: 2 * time.Second, onCPU: stallLimit}).stalled() {
			t.Fatal("the run queue counts as a stall with more than stallLimit on a CPU, or not with stallLimit")
		}
		failsOnce(t, c, "spinning")
	})
	t.Run("loop gap", func(t *testing.T) {
		c := ready(t)
		w := openWindow(c.cmd.Process.Pid, c.vtList(), &c.testStop)
		w.pass()
		time.Sleep(700 * time.Millisecond)
		s := w.close()
		t.Logf("loop gap: %v", s)
		if !s.stalled() || s.loopGap < 700*time.Millisecond {
			t.Fatalf("a gap of 700 ms of the waiting loop not seen as stalled: %v", s)
		}
	})
	t.Run("reader gap", func(t *testing.T) {
		c := ready(t)
		w := openWindow(c.cmd.Process.Pid, c.vtList(), &c.testStop)
		// The poller of stdout finds output and waits for the lock of
		// its buffer.
		c.out.mu.Lock()
		if _, err := c.out.s.Write([]byte("x")); err != nil {
			c.out.mu.Unlock()
			t.Fatal(err)
		}
		for end := time.Now().Add(700 * time.Millisecond); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
			w.pass()
		}
		c.out.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		s := w.close()
		t.Logf("reader gap: %v", s)
		if !s.stalled() || s.readGap < 650*time.Millisecond || s.loopGap > stallLimit {
			t.Fatalf("a gap of 700 ms of a poller not seen as stalled: %v", s)
		}
	})
	t.Run("retry", func(t *testing.T) {
		attempts := 0
		retryStalled(func(t *testing.T) {
			attempts++
			c := ready(t)
			if attempts == 1 {
				stopFor(t, c, 3*time.Second)
			}
			if c.poll(2*time.Second, "holder 1 confirms", func() bool { return attempts > 1 }) != 0 {
				t.Fatal("no stall and no condition")
			}
		})(t)
		if attempts != 2 {
			t.Fatalf("%d attempts", attempts)
		}
	})
	t.Run("retry stalled twice", func(t *testing.T) {
		attempts := 0
		var inner *testing.T
		t.Run("inner", func(t *testing.T) {
			inner = t
			retryStalled(func(t *testing.T) {
				attempts++
				c := ready(t)
				stopFor(t, c, 3*time.Second)
				c.poll(2*time.Second, "never", never)
				t.Fatal("poll returned in a stall")
			})(t)
		})
		if attempts != 2 || !inner.Skipped() || inner.Failed() {
			t.Fatalf("%d attempts, skipped %v, failed %v", attempts, inner.Skipped(), inner.Failed())
		}
	})
	t.Run("no stall", func(t *testing.T) {
		attempts := 0
		var got int
		var s time.Duration
		retryStalled(func(t *testing.T) {
			attempts++
			c := ready(t)
			c.observeFor = 300 * time.Millisecond
			start := time.Now()
			got = c.poll(time.Second, "never", never)
			s = time.Since(start)
		})(t)
		if attempts == 2 {
			t.Skip("the machine stalled in the first attempt")
		}
		if attempts != 1 || got != -1 {
			t.Fatalf("%d attempts, poll %d", attempts, got)
		}
		t.Logf("poll returned -1 after %v", s.Round(time.Millisecond))
	})
}
