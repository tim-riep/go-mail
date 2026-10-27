//go:build linux && !ceremony_notty

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/tim-riep/go-mail/internal/ceremony"
)

// Tests of task 15b point 0 (Q17, findings of the last attack on task
// 10e): signals between close and the exit (0a), stdout on another
// terminal than stdin (0b).

// salvoResult is the outcome of one run of salvoRun.
type salvoResult struct {
	code     int           // exit code
	sent     int64         // signals sent
	took     time.Duration // from the third share typed back to the exit
	complete bool          // export and keys complete
}

// salvoRun runs init 3-of-3 on a pseudo terminal and, delay after the
// third share typed back in the trial reconstruction (the last input of
// the ceremony), sends the signals sigs in turn every 100 µs until the
// program has exited. It checks the invariant of task 15b point 0a: the
// program is never killed or stopped by a signal; exit code 0 if and
// only if the export and the keys are complete, exit code 130 if and
// only if nothing is written (no export, no key directory, no staging
// directory); the terminal is restored in both cases.
func salvoRun(t *testing.T, w1 string, sigs []syscall.Signal, delay time.Duration) salvoResult {
	t.Helper()
	base := t.TempDir()
	out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
	p := openPTY(t)
	p.start(nil, nil, "init", "--shares", "3-of-3", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
	var sent atomic.Int64
	var typed time.Time
	exitedAt := make(chan time.Time, 1)
	go func() {
		<-p.exited
		exitedAt <- time.Now()
	}()
	p.afterType = func(n int) {
		if n != 3 {
			return
		}
		typed = time.Now()
		if len(sigs) == 0 {
			return
		}
		proc := p.cmd.Process
		go func() {
			time.Sleep(delay)
			for k := 0; ; k++ {
				select {
				case <-p.exited:
					return
				default:
				}
				// Process.Signal goes through a pidfd: it never reaches
				// another process once this one is reaped.
				if proc.Signal(sigs[k%len(sigs)]) != nil {
					return
				}
				sent.Add(1)
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}
	p.converse(nil)
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.cmd.Process.Pid))
		t.Fatalf("no exit within 30 s (stopped by a signal?): %q\n%q", stat, p.output())
	}
	took := (<-exitedAt).Sub(typed)
	time.Sleep(50 * time.Millisecond) // the rest of the output
	var ee *exec.ExitError
	code := 0
	if errors.As(p.err, &ee) {
		ws := ee.Sys().(syscall.WaitStatus)
		if ws.Signaled() {
			t.Fatalf("killed by %v after %d signals; export %v\n%q", ws.Signal(), sent.Load(), exists(out), p.output())
		}
		code = ws.ExitStatus()
	} else if p.err != nil {
		t.Fatal(p.err)
	}
	p.restored()
	screen := p.output()
	staging, _ := filepath.Glob(filepath.Join(base, ".tmp-ceremony-*"))
	if len(staging) != 0 {
		t.Fatalf("exit %d: staging left %v", code, staging)
	}
	keys, _ := os.ReadDir(kd)
	exported, _ := os.ReadDir(filepath.Join(out, "platform"))
	switch code {
	case 0:
		if len(keys) != 2 || len(exported) != 6 {
			t.Fatalf("exit 0 with keys %v, export %v", keys, exported)
		}
		if _, err := ceremony.ReadPin(filepath.Join(out, "identity-1.pin")); err != nil {
			t.Fatalf("exit 0: %v", err)
		}
		tail := screen[strings.LastIndex(screen, clearScreen):]
		if !strings.Contains(tail, "Exportverzeichnis:") || strings.Contains(screen, "abgebrochen") {
			t.Fatalf("exit 0: behind the last clear %q", tail)
		}
	case exitAbort:
		if exists(out) || exists(kd) {
			t.Fatalf("exit 130 with export %v, keys %v", exists(out), exists(kd))
		}
		if !strings.HasSuffix(screen, "gomail-ceremony: abgebrochen\r\n") {
			t.Fatalf("exit 130: end of screen %q", screen[max(0, len(screen)-200):])
		}
	default:
		t.Fatalf("exit code %d\n%q", code, screen)
	}
	return salvoResult{code: code, sent: sent.Load(), took: took, complete: code == 0}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// TestPTYSignalSalvo (task 15b point 0a, Q17 finding 1): a salvo of
// SIGINT from the third share typed back on, every 100 µs until the
// program has exited, in 100 runs. In 5 of every 25 runs the salvo
// begins at once, in the others its start is spread over half to 1.2
// times the time the program needs from that share to its exit
// (calibrated by a run without signals and followed by the runs the
// salvo missed): some salvos begin before the commit, some after the
// commit point, some while close runs or between close and the exit,
// some after the exit. In every run the invariant of salvoRun holds: no
// death by a signal, exit code 0 exactly with the export complete, exit
// code 130 exactly with nothing written; and some runs end with exit
// code 0 although the salvo hit them. Before task 15b close used
// signal.Stop, and a SIGINT between it and the exit killed the complete
// ceremony (13 of 97 runs of the attack script postclose.py); with
// signal.Ignore instead this test still found a run killed by SIGINT
// (see close).
//
// A second, shorter salvo rotates SIGTSTP, SIGTERM, SIGHUP, SIGQUIT and
// SIGINT. The kernel discards a SIGTSTP with its default action for the
// program here (its process group, a new session, is orphaned), so the
// salvo shows only that SIGTSTP does nothing else;
// TestCloseKeepsSignals checks that close leaves every abort signal,
// SIGTSTP included, taken in and discarded, not at its default.
func TestPTYSignalSalvo(t *testing.T) {
	w1 := witnessArg(t, "w1")
	var calib salvoResult
	t.Run("calibration", func(t *testing.T) { calib = salvoRun(t, w1, nil, 0) })
	if calib.code != 0 {
		t.Fatal("calibration failed")
	}
	window := calib.took
	t.Logf("third share typed to exit without a signal: %v", window)
	count := func(name string, runs int, needHit bool, sigs []syscall.Signal) {
		var complete, aborted, completeSignalled int
		for i := 0; i < runs; i++ {
			var delay time.Duration
			if k := i % 25; k >= 5 {
				delay = window/2 + window*7*time.Duration(k-5)/(10*19)
			}
			t.Run(fmt.Sprintf("%s%03d", name, i), func(t *testing.T) {
				r := salvoRun(t, w1, sigs, delay)
				switch {
				case r.complete && r.sent > 0:
					completeSignalled++
					complete++
				case r.complete:
					complete++
					window = (3*window + r.took) / 4
				default:
					aborted++
				}
			})
		}
		t.Logf("%s: %d runs, %d exit 0 with the export complete (%d of them hit by the salvo), %d exit 130 with nothing written, none killed; window at the end %v",
			name, runs, complete, completeSignalled, aborted, window)
		if aborted == 0 || complete == 0 || (needHit && completeSignalled == 0) {
			t.Fatalf("%s: the salvos do not cover both outcomes", name)
		}
	}
	count("sigint", 100, true, []syscall.Signal{syscall.SIGINT})
	count("mixed", 25, false, []syscall.Signal{syscall.SIGTSTP, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT})
}

// TestPTYTwoTerminals (task 15b point 0b, Q17 finding 2): stdin (and
// stderr) on terminal A, stdout on terminal B.
//
// "XOFF on stdout": B has IXON, IXOFF and IXANY set; an XOFF (Ctrl-S)
// typed on B before share 1 is shown stops nothing, because the program
// clears the flow control of B as well: share 1 appears on B, its holder
// is asked, and SIGINT ends the program within 2 s with exit code 130,
// the share cleared on B, nothing written, both terminals as before.
//
// "stdout blocked": B takes no output at all (nobody reads its master
// side and its buffer is full), so the first write to stdout blocks. A
// write that blocks holds up neither the signal handling nor the end of
// the program: SIGINT ends it within 2 s with exit code 130, "abgebrochen"
// on A, both terminals as before, nothing written, no share on B. Since
// task 15m (point 2) the abort path discards the output not yet sent to
// B, and the blocked clear and that of the abort path reach B: besides
// (what is left of) the filling, B shows clears only.
func TestPTYTwoTerminals(t *testing.T) {
	w1 := witnessArg(t, "w1")
	t.Run("XOFF on stdout", func(t *testing.T) {
		base := t.TempDir()
		p, b := openPTY(t), openPTY(t)
		t.Cleanup(func() { b.master.Write([]byte("\x11")) })
		p.setIflag(flow)
		b.setIflag(flow)
		out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
		p.start(nil, b.slave, "init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		if p.next(regexp.MustCompile(`Inhaber von Anteil 1 von 2 an den Bildschirm, dann Eingabetaste: `)) == nil {
			t.Fatalf("exited early: %q", p.output())
		}
		b.noFlow()
		b.send("\x13") // XOFF on the terminal of stdout
		time.Sleep(100 * time.Millisecond)
		p.confirm()
		noted := p.next(regexp.MustCompile(`Anteil notiert\?`)) != nil
		if !noted {
			t.Error("share 1 not shown: the write to stdout stopped by XOFF")
		}
		sent := time.Now()
		if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-p.exited:
		case <-time.After(2 * time.Second):
			t.Fatalf("no exit within 2 s after SIGINT; stdout stopped? A %q, B %q", p.output(), b.output())
		}
		took := time.Since(sent)
		if code := p.wait(); code != exitAbort {
			t.Fatalf("exit code %d\nA %q\nB %q", code, p.output(), b.output())
		}
		p.restored()
		b.restored()
		screen := b.output()
		i := strings.Index(screen, "Anteil 1/2: ")
		if i < 0 || !strings.Contains(screen[i:], clearScreen) || !strings.HasSuffix(screen, clearScreen) {
			t.Fatalf("stdout %q", screen)
		}
		// stderr is another terminal than stdout: it is cleared too (task 15b
		// point 6), before every holder is called and in the abort path.
		if !strings.HasSuffix(p.output(), clearScreen+"gomail-ceremony: abgebrochen\r\n") || strings.Count(p.output(), clearScreen) < 2 {
			t.Fatalf("stderr %q", p.output())
		}
		for _, d := range []string{out, kd} {
			if exists(d) {
				t.Fatalf("%s written", d)
			}
		}
		t.Logf("exit 130 %v after SIGINT; input modes of B before %#x, after %#x", took.Round(time.Millisecond), b.iflag0, b.iflag())
	})
	t.Run("stdout blocked", func(t *testing.T) {
		base := t.TempDir()
		p := openPTY(t)
		bm, bs, name := rawPTY(t)
		defer bm.Close()
		defer bs.Close()
		var before syscall.Termios
		if err := sysIoctl(bs.Fd(), syscall.TCGETS, unsafe.Pointer(&before)); err != nil {
			t.Fatal(err)
		}
		// Fill the terminal B until it takes no more output: through a
		// second, non-blocking open file description, so that the
		// program's stdout stays blocking.
		fd, err := syscall.Open(name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		// The terminal moves output on to its master side in the
		// background, so it is full only once it refused output for a
		// while.
		filled := 0
		chunk := bytes.Repeat([]byte("."), 256)
		for refused := 0; refused < 20 && filled < 16<<20; {
			n, err := syscall.Write(fd, chunk)
			if n > 0 {
				filled += n
				refused = 0
			}
			if errors.Is(err, syscall.EAGAIN) {
				refused++
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		syscall.Close(fd)
		out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
		p.start(nil, bs, "init", "--shares", "2-of-2", "--out", out, "--keys", kd, "--origin", "o", "--witness", w1, "--min-witnesses", "1")
		if p.next(regexp.MustCompile(`Zeremonie 2-of-2`)) == nil {
			t.Fatalf("exited early: %q", p.output())
		}
		// The program now blocks in its first write to stdout (the clear
		// before holder 1 is called).
		time.Sleep(300 * time.Millisecond)
		if strings.Contains(p.output(), "Inhaber von Anteil") {
			t.Fatalf("stdout not blocked after %d bytes: %q", filled, p.output())
		}
		sent := time.Now()
		if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-p.exited:
		case <-time.After(2 * time.Second):
			t.Fatalf("no exit within 2 s after SIGINT with stdout blocked; stderr %q", p.output())
		}
		took := time.Since(sent)
		if code := p.wait(); code != exitAbort {
			t.Fatalf("exit code %d\n%q", code, p.output())
		}
		p.restored()
		var after syscall.Termios
		if err := sysIoctl(bs.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil {
			t.Fatal(err)
		}
		if after.Iflag != before.Iflag || after.Lflag != before.Lflag {
			t.Fatalf("terminal B: input modes %#x, local modes %#x after; %#x, %#x before", after.Iflag, after.Lflag, before.Iflag, before.Lflag)
		}
		if !strings.HasSuffix(p.output(), clearScreen+"gomail-ceremony: abgebrochen\r\n") {
			t.Fatalf("stderr %q", p.output())
		}
		for _, d := range []string{out, kd} {
			if exists(d) {
				t.Fatalf("%s written", d)
			}
		}
		// What reached B: the filling, and clears only.
		mfd, err := syscall.Dup(int(bm.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(mfd)
		syscall.SetNonblock(mfd, true)
		var got []byte
		buf := make([]byte, 65536)
		for {
			n, err := syscall.Read(mfd, buf)
			if n <= 0 || err != nil {
				break
			}
			got = append(got, buf[:n]...)
		}
		if rest := bytes.ReplaceAll(bytes.Trim(got, "."), []byte(clearScreen), nil); bytes.Contains(got, []byte("Anteil")) || len(rest) != 0 {
			t.Fatalf("on B besides the filling and clears: %q", bytes.Trim(got, "."))
		}
		t.Logf("B filled with %d bytes; exit 130 %v after SIGINT", filled, took.Round(time.Millisecond))
	})
}

// TestCloseKeepsSignals: once a command has closed its term, every
// abort signal is still taken in, and discarded, until the program
// exits, SIGTSTP included, after a complete ceremony and after a failed
// one (task 15b point 0a). With the default disposition back
// (signal.Stop) the signals sent here would kill this test process; the
// signals are not merely ignored either (signal.Ignore races with a
// signal on its way, see close).
func TestCloseKeepsSignals(t *testing.T) {
	fixClock(t)
	defer signal.Reset(abortSignals...)
	codes := stubExit(t)
	base := t.TempDir()
	w1 := witnessArg(t, "w1")
	out := filepath.Join(base, "out")
	check := func(what string) {
		t.Helper()
		for _, s := range abortSignals {
			if signal.Ignored(s) {
				t.Fatalf("%s: %v ignored instead of taken in", what, s)
			}
		}
		for _, s := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP} {
			if err := syscall.Kill(os.Getpid(), s); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case code := <-codes:
			t.Fatalf("%s: exit %d after close", what, code)
		case <-time.After(200 * time.Millisecond):
		}
	}
	tt := newTTY()
	if code := run([]string{"init", "--shares", "2-of-2", "--out", out, "--keys", filepath.Join(base, "keys"), "--origin", "o",
		"--witness", w1, "--min-witnesses", "1"}, ttyIn{tt}, ttyOut{tt}, ttyErr{tt}); code != 0 {
		t.Fatal(tt.msgs.String())
	}
	check("complete ceremony")
	signal.Reset(abortSignals...)
	tt = newTTY() // no input: the command fails after openTerm
	if code := run([]string{"reshare", "--pin", filepath.Join(out, "identity-1.pin"), "--shares", "2-of-2"}, ttyIn{tt}, ttyOut{tt}, ttyErr{tt}); code != 1 {
		t.Fatalf("%d %s", code, tt.msgs.String())
	}
	check("failed command")
}
