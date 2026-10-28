package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// twoHost holds what the runs of scripts/two-host-test.sh need: sh, the
// script and the programs (built with the tag gomail_test). Since task 14
// gomailctl appends its records to the log itself; the log helper of
// task 16 (--log-helper) is gone.
type twoHost struct {
	sh, script, bin string
}

// newTwoHost skips the test when sh or a tool the script needs is
// missing.
func newTwoHost(t *testing.T) *twoHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, tool := range []string{"curl", "mkfifo", "mktemp", "find", "grep", "sed", "awk", "od", "base64", "cksum", "dd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s missing", tool)
		}
	}
	_, e1 := exec.LookPath("sha256sum")
	_, e2 := exec.LookPath("shasum")
	if e1 != nil && e2 != nil {
		t.Skip("neither sha256sum nor shasum")
	}
	if out, err := exec.Command("curl", "--version").Output(); err != nil || !strings.Contains(strings.ToLower(string(out)), "smtp") {
		t.Skip("curl without SMTP")
	}
	bin := programs(t)
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "two-host-test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return &twoHost{sh: sh, script: script, bin: bin}
}

// scriptDirs is the layout of one run: TMPDIR, a --workdir with files of
// somebody else in server/, client/ and bin/ (task 16b finding 2), and
// --out. The name of the work directory has a single quote (finding 6).
type scriptDirs struct {
	dir, tmp, work, out string
	foreign             map[string]string
}

func newScriptDirs(t *testing.T) *scriptDirs {
	t.Helper()
	dir := t.TempDir()
	d := &scriptDirs{dir: dir, tmp: filepath.Join(dir, "tmp"), work: filepath.Join(dir, "work'q"), out: filepath.Join(dir, "out"),
		foreign: map[string]string{}}
	if err := os.Mkdir(d.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"server", "client", "bin"} {
		if err := os.MkdirAll(filepath.Join(d.work, sub), 0o700); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(d.work, sub, "fremd.txt")
		content := "nicht vom Skript: " + sub + "\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		d.foreign[f] = content
	}
	return d
}

// env is the environment of a run: only what the script documents
// (PATH, TMPDIR, GOMAIL_TEST_MIN_FREE), as env -i would leave it (task
// 16c finding 1), and extra (a later entry wins).
func (d *scriptDirs) env(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + d.tmp, testMinFree}, extra...)
}

// check checks that the files of somebody else are unchanged, that the
// run left nothing in TMPDIR and that it left as many directories of its
// own under --workdir as want.
func (d *scriptDirs) check(t *testing.T, want int) {
	t.Helper()
	for f, content := range d.foreign {
		b, err := os.ReadFile(f)
		if err != nil || string(b) != content {
			t.Errorf("foreign file %s: %q, %v", f, b, err)
		}
	}
	if ents, err := os.ReadDir(d.tmp); err != nil || len(ents) != 0 {
		t.Errorf("TMPDIR not empty: %v %v", ents, err)
	}
	own, err := filepath.Glob(filepath.Join(d.work, "two-host.*"))
	if err != nil || len(own) != want {
		t.Errorf("own directories under --workdir: %v, want %d (%v)", own, want, err)
	}
}

func (h *twoHost) args(bin string, d *scriptDirs, more ...string) []string {
	return append([]string{h.script, "--local", "--bin", bin, "--workdir", d.work, "--out", d.out}, more...)
}

// remoteArgs are the arguments of the two-host mode over the ssh
// substitute f (hosts srv and cli).
func (h *twoHost) remoteArgs(bin string, d *scriptDirs, f *fakeSSH, more ...string) []string {
	return append([]string{h.script, "--server-host", "srv", "--client-host", "cli", "--export", f.export, "--mount", f.mount,
		"--group", f.group, "--bin", bin, "--workdir", d.work, "--out", d.out}, more...)
}

func protocol(t *testing.T, d *scriptDirs) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.out, "protokoll.md"))
	if err != nil {
		t.Fatalf("protocol: %v", err)
	}
	return string(b)
}

// secretPrefixes start subject, body token and passphrase of every run
// of the script (Nordlicht-, Kennwort-, geheim-).
var secretPrefixes = []string{"Nordlicht-", "Kennwort-", "geheim-"}

// TestTwoHostScript runs scripts/two-host-test.sh in its local mode
// (task 16): the programs of this package (built with the tag
// gomail_test), everything on this
// machine as one user and without NFS. It is skipped when sh or a tool
// the script needs is missing. The local mode proves no separation of
// 9.1 (the script says so); the test checks that the run passes, that
// the protocol carries the warning and holds no plaintext, and (task
// 16b) that the script deletes only what it made, keeps no seed words
// or mail text on disk, refuses existing --pin/--witness targets and
// stops every process it started when a signal ends it. Task 16c adds
// the two-host mode over an ssh substitute on this machine, a clean-up
// that takes nothing from the environment, keygen errors without the
// word questions, and command lines without subject and body.
func TestTwoHostScript(t *testing.T) {
	h := newTwoHost(t)

	// A full run with --keep, a single quote in --workdir and --export
	// (finding 6) and files of somebody else under --workdir (finding 2):
	// they stay, and no kept file holds subject or text (finding 5). The
	// environment holds only PATH, TMPDIR and GOMAIL_TEST_MIN_FREE (task
	// 16c finding 1), and no command line of the run shows subject, body
	// or passphrase (task 16c finding 8).
	t.Run("run", func(t *testing.T) {
		d := newScriptDirs(t)
		export := filepath.Join(d.dir, "export'x")
		run := startDetached(t, h, d, h.args(h.bin, d, "--keep", "--export", export), d.env())
		scan := watchCmdlines(run.pgid)
		code := run.wait(t, 5*time.Minute)
		scan.finish(t)
		output := run.output(t)
		p := protocol(t, d)
		if code != 0 {
			t.Fatalf("script: exit status %d\n%s\nprotocol:\n%s", code, output, p)
		}
		for _, want := range []string{"kein Nachweis nach 9.1", "**bestanden**", "Testsperre", "Serversperre", "client lock in force",
			"no registered user", "Server-Sperre: store: in use", "keine privaten Schlüssel im Export", "kein Klartext", "ohne Datei",
			"gelöscht: Passphrase-Datei", "ohne Freigabe nicht", "liest die Mail", "nach der Freigabe"} {
			if !strings.Contains(p, want) {
				t.Errorf("protocol without %q", want)
			}
		}
		// Subject, body and addresses of the run never reach the protocol.
		for _, s := range append([]string{"brownbear", "lieferant"}, secretPrefixes...) {
			if strings.Contains(p, s) {
				t.Errorf("protocol contains %q", s)
			}
		}
		d.check(t, 1)
		// No kept file holds the subject or the body token: not the data
		// directory, not the work directories (list/read), not TMPDIR,
		// not the output of the script. The passphrase file is gone also
		// with --keep (task 16c finding 6).
		err := filepath.WalkDir(d.dir, func(path string, e os.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return err
			}
			if e.Name() == "passphrase" {
				t.Errorf("passphrase file kept: %s", path)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, s := range secretPrefixes {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("plaintext %q in %s", s, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(export); err != nil {
			t.Errorf("--keep: export: %v", err)
		}
		if t.Failed() {
			t.Logf("output:\n%s\nprotocol:\n%s", output, p)
		}
	})

	// The two-host mode over the ssh substitute (task 16c finding 4, 8):
	// export and mount point have a space in their path, which
	// /proc/mounts writes as \040; the script decodes it and finds the
	// NFSv4 line of the mount. Subject and body reach the remote shells
	// through their standard input, never through a command line.
	t.Run("two hosts over an ssh substitute", func(t *testing.T) {
		d := newScriptDirs(t)
		f := newFakeSSH(t, d.dir, false)
		run := startDetached(t, h, d, h.remoteArgs(h.bin, d, f), d.env("PATH="+f.path))
		scan := watchCmdlines(run.pgid)
		code := run.wait(t, 5*time.Minute)
		scan.finish(t)
		output := run.output(t)
		p := protocol(t, d)
		if code != 0 {
			t.Fatalf("script: exit status %d\n%s\nprotocol:\n%s", code, output, p)
		}
		for _, want := range []string{"zwei Maschinen, NFSv4", "**bestanden**", "nfs4 mit vers=4.2 local_lock=none",
			"getrennte Benutzer", "Gruppe " + f.group, "kein Klartext", "nach der Freigabe"} {
			if !strings.Contains(p, want) {
				t.Errorf("protocol without %q", want)
			}
		}
		for _, s := range append([]string{"brownbear", "lieferant"}, secretPrefixes...) {
			if strings.Contains(p, s) {
				t.Errorf("protocol contains %q", s)
			}
		}
		d.check(t, 0)
		if ents, err := os.ReadDir(f.export); err != nil || len(ents) != 0 {
			t.Errorf("export after the run: %v %v", ents, err)
		}
		if t.Failed() {
			t.Logf("output:\n%s\nprotocol:\n%s", output, p)
		}
	})

	// The variables of the clean-up come from the script alone (task 16c
	// finding 1): set in the environment to paths of somebody else and
	// to "made by the script", they change nothing; runs that abort
	// early leave every such path and process as it was.
	t.Run("clean-up state not from the environment", func(t *testing.T) {
		d := newScriptDirs(t)
		f := newFakeSSH(t, d.dir, false)
		foreign := filepath.Join(d.dir, "fremd")
		dirs := map[string]string{}
		for _, v := range []string{"RW", "SW", "CW", "SDATA", "T", "EXPORT", "WORKDIR"} {
			p := filepath.Join(foreign, v)
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			dirs[v] = p
		}
		// An empty --export and --workdir of somebody else: rmdir would
		// take them.
		for _, v := range []string{"RW", "SW", "CW", "SDATA", "T"} {
			if err := os.WriteFile(filepath.Join(dirs[v], "bleibt"), []byte("fremd\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		files := map[string]string{}
		for _, v := range []string{"WKEY", "CPIN", "MARKF", "PASS", "MOUNT", "PIN"} {
			p := filepath.Join(foreign, v)
			if err := os.WriteFile(p, []byte("fremd\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			files[v] = p
		}
		// A process of somebody else with its PID file.
		sleep := exec.Command("sleep", "120")
		if err := sleep.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sleep.Process.Kill(); sleep.Wait() })
		pidf := filepath.Join(foreign, "fremd.pid")
		if err := os.WriteFile(pidf, []byte(strconv.Itoa(sleep.Process.Pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := []string{"RW=" + dirs["RW"], "SW=" + dirs["SW"], "CW=" + dirs["CW"], "SDATA=" + dirs["SDATA"],
			"T=" + dirs["T"], "TBASE=" + foreign, "WKEY=" + files["WKEY"], "CPIN=" + files["CPIN"], "MARKF=" + files["MARKF"],
			"PASS=" + files["PASS"], "PIDS=client:" + pidf + " server:" + pidf, "PROTO=1", "STATUS=bestanden", "KEEP=0"}
		for _, v := range []string{"DATA_OURS", "WKEY_OURS", "PIN_OURS", "PASS_OURS", "MARK_OURS", "RW_OURS", "SW_OURS", "CW_OURS",
			"T_OURS", "MADE_LINK", "MADE_EXPORT", "MADE_WORKDIR", "MADE_SWORKDIR", "MADE_CWORKDIR"} {
			env = append(env, v+"=1")
		}
		cases := []struct {
			name string
			args []string
			path string
		}{
			// Before the own directory exists: --workdir without parent.
			{"missing --workdir", h.args(h.bin, &scriptDirs{work: filepath.Join(d.dir, "fehlt", "x"), out: filepath.Join(d.dir, "out1")},
				"--export", dirs["EXPORT"], "--mount", files["MOUNT"]), ""},
			// After the own directory exists: an existing --pin.
			{"existing --pin", h.args(h.bin, &scriptDirs{work: dirs["WORKDIR"], out: filepath.Join(d.dir, "out2")},
				"--export", dirs["EXPORT"], "--mount", files["MOUNT"], "--pin", files["PIN"]), ""},
			// The same on two hosts over the ssh substitute.
			{"existing --pin on two hosts", h.remoteArgs(h.bin, &scriptDirs{work: dirs["WORKDIR"], out: filepath.Join(d.dir, "out3")}, f,
				"--pin", files["PIN"]), f.path},
		}
		for _, c := range cases {
			bad := false
			errf := func(format string, a ...any) {
				t.Helper()
				bad = true
				t.Errorf(format, a...)
			}
			cmd := exec.Command(h.sh, c.args...)
			cmd.Env = append(d.env(), env...)
			if c.path != "" {
				cmd.Env = append(cmd.Env, "PATH="+c.path)
			}
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 2 {
				errf("%s: %v, want exit status 2\n%s", c.name, err, out)
			}
			for v, p := range dirs {
				if _, err := os.Stat(p); err != nil {
					errf("%s: %s=%s: %v", c.name, v, p, err)
				}
			}
			for v, p := range files {
				if b, err := os.ReadFile(p); err != nil || string(b) != "fremd\n" {
					errf("%s: %s=%s: %q %v", c.name, v, p, b, err)
				}
			}
			for _, v := range []string{"RW", "SW", "CW", "SDATA", "T"} {
				if _, err := os.Stat(filepath.Join(dirs[v], "bleibt")); err != nil {
					errf("%s: %s: %v", c.name, v, err)
				}
			}
			if err := sleep.Process.Signal(syscall.Signal(0)); err != nil {
				errf("%s: process of somebody else stopped: %v", c.name, err)
			}
			if own, _ := filepath.Glob(filepath.Join(dirs["WORKDIR"], "two-host.*")); len(own) != 0 {
				errf("%s: own directories left: %v", c.name, own)
			}
			if !bad {
				t.Logf("%s: exit status 2, every path and process of somebody else kept", c.name)
			}
		}
		if ents, err := os.ReadDir(d.tmp); err != nil || len(ents) != 0 {
			t.Errorf("TMPDIR not empty: %v %v", ents, err)
		}
	})

	// --pin and --witness are places that must not exist yet (finding
	// 3): an existing file is an invocation error (exit status 2) and
	// stays as it was; a --workdir the script had to create is removed.
	for _, opt := range []string{"--pin", "--witness"} {
		t.Run("existing "+opt, func(t *testing.T) {
			d := newScriptDirs(t)
			d.work = filepath.Join(d.dir, "neu")
			d.foreign = nil
			f := filepath.Join(d.dir, "vorhanden")
			if err := os.WriteFile(f, []byte("fremd\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(h.sh, h.args(h.bin, d, opt, f)...)
			cmd.Env = d.env()
			output, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 2 {
				t.Fatalf("script: %v, want exit status 2\n%s", err, output)
			}
			if !strings.Contains(string(output), "existiert schon") || !strings.Contains(string(output), opt) {
				t.Errorf("output without the reason:\n%s", output)
			}
			if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o644 {
				t.Errorf("%s: %v %v", f, fi, err)
			}
			if b, err := os.ReadFile(f); err != nil || string(b) != "fremd\n" {
				t.Errorf("%s changed: %q %v", f, b, err)
			}
			if _, err := os.Stat(d.work); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("--workdir made by the script left: %v", err)
			}
			if p := protocol(t, d); !strings.Contains(p, "Aufruffehler") {
				t.Errorf("protocol without Aufruffehler:\n%s", p)
			}
			d.check(t, 0)
		})
	}

	// --log-helper of task 16 is gone (task 14): a usage error before the
	// script makes anything.
	t.Run("--log-helper refused", func(t *testing.T) {
		d := newScriptDirs(t)
		cmd := exec.Command(h.sh, h.args(h.bin, d, "--log-helper", filepath.Join(d.dir, "helper"))...)
		cmd.Env = d.env()
		output, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(string(output), "--log-helper entfällt") {
			t.Fatalf("--log-helper: %v\n%s", err, output)
		}
		d.check(t, 0)
	})

	// A keygen that fails after its word questions (task 16c finding 2):
	// the wrapper passes the first answer and replaces the others. The
	// protocol shows the last error line of keygen, not the questions
	// ("Wort Nr. N:").
	t.Run("keygen error without word questions", func(t *testing.T) {
		d := newScriptDirs(t)
		wrap := wrapPrograms(t, h, d.dir, "exec "+shq(filepath.Join(h.bin, "gomailctl"))+" \"$@\" < <(n=0\n"+
			"while IFS= read -r l; do n=$((n + 1)); if [ $n -eq 1 ]; then printf '%s\\n' \"$l\"; else echo falsch; fi; done)\n")
		cmd := exec.Command(h.sh, h.args(wrap, d)...)
		cmd.Env = d.env()
		output, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("script: %v, want exit status 1\n%s", err, output)
		}
		p := protocol(t, d)
		if !strings.Contains(p, "gomailctl: ") {
			t.Errorf("protocol without the error of keygen:\n%s", p)
		}
		for _, s := range [][]byte{output, []byte(p)} {
			if bytes.Contains(s, []byte("Wort Nr")) {
				t.Errorf("word questions in the output or the protocol:\n%s", s)
			}
		}
		d.check(t, 0)
		t.Logf("protocol: %s", result(p))
	})

	// SIGINT to the process group while gomailctl keygen shows the seed
	// words (finding 1): a wrapper records the words (outside the
	// directories of the run) and delays the answers. Afterwards no file
	// under --workdir, TMPDIR or --out holds them. The wrapper execs the
	// real gomailctl with SIGINT ignored (task 16c finding 7): the script
	// started that very process, and only the script can end it.
	t.Run("SIGINT during keygen", func(t *testing.T) {
		d := newScriptDirs(t)
		kw := newKeygenWrapper(t, h, d.dir)
		run := startDetached(t, h, d, h.args(kw.wrap, d), d.env())
		ctl := kw.waitWords(t, run)
		run.signal(t, "INT", true)
		code := run.wait(t, time.Minute)
		t.Logf("SIGINT to the process group: exit status %d", code)
		if code != 130 {
			t.Errorf("exit status %d, want 130\n%s", code, run.output(t))
		}
		if ctl > 0 {
			if alive := waitGone(ctl, 5*time.Second); alive {
				t.Errorf("gomailctl keygen (pid %d) still runs", ctl)
			} else {
				t.Logf("the script ended gomailctl keygen (pid %d, SIGINT ignored)", ctl)
			}
		}
		checkGroupEmpty(t, run)
		kw.checkWords(t, d.work, d.tmp, d.out)
		p := protocol(t, d)
		if !strings.Contains(p, "durch ein Signal (Exit 130)") {
			t.Errorf("protocol without the abort:\n%s", p)
		}
		d.check(t, 0)
		t.Logf("protocol: %s", result(p))
	})

	// SIGINT while keygen runs on a client host whose shell outlives the
	// connection (task 16c finding 3): the ssh substitute runs each
	// command in a session of its own, so the signal ends ssh but not the
	// remote shell, as on another machine. cleanup stops keygen through
	// its PID file, and nothing of the run remains on the hosts.
	t.Run("SIGINT during keygen on a remote host", func(t *testing.T) {
		d := newScriptDirs(t)
		f := newFakeSSH(t, d.dir, true)
		kw := newKeygenWrapper(t, h, d.dir)
		run := startDetached(t, h, d, h.remoteArgs(kw.wrap, d, f), d.env("PATH="+f.path))
		ctl := kw.waitWords(t, run)
		run.signal(t, "INT", true)
		start := time.Now()
		code := run.wait(t, time.Minute)
		t.Logf("SIGINT to the process group: exit status %d", code)
		if code != 130 {
			t.Errorf("exit status %d, want 130\n%s", code, run.output(t))
		}
		if ctl > 0 && waitGone(ctl, 5*time.Second) {
			t.Errorf("gomailctl keygen (pid %d) still runs on the client host", ctl)
		}
		// Every process whose command line names a path of this run is
		// gone (but the delaying helper of the wrapper).
		var left []string
		for i := 0; i < 50; i++ {
			left = procsNaming(d.dir, kw.gate())
			if len(left) == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if len(left) > 0 {
			t.Errorf("processes of the run left on the hosts: %q", left)
		} else {
			t.Logf("nothing of the run left on the hosts %v after the signal", time.Since(start).Round(time.Millisecond))
		}
		kw.checkWords(t, d.work, d.tmp, d.out)
		p := protocol(t, d)
		if !strings.Contains(p, "durch ein Signal (Exit 130)") {
			t.Errorf("protocol without the abort:\n%s", p)
		}
		d.check(t, 0)
		t.Logf("protocol: %s", result(p))
	})

	// SIGTERM to the script alone while the client on the client host
	// starts to hold locks/client (finding 4): the script stops every
	// process it started (server, gomailctl, sleep).
	t.Run("SIGTERM while the client holds its lock", func(t *testing.T) {
		d := newScriptDirs(t)
		run := startDetached(t, h, d, h.args(h.bin, d), d.env())
		run.until(t, "holder.in", func() bool {
			m, _ := filepath.Glob(filepath.Join(d.work, "two-host.*", "client", "holder.in"))
			return len(m) > 0
		})
		run.signal(t, "TERM", false)
		code := run.wait(t, time.Minute)
		t.Logf("SIGTERM to the script: exit status %d", code)
		if code != 130 {
			t.Errorf("exit status %d, want 130\n%s", code, run.output(t))
		}
		checkGroupEmpty(t, run)
		p := protocol(t, d)
		if !strings.Contains(p, "durch ein Signal (Exit 130)") {
			t.Errorf("protocol without the abort:\n%s", p)
		}
		d.check(t, 0)
		t.Logf("protocol: %s", result(p))
	})
}

// checkGroupEmpty checks that no process of the process group of run is
// left (zombies aside), waiting up to five seconds.
func checkGroupEmpty(t *testing.T, run *detached) {
	t.Helper()
	left, ok := groupProcs(run.pgid)
	for i := 0; ok && len(left) > 0 && i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		left, _ = groupProcs(run.pgid)
	}
	switch {
	case !ok:
		t.Log("no /proc: processes not checked")
	case len(left) > 0:
		t.Errorf("processes left: %q", left)
	default:
		t.Logf("no process of the run left (process group %d)", run.pgid)
	}
}

// wrapPrograms makes a directory with the programs of h.bin, where
// gomailctl keygen runs as body (a bash script with the arguments of
// gomailctl); every other command execs the real gomailctl.
func wrapPrograms(t *testing.T, h *twoHost, dir, body string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	wrap := filepath.Join(dir, "wrap")
	if err := os.Mkdir(wrap, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"gomail-server", "gomail-ceremony", "gomail-witness"} {
		if err := os.Symlink(filepath.Join(h.bin, p), filepath.Join(wrap, p)); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!" + bash + "\n# gomailctl wrapper of TestTwoHostScript.\n" +
		"[ \"$1\" = keygen ] || exec " + shq(filepath.Join(h.bin, "gomailctl")) + " \"$@\"\n" + body
	if err := os.WriteFile(filepath.Join(wrap, "gomailctl"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrap
}

// keygenWrapper is a gomailctl whose keygen records what it shows and
// gets its answers only after 20 s (task 16b finding 1). The wrapper
// writes its PID and then execs the real gomailctl with SIGINT ignored
// (task 16c finding 7): the process the script started is gomailctl
// itself, and a signal to the process group does not end it, only the
// script can. Standard input comes from a helper in a session of its
// own (the gate), so it does not end with the signal either.
type keygenWrapper struct {
	wrap, spy, words string
}

func newKeygenWrapper(t *testing.T, h *twoHost, dir string) *keygenWrapper {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("no setsid")
	}
	kw := &keygenWrapper{spy: filepath.Join(dir, "spy")}
	if err := os.Mkdir(kw.spy, 0o700); err != nil {
		t.Fatal(err)
	}
	kw.words = filepath.Join(kw.spy, "words")
	gate := shq(filepath.Join(kw.spy, "gate.pid"))
	kw.wrap = wrapPrograms(t, h, dir, "echo $$ >"+shq(filepath.Join(kw.spy, "ctl.pid"))+"\n"+
		"exec sh -c 'trap \"\" INT; exec \"$0\" \"$@\"' "+shq(filepath.Join(h.bin, "gomailctl"))+" \"$@\" \\\n"+
		"\t< <(exec setsid sh -c 'echo $$ >\"$0\"; sleep 20; exec cat' "+gate+") \\\n"+
		"\t> >(exec tee "+shq(kw.words)+")\n")
	t.Cleanup(func() {
		if g := kw.gate(); g > 0 {
			// kill(1) as for the run (detached.kill): syscall.Kill does not
			// build on Windows (go vet, task 20a).
			exec.Command("kill", "-s", "KILL", "--", "-"+strconv.Itoa(g)).Run()
		}
	})
	return kw
}

// gate returns the PID of the helper that delays the answers (0 if
// unknown); it leads a process group of its own.
func (kw *keygenWrapper) gate() int {
	b, _ := os.ReadFile(filepath.Join(kw.spy, "gate.pid"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// waitWords waits until keygen has shown the 24 words and returns the
// PID of the real gomailctl, which it checks where /proc is: gomailctl
// keygen, SIGINT ignored. It returns 0 without /proc.
func (kw *keygenWrapper) waitWords(t *testing.T, run *detached) int {
	t.Helper()
	run.until(t, "the seed words", func() bool {
		b, _ := os.ReadFile(kw.words)
		return bytes.Contains(b, []byte(" 24. "))
	})
	b, err := os.ReadFile(filepath.Join(kw.spy, "ctl.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		t.Logf("no /proc: gomailctl (pid %d) not checked", pid)
		return 0
	}
	if args := bytes.Split(cl, []byte{0}); len(args) < 2 || filepath.Base(string(args[0])) != "gomailctl" || string(args[1]) != "keygen" {
		t.Fatalf("pid %d is not gomailctl keygen: %q", pid, cl)
	}
	if !sigIgnored(pid, syscall.SIGINT) {
		t.Fatalf("gomailctl keygen (pid %d) does not ignore SIGINT: the test would prove nothing", pid)
	}
	return pid
}

// checkWords checks that the recorded words are found by the scan and
// that no file under dirs holds them.
func (kw *keygenWrapper) checkWords(t *testing.T, dirs ...string) {
	t.Helper()
	b, err := os.ReadFile(kw.words)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedWords(b)
	if len(seed) != 24 {
		t.Fatalf("recorded %d words", len(seed))
	}
	if found := filesWithWords(t, seed, kw.spy); len(found) != 1 {
		t.Fatalf("scan does not find the recorded words: %v", found)
	}
	if found := filesWithWords(t, seed, dirs...); len(found) != 0 {
		t.Errorf("seed words on disk: %v", found)
	}
}

// sigIgnored reads from /proc whether pid ignores sig.
func sigIgnored(pid int, sig syscall.Signal) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "SigIgn:"); ok {
			m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && m&(1<<(uint(sig)-1)) != 0
		}
	}
	return false
}

// waitGone waits up to d until pid has ended (or is a zombie) and
// reports whether it still runs.
func waitGone(pid int, d time.Duration) bool {
	for deadline := time.Now().Add(d); ; {
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err != nil {
			return false
		}
		if i := bytes.LastIndexByte(b, ')'); i >= 0 {
			if f := strings.Fields(string(b[i+1:])); len(f) > 0 && f[0] == "Z" {
				return false
			}
		}
		if time.Now().After(deadline) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// procsNaming lists the running processes (not zombies) whose command
// line contains path, but the process group skip.
func procsNaming(path string, skip int) []string {
	var procs []string
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		f := procStat(pid)
		if len(f) < 3 || f[0] == "Z" || (skip > 0 && f[2] == strconv.Itoa(skip)) {
			continue
		}
		cl, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if bytes.Contains(cl, []byte(path)) {
			procs = append(procs, e.Name()+" "+strings.TrimSpace(string(bytes.ReplaceAll(cl, []byte{0}, []byte{' '}))))
		}
	}
	return procs
}

// procStat returns the fields of /proc/<pid>/stat after the command name
// (state, ppid, pgrp, session, ...), nil if unknown.
func procStat(pid int) []string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return nil
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return nil
	}
	return strings.Fields(string(b[i+1:]))
}

// cmdlineScan reads the command lines (/proc/*/cmdline, readable by
// every user of the machine) of the processes of one session again and
// again while a run lasts, looking for subject, body token and
// passphrase (task 16c finding 8).
type cmdlineScan struct {
	sid         string
	stop, done  chan struct{}
	scans, seen int
	progs       map[string]bool
	hits        []string
}

func watchCmdlines(sid int) *cmdlineScan {
	s := &cmdlineScan{sid: strconv.Itoa(sid), stop: make(chan struct{}), done: make(chan struct{}), progs: map[string]bool{}}
	go func() {
		defer close(s.done)
		for {
			select {
			case <-s.stop:
				return
			default:
			}
			s.scan()
			time.Sleep(2 * time.Millisecond)
		}
	}()
	return s
}

func (s *cmdlineScan) scan() {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	s.scans++
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if f := procStat(pid); len(f) < 4 || f[3] != s.sid {
			continue
		}
		cl, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(cl) == 0 {
			continue
		}
		s.seen++
		args := bytes.Split(cl, []byte{0})
		prog := filepath.Base(string(args[0]))
		s.progs[prog] = true
		for _, p := range secretPrefixes {
			if bytes.Contains(cl, []byte(p)) {
				s.hits = append(s.hits, fmt.Sprintf("pid %s %s: %s", e.Name(), prog, p))
			}
		}
	}
}

// finish stops the scan and reports what it found; it skips without
// /proc.
func (s *cmdlineScan) finish(t *testing.T) {
	t.Helper()
	close(s.stop)
	<-s.done
	if s.scans == 0 {
		t.Log("no /proc: command lines not checked")
		return
	}
	if !s.progs["gomailctl"] || !s.progs["awk"] {
		t.Errorf("the scan saw too little of the run (%d scans, programs %v)", s.scans, s.progs)
	}
	if len(s.hits) > 0 {
		t.Errorf("subject, body or passphrase in command lines: %q", s.hits)
	} else {
		t.Logf("%d scans of /proc/*/cmdline (%d command lines of the run): no subject, body or passphrase", s.scans, s.seen)
	}
}

// fakeSSH is an ssh substitute for the two-host mode on this machine
// (task 16c finding 3, 4): "ssh -o ... -- HOST CMD" runs CMD with sh and
// a PATH where id, uname (and on the client host awk) answer as on host
// srv (user srvuser) or cli (user clientuser). The awk of cli reads
// mounts, an NFSv4 line for the export, instead of /proc/mounts. Export
// and mount point have a space in their path: /proc/mounts writes it as
// \040. With detach, each command runs in a session of its own and
// outlives a signal to the script, as on another machine.
type fakeSSH struct {
	path, export, mount, group string
}

func newFakeSSH(t *testing.T, dir string, detach bool) *fakeSSH {
	t.Helper()
	if _, err := os.Stat("/proc/mounts"); err != nil {
		t.Skip("no /proc/mounts")
	}
	tools := map[string]string{}
	for _, tool := range []string{"id", "uname", "awk", "setsid"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s missing", tool)
		}
		tools[tool] = p
	}
	out, err := exec.Command("id", "-gn").Output()
	if err != nil {
		t.Skip("id -gn: ", err)
	}
	f := &fakeSSH{group: strings.TrimSpace(string(out)), export: filepath.Join(dir, "ex port"), mount: filepath.Join(dir, "mnt point")}
	fake := filepath.Join(dir, "fake")
	for _, d := range []string{"ssh", "srv", "cli"} {
		if err := os.MkdirAll(filepath.Join(fake, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(f.export, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.export, f.mount); err != nil {
		t.Fatal(err)
	}
	phys, err := filepath.EvalSymlinks(f.export)
	if err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(fake, "mounts")
	esc := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`).Replace(phys)
	if err := os.WriteFile(mounts, []byte("rootfs / rootfs rw 0 0\n/dev/root / ext4 rw,relatime 0 0\n"+
		"srv:/export "+esc+" nfs4 rw,relatime,vers=4.2,hard,proto=tcp,local_lock=none 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := `exec sh -c "$*"`
	if detach {
		run = "exec 3<&0\n" + shq(tools["setsid"]) + " sh -c \"$*\" <&3 3<&- &\nwait $!"
	}
	files := map[string]string{
		"ssh/ssh": "while [ $# -gt 0 ]; do case $1 in -o) shift 2 ;; --) shift; break ;; *) break ;; esac; done\n" +
			"h=$1; shift\nPATH=" + shq(fake) + "/$h:$PATH; export PATH\n" + run + "\n",
		"cli/awk": "for a do shift; [ \"$a\" != /proc/mounts ] || a=" + shq(mounts) + "; set -- \"$@\" \"$a\"; done\nexec " + shq(tools["awk"]) + " \"$@\"\n",
	}
	for host, user := range map[string]string{"srv": "srvuser 61001", "cli": "clientuser 61002"} {
		name, uid, _ := strings.Cut(user, " ")
		files[host+"/id"] = "case \"$*\" in -un) echo " + name + " ;; -u) echo " + uid + " ;; -nG) echo " + shq(name+" "+f.group) +
			" ;; *) exec " + shq(tools["id"]) + " \"$@\" ;; esac\n"
		files[host+"/uname"] = "[ \"$1\" != -n ] || { echo " + host + "host; exit 0; }\nexec " + shq(tools["uname"]) + " \"$@\"\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(fake, name), []byte("#!/bin/sh\n# ssh substitute of TestTwoHostScript.\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.path = filepath.Join(fake, "ssh") + string(os.PathListSeparator) + os.Getenv("PATH")
	return f
}

// shq quotes a word for sh.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// result returns the result line of a protocol and the last check
// passed before it.
func result(p string) string {
	var res, last string
	for _, l := range strings.Split(p, "\n") {
		switch {
		case strings.HasPrefix(l, "**abgebrochen**"), strings.HasPrefix(l, "**bestanden**"):
			res = l
		case strings.HasPrefix(l, "- [x] "):
			last = l
		}
	}
	return res + "; last check: " + last
}

// detached is a run of the script in a session of its own (setsid), so
// that a signal can reach its whole process group.
type detached struct {
	cmd  *exec.Cmd
	pgid int
	log  string
	done chan struct{}
	err  error
}

func startDetached(t *testing.T, h *twoHost, d *scriptDirs, args, env []string) *detached {
	t.Helper()
	setsid, err := exec.LookPath("setsid")
	if err != nil {
		t.Skip("no setsid")
	}
	for _, tool := range []string{"tee", "kill"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s missing", tool)
		}
	}
	r := &detached{log: filepath.Join(d.dir, "output"), done: make(chan struct{})}
	f, err := os.Create(r.log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r.cmd = exec.Command(setsid, append([]string{h.sh}, args...)...)
	r.cmd.Env = env
	r.cmd.Stdout, r.cmd.Stderr = f, f
	// A shell started with SIGINT ignored cannot trap it. When this
	// process ignores SIGINT (started in the background), a handler for
	// the time of the start makes the child start with the default.
	if signal.Ignored(os.Interrupt) {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		defer signal.Stop(c)
	}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.pgid = r.cmd.Process.Pid
	go func() {
		r.err = r.cmd.Wait()
		close(r.done)
	}()
	t.Cleanup(func() {
		r.kill()
		<-r.done
	})
	// setsid makes the script the leader of its own process group (it
	// does not fork: this child leads no group). Checked where /proc is.
	if _, err := os.Stat("/proc/self/stat"); err == nil {
		r.until(t, "a process group of its own", func() bool { return procPgrp(r.pgid) == r.pgid })
	}
	return r
}

// procPgrp returns the process group of pid from /proc (0 if unknown).
func procPgrp(pid int) int {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	if len(f) < 3 {
		return 0
	}
	n, _ := strconv.Atoi(f[2])
	return n
}

func (r *detached) output(t *testing.T) string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

// until waits up to two minutes for cond while the script runs.
func (r *detached) until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for !cond() {
		select {
		case <-r.done:
			t.Fatalf("script ended before %s: %v\n%s", what, r.err, r.output(t))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s\n%s", what, r.output(t))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// signal sends sig to the script, or with group to its process group.
func (r *detached) signal(t *testing.T, sig string, group bool) {
	t.Helper()
	target := strconv.Itoa(r.pgid)
	if group {
		target = "-" + target
	}
	if out, err := exec.Command("kill", "-s", sig, "--", target).CombinedOutput(); err != nil {
		t.Fatalf("kill -s %s %s: %v %s", sig, target, err, out)
	}
}

// wait waits up to d for the script and returns its exit status.
func (r *detached) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(d):
		r.kill()
		<-r.done
		t.Fatalf("script did not end\n%s", r.output(t))
	}
	return r.cmd.ProcessState.ExitCode()
}

// kill stops what is left of the process group.
func (r *detached) kill() {
	exec.Command("kill", "-s", "KILL", "--", "-"+strconv.Itoa(r.pgid)).Run()
}

// groupProcs lists the processes of process group pgid that still run
// (not zombies), read from /proc; ok is false without /proc.
func groupProcs(pgid int) (procs []string, ok bool) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		return nil, false
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) < 3 || f[0] == "Z" || f[2] != strconv.Itoa(pgid) {
			continue
		}
		cl, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		procs = append(procs, e.Name()+" "+strings.TrimSpace(string(bytes.ReplaceAll(cl, []byte{0}, []byte{' '}))))
	}
	return procs, true
}

// seedWords returns the words of the output of gomailctl keygen
// (" 1. word  2. word ...").
func seedWords(b []byte) []string {
	var w []string
	for _, m := range regexp.MustCompile(`(\d+)\. ([a-z]+)`).FindAllSubmatch(b, -1) {
		if n, _ := strconv.Atoi(string(m[1])); n == len(w)+1 {
			w = append(w, string(m[2]))
		}
	}
	return w
}

// filesWithWords returns the files under dirs that hold the words of a
// seed or a share: one of them with its number ("7. word"), or at least
// three of them that follow each other in the seed, one after the other
// in the file (task 20a point 6: three words of the seed anywhere in a
// file, such as "able", "about" and "add" in a log or a binary, are
// no hit).
func filesWithWords(t *testing.T, words []string, dirs ...string) []string {
	t.Helper()
	var runs []*regexp.Regexp
	for i := 0; i+3 <= len(words); i++ {
		runs = append(runs, wordRun(words[i:i+3]))
	}
	var found []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil || !e.Type().IsRegular() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if hasWords(b, words, runs) {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}

// hasWords reports whether b holds one of words with its number, or a
// run of three words that follow each other in words (runs, wordRun).
func hasWords(b []byte, words []string, runs []*regexp.Regexp) bool {
	for i, w := range words {
		if bytes.Contains(b, []byte(fmt.Sprintf("%d. %s", i+1, w))) {
			return true
		}
	}
	for _, re := range runs {
		if re.Match(b) {
			return true
		}
	}
	return false
}

// wordRun matches the words ws as whole words one after the other,
// apart by one to four characters that are no letters (a space, a line
// break, ", ", "\",\"").
func wordRun(ws []string) *regexp.Regexp {
	q := make([]string, len(ws))
	for i, w := range ws {
		q[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile(`(?i)(^|[^a-z])` + strings.Join(q, `[^a-z]{1,4}`) + `($|[^a-z])`)
}

// TestHasWords (task 20a point 6): a hit is a word with its number or
// three words of the seed in their order; three words scattered over a
// file, or two in order, are none.
func TestHasWords(t *testing.T) {
	words := []string{"abandon", "ability", "able", "about", "above"}
	var runs []*regexp.Regexp
	for i := 0; i+3 <= len(words); i++ {
		runs = append(runs, wordRun(words[i:i+3]))
	}
	for in, want := range map[string]bool{
		"3. able":                          true,
		"ability able about":               true,
		"x\nABLE\nABOUT\nABOVE\n":          true,
		`["abandon","ability","able"]`:     true,
		"able to talk about it, above all": false,
		"about able ability":               false,
		"abandon ability":                  false,
		"abandonability able about":        false,
		"ability able aboutx":              false,
	} {
		if got := hasWords([]byte(in), words, runs); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}
