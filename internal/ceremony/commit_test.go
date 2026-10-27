package ceremony

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/witness"
)

// guard is a Prompter that implements CommitGuard and checks the state
// of the files when the ceremony begins and ends writing.
type guard struct {
	*prompter
	t          *testing.T
	base       string // the parent of the export and key directory
	out, kd    string
	begins     int
	points     int // calls of CommitPoint
	ends       int
	active     bool
	activeSeen map[string]bool // injection points reached while active
	lastPoint  string          // the last injection point reached
	pointState string          // the files at CommitPoint
	refuse     error           // returned by CommitPoint
	committed  bool            // passed to EndCommit
	endState   string          // "nothing", "complete" or a description
}

func (g *guard) BeginCommit() {
	g.begins++
	g.active = true
	// Nothing written yet.
	if staging, _ := filepath.Glob(filepath.Join(g.base, stagingPrefix+"*")); len(staging) != 0 {
		g.t.Errorf("staging before BeginCommit: %v", staging)
	}
	if _, err := os.Lstat(g.out); err == nil {
		g.t.Error("export before BeginCommit")
	}
}

// CommitPoint records the files just before the rename: the staging
// directory complete, both keys written, no export yet.
func (g *guard) CommitPoint() error {
	g.points++
	if !g.active {
		g.t.Error("CommitPoint outside BeginCommit/EndCommit")
	}
	staging, _ := filepath.Glob(filepath.Join(g.base, stagingPrefix+"*"))
	_, outErr := os.Lstat(g.out)
	keys, _ := os.ReadDir(g.kd)
	g.pointState = fmt.Sprintf("after %s: %d staging, export %v, %d keys", g.lastPoint, len(staging), outErr == nil, len(keys))
	if len(staging) == 1 {
		g.pointState += fmt.Sprintf(", %d staged", len(listDir(g.t, staging[0])))
	}
	return g.refuse
}

func (g *guard) EndCommit(committed bool) {
	g.ends++
	g.active = false
	g.committed = committed
	staging, _ := filepath.Glob(filepath.Join(g.base, stagingPrefix+"*"))
	_, outErr := os.Lstat(g.out)
	keys := 0
	if names, err := os.ReadDir(g.kd); err == nil {
		keys = len(names)
	}
	switch {
	case len(staging) != 0:
		g.endState = fmt.Sprint("staging left: ", staging)
	case outErr != nil && keys == 0:
		g.endState = "nothing"
	case outErr == nil && keys == 2 && len(listDir(g.t, g.out)) == 7:
		g.endState = "complete"
	default:
		g.endState = fmt.Sprintf("half: export %v, %d keys", outErr, keys)
	}
}

// TestCommitGuard: the ceremony calls BeginCommit before the first file
// is written and EndCommit after the files are complete or rolled back,
// with every injection point of commit in between (task 10c finding 3;
// the command line defers signals in between, TestSignalDuringCommit).
func TestCommitGuard(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	defer func() { crashHook = nil }()
	for n := 1; ; n++ {
		base := filepath.Join(f.base, fmt.Sprint(n))
		os.Mkdir(base, 0o700)
		g := &guard{prompter: &prompter{scr: &screen{}}, t: t, base: base, out: filepath.Join(base, "out"), kd: filepath.Join(base, "keys"),
			activeSeen: map[string]bool{}}
		calls := 0
		crashHook = func(point string) error {
			if !g.active {
				t.Errorf("injection point %s outside BeginCommit/EndCommit", point)
			}
			g.activeSeen[point] = true
			g.lastPoint = point
			calls++
			if calls == n {
				return errors.New("signal at " + point)
			}
			return nil
		}
		o := f.opts(g.out, g.kd, g.prompter)
		o.Prompter = g
		o.MinWitnesses = 1
		_, err := Init(o)
		if g.begins != 1 || g.ends != 1 {
			t.Fatalf("crash %d: %d begins, %d ends", n, g.begins, g.ends)
		}
		if calls < n {
			if err != nil || g.endState != "complete" || !g.committed || g.points != 1 {
				t.Fatalf("no crash: %v, %s, committed %v, %d commit points", err, g.endState, g.committed, g.points)
			}
			// CommitPoint comes last before the rename: everything
			// written, nothing committed.
			if want := "after keys: 1 staging, export false, 2 keys, 7 staged"; g.pointState != want {
				t.Fatalf("at CommitPoint %s, want %s", g.pointState, want)
			}
			for _, p := range []string{"commit", "export", "root", "link", "key", "keys"} {
				if !g.activeSeen[p] {
					t.Fatalf("point %s not reached", p)
				}
			}
			break
		}
		if err == nil || g.endState != "nothing" || g.committed || g.points != 0 {
			t.Fatalf("crash %d: %v, %s, committed %v, %d commit points", n, err, g.endState, g.committed, g.points)
		}
	}
	// A ceremony refused before commit never begins.
	g := &guard{prompter: &prompter{scr: &screen{}}, t: t}
	o := f.opts(filepath.Join(f.base, "x"), filepath.Join(f.base, "y"), g.prompter)
	o.Prompter = g
	o.MinWitnesses = 1
	g.prompter.answer = func(int) ([]string, error) { return nil, errors.New("holder away") }
	if _, err := Init(o); err == nil || g.begins != 0 {
		t.Fatalf("%v, %d begins", err, g.begins)
	}
}

// TestCommitPointRefused: a CommitGuard that refuses the commit point
// (the command line after a signal, task 10e finding 2) gets its error
// back, with every file written removed again and EndCommit(false); for
// Init, IngestRotate and Succeed.
func TestCommitPointRefused(t *testing.T) {
	f := newFixture(t)
	errSig := errors.New("signal before the commit point")
	newGuard := func(name string) *guard {
		base := filepath.Join(f.base, name)
		if err := os.Mkdir(base, 0o700); err != nil {
			t.Fatal(err)
		}
		return &guard{prompter: &prompter{scr: &screen{}}, t: t, base: base, out: filepath.Join(base, "out"), kd: filepath.Join(base, "keys"),
			activeSeen: map[string]bool{}, refuse: errSig}
	}
	check := func(what string, g *guard, err error) {
		t.Helper()
		if !errors.Is(err, errSig) || g.begins != 1 || g.points != 1 || g.ends != 1 || g.committed || g.endState != "nothing" {
			t.Fatalf("%s: %v, %d/%d/%d calls, committed %v, %s", what, err, g.begins, g.points, g.ends, g.committed, g.endState)
		}
	}
	g := newGuard("init")
	o := f.opts(g.out, g.kd, g.prompter)
	o.Prompter = g
	_, err := Init(o)
	check("init", g, err)

	g = newGuard("rotate")
	u, p := f.unlock(1, 2, 3)
	g.prompter = p
	u.Prompter = g
	_, err = IngestRotate(RotateOptions{UnlockOptions: u, Out: g.out, KeyDir: g.kd, Gen: 2, ValidFrom: testNow})
	check("ingest-rotate", g, err)

	g = newGuard("succeed")
	u, p = f.unlock(1, 2, 3)
	g.prompter = p
	u.Prompter = g
	_, err = Succeed(SucceedOptions{UnlockOptions: u, Out: g.out, Identities: f.res.Identities, Origin: "o", Witnesses: f.w[:1], MinWitnesses: 1})
	check("succeed", g, err)
}

// TestRotateValidFrom: a valid_from before the clock of the ceremony is
// ErrOptions, before any share is asked and again after the shares were
// entered (task 10c finding 7); the current time itself is fine.
func TestRotateValidFrom(t *testing.T) {
	f := newFixture(t)
	kd := filepath.Join(f.base, "keys")
	out := filepath.Join(f.base, "rot")
	for _, vf := range []time.Time{testNow.Add(-time.Millisecond), testNow.Add(-24 * time.Hour), time.Unix(0, 0)} {
		u, p := f.unlock(1, 2, 3)
		_, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: 2, ValidFrom: vf})
		if !errors.Is(err, ErrOptions) || !strings.Contains(err.Error(), "before the current time") || len(p.asked) != 0 {
			t.Fatalf("%v: %v, asked %v", vf, err, p.asked)
		}
	}
	// The clock moves on while the shares are entered: checked again.
	u, p := f.unlock(1, 2, 3)
	calls := 0
	u.Now = func() time.Time {
		calls++
		if calls == 1 {
			return testNow
		}
		return testNow.Add(time.Hour)
	}
	_, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: 2, ValidFrom: testNow.Add(time.Minute)})
	if !errors.Is(err, ErrOptions) || len(p.asked) != 3 {
		t.Fatalf("after the shares: %v, asked %v", err, p.asked)
	}
	assertNothing(t, out, "")
	if names := listDir(t, kd); fmt.Sprint(names) != "[admin-1.key ingest-1.key]" {
		t.Fatalf("keys %v", names)
	}
	// Now itself.
	u, _ = f.unlock(1, 2, 3)
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: out, KeyDir: kd, Gen: 2, ValidFrom: testNow}); err != nil {
		t.Fatal(err)
	}
}

// TestRollbackAfterLink: a failure after the link of a key file (the
// temporary name not removed, the directory not synced) still removes
// that key on rollback (task 10d finding 5); for the first and the
// second key, in a key directory created by commit and in one that
// existed before.
func TestRollbackAfterLink(t *testing.T) {
	f := &fixture{base: t.TempDir(), w: []witness.Key{witnessKey(t, "w")}}
	defer func() { crashHook = nil }()
	for _, existing := range []bool{false, true} {
		for nth := 1; nth <= 2; nth++ {
			base := filepath.Join(f.base, fmt.Sprint(existing, nth))
			if err := os.Mkdir(base, 0o700); err != nil {
				t.Fatal(err)
			}
			out, kd := filepath.Join(base, "out"), filepath.Join(base, "keys")
			if existing {
				if err := os.Mkdir(kd, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			links := 0
			var atCrash []string
			crashHook = func(point string) error {
				if point != "link" {
					return nil
				}
				links++
				if links < nth {
					return nil
				}
				// The key is linked under its name; the temporary name
				// is still there.
				for _, n := range listDir(t, kd) {
					if !strings.HasPrefix(n, ".tmp-") {
						atCrash = append(atCrash, n)
					}
				}
				return errors.New("crash after link")
			}
			o := f.opts(out, kd, &prompter{scr: &screen{}})
			o.MinWitnesses = 1
			_, err := Init(o)
			if err == nil || !strings.Contains(err.Error(), "crash after link") {
				t.Fatalf("existing %v, key %d: %v", existing, nth, err)
			}
			if len(atCrash) != nth {
				t.Fatalf("existing %v, key %d: keys at the crash %v", existing, nth, atCrash)
			}
			assertNothing(t, out, kd)
			_, err = os.Lstat(kd)
			if existing != (err == nil) {
				t.Fatalf("existing %v, key %d: key directory %v", existing, nth, err)
			}
		}
	}
}
