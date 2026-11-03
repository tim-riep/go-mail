package testenv

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fatalTB is a testing.TB whose Fatal and Fatalf record the message and
// end the calling goroutine (runtime.Goexit, as testing does), so that a
// test can check that a helper of the package fails the test it was
// given. Everything else goes to the real test.
type fatalTB struct {
	testing.TB
	mu     sync.Mutex
	failed bool
	msg    string
	// dir, if set, is what TempDir returns.
	dir string
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) TempDir() string {
	if f.dir != "" {
		return f.dir
	}
	return f.TB.TempDir()
}

func (f *fatalTB) Fatal(args ...any) {
	f.mu.Lock()
	f.failed, f.msg = true, fmt.Sprint(args...)
	f.mu.Unlock()
	runtime.Goexit()
}

func (f *fatalTB) Fatalf(format string, args ...any) { f.Fatal(fmt.Sprintf(format, args...)) }

// expectFatal runs fn with a fatalTB in its own goroutine and fails t
// unless fn called Fatal before returning. It returns the message.
func expectFatal(t *testing.T, fn func(tb testing.TB)) string {
	t.Helper()
	return expectFatalIn(t, "", fn)
}

// expectFatalIn is expectFatal with a fatalTB whose TempDir is dir.
func expectFatalIn(t *testing.T, dir string, fn func(tb testing.TB)) string {
	t.Helper()
	f := &fatalTB{TB: t, dir: dir}
	done := make(chan bool)
	go func() {
		returned := false
		defer func() { done <- returned }()
		fn(f)
		returned = true
	}()
	if returned := <-done; returned {
		t.Fatal("returned without Fatal")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.failed {
		t.Fatal("goroutine ended without Fatal")
	}
	return f.msg
}

// TestClock: Now starts where Set put it, Advance moves it, concurrent
// use is safe (run with -race).
func TestClock(t *testing.T) {
	var c Clock
	if !c.Now().IsZero() {
		t.Fatal("zero clock")
	}
	c.Set(Start)
	if !c.Now().Equal(Start) {
		t.Fatal("Set")
	}
	c.Advance(90 * time.Minute)
	if want := Start.Add(90 * time.Minute); !c.Now().Equal(want) {
		t.Fatalf("Advance: %v, want %v", c.Now(), want)
	}
	c.Advance(-30 * time.Minute)
	if want := Start.Add(time.Hour); !c.Now().Equal(want) {
		t.Fatalf("Advance back: %v, want %v", c.Now(), want)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Advance(time.Second)
			_ = c.Now()
		}()
	}
	wg.Wait()
	if want := Start.Add(time.Hour + 8*time.Second); !c.Now().Equal(want) {
		t.Fatalf("concurrent Advance: %v, want %v", c.Now(), want)
	}
	if want := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC); !Start.Equal(want) {
		t.Fatalf("Start %v", Start)
	}
}

// TestWarnings: Take returns the warnings in order and clears them.
func TestWarnings(t *testing.T) {
	var w Warnings
	if l := w.Take(); l != nil {
		t.Fatalf("empty: %v", l)
	}
	w.Add("a")
	w.Add("b")
	if l := w.Take(); !reflect.DeepEqual(l, []string{"a", "b"}) {
		t.Fatalf("Take %v", l)
	}
	if l := w.Take(); l != nil {
		t.Fatalf("not cleared: %v", l)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.Add("x") }()
	}
	wg.Wait()
	if l := w.Take(); len(l) != 8 {
		t.Fatalf("concurrent Add: %d", len(l))
	}
}

// TestEcho: AskWord answers the word at a 1-based position; Words and
// Shares are copies, independent of the caller's slices and of each
// other; ShowShares replaces the shares shown before.
func TestEcho(t *testing.T) {
	var p Echo
	if p.Words() != nil || p.Shares() != nil {
		t.Fatal("empty echo")
	}
	w := []string{"alpha", "beta", "gamma"}
	if err := p.ShowWords(w); err != nil {
		t.Fatal(err)
	}
	w[0] = "changed"
	for i, want := range []string{"alpha", "beta", "gamma"} {
		if got, err := p.AskWord(i + 1); err != nil || got != want {
			t.Fatalf("AskWord(%d) = %q %v", i+1, got, err)
		}
	}
	got := p.Words()
	got[1] = "changed"
	if !reflect.DeepEqual(p.Words(), []string{"alpha", "beta", "gamma"}) {
		t.Fatalf("Words not a copy: %v", p.Words())
	}
	s := [][]string{{"a", "b"}, {"c"}}
	if err := p.ShowShares(s); err != nil {
		t.Fatal(err)
	}
	s[0][0] = "changed"
	sh := p.Shares()
	if !reflect.DeepEqual(sh, [][]string{{"a", "b"}, {"c"}}) {
		t.Fatalf("Shares %v", sh)
	}
	sh[1][0] = "changed"
	if !reflect.DeepEqual(p.Shares(), [][]string{{"a", "b"}, {"c"}}) {
		t.Fatalf("Shares not a copy: %v", p.Shares())
	}
	if err := p.ShowShares([][]string{{"d"}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Shares(), [][]string{{"d"}}) {
		t.Fatalf("ShowShares does not replace: %v", p.Shares())
	}
}

// TestVkeyData: the key part of a verifier key, "" for a malformed one.
func TestVkeyData(t *testing.T) {
	for in, want := range map[string]string{
		"name+0123abcd+QUJD":   "QUJD",
		"name+0123abcd+QU+JD":  "QU+JD",
		"name+0123abcd":        "",
		"name":                 "",
		"":                     "",
		"name+0123abcd+":       "",
		"testenv-witness+1+AA": "AA",
	} {
		if got := vkeyData(in); got != want {
			t.Errorf("vkeyData(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExpectFatal checks the helper itself: Fatalf records its
// message and ends the goroutine; TempDir is the given directory.
func TestExpectFatal(t *testing.T) {
	if msg := expectFatal(t, func(tb testing.TB) { tb.Fatalf("x%d", 1) }); msg != "x1" {
		t.Fatalf("message %q", msg)
	}
	dir := t.TempDir()
	if msg := expectFatalIn(t, dir, func(tb testing.TB) { tb.Fatal(tb.TempDir()) }); msg != dir {
		t.Fatalf("TempDir %q", msg)
	}
}

// TestPassphraseAndName pins the constants tests elsewhere rely on.
func TestPassphraseAndName(t *testing.T) {
	if string(Passphrase) != "correct horse battery staple" || WitnessName != "testenv-witness" {
		t.Fatal("constants changed")
	}
}
