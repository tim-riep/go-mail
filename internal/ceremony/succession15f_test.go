package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// TestVerifyCompromisedIdentityStillIssues is the test that 10.1 asks
// for the compromise of the platform identity (2.3: "Clients lehnen ab
// diesem Update jede Signatur der kompromittierten Generation ab"), taken
// over from the review of task 15b. After succeed --compromised (pin 2
// without succession, generation 1 still in its identity list so that
// old certificates stay verifiable) the owner of the stolen identity key
// 1 issues ingest-3.cert and admin-2.cert. They must neither be
// published with pin 2 nor be valid in its operator log. Nothing in the
// pin, the succession or the log marks generation 1 as compromised, so
// today they would be (the review reproduced it); the compromise case is
// therefore locked (ErrCompromised) and this test is skipped until Q19
// specifies the revocation (a record revocation-<g>.rec signed by the new
// identity, or pin field 7 after Q8). Whoever lifts the lock removes the
// Skip; the test then has to pass.
func TestVerifyCompromisedIdentityStillIssues(t *testing.T) {
	t.Skip("Q19: the revocation of a compromised platform generation is not specified; succeed --compromised is locked (ErrCompromised) until it is")
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "succ2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin, Compromised: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	// Ingest rotation under identity 2 (the intended reaction).
	u, _ = f.unlock(3, 4, 5)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	rot := filepath.Join(f.base, "rot")
	if _, err := IngestRotate(RotateOptions{UnlockOptions: u, Out: rot, KeyDir: filepath.Join(f.base, "keys"), Gen: 2}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: rot, Data: st, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	// The attacker with the key of the compromised generation 1:
	// ingest-3.cert and admin-2.cert issued by identity_gen 1.
	i3pub, i3 := f.cert(t, 1, keys.RoleIngest, 3)
	a2pub, a2 := f.cert(t, 1, keys.RoleAdmin, 2)
	dir := writeExport(t, filepath.Join(f.base, "attack"), map[string][]byte{
		"ingest-3.pub": i3pub, "ingest-3.cert": i3, "admin-2.pub": a2pub, "admin-2.cert": a2})
	if err := Publish(PublishOptions{From: dir, Data: st, Pin: res2.Pin}); err == nil {
		t.Fatal("publish takes certificates issued by the compromised generation 1 with pin 2")
	}
	l, err := OpenLog(st, res2.Pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ingest-3.cert", "admin-2.cert"} {
		data := i3
		if n == "admin-2.cert" {
			data = a2
		}
		if err := l.CheckPlatform(n, data); err == nil {
			t.Fatalf("%s issued by the compromised generation 1 is valid in the operator log of pin 2", n)
		}
	}
}

// TestVerifySuccessionGap (task 15f point 3, taken over from the review
// of task 15b): two regular successions, only the second published.
// Publish with pin 3 refuses identity-3.succ without identity-2.succ in
// the export, in data/platform/ or in the log (translog.ErrPrerequisite,
// with a hint), before anything is written; a client with pin 1 could
// not follow the chain. With identity-2.succ in the export, or published
// before, identity-3.succ goes through.
func TestVerifySuccessionGap(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.unlock(1, 2, 3)
	out2 := filepath.Join(f.base, "s2")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out2, Pin: f.res.Pin})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = f.unlock(2, 3, 4)
	u.IdentityGen, u.IdentityPub = 2, res2.IdentityPub
	out3 := filepath.Join(f.base, "s3")
	res3, err := Succeed(SucceedOptions{UnlockOptions: u, Out: out3, Pin: res2.Pin})
	if err != nil {
		t.Fatal(err)
	}
	before := listDir(t, filepath.Join(st.Root, "platform"))
	// out2 is not published.
	err = Publish(PublishOptions{From: out3, Data: st, Pin: res3.Pin})
	if !errors.Is(err, translog.ErrPrerequisite) || !strings.Contains(err.Error(), "identity-2.succ") {
		t.Fatalf("publish of generation 3 without generation 2: %v", err)
	}
	if after := listDir(t, filepath.Join(st.Root, "platform")); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("written: %v", after)
	}
	// A client with pin 1 cannot follow identity-3.succ alone.
	raw := mustReadFile(t, filepath.Join(out3, "platform", "identity-3.succ"))
	l1, err := translog.Open(translog.Options{Store: st, Identities: []translog.Identity{{Gen: 1, Pub: f.res.IdentityPub}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l1.CheckPlatform("identity-3.succ", raw); err == nil {
		t.Fatal("pin-1 log accepts identity-3.succ without identity-2.succ")
	}

	// Both successions in one export: in order.
	both := writeExport(t, filepath.Join(f.base, "both"), map[string][]byte{
		"identity-2.pub":  mustReadFile(t, filepath.Join(out2, "platform", "identity-2.pub")),
		"identity-2.succ": mustReadFile(t, filepath.Join(out2, "platform", "identity-2.succ")),
		"identity-3.pub":  mustReadFile(t, filepath.Join(out3, "platform", "identity-3.pub")),
		"identity-3.succ": raw,
	})
	stB := newData(t, filepath.Join(f.base, "dataB"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: stB, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: both, Data: stB, Pin: res3.Pin}); err != nil {
		t.Fatalf("both successions: %v", err)
	}
	// One after the other: identity-2.succ in data/platform/ and the log.
	if err := Publish(PublishOptions{From: out2, Data: st, Pin: res3.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out3, Data: st, Pin: res3.Pin}); err != nil {
		t.Fatalf("after identity-2.succ: %v", err)
	}
	if err := l1.CheckPlatform("identity-3.succ", raw); err != nil {
		t.Fatalf("pin-1 log after both successions: %v", err)
	}

	// In the log only (the file of data/platform/ gone): enough.
	stL := newData(t, filepath.Join(f.base, "dataL"))
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: stL, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out2, Data: stL, Pin: res3.Pin}); err != nil {
		t.Fatal(err)
	}
	if err := removePlatformFile(stL, "identity-2.succ"); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: out3, Data: stL, Pin: res3.Pin}); err != nil {
		t.Fatalf("identity-2.succ only in the log: %v", err)
	}
}

// removePlatformFile removes platform/<name> of a data directory.
func removePlatformFile(st *store.Store, name string) error {
	return os.Remove(st.Path("platform", name))
}

// TestPublishReplaceWitnesses (task 15f point 2): a data directory whose
// witnesses.rec differs from the pin is refused without ReplaceWitnesses
// (translog.ErrMismatch, nothing written or logged) and replaced by the
// pin's with it, after every other check, atomically; WitnessesReplaced
// gets the old and the new working copy. An export whose witnesses.rec
// differs from the pin is refused even with ReplaceWitnesses, and so is
// a pin that does not know the identity generations of the data
// directory, and a working copy that does not decode.
func TestPublishReplaceWitnesses(t *testing.T) {
	f := newFixture(t)
	st := newData(t, filepath.Join(f.base, "data"))
	log := newLog(t)
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: log, Pin: f.res.Pin}); err != nil {
		t.Fatal(err)
	}
	old := mustReadFile(t, filepath.Join(st.Root, "platform", WitnessesFile))
	// Succession 1 to 2 with one witness, quorum 1.
	u, _ := f.unlock(1, 2, 3)
	succ := filepath.Join(f.base, "succ")
	res2, err := Succeed(SucceedOptions{UnlockOptions: u, Out: succ, Pin: f.res.Pin, Witnesses: f.w[:1], MinWitnesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	report := func(o, n *witness.Witnesses) {
		calls++
		if o.Min != 2 || len(o.List) != 3 || n.Min != 1 || len(n.List) != 1 || n.List[0].Name != "w1" {
			t.Errorf("reported %+v -> %+v", o, n)
		}
	}
	log.names = nil
	err = Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin, WitnessesReplaced: report})
	if !errors.Is(err, translog.ErrMismatch) || !strings.Contains(err.Error(), "replace-witnesses") || len(log.names) != 0 || calls != 0 {
		t.Fatalf("without ReplaceWitnesses: %v %v", err, log.names)
	}
	if _, err := st.ReadPlatformFile("identity-2.succ"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("succession copied")
	}
	// A witnesses.rec in the export that is not the pin's: refused even
	// with the flag.
	otherW, _ := (&witness.Witnesses{List: f.w, Min: 2}).Encode()
	bad := writeExport(t, filepath.Join(f.base, "bad"), map[string][]byte{WitnessesFile: otherW})
	if err := Publish(PublishOptions{From: bad, Data: st, Log: log, Pin: res2.Pin, ReplaceWitnesses: true}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("export witnesses.rec: %v", err)
	}
	// A check that fails after the witnesses: nothing replaced.
	_, ingest3 := f.cert(t, 2, keys.RoleIngest, 3)
	gap := writeExport(t, filepath.Join(f.base, "gap"), map[string][]byte{"ingest-3.cert": ingest3, "ingest-3.pub": make([]byte, 32)})
	if err := Publish(PublishOptions{From: gap, Data: st, Log: log, Pin: res2.Pin, ReplaceWitnesses: true, WitnessesReplaced: report}); err == nil {
		t.Fatal("bad export")
	}
	if !bytes.Equal(mustReadFile(t, filepath.Join(st.Root, "platform", WitnessesFile)), old) || calls != 0 {
		t.Fatal("witnesses.rec replaced by a refused publish")
	}
	// With the flag: replaced.
	log.names = nil
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin, ReplaceWitnesses: true, WitnessesReplaced: report}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || fmt.Sprint(log.names) != "[identity-2.succ]" {
		t.Fatalf("replaced %d times, log %v", calls, log.names)
	}
	want, _ := (&witness.Witnesses{List: f.w[:1], Min: 1}).Encode()
	if got := mustReadFile(t, filepath.Join(st.Root, "platform", WitnessesFile)); !bytes.Equal(got, want) {
		t.Fatal("witnesses.rec is not the pin's")
	}
	assertNoTemp(t, filepath.Join(st.Root, "platform"))
	// Equal now: the flag replaces nothing, without the flag it passes.
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin, ReplaceWitnesses: true, WitnessesReplaced: report}); err != nil || calls != 1 {
		t.Fatalf("again: %v, %d", err, calls)
	}
	if err := Publish(PublishOptions{From: succ, Data: st, Log: log, Pin: res2.Pin}); err != nil {
		t.Fatal(err)
	}
	// The old pin does not know generation 2 of the data directory: the
	// flag does not let it replace anything.
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: st, Log: log, Pin: f.res.Pin, ReplaceWitnesses: true, WitnessesReplaced: report}); !errors.Is(err, translog.ErrMismatch) {
		t.Fatalf("old pin: %v", err)
	}
	if got := mustReadFile(t, filepath.Join(st.Root, "platform", WitnessesFile)); !bytes.Equal(got, want) || calls != 1 {
		t.Fatal("witnesses.rec replaced with the old pin")
	}
	// A working copy that does not decode is refused with the flag too.
	stX := newData(t, filepath.Join(f.base, "dataX"))
	if err := store.WriteFileAtomic(stX.Path("platform", WitnessesFile), []byte("not a record")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(PublishOptions{From: filepath.Join(f.base, "out"), Data: stX, Log: log, Pin: f.res.Pin, ReplaceWitnesses: true}); !errors.Is(err, witness.ErrWitnesses) {
		t.Fatalf("malformed witnesses.rec: %v", err)
	}
}

// assertNoTemp checks that dir holds no temporary file of an atomic
// write.
func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	for _, n := range listDir(t, dir) {
		if strings.Contains(n, ".tmp") {
			t.Fatalf("temporary file %s left", n)
		}
	}
}
