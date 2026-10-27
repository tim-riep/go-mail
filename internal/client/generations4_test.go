package client_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 06h: device lost keeps the memory of a mailbox missing
// from the data directory, Sync clears the mark of an incomplete device
// lost only once the head no longer names the revoked generation, the
// warning about an own wrap names the revoked generation, the seed proves
// own wraps only (with keys equal to epoch.rec), and a planted mailbox
// with a broken chain is not adopted.

// memory is what the state of a client directory remembers of one
// mailbox, as far as no path may make it smaller (mailboxState).
type memory struct {
	Epoch     uint32                     `json:"epoch"`
	EpochHash string                     `json:"epoch_hash"`
	Versions  map[string]uint32          `json:"versions"`
	Epochs    map[string]json.RawMessage `json:"epochs"`
	Recovery  map[string]string          `json:"recovery"`
	Folders   map[string]uint32          `json:"folders"`
	Checked   map[string]json.RawMessage `json:"checked"`
	Mails     map[string]json.RawMessage `json:"mails"`
	Reissue   uint32                     `json:"reissue"`
}

// memoryOf returns the memory of mbx in the state of the client directory
// dir (nil if the state does not name it).
func memoryOf(t *testing.T, dir string, mbx store.ID) *memory {
	t.Helper()
	var st struct {
		Mailboxes map[string]*memory `json:"mailboxes"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	return st.Mailboxes[mbx.String()]
}

// notSmaller fails if after forgets anything of before: the fixed rule of
// task 06h, no path makes the memory of a mailbox smaller. A discarded
// epoch stays discarded, a check record may only be replaced by a newer
// one (takeover), the highest epoch seen never falls and keeps its hash
// unless it rises.
func notSmaller(t *testing.T, what string, before, after *memory) {
	t.Helper()
	if before == nil {
		return
	}
	if after == nil {
		t.Fatalf("%s: the mailbox left the state", what)
	}
	if after.Epoch < before.Epoch || (after.Epoch == before.Epoch && after.EpochHash != before.EpochHash) {
		t.Fatalf("%s: highest epoch %d %s, before %d %s", what, after.Epoch, after.EpochHash, before.Epoch, before.EpochHash)
	}
	for k, v := range before.Versions {
		if after.Versions[k] < v {
			t.Fatalf("%s: version of %s fell", what, k)
		}
	}
	for k, v := range before.Folders {
		if after.Folders[k] < v {
			t.Fatalf("%s: version of folders.gml of epoch %s fell", what, k)
		}
	}
	for k, v := range before.Epochs {
		w, ok := after.Epochs[k]
		if !ok {
			t.Fatalf("%s: epoch %s forgotten", what, k)
		}
		if strings.Contains(string(v), `"discarded":true`) && !strings.Contains(string(w), `"discarded":true`) {
			t.Fatalf("%s: discarded epoch %s valid again", what, k)
		}
	}
	for k, v := range before.Recovery {
		if after.Recovery[k] != v {
			t.Fatalf("%s: recovery record %s forgotten", what, k)
		}
	}
	for k := range before.Checked {
		if _, ok := after.Checked[k]; !ok {
			t.Fatalf("%s: check record %s forgotten", what, k)
		}
	}
	for k, v := range before.Mails {
		if string(after.Mails[k]) != string(v) {
			t.Fatalf("%s: memo of mail %s changed", what, k)
		}
	}
}

// noSeed fails if a warning holds two consecutive seed words.
func noSeed(t *testing.T, warnings []string, words []string) {
	t.Helper()
	for _, w := range warnings {
		lw := strings.ToLower(w)
		for i := 0; i+1 < len(words); i++ {
			if strings.Contains(lw, strings.ToLower(words[i]+" "+words[i+1])) {
				t.Fatalf("warning holds seed words: %s", w)
			}
		}
	}
}

// rollbackTo resets mailbox.rec of mbx to epoch n and removes the epoch
// directories after n: a server putting back an old state (2.4).
func rollbackTo(t *testing.T, env *testenv.Env, mbx store.ID, n uint32) {
	t.Helper()
	m, err := env.Store.ReadMailbox(mbx)
	if err != nil {
		t.Fatal(err)
	}
	epochs, err := env.Store.ListEpochs(mbx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range epochs {
		if e > n {
			if err := os.RemoveAll(env.Store.EpochDir(mbx, e)); err != nil {
				t.Fatal(err)
			}
		}
	}
	m.Epoch = n
	if err := env.Store.WriteMailbox(m); err != nil {
		t.Fatal(err)
	}
}

// editState changes the memory of mbx in state.json of the client
// directory dir (the client is closed).
func editState(t *testing.T, dir string, mbx store.ID, change func(ms map[string]any)) {
	t.Helper()
	p := filepath.Join(dir, "state.json")
	var st map[string]any
	if err := json.Unmarshal(mustRead(t, p), &st); err != nil {
		t.Fatal(err)
	}
	boxes, _ := st["mailboxes"].(map[string]any)
	ms, ok := boxes[mbx.String()].(map[string]any)
	if !ok {
		t.Fatal("the state does not name the mailbox")
	}
	change(ms)
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// forgetChecks removes the check records of mbx from the state of the
// client directory dir and returns them: the client then has no proof
// that it verified folders.gml before the revocation.
func forgetChecks(t *testing.T, dir string, mbx store.ID) any {
	t.Helper()
	var checked any
	editState(t, dir, mbx, func(ms map[string]any) {
		var ok bool
		if checked, ok = ms["checked"]; !ok {
			t.Fatal("no check records to forget")
		}
		delete(ms, "checked")
	})
	return checked
}

// TestMissingMailboxKeepsState (task 06h finding 1, after the verifier's
// TestVerifyMissingMailboxState): alice has seen the epochs of her
// mailbox, read a mail and recorded folders.gml. Variants:
//
//   - control: mailbox.rec is present during device lost; afterwards the
//     server rolls the mailbox back to epoch 1: detected.
//   - hidden-rollback: mailbox.rec is missing during the whole device
//     lost; the mailbox stays in the state with all its memory and no
//     mark; then the same rollback: device lost run again detects it.
//   - hidden-intact: mailbox.rec is missing during the whole device lost
//     and put back unchanged: device lost run again completes the mailbox
//     with the kept check records, and List, Folders, Sync and Read work.
func TestMissingMailboxKeepsState(t *testing.T) {
	for _, v := range []string{"control", "hidden-rollback", "hidden-intact"} {
		t.Run(v, func(t *testing.T) {
			hide := strings.HasPrefix(v, "hidden")
			f := newFixture(t)
			old := f.deliver(t, "old", "secret")
			if len(chainOf(t, f.env, f.mbx)) < 4 {
				t.Fatal("no supply")
			}
			if err := f.u.Client.Sync(); err != nil {
				t.Fatal(err)
			}
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			cfg := f.env.ClientConfig(f.u.Dir)
			before := memoryOf(t, f.u.Dir, f.mbx)
			if before == nil || before.Epoch < 4 || len(before.Checked) == 0 || len(before.Epochs) < 4 {
				t.Fatalf("no memory to keep: %+v", before)
			}
			mrec := f.env.Store.MailboxFile(f.mbx)
			if hide {
				if err := os.Rename(mrec, mrec+".hidden"); err != nil {
					t.Fatal(err)
				}
			}
			f.env.Warnings.Take()
			gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
			if gen != 2 || (err != nil) != hide || (hide && !errors.Is(err, client.ErrPartial)) {
				t.Fatalf("device lost: generation %d, %v", gen, err)
			}
			w := f.env.Warnings.Take()
			noSeed(t, w, f.u.Words)
			after := memoryOf(t, f.u.Dir, f.mbx)
			notSmaller(t, "first device lost", before, after)
			if hide {
				if err := os.Rename(mrec+".hidden", mrec); err != nil {
					t.Fatal(err)
				}
				warningWith(t, w, f.mbx.String(), "fehlt im Datenverzeichnis", "eine neue wird nicht gesetzt", "bleibt erhalten")
				if after.Reissue != 0 || after.Epoch != before.Epoch || after.EpochHash != before.EpochHash || len(after.Checked) != len(before.Checked) {
					t.Fatalf("memory after device lost: %+v, before %+v", after, before)
				}
			}
			if v != "hidden-intact" {
				rollbackTo(t, f.env, f.mbx, 1)
			}
			f.env.Clock.Advance(time.Minute)
			f.env.Warnings.Take()
			gen, err = client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
			w = f.env.Warnings.Take()
			noSeed(t, w, f.u.Words)
			if gen != 3 {
				t.Fatalf("second device lost: generation %d, %v", gen, err)
			}
			notSmaller(t, "second device lost", after, memoryOf(t, f.u.Dir, f.mbx))
			if v != "hidden-intact" {
				// The rollback is detected (2.4): the mailbox is marked and
				// not worked on.
				if !errors.Is(err, client.ErrPartial) {
					t.Fatalf("second device lost on a rolled back mailbox: %v", err)
				}
				warningWith(t, w, f.mbx.String(), "gesehen wurde bereits")
				f.env.Warnings.Take()
				if _, err := f.env.Reopen(f.u).List(f.mbx, store.ID{}); err == nil {
					warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "gesehen wurde bereits")
				}
				return
			}
			if err != nil {
				t.Fatalf("second device lost: %v\n%s", err, strings.Join(w, "\n"))
			}
			if m := reissueMark(t, f.u.Dir, f.mbx); m != 0 {
				t.Fatalf("mark %d", m)
			}
			c := f.env.Reopen(f.u)
			if _, err := c.List(f.mbx, store.ID{}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Folders(f.mbx); err != nil {
				t.Fatal(err)
			}
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			readBody(t, f.env, c, f.mbx, old.ID, "secret")
			ownWrapsFor(t, f, f.u, 3)
			if g := headGen(t, f, f.u); g != 3 {
				t.Fatalf("head names generation %d", g)
			}
			if m := memoryOf(t, f.u.Dir, f.mbx); len(m.Checked) == 0 {
				t.Fatal("no check records")
			}
		})
	}
}

// TestRollbackMemoryKeptByDeviceLost (after the verifier's
// TestRollbackMemoryWipedByDeviceLost): mailbox.rec is removed around a
// device lost; afterwards the server writes it back pointing to epoch 1.
// The memory of the highest epoch seen survived the device lost, so List
// warns about the rollback (2.4).
func TestRollbackMemoryKeptByDeviceLost(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	f.env.Share(f.u, f.mbx, bob, client.ShareOptions{})
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	m, err := f.env.Store.ReadMailbox(f.mbx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Epoch < 2 {
		t.Fatalf("head %d", m.Epoch)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	if err := os.Remove(f.env.Store.MailboxFile(f.mbx)); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	back := *m
	back.Epoch = 1
	if err := f.env.Store.WriteMailbox(&back); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	f.env.Reopen(f.u).List(f.mbx, store.ID{})
	warningWith(t, f.env.Warnings.Take(), f.mbx.String(), "gesehen wurde bereits")
}

// TestSyncKeepsMarkUntilGenerationRevoked (task 06h finding 2): alice is
// the only member of her mailbox. Her first device lost runs while
// mailbox.rec is missing (her memory stays, finding 1); afterwards her
// check records are lost, so the second device lost seals her own wraps
// for generation 3 (the seed proves them) but cannot take over folders.gml
// signed by generation 1 nor create the epoch generation-revoked:
// ErrPartial, marked. Sync cannot create it either (no checked folder
// list of the newest epoch): it keeps the mark and reports ErrPartial
// with the fixed cause of Q18 (task 14, 06h point 3) instead of a hint.
// Once the check records are back, Sync (variant sync) or device lost run
// again (variant device-lost, generation 4 since task 14) takes over
// folders.gml, creates the epoch and clears the mark.
func TestSyncKeepsMarkUntilGenerationRevoked(t *testing.T) {
	for _, v := range []string{"sync", "device-lost"} {
		t.Run(v, func(t *testing.T) {
			f := newFixture(t)
			old := f.deliver(t, "old", "secret")
			if err := f.u.Client.Sync(); err != nil {
				t.Fatal(err)
			}
			f.env.Clock.Advance(time.Minute)
			f.u.Client.Close()
			cfg := f.env.ClientConfig(f.u.Dir)
			mrec := f.env.Store.MailboxFile(f.mbx)
			if err := os.Rename(mrec, mrec+".hidden"); err != nil {
				t.Fatal(err)
			}
			if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
				t.Fatalf("device lost: generation %d, %v", gen, err)
			}
			if err := os.Rename(mrec+".hidden", mrec); err != nil {
				t.Fatal(err)
			}
			checked := forgetChecks(t, f.u.Dir, f.mbx)
			f.env.Clock.Advance(time.Minute)
			gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words)
			if gen != 3 || !errors.Is(err, client.ErrPartial) {
				t.Fatalf("second device lost: generation %d, %v", gen, err)
			}
			if m := reissueMark(t, f.u.Dir, f.mbx); m != 3 {
				t.Fatalf("mark %d", m)
			}
			ownWrapsFor(t, f, f.u, 3)
			if g := headGen(t, f, f.u); g != 1 {
				t.Fatalf("head names generation %d", g)
			}
			before := chainOf(t, f.env, f.mbx)
			f.env.Warnings.Take()
			err = f.env.Reopen(f.u).Sync()
			if !errors.Is(err, client.ErrPartial) || !strings.Contains(err.Error(), "no checked folder list") || !strings.Contains(err.Error(), "Q18") ||
				strings.Contains(err.Error(), "device lost again") {
				t.Fatalf("Sync: %v", err)
			}
			w := f.env.Warnings.Take()
			warningWith(t, w, f.mbx.String(), "einzige Mitglied", "keine geprüfte Ordnerliste der Epoche", "derzeit keine Abhilfe, siehe Q18")
			for _, s := range w {
				if strings.Contains(s, "device lost erneut") {
					t.Fatalf("remedy that never helps: %s", s)
				}
			}
			noSeed(t, w, f.u.Words)
			if m := reissueMark(t, f.u.Dir, f.mbx); m != 3 {
				t.Fatalf("mark %d after Sync", m)
			}
			if len(chainOf(t, f.env, f.mbx)) != len(before) {
				t.Fatal("Sync created an epoch")
			}
			f.u.Client.Close()
			editState(t, f.u.Dir, f.mbx, func(ms map[string]any) { ms["checked"] = checked })
			now := f.env.Clock.Now()
			if v == "sync" {
				if err := f.env.Reopen(f.u).Sync(); err != nil {
					t.Fatalf("Sync with the check records: %v", err)
				}
			} else if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 4 || err != nil {
				t.Fatalf("device lost with the check records: generation %d, %v", gen, err)
			}
			checkImmediate(t, before, chainOf(t, f.env, f.mbx), now, store.ReasonGenerationRevoked)
			want := uint32(3)
			if v != "sync" {
				want = 4
			}
			if g := headGen(t, f, f.u); g != want {
				t.Fatalf("head names generation %d", g)
			}
			if n := generations(t, f, f.u); n != int(want) {
				t.Fatalf("%d generations", n)
			}
			if m := reissueMark(t, f.u.Dir, f.mbx); m != 0 {
				t.Fatalf("mark %d after the epoch", m)
			}
			c := f.env.Reopen(f.u)
			if err := c.Sync(); err != nil {
				t.Fatal(err)
			}
			readBody(t, f.env, c, f.mbx, old.ID, "secret")
		})
	}
}

// TestOwnWrapRevokedCause (task 06h finding 3): alice moves to generation
// 2 without device lost (testenv.Rotate), so her own wraps stay signed by
// generation 1, and no wrap-accept of generation 2 names them. Reading
// warns with the fixed cause of a revoked generation, not with the one of
// an invalid signature.
func TestOwnWrapRevokedCause(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.env.Rotate(f.u)
	f.env.Warnings.Take()
	if _, _, err := f.env.Reopen(f.u).Read(f.mbx, old.ID); err == nil {
		t.Fatal("the own wrap of a revoked generation without wrap-accept is used")
	}
	warningWith(t, f.env.Warnings.Take(), "Verpackung der Epoche 1 von "+f.mbx.String()+" abgelehnt", client.WarnCause(client.ErrRevoked))
}

// TestSeedProofMatchesKeys (task 06h finding 4, the verifier's
// TestVerifySeedProofMatches): like TestSeedProofNeedsMatchingKeys, but
// the planted own wrap holds well-formed epoch keys that differ from
// epoch.rec, so that only Matches in openOwnWrap rejects it. The
// continuation does not seal it again for generation 2, and epoch 1 does
// not open with it.
func TestSeedProofMatchesKeys(t *testing.T) {
	f := newFixture(t)
	f.deliver(t, "old", "secret")
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	planted := plantOwnWrapWithKeys(t, f.env, f.mbx, 1, f.u, 1)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); !errors.Is(err, client.ErrPartial) {
		t.Fatal(err)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 3 || err != nil {
		t.Fatalf("continuation: generation %d, %v", gen, err)
	}
	w := f.env.Warnings.Take()
	if got := mustRead(t, f.env.Store.WrapFile(f.mbx, 1, f.u.ID)); string(got) != string(planted) {
		t.Fatalf("the planted own wrap with other keys was sealed again for the new generation\n%s", strings.Join(w, "\n"))
	}
	warningWith(t, w, "Schlüssel der Verpackung passen nicht zur signierten Epoche 1")
	if _, err := f.env.Reopen(f.u).FoldersOfEpoch(f.mbx, 1); err == nil {
		t.Fatal("epoch 1 opens with the planted wrap")
	}
}

// TestFoldersNotCheckedBeforeDeviceLost (task 06h finding 4, the
// verifier's TestVerifyFoldersNotCheckedBeforeDeviceLost): folders.gml of
// every epoch is signed by alice's generation 1, and her client has no
// check record for them (2.2 rule 4: a file no client checked before the
// revocation is not taken over). mailbox.rec is invalid during step 2, so
// step 2 records nothing while generation 1 is valid; the continuation
// leaves folders.gml signed by generation 1 and warns: the seed proves own
// wraps only, never folders.gml or a file of another signer.
func TestFoldersNotCheckedBeforeDeviceLost(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	forgetChecks(t, f.u.Dir, f.mbx)
	cfg := f.env.ClientConfig(f.u.Dir)
	mrec := f.env.Store.MailboxFile(f.mbx)
	good := mustRead(t, mrec)
	if err := store.WriteFileAtomic(mrec, []byte("not a mailbox record")); err != nil {
		t.Fatal(err)
	}
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("device lost: generation %d, %v", gen, err)
	}
	if err := store.WriteFileAtomic(mrec, good); err != nil {
		t.Fatal(err)
	}
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 3 || !errors.Is(err, client.ErrPartial) {
		t.Fatalf("continuation: generation %d, %v", gen, err)
	}
	w := strings.Join(f.env.Warnings.Take(), "\n")
	for _, e := range chainOf(t, f.env, f.mbx) {
		tr := parse(t, mustRead(t, f.env.Store.FoldersFile(f.mbx, e.Number))).Trailer
		if store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 1 {
			t.Fatalf("folders.gml of epoch %d taken over without a check record: signed by generation %d\n%s", e.Number, tr.Signer.Gen, w)
		}
	}
	if !strings.Contains(w, "vorher nicht geprüft") {
		t.Fatalf("no warning:\n%s", w)
	}
	// The own wraps are sealed again regardless (seed proof), the mail reads.
	ownWrapsFor(t, f, f.u, 3)
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}

// TestPlantedBrokenMailboxNotMarked (task 06h finding 5, after the
// verifier's TestA3PlantedBrokenMailboxMark): a writer of the data
// directory plants a wrap for alice in mallory's mailbox, whose
// mailbox.rec it breaks. Alice never opened that mailbox; device lost
// does not adopt it (its chain does not verify) and marks nothing, so a
// plain device lost run again creates generation 3.
func TestPlantedBrokenMailboxNotMarked(t *testing.T) {
	f := newFixture(t)
	old := f.deliver(t, "old", "secret")
	mallory := f.env.NewUser("mallory")
	mbox := f.env.Mailbox(mallory, "M", "m@example.org")
	id1m := identityOf(t, mallory.Words, 1)
	defer keys.Wipe(id1m)
	plantWrap(t, f.env, mbox, 1, f.u.ID, 1, mallory.ID, 1, id1m)
	if err := store.WriteFileAtomic(f.env.Store.MailboxFile(mbox), []byte("broken")); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	f.u.Client.Close()
	cfg := f.env.ClientConfig(f.u.Dir)
	f.env.Warnings.Take()
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("first device lost: generation %d, %v", gen, err)
	}
	w := f.env.Warnings.Take()
	warningWith(t, w, mbox.String(), "noch nicht geöffnet", "Epochenkette prüft nicht", "merkt nichts vor")
	noSeed(t, w, f.u.Words)
	if knows(t, f.u.Dir, mbox) || reissueMark(t, f.u.Dir, mbox) != 0 {
		t.Fatal("the planted mailbox was adopted")
	}
	f.env.Clock.Advance(time.Minute)
	if gen, err := client.DeviceLost(cfg, testenv.Passphrase, f.u.Words); gen != 3 || err != nil {
		t.Fatalf("second device lost: generation %d, %v", gen, err)
	}
	if n := generations(t, f, f.u); n != 3 {
		t.Fatalf("%d generations", n)
	}
	ownWrapsFor(t, f, f.u, 3)
	readBody(t, f.env, f.env.Reopen(f.u), f.mbx, old.ID, "secret")
}
