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
	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/store"
)

// at returns the time hh:mm on the day of testenv.Start (2026-10-26 UTC).
func at(hh, mm int) time.Time {
	return time.Date(2026, 10, 26, hh, mm, 0, 0, time.UTC)
}

// discardFixture: epochs 1 (10:00), 2 (1.11.), 3 (1.12.), 4 (1.1.), then
// 5 member-removed beginning at 12:00 that discards 2, 3 and 4, signed by
// the member alice (2.4, K1).
func discardFixture(t *testing.T) (*fixture, map[uint32]*store.Epoch) {
	t.Helper()
	f := newFixture(t)
	e5 := f.env.ImmediateEpoch(f.u, f.mbx, at(12, 0), store.ReasonMemberRemoved, "A")
	if len(e5.Discards) != 3 || e5.Discards[0] != 2 || e5.Discards[2] != 4 {
		t.Fatalf("discards %v", e5.Discards)
	}
	es := map[uint32]*store.Epoch{}
	for n := uint32(1); n <= 5; n++ {
		e, _, err := f.env.Store.ReadEpoch(f.mbx, n)
		if err != nil {
			t.Fatal(err)
		}
		es[n] = e
	}
	return f, es
}

// epochCases are the cases of task 02b for mails, term lists and markers.
var epochCases = []struct {
	name     string
	epoch    uint32
	received time.Time
	want     error // nil: accepted
}{
	{"epoch 1 after the begin of 5", 1, at(13, 0), client.ErrStaleEpoch},
	{"discarded epoch 2", 2, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), client.ErrDiscardedEpoch},
	{"discarded epoch 2 before its begin", 2, at(11, 0), client.ErrDiscardedEpoch},
	{"discarded epoch 4", 4, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), client.ErrDiscardedEpoch},
	{"epoch 5 within the lead time", 5, at(11, 56), nil},
	{"epoch 5 before the lead time", 5, at(11, 54), client.ErrStaleEpoch},
	{"epoch 5 after its begin", 5, at(12, 30), nil},
	{"epoch 1 before the begin of 5", 1, at(11, 30), nil},
	{"epoch 1 within the lead time of 5", 1, at(11, 56), nil},
	{"epoch 1 at the begin of 5", 1, at(12, 0), client.ErrStaleEpoch},
	// The lead time applies to immediate epochs only: the planned epoch 1
	// (10:00) does not accept a receipt a minute before its begin.
	{"planned epoch 1 before its begin", 1, at(9, 59), client.ErrStaleEpoch},
}

func TestDiscardedAndImmediateEpochsMails(t *testing.T) {
	f, es := discardFixture(t)
	accepted := 0
	for _, tc := range epochCases {
		id := f.forge(t, es[tc.epoch], tc.received, "body "+tc.name, 1, f.env.IngestKey, 1)
		f.env.Warnings.Take()
		_, content, err := f.u.Client.Read(f.mbx, id)
		if tc.want == nil {
			if err != nil || string(content) != "body "+tc.name {
				t.Fatalf("%s: %v", tc.name, err)
			}
			accepted++
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		// K8: shown as not deliverable, to be requested again, without
		// content.
		ws := f.env.Warnings.Take()
		found := false
		for _, w := range ws {
			if strings.Contains(w, "body") {
				t.Fatalf("warning carries content: %q", w)
			}
			found = found || strings.Contains(w, id.String()) && strings.Contains(w, "nicht zustellbar, bitte erneut anfordern")
		}
		if !found {
			t.Fatalf("%s: warnings %q", tc.name, ws)
		}
	}
	list, err := f.u.Client.List(f.mbx, store.ID{})
	if err != nil || len(list) != accepted {
		t.Fatalf("listed %d of %d: %v", len(list), accepted, err)
	}
	if !warned(f.env, "nicht zustellbar") {
		t.Fatal("List does not warn")
	}
}

// forgePending writes a marker for epoch e created at created, signed
// with the ingest key, into pending/<n>/.
func (f *fixture) forgePending(t *testing.T, e *store.Epoch, created time.Time) store.ID {
	t.Helper()
	id, _ := store.NewID(nil)
	p := &store.Pending{MailboxID: f.mbx, Epoch: e.Number, Entries: []store.PendingEntry{{MailID: id, Unprocessed: true}}}
	plain, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := envelope.Seal(envelope.Header{Kind: envelope.KindPending, MailboxID: f.mbx, Epoch: e.Number, FileID: id, Created: created.UnixMilli()},
		[]envelope.Recipient{{Type: envelope.RecipientEpochMeta, ID: f.mbx, Gen: e.Number, PublicKey: e.MetaPub}}, plain,
		&envelope.SealOptions{Signer: &envelope.Signer{Type: envelope.SignerIngest, Gen: 1, Key: f.env.IngestKey}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirAll(f.env.Store.PendingDir(f.mbx, e.Number)); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateFileAtomic(f.env.Store.PendingFile(f.mbx, e.Number, id), data); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDiscardedAndImmediateEpochsPending(t *testing.T) {
	f, es := discardFixture(t)
	for _, tc := range epochCases {
		id := f.forgePending(t, es[tc.epoch], tc.received)
		f.env.Warnings.Take()
		p, err := f.u.Client.OpenPending(f.mbx, tc.epoch, id)
		if tc.want == nil {
			if err != nil || len(p.Entries) != 1 || p.Entries[0].MailID != id {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if !warned(f.env, "Begriffsliste") {
			t.Fatalf("%s: no warning", tc.name)
		}
	}
	// An epoch outside the chain.
	if _, err := f.u.Client.OpenPending(f.mbx, 9, store.ID{1}); !errors.Is(err, client.ErrEpoch) {
		t.Fatal(err)
	}
}

func TestFoldersOfDiscardedEpochNotRead(t *testing.T) {
	f, _ := discardFixture(t)
	// The folders of epoch 2 are valid but never read; damaging them does
	// not change the answer.
	if _, err := f.u.Client.FoldersOfEpoch(f.mbx, 2); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("folders of a discarded epoch: %v", err)
	}
	os.WriteFile(f.env.Store.FoldersFile(f.mbx, 3), []byte("junk"), 0o660)
	if _, err := f.u.Client.FoldersOfEpoch(f.mbx, 3); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("damaged folders of a discarded epoch: %v", err)
	}
	if _, err := f.u.Client.FoldersOfEpoch(f.mbx, 9); !errors.Is(err, client.ErrEpoch) {
		t.Fatalf("folders outside the chain: %v", err)
	}
	if l, err := f.u.Client.FoldersOfEpoch(f.mbx, 5); err != nil || l.Name != "A" {
		t.Fatalf("folders of epoch 5: %v", err)
	}
	// The newest epoch that is not discarded is read: 5 now, and after a
	// sync the supply 6 to 8 (regular, after 5).
	if name, err := f.u.Client.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	if err := f.u.Client.Sync(); err != nil {
		t.Fatal(err)
	}
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	e6, _, err := f.env.Store.ReadEpoch(f.mbx, 6)
	if m.Epoch != 8 || err != nil || e6.Begin != time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixMilli() || len(e6.Discards) != 0 {
		t.Fatalf("supply after an immediate epoch: head %d, %v", m.Epoch, err)
	}
	if fs, err := f.u.Client.Folders(f.mbx); err != nil || len(fs) != 1 {
		t.Fatal(err)
	}
}

// The discards and begins are remembered: when epoch 5 later disappears
// (and mailbox.rec is reset), epoch 2 stays discarded and the begin of 5
// still decides the epoch rule for epoch 1 (DECISIONS D50).
func TestDiscardsRemembered(t *testing.T) {
	f, es := discardFixture(t)
	late := f.forge(t, es[1], at(13, 0), "late", 1, f.env.IngestKey, 1)
	early := f.forge(t, es[1], at(11, 30), "early", 1, f.env.IngestKey, 1)
	two := f.forge(t, es[2], time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), "two", 1, f.env.IngestKey, 1)
	if _, err := f.u.Client.List(f.mbx, store.ID{}); err != nil {
		t.Fatal(err)
	}
	var st struct {
		Mailboxes map[string]struct {
			Epochs map[string]struct {
				Begin     int64 `json:"begin"`
				Immediate bool  `json:"immediate"`
				Discarded bool  `json:"discarded"`
			} `json:"epochs"`
		} `json:"mailboxes"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.u.Dir, "state.json")), &st); err != nil {
		t.Fatal(err)
	}
	ep := st.Mailboxes[f.mbx.String()].Epochs
	if !ep["2"].Discarded || !ep["4"].Discarded || ep["1"].Discarded || ep["5"].Discarded || !ep["5"].Immediate || ep["1"].Immediate ||
		ep["5"].Begin != at(12, 0).UnixMilli() {
		t.Fatalf("remembered epochs %+v", ep)
	}
	os.Remove(f.env.Store.EpochFile(f.mbx, 5))
	m, _ := f.env.Store.ReadMailbox(f.mbx)
	m.Epoch = 4
	f.env.Store.WriteMailbox(m)
	c := f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, two); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("remembered discard: %v", err)
	}
	if _, _, err := c.Read(f.mbx, late); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("remembered begin of 5: %v", err)
	}
	if _, _, err := c.Read(f.mbx, early); err != nil {
		t.Fatalf("mail before the remembered begin: %v", err)
	}
	// The newest epoch that is not discarded is 1 now.
	if name, err := c.MailboxName(f.mbx); err != nil || name != "A" {
		t.Fatal(name, err)
	}
	// Epoch 5 replaced by a regular epoch 5' after 4 that discards
	// nothing: the client notices the replacement, and the chain that no
	// longer discards epoch 2 does not make it valid again (K1 point 3).
	f.env.Warnings.Take()
	r := f.env.ImmediateEpoch(f.u, f.mbx, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC), store.ReasonRegular, "A")
	if r.Number != 5 || r.Reason.Immediate() || len(r.Discards) != 0 {
		t.Fatalf("replacement %d %v %v", r.Number, r.Reason, r.Discards)
	}
	if _, err := c.FoldersOfEpoch(f.mbx, 2); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("discarded epoch 2 after the replacement: %v", err)
	}
	// Since task 14 the log holds the original epoch 5: the replacement
	// contradicts it (CheckEpoch, ErrMismatch) and the chain ends before it.
	if w := strings.Join(f.env.Warnings.Take(), "\n"); !strings.Contains(w, "Epoche 5 von "+f.mbx.String()+" wurde ersetzt") &&
		!strings.Contains(w, f.mbx.String()+" bricht bei Epoche 5 ab") {
		t.Fatalf("replacement not noticed: %s", w)
	}
	if _, _, err := c.Read(f.mbx, two); !errors.Is(err, client.ErrDiscardedEpoch) {
		t.Fatalf("mail of discarded epoch 2 after the replacement: %v", err)
	}
	if _, _, err := c.Read(f.mbx, late); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("remembered begin of 5 after the replacement: %v", err)
	}
	if _, _, err := c.Read(f.mbx, early); err != nil {
		t.Fatalf("mail before the remembered begin after the replacement: %v", err)
	}
}

// A state file from before discarded epochs ("begins" only) is read and
// its begins still decide the epoch rule.
func TestLegacyBeginsMigrated(t *testing.T) {
	f := newFixture(t)
	e1, _, _ := f.env.Store.ReadEpoch(f.mbx, 1)
	e2, _, _ := f.env.Store.ReadEpoch(f.mbx, 2)
	late := f.forge(t, e1, time.UnixMilli(e2.Begin).Add(time.Hour), "late", 1, f.env.IngestKey, 1)
	sp := filepath.Join(f.u.Dir, "state.json")
	var st map[string]any
	json.Unmarshal(mustRead(t, sp), &st)
	mb := st["mailboxes"].(map[string]any)[f.mbx.String()].(map[string]any)
	delete(mb, "epochs")
	mb["begins"] = map[string]any{"1": e1.Begin, "2": e2.Begin}
	b, _ := json.Marshal(st)
	f.u.Client.Close()
	os.WriteFile(sp, b, 0o600)
	// Epoch 2 damaged: only the remembered begin decides.
	os.WriteFile(f.env.Store.EpochFile(f.mbx, 2), []byte("junk"), 0o600)
	c := f.env.Reopen(f.u)
	if _, _, err := c.Read(f.mbx, late); !errors.Is(err, client.ErrStaleEpoch) {
		t.Fatalf("legacy begins: %v", err)
	}
}
