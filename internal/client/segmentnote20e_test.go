package client_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// TestOwnSegmentNotedOnWrite (task 20e point 1, P-2 of task 20c, case
// "index weg" of task 09c): alice's Index writes a segment that she
// never reads. Its check record is there right after the write (her
// generation 1, a tree size). The segment is hidden for the whole
// DeviceLost run, step 2 included, and put back afterwards: her next
// Search takes it over through that record (it is from before the
// revocation), signs it again with generation 2 and finds the mail.
func TestOwnSegmentNotedOnWrite(t *testing.T) {
	f := newFixture(t)
	a := f.deliver(t, "a", "x")
	c := f.u.Client
	if _, err := c.Index(f.mbx); err != nil {
		t.Fatal(err)
	}
	dev, err := c.Device()
	if err != nil {
		t.Fatal(err)
	}
	old := ownSegments(t, f.env, f.mbx, a.Epoch, dev)
	if len(old) != 1 {
		t.Fatalf("segments %v", old)
	}
	p := f.env.Store.IndexSegmentFile(f.mbx, a.Epoch, dev, old[0].Seq)
	data := mustRead(t, p)
	checked, _ := readState(t, f.u.Dir, f.mbx)["checked"].(map[string]any)
	m, _ := checked[client.SegmentMemoKey(a.Epoch, dev, data)].(map[string]any)
	if m == nil || m["signer"] != f.u.ID.String() || m["gen"] != 1.0 {
		t.Fatalf("no record of the segment written: %v", m)
	}
	if tree, _ := m["tree"].(float64); tree <= 0 {
		t.Fatalf("record without tree size: %v", m)
	}

	aside := filepath.Join(t.TempDir(), "segment")
	if err := os.Rename(p, aside); err != nil {
		t.Fatal(err)
	}
	f.env.Clock.Advance(time.Minute)
	c.Close()
	if gen, err := client.DeviceLost(f.env.ClientConfig(f.u.Dir), testenv.Passphrase, f.u.Words); gen != 2 || err != nil {
		t.Fatalf("DeviceLost: %d %v", gen, err)
	}
	if err := os.Rename(aside, p); err != nil {
		t.Fatal(err)
	}
	c = f.env.Reopen(f.u)
	f.env.Warnings.Take()
	if got := search(t, c, f.mbx, "from:s@x.example", ""); got != "a" {
		t.Fatalf("search after the segment came back: %q", got)
	}
	warningWith(t, f.env.Warnings.Take(), "übernommen und neu signiert")
	now := ownSegments(t, f.env, f.mbx, a.Epoch, dev)
	if len(now) != 1 || now[0] == old[0] {
		t.Fatalf("segment not signed again: %v", now)
	}
	if got := search(t, f.env.Reopen(f.u), f.mbx, "from:s@x.example", ""); got != "a" {
		t.Fatalf("search after the new signature: %q", got)
	}
}
