package client_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

// Tests of task 20h point 1 (F-1 of docs/tasks/20-mandatory-tests.md,
// scenario Z3 of 10.1 without the full text index): a device change
// takes over the index segments of the old device.

// changeSenders are the senders of the three mails of devicechange; the
// subject of each mail is its sender's local part.
var changeSenders = []string{"r1@lieferant.example", "n1@other.example", "p1@post.example"}

// devicechange delivers three mails with different senders over SMTP,
// lets alice index them into one segment (pending/ empty afterwards),
// closes her client and restores her user from the seed words into a new
// client directory, a new device. It returns that directory, the epoch
// of the mails and the segments listed after alice's Index.
func devicechange(t *testing.T, f *fixture) (string, uint32, []store.IndexSegmentRef) {
	t.Helper()
	for _, s := range changeSenders {
		f.send(t, s, header(s, strings.Split(s, "@")[0]))
	}
	f.flush(t)
	c := f.u.Client
	list, err := c.List(f.mbx, store.ID{})
	if err != nil || len(list) != len(changeSenders) {
		t.Fatalf("list: %d mails, %v", len(list), err)
	}
	n := list[0].Epoch
	for _, m := range list {
		if m.Epoch != n {
			t.Fatalf("mails in epochs %d and %d", n, m.Epoch)
		}
	}
	if got, err := c.Index(f.mbx); err != nil || got != len(changeSenders) {
		t.Fatalf("index: %d %v", got, err)
	}
	refs, err := f.env.Store.ListIndexSegments(f.mbx, n)
	if err != nil || len(refs) != 1 {
		t.Fatalf("segments after index: %v %v", refs, err)
	}
	if p := pendingCount(t, f.env, f.mbx, n); p != 0 {
		t.Fatalf("%d pending files after index", p)
	}
	c.Close()
	f.env.Clock.Advance(time.Minute)
	dir := t.TempDir()
	if _, err := client.Restore(f.env.ClientConfig(dir), client.RestoreOptions{Words: f.u.Words, UserID: f.u.ID}, testenv.Passphrase); err != nil {
		t.Fatal(err)
	}
	return dir, n, refs
}

// openDevice opens the client in dir and closes it at the end of t.
func openDevice(t *testing.T, f *fixture, dir string) *client.Client {
	t.Helper()
	c, err := client.Open(f.env.ClientConfig(dir), testenv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// findsAll fails unless c finds each of the three mails of devicechange
// by its sender, and only it.
func findsAll(t *testing.T, f *fixture, c *client.Client) {
	t.Helper()
	for _, s := range changeSenders {
		if got, want := search(t, c, f.mbx, "from:"+s, ""), strings.Split(s, "@")[0]; got != want {
			t.Fatalf("search from:%s: %q, want %q (%q)", s, got, want, f.env.Warnings.Take())
		}
	}
}

// TestDeviceChangeTakesOverSegments (F-1 a and b): the new device finds
// all three mails through the segment of the old device without having
// indexed anything itself, and its own Index afterwards finds nothing to
// do and writes no segment.
func TestDeviceChangeTakesOverSegments(t *testing.T) {
	f := newFixture(t)
	dir, n, refs := devicechange(t, f)
	c := openDevice(t, f, dir)
	if c.UserID() != f.u.ID {
		t.Fatalf("restored user %s", c.UserID())
	}
	f.env.Warnings.Take()
	// (a) without Index on the new device.
	findsAll(t, f, c)
	if after, _ := f.env.Store.ListIndexSegments(f.mbx, n); !slices.Equal(after, refs) {
		t.Fatalf("segments changed by Search: %v, before %v", after, refs)
	}
	dev, err := c.Device()
	if err != nil {
		t.Fatal(err)
	}
	if dev == refs[0].Device {
		t.Fatal("the restored client has the device ID of the old device")
	}
	// (b) Index of the new device: nothing to do, no segment.
	if got, err := c.Index(f.mbx); err != nil || got != 0 {
		t.Fatalf("index on the new device: %d %v", got, err)
	}
	if after, _ := f.env.Store.ListIndexSegments(f.mbx, n); !slices.Equal(after, refs) {
		t.Fatalf("segments after Index on the new device: %v, before %v", after, refs)
	}
	findsAll(t, f, c)
}

// TestDeviceChangeThenDeviceLost (F-1 c): device lost in the new client
// directory right after the restore issues the segment of the old device
// again, signed by generation 2; Search still finds all three mails, and
// no warning names a revoked generation (device lost itself only notes
// what it took over and signed again).
func TestDeviceChangeThenDeviceLost(t *testing.T) {
	f := newFixture(t)
	dir, n, refs := devicechange(t, f)
	f.env.Warnings.Take()
	gen, err := client.DeviceLost(f.env.ClientConfig(dir), testenv.Passphrase, f.u.Words)
	if err != nil || gen != 2 {
		t.Fatalf("device lost: generation %d, %v (%q)", gen, err, f.env.Warnings.Take())
	}
	// The run itself notes what it took over and signed again; none of
	// it is a warning.
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "widerrufenen") && !strings.HasPrefix(w, "Hinweis: ") {
			t.Fatalf("warning of device lost: %s", w)
		}
	}
	after, err := f.env.Store.ListIndexSegments(f.mbx, n)
	if err != nil || len(after) != 1 || after[0] == refs[0] {
		t.Fatalf("segment not issued again: %v, before %v (%v)", after, refs, err)
	}
	data, err := f.env.Store.ReadIndexSegment(f.mbx, n, after[0].Device, after[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	if tr := parse(t, data).Trailer; tr == nil || store.ID(tr.Signer.ID) != f.u.ID || tr.Signer.Gen != 2 {
		t.Fatal("segment not signed by generation 2")
	}
	c := openDevice(t, f, dir)
	if dev, err := c.Device(); err != nil || dev != after[0].Device || dev == refs[0].Device {
		t.Fatalf("segment issued again as %s, device %s (%v), old device %s", after[0].Device, dev, err, refs[0].Device)
	}
	findsAll(t, f, c)
	for _, w := range f.env.Warnings.Take() {
		if strings.Contains(w, "widerrufenen") {
			t.Fatalf("warning after device lost: %s", w)
		}
	}
}
