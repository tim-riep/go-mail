package translog

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
)

// TestPublishHeadRefusesRolledBackTree (backlog item 74): PublishHead
// refuses like SignHead when an entry lies beyond the committed size (a
// rolled-back tree.rec), for a new head and for the merge of a further
// cosignature into a published one, and writes nothing.
func TestPublishHeadRefusesRolledBackTree(t *testing.T) {
	e := newEnv(t, 3, 2)
	e.addresses(2)
	op := e.openServer()
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	w0, w1, w2 := e.ws[0], e.ws[1], e.ws[2]
	beyond := e.path(EntryPath(h.Size + 1))
	plant := func() {
		t.Helper()
		data, err := os.ReadFile(e.path(EntryPath(h.Size - 1)))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteFileAtomic(beyond, data); err != nil {
			t.Fatal(err)
		}
	}
	// A new head of the signed tree: refused, nothing written.
	plant()
	if err := op.PublishHead(e.cosigned(h, w0, w1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("new head with an entry beyond the tree: %v", err)
	}
	if n, _ := op.f.newestHeadSize(); n != 0 {
		t.Fatalf("head %d written", n)
	}
	if err := os.Remove(beyond); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h, w0, w1)); err != nil {
		t.Fatal(err)
	}
	stored := readHeadFile(t, e, h.Size)
	// The merge of a further cosignature into the published head:
	// refused, the stored head is left as it is.
	plant()
	if err := op.PublishHead(e.cosigned(h, w2)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("merge with an entry beyond the tree: %v", err)
	}
	if got := readHeadFile(t, e, h.Size); !bytes.Equal(got, stored) {
		t.Fatal("stored head changed")
	}
	// SignHead refuses the same tree (the rule PublishHead shares).
	if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("SignHead: %v", err)
	}
	if err := os.Remove(beyond); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h, w2)); err != nil {
		t.Fatal(err)
	}
	if got := readHeadFile(t, e, h.Size); bytes.Equal(got, stored) {
		t.Fatal("merge not written after the entry is gone")
	}
}
