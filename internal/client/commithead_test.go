package client_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tim-riep/go-mail/internal/client"
)

// TestCommitHeadNeverSinks (task 20b point 8, from the specification
// check of 14b): commitHead refuses to set mailbox.rec back to an older
// epoch (2.4, ErrRollback) and writes nothing, neither mailbox.rec nor
// state.json; the current head itself is committed again without error.
func TestCommitHeadNeverSinks(t *testing.T) {
	f := newFixture(t)
	bob := f.env.NewUser("bob")
	if _, err := f.u.Client.Share(f.mbx, bob.ID, client.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	head := headOf(t, f.env, f.mbx)
	if head < 2 {
		t.Fatalf("head %d", head)
	}
	// Committing the head itself is allowed; it leaves the state that the
	// refused commits must not change.
	if err := f.u.Client.CommitHeadAt(f.mbx, head); err != nil {
		t.Fatalf("commit of the head itself: %v", err)
	}
	mrec := mustRead(t, f.env.Store.MailboxFile(f.mbx))
	state := mustRead(t, filepath.Join(f.u.Dir, "state.json"))
	for n := uint32(1); n < head; n++ {
		if err := f.u.Client.CommitHeadAt(f.mbx, n); !errors.Is(err, client.ErrRollback) {
			t.Fatalf("head %d set back to %d: %v", head, n, err)
		}
		if !bytes.Equal(mustRead(t, f.env.Store.MailboxFile(f.mbx)), mrec) {
			t.Fatalf("mailbox.rec changed by a refused commit of epoch %d", n)
		}
		if !bytes.Equal(mustRead(t, filepath.Join(f.u.Dir, "state.json")), state) {
			t.Fatalf("state.json changed by a refused commit of epoch %d", n)
		}
	}
	if got := headOf(t, f.env, f.mbx); got != head {
		t.Fatalf("head %d after committing it again, want %d", got, head)
	}
}
