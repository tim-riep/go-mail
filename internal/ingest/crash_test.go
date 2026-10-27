package ingest

import (
	"fmt"
	"testing"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
)

func setCrash(t *testing.T, point string) {
	crashHook = func(p string) bool { return p == point }
	t.Cleanup(func() { crashHook = nil })
}

// checkAllOrNothing verifies the invariant after a crash and restart:
// nothing left in spool/ and work/, and in every mailbox either no trace
// of the mail or the complete mail with metadata and marker, readable.
func checkAllOrNothing(t *testing.T, env *testenv.Env, u *testenv.User, mbxs []store.ID, wantComplete bool) {
	t.Helper()
	if f := files(t, env.Store.SpoolDir()); len(f) != 0 {
		t.Fatalf("spool after recovery: %v", f)
	}
	if f := files(t, env.Store.WorkDir()); len(f) != 0 {
		t.Fatalf("work after recovery: %v", f)
	}
	for _, mbx := range mbxs {
		mails, metas, pending := mailFiles(t, env, mbx)
		switch {
		case len(mails) == 0 && len(metas) == 0 && len(pending) == 0:
			if wantComplete {
				t.Fatalf("mail missing in %s", mbx)
			}
		case len(mails) == 1 && len(metas) == 1 && len(pending) == 1:
			if !wantComplete {
				t.Fatalf("mail present in %s although the sender got no 250 before the commit", mbx)
			}
			list, err := u.Client.List(mbx, store.ID{})
			if err != nil || len(list) != 1 {
				t.Fatalf("complete mail not listed: %v %v", err, env.Warnings.Take())
			}
			if _, _, err := u.Client.Read(mbx, list[0].ID); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("intermediate state in %s: mails %v metas %v pending %v", mbx, mails, metas, pending)
		}
	}
}

func TestCrashDuringReceipt(t *testing.T) {
	points := []string{"data", "meta-written", "marker-written", "spooled", "journal", "moved-1", "moved-2", "moved-3", "moved-4", "moved-5", "moved-6", "committed"}
	for _, p := range points {
		t.Run(p, func(t *testing.T) {
			env := testenv.New(t)
			u := env.NewUser("alice")
			a := env.Mailbox(u, "A", "a@example.org")
			b := env.Mailbox(u, "B", "b@example.org")
			in := newIngest(t, env)
			setCrash(t, p)
			if err := deliver(t, in, "s@x", []string{"a@example.org", "b@example.org"}, message("crash "+p, "body")); err == nil {
				t.Fatal("the crashed delivery must not report success (no 250)")
			}
			crashHook = nil
			// Restart.
			kill(in)
			in2 := newIngest(t, env)
			checkAllOrNothing(t, env, u, []store.ID{a, b}, p == "committed")
			// The server keeps working.
			if err := deliver(t, in2, "s@x", []string{"a@example.org"}, message("after", "x")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrashDuringPreprocessing(t *testing.T) {
	for _, p := range []string{"batch-written", "marker-removed"} {
		t.Run(p, func(t *testing.T) {
			env := testenv.New(t)
			u := env.NewUser("alice")
			mbx := env.Mailbox(u, "A", "a@example.org")
			in := newIngest(t, env)
			for i := 0; i < 2; i++ {
				if err := deliver(t, in, "s@x", []string{"a@example.org"}, message(fmt.Sprint(i), "b")); err != nil {
					t.Fatal(err)
				}
			}
			setCrash(t, p)
			in.Flush()
			crashHook = nil
			kill(in)
			newIngest(t, env)
			list, _ := u.Client.List(mbx, store.ID{})
			if len(list) != 2 {
				t.Fatal("mails lost")
			}
			// Every mail is covered by its marker or by the term list.
			ids, _ := env.Store.ListPending(mbx, 1)
			covered := map[store.ID]bool{}
			for _, id := range ids {
				pd, err := u.Client.OpenPending(mbx, 1, id)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range pd.Entries {
					covered[e.MailID] = true
				}
			}
			for _, m := range list {
				if !covered[m.ID] {
					t.Fatalf("mail %s has neither marker nor term list", m.ID)
				}
			}
		})
	}
}

func TestRecoverRejectsDamagedJournal(t *testing.T) {
	env := testenv.New(t)
	in := newIngest(t, env)
	dir := env.Store.Path("spool", "x")
	store.MkdirAll(dir)
	store.WriteFileAtomic(dir+"/"+journalName, []byte("junk"))
	if err := in.Recover(); err == nil {
		t.Fatal("damaged journal accepted")
	}
	// A journal naming a path outside the data directory is not followed.
	j, _ := store.EncodeJournal([]store.Move{{Src: "spool/x/a", Dst: "users/../../etc"}})
	store.WriteFileAtomic(dir+"/"+journalName, j)
	if err := in.Recover(); err == nil {
		t.Fatal("unsafe journal accepted")
	}
}
