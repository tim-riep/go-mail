package translog

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 07c (docs/tasks/07c-translog-rework-2.md). Finding 1 is
// tested by TestBoundedSync (rework_test.go).

// replacedOwnEntry builds the rollback by one of doc.go "Withheld
// entries": the client appends u at index i, tree.rec is set back to i
// and another writer's Append takes index i. The client's reference head
// stays below i. It returns the client, its Verifier, u and i.
func replacedOwnEntry(t *testing.T, e *tenv) (*fileLog, *Verifier, *tuser, int64) {
	t.Helper()
	e.head()
	c, v := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	u := newUser(t)
	i, err := c.Append(KindUser, u.rec(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	h, err := tlog.TreeHash(i, e.hashReader())
	if err != nil {
		t.Fatal(err)
	}
	if err := (&files{root: e.st.Root}).writeTree(treeState{Size: i, Hash: h}); err != nil {
		t.Fatal(err)
	}
	if j, err := e.openOp().Append(KindUser, newUser(t).rec(t, 1)); err != nil || j != i {
		t.Fatalf("foreign append: %d %v", j, err)
	}
	e.now = e.now.Add(time.Minute)
	return c, v, u, i
}

// TestRefreshUnjudgedHead (finding 2): a head that note.Open opens but
// CheckHead refuses is never used for the Pending check. Its own error
// is returned (no quorum: ErrWitness; another origin, a time in the
// future: ErrHead), not ErrConsistency; the own-entry verdict is not
// set, CheckFresh answers as before and nothing is taken over.
func TestRefreshUnjudgedHead(t *testing.T) {
	e := newEnv(t, 1, 1)
	c, v, _, i := replacedOwnEntry(t, e)
	freshBefore := c.CheckFresh(e.now)
	if freshBefore != nil {
		t.Fatalf("CheckFresh before: %v", freshBefore)
	}
	before := takeRefreshState(t, c, v)
	for _, tc := range []struct {
		name string
		head func() (*Head, []noteSigner)
		want error
	}{
		{"log signature without quorum", func() (*Head, []noteSigner) {
			return e.headOf(e.now.UnixMilli()), []noteSigner{e.signer}
		}, ErrWitness},
		{"other origin", func() (*Head, []noteSigner) {
			h := e.headOf(e.now.UnixMilli())
			h.Origin = "other"
			return h, e.all()
		}, ErrHead},
		{"time in the future", func() (*Head, []noteSigner) {
			return e.headOf(e.now.Add(time.Hour).UnixMilli()), e.all()
		}, ErrHead},
	} {
		h, signers := tc.head()
		if h.Size != i+1 {
			t.Fatalf("%s: head of size %d does not cover the own entry %d", tc.name, h.Size, i)
		}
		e.publish(h, signers...)
		_, err := c.Refresh(e.now)
		if !errors.Is(err, tc.want) || errors.Is(err, ErrConsistency) {
			t.Fatalf("%s: Refresh %v, want %v", tc.name, err, tc.want)
		}
		if c.ownErr != nil {
			t.Fatalf("%s: own-entry verdict from a refused head: %v", tc.name, c.ownErr)
		}
		if err := c.CheckFresh(e.now); err != freshBefore {
			t.Fatalf("%s: CheckFresh changed: %v", tc.name, err)
		}
		before.same(t, takeRefreshState(t, c, v))
	}
	// The same tree under a head that passes CheckHead: the own entry is
	// found replaced.
	e.head()
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("Refresh with a verified head: %v", err)
	}
	if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("CheckFresh after the verified head: %v", err)
	}
	before.same(t, takeRefreshState(t, c, v))
}

// TestOwnErrCleared (finding 2): the verdict "own entry replaced" is
// cleared once a Refresh passes the Pending check against a verified
// tree at least as large as the one it was found in, with or without a
// new head; a check against a smaller tree does not clear it.
func TestOwnErrCleared(t *testing.T) {
	t.Run("rollback by one, same head", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		c, v, u, i := replacedOwnEntry(t, e)
		h := e.head()
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("Refresh: %v", err)
		}
		// heads/ gone: the check against the smaller reference head does
		// not cover the index and does not clear the verdict.
		if err := os.RemoveAll(e.path(HeadsDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("Refresh without heads: %v", err)
		}
		if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("CheckFresh without heads: %v", err)
		}
		if err := store.MkdirAll(e.path(HeadsDir)); err != nil {
			t.Fatal(err)
		}
		e.publish(h, e.all()...)
		// The caller removes the entry and appends the record again: it
		// gets the next index; the same head (no new one) is then taken
		// over and the verdict is cleared.
		v.Pending = nil
		j, err := c.Append(KindUser, u.rec(t, 1))
		if errors.Is(err, ErrConsistency) {
			// The client's cached state of the committed tree still holds
			// the own entry at i; the first Append after the rollback
			// discards it, the next one starts from the reference index.
			j, err = c.Append(KindUser, u.rec(t, 1))
		}
		if err != nil || j != i+1 {
			t.Fatalf("append again: %d %v", j, err)
		}
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatalf("Refresh after the new append: %v", err)
		}
		if v.Last.Size != h.Size || c.ownErr != nil || len(v.Pending) != 1 || v.Pending[0].Index != j {
			t.Fatalf("not taken over: size %d, ownErr %v, pending %v", v.Last.Size, c.ownErr, v.Pending)
		}
		if err := c.CheckFresh(e.now); err != nil {
			t.Fatalf("CheckFresh: %v", err)
		}
		e.now = e.now.Add(time.Minute)
		e.head()
		if _, err := c.Refresh(e.now); err != nil || len(v.Pending) != 0 {
			t.Fatalf("Refresh covering the new append: %v %v", err, v.Pending)
		}
		if err := c.CheckUser(u.id, u.rec(t, 1)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reference head, no published head", func(t *testing.T) {
		// A Pending entry that the reference head covers with another
		// leaf (a state.json with a wrong list): found replaced against
		// the reference head; once the caller has removed it, a Refresh
		// without any published head clears the verdict.
		e := newEnv(t, 1, 1)
		e.head()
		c, v := e.client()
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatal(err)
		}
		v.Pending = []Pending{{Index: 0, Leaf: tlog.Hash{9}, At: e.now.UnixMilli()}}
		if err := os.RemoveAll(e.path(HeadsDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("Refresh: %v", err)
		}
		if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("CheckFresh: %v", err)
		}
		v.Pending = nil
		if _, err := c.Refresh(e.now); err != nil {
			t.Fatalf("Refresh after the entry was removed: %v", err)
		}
		if err := c.CheckFresh(e.now); err != nil {
			t.Fatalf("CheckFresh after the entry was removed: %v", err)
		}
	})
}

// TestRetryAfterIOFailure (finding 3): a rebuild of the audit index that
// fails with ErrIO is tried again by the next call; once the index file
// is writable, the rebuilt index answers.
func TestRetryAfterIOFailure(t *testing.T) {
	e := newEnv(t, 1, 1)
	u := newUser(t)
	e.mustAppend(KindUser, u.rec(t, 1))
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// An index that contradicts the log: generation 1 copied as 2.
	k1 := keyID(Key{Kind: KindUser, Subject: u.id[:], Seq: 1})
	k2 := keyID(Key{Kind: KindUser, Subject: u.id[:], Seq: 2})
	r := c.ref.Valid[k1]
	r.Seq = 2
	c.ref.Valid[k2] = r
	bad := c.ref
	// The index file cannot be written: its path is a directory.
	if err := os.Remove(c.opts.IndexFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c.opts.IndexFile, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		// Every call tries the rebuild again (ErrIO), none answers from
		// the contradicting index (ErrConsistency).
		if err := c.CheckGeneration(u.id, 2); !errors.Is(err, ErrIO) || errors.Is(err, ErrConsistency) {
			t.Fatalf("call %d with the index file unwritable: %v", i+1, err)
		}
	}
	if c.ref != bad || c.rebuilt == bad {
		t.Fatal("failed rebuild recorded")
	}
	if err := os.Remove(c.opts.IndexFile); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckGeneration(u.id, 2); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("after the repair: %v", err)
	}
	if c.ref == bad || c.rebuilt != c.ref {
		t.Fatal("index not rebuilt")
	}
	if err := c.CheckGeneration(u.id, 1); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(c.opts.IndexFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalState(data, c.f, c.ids); err != nil {
		t.Fatalf("rebuilt index file: %v", err)
	}
}

// TestIndexPathLinks (finding 4): the location of the audit index is
// judged with symbolic links resolved, in its directory and in the data
// directory; a path into the data directory is ErrIO.
func TestIndexPathLinks(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	tmp := t.TempDir()
	open := func(st *store.Store, idx string) error {
		_, err := Open(Options{Store: st, Verifier: e.verifier(), IndexFile: idx})
		return err
	}
	refused := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrIO) || errors.Is(err, ErrConsistency) {
			t.Fatalf("%s: want ErrIO, got %v", what, err)
		}
	}
	// The plain cases.
	refused("in the data directory", open(e.st, filepath.Join(e.st.Root, "index.json")))
	refused("under log/", open(e.st, filepath.Join(e.st.Root, "log", "index.json")))
	refused("the data directory itself", open(e.st, e.st.Root))
	refused("directory missing", open(e.st, filepath.Join(tmp, "missing", "index.json")))
	// A directory of the client that is a link into the data directory.
	link := filepath.Join(tmp, "client")
	if err := os.Symlink(filepath.Join(e.st.Root, "log"), link); err != nil {
		t.Fatal(err)
	}
	refused("through a link", open(e.st, filepath.Join(link, "index.json")))
	// The data directory reached through a link, the index named by its
	// real path.
	dataLink := filepath.Join(tmp, "data")
	if err := os.Symlink(e.st.Root, dataLink); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dataLink)
	if err != nil {
		t.Fatal(err)
	}
	refused("data directory through a link", open(st, filepath.Join(e.st.Root, "index.json")))
	// An index file that is itself a link, here into the data directory.
	dir := filepath.Join(tmp, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(dir, "index.json")
	if err := os.Symlink(filepath.Join(e.st.Root, "evil.json"), fileLink); err != nil {
		t.Fatal(err)
	}
	refused("index file is a link", open(e.st, fileLink))
	for _, p := range []string{filepath.Join(e.st.Root, "index.json"), filepath.Join(e.st.Root, "log", "index.json"), filepath.Join(e.st.Root, "evil.json")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written: %v", p, err)
		}
	}
	// A client directory reached through a link outside the data
	// directory is fine; the resolved path is used.
	real := filepath.Join(tmp, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	clientLink := filepath.Join(tmp, "clientlink")
	if err := os.Symlink(real, clientLink); err != nil {
		t.Fatal(err)
	}
	l, err := Open(Options{Store: st, Verifier: e.verifier(), IndexFile: filepath.Join(clientLink, "index.json")})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.(*fileLog).opts.IndexFile; got != filepath.Join(mustEval(t, real), "index.json") {
		t.Fatalf("index file %s", got)
	}
	if _, err := os.Stat(filepath.Join(real, "index.json")); err != nil {
		t.Fatal(err)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRefreshStaleWithoutPending (finding 6, documentation of Refresh):
// without Pending entries Refresh does not apply the age limit; only
// CheckFresh reports ErrStale for a reference head older than
// MaxHeadAge.
func TestRefreshStaleWithoutPending(t *testing.T) {
	e := newEnv(t, 1, 1)
	e.head()
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	later := e.now.Add(MaxHeadAge + time.Minute)
	e.now = later
	if _, err := c.Refresh(later); err != nil {
		t.Fatalf("Refresh with an old head and no Pending entry: %v", err)
	}
	if err := c.CheckFresh(later); !errors.Is(err, ErrStale) {
		t.Fatalf("CheckFresh: %v", err)
	}
}
