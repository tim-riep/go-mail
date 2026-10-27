package translog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of the server side of the log (task 11): SignHead, PublishHead,
// RepairTree.

// openServer opens the operator log as the server does: with the origin
// of the pin and the witnesses of witnesses.rec.
func (e *tenv) openServer() *operatorLog {
	e.t.Helper()
	l, err := Open(e.serverOptions())
	if err != nil {
		e.t.Fatal(err)
	}
	return l.(*operatorLog)
}

func (e *tenv) serverOptions() Options {
	var wv []note.Verifier
	for _, w := range e.ws {
		wv = append(wv, w.verifier)
	}
	return Options{Store: e.st, Identities: e.p.ids(e.t, e.idGen), Origin: testOrigin, Witnesses: wv, MinWitnesses: e.min}
}

// cosigned returns h with a note signed by the log signer and the given
// witnesses.
func (e *tenv) cosigned(h *Head, ws ...twit) *Head {
	e.t.Helper()
	signers := []note.Signer{e.signer}
	for _, w := range ws {
		signers = append(signers, w.signer)
	}
	c := *h
	c.Note = sign(e.t, h, signers...)
	return &c
}

// addresses appends n address assignments (any valid entry will do).
func (e *tenv) addresses(n int) {
	e.t.Helper()
	mbx := newMbx(e.t)
	for i := 0; i < n; i++ {
		e.vf++
		e.mustAppend(KindAddress, e.addr(e.t, "grow@example.org", mbx, t0+e.vf, 1))
	}
}

func readHeadFile(t *testing.T, e *tenv, size int64) []byte {
	t.Helper()
	b, err := os.ReadFile(e.path(HeadPath(size)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignHead(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	tr := e.tree()
	if h.Origin != testOrigin || h.Size != tr.Size || h.Hash != tr.Hash || h.Time != e.now.UnixMilli() || len(h.Sigs) != 1 {
		t.Fatalf("head %+v", h)
	}
	if _, err := OpenHead(h.Note, e.known()); err != nil {
		t.Fatalf("signed head does not open: %v", err)
	}
	// SignHead writes nothing.
	if n, _ := (&files{root: e.st.Root}).newestHeadSize(); n != 0 {
		t.Fatal("SignHead wrote a head")
	}
	// Same tree, later time: a re-signature; an earlier time: refused.
	e.now = e.now.Add(time.Minute)
	if h2, err := op.SignHead(e.signer, e.now); err != nil || h2.Size != h.Size || h2.Time <= h.Time {
		t.Fatalf("re-sign: %v", err)
	}
	if _, err := op.SignHead(e.signer, e.now.Add(-time.Second)); !errors.Is(err, ErrHead) {
		t.Fatalf("clock went back: %v", err)
	}
	// Growth.
	e.addresses(3)
	h3, err := op.SignHead(e.signer, e.now)
	if err != nil || h3.Size != h.Size+3 {
		t.Fatalf("after growth: %v", err)
	}
	// Signer rules.
	if _, err := op.SignHead(e.logSigner(2), e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("unlogged generation: %v", err)
	}
	if _, err := op.SignHead(e.ws[0].signer, e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("witness as log signer: %v", err)
	}
	if _, err := op.SignHead(nil, e.now); !errors.Is(err, ErrHead) {
		t.Fatal("nil signer")
	}
	if _, err := op.SignHead(e.signer, time.UnixMilli(-1)); !errors.Is(err, ErrHead) {
		t.Fatal("time before 1970")
	}
	// Without an origin (the ceremony's operator log) nothing is signed
	// or published.
	plain := e.openOp().(*operatorLog)
	if _, err := plain.SignHead(e.signer, e.now); !errors.Is(err, ErrHead) {
		t.Fatalf("no origin: %v", err)
	}
	if err := plain.PublishHead(e.cosigned(h3, e.ws...)); !errors.Is(err, ErrWitness) {
		t.Fatalf("no witnesses: %v", err)
	}
	o := e.serverOptions()
	o.Witnesses, o.MinWitnesses = nil, 0
	nw, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := nw.(Operator).PublishHead(e.cosigned(h3, e.ws...)); !errors.Is(err, ErrWitness) {
		t.Fatalf("no witnesses: %v", err)
	}
	o = e.serverOptions()
	o.Origin = ""
	no, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := no.(Operator).PublishHead(e.cosigned(h3, e.ws...)); !errors.Is(err, ErrHead) {
		t.Fatalf("no origin: %v", err)
	}
}

func TestSignHeadEmptyLog(t *testing.T) {
	st, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	p := newPlat(t)
	l, err := Open(Options{Store: st, Identities: p.ids(t, 1), Origin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewLogSigner(p.ingest(t, 1))
	if _, err := l.(Operator).SignHead(s, time.UnixMilli(t0)); !errors.Is(err, ErrNotInLog) {
		t.Fatalf("empty log: %v", err)
	}
}

func TestOpenServerOptions(t *testing.T) {
	e := newEnv(t, 3, 2)
	o := e.serverOptions()
	o.Origin = "bad origin"
	if _, err := Open(o); !errors.Is(err, ErrHead) {
		t.Fatalf("bad origin: %v", err)
	}
	o = e.serverOptions()
	o.MinWitnesses = 1
	if _, err := Open(o); !errors.Is(err, ErrWitness) {
		t.Fatalf("quorum 1 of 3: %v", err)
	}
	o = e.serverOptions()
	o.Witnesses = nil
	if _, err := Open(o); !errors.Is(err, ErrWitness) {
		t.Fatalf("minimum without witnesses: %v", err)
	}
	o = e.serverOptions()
	o.Witnesses[1] = o.Witnesses[0]
	if _, err := Open(o); !errors.Is(err, ErrWitness) {
		t.Fatalf("witness twice: %v", err)
	}
}

// TestSignHeadRotation: SignHead signs only with the generation that
// covers now in the committed tree.
func TestSignHeadRotation(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	sw := e.now.Add(time.Hour).UnixMilli()
	cert2 := e.p.cert(t, keys.RoleIngest, 2, 1, sw)
	if err := e.st.WritePlatformFile("ingest-2.cert", cert2); err != nil {
		t.Fatal(err)
	}
	e.mustAppend(KindPlatform, cert2)
	g1, g2 := e.logSigner(1), e.logSigner(2)
	if _, err := op.SignHead(g2, time.UnixMilli(sw-1)); !errors.Is(err, ErrHead) {
		t.Fatalf("generation 2 before valid_from: %v", err)
	}
	if _, err := op.SignHead(g1, time.UnixMilli(sw-1)); err != nil {
		t.Fatalf("generation 1 before the switch: %v", err)
	}
	if _, err := op.SignHead(g1, time.UnixMilli(sw)); !errors.Is(err, ErrHead) {
		t.Fatalf("generation 1 at the switch: %v", err)
	}
	h, err := op.SignHead(g2, time.UnixMilli(sw))
	if err != nil {
		t.Fatal(err)
	}
	// The client accepts what the server signed.
	e.now = time.UnixMilli(sw)
	e.signer = g2
	if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
		t.Fatal(err)
	}
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// A head of the tree before ingest-2.cert, published with the
	// generation-1 signature at a time before the switch, judges the
	// generation in the tree of that head (logKeysOf, index < size).
	if k, ok := coveringKey(op.cur, h.Size-1, sw); !ok || k.KeyHash() != g1.KeyHash() {
		t.Fatal("generation 1 must cover a tree without ingest-2.cert")
	}
}

func TestSignHeadInvalidEntries(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
		t.Fatal(err)
	}
	u := newUser(t)
	mbx := newMbx(t)
	ep1 := mkEpoch(t, mbx, 1, nil, u, 1, []store.Member{member(u, 1)}, t0)
	raw := func(enc []byte) {
		t.Helper()
		if _, err := (&fileLog{f: &files{root: e.st.Root}}).write(e.tree(), Key{Kind: KindEpoch, Subject: []byte("x")}, enc); err != nil {
			t.Fatal(err)
		}
	}
	en, _ := NewEntry(KindEpoch, ep1)
	enc, _ := en.Encode()
	raw(enc)               // epoch before its signer: unlogged signer
	raw([]byte("garbage")) // not an entry
	e.addresses(1)         // a valid one after them
	e.now = e.now.Add(time.Minute)
	h2, err := op.SignHead(e.signer, e.now)
	var inv *InvalidEntriesError
	if h2 == nil || !errors.As(err, &inv) || !errors.Is(err, ErrUnloggedSigner) || !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("invalid entries: %v %v", h2, err)
	}
	if len(inv.Entries) != 2 || inv.Entries[0].Index != h.Size || inv.Entries[1].Index != h.Size+1 || inv.Entries[1].Class != "entry" {
		t.Fatalf("entries %v", inv.Entries)
	}
	if h2.Size != h.Size+3 || !strings.Contains(err.Error(), "invalid entries") {
		t.Fatalf("head %d, %v", h2.Size, err)
	}
	// Once a head covering them is published, they are no longer
	// reported.
	if err := op.PublishHead(e.cosigned(h2, e.ws...)); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	if _, err := op.SignHead(e.signer, e.now); err != nil {
		t.Fatalf("after publication: %v", err)
	}
	// The client audits the same verdict.
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	if got := c.Invalid(); len(got) != 2 {
		t.Fatalf("client invalid %v", got)
	}
}

func TestInvalidEntriesError(t *testing.T) {
	for class, want := range map[string]error{
		"unlogged-signer": ErrUnloggedSigner, "prerequisite": ErrPrerequisite, "duplicate": ErrDuplicate,
		"order": ErrOrder, "mismatch": ErrMismatch, "entry": ErrEntry, "other": ErrEntry,
	} {
		err := &InvalidEntriesError{Entries: []InvalidEntry{{Index: 3, Class: class}}}
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v", class, err)
		}
	}
	if !errors.Is(&InvalidEntriesError{}, ErrEntry) {
		t.Fatal("empty")
	}
	var many []InvalidEntry
	for i := 0; i < 20; i++ {
		many = append(many, InvalidEntry{Index: int64(i), Class: "order"})
	}
	if msg := (&InvalidEntriesError{Entries: many}).Error(); !strings.Contains(msg, "and 4 more") || strings.Contains(msg, " 16 (") {
		t.Fatalf("message %q", msg)
	}
}

// TestSignHeadRefuses: an inconsistent tree is never signed.
func TestSignHeadRefuses(t *testing.T) {
	t.Run("tree.rec rolled back below a published head", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		e.addresses(2)
		op := e.openServer()
		h, err := op.SignHead(e.signer, e.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
			t.Fatal(err)
		}
		f := &files{root: e.st.Root}
		hr, _ := tlog.TreeHash(h.Size-1, e.hashReader())
		if err := f.writeTree(treeState{Size: h.Size - 1, Hash: hr}); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("rolled back: %v", err)
		}
		if _, err := e.openServer().SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("rolled back, new process: %v", err)
		}
	})
	t.Run("rolled back by one below the last signed head", func(t *testing.T) {
		// No published head; the process remembers the candidate it
		// handed out. Another entry at the same index gives another
		// tree of the same size: never signed (a witness that cosigned
		// the candidate would record a fork).
		e := newEnv(t, 1, 1)
		e.addresses(1)
		op := e.openServer()
		h, err := op.SignHead(e.signer, e.now)
		if err != nil {
			t.Fatal(err)
		}
		f := &files{root: e.st.Root}
		hr, _ := tlog.TreeHash(h.Size-1, e.hashReader())
		if err := f.writeTree(treeState{Size: h.Size - 1, Hash: hr}); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("smaller than the last signed head: %v", err)
		}
		e.op = e.openOp()
		e.addresses(1)
		if e.tree().Size != h.Size {
			t.Fatal("setup")
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("another tree of the signed size: %v", err)
		}
	})
	t.Run("entry changed below the cached state", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		op := e.openServer()
		h, err := op.SignHead(e.signer, e.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
			t.Fatal(err)
		}
		e.addresses(2)
		// The server's state of the committed tree is synced now.
		if _, err := op.Entry(h.Size); err != nil {
			t.Fatal(err)
		}
		// Somebody rewrites entry h.Size (tiles and tree.rec unchanged):
		// the state does not read it again, the recomputation does.
		data, _ := os.ReadFile(e.path(EntryPath(h.Size + 1)))
		if err := store.WriteFileAtomic(e.path(EntryPath(h.Size)), data); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("changed entry: %v", err)
		}
	})
	t.Run("entry missing", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		e.addresses(2)
		op := e.openServer()
		if err := os.Remove(e.path(EntryPath(2))); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("missing entry: %v", err)
		}
	})
	t.Run("garbage in heads", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		op := e.openServer()
		if err := store.WriteFileAtomic(e.path(HeadPath(1)), []byte("garbage")); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("garbage head: %v", err)
		}
	})
	t.Run("published head of another tree", func(t *testing.T) {
		e := newEnv(t, 1, 1)
		op := e.openServer()
		h := e.headOf(e.now.UnixMilli())
		h.Hash[0] ^= 1
		e.publish(h, e.all()...)
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("foreign head: %v", err)
		}
	})
}

func TestSyncTree(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	if err := op.syncTree(0, 2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(EntryPath(1))); err != nil {
		t.Fatal(err)
	}
	if err := op.syncTree(0, 2); !errors.Is(err, ErrConsistency) {
		t.Fatalf("missing entry: %v", err)
	}
	if err := op.syncTree(2, 2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(TreeFile)); err != nil {
		t.Fatal(err)
	}
	if err := op.syncTree(2, 2); !errors.Is(err, ErrConsistency) {
		t.Fatalf("missing tree.rec: %v", err)
	}
}

func TestPublishHead(t *testing.T) {
	e := newEnv(t, 3, 2)
	op := e.openServer()
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	w0, w1, w2 := e.ws[0], e.ws[1], e.ws[2]
	// Below the quorum: nothing is written.
	if err := op.PublishHead(e.cosigned(h, w0)); !errors.Is(err, ErrWitness) {
		t.Fatalf("one of two: %v", err)
	}
	if n, _ := op.f.newestHeadSize(); n != 0 {
		t.Fatal("head written without quorum")
	}
	// A witness's line given twice counts once.
	twice := e.cosigned(h, w0)
	twice.Note = append(append([]byte(nil), twice.Note...), lastSigLine(twice.Note)...)
	if err := op.PublishHead(twice); !errors.Is(err, ErrWitness) {
		t.Fatalf("one witness twice: %v", err)
	}
	// Quorum, with an invalid line by a known witness and a line by an
	// unknown key: both dropped, the stored note opens.
	other := newWitnesses(t, 1)[0]
	good := e.cosigned(h, w0, w1)
	bad := sign(t, &Head{Origin: h.Origin, Size: h.Size, Hash: h.Hash, Time: h.Time + 1}, w2.signer)
	withBad := *good
	withBad.Note = append(append(append([]byte(nil), good.Note...), lastSigLine(bad)...), lastSigLine(sign(t, h, other.signer))...)
	if _, err := OpenHead(withBad.Note, e.known()); err == nil {
		t.Fatal("setup: the poisoned note must not open")
	}
	if err := op.PublishHead(&withBad); err != nil {
		t.Fatal(err)
	}
	stored := readHeadFile(t, e, h.Size)
	sh, err := OpenHead(stored, e.known())
	if err != nil || len(sh.Sigs) != 3 {
		t.Fatalf("stored head: %v %d", err, len(sh.Sigs))
	}
	if bytes.Contains(stored, lastSigLine(bad)) {
		t.Fatal("invalid line stored")
	}
	// The client accepts it.
	c, _ := e.client()
	if _, err := c.Refresh(e.now); err != nil {
		t.Fatal(err)
	}
	// The same text with a further cosignature: merged, one line per key.
	if err := op.PublishHead(e.cosigned(h, w2)); err != nil {
		t.Fatal(err)
	}
	sh, err = OpenHead(readHeadFile(t, e, h.Size), e.known())
	if err != nil || len(sh.Sigs) != 4 {
		t.Fatalf("merged: %v %d", err, len(sh.Sigs))
	}
	// A re-signature with a later time replaces it (its own quorum); an
	// earlier time is refused.
	e.now = e.now.Add(time.Minute)
	h2, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h2, w2)); !errors.Is(err, ErrWitness) {
		t.Fatalf("old cosignatures are for another text: %v", err)
	}
	if err := op.PublishHead(e.cosigned(h2, w1, w2)); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h, w0, w1)); !errors.Is(err, ErrHead) {
		t.Fatalf("earlier time: %v", err)
	}
	// Another hash of the same size, a size beyond the tree, a smaller
	// size than the newest, another origin, a note that differs from
	// the head, no log signature by the covering generation.
	forged := *h2
	forged.Hash[0] ^= 1
	if err := op.PublishHead(e.cosigned(&forged, w0, w1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("other hash: %v", err)
	}
	beyond := *h2
	beyond.Size++
	if err := op.PublishHead(e.cosigned(&beyond, w0, w1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("beyond: %v", err)
	}
	e.addresses(1)
	h3, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h3, w0, w1)); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h2, w0, w1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("smaller than the newest: %v", err)
	}
	foreign := *h3
	foreign.Origin = "other"
	if err := op.PublishHead(e.cosigned(&foreign, w0, w1)); !errors.Is(err, ErrHead) {
		t.Fatalf("origin: %v", err)
	}
	differs := e.cosigned(h3, w0, w1)
	differs.Time++
	if err := op.PublishHead(differs); !errors.Is(err, ErrHead) {
		t.Fatalf("note differs: %v", err)
	}
	h4 := *h3
	h4.Time++
	g2 := &h4
	g2.Note = sign(t, g2, e.logSigner(2), w0.signer, w1.signer)
	if err := op.PublishHead(g2); !errors.Is(err, ErrHead) {
		t.Fatalf("unlogged generation: %v", err)
	}
	if err := op.PublishHead(&Head{}); !errors.Is(err, ErrHead) {
		t.Fatal("empty head")
	}
	if err := op.PublishHead(&Head{Note: []byte("x")}); !errors.Is(err, ErrHead) {
		t.Fatal("no signature block")
	}
	noText := *h3
	noText.Note = []byte("x\n\n— gomail-log AAAA\n")
	if err := op.PublishHead(&noText); !errors.Is(err, ErrHead) {
		t.Fatal("no head text")
	}
	// A stored head of the same size poisoned by a writer of log/: the
	// next publication of the same text drops the poisoned line.
	poisoned := append(readHeadFile(t, e, h3.Size), lastSigLine(sign(t, h2, w2.signer))...)
	if err := store.WriteFileAtomic(e.path(HeadPath(h3.Size)), poisoned); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHead(poisoned, e.known()); err == nil {
		t.Fatal("setup: poisoned head must not open")
	}
	if err := op.PublishHead(e.cosigned(h3, w2)); err != nil {
		t.Fatal(err)
	}
	if sh, err := OpenHead(readHeadFile(t, e, h3.Size), e.known()); err != nil || len(sh.Sigs) != 4 {
		t.Fatalf("repaired: %v", err)
	}
	// A stored head without a valid log line is ErrConsistency.
	if err := store.WriteFileAtomic(e.path(HeadPath(h3.Size)), sign(t, h3, w0.signer, w1.signer)); err != nil {
		t.Fatal(err)
	}
	if err := op.PublishHead(e.cosigned(h3, w0, w1)); !errors.Is(err, ErrConsistency) {
		t.Fatalf("stored head without log signature: %v", err)
	}
}

// lastSigLine returns the last signature line of a note, with newline.
func lastSigLine(msg []byte) []byte {
	t := bytes.TrimSuffix(msg, []byte("\n"))
	return append([]byte(nil), msg[bytes.LastIndexByte(t, '\n')+1:]...)
}

func TestVerifyLines(t *testing.T) {
	e := newEnv(t, 1, 1)
	h := e.headOf(t0)
	msg := sign(t, h, e.signer, e.ws[0].signer)
	text, lines, err := splitNote(msg)
	if err != nil || len(lines) != 2 {
		t.Fatal(err)
	}
	known := verifierList(e.ws[0].verifier)
	if got := verifyLines(text, lines, known); len(got) != 1 || got[0].Name != e.ws[0].name {
		t.Fatalf("lines %v", got)
	}
	for _, bad := range [][]byte{[]byte("no block"), []byte("a\n\nb"), append(bytes.Repeat([]byte("x"), MaxHeadNote), "\n\n— a b\n"...)} {
		if _, _, err := splitNote(bad); !errors.Is(err, ErrHead) {
			t.Fatalf("%q accepted", bad[:min(len(bad), 20)])
		}
	}
}

// TestRefreshOwnErrStrict (task 11, addendum point 1): while an own
// entry found replaced in a larger verified tree is unresolved, Refresh
// takes over no head, even one that passes CheckHead and the Pending
// check.
func TestRefreshOwnErrStrict(t *testing.T) {
	e := newEnv(t, 1, 1)
	c, v, _, i := replacedOwnEntry(t, e)
	old := *v.Last
	e.head() // size i+1 with the foreign entry at i
	if _, err := c.Refresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("Refresh: %v", err)
	}
	// The newest head is now a re-signature of the old reference size
	// with a later time: it passes CheckHead and does not cover the own
	// entry, but the verdict stays and nothing is taken over.
	if err := os.Remove(e.path(HeadPath(i + 1))); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	h := &Head{Origin: testOrigin, Size: old.Size, Hash: old.Hash, Time: e.now.UnixMilli()}
	e.publish(h, e.all()...)
	got, err := c.Refresh(e.now)
	if !errors.Is(err, ErrConsistency) {
		t.Fatalf("Refresh with a smaller verified head: %v", err)
	}
	if v.Last.Time != old.Time || got.Time != old.Time || len(v.Pending) != 1 {
		t.Fatalf("taken over: %d, pending %v", v.Last.Time, v.Pending)
	}
	if err := c.CheckFresh(e.now); !errors.Is(err, ErrConsistency) {
		t.Fatalf("CheckFresh: %v", err)
	}
}

func TestRepairTree(t *testing.T) {
	setup := func(t *testing.T) (*tenv, *operatorLog, *Head) {
		e := newEnv(t, 1, 1)
		e.addresses(3)
		op := e.openServer()
		h, err := op.SignHead(e.signer, e.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
			t.Fatal(err)
		}
		e.addresses(2) // two entries beyond the published head
		return e, op, h
	}
	t.Run("rolled back tree.rec", func(t *testing.T) {
		e, op, h := setup(t)
		full := e.tree()
		f := &files{root: e.st.Root}
		hr, _ := tlog.TreeHash(h.Size-1, e.hashReader())
		if err := f.writeTree(treeState{Size: h.Size - 1, Hash: hr}); err != nil {
			t.Fatal(err)
		}
		if _, err := op.SignHead(e.signer, e.now); !errors.Is(err, ErrConsistency) {
			t.Fatalf("SignHead on a rolled back tree: %v", err)
		}
		if err := RepairTree(e.serverOptions()); err != nil {
			t.Fatal(err)
		}
		if got := e.tree(); got != full {
			t.Fatalf("repaired to %d", got.Size)
		}
		if _, err := op.SignHead(e.signer, e.now); err != nil {
			t.Fatalf("SignHead after the repair: %v", err)
		}
		// Idempotent.
		if err := RepairTree(e.serverOptions()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("damaged tiles, missing tree.rec and keys", func(t *testing.T) {
		e, _, _ := setup(t)
		full := e.tree()
		tile := tlog.NewTiles(TileHeight, 0, full.Size)[0]
		if err := store.WriteFileAtomic(e.path(TilePath(tile)), bytes.Repeat([]byte{7}, tile.W*tlog.HashSize)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(e.path(TreeFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(e.path(KeysDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("Open of the damaged log: %v", err)
		}
		if err := RepairTree(e.serverOptions()); err != nil {
			t.Fatal(err)
		}
		if got := e.tree(); got != full {
			t.Fatal("tree.rec")
		}
		op := e.openServer()
		if _, err := op.SignHead(e.signer, e.now); err != nil {
			t.Fatal(err)
		}
		u := newUser(t)
		e.op = op
		e.mustAppend(KindUser, u.rec(t, 1))
		if n := op.f.readKeyFile(Key{Kind: KindUser, Subject: u.id[:], Seq: 1}); n != full.Size {
			t.Fatalf("key file of the new entry: %d", n)
		}
		e2 := e.p.cert(t, keys.RoleAdmin, 1, 1, t0-day)
		k, _ := KeyOf(KindPlatform, e2)
		if op.f.readKeyFile(k) != 0 {
			t.Fatal("key files not rebuilt")
		}
	})
	t.Run("entry missing below a head", func(t *testing.T) {
		e, _, h := setup(t)
		if err := os.Remove(e.path(EntryPath(h.Size - 1))); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("entry missing below a head: %v", err)
		}
	})
	t.Run("entry missing below tree.rec", func(t *testing.T) {
		e, _, h := setup(t)
		if err := os.Remove(e.path(EntryPath(h.Size + 1))); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("entry missing below tree.rec: %v", err)
		}
	})
	t.Run("changed entry below a head", func(t *testing.T) {
		e, _, h := setup(t)
		data, _ := os.ReadFile(e.path(EntryPath(h.Size + 1)))
		if err := store.WriteFileAtomic(e.path(EntryPath(h.Size-1)), data); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("changed entry: %v", err)
		}
	})
	t.Run("head without log signature or of another origin", func(t *testing.T) {
		e, _, h := setup(t)
		if err := store.WriteFileAtomic(e.path(HeadPath(h.Size)), sign(t, h, e.ws[0].signer)); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("unsigned head: %v", err)
		}
		o := *h
		o.Origin = "other"
		if err := store.WriteFileAtomic(e.path(HeadPath(h.Size)), sign(t, &o, e.signer)); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); !errors.Is(err, ErrConsistency) {
			t.Fatalf("other origin: %v", err)
		}
	})
	t.Run("options", func(t *testing.T) {
		e, _, _ := setup(t)
		if err := RepairTree(Options{}); !errors.Is(err, ErrConsistency) {
			t.Fatal("no store")
		}
		o := e.serverOptions()
		o.Verifier = e.verifier()
		if err := RepairTree(o); !errors.Is(err, ErrConsistency) {
			t.Fatal("client options")
		}
		o = e.serverOptions()
		o.Identities = nil
		if err := RepairTree(o); !errors.Is(err, ErrPin) {
			t.Fatal("no identities")
		}
		o.Identities = []Identity{{Gen: 2}}
		if err := RepairTree(o); !errors.Is(err, ErrPin) {
			t.Fatal("bad identities")
		}
		o = e.serverOptions()
		o.Origin = "a b"
		if err := RepairTree(o); !errors.Is(err, ErrHead) {
			t.Fatal("bad origin")
		}
	})
	t.Run("garbage entry ends the tree", func(t *testing.T) {
		e, _, _ := setup(t)
		full := e.tree()
		// A garbage file beyond the tree is not taken into it.
		if err := store.WriteFileAtomic(e.path(EntryPath(full.Size)), []byte("garbage")); err != nil {
			t.Fatal(err)
		}
		if err := RepairTree(e.serverOptions()); err != nil {
			t.Fatal(err)
		}
		if e.tree() != full {
			t.Fatal("garbage entry taken into the tree")
		}
	})
}
