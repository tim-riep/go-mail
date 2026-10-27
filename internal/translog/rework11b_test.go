package translog

import (
	"bytes"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// Tests of task 11b (findings of the verification of task 11).

// TestSignHeadSyncHook (finding 1): a failure between the sync and the
// signature leaves no head: SignHead returns the error and no head, the
// process remembers no signed head, and heads/ stays empty.
func TestSignHeadSyncHook(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	errSync := errors.New("sync failed")
	steps := 0
	crashHook = func(step string) error {
		if step == "sync" {
			steps++
			return errSync
		}
		return nil
	}
	t.Cleanup(func() { crashHook = nil })
	h, err := op.SignHead(e.signer, e.now)
	if !errors.Is(err, errSync) || h != nil || steps != 1 {
		t.Fatalf("head despite the failed sync step: %v %v %d", h, err, steps)
	}
	if op.signed != nil {
		t.Fatal("a head was remembered as signed")
	}
	if n, err := op.f.newestHeadSize(); err != nil || n != 0 {
		t.Fatalf("heads/: %d %v", n, err)
	}
	crashHook = nil
	if h, err := op.SignHead(e.signer, e.now); err != nil || h == nil {
		t.Fatalf("after the failure: %v", err)
	}
}

// syncRecorder records the paths SignHead syncs (fsyncFile, fsyncDir)
// and the injection point "sync", in order.
type syncRecorder struct {
	files, dirs []string
	order       []string
}

func recordSyncs(t *testing.T) *syncRecorder {
	t.Helper()
	r := &syncRecorder{}
	of, od := fsyncFile, fsyncDir
	fsyncFile = func(p string) error {
		r.files = append(r.files, p)
		r.order = append(r.order, "file:"+p)
		return of(p)
	}
	fsyncDir = func(p string) error {
		r.dirs = append(r.dirs, p)
		r.order = append(r.order, "dir:"+p)
		return od(p)
	}
	crashHook = func(step string) error {
		if step == "sync" {
			r.order = append(r.order, "hook:sync")
		}
		return nil
	}
	t.Cleanup(func() { fsyncFile, fsyncDir, crashHook = of, od, nil })
	return r
}

func (r *syncRecorder) reset() { r.files, r.dirs, r.order = nil, nil, nil }

// expectSynced returns the files SignHead must sync for the tree from
// size from to size to (the entries from..to-1, the tiles that changed,
// tree.rec) and every directory above them up to and including log/;
// log/entries/ and log/tree/ are synced always.
func expectSynced(e *tenv, from, to int64) (files, dirs []string) {
	for i := from; i < to; i++ {
		files = append(files, e.path(EntryPath(i)))
	}
	for _, x := range tlog.NewTiles(TileHeight, from, to) {
		files = append(files, e.path(TilePath(x)))
	}
	files = append(files, e.path(TreeFile))
	seen := map[string]bool{EntriesDir: true, TilesDir: true}
	dirs = append(dirs, e.path(EntriesDir), e.path(TilesDir))
	for _, f := range files {
		rel := strings.TrimPrefix(filepath.ToSlash(f), filepath.ToSlash(e.st.Root)+"/")
		for d := path.Dir(rel); ; d = path.Dir(d) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, e.path(d))
			}
			if d == Dir {
				break
			}
		}
	}
	return files, dirs
}

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSignHeadSyncedPaths (finding 1, Q10 (2)): SignHead syncs exactly
// the entries from its base on, the tiles that changed, tree.rec and
// every directory up to log/ (deepest first, log/ last), each once, and
// all of it before the signature (injection point "sync").
func TestSignHeadSyncedPaths(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	r := recordSyncs(t)
	check := func(name string, from, to int64) {
		t.Helper()
		files, dirs := expectSynced(e, from, to)
		if !sameSet(r.files, files) || len(r.files) != len(files) {
			t.Fatalf("%s: files synced %v, want %v", name, r.files, files)
		}
		if !sameSet(r.dirs, dirs) || len(r.dirs) != len(dirs) {
			t.Fatalf("%s: directories synced %v, want %v", name, r.dirs, dirs)
		}
		if len(r.order) == 0 || r.order[len(r.order)-1] != "hook:sync" || r.order[len(r.order)-2] != "dir:"+e.path(Dir) {
			t.Fatalf("%s: order %v", name, r.order)
		}
		for i := 1; i < len(r.dirs); i++ {
			if strings.HasPrefix(r.dirs[i], r.dirs[i-1]+string(filepath.Separator)) {
				t.Fatalf("%s: %s synced before %s", name, r.dirs[i-1], r.dirs[i])
			}
		}
		r.reset()
	}
	// No base: the whole tree.
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	check("first head", 0, h.Size)
	if err := op.PublishHead(e.cosigned(h, e.ws...)); err != nil {
		t.Fatal(err)
	}
	r.reset()
	// Base: the published head; only what came after it.
	e.addresses(300)
	size := e.tree().Size
	h2, err := op.SignHead(e.signer, e.now.Add(time.Minute))
	if err != nil || h2.Size != size {
		t.Fatal(err)
	}
	check("after the published head", h.Size, size)
	// Base: the head this process signed last (larger than the published).
	e.addresses(2)
	h3, err := op.SignHead(e.signer, e.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	check("after the signed head", h2.Size, h3.Size)
	// Re-signing the same size syncs tree.rec and the directories only.
	if _, err := op.SignHead(e.signer, e.now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	check("same size", h3.Size, h3.Size)
	// A sync that fails: no head.
	fsyncDir = func(string) error { return errors.New("disk") }
	if h, err := op.SignHead(e.signer, e.now.Add(4*time.Minute)); h != nil || err == nil {
		t.Fatalf("failed sync: %v %v", h, err)
	}
}

// TestPublishSameSizeOtherHash (finding 3, from verifier test 1): a stored
// head of the same size with another hash, validly signed by the log
// key, is never replaced (ErrConsistency), even when the new head
// matches the committed tree.
func TestPublishSameSizeOtherHash(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	h, err := op.SignHead(e.signer, e.now)
	if err != nil {
		t.Fatal(err)
	}
	other := *h
	other.Hash[0] ^= 1
	e.publish(&other, e.all()...)
	err = op.PublishHead(e.cosigned(h, e.ws...))
	if !errors.Is(err, ErrConsistency) {
		t.Fatalf("other hash stored: %v", err)
	}
	if sh, err := OpenHead(readHeadFile(t, e, h.Size), e.known()); err != nil || sh.Hash != other.Hash {
		t.Fatalf("stored head replaced: %v", err)
	}
}

// TestPublishCoveringGeneration (finding 4, from verifier test 2):
// PublishHead refuses a log line by a logged generation that does not
// cover the head time (generation 1 at valid_from of ingest-2.cert) and
// accepts the covering generation 2.
func TestPublishCoveringGeneration(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	sw := e.now.Add(time.Hour).UnixMilli()
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 1, sw))
	h := e.headOf(sw)
	h.Note = sign(t, h, e.logSigner(1), e.ws[0].signer)
	if err := op.PublishHead(h); !errors.Is(err, ErrHead) {
		t.Fatalf("generation 1 at the switch accepted: %v", err)
	}
	if n, _ := op.f.newestHeadSize(); n != 0 {
		t.Fatal("a head was written")
	}
	// Both log lines: only the covering one is stored.
	h.Note = sign(t, h, e.logSigner(1), e.logSigner(2), e.ws[0].signer)
	if err := op.PublishHead(h); err != nil {
		t.Fatalf("generation 2 beside 1: %v", err)
	}
	stored := readHeadFile(t, e, h.Size)
	g1 := e.logSigner(1).KeyHash()
	sh, err := OpenHead(stored, e.known())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sh.Sigs {
		if s.Name == LogSignerName && s.Hash == g1 {
			t.Fatal("line of generation 1 stored")
		}
	}
	if len(sh.Sigs) != 2 {
		t.Fatalf("stored lines: %d", len(sh.Sigs))
	}
}

// TestOperatorHeadLineByLine (finding 5): the operator opens the newest
// published head line by line; a witness line with a known name and key
// hash but an invalid signature (written into heads/ past PublishHead)
// is dropped from the returned note instead of failing Head and
// Refresh. A client still refuses the file (OpenHead).
func TestOperatorHeadLineByLine(t *testing.T) {
	e := newEnv(t, 2, 2)
	op := e.openServer() // Known nil: Options.Witnesses open the witness lines
	h := e.headOf(e.now.UnixMilli())
	e.publish(h, e.signer, e.ws[0].signer)
	other := e.headOf(e.now.UnixMilli() + 1)
	poisoned := append(readHeadFile(t, e, h.Size), lastSigLine(sign(t, other, e.ws[1].signer))...)
	if err := store.WriteFileAtomic(e.path(HeadPath(h.Size)), poisoned); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHead(poisoned, e.known()); err == nil {
		t.Fatal("setup: the poisoned note must not open")
	}
	for name, l := range map[string]Operator{"server options": op, "known as main.go": e.openOp()} {
		for _, get := range []func() (*Head, error){l.Head, func() (*Head, error) { return l.Refresh(e.now) }} {
			got, err := get()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got.Size != h.Size || got.Hash != h.Hash || len(got.Sigs) != 2 {
				t.Fatalf("%s: head %d, %d lines", name, got.Size, len(got.Sigs))
			}
			if bytes.Equal(got.Note, poisoned) {
				t.Fatalf("%s: poisoned note handed on", name)
			}
			if n, err := OpenHead(got.Note, e.known()); err != nil || len(n.Sigs) != 2 || bytes.Contains(got.Note, []byte(e.ws[1].name)) {
				t.Fatalf("%s: returned note does not open with every key: %v", name, err)
			}
		}
	}
	c, _ := e.client()
	if _, err := c.Head(); !errors.Is(err, ErrHead) {
		t.Fatalf("client opened the poisoned head: %v", err)
	}
	// Without a log line the operator still refuses (ErrHead).
	if err := store.WriteFileAtomic(e.path(HeadPath(h.Size)), sign(t, h, e.ws[0].signer, e.ws[1].signer)); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Head(); !errors.Is(err, ErrHead) {
		t.Fatalf("head without log line: %v", err)
	}
	// A head of another origin: ErrHead.
	h.Origin = "other-origin"
	if err := store.WriteFileAtomic(e.path(HeadPath(h.Size)), sign(t, h, e.all()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Head(); !errors.Is(err, ErrHead) {
		t.Fatalf("head of another origin: %v", err)
	}
}

// TestOperatorLogKeys (finding 7): LogKeys lists every valid ingest
// certificate of the committed tree with its time line.
func TestOperatorLogKeys(t *testing.T) {
	e := newEnv(t, 1, 1)
	op := e.openServer()
	ks, err := op.LogKeys()
	if err != nil || len(ks) != 1 || ks[0].Gen != 1 || !ks[0].Logged || ks[0].Until != 0 {
		t.Fatalf("one generation: %v %+v", err, ks)
	}
	sw := e.now.Add(time.Hour).UnixMilli()
	e.mustAppend(KindPlatform, e.p.cert(t, keys.RoleIngest, 2, 1, sw))
	ks, err = op.LogKeys()
	if err != nil || len(ks) != 2 {
		t.Fatalf("two generations: %v %d", err, len(ks))
	}
	byGen := map[uint32]LogKey{}
	for _, k := range ks {
		byGen[k.Gen] = k
	}
	if byGen[1].Until != sw || byGen[2].ValidFrom != sw || byGen[1].Verifier.KeyHash() != e.logSigner(1).KeyHash() ||
		byGen[2].Verifier.KeyHash() != e.logSigner(2).KeyHash() {
		t.Fatalf("time line: %+v", byGen)
	}
	if err := os.Remove(e.path(TreeFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := op.LogKeys(); err == nil {
		t.Fatal("LogKeys without tree.rec")
	}
}

// TestRepairForgedEntry (from the attack tests of the verification of
// task 11): a decodable but invalid entry written past Append beyond the
// published head stays in the tree after RepairTree as an invalid entry
// that occupies no key; committed entries are kept and SignHead alerts.
func TestRepairForgedEntry(t *testing.T) {
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
	full := e.tree()
	mbx := newMbx(t)
	// Signed by the ingest key (wrong role): the admin signature never
	// verifies.
	as := &store.AddressAssignment{Address: "forged@example.org", MailboxID: mbx, ValidFrom: t0 + 5000, AdminGen: 1}
	if err := as.Sign(e.p.ingest(t, 1)); err != nil {
		t.Fatal(err)
	}
	forged, err := as.Encode()
	if err != nil {
		t.Fatal(err)
	}
	en, err := NewEntry(KindAddress, forged)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := en.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&fileLog{f: &files{root: e.st.Root}}).write(full, en.Key, enc); err != nil {
		t.Fatal(err)
	}
	if err := RepairTree(e.serverOptions()); err != nil {
		t.Fatalf("repair refused a decodable invalid entry: %v", err)
	}
	if after := e.tree(); after.Size != full.Size+1 {
		t.Fatalf("size after the repair: %d", after.Size)
	}
	op2 := e.openServer()
	idx, err := op2.Append(KindAddress, e.addr(t, "forged@example.org", mbx, t0+5000, 1))
	if err != nil || idx != full.Size+1 {
		t.Fatalf("the key of the forged entry is occupied: %d %v", idx, err)
	}
	_, err = op2.SignHead(e.signer, e.now.Add(time.Minute))
	var inv *InvalidEntriesError
	if !errors.As(err, &inv) || len(inv.Entries) != 1 || inv.Entries[0].Index != full.Size {
		t.Fatalf("no alert for the forged entry: %v", err)
	}
}
