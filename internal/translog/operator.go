package translog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// This file is the server side of the log (task 11): Operator.SignHead,
// Operator.PublishHead and RepairTree (doc.go "Heads", "What write access
// to log/ gives an attacker", "Tasks" point 11).

// InvalidEntriesError is returned by SignHead together with the head when
// committed entries from the newest published head on fail the validity
// rules (doc.go "Validity rules": written past Append by someone with
// write access to log/). The head covers them; they occupy no key and
// every audit skips them. The server alerts. It unwraps to the error of
// the first entry (ErrEntry, ErrDuplicate, ErrOrder, ErrPrerequisite,
// ErrUnloggedSigner or ErrMismatch).
type InvalidEntriesError struct {
	Entries []InvalidEntry
}

// OrphanEntriesError is returned by RepairTree when files
// entries/<i>.rec with i >= Size exist, where Size is the number of
// entries that exist and decode from entry 0 on (the size the repair
// would set; task 15d point 2). Such an orphan is left beyond a gap
// (tree.rec rolled back with entries/<n+1>.rec removed and entry n
// appended again, doc.go "What write access to log/ gives an attacker")
// or does not decode. RepairTree removes nothing and writes nothing; it
// unwraps to ErrConsistency. Count is the number of orphans, First and
// Last their smallest and largest index.
type OrphanEntriesError struct {
	Size        int64
	Count       int64
	First, Last int64
}

func (e *OrphanEntriesError) Error() string {
	where := fmt.Sprintf("entries/%d.rec", e.First)
	if e.Last != e.First {
		where += fmt.Sprintf(" to entries/%d.rec", e.Last)
	}
	return fmt.Sprintf("%v: %d orphaned entries beyond the %d entries that exist and decode (%s); nothing removed",
		ErrConsistency, e.Count, e.Size, where)
}

// Unwrap returns ErrConsistency.
func (e *OrphanEntriesError) Unwrap() error { return ErrConsistency }

// maxListedInvalid bounds the indices the message of an
// InvalidEntriesError lists.
const maxListedInvalid = 16

func (e *InvalidEntriesError) Error() string {
	var b strings.Builder
	b.WriteString(e.Unwrap().Error())
	b.WriteString(": invalid entries")
	for i, x := range e.Entries {
		if i == maxListedInvalid {
			fmt.Fprintf(&b, " and %d more", len(e.Entries)-i)
			break
		}
		fmt.Fprintf(&b, " %d (%s)", x.Index, x.Class)
	}
	return b.String()
}

// Unwrap returns the error variable of the first invalid entry.
func (e *InvalidEntriesError) Unwrap() error {
	if len(e.Entries) == 0 {
		return ErrEntry
	}
	switch e.Entries[0].Class {
	case "unlogged-signer":
		return ErrUnloggedSigner
	case "prerequisite":
		return ErrPrerequisite
	case "duplicate":
		return ErrDuplicate
	case "order":
		return ErrOrder
	case "mismatch":
		return ErrMismatch
	}
	return ErrEntry
}

// logKeysOf returns a LogKey for every valid ingest certificate of s
// with an index below size, judged against the tree of that size
// (Logged, Until; doc.go "Platform generations"). For the operator s is
// the committed tree, which may be larger than the head being judged:
// a certificate at or above size is not in the tree of that head.
func logKeysOf(s *state, size int64) []LogKey {
	var out []LogKey
	for _, c := range s.Certs {
		if c.Role != uint8(keys.RoleIngest) || c.Index >= size {
			continue
		}
		v, err := NewLogVerifier(ed25519.PublicKey(c.Pub))
		if err != nil {
			continue
		}
		k := LogKey{Gen: c.Gen, Verifier: v, ValidFrom: c.ValidFrom, Logged: true}
		if c.Gen < 1<<32-1 {
			if next := s.Certs[certName(keys.RoleIngest, c.Gen+1)]; next != nil && next.Index < size {
				k.Until = next.ValidFrom
				if k.Until == 0 {
					k.Until = -1 // valid_from 0: generation Gen covers nothing
				}
			}
		}
		out = append(out, k)
	}
	return out
}

// coveringKey returns the verifier of the ingest generation that Covers
// time t in the tree of size size (at most one does, LogKey.Covers).
func coveringKey(s *state, size, t int64) (note.Verifier, bool) {
	for _, k := range logKeysOf(s, size) {
		if k.Covers(t) {
			return k.Verifier, true
		}
	}
	return nil, false
}

// verifierList is a note.Verifiers of a fixed list.
func verifierList(vs ...note.Verifier) note.Verifiers { return &verifierSet{list: vs} }

// splitNote splits a signed note into its text (ending in a newline) and
// its signature lines (without newline), as note.Open does: the text
// ends at the last blank line.
func splitNote(msg []byte) ([]byte, [][]byte, error) {
	if len(msg) > MaxHeadNote {
		return nil, nil, fmt.Errorf("%w: signed head too long", ErrHead)
	}
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return nil, nil, fmt.Errorf("%w: no signature block", ErrHead)
	}
	text, sigs := msg[:i+1], msg[i+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, nil, fmt.Errorf("%w: malformed signature block", ErrHead)
	}
	return text, bytes.Split(sigs[:len(sigs)-1], []byte("\n")), nil
}

// verifyLines verifies every signature line on its own (one note.Open
// over the text and that line) and returns the lines that verify with a
// key of known, once per key, with their signature in canonical base64.
// A line that does not verify, by an unknown key or not well formed, is
// dropped (doc.go "Heads", task 03b finding A2-10): unlike note.Open on
// the whole note, one bad line never makes the others unusable.
func verifyLines(text []byte, lines [][]byte, known note.Verifiers) []note.Signature {
	var out []note.Signature
	for _, ln := range lines {
		msg := make([]byte, 0, len(text)+len(ln)+2)
		msg = append(append(append(append(msg, text...), '\n'), ln...), '\n')
		n, err := note.Open(msg, known)
		if err != nil || len(n.Sigs) != 1 {
			continue
		}
		sig := n.Sigs[0]
		raw, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil {
			continue
		}
		sig.Base64 = base64.StdEncoding.EncodeToString(raw)
		dup := false
		for _, o := range out {
			dup = dup || (o.Name == sig.Name && o.Hash == sig.Hash)
		}
		if !dup {
			out = append(out, sig)
		}
	}
	return out
}

// readHead reads heads/<size>.sig and returns the head whose text the
// lines verifying with known sign, with those lines. At least one of them
// must be a log signature (LogSignerName); the text must be a strict head
// text of that size with Options.Origin when that is set. Any violation
// is ErrConsistency: a file in heads/ that is no head signed by the log
// contradicts the committed tree (it names a size the server cannot
// account for). Head.Note is the file as stored.
func (l *fileLog) readHead(size int64, known note.Verifiers) (*Head, error) {
	h, _, err := l.headLines(size, known, ErrConsistency)
	return h, err
}

// headLines is readHead with the error variable class for every
// violation; it also returns the text of the head (ending in a newline).
func (l *fileLog) headLines(size int64, known note.Verifiers, class error) (*Head, []byte, error) {
	msg, err := store.ReadFileLimited(l.f.path(HeadPath(size)), MaxHeadNote)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: heads/%d.sig: %v", class, size, err)
	}
	text, lines, err := splitNote(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: heads/%d.sig is no signed note", class, size)
	}
	sigs := verifyLines(text, lines, known)
	logged := false
	for _, s := range sigs {
		logged = logged || s.Name == LogSignerName
	}
	if !logged {
		return nil, nil, fmt.Errorf("%w: heads/%d.sig carries no valid log signature", class, size)
	}
	h, err := ParseHeadText(text)
	if err != nil || h.Size != size || (l.opts.Origin != "" && h.Origin != l.opts.Origin) {
		return nil, nil, fmt.Errorf("%w: heads/%d.sig holds no head of this log and size", class, size)
	}
	h.Sigs, h.Note = sigs, msg
	return h, text, nil
}

// operatorHead opens heads/<size>.sig for Head and Refresh of an
// operator log (task 11b finding 5): line by line as readHead, so that
// one invalid line by a known key (a witness line written into heads/ by
// someone with write access to log/) does not make the head unreadable
// for the server, which serves it to witnesses (GET /gomail/log/head).
// Every violation is ErrHead, as for OpenHead. The returned Note holds
// the text and only the lines that verified, one per key; a line that
// does not verify is never handed on. A client log keeps OpenHead: its
// verdict on such a file stays "unopenable" (doc.go "What write access to
// log/ gives an attacker").
func (l *fileLog) operatorHead(size int64, known note.Verifiers) (*Head, error) {
	h, text, err := l.headLines(size, known, ErrHead)
	if err != nil {
		return nil, err
	}
	if len(h.Sigs) > MaxSignatures {
		return nil, fmt.Errorf("%w: heads/%d.sig: too many signatures", ErrHead, size)
	}
	msg, err := note.Sign(&note.Note{Text: string(text), Sigs: h.Sigs})
	if err != nil {
		return nil, fmt.Errorf("%w: heads/%d.sig: %v", ErrHead, size, err)
	}
	h.Note = msg
	return h, nil
}

// logVerifiers returns the verifiers of every valid ingest certificate
// of s, whatever the time they cover: a published head of the past may be
// signed by an earlier generation.
func logVerifiers(s *state) []note.Verifier {
	var out []note.Verifier
	for _, k := range logKeysOf(s, s.Size) {
		out = append(out, k.Verifier)
	}
	return out
}

// published returns the newest published head, nil when there is none.
func (l *fileLog) published(s *state) (*Head, error) {
	size, err := l.f.newestHeadSize()
	if err != nil || size == 0 {
		return nil, err
	}
	return l.readHead(size, verifierList(logVerifiers(s)...))
}

// extends checks that the committed tree has the root b.Hash at size
// b.Size (ErrConsistency).
func (l *fileLog) extends(tree treeState, b *Head) error {
	if b.Size > tree.Size {
		return fmt.Errorf("%w: a head of size %d is beyond the committed size %d (tree.rec rolled back?)", ErrConsistency, b.Size, tree.Size)
	}
	h, err := tlog.TreeHash(b.Size, l.f.reader(tree))
	if err != nil {
		return wrapConsistency(err)
	}
	if h != b.Hash {
		return fmt.Errorf("%w: the committed tree does not extend the head of size %d", ErrConsistency, b.Size)
	}
	return nil
}

// recompute returns the root hash of the committed tree recomputed from
// entries/<i>.rec for every i from base.Size on; the stored hashes below
// come from tiles verified against base.Hash (doc.go "What write access
// to log/ gives an attacker": the server recomputes the tree from the
// entries, not from tiles written by others). base nil means from entry
// 0.
func (l *fileLog) recompute(base *Head, tree treeState) (tlog.Hash, error) {
	var b treeState
	if base != nil {
		b = treeState{Size: base.Size, Hash: base.Hash}
	}
	var hashes []tlog.Hash
	rd := combReader(l.f.reader(b), tlog.StoredHashCount(b.Size), &hashes)
	for i := b.Size; i < tree.Size; i++ {
		data, err := l.f.readEntry(i)
		if err != nil {
			if errors.Is(err, ErrNotInLog) {
				return tlog.Hash{}, fmt.Errorf("%w: committed entry %d is missing", ErrConsistency, i)
			}
			return tlog.Hash{}, err
		}
		hs, err := tlog.StoredHashes(i, data, rd)
		if err != nil {
			return tlog.Hash{}, wrapConsistency(err)
		}
		hashes = append(hashes, hs...)
	}
	root, err := tlog.TreeHash(tree.Size, rd)
	if err != nil {
		return tlog.Hash{}, wrapConsistency(err)
	}
	return root, nil
}

// fsyncFile and fsyncDir are the two sync operations of syncTree; tests
// replace them to record the paths synced (task 11b finding 1).
var (
	fsyncFile = syncFile
	fsyncDir  = store.SyncDir
)

// syncFile fsyncs a file that exists.
func syncFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncTree makes the tree of size to durable from size from on (task 07
// finding Q10 (2)): the entries from..to-1, the tiles that changed
// between the two sizes, tree.rec, and the directories that hold them up
// to log/. A visible tree.rec is not yet a durable one; a head over a
// tree lost in a crash could never be matched again.
func (l *fileLog) syncTree(from, to int64) error {
	dirs := map[string]bool{l.f.path(Dir): true, l.f.path(EntriesDir): true, l.f.path(TilesDir): true}
	for i := from; i < to; i++ {
		if err := fsyncFile(l.f.path(EntryPath(i))); err != nil {
			return logErr("sync entry", err)
		}
	}
	top := l.f.path(TilesDir)
	for _, t := range tlog.NewTiles(TileHeight, from, to) {
		p := l.f.path(TilePath(t))
		if err := fsyncFile(p); err != nil {
			return logErr("sync tile", err)
		}
		for d := filepath.Dir(p); len(d) > len(top) && !dirs[d]; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	if err := fsyncFile(l.f.path(TreeFile)); err != nil {
		return logErr("sync tree.rec", err)
	}
	// Deepest directories first, log/ last.
	list := make([]string, 0, len(dirs))
	for d := range dirs {
		list = append(list, d)
	}
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && len(list[j]) > len(list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	for _, d := range list {
		if err := fsyncDir(d); err != nil {
			return logErr("sync directory", err)
		}
	}
	return nil
}

// SignHead (Operator.SignHead).
func (o *operatorLog) SignHead(signer note.Signer, now time.Time) (*Head, error) {
	l := o.fileLog
	if signer == nil || signer.Name() != LogSignerName {
		return nil, fmt.Errorf("%w: the log signs with the name %s", ErrHead, LogSignerName)
	}
	if l.opts.Origin == "" {
		return nil, fmt.Errorf("%w: no origin configured", ErrHead)
	}
	t := now.UnixMilli()
	if t < 0 {
		return nil, fmt.Errorf("%w: time before 1970", ErrHead)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := store.LockPath(l.f.path(LockFile))
	if err != nil {
		return nil, fmt.Errorf("%w: log lock: %v", ErrConsistency, err)
	}
	defer unlock()
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	if err := l.refuse(tree); err != nil {
		return nil, err
	}
	if tree.Size == 0 {
		return nil, fmt.Errorf("%w: the log is empty; a head of the empty log is never signed", ErrNotInLog)
	}
	cur, err := l.getCur(tree)
	if err != nil {
		return nil, err
	}
	pub, err := l.published(cur)
	if err != nil {
		return nil, err
	}
	base := pub
	for _, b := range []*Head{pub, l.signed} {
		if b == nil {
			continue
		}
		if err := l.extends(tree, b); err != nil {
			return nil, err
		}
		if t < b.Time {
			return nil, fmt.Errorf("%w: the clock lies before the newest head", ErrHead)
		}
		if base == nil || b.Size > base.Size {
			base = b
		}
	}
	root, err := l.recompute(base, tree)
	if err != nil {
		return nil, err
	}
	if root != tree.Hash {
		return nil, fmt.Errorf("%w: the entries do not give the root hash of tree.rec", ErrConsistency)
	}
	from := int64(0)
	if base != nil {
		from = base.Size
	}
	if err := l.syncTree(from, tree.Size); err != nil {
		return nil, err
	}
	// Injection point between the sync and the signature (task 11b
	// finding 1): a failure here leaves no head.
	if err := hook("sync"); err != nil {
		return nil, err
	}
	v, ok := coveringKey(cur, tree.Size, t)
	if !ok || v.KeyHash() != signer.KeyHash() {
		return nil, fmt.Errorf("%w: the signer is not the ingest generation that covers the head time", ErrHead)
	}
	h := &Head{Origin: l.opts.Origin, Size: tree.Size, Hash: tree.Hash, Time: t}
	text, err := h.Text()
	if err != nil {
		return nil, err
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: sign: %v", ErrHead, err)
	}
	n, err := note.Open(msg, verifierList(v))
	if err != nil || len(n.Sigs) != 1 {
		return nil, fmt.Errorf("%w: the signature does not verify with the certified ingest key", ErrHead)
	}
	h.Sigs, h.Note = n.Sigs, msg
	l.signed = &Head{Origin: h.Origin, Size: h.Size, Hash: h.Hash, Time: h.Time}
	pubSize := int64(0)
	if pub != nil {
		pubSize = pub.Size
	}
	var bad []InvalidEntry
	for _, x := range cur.Invalid {
		if x.Index >= pubSize && x.Index < tree.Size {
			bad = append(bad, x)
		}
	}
	if len(bad) > 0 {
		return h, &InvalidEntriesError{Entries: bad}
	}
	return h, nil
}

// LogKeys (Operator.LogKeys).
func (o *operatorLog) LogKeys() ([]LogKey, error) {
	l := o.fileLog
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := l.view()
	if err != nil {
		return nil, err
	}
	return logKeysOf(s, s.Size), nil
}

// PublishHead (Operator.PublishHead).
func (o *operatorLog) PublishHead(h *Head) error {
	l := o.fileLog
	if h == nil || len(h.Note) == 0 {
		return fmt.Errorf("%w: no signed head", ErrHead)
	}
	if len(l.opts.Witnesses) == 0 {
		return fmt.Errorf("%w: no witnesses configured (witnesses.rec)", ErrWitness)
	}
	if l.opts.Origin == "" {
		return fmt.Errorf("%w: no origin configured", ErrHead)
	}
	text, lines, err := splitNote(h.Note)
	if err != nil {
		return err
	}
	hd, err := ParseHeadText(text)
	if err != nil {
		return err
	}
	if hd.Origin != h.Origin || hd.Size != h.Size || hd.Hash != h.Hash || hd.Time != h.Time {
		return fmt.Errorf("%w: note text differs from the head", ErrHead)
	}
	if hd.Origin != l.opts.Origin {
		return fmt.Errorf("%w: head of another log", ErrHead)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := store.LockPath(l.f.path(LockFile))
	if err != nil {
		return fmt.Errorf("%w: log lock: %v", ErrConsistency, err)
	}
	defer unlock()
	tree, err := l.f.readTree()
	if err != nil {
		return err
	}
	cur, err := l.getCur(tree)
	if err != nil {
		return err
	}
	if err := l.extends(tree, hd); err != nil {
		return err
	}
	newest, err := l.f.newestHeadSize()
	if err != nil {
		return err
	}
	if newest > hd.Size {
		return fmt.Errorf("%w: a larger head is published", ErrConsistency)
	}
	if newest > 0 {
		prev, err := l.readHead(newest, verifierList(logVerifiers(cur)...))
		if err != nil {
			return err
		}
		if newest == hd.Size && prev.Hash != hd.Hash {
			return fmt.Errorf("%w: two heads of one size with different hashes", ErrConsistency)
		}
		if hd.Time < prev.Time {
			return fmt.Errorf("%w: head older than the newest published head", ErrHead)
		}
		if newest == hd.Size {
			// Keep the cosignatures of the stored head when they are for
			// the same text (merge, one line per key).
			if ptext, plines, err := splitNote(prev.Note); err == nil && bytes.Equal(ptext, text) {
				lines = append(plines, lines...)
			}
		}
	}
	key, ok := coveringKey(cur, hd.Size, hd.Time)
	if !ok {
		return fmt.Errorf("%w: no ingest generation covers the head time", ErrHead)
	}
	sigs := verifyLines(text, lines, verifierList(append([]note.Verifier{key}, l.opts.Witnesses...)...))
	var logSig []note.Signature
	var cos []note.Signature
	for _, s := range sigs {
		if s.Name == LogSignerName {
			logSig = append(logSig, s)
		} else {
			cos = append(cos, s)
		}
	}
	if len(logSig) != 1 {
		return fmt.Errorf("%w: no log signature by the generation that covers the head time", ErrHead)
	}
	// verifyLines keeps one line per key, and Open refused one key under
	// two names (checkWitnessSet), so every line is another witness.
	if len(cos) < l.opts.MinWitnesses {
		return fmt.Errorf("%w: %d of %d required cosignatures", ErrWitness, len(cos), l.opts.MinWitnesses)
	}
	msg, err := note.Sign(&note.Note{Text: string(text), Sigs: append(logSig, cos...)})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHead, err)
	}
	if len(msg) > MaxHeadNote {
		return fmt.Errorf("%w: signed head too long", ErrHead)
	}
	return logErr("head", store.WriteFileAtomic(l.f.path(HeadPath(hd.Size)), msg))
}

// RepairTree rebuilds tree.rec, the tiles and keys/ of the log in
// opts.Store from the entries and the signed heads (doc.go "What write
// access to log/ gives an attacker", task 03d finding 3, task 07 finding
// Q10 (4); an operator action of task 11, "gomail-server log repair").
// It needs the operator's options (Verifier nil, Identities of the pin;
// Origin, when set, is required of every head) and works without Open,
// which refuses exactly the damaged logs it repairs. Under log/lock:
//
//  1. m is the largest size for which entries/0.rec to entries/<m-1>.rec
//     exist and decode (DecodeEntry); the entries are replayed with the
//     validity rules as Open does;
//  2. every heads/<s>.sig must carry a valid log signature by an ingest
//     certificate that is a valid entry of the log, with s <= m and the
//     root hash of size s recomputed from the entries (ErrConsistency
//     otherwise: the entries do not hold what the server signed);
//  3. a tree.rec that can be read and names a size above m is
//     ErrConsistency: entries below the committed size are missing, and
//     a smaller tree.rec would drop committed entries for good;
//  4. a file entries/<i>.rec with i >= m (an orphaned entry: left beyond
//     a gap or not decodable, task 15d point 2) is an
//     *OrphanEntriesError, which wraps ErrConsistency and counts them.
//     Nothing is removed and nothing is written: refuse would keep the
//     repaired log failing on an orphan at m+1 or above, and only the
//     operator decides to remove them (doc.go "What write access to log/
//     gives an attacker"); then he repairs again. An orphan at m alone
//     would not stop the log (the next Append removes it as a
//     leftover); it is reported all the same (task 15d names i >= m);
//  5. it writes the tiles of tlog.NewTiles(8, 0, m) (a tile with other
//     bytes is replaced), the key file of every valid entry and then
//     tree.rec with m and the recomputed root hash.
//
// Steps 1 to 4 write no file (only missing directories of log/ are
// created first); an error there leaves the files as they were.
//
// TODO(ask): doc.go says "exist and decode"; read strictly, an entry that
// is in the tree but does not decode with DecodeEntry (written past
// Append) ends the repair below it, and a head that covers it makes the
// repair fail (fail closed, the operator restores log/ from a backup);
// it and the entries after it are orphans (step 4). The hashes of the
// whole tree are held in memory (about 64 bytes per entry).
func RepairTree(opts Options) error {
	if opts.Store == nil {
		return fmt.Errorf("%w: no data directory", ErrConsistency)
	}
	if opts.Verifier != nil {
		return fmt.Errorf("%w: RepairTree is an operator action", ErrConsistency)
	}
	if len(opts.Identities) == 0 {
		return fmt.Errorf("%w: an operator log needs the identity list of a pin", ErrPin)
	}
	if err := CheckIdentities(opts.Identities, opts.Identities[len(opts.Identities)-1]); err != nil {
		return err
	}
	if opts.Origin != "" {
		if err := checkOrigin(opts.Origin); err != nil {
			return err
		}
	}
	l := &fileLog{st: opts.Store, f: &files{root: opts.Store.Root}, opts: opts, ids: opts.Identities}
	for _, d := range []string{Dir, EntriesDir, TilesDir, HeadsDir, KeysDir} {
		if err := store.MkdirAll(l.f.path(d)); err != nil {
			return logErr(d, err)
		}
	}
	unlock, err := store.LockPath(l.f.path(LockFile))
	if err != nil {
		return fmt.Errorf("%w: log lock: %v", ErrConsistency, err)
	}
	defer unlock()
	// 1. entries
	s := newState(l.f, l.ids)
	var hashes []tlog.Hash
	rd := combReader(l.f.reader(treeState{}), 0, &hashes)
	m := int64(0)
	for ; m < MaxTreeSize; m++ {
		data, err := l.f.readEntry(m)
		if errors.Is(err, ErrNotInLog) {
			break
		}
		if err != nil {
			return err
		}
		if _, err := DecodeEntry(data, m); err != nil {
			break
		}
		hs, err := tlog.StoredHashes(m, data, rd)
		if err != nil {
			return wrapConsistency(err)
		}
		hashes = append(hashes, hs...)
		if err := s.replay(m, data); errors.Is(err, ErrConsistency) {
			return err
		}
	}
	// 2. heads
	known := verifierList(logVerifiers(s)...)
	err = l.eachHead(func(size int64) error {
		if size > m {
			return fmt.Errorf("%w: heads/%d.sig is beyond the %d entries that exist and decode", ErrConsistency, size, m)
		}
		h, err := l.readHead(size, known)
		if err != nil {
			return err
		}
		root, err := tlog.TreeHash(size, rd)
		if err != nil {
			return wrapConsistency(err)
		}
		if root != h.Hash {
			return fmt.Errorf("%w: the entries do not give the root hash of heads/%d.sig", ErrConsistency, size)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 3. a committed size above m
	if old, err := l.f.readTree(); err == nil && old.Size > m {
		return fmt.Errorf("%w: tree.rec names %d entries, only %d exist and decode", ErrConsistency, old.Size, m)
	}
	// 4. orphaned entries at m and beyond
	if err := l.f.orphans(m); err != nil {
		return err
	}
	// 5. tiles, keys, tree.rec
	for _, t := range tlog.NewTiles(TileHeight, 0, m) {
		data, err := tlog.ReadTileData(t, rd)
		if err != nil {
			return wrapConsistency(err)
		}
		p := l.f.path(TilePath(t))
		if old, err := store.ReadFileLimited(p, maxTileFile); err == nil && bytes.Equal(old, data) {
			continue
		}
		if err := store.MkdirAll(filepath.Dir(p)); err != nil {
			return logErr("tile", err)
		}
		if err := store.WriteFileAtomic(p, data); err != nil {
			return logErr("tile", err)
		}
	}
	for kid, r := range s.Valid {
		if err := l.f.writeKeyFileID(kid, r.Index); err != nil {
			return err
		}
	}
	t := treeState{Size: m}
	if m > 0 {
		if t.Hash, err = tlog.TreeHash(m, rd); err != nil {
			return wrapConsistency(err)
		}
	}
	return l.f.writeTree(t)
}

// eachHead calls fn with the size of every canonical heads/<size>.sig.
func (l *fileLog) eachHead(fn func(size int64) error) error {
	d, err := os.Open(l.f.path(HeadsDir))
	if err != nil {
		return logErr("heads", err)
	}
	defer d.Close()
	for {
		ents, err := d.ReadDir(headBatch)
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".sig")
			if !ok || !e.Type().IsRegular() {
				continue
			}
			n, perr := parseDecimal(name)
			if perr != nil || n < 1 || n > MaxTreeSize {
				continue
			}
			if err := fn(n); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return logErr("heads", err)
		}
	}
}

// orphans returns an *OrphanEntriesError when entries/ holds a file
// <i>.rec with a canonical decimal i >= m (RepairTree step 4), of any
// file type: refuse looks at the name only. Other names are no entries
// and are ignored. It only reads the directory.
func (f *files) orphans(m int64) error {
	d, err := os.Open(f.path(EntriesDir))
	if err != nil {
		return logErr("entries", err)
	}
	defer d.Close()
	o := &OrphanEntriesError{Size: m, First: -1}
	for {
		ents, err := d.ReadDir(headBatch)
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".rec")
			if !ok {
				continue
			}
			i, perr := parseDecimal(name)
			if perr != nil || i < m || i >= MaxTreeSize {
				continue
			}
			o.Count++
			if o.First < 0 || i < o.First {
				o.First = i
			}
			if i > o.Last {
				o.Last = i
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return logErr("entries", err)
		}
	}
	if o.Count > 0 {
		return o
	}
	return nil
}

// writeKeyFileID is writeKeyFile for a key given by its keyID.
func (f *files) writeKeyFileID(kid string, index int64) error {
	p := f.path(path.Join(KeysDir, kid))
	data := []byte(strconv.FormatInt(index, 10))
	if old, err := store.ReadFileLimited(p, maxKeyFile); err == nil && bytes.Equal(old, data) {
		return nil
	}
	if err := store.MkdirAll(filepath.Dir(p)); err != nil {
		return logErr("key file", err)
	}
	return logErr("key file", store.WriteFileAtomic(p, data))
}
