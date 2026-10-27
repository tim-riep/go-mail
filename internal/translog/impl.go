package translog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// crashHook lets tests interrupt Append after each of its writes
// ("entry", "tiles", "key", "tree"), as a crash would.
var crashHook func(step string) error

func hook(step string) error {
	if crashHook != nil {
		return crashHook(step)
	}
	return nil
}

// fileLog is the log on a data directory: a client log when v is set,
// an operator log otherwise (operatorLog).
type fileLog struct {
	mu   sync.Mutex
	st   *store.Store
	f    *files
	opts Options
	v    *Verifier
	ids  []Identity
	now  func() time.Time
	// ref is the client's audit index: the valid entries of the tree of
	// v.Last (doc.go "Audit").
	ref *state
	// cur is the state of the committed tree (log/tree.rec): the
	// reference of an operator log and what a client's Append checks
	// against. nil when it must be rebuilt.
	cur *state
	// ownErr is set when Refresh found an own Pending entry replaced in
	// a verified head that covers it (ErrConsistency, task 07b finding
	// 2): a head that passed CheckHead, or the reference head itself
	// (task 07c finding 2). The reference head stays the old one, so
	// Verifier.Fresh alone would not notice; CheckFresh and Refresh
	// report ownErr until a Refresh passes the Pending check against a
	// verified tree of at least ownSize, with or without a new head (the
	// caller has removed the entry from Verifier.Pending and appends it
	// again).
	ownErr error
	// ownSize is the size of the largest verified tree in which ownErr
	// was found.
	ownSize int64
	// rebuilt is the audit index that retry last rebuilt from the log.
	// When that very index contradicts the log again, the log itself is
	// inconsistent and retry does not rebuild once more. A rebuild that
	// failed does not set it (task 07c finding 3): the next call tries
	// again, for instance once the index file is writable again (ErrIO).
	rebuilt *state
	// signed is the last head SignHead returned (operator log, task 11),
	// without signatures; in memory only.
	signed *Head
	// seen is the largest committed tree this operator log has accepted
	// in this process (task 15c finding 2): a tree.rec below it, or of
	// its size with another root, or one that does not extend it, is
	// ErrConsistency (operatorCur). In memory only: a new process
	// starts from tree.rec, which "gomail-server log repair"
	// (RepairTree) restores.
	seen treeState
	// seenKeys are the log keys of the tree of seen (operator log). They
	// open the heads published before when the committed tree fails the
	// checks (logKeys): Head keeps serving the newest published head,
	// while every Check, Lookup and Append fails.
	seenKeys []LogKey
}

// operatorLog is the log of the server and the ceremony; SignHead and
// PublishHead are in operator.go (task 11).
type operatorLog struct{ *fileLog }

// Open opens (and on first use creates) the log in st (task 07). With
// Options.Verifier nil it returns an Operator.
//
// It creates log/ and its directories and, when log/tree.rec is missing
// and log/entries/ is empty, an empty tree.rec under log/lock; a missing
// tree.rec beside entries is ErrConsistency (repair is an operator
// action, doc.go "What write access to log/ gives an attacker"). The
// root hash recomputed from the tiles must equal tree.rec
// (ErrConsistency). An operator log then applies the validity rules to
// every committed entry (Options.Identities, ErrPin when missing or
// malformed). A client log checks its Verifier (CheckIdentities: ErrPin,
// CheckQuorum: ErrWitness, CheckOrigin: ErrHead), refuses an IndexFile
// inside the data directory, symbolic links resolved (ErrIO, indexPath),
// and loads or rebuilds its audit index.
func Open(opts Options) (Log, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("%w: no data directory", ErrConsistency)
	}
	l := &fileLog{st: opts.Store, f: &files{root: opts.Store.Root}, opts: opts, v: opts.Verifier, now: opts.Now}
	if l.v == nil {
		if len(opts.Identities) == 0 {
			return nil, fmt.Errorf("%w: an operator log needs the identity list of a pin", ErrPin)
		}
		if err := CheckIdentities(opts.Identities, opts.Identities[len(opts.Identities)-1]); err != nil {
			return nil, err
		}
		l.ids = opts.Identities
		if opts.Origin != "" {
			if err := checkOrigin(opts.Origin); err != nil {
				return nil, err
			}
		}
		if len(opts.Witnesses) > 0 || opts.MinWitnesses != 0 {
			if err := checkWitnessSet(opts.Witnesses, opts.MinWitnesses); err != nil {
				return nil, err
			}
		}
	} else {
		v := l.v
		if l.now == nil {
			l.now = v.Now
		}
		if l.now == nil {
			return nil, fmt.Errorf("%w: a client log needs a clock", ErrStale)
		}
		// Options.Now takes precedence and is the Verifier's clock as
		// well (task 07b finding 4): CheckHead needs one, and log and
		// Verifier must not judge times by different clocks.
		v.Now = l.now
		if err := v.checkConfig(); err != nil {
			return nil, err
		}
		if v.Last != nil && (v.Last.Size < 1 || v.Last.Size > MaxTreeSize) {
			return nil, fmt.Errorf("%w: last head size out of range", ErrHead)
		}
		if opts.IndexFile == "" {
			return nil, fmt.Errorf("%w: a client log needs an audit index file", ErrConsistency)
		}
		idx, err := indexPath(opts.IndexFile, l.st.Root)
		if err != nil {
			return nil, err
		}
		l.opts.IndexFile = idx
		l.ids = v.Identities
	}
	if err := l.create(); err != nil {
		return nil, err
	}
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	if tree.Size > 0 {
		if h, err := tlog.TreeHash(tree.Size, l.f.reader(tree)); err != nil || h != tree.Hash {
			return nil, fmt.Errorf("%w: the tiles do not match tree.rec", ErrConsistency)
		}
	}
	if l.v == nil {
		if _, err := l.getCur(tree); err != nil {
			return nil, err
		}
		return &operatorLog{l}, nil
	}
	if err := l.loadIndex(); err != nil {
		return nil, err
	}
	return l, nil
}

// indexPath returns the location of the audit index with every symbolic
// link of its directory resolved (task 07c finding 4), and refuses a
// location inside the data directory root (doc.go "Audit": the index is
// part of the client directory). The directory of the index must exist;
// the data directory is resolved as well, so that neither a link in the
// path of the index nor a data directory reached through a link hides
// that the index lies inside it. An index file that is itself a symbolic
// link is refused: reading would follow it. Every refusal is ErrIO (a
// file outside the tree that cannot be used, Options.IndexFile).
func indexPath(file, root string) (string, error) {
	idx, err := filepath.Abs(file)
	if err != nil {
		return "", fmt.Errorf("%w: audit index: %v", ErrIO, err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(idx))
	if err != nil {
		return "", fmt.Errorf("%w: directory of the audit index: %v", ErrIO, err)
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return "", fmt.Errorf("%w: directory of the audit index: %v", ErrIO, err)
	}
	idx = filepath.Join(dir, filepath.Base(idx))
	if fi, err := os.Lstat(idx); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: the audit index must not be a symbolic link", ErrIO)
	}
	data, err := filepath.Abs(root)
	if err == nil {
		data, err = filepath.EvalSymlinks(data)
	}
	if err != nil {
		return "", fmt.Errorf("%w: data directory: %v", ErrIO, err)
	}
	if rel, err := filepath.Rel(data, idx); err != nil || rel == "." || filepath.IsLocal(rel) {
		return "", fmt.Errorf("%w: the audit index must not be in the data directory", ErrIO)
	}
	return idx, nil
}

// create makes the directories of log/ and an empty tree.rec.
func (l *fileLog) create() error {
	for _, d := range []string{Dir, EntriesDir, TilesDir, HeadsDir, KeysDir} {
		if err := store.MkdirAll(l.f.path(d)); err != nil {
			return logErr(d, err)
		}
	}
	if ok, err := l.f.exists(TreeFile); err != nil || ok {
		return err
	}
	unlock, err := store.LockPath(l.f.path(LockFile))
	if err != nil {
		return fmt.Errorf("%w: log lock: %v", ErrConsistency, err)
	}
	defer unlock()
	if ok, err := l.f.exists(TreeFile); err != nil || ok {
		return err
	}
	ents, err := os.ReadDir(l.f.path(EntriesDir))
	if err != nil {
		return logErr("entries", err)
	}
	if len(ents) > 0 {
		return fmt.Errorf("%w: entries without tree.rec", ErrConsistency)
	}
	return l.f.writeTree(treeState{})
}

// sync brings s up to the committed tree: it checks that the tiles hold
// the tree of tree.rec and that the tree of s.Size is a prefix of it, and
// applies the entries beyond s, each checked against the leaf hash in the
// tiles.
//
// Task 07b finding 1: the size in tree.rec is not trusted before the
// tiles prove it. tlog.TreeHash reads one hash per level, so a tree.rec
// naming MaxTreeSize without the tiles fails here without any allocation
// of that size, and the leaf hashes are then read at most one tile
// (maxLeavesPerRead) at a time.
func (l *fileLog) sync(s *state, tree treeState) error {
	switch {
	case s.Size > tree.Size:
		return fmt.Errorf("%w: tree.rec is behind the verified log", ErrConsistency)
	case s.Size == tree.Size:
		if s.Root != tree.Hash {
			return fmt.Errorf("%w: tree.rec does not match the verified log", ErrConsistency)
		}
		return nil
	}
	rd := l.f.reader(tree)
	if h, err := tlog.TreeHash(tree.Size, rd); err != nil || h != tree.Hash {
		return fmt.Errorf("%w: the tiles do not match tree.rec", ErrConsistency)
	}
	if s.Size > 0 {
		if h, err := tlog.TreeHash(s.Size, rd); err != nil || h != s.Root {
			return fmt.Errorf("%w: the committed tree does not extend the verified log", ErrConsistency)
		}
	}
	for from := s.Size; from < tree.Size; {
		// Up to the end of the tile of from, so that every read is one
		// tile.
		to := min((from/maxLeavesPerRead+1)*maxLeavesPerRead, tree.Size)
		leaves, err := l.f.leaves(tree, from, to)
		if err != nil {
			return err
		}
		for i := from; i < to; i++ {
			data, err := l.f.readEntry(i)
			if err != nil {
				return fmt.Errorf("%w: committed entry %d: %v", ErrConsistency, i, err)
			}
			if LeafHash(data) != leaves[i-from] {
				return fmt.Errorf("%w: entry %d does not match the tree", ErrConsistency, i)
			}
			if err := s.replay(i, data); errors.Is(err, ErrConsistency) {
				return err
			}
		}
		from = to
	}
	s.Root = tree.Hash
	return nil
}

// getCur returns the state of the committed tree.
//
// Client log: a cached state that the committed tree no longer extends
// (tree.rec rolled back by one and another entry appended at the same
// index, doc.go "What write access to log/ gives an attacker") is
// discarded silently and rebuilt once from its base, the verified
// reference index, instead of failing the call once with ErrConsistency
// (task 11, addendum point 2): the client's checks answer from the
// reference index, not from this state. Only a state built in this very
// call that does not match the tree is ErrConsistency. An operator log
// answers its checks from this state and never rebuilds it silently
// (operatorCur, task 15c finding 2).
func (l *fileLog) getCur(tree treeState) (*state, error) {
	if l.v == nil {
		return l.operatorCur(tree)
	}
	base := func() *state {
		if l.ref != nil {
			return l.ref.clone()
		}
		return newState(l.f, l.ids)
	}
	fresh := false
	if l.cur == nil || (l.ref != nil && l.cur.Size < l.ref.Size) {
		l.cur, fresh = base(), true
	}
	err := l.sync(l.cur, tree)
	if err != nil && !fresh {
		l.cur = base()
		err = l.sync(l.cur, tree)
	}
	if err != nil {
		l.cur = nil
		return nil, err
	}
	return l.cur, nil
}

// operatorCur is getCur of an operator log (task 15c finding 2): it
// fails closed instead of rebuilding. The committed tree must extend the
// largest tree this process has accepted (seen): a smaller tree.rec, one
// of the same size with another root, or one whose prefix of that size
// has another root is ErrConsistency, and so is a cached state that the
// tree does not extend (sync); nothing is rebuilt from entry 0 then.
// Without this, a tree.rec rolled back while the server runs would be
// taken as the new reference: Lookup would no longer see the newer
// epochs of a mailbox (ingest.checkLogHead), and the server would
// encrypt for an older epoch again. Only a new process, after "gomail-
// server log repair" (RepairTree) where the files demand it, accepts
// the tree again (doc.go "Tasks", 15c). A state that was dropped for
// another reason (retry after errIndex, a failed write) is rebuilt from
// entry 0, but only into a tree that extends seen.
func (l *fileLog) operatorCur(tree treeState) (*state, error) {
	if seen := l.seen; seen.Size > 0 {
		switch {
		case tree.Size < seen.Size:
			l.cur = nil
			return nil, fmt.Errorf("%w: tree.rec names %d entries, this process saw %d (tree.rec rolled back?)", ErrConsistency, tree.Size, seen.Size)
		case tree.Size == seen.Size && tree.Hash != seen.Hash:
			l.cur = nil
			return nil, fmt.Errorf("%w: tree.rec holds another tree of the size this process saw (tree.rec rolled back?)", ErrConsistency)
		case tree.Size > seen.Size && l.cur == nil:
			if h, err := tlog.TreeHash(seen.Size, l.f.reader(tree)); err != nil || h != seen.Hash {
				return nil, fmt.Errorf("%w: the committed tree does not extend the tree this process saw", ErrConsistency)
			}
		}
	}
	if l.cur == nil {
		l.cur = newState(l.f, l.ids)
	}
	if err := l.sync(l.cur, tree); err != nil {
		l.cur = nil
		return nil, err
	}
	l.see(l.cur)
	return l.cur, nil
}

// see records the tree of the operator state s as seen (operatorCur).
func (l *fileLog) see(s *state) {
	if l.v != nil || s.Size < l.seen.Size || (s.Size == l.seen.Size && l.seenKeys != nil) {
		return
	}
	l.seen = treeState{Size: s.Size, Hash: s.Root}
	l.seenKeys = logKeysOf(s, s.Size)
}

// -------------------------------------------------------------- append

// prepare decodes content once and returns the entry and its encoding.
func prepare(kind Kind, content []byte) (*Entry, any, []byte, error) {
	k, obj, err := decodeContent(kind, content)
	if err != nil {
		return nil, nil, nil, err
	}
	e := &Entry{Key: k, Content: content, Index: -1}
	enc, err := rec.New(EntrySchema).SetU8(1, uint8(e.Kind)).SetBytes(2, e.Subject).SetI64(3, e.Seq).SetBytes(4, e.Content).Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	return e, obj, enc, nil
}

// Verified is true: the checks are backed by the log.
func (l *fileLog) Verified() bool { return true }

// Append logs a record (Log.Append).
func (l *fileLog) Append(kind Kind, content []byte) (int64, error) {
	e, obj, enc, err := prepare(kind, content)
	if err != nil {
		return -1, err
	}
	return l.appendEntry(e, obj, enc)
}

func (l *fileLog) appendChecked(kind Kind, content []byte, check func(Key) bool) error {
	e, obj, enc, err := prepare(kind, content)
	if err != nil {
		return err
	}
	if !check(e.Key) {
		return fmt.Errorf("%w: the record does not belong to the named subject", ErrEntry)
	}
	_, err = l.appendEntry(e, obj, enc)
	return err
}

// AppendUser is Append(KindUser, userRec) for the user named user.
func (l *fileLog) AppendUser(user store.ID, userRec []byte) error {
	return l.appendChecked(KindUser, userRec, func(k Key) bool { return bytes.Equal(k.Subject, user[:]) })
}

// AppendEpoch is Append(KindEpoch, epochRec) for epoch number of mailbox.
func (l *fileLog) AppendEpoch(mailbox store.ID, number uint32, epochRec []byte) error {
	return l.appendChecked(KindEpoch, epochRec, func(k Key) bool {
		return bytes.Equal(k.Subject, mailbox[:]) && k.Seq == int64(number)
	})
}

// AppendAddress is Append(KindAddress, addressRec).
func (l *fileLog) AppendAddress(addressRec []byte) error {
	return l.appendChecked(KindAddress, addressRec, func(Key) bool { return true })
}

// AppendPlatform is Append(KindPlatform, data) for the file name.
func (l *fileLog) AppendPlatform(name string, data []byte) error {
	return l.appendChecked(KindPlatform, data, func(k Key) bool { return string(k.Subject) == name })
}

func (l *fileLog) appendEntry(e *Entry, obj any, enc []byte) (int64, error) {
	leaf := LeafHash(enc)
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := store.LockPath(l.f.path(LockFile))
	if err != nil {
		return -1, fmt.Errorf("%w: log lock: %v", ErrConsistency, err)
	}
	defer unlock()
	index := int64(-1)
	err = l.retry(func() error {
		var err error
		index, err = l.appendLocked(e, obj, enc, leaf)
		return err
	})
	if err != nil {
		return -1, err
	}
	return index, nil
}

// appendLocked is Append under l.mu and log/lock.
func (l *fileLog) appendLocked(e *Entry, obj any, enc []byte, leaf tlog.Hash) (int64, error) {
	tree, err := l.f.readTree()
	if err != nil {
		return -1, err
	}
	if err := l.refuse(tree); err != nil {
		return -1, err
	}
	cur, err := l.getCur(tree)
	if err != nil {
		return -1, err
	}
	ch, err := cur.admit(e, obj, leaf)
	if errors.Is(err, errSame) {
		l.addPending(ch.same, leaf)
		return ch.same, nil
	}
	if err != nil {
		return -1, err
	}
	root, err := l.write(tree, e.Key, enc)
	if err != nil {
		ch.abort()
		l.cur = nil
		return -1, err
	}
	ch.commit(tree.Size)
	cur.Size, cur.Root = tree.Size+1, root
	l.see(cur)
	l.addPending(tree.Size, leaf)
	return tree.Size, nil
}

// refuse implements finding 03d-3: an entry beyond the next index or a
// head beyond the committed size means that tree.rec was rolled back or
// damaged; nothing is deleted.
func (l *fileLog) refuse(tree treeState) error {
	ok, err := l.f.exists(EntryPath(tree.Size + 1))
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("%w: an entry beyond the committed size exists (tree.rec rolled back?)", ErrConsistency)
	}
	newest, err := l.f.newestHeadSize()
	if err != nil {
		return err
	}
	if newest > tree.Size {
		return fmt.Errorf("%w: a head beyond the committed size exists (tree.rec rolled back?)", ErrConsistency)
	}
	return nil
}

// removeLeftovers removes what an interrupted append left at index n:
// the entry, its key file and the tiles of tlog.NewTiles(8, n, n+1).
func (l *fileLog) removeLeftovers(n int64) error {
	if data, err := l.f.readEntry(n); err == nil {
		if e, err := DecodeEntry(data, n); err == nil && l.f.readKeyFile(e.Key) == n {
			if err := store.RemoveDurable(l.f.path(KeyPath(e.Key))); err != nil {
				return logErr("leftover key file", err)
			}
		}
	}
	if err := store.RemoveDurable(l.f.path(EntryPath(n))); err != nil {
		return logErr("leftover entry", err)
	}
	for _, t := range tlog.NewTiles(TileHeight, n, n+1) {
		if err := store.RemoveDurable(l.f.path(TilePath(t))); err != nil {
			return logErr("leftover tile", err)
		}
	}
	return nil
}

// write appends the encoded entry at index tree.Size: entry, tiles, key
// file and then tree.rec, the commit point. It returns the new root.
func (l *fileLog) write(tree treeState, k Key, enc []byte) (tlog.Hash, error) {
	n := tree.Size
	if n >= MaxTreeSize {
		return tlog.Hash{}, fmt.Errorf("%w: the log is full", ErrConsistency)
	}
	if err := l.removeLeftovers(n); err != nil {
		return tlog.Hash{}, err
	}
	if err := store.CreateFileAtomic(l.f.path(EntryPath(n)), enc); err != nil {
		return tlog.Hash{}, logErr("entry", err)
	}
	if err := hook("entry"); err != nil {
		return tlog.Hash{}, err
	}
	old := l.f.reader(tree)
	hashes, err := tlog.StoredHashes(n, enc, old)
	if err != nil {
		return tlog.Hash{}, wrapConsistency(err)
	}
	comb := combReader(old, tlog.StoredHashCount(n), &hashes)
	for _, t := range tlog.NewTiles(TileHeight, n, n+1) {
		data, err := tlog.ReadTileData(t, comb)
		if err != nil {
			return tlog.Hash{}, wrapConsistency(err)
		}
		if err := l.f.createOrSame(TilePath(t), data, maxTileFile); err != nil {
			return tlog.Hash{}, err
		}
	}
	if err := hook("tiles"); err != nil {
		return tlog.Hash{}, err
	}
	if err := l.f.writeKeyFile(k, n); err != nil {
		return tlog.Hash{}, err
	}
	if err := hook("key"); err != nil {
		return tlog.Hash{}, err
	}
	root, err := tlog.TreeHash(n+1, comb)
	if err != nil {
		return tlog.Hash{}, wrapConsistency(err)
	}
	if err := l.f.writeTree(treeState{Size: n + 1, Hash: root}); err != nil {
		return tlog.Hash{}, err
	}
	if err := hook("tree"); err != nil {
		return tlog.Hash{}, err
	}
	return root, nil
}

// combReader reads the stored hashes below base from old and those from
// base on from *hashes (computed in memory, in index order).
func combReader(old tlog.HashReader, base int64, hashes *[]tlog.Hash) tlog.HashReader {
	return tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		var olds []int64
		var pos []int
		for i, x := range idx {
			switch {
			case x >= base && x-base < int64(len(*hashes)):
				out[i] = (*hashes)[x-base]
			case x >= 0 && x < base:
				olds = append(olds, x)
				pos = append(pos, i)
			default:
				return nil, fmt.Errorf("%w: hash index out of range", ErrConsistency)
			}
		}
		if len(olds) > 0 {
			hs, err := old.ReadHashes(olds)
			if err != nil {
				return nil, err
			}
			for j, p := range pos {
				out[p] = hs[j]
			}
		}
		return out, nil
	})
}

// wrapConsistency wraps a foreign error (of tlog) with ErrConsistency and
// returns an error of this package unchanged, so that every error wraps
// exactly one documented error and its text carries one prefix (task 11,
// addendum point 3).
func wrapConsistency(err error) error {
	if err == nil || isPkgErr(err) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrConsistency, err)
}

// addPending remembers an own append that the reference head does not
// cover yet (doc.go "Withheld entries").
func (l *fileLog) addPending(index int64, leaf tlog.Hash) {
	v := l.v
	if v == nil || (v.Last != nil && index < v.Last.Size) {
		return
	}
	for _, p := range v.Pending {
		if p.Index == index {
			return
		}
	}
	v.Pending = append(v.Pending, Pending{Index: index, Leaf: leaf, At: l.now().UnixMilli()})
}

// ------------------------------------------------------------- reading

// view returns the state the Check methods answer from: the audit index
// of a client, the committed tree of an operator. An operator log first
// refuses a committed tree that an entry beyond the next index or a
// published head beyond its size shows to be rolled back (refuse, task
// 15c finding 2), so that Lookup and every Check fail closed like Append
// and SignHead; operatorCur refuses a tree smaller than the one this
// process saw.
func (l *fileLog) view() (*state, error) {
	if l.v != nil {
		return l.ref, nil
	}
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	if err := l.refuse(tree); err != nil {
		return nil, err
	}
	return l.getCur(tree)
}

// lastTree is the tree of the client's reference head.
func (l *fileLog) lastTree() (treeState, error) {
	if l.v.Last == nil {
		return treeState{}, fmt.Errorf("%w: no verified head", ErrStale)
	}
	return treeState{Size: l.v.Last.Size, Hash: l.v.Last.Hash}, nil
}

// included reads the valid entry r, which the state holds under key k,
// and proves it: for a client with an inclusion proof against the
// reference head (Verifier.CheckInclusion), for an operator against the
// leaf recorded from the tiles. An entry that the log proves but that
// does not carry the leaf or the key the state recorded for it is a
// contradiction of the state itself (errIndex, task 07b finding 5): the
// client then rebuilds its audit index (retry).
func (l *fileLog) included(r ref, k Key) (*Entry, any, error) {
	if l.v == nil {
		e, obj, _, err := l.f.readEntryLeaf(r.Index, r.Leaf)
		if err != nil {
			return nil, nil, err
		}
		if !e.Key.Equal(k) {
			return nil, nil, fmt.Errorf("%w: entry %d holds another key", errIndex, r.Index)
		}
		return e, obj, nil
	}
	t, err := l.lastTree()
	if err != nil {
		return nil, nil, err
	}
	data, err := l.f.readEntry(r.Index)
	if err != nil {
		if errors.Is(err, ErrNotInLog) {
			return nil, nil, fmt.Errorf("%w: entry %d of the reference tree is missing", ErrConsistency, r.Index)
		}
		return nil, nil, err
	}
	proof, err := tlog.ProveRecord(t.Size, r.Index, l.f.reader(t))
	if err != nil {
		return nil, nil, wrapConsistency(err)
	}
	if err := l.v.CheckInclusion(r.Index, data, proof); err != nil {
		return nil, nil, err
	}
	// data is record r.Index of the reference tree; what follows checks
	// the audit index against it.
	if LeafHash(data) != r.Leaf {
		return nil, nil, fmt.Errorf("%w: leaf of entry %d", errIndex, r.Index)
	}
	e, obj, err := decodeEntry(data, r.Index)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: entry %d is not a valid entry", errIndex, r.Index)
	}
	if !e.Key.Equal(k) {
		return nil, nil, fmt.Errorf("%w: entry %d holds another key", errIndex, r.Index)
	}
	return e, obj, nil
}

// notFound is the error for a key without a valid entry in the
// reference tree: ErrPending when a client finds it in the committed
// tree beyond its head (keys/ only decides between two errors that
// both fail closed), ErrNotInLog otherwise.
func (l *fileLog) notFound(k Key) error {
	if l.v != nil {
		if idx := l.f.readKeyFile(k); idx >= l.ref.Size {
			if tree, err := l.f.readTree(); err == nil && idx < tree.Size {
				return fmt.Errorf("%w: entry %d", ErrPending, idx)
			}
		}
	}
	return fmt.Errorf("%w: no valid entry with this key", ErrNotInLog)
}

// find returns the valid entry with key k, which must have exactly the
// encoding leaf when leaf is set (ErrMismatch otherwise). The entry is
// read and proven first (included), so that ErrMismatch rests on the
// log, not on the audit index alone.
func (l *fileLog) find(s *state, k Key, leaf *tlog.Hash) (ref, *Entry, any, error) {
	r, ok := s.Valid[keyID(k)]
	if !ok {
		return ref{}, nil, nil, l.notFound(k)
	}
	e, obj, err := l.included(r, k)
	if err != nil {
		return ref{}, nil, nil, err
	}
	if leaf != nil && r.Leaf != *leaf {
		return ref{}, nil, nil, fmt.Errorf("%w: the log holds other content under this key", ErrMismatch)
	}
	return r, e, obj, nil
}

// retry runs op and, when it failed because the state contradicts the
// log (errIndex, task 07b finding 5), discards the state and runs op
// once more: a client rebuilds its audit index from entry 0 against the
// reference head, as for a damaged index file. An index that retry has
// just rebuilt is not rebuilt again: if it contradicts the log as well,
// the log itself is inconsistent and the error is returned. An operator
// rebuilds its state from the committed tree (getCur), which reads and
// checks every entry against the tiles.
func (l *fileLog) retry(op func() error) error {
	err := op()
	if !errors.Is(err, errIndex) {
		return err
	}
	if l.v == nil {
		l.cur = nil
		return op()
	}
	if l.ref == l.rebuilt {
		return err
	}
	// rebuilt is set only once the rebuild has succeeded (task 07c
	// finding 3): a rebuild that failed, for ErrIO of the index file or
	// for ErrConsistency of the log, leaves the contradicting index as the
	// reference, so every Check keeps failing and the next one tries the
	// rebuild again.
	if err := l.buildIndex(); err != nil {
		return err
	}
	l.rebuilt = l.ref
	return op()
}

// checkRecord looks up a record by its derived key with exactly its
// content.
func (l *fileLog) checkRecord(kind Kind, content []byte, check func(Key) bool) (*state, *Entry, any, ref, error) {
	e, obj, enc, err := prepare(kind, content)
	if err != nil {
		return nil, nil, nil, ref{}, err
	}
	if !check(e.Key) {
		return nil, nil, nil, ref{}, fmt.Errorf("%w: the record does not belong to the named subject", ErrEntry)
	}
	s, err := l.view()
	if err != nil {
		return nil, nil, nil, ref{}, err
	}
	leaf := LeafHash(enc)
	r, _, _, err := l.find(s, e.Key, &leaf)
	return s, e, obj, r, err
}

// CheckUser (Log.CheckUser).
func (l *fileLog) CheckUser(user store.ID, userRec []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retry(func() error {
		s, e, _, _, err := l.checkRecord(KindUser, userRec, func(k Key) bool { return bytes.Equal(k.Subject, user[:]) })
		if err != nil {
			return err
		}
		if us := s.Users[user.String()]; us != nil && int64(len(us.Idents)) > e.Seq {
			return fmt.Errorf("%w: user entry with %d generations", ErrSuperseded, len(us.Idents))
		}
		return nil
	})
}

// CheckGeneration (Log.CheckGeneration).
func (l *fileLog) CheckGeneration(user store.ID, gen uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if gen == 0 {
		return fmt.Errorf("%w: generation 0", ErrNotInLog)
	}
	return l.retry(func() error {
		s, err := l.view()
		if err != nil {
			return err
		}
		_, _, _, err = l.find(s, Key{Kind: KindUser, Subject: user[:], Seq: int64(gen)}, nil)
		return err
	})
}

// CheckRevokedSignature (Log.CheckRevokedSignature).
func (l *fileLog) CheckRevokedSignature(user store.ID, gen uint32, signed []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if gen == 0 {
		return fmt.Errorf("%w: generation 0", ErrNotInLog)
	}
	kind, err := KindOf(signed)
	if err != nil {
		return err
	}
	return l.retry(func() error {
		s, _, _, r, err := l.checkRecord(kind, signed, func(Key) bool { return true })
		if err != nil {
			return err
		}
		if uint64(gen)+1 > 1<<32-1 {
			return nil
		}
		rk := Key{Kind: KindUser, Subject: user[:], Seq: int64(gen) + 1}
		rv, ok := s.Valid[keyID(rk)]
		if !ok {
			return nil
		}
		if _, _, err := l.included(rv, rk); err != nil {
			return err
		}
		if r.Index >= rv.Index {
			return fmt.Errorf("%w: logged after the revocation of the generation", ErrOrder)
		}
		return nil
	})
}

// CheckEpoch (Log.CheckEpoch).
func (l *fileLog) CheckEpoch(mailbox store.ID, number uint32, epochRec []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retry(func() error {
		_, _, _, _, err := l.checkRecord(KindEpoch, epochRec, func(k Key) bool {
			return bytes.Equal(k.Subject, mailbox[:]) && k.Seq == int64(number)
		})
		return err
	})
}

// CheckAddress (Log.CheckAddress). TODO(Q9): the newest valid_from <= at
// decides, without an upper bound (doc.go "Address assignments").
func (l *fileLog) CheckAddress(address string, mailbox store.ID, at int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, err := store.NormalizeAddress(address)
	if err != nil || a != address {
		return fmt.Errorf("%w: address not normalized", ErrEntry)
	}
	return l.retry(func() error {
		s, err := l.view()
		if err != nil {
			return err
		}
		list := s.Addresses[subjectID(KindAddress, []byte(a))]
		i := len(list) - 1
		for i >= 0 && list[i].ValidFrom > at {
			i--
		}
		if i < 0 {
			return fmt.Errorf("%w: no assignment of the address at that time", ErrNotInLog)
		}
		_, _, obj, err := l.find(s, Key{Kind: KindAddress, Subject: []byte(a), Seq: list[i].ValidFrom}, nil)
		if err != nil {
			return err
		}
		as, ok := obj.(*store.AddressAssignment)
		if !ok {
			return fmt.Errorf("%w: entry is no address assignment", errIndex)
		}
		if as.MailboxID != mailbox {
			return fmt.Errorf("%w: the address is assigned to another mailbox", ErrMismatch)
		}
		return nil
	})
}

// CheckPlatform (Log.CheckPlatform).
func (l *fileLog) CheckPlatform(name string, data []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if hasType(data, keys.PlatformSuccessionSchema) {
		if sc, err := keys.DecodePlatformSuccession(data); err == nil {
			if k, ok := IdentityKey(l.ids, sc.Gen); ok && !k.Equal(sc.Pub) {
				return fmt.Errorf("%w: succession %d names another key than the pin", ErrMismatch, sc.Gen)
			}
		}
	}
	return l.retry(func() error {
		_, _, _, _, err := l.checkRecord(KindPlatform, data, func(k Key) bool { return string(k.Subject) == name })
		return err
	})
}

// CheckFresh (Log.CheckFresh). A client log also reports an own entry
// that a verified head replaced (ownErr, task 07b finding 2) until a
// Refresh passes the Pending check again (task 07c finding 2).
func (l *fileLog) CheckFresh(now time.Time) error {
	if l.v == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ownErr != nil {
		return l.ownErr
	}
	return l.v.Fresh(now)
}

// Lookup (Log.Lookup).
func (l *fileLog) Lookup(kind Kind, subject []byte) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Entry
	err := l.retry(func() error {
		out = nil
		s, err := l.view()
		if err != nil {
			return err
		}
		for _, r := range s.subjects[subjectID(kind, subject)] {
			e, _, err := l.included(r, Key{Kind: kind, Subject: subject, Seq: r.Seq})
			if err != nil {
				return err
			}
			out = append(out, *e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Entry (Log.Entry). A missing file below the reference size (client)
// or the committed size (operator) is ErrConsistency, not ErrNotInLog:
// the tree holds the entry, the files lost it (task 07b finding 6).
func (l *fileLog) Entry(index int64) (*Entry, error) {
	if index < 0 || index >= MaxTreeSize {
		return nil, fmt.Errorf("%w: index out of range", ErrNotInLog)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	read := func() ([]byte, error) {
		data, err := l.f.readEntry(index)
		if errors.Is(err, ErrNotInLog) {
			return nil, fmt.Errorf("%w: entry %d of the tree is missing", ErrConsistency, index)
		}
		return data, err
	}
	var data []byte
	if l.v != nil {
		if l.v.Last == nil || index >= l.v.Last.Size {
			if index < tree.Size {
				return nil, fmt.Errorf("%w: entry %d", ErrPending, index)
			}
			return nil, fmt.Errorf("%w: entry %d", ErrNotInLog, index)
		}
		t, _ := l.lastTree()
		if data, err = read(); err != nil {
			return nil, err
		}
		proof, err := tlog.ProveRecord(t.Size, index, l.f.reader(t))
		if err != nil {
			return nil, wrapConsistency(err)
		}
		if err := l.v.CheckInclusion(index, data, proof); err != nil {
			return nil, err
		}
	} else {
		if index >= tree.Size {
			return nil, fmt.Errorf("%w: entry %d", ErrNotInLog, index)
		}
		if data, err = read(); err != nil {
			return nil, err
		}
		lv, err := l.f.leaves(tree, index, index+1)
		if err != nil {
			return nil, err
		}
		if LeafHash(data) != lv[0] {
			return nil, fmt.Errorf("%w: entry %d does not match the tree", ErrConsistency, index)
		}
	}
	e, err := DecodeEntry(data, index)
	if err != nil {
		// The tree holds this encoding: it is no valid entry, an entry
		// written past Append (doc.go "Validity rules").
		return nil, err
	}
	return e, nil
}

// InclusionProof (Log.InclusionProof) over the committed tree.
func (l *fileLog) InclusionProof(index, size int64) (tlog.RecordProof, error) {
	if index < 0 || index >= size || size > MaxTreeSize {
		return nil, fmt.Errorf("%w: record index or tree size out of range", ErrConsistency)
	}
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	if size > tree.Size {
		return nil, fmt.Errorf("%w: tree size beyond the committed size", ErrNotInLog)
	}
	p, err := tlog.ProveRecord(size, index, l.f.reader(tree))
	if err != nil {
		return nil, wrapConsistency(err)
	}
	return p, nil
}

// ConsistencyProof (Log.ConsistencyProof) over the committed tree.
func (l *fileLog) ConsistencyProof(from, to int64) (tlog.TreeProof, error) {
	if from < 1 || from > to || to > MaxTreeSize {
		return nil, fmt.Errorf("%w: tree sizes out of range", ErrConsistency)
	}
	tree, err := l.f.readTree()
	if err != nil {
		return nil, err
	}
	if to > tree.Size {
		return nil, fmt.Errorf("%w: tree size beyond the committed size", ErrNotInLog)
	}
	p, err := tlog.ProveTree(to, from, l.f.reader(tree))
	if err != nil {
		return nil, wrapConsistency(err)
	}
	return p, nil
}

// --------------------------------------------------------------- heads

// verifierSet is the note.Verifiers of a list, falling back to next.
type verifierSet struct {
	list []note.Verifier
	next note.Verifiers
}

func (vs *verifierSet) Verifier(name string, hash uint32) (note.Verifier, error) {
	for _, v := range vs.list {
		if v != nil && v.Name() == name && v.KeyHash() == hash {
			return v, nil
		}
	}
	if vs.next != nil {
		return vs.next.Verifier(name, hash)
	}
	return nil, &note.UnknownVerifierError{Name: name, KeyHash: hash}
}

// known returns the verifiers that open heads/<n>.sig: Options.Known
// (for a client without Known: the pinned witnesses; for an operator
// also Options.Witnesses, so that the lines of witnesses.rec survive
// operatorHead) and the log keys.
func (l *fileLog) known(logKeys []LogKey) note.Verifiers {
	vs := &verifierSet{next: l.opts.Known}
	for _, k := range logKeys {
		vs.list = append(vs.list, k.Verifier)
	}
	if l.v != nil && l.opts.Known == nil {
		vs.list = append(vs.list, l.v.Witnesses...)
	}
	if l.v == nil {
		vs.list = append(vs.list, l.opts.Witnesses...)
	}
	return vs
}

func (l *fileLog) openHead(size int64, known note.Verifiers) (*Head, error) {
	msg, err := store.ReadFileLimited(l.f.path(HeadPath(size)), MaxHeadNote)
	if err != nil {
		return nil, fmt.Errorf("%w: heads/%d.sig: %v", ErrHead, size, err)
	}
	h, err := OpenHead(msg, known)
	if err != nil {
		return nil, err
	}
	if h.Size != size {
		return nil, fmt.Errorf("%w: heads/%d.sig holds a head of another size", ErrHead, size)
	}
	return h, nil
}

// Head (Log.Head). An operator log opens the head line by line and
// returns a note of only the lines that verified (operatorHead).
func (l *fileLog) Head() (*Head, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.newestHead(l.logKeys())
}

// logKeys returns the log keys that open heads: for a client
// Verifier.LogKeys (as of the last Refresh), for an operator those of the
// valid ingest certificates of the committed tree (task 11), so that the
// server needs no log key in Options.Known.
func (l *fileLog) logKeys() []LogKey {
	if l.v == nil {
		s, err := l.view()
		if err != nil {
			// The committed tree fails the checks (task 15c finding 2):
			// the heads published before still open with the keys of the
			// last tree this process accepted, so that the server keeps
			// serving them to its witnesses; nothing is checked against
			// them.
			return l.seenKeys
		}
		return logKeysOf(s, s.Size)
	}
	return l.v.LogKeys
}

func (l *fileLog) newestHead(logKeys []LogKey) (*Head, error) {
	size, err := l.f.newestHeadSize()
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: no published head", ErrStale)
	}
	if l.v == nil {
		// Operator: line by line (task 11b finding 5).
		return l.operatorHead(size, l.known(logKeys))
	}
	return l.openHead(size, l.known(logKeys))
}

// candidate is a LogKey with the certified key it came from.
type candidate struct {
	key LogKey
	pub ed25519.PublicKey
}

// candidates builds the log keys of doc.go "Platform generations" (task
// 03d finding 1): every ingest certificate in platform/ that verifies
// against the pinned identity list, or against a generation above it
// named by a succession (logged, or from platform/ in a chain from the
// list), logged or not; and every valid ingest certificate of s, the
// state of the tree of the head being opened.
func (l *fileLog) candidates(s *state) []candidate {
	idk := map[uint32]ed25519.PublicKey{}
	for _, id := range l.ids {
		idk[id.Gen] = id.Pub
	}
	// Generations above the pinned list: at most MaxIdentities of them
	// (task 11, addendum point 4: an explicit bound instead of one that
	// rests on the successions running out).
	for n, g := 0, uint32(len(l.ids))+1; n < MaxIdentities && g > 1; n, g = n+1, g+1 {
		if sc := s.Succs[g]; sc != nil {
			idk[g] = sc.Pub
			continue
		}
		data, err := l.st.ReadPlatformFile(succName(g))
		if err != nil {
			break
		}
		sc, err := keys.DecodePlatformSuccession(data)
		if err != nil || sc.Gen != g || sc.Verify(idk[g-1], g-1) != nil {
			break
		}
		idk[g] = sc.Pub
	}
	var out []candidate
	add := func(gen uint32, pub ed25519.PublicKey, validFrom int64) {
		for _, c := range out {
			if c.key.Gen == gen && c.pub.Equal(pub) && c.key.ValidFrom == validFrom {
				return
			}
		}
		v, err := NewLogVerifier(pub)
		if err != nil {
			return
		}
		out = append(out, candidate{key: LogKey{Gen: gen, Verifier: v, ValidFrom: validFrom}, pub: pub})
	}
	if ents, err := os.ReadDir(l.st.Path("platform")); err == nil {
		for _, de := range ents {
			g, ok := parseGenName(de.Name(), "ingest-", ".cert")
			if !ok {
				continue
			}
			data, err := l.st.ReadPlatformFile(de.Name())
			if err != nil {
				continue
			}
			c, err := keys.DecodePlatformCert(data)
			if err != nil || c.Role != keys.RoleIngest || c.Gen != g || idk[c.IdentityGen] == nil || c.Verify(idk[c.IdentityGen]) != nil {
				continue
			}
			add(c.Gen, c.Pub, c.ValidFrom)
		}
	}
	for _, c := range s.Certs {
		if c.Role == uint8(keys.RoleIngest) {
			add(c.Gen, ed25519.PublicKey(c.Pub), c.ValidFrom)
		}
	}
	return out
}

// mergeCandidates returns a with every candidate of b that a lacks.
func mergeCandidates(a, b []candidate) []candidate {
	out := append([]candidate(nil), a...)
	for _, c := range b {
		dup := false
		for _, o := range a {
			if o.key.Gen == c.key.Gen && o.pub.Equal(c.pub) && o.key.ValidFrom == c.key.ValidFrom {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// judge sets Logged and Until of every candidate from the state s of
// the tree of the head being checked (doc.go "Platform generations").
// A certificate logged in an earlier tree stays logged: s extends it.
func judge(s *state, cands []candidate) []LogKey {
	out := make([]LogKey, 0, len(cands))
	for _, c := range cands {
		k := c.key
		lc := s.Certs[certName(keys.RoleIngest, k.Gen)]
		k.Logged = lc != nil && bytes.Equal(lc.Pub, c.pub) && lc.ValidFrom == k.ValidFrom
		k.Until = 0
		if next := s.Certs[certName(keys.RoleIngest, k.Gen+1)]; next != nil && k.Gen < 1<<32-1 {
			k.Until = next.ValidFrom
			if k.Until == 0 {
				k.Until = -1 // valid_from 0: generation Gen covers nothing
			}
		}
		out = append(out, k)
	}
	return out
}

// audit applies the entries from s.Size to h.Size-1 to s, each proven
// with an inclusion proof against h (doc.go "Audit").
func (l *fileLog) audit(s *state, h *Head) error {
	t := treeState{Size: h.Size, Hash: h.Hash}
	rd := l.f.reader(t)
	for i := s.Size; i < h.Size; i++ {
		data, err := l.f.readEntry(i)
		if err != nil {
			if errors.Is(err, ErrNotInLog) {
				return fmt.Errorf("%w: entry %d of the head is missing", ErrConsistency, i)
			}
			// readEntry wraps every other failure with ErrConsistency
			// itself (task 11, addendum point 3: one prefix).
			return err
		}
		proof, err := tlog.ProveRecord(h.Size, i, rd)
		if err != nil {
			return wrapConsistency(err)
		}
		if err := CheckRecordProof(proof, h.Size, h.Hash, i, LeafHash(data)); err != nil {
			return err
		}
		if err := s.replay(i, data); errors.Is(err, ErrConsistency) {
			return err
		}
	}
	s.Root = h.Hash
	return nil
}

// Refresh (Log.Refresh).
//
// Task 07b finding 2, order fixed by task 07c finding 2: nothing of the
// client's state changes before every step has succeeded. In this order:
// open the newest head; audit the entries it adds on a copy of the audit
// index; judge the head with CheckHead on a copy of the Verifier; check
// every Pending entry the head covers against its leaf in the tree of
// the head; write the audit index. Only then are Verifier.Last,
// Verifier.LogKeys, the reference index and Verifier.Pending (without
// the checked entries) taken over. On any failure Last, LogKeys,
// Pending, the reference index and the index file stay as they were, so
// the next Refresh audits the same entries again. A head that CheckHead
// refuses is never used for the Pending check: its verdict (ErrWitness,
// ErrHead, ErrConsistency) is returned and ownErr stays as it was. The
// freshness rules (ErrWithheld, ErrStale) apply after the new head is
// taken over: they judge the new reference head.
func (l *fileLog) Refresh(now time.Time) (*Head, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.v == nil {
		return l.newestHead(l.logKeys())
	}
	err := l.retry(func() error { return l.refresh(now) })
	return l.v.Last, err
}

func (l *fileLog) refresh(now time.Time) error {
	v := l.v
	// The keys that open the head come from platform/ and the old
	// reference tree; the head is judged with the keys of its own tree.
	cands := l.candidates(l.ref)
	all := make([]LogKey, len(cands))
	for i, c := range cands {
		all[i] = c.key
	}
	size, err := l.f.newestHeadSize()
	if err != nil {
		return err
	}
	if size == 0 {
		if v.Last == nil {
			return fmt.Errorf("%w: no published head", ErrStale)
		}
		keep, err := l.checkCovered(treeState{Size: v.Last.Size, Hash: v.Last.Hash})
		if err != nil {
			return err
		}
		if l.ownErr != nil {
			// Not resolved by the smaller reference tree: nothing changes
			// (task 11, addendum point 1).
			return l.ownErr
		}
		v.Pending = keep
		return l.fresh(now)
	}
	h, err := l.openHead(size, l.known(all))
	if err != nil {
		return err
	}
	if v.Last != nil && h.Size < v.Last.Size {
		return l.olderHead(h, cands, now)
	}
	ns := l.ref
	var proof tlog.TreeProof
	if v.Last == nil || h.Size > v.Last.Size {
		ns = l.ref.clone()
		if err := l.audit(ns, h); err != nil {
			return err
		}
		if v.Last != nil {
			if proof, err = tlog.ProveTree(h.Size, v.Last.Size, l.f.reader(treeState{Size: h.Size, Hash: h.Hash})); err != nil {
				return wrapConsistency(err)
			}
		}
		cands = mergeCandidates(cands, l.candidates(ns))
	}
	vc := *v
	vc.LogKeys = judge(ns, cands)
	if err := vc.CheckHead(h, proof); err != nil {
		return err
	}
	// Only a head that passed CheckHead is used for the Pending check
	// (task 07c finding 2).
	keep, err := l.checkCovered(treeState{Size: h.Size, Hash: h.Hash})
	if err != nil {
		return err
	}
	if l.ownErr != nil {
		// Task 11, addendum point 1 (strictest reading): while an own
		// entry found replaced in a larger verified tree is unresolved, a
		// head that passed CheckHead and the Pending check is not taken
		// over either: Last, LogKeys, Pending and the audit index stay.
		return l.ownErr
	}
	if ns != l.ref {
		if err := l.saveIndex(ns); err != nil {
			return err
		}
	}
	v.Last, v.LogKeys, v.Pending = vc.Last, vc.LogKeys, keep
	l.ref = ns
	return l.fresh(now)
}

// olderHead handles a newest published head h smaller than the reference
// head (task 14b point 2, ErrOlderHead): h is judged with
// Verifier.CheckOlderHead against the reference head, with the log keys
// judged in the reference tree and the consistency proof from h to the
// reference head over the tiles of the reference tree. A head that fails
// returns that error (ErrConsistency for a contradiction, the errors of
// CheckHead otherwise) and nothing changes. A head that passes is not
// taken over; the Pending entries are checked against the reference head
// and the freshness rules applied as without a published head, and only
// when they pass is the result ErrOlderHead.
//
// Reading: the log keys are judged in the reference tree, which extends
// the tree of h. A generation whose successor certificate entered the
// log after h may then not cover the time of h any more and h fails
// with ErrHead; that is a warning for the caller as well, not a verdict
// on the log.
func (l *fileLog) olderHead(h *Head, cands []candidate, now time.Time) error {
	v := l.v
	last := treeState{Size: v.Last.Size, Hash: v.Last.Hash}
	proof, err := tlog.ProveTree(last.Size, h.Size, l.f.reader(last))
	if err != nil {
		return wrapConsistency(err)
	}
	vc := *v
	vc.LogKeys = judge(l.ref, cands)
	if err := vc.CheckOlderHead(h, proof); err != nil {
		return err
	}
	keep, err := l.checkCovered(last)
	if err != nil {
		return err
	}
	if l.ownErr != nil {
		return l.ownErr
	}
	v.Pending = keep
	if err := l.fresh(now); err != nil {
		return err
	}
	return fmt.Errorf("%w: newest published head %d, reference head %d", ErrOlderHead, h.Size, last.Size)
}

// checkCovered checks every Pending entry that the tree t covers against
// its leaf (record proof for its index, doc.go "Withheld entries") and
// returns the entries t does not cover. t is always a verified tree: a
// head that passed CheckHead, or the reference head (task 07c finding
// 2). A covered entry with another leaf is ErrConsistency: the log does
// not hold the own entry as it was appended. That error is kept in
// ownErr (CheckFresh, Refresh) with the size of t. ownErr is cleared
// once the check passes against a verified tree of at least that size,
// whether or not the head is new: the caller has removed the entry from
// Verifier.Pending (and appends it again, doc.go "Withheld entries").
// A check against a smaller tree, which may not cover the index that
// failed, does not clear it.
func (l *fileLog) checkCovered(t treeState) ([]Pending, error) {
	var keep []Pending
	var rd tlog.HashReader
	for _, p := range l.v.Pending {
		if p.Index >= t.Size {
			keep = append(keep, p)
			continue
		}
		if rd == nil {
			rd = l.f.reader(t)
		}
		err := fmt.Errorf("%w: own entry %d is not in the log as appended", ErrConsistency, p.Index)
		if p.Index >= 0 {
			if proof, perr := tlog.ProveRecord(t.Size, p.Index, rd); perr != nil {
				err = fmt.Errorf("%w: own entry %d: %v", ErrConsistency, p.Index, perr)
			} else if CheckRecordProof(proof, t.Size, t.Hash, p.Index, p.Leaf) == nil {
				continue
			}
		}
		l.ownErr, l.ownSize = err, max(l.ownSize, t.Size)
		return nil, err
	}
	if l.ownErr != nil && t.Size >= l.ownSize {
		l.ownErr, l.ownSize = nil, 0
	}
	return keep, nil
}

// fresh applies the rules of doc.go "Withheld entries" to the Pending
// entries the reference head does not cover (Verifier.Fresh), after an
// own entry found replaced (ownErr).
func (l *fileLog) fresh(now time.Time) error {
	if l.ownErr != nil {
		return l.ownErr
	}
	if len(l.v.Pending) == 0 {
		return nil
	}
	return l.v.Fresh(now)
}

// ---------------------------------------------------------- audit index

// loadIndex reads the audit index or rebuilds it from entry 0 against
// Verifier.Last.
func (l *fileLog) loadIndex() error {
	anchor := anchorHash(l.ids)
	if data, err := store.ReadFileLimited(l.opts.IndexFile, MaxIndexFile); err == nil {
		if s, err := unmarshalState(data, l.f, l.ids); err == nil && s.Anchor == anchor && l.matchesLast(s) {
			l.ref = s
			return nil
		}
	}
	return l.buildIndex()
}

// buildIndex builds the audit index from entry 0 against Verifier.Last,
// writes it and makes it the reference index.
func (l *fileLog) buildIndex() error {
	s := newState(l.f, l.ids)
	if l.v.Last != nil {
		if err := l.audit(s, l.v.Last); err != nil {
			return err
		}
	}
	if err := l.saveIndex(s); err != nil {
		return err
	}
	l.ref, l.cur = s, nil
	return nil
}

func (l *fileLog) matchesLast(s *state) bool {
	if l.v.Last == nil {
		return s.Size == 0
	}
	return s.Size == l.v.Last.Size && s.Root == l.v.Last.Hash
}

// saveIndex writes the audit index to the client directory (ErrIO, task
// 07b finding 3).
func (l *fileLog) saveIndex(s *state) error {
	data, err := s.marshal()
	if err != nil {
		return fmt.Errorf("%w: audit index: %v", ErrIO, err)
	}
	if err := store.WritePrivateFileAtomic(l.opts.IndexFile, data); err != nil {
		return fmt.Errorf("%w: audit index: %v", ErrIO, err)
	}
	return nil
}

// Invalid returns the entries of the reference tree that failed the
// validity rules (doc.go "Audit": the client warns, task 14).
func (l *fileLog) Invalid() []InvalidEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := l.view()
	if err != nil {
		return nil
	}
	return append([]InvalidEntry(nil), s.Invalid...)
}
