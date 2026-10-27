package translog

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/rec"
	"github.com/tim-riep/go-mail/internal/store"
)

// Read limits of the files under log/ (doc.go "File format").
const (
	maxTileFile = (1 << TileHeight) * tlog.HashSize
	maxTreeFile = 256
	maxKeyFile  = 32
	// maxLeavesPerRead bounds the leaf hashes of one files.leaves call
	// (one tile): sizes from tree.rec are never trusted for an allocation
	// (task 07b finding 1).
	maxLeavesPerRead = 1 << TileHeight
	// headBatch is the number of names read from heads/ at a time.
	headBatch = 1024
)

// logErr wraps an error of the file system under log/ (task 07b finding
// 3): the files under log/ do not hold the committed tree, which is
// ErrConsistency. An error that already wraps an error of this package is
// returned unchanged, so that it wraps exactly one.
func logErr(what string, err error) error {
	if err == nil || isPkgErr(err) {
		return err
	}
	return fmt.Errorf("%w: %s: %v", ErrConsistency, what, err)
}

// isPkgErr reports whether err wraps one of the documented errors.
func isPkgErr(err error) bool {
	for _, e := range []error{ErrNotInLog, ErrMismatch, ErrSuperseded, ErrDuplicate, ErrOrder, ErrPrerequisite,
		ErrConsistency, ErrWitness, ErrStale, ErrPin, ErrIO, ErrNotImplemented, ErrEntry, ErrHead} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// files is the access to log/ of one data directory.
type files struct {
	root string
}

func (f *files) path(rel string) string { return filepath.Join(f.root, filepath.FromSlash(rel)) }

// treeState is the content of log/tree.rec.
type treeState struct {
	Size int64
	Hash tlog.Hash
}

func encodeTree(t treeState) ([]byte, error) {
	if t.Size < 0 || t.Size > MaxTreeSize {
		return nil, fmt.Errorf("%w: tree size out of range", ErrConsistency)
	}
	b, err := rec.New(TreeSchema).SetI64(1, t.Size).SetBytes(2, t.Hash[:]).Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConsistency, err)
	}
	return b, nil
}

func decodeTree(data []byte) (treeState, error) {
	r, err := rec.Decode(TreeSchema, data)
	if err != nil {
		return treeState{}, fmt.Errorf("%w: tree.rec: %v", ErrConsistency, err)
	}
	t := treeState{Size: r.I64(1)}
	copy(t.Hash[:], r.Bytes(2))
	if t.Size < 0 || t.Size > MaxTreeSize {
		return treeState{}, fmt.Errorf("%w: tree.rec size out of range", ErrConsistency)
	}
	if t.Size == 0 && t.Hash != (tlog.Hash{}) {
		return treeState{}, fmt.Errorf("%w: tree.rec of the empty log names a hash", ErrConsistency)
	}
	return t, nil
}

// readTree reads log/tree.rec.
func (f *files) readTree() (treeState, error) {
	data, err := store.ReadFileLimited(f.path(TreeFile), maxTreeFile)
	if err != nil {
		return treeState{}, fmt.Errorf("%w: tree.rec: %v", ErrConsistency, err)
	}
	return decodeTree(data)
}

func (f *files) writeTree(t treeState) error {
	b, err := encodeTree(t)
	if err != nil {
		return err
	}
	return logErr("tree.rec", store.WriteFileAtomic(f.path(TreeFile), b))
}

// readEntry reads log/entries/<index>.rec. A missing file is ErrNotInLog.
func (f *files) readEntry(index int64) ([]byte, error) {
	if index < 0 || index >= MaxTreeSize {
		return nil, fmt.Errorf("%w: index out of range", ErrNotInLog)
	}
	data, err := store.ReadFileLimited(f.path(EntryPath(index)), MaxEntryFile)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: entry %d missing", ErrNotInLog, index)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: entry %d: %v", ErrConsistency, index, err)
	}
	return data, nil
}

// readEntryLeaf reads entry index and checks it against the leaf hash
// recorded for it (ErrConsistency: the file changed below a verified
// tree).
func (f *files) readEntryLeaf(index int64, leaf tlog.Hash) (*Entry, any, []byte, error) {
	data, err := f.readEntry(index)
	if err != nil {
		if errors.Is(err, ErrNotInLog) {
			return nil, nil, nil, fmt.Errorf("%w: entry %d of the tree is missing", ErrConsistency, index)
		}
		return nil, nil, nil, err
	}
	if LeafHash(data) != leaf {
		return nil, nil, nil, fmt.Errorf("%w: entry %d changed", ErrConsistency, index)
	}
	e, obj, err := decodeEntry(data, index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: entry %d: %v", ErrConsistency, index, err)
	}
	return e, obj, data, nil
}

func (f *files) exists(rel string) (bool, error) {
	_, err := os.Lstat(f.path(rel))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, logErr(path.Base(rel), err)
}

// createOrSame creates rel with data; an existing file with exactly data
// is accepted (a tile or entry written again after a crash).
func (f *files) createOrSame(rel string, data []byte, max int64) error {
	p := f.path(rel)
	if err := store.MkdirAll(filepath.Dir(p)); err != nil {
		return logErr(filepath.Base(p), err)
	}
	err := store.CreateFileAtomic(p, data)
	if !errors.Is(err, store.ErrExists) {
		return logErr(filepath.Base(p), err)
	}
	old, rerr := store.ReadFileLimited(p, max)
	if rerr != nil || string(old) != string(data) {
		return fmt.Errorf("%w: %s exists with other content", ErrConsistency, filepath.Base(p))
	}
	return nil
}

// newestHeadSize returns the largest size named by heads/<size>.sig, 0
// when there is none. Names that are not canonical are ignored. Only the
// maximum is ever needed (refuse, newestHead), so the directory is
// scanned once in batches, without sorting (task 07b finding 7: the
// insertion sort of task 07 took half a second for 40,000 heads).
func (f *files) newestHeadSize() (int64, error) {
	d, err := os.Open(f.path(HeadsDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, logErr("heads", err)
	}
	defer d.Close()
	var max int64
	for {
		ents, err := d.ReadDir(headBatch)
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".sig")
			if !ok || !e.Type().IsRegular() {
				continue
			}
			n, err := parseDecimal(name)
			if err != nil || n < 1 || n > MaxTreeSize {
				continue
			}
			if n > max {
				max = n
			}
		}
		if errors.Is(err, io.EOF) {
			return max, nil
		}
		if err != nil {
			return 0, logErr("heads", err)
		}
	}
}

// readKeyFile returns the index stored in the key file of k, or -1.
func (f *files) readKeyFile(k Key) int64 {
	data, err := store.ReadFileLimited(f.path(KeyPath(k)), maxKeyFile)
	if err != nil {
		return -1
	}
	n, err := parseDecimal(string(data))
	if err != nil || n >= MaxTreeSize {
		return -1
	}
	return n
}

// writeKeyFile records index as the entry of k. keys/ is derived data:
// a file that names another index is replaced.
func (f *files) writeKeyFile(k Key, index int64) error {
	p := f.path(KeyPath(k))
	if err := store.MkdirAll(filepath.Dir(p)); err != nil {
		return logErr("key file", err)
	}
	data := []byte(strconv.FormatInt(index, 10))
	err := store.CreateFileAtomic(p, data)
	if !errors.Is(err, store.ErrExists) {
		return logErr("key file", err)
	}
	if f.readKeyFile(k) == index {
		return nil
	}
	return logErr("key file", store.WriteFileAtomic(p, data))
}

// tileFiles reads tiles from log/tree/ (tlog.TileReader). Tiles that
// tlog.TileHashReader verified are kept for the lifetime of the reader;
// TileHashReader verifies every tile it is given again, cached or not.
type tileFiles struct {
	f     *files
	cache map[tlog.Tile][]byte
}

func (r *tileFiles) Height() int { return TileHeight }

func (r *tileFiles) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		if d, ok := r.cache[t]; ok {
			out[i] = d
			continue
		}
		if t.H != TileHeight || t.L < 0 || t.L > 8 || t.N < 0 || t.W < 1 || t.W > 1<<TileHeight {
			return nil, fmt.Errorf("%w: tile out of range", ErrConsistency)
		}
		data, err := store.ReadFileLimited(r.f.path(TilePath(t)), maxTileFile)
		if err != nil {
			return nil, fmt.Errorf("%w: tile: %v", ErrConsistency, err)
		}
		if len(data) != t.W*tlog.HashSize {
			return nil, fmt.Errorf("%w: tile has the wrong length", ErrConsistency)
		}
		out[i] = data
	}
	return out, nil
}

func (r *tileFiles) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	if r.cache == nil {
		r.cache = map[tlog.Tile][]byte{}
	}
	for i, t := range tiles {
		r.cache[t] = data[i]
	}
}

// reader returns a HashReader over the stored hashes of the tree t,
// every tile verified against t.Hash (tlog.TileHashReader).
func (f *files) reader(t treeState) tlog.HashReader {
	if t.Size <= 0 {
		return tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
			if len(idx) == 0 {
				return nil, nil
			}
			return nil, fmt.Errorf("%w: empty tree", ErrConsistency)
		})
	}
	tr := tlog.TileHashReader(tlog.Tree{N: t.Size, Hash: t.Hash}, &tileFiles{f: f})
	return tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		hs, err := tr.ReadHashes(idx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConsistency, err)
		}
		return hs, nil
	})
}

// leaves returns the leaf hashes of the records from to to-1 of the tree
// t, verified against t.Hash; at most maxLeavesPerRead per call, so that
// a size read from tree.rec never decides an allocation (task 07b
// finding 1).
func (f *files) leaves(t treeState, from, to int64) ([]tlog.Hash, error) {
	if from < 0 || from > to || to > t.Size {
		return nil, fmt.Errorf("%w: records out of range", ErrConsistency)
	}
	if to-from > maxLeavesPerRead {
		return nil, fmt.Errorf("%w: too many records in one read", ErrConsistency)
	}
	if from == to {
		return nil, nil
	}
	idx := make([]int64, 0, to-from)
	for i := from; i < to; i++ {
		idx = append(idx, tlog.StoredHashIndex(0, i))
	}
	return f.reader(t).ReadHashes(idx)
}

// parseGenName parses <prefix><gen><suffix> with gen in canonical
// decimal, 1 <= gen <= 2^32-1.
func parseGenName(name, prefix, suffix string) (uint32, bool) {
	s, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return 0, false
	}
	if s, ok = strings.CutSuffix(s, suffix); !ok {
		return 0, false
	}
	n, err := parseDecimal(s)
	if err != nil || n < 1 || n > 1<<32-1 {
		return 0, false
	}
	return uint32(n), true
}
