package client_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/client"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/testenv"
	"github.com/tim-riep/go-mail/internal/translog"
	"golang.org/x/mod/sumdb/tlog"
)

// Fuzz targets of task 26E for the checks of the client that read the
// data directory (chain and head of a mailbox, checkpoints) and its own
// state.json. They need the development platform (testenv, tags
// gomail_dev,gomail_test) and skip without it. Each fuzz process builds
// a platform of its own, with its own keys and IDs; so an input names the
// files of the platform relative to the genuine ones (xorDelta, patches,
// tokens of stateVals), never by their bytes, and a seed means the same
// in every process. A target changes only files it puts back after every
// input, and the state of the client is reset from a copy.

// heapAllocated returns the bytes the heap allocated while f ran
// (runtime.MemStats.TotalAlloc, whatever was freed again).
func heapAllocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// fuzzAllocBase bounds the heap one input of a client target may
// allocate besides fuzzAllocPerByte for every byte of input. A check of
// the client reads the files of a mailbox and the log (each at most
// store.MaxRecordFile or the bounds of translog). The largest amounts
// measured on the seeds (review of task 26E, H4): FuzzVerifyChain 2.1
// MiB (a load of the chain of 16 epochs), FuzzState 2.7 MiB (an open of
// the client log, an audit from an older reference head included, and
// the chain), FuzzCheckpoint 60 KiB. 8 MiB leaves a factor of about 3
// over the largest for what the fuzzer makes beyond the seeds; 32 MiB,
// the first bound, would have let a check that reads the chain or the
// log several times over pass unnoticed.
const (
	fuzzAllocBase    = 8 << 20
	fuzzAllocPerByte = 256
)

// xorDelta returns d XOR base over their common length, then the rest of
// d: d of the length of base with only zero bytes is base itself.
func xorDelta(base, d []byte) []byte {
	out := bytes.Clone(d)
	for i := range min(len(base), len(d)) {
		out[i] ^= base[i]
	}
	if out == nil {
		out = []byte{}
	}
	return out
}

// fuzzPlatform is the platform of the client targets: alice's mailbox,
// shared with bob and with carol, then carol removed (an immediate
// epoch that discards the supply), and a head published after
// everything, which the clock keeps fresh.
type fuzzPlatform struct {
	env               *testenv.Env
	alice, bob, carol *testenv.User
	mbx               store.ID
	// c is alice's client, opened without warnings.
	c *client.Client
	// epochs are the encodings of the epochs 1..len of mbx, mailbox the
	// encoding of mailbox.rec.
	epochs  [][]byte
	mailbox []byte
	// state is alice's state after a verified chain.
	state []byte
	// head is the published head, alice's reference head.
	head *translog.Head
	// bobDev is the device of bob's client; bobCheckpoints are the
	// checkpoint files bob wrote, for an earlier head and for head.
	bobDev         store.ID
	bobCheckpoints [][]byte
	bobKey         ed25519.PrivateKey
	carolKey       ed25519.PrivateKey
}

func discard(string) {}

func newFuzzPlatform(f *testing.F) *fuzzPlatform {
	env := testenv.New(f)
	p := &fuzzPlatform{env: env}
	p.alice, p.bob, p.carol = env.NewUser("alice"), env.NewUser("bob"), env.NewUser("carol")
	p.mbx = env.Mailbox(p.alice, "A", "a@example.org")
	env.Clock.Advance(time.Hour)
	env.Share(p.alice, p.mbx, p.bob, client.ShareOptions{})
	env.Share(p.alice, p.mbx, p.carol, client.ShareOptions{})
	if err := p.alice.Client.Revoke(p.mbx, p.carol.ID); err != nil {
		f.Fatal(err)
	}
	if _, err := p.bob.Client.List(p.mbx, store.ID{}); err != nil {
		f.Fatal(err)
	}
	env.Reopen(p.bob)
	p.bobDev = fuzzDevice(f, p.bob.Dir)
	cpFile := env.Store.CheckpointFile(p.mbx, p.bob.ID, p.bobDev)
	p.bobCheckpoints = append(p.bobCheckpoints, fuzzRead(f, cpFile))
	// A mailbox of carol grows the log after that checkpoint.
	env.Mailbox(p.carol, "C", "c@example.org")
	env.AutoHeads = false
	env.Clock.Advance(time.Minute)
	p.head = env.MustPublishHead()
	env.Reopen(p.bob)
	p.bobCheckpoints = append(p.bobCheckpoints, fuzzRead(f, cpFile))
	if bytes.Equal(p.bobCheckpoints[0], p.bobCheckpoints[1]) {
		f.Fatal("bob wrote no checkpoint for the published head")
	}
	for _, u := range []*testenv.User{p.bob, p.carol} {
		ks := env.Keystore(u)
		f.Cleanup(ks.Zero)
		if u == p.bob {
			p.bobKey = ks.Identity
		} else {
			p.carolKey = ks.Identity
		}
	}
	p.alice.Client.Close()
	cfg := env.ClientConfig(p.alice.Dir)
	cfg.Warn = discard
	c, err := client.Open(cfg, testenv.Passphrase)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(c.Close)
	p.c = c
	if !bytes.Equal(c.ReferenceHead().Note, p.head.Note) {
		f.Fatal("alice's reference head is not the published head")
	}
	m, err := env.Store.ReadMailbox(p.mbx)
	if err != nil {
		f.Fatal(err)
	}
	p.mailbox = fuzzRead(f, env.Store.MailboxFile(p.mbx))
	for n := uint32(1); n <= m.Epoch; n++ {
		p.epochs = append(p.epochs, fuzzRead(f, env.Store.EpochFile(p.mbx, n)))
	}
	v, err := c.LoadChainView(p.mbx, false)
	if err != nil || v.Err != nil || len(v.Data) != len(p.epochs) {
		f.Fatalf("alice's chain: %v", err)
	}
	if p.state, err = c.StateData(); err != nil {
		f.Fatal(err)
	}
	if n, _ := c.Remembered(p.mbx); n != m.Epoch {
		f.Fatalf("alice remembers epoch %d of %d", n, m.Epoch)
	}
	return p
}

func fuzzRead(f *testing.F, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// fuzzDevice returns the device ID in the state.json of dir.
func fuzzDevice(f *testing.F, dir string) store.ID {
	var st struct {
		Device string `json:"device"`
	}
	if err := json.Unmarshal(fuzzRead(f, filepath.Join(dir, "state.json")), &st); err != nil {
		f.Fatal(err)
	}
	id, err := store.ParseID(st.Device)
	if err != nil {
		f.Fatal(err)
	}
	return id
}

// replaceFile puts data at path (removing what is there first, whatever
// its mode), or removes path when data is nil.
func replaceFile(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if data == nil {
		return nil
	}
	return os.WriteFile(path, data, 0o600)
}

func epochHashHex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// consistent reports whether a tree of size n with root hash h is a
// prefix of the published head of p (the whole log of the platform).
func (p *fuzzPlatform) consistent(n int64, h [32]byte) bool {
	if n < 1 || n > p.head.Size {
		return false
	}
	if n == p.head.Size {
		return h == p.head.Hash
	}
	proof, err := p.env.LogOperator().ConsistencyProof(n, p.head.Size)
	return err == nil && translog.CheckTreeProof(proof, p.head.Size, p.head.Hash, n, h) == nil
}

// patchEpoch changes the decoded epoch e by the patches of data, two
// bytes each: an operation and its value. The fields stay well-formed
// where the operation allows it; the signature is kept (or flipped), so
// that the change is one the fuzzer could make to the file without the
// key.
func patchEpoch(e *store.Epoch, data []byte) {
	e.Signature = bytes.Clone(e.Signature)
	for ; len(data) >= 2; data = data[2:] {
		op, v := data[0], data[1]
		i := int(v) % len(e.Members)
		switch op % 12 {
		case 0:
			e.Begin += int64(int8(v)) * time.Minute.Milliseconds()
		case 1:
			e.Reason = store.Reason(v % 8)
		case 2:
			e.Number = uint32(int64(e.Number) + int64(int8(v)))
		case 3:
			e.PrevHash[v%32] ^= 1 << (v >> 5)
		case 4:
			e.Members[i].Gen = uint32(v >> 4)
		case 5:
			e.Members[i].Kind = store.MemberKind(v >> 6)
		case 6:
			if len(e.Members) > 1 {
				e.Members = append(e.Members[:i:i], e.Members[i+1:]...)
			}
		case 7:
			e.SignerID, e.SignerGen = e.Members[i].ID, e.Members[i].Gen
		case 8:
			e.SignerGen = uint32(v % 4)
		case 9:
			e.Discards = toggle(e.Discards, uint32(uint64(v)%(uint64(e.Number)+1)))
		case 10:
			e.Signature[v%64] ^= 1 << (v >> 6)
		case 11:
			b := e.ContentPub.Bytes()
			b[v%32] ^= 1 << (v >> 5)
			if k, err := ecdh.X25519().NewPublicKey(b); err == nil {
				e.ContentPub = k
			}
		}
	}
}

// toggle removes d from the ascending list ds if it is there and adds it
// otherwise.
func toggle(ds []uint32, d uint32) []uint32 {
	if i, ok := slices.BinarySearch(ds, d); ok {
		return slices.Delete(slices.Clone(ds), i, i+1)
	}
	out := append(slices.Clone(ds), d)
	slices.Sort(out)
	return out
}

// base returns the genuine file of slot k of FuzzVerifyChain (0:
// mailbox.rec, 1..N: epoch.rec; N+1, after the head: epoch N).
func (p *fuzzPlatform) base(k int) []byte {
	if k == 0 {
		return p.mailbox
	}
	return p.epochs[min(k, len(p.epochs))-1]
}

// patched returns the file of slot k with the patches of data
// (patchEpoch; for mailbox.rec: an even operation adds the value as a
// signed number to the epoch, an odd one flips a bit of the inbox), nil
// if the result no longer encodes. Epoch N+1 is epoch N renumbered
// after it.
func (p *fuzzPlatform) patched(k int, data []byte) []byte {
	if k == 0 {
		m, err := store.DecodeMailbox(p.mailbox)
		if err != nil {
			return nil
		}
		for ; len(data) >= 2; data = data[2:] {
			if data[0]%2 == 0 {
				m.Epoch = uint32(int64(m.Epoch) + int64(int8(data[1])))
			} else {
				m.Inbox[data[1]%16] ^= 1
			}
		}
		b, _ := m.Encode()
		return b
	}
	base := p.base(k)
	e, err := store.DecodeEpoch(bytes.Clone(base))
	if err != nil {
		return nil
	}
	if k > len(p.epochs) {
		e.Number, e.PrevHash = uint32(k), store.EpochHash(base)
	}
	patchEpoch(e, data)
	b, _ := e.Encode()
	return b
}

// FuzzVerifyChain replaces one file of the chain of alice's mailbox and
// loads the chain as every read does (verifyChain) or, with sel&0x80, as
// a change does (loadChain with adopt). sel&0x3f picks the file: 0
// mailbox.rec, 1..N epoch.rec of epoch 1..N, N+1 epoch.rec after the
// head. The file is the input XOR the genuine file (xorDelta; after the
// head: epoch N); with sel&0x40 it is the genuine file changed field by
// field (patched), so that the checks behind the decoding (chain, log,
// signature) are reached. The client must not panic; every epoch of the
// chain it returns is a genuine epoch.rec of the platform byte for byte
// (no change to an epoch.rec, which the fuzzer cannot sign, is ever
// accepted, and nothing beyond the genuine head is adopted); a chain
// without error is not shorter than the epoch alice already saw (no
// rollback through mailbox.rec); what alice remembers afterwards is a
// genuine epoch at least as high as before; and the heap allocated is
// bounded.
func FuzzVerifyChain(f *testing.F) {
	p := newFuzzPlatform(f)
	n := len(p.epochs)
	files := uint8(n + 2)
	for k := 0; k <= n+1; k++ {
		zero := make([]byte, len(p.base(k)))
		f.Add(uint8(k), zero)
		f.Add(uint8(k)|0x80, zero)
	}
	f.Add(uint8(2), []byte{})
	for _, k := range []uint8{0, 1, 2, uint8(n - 1), uint8(n), uint8(n + 1)} {
		for op := uint8(0); op < 12; op++ {
			f.Add(k|0x40, []byte{op, 1})
			f.Add(k|0xc0, []byte{op, 0xff})
		}
	}
	f.Add(uint8(0x40), []byte{0, 0xf1})
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		adopt := sel&0x80 != 0
		k := (sel & 0x3f) % files
		var content []byte
		if sel&0x40 != 0 {
			if content = p.patched(int(k), data); content == nil {
				return
			}
		} else {
			content = xorDelta(p.base(int(k)), data)
		}
		var path string
		var genuine []byte
		switch {
		case k == 0:
			path, genuine = p.env.Store.MailboxFile(p.mbx), p.mailbox
		case int(k) <= n:
			path, genuine = p.env.Store.EpochFile(p.mbx, uint32(k)), p.epochs[k-1]
		default:
			path = p.env.Store.EpochFile(p.mbx, uint32(k))
		}
		if err := p.c.SetStateData(p.state); err != nil {
			t.Fatal(err)
		}
		if genuine == nil {
			// Epoch N+1 has no directory yet; it goes again afterwards.
			if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Remove(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			}()
		}
		if err := replaceFile(path, content); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := replaceFile(path, genuine); err != nil {
				t.Fatal(err)
			}
		}()
		before, _ := p.c.Remembered(p.mbx)
		var v *client.ChainView
		var err error
		used := heapAllocated(func() { v, err = p.c.LoadChainView(p.mbx, adopt) })
		if err == nil {
			if len(v.Data) > n {
				t.Fatalf("chain of %d epochs, the platform has %d", len(v.Data), n)
			}
			for i, d := range v.Data {
				if !bytes.Equal(d, p.epochs[i]) {
					t.Fatalf("epoch %d of the chain is not the genuine epoch.rec", i+1)
				}
			}
			if v.Err == nil && uint32(len(v.Data)) < before {
				t.Fatalf("chain of %d epochs without error, alice saw epoch %d", len(v.Data), before)
			}
		}
		after, hash := p.c.Remembered(p.mbx)
		if after < before || after > uint32(n) || after > 0 && hash != epochHashHex(p.epochs[after-1]) {
			t.Fatalf("alice remembers epoch %d (before %d) with a hash that is not the genuine one", after, before)
		}
		if limit := uint64(fuzzAllocBase + fuzzAllocPerByte*len(content)); used > limit {
			t.Fatalf("allocated %d bytes for %d bytes of input (bound %d)", used, len(content), limit)
		}
	})
}

// FuzzCheckpoint checks a checkpoint file of another member against
// alice's reference head (checkCheckpoint, translog doc.go "Client
// checkpoints"). sel%4 picks the file name: bob's device, another device
// of alice, carol's device (carol is no member of the head) or another
// device of bob. The base is bob's checkpoint of the reference head
// (sel&16: of an earlier head). Without sel&4 the file is the input XOR
// the base (xorDelta). With sel&4 the checkpoint is made of the fuzzed
// fields and signed with bob's identity (sel&8: carol's), so that the
// rules behind the signature are reached: size and time are added to
// those of the base, root is XORed onto its root, an empty origin is the
// base's. The client must not panic, and a checkpoint it accepts
// decodes, names its file, is signed by the current generation of a user
// member of the head, names the origin of the log and a tree that the
// reference head extends (a smaller one signed no later than the
// reference head); the heap allocated is bounded.
func FuzzCheckpoint(f *testing.F) {
	p := newFuzzPlatform(f)
	check, err := p.c.CheckpointChecker(p.mbx)
	if err != nil {
		f.Fatal(err)
	}
	other := store.ID{0xd1, 0xd2}
	type ref struct {
		user, device store.ID
		key          ed25519.PublicKey
		member       bool
	}
	bobPub := p.bobKey.Public().(ed25519.PublicKey)
	refs := []ref{
		{p.bob.ID, p.bobDev, bobPub, true},
		{p.alice.ID, other, nil, true},
		{p.carol.ID, other, p.carolKey.Public().(ed25519.PublicKey), false},
		{p.bob.ID, other, bobPub, true},
	}
	var bases []*store.Checkpoint
	for _, b := range p.bobCheckpoints {
		cp, err := store.DecodeCheckpoint(b)
		if err != nil {
			f.Fatal(err)
		}
		bases = append(bases, cp)
	}
	h := p.head
	if bases[1].Size != h.Size || bases[0].Size >= h.Size {
		f.Fatalf("bob's checkpoints have sizes %d and %d, the head %d", bases[0].Size, bases[1].Size, h.Size)
	}
	for _, sel := range []uint8{0, 3, 16, 16 | 3} {
		f.Add(sel, make([]byte, len(p.bobCheckpoints[0])), "", int64(0), []byte{}, int64(0), uint32(0))
	}
	f.Add(uint8(0), []byte{}, "", int64(0), []byte{}, int64(0), uint32(0))
	for _, sel := range []uint8{4, 4 | 16, 4 | 8, 4 | 8 | 2, 4 | 1, 4 | 3, 4 | 16 | 3} {
		f.Add(sel, []byte{}, "", int64(0), []byte{}, int64(0), uint32(1))
	}
	f.Add(uint8(4), []byte{}, "", int64(-1), []byte{}, int64(-1), uint32(1))
	f.Add(uint8(4), []byte{}, "", int64(1), []byte{}, int64(1), uint32(1))
	f.Add(uint8(4), []byte{}, "", int64(1), []byte{}, int64(-1), uint32(1))
	f.Add(uint8(4), []byte{}, "", int64(0), []byte{1}, int64(0), uint32(1))
	f.Add(uint8(4|16), []byte{}, "", int64(0), []byte{}, int64(1<<30), uint32(1))
	f.Add(uint8(4), []byte{}, "", int64(0), []byte{}, int64(0), uint32(2))
	f.Add(uint8(4), []byte{}, "other.test/log", int64(0), []byte{}, int64(0), uint32(1))
	f.Fuzz(func(t *testing.T, sel uint8, data []byte, origin string, size int64, root []byte, headTime int64, gen uint32) {
		r := refs[sel%4]
		bi := 1
		if sel&16 != 0 {
			bi = 0
		}
		base := bases[bi]
		if sel&4 == 0 {
			data = xorDelta(p.bobCheckpoints[bi], data)
		} else {
			cp := &store.Checkpoint{UserID: r.user, DeviceID: r.device, Origin: origin, Size: base.Size + size,
				RootHash: base.RootHash, HeadTime: base.HeadTime + headTime, UserGen: gen}
			if origin == "" {
				cp.Origin = base.Origin
			}
			for i := range min(len(root), len(cp.RootHash)) {
				cp.RootHash[i] ^= root[i]
			}
			key := p.bobKey
			if sel&8 != 0 {
				key = p.carolKey
			}
			if cp.Sign(key) != nil {
				return
			}
			var err error
			if data, err = cp.Encode(); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		used := heapAllocated(func() { err = check(r.user, r.device, data) })
		if err == nil {
			cp, derr := store.DecodeCheckpoint(data)
			switch {
			case derr != nil:
				t.Fatalf("accepted a checkpoint that does not decode: %v", derr)
			case cp.UserID != r.user || cp.DeviceID != r.device:
				t.Fatal("accepted a checkpoint that names another file")
			case !r.member:
				t.Fatal("accepted a checkpoint of a non-member")
			case r.key == nil || cp.UserGen != 1 || cp.Verify(r.key) != nil:
				t.Fatal("accepted a checkpoint not signed by the current generation of its user")
			case cp.Origin != h.Origin:
				t.Fatal("accepted a checkpoint of another log")
			case !p.consistent(cp.Size, cp.RootHash):
				t.Fatalf("accepted a checkpoint of size %d that the reference head does not extend", cp.Size)
			case cp.Size < h.Size && cp.HeadTime > h.Time:
				t.Fatal("accepted a smaller checkpoint signed after the reference head")
			}
		}
		if limit := uint64(fuzzAllocBase + fuzzAllocPerByte*(len(data)+len(origin)+len(root))); used > limit {
			t.Fatalf("allocated %d bytes for %d bytes of input (bound %d)", used, len(data), limit)
		}
	})
}

// stateHex matches the IDs (store.ID: 26 characters of base32) and the
// hashes (64 hex digits) in state.json.
var stateHex = regexp.MustCompile(`\b(?:[0-9a-f]{64}|[a-z2-7]{26})\b`)

// stateVals are the values of a state.json of the platform that differ
// between fuzz processes, or that a template names by a token
// (stateTemplate, expand):
//
//   - $H the signed reference head, the JSON string escaped as in the
//     file;
//   - $S, $R and $T its size, root hash (base64, as in the head text) and
//     time (review of task 26E, B1), and $G its signature lines, escaped:
//     the templates hold the head as "<origin>\n$S\n$R\ntime $T\n\n$G",
//     so that the fuzzer changes the fields of the head (the client parses
//     the head of state.json without its signatures, D57);
//   - $R<n> the root hash of the tree of size n of the log (1 <= n <= $S),
//     for an older reference head that the published head extends;
//   - $L<n> the leaf hash (hex) of entry n of the log (n < $S), for a
//     pending entry that the log holds as appended;
//   - $<i> values[i], every ID and hash of the state in the order they
//     first appear (the state of every process has the same shape).
type stateVals struct {
	head, sig  string
	size, time int64
	roots      []string // roots[n] for 1 <= n <= size
	leaves     []string
	values     []string
}

// escapeJSON returns s as the contents of a JSON string.
func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// merkleRoot returns the root hash of the tree with the leaf hashes l
// (RFC 6962, as tlog.TreeHash).
func merkleRoot(l []tlog.Hash) tlog.Hash {
	if len(l) == 1 {
		return l[0]
	}
	k := 1
	for k*2 < len(l) {
		k *= 2
	}
	return tlog.NodeHash(merkleRoot(l[:k]), merkleRoot(l[k:]))
}

// newStateVals returns the values of the state of p and of its log.
func newStateVals(f *testing.F, p *fuzzPlatform) *stateVals {
	var st struct {
		Log struct {
			Head string `json:"head"`
		} `json:"log"`
	}
	if err := json.Unmarshal(p.state, &st); err != nil || st.Log.Head != string(p.head.Note) {
		f.Fatalf("alice's state.json does not hold the published head: %v", err)
	}
	h := p.head
	_, sig, ok := strings.Cut(st.Log.Head, "\n\n")
	if !ok {
		f.Fatal("reference head without signatures")
	}
	sv := &stateVals{head: escapeJSON(st.Log.Head), sig: escapeJSON(sig), size: h.Size, time: h.Time,
		roots: make([]string, h.Size+1)}
	var leaves []tlog.Hash
	for i := range h.Size {
		e, err := p.env.LogOperator().Entry(i)
		if err != nil {
			f.Fatal(err)
		}
		enc, err := e.Encode()
		if err != nil {
			f.Fatal(err)
		}
		leaves = append(leaves, translog.LeafHash(enc))
		sv.leaves = append(sv.leaves, hex.EncodeToString(leaves[i][:]))
		root := merkleRoot(leaves)
		if !p.consistent(i+1, root) {
			f.Fatalf("root of size %d is not a prefix of the published head", i+1)
		}
		sv.roots[i+1] = base64.StdEncoding.EncodeToString(root[:])
	}
	// The head is a token of its own; a run of its base64 that looks like
	// an ID must not shift the numbers of the values.
	for _, m := range stateHex.FindAll(bytes.ReplaceAll(p.state, []byte(sv.head), nil), -1) {
		if v := string(m); !slices.Contains(sv.values, v) {
			sv.values = append(sv.values, v)
		}
	}
	return sv
}

// headTemplate returns the template of a reference head with the given
// size, root and time (tokens or literals) and the signature lines of the
// published head ($G), as the value of the JSON string, not escaped.
func headTemplate(origin, size, root, time string) string {
	return origin + "\n" + size + "\n" + root + "\ntime " + time + "\n\n$G"
}

// stateTemplate replaces the values of sv in a state.json by tokens: the
// head by headTemplate with $S, $R and $T, the IDs and hashes by $<i>.
// Quoted tokens of a number ("$S", "$T") lose their quotes, so that a
// variant built from JSON can name them in a number field.
func stateTemplate(state []byte, origin string, sv *stateVals) []byte {
	out := bytes.ReplaceAll(state, []byte(sv.head), []byte(escapeJSON(headTemplate(origin, "$S", "$R", "$T"))))
	out = stateHex.ReplaceAllFunc(out, func(m []byte) []byte {
		if i := slices.Index(sv.values, string(m)); i >= 0 {
			return []byte("$" + strconv.Itoa(i))
		}
		return m
	})
	for _, tok := range []string{"$S", "$T"} {
		out = bytes.ReplaceAll(out, []byte(`"`+tok+`"`), []byte(tok))
	}
	return out
}

// expand replaces the tokens of stateTemplate in t by the values of this
// process. A token that names nothing ($L or $R with a number out of
// range, $<i> beyond values) stays as it is.
func (sv *stateVals) expand(t []byte) []byte {
	var out []byte
	for {
		i := bytes.IndexByte(t, '$')
		if i < 0 {
			return append(out, t...)
		}
		out, t = append(out, t[:i]...), t[i+1:]
		var c byte
		if len(t) > 0 {
			c = t[0]
		}
		// n is the number after the token letter (or after $), if any.
		rest := t
		if c >= 'A' && c <= 'Z' {
			rest = t[1:]
		}
		j := 0
		for j < len(rest) && j < 3 && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		n, nerr := strconv.Atoi(string(rest[:j]))
		switch {
		case c == 'H':
			out, t = append(out, sv.head...), t[1:]
		case c == 'G':
			out, t = append(out, sv.sig...), t[1:]
		case c == 'S':
			out, t = strconv.AppendInt(out, sv.size, 10), t[1:]
		case c == 'T':
			out, t = strconv.AppendInt(out, sv.time, 10), t[1:]
		case c == 'R' && j == 0:
			out, t = append(out, sv.roots[sv.size]...), t[1:]
		case c == 'R' && nerr == nil && n >= 1 && n <= len(sv.roots)-1:
			out, t = append(out, sv.roots[n]...), rest[j:]
		case c == 'L' && nerr == nil && n < len(sv.leaves):
			out, t = append(out, sv.leaves[n]...), rest[j:]
		case c >= '0' && c <= '9' && nerr == nil && n < len(sv.values):
			out, t = append(out, sv.values[n]...), rest[j:]
		default:
			out = append(out, '$')
		}
	}
}

// FuzzState opens alice's client once more with the input as state.json
// (loadState, the registration, the client log with the reference head
// and the pending entries of the state, the check of the own user.rec;
// client.OpenWithState) and, if that succeeds, loads the chain of her
// mailbox. The input is a template of stateTemplate, expanded with the
// values of this process (stateVals). state.json lies in the trust zone
// of the client directory (D57); the target checks what a damaged one
// must still not achieve. Nothing may panic; an accepted reference head
// names the log's origin and a tree that the log holds (a prefix of the
// published head); every pending entry of an accepted state whose index
// the client's reference head after the open covers carries the leaf
// that the log holds at that index (Refresh checks it against the head
// and drops it, translog doc.go "Withheld entries"; review of task 26E,
// B1), and none that this head does not cover is withheld by it
// (Verifier.Fresh; review of task 26E2); a chain without error is
// not shorter than the epoch the state remembers, and the remembered
// epoch.rec is the genuine one (a state that remembers more than the
// data directory holds is a rollback, one with another hash a replaced
// epoch); and the heap allocated is bounded.
//
// A pending entry the log does not hold as appended is accepted only
// when the client appends its record again (repairPending) and the new
// entry passes; that needs a signed record the log does not hold yet,
// which the fuzzer cannot make.
func FuzzState(f *testing.F) {
	p := newFuzzPlatform(f)
	sv := newStateVals(f, p)
	if len(sv.values) < 3 {
		f.Fatalf("state.json without IDs: %d values", len(sv.values))
	}
	origin := p.head.Origin
	base := stateTemplate(p.state, origin, sv)
	if !bytes.Equal(sv.expand(base), p.state) {
		f.Fatal("the template of alice's state.json does not expand to it")
	}
	f.Add(base)
	variant := func(change func(st map[string]any)) {
		var c map[string]any
		if err := json.Unmarshal(p.state, &c); err != nil {
			f.Fatal(err)
		}
		change(c)
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(stateTemplate(b, origin, sv))
	}
	mbxKey := p.mbx.String()
	mailbox := func(st map[string]any) map[string]any {
		return st["mailboxes"].(map[string]any)[mbxKey].(map[string]any)
	}
	logOf := func(st map[string]any) map[string]any { return st["log"].(map[string]any) }
	variant(func(st map[string]any) { delete(st, "log") })
	variant(func(st map[string]any) { mailbox(st)["epoch"] = len(p.epochs) + 1 })
	variant(func(st map[string]any) { mailbox(st)["epoch"] = len(p.epochs) - 1 })
	variant(func(st map[string]any) { mailbox(st)["epoch_hash"] = epochHashHex(nil) })
	variant(func(st map[string]any) { mailbox(st)["epoch_hash"] = epochHashHex(p.epochs[0]) })
	variant(func(st map[string]any) { delete(st, "mailboxes") })
	variant(func(st map[string]any) { st["unconfirmed"] = true })
	// Pending entries (review of task 26E, B1): index, leaf (a token or
	// literal hex) and time of the append ("$T" is the time of the head).
	type pend struct {
		index any
		leaf  string
		at    any
	}
	zero := hex.EncodeToString(make([]byte, 32))
	pending := func(ps ...pend) func(st map[string]any) {
		return func(st map[string]any) {
			var l []any
			for _, x := range ps {
				l = append(l, map[string]any{"index": x.index, "leaf": x.leaf, "at": x.at, "kind": 1})
			}
			logOf(st)["pending"] = l
		}
	}
	// older is the size of bob's first checkpoint, a head before the
	// mailbox of carol.
	cp, err := store.DecodeCheckpoint(p.bobCheckpoints[0])
	if err != nil || cp.Size < 1 || cp.Size+2 > sv.size {
		f.Fatalf("no older head below the published head of size %d: %v", sv.size, err)
	}
	older := cp.Size
	num := func(n int64) string { return strconv.FormatInt(n, 10) }
	// Covered by the head: the leaf the log holds (accepted and dropped),
	// another leaf, the leaf of another entry (also at the last index the
	// head covers), a negative index.
	variant(pending(pend{1, "$L1", "$T"}))
	variant(pending(pend{sv.size - 1, "$L" + num(sv.size-1), "$T"}))
	variant(pending(pend{1, zero, 0}))
	variant(pending(pend{1, "$L2", "$T"}))
	variant(pending(pend{sv.size - 1, "$L" + num(sv.size-2), "$T"}))
	variant(pending(pend{-1, "$L0", "$T"}))
	// Behind the head: still pending (accepted while the head is fresh),
	// and one the head withholds (appended long before it).
	variant(pending(pend{"$S", zero, "$T"}))
	variant(pending(pend{"$S", zero, 0}))
	variant(pending(pend{1, "$L1", "$T"}, pend{"$S", zero, "$T"}))
	variant(pending(pend{1, "$L2", "$T"}, pend{"$S", zero, "$T"}))
	// Another reference head: an older one that the published head
	// extends, alone and with an entry between the two that the log holds
	// as appended or with another leaf; one of the size of the published
	// head with the root of the older one; one larger than the published
	// head; one with another time.
	olderHead := headTemplate(origin, num(older), "$R"+num(older), "$T")
	headVariant := func(head string, ps ...pend) {
		variant(func(st map[string]any) {
			logOf(st)["head"] = head
			if len(ps) > 0 {
				pending(ps...)(st)
			}
		})
	}
	headVariant(olderHead)
	headVariant(olderHead, pend{older + 1, "$L" + num(older+1), "$T"})
	headVariant(olderHead, pend{older + 1, "$L" + num(older), "$T"})
	headVariant(olderHead, pend{older + 1, "$L" + num(older+1), "$T"}, pend{"$S", zero, "$T"})
	headVariant(headTemplate(origin, "$S", "$R"+num(older), "$T"))
	headVariant(headTemplate(origin, num(sv.size+1), "$R", "$T"))
	headVariant(headTemplate(origin, "$S", "$R", "1"))
	// A reference head 1 ms newer than the published one, of the same
	// size or older: the client keeps it and checks no pending entry
	// against the log (review of task 26E2). An entry that it covers was
	// never checked (Verifier.Fresh); one behind it stays pending,
	// whatever its leaf, because this head does not cover it.
	newer := num(sv.time + 1)
	headVariant(headTemplate(origin, "$S", "$R", newer), pend{1, zero, "$T"})
	headVariant(headTemplate(origin, num(older), "$R"+num(older), newer), pend{older - 1, zero, "$T"})
	headVariant(headTemplate(origin, num(older), "$R"+num(older), newer), pend{older + 1, zero, "$T"})
	f.Add(stateTemplate([]byte(`{"registered":true,"user_id":"`+p.alice.ID.String()+`"}`), origin, sv))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		content := sv.expand(data)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "state.json"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		var bad string
		used := heapAllocated(func() {
			nc, err := p.c.OpenWithState(dir, discard)
			if err != nil {
				return
			}
			ref := nc.ReferenceHead()
			if ref == nil || ref.Origin != p.head.Origin || !p.consistent(ref.Size, ref.Hash) {
				bad = "the reference head of the state names a tree the log does not hold"
				return
			}
			if bad = sv.checkPending(content, ref.Size, ref.Time); bad != "" {
				return
			}
			before, hash := nc.Remembered(p.mbx)
			v, err := nc.LoadChainView(p.mbx, false)
			if err != nil || v.Err != nil {
				return
			}
			if before > uint32(len(v.Data)) {
				bad = fmt.Sprintf("chain of %d epochs without error, the state remembers epoch %d", len(v.Data), before)
			} else if before > 0 && hash != epochHashHex(p.epochs[before-1]) {
				bad = fmt.Sprintf("chain without error, the state remembers another epoch.rec for epoch %d", before)
			}
		})
		if bad != "" {
			t.Fatal(bad)
		}
		if limit := uint64(fuzzAllocBase + fuzzAllocPerByte*len(content)); used > limit {
			t.Fatalf("allocated %d bytes for %d bytes of input (bound %d)", used, len(content), limit)
		}
	})
}

// checkPending reports a pending entry of the accepted state.json
// content that the client's reference head after the open (size
// covered, time refTime) covers and whose leaf is not the one the log
// holds there, or that this head does not cover and withholds
// (Verifier.Fresh), "" if none. A pending entry behind a reference head
// older than the published head is not checked against the log, so its
// leaf is not judged here (review of task 26E2). The client parsed
// content with the same field names and types (and more fields), so
// content parses here as well; covered is at most the size of the
// published head (consistent).
func (sv *stateVals) checkPending(content []byte, covered, refTime int64) string {
	var st struct {
		Log *struct {
			Pending []struct {
				Index int64  `json:"index"`
				Leaf  string `json:"leaf"`
				At    int64  `json:"at"`
			} `json:"pending"`
		} `json:"log"`
	}
	if err := json.Unmarshal(content, &st); err != nil {
		return fmt.Sprintf("accepted a state.json that does not parse: %v", err)
	}
	if st.Log == nil {
		return ""
	}
	for _, pe := range st.Log.Pending {
		if pe.Index >= covered {
			if refTime > pe.At+translog.HeadInterval.Milliseconds() {
				return fmt.Sprintf("accepted pending entry %d, which the reference head withholds", pe.Index)
			}
			continue
		}
		leaf, err := hex.DecodeString(pe.Leaf)
		if pe.Index < 0 || err != nil || hex.EncodeToString(leaf) != sv.leaves[pe.Index] {
			return fmt.Sprintf("accepted pending entry %d, which the reference head covers, with another leaf than the log holds there", pe.Index)
		}
	}
	return ""
}
