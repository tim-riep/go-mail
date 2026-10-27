package translog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
)

// state is the result of applying the validity rules (doc.go "Validity
// rules") to the entries 0 to Size-1 of a log against an identity anchor.
// The client keeps it in its client directory as the audit index (doc.go
// "Audit", JSON); an operator log builds it at Open and keeps it in
// memory. It holds IDs, numbers, public keys and hashes, never the
// content of a record and never an address in clear: subjects are
// hashed (keyID). Every entry an answer relies on is read again from
// log/entries/ and checked against the leaf hash recorded here.
type state struct {
	Version int       `json:"version"`
	Anchor  tlog.Hash `json:"anchor"`
	Size    int64     `json:"size"`
	Root    tlog.Hash `json:"root"`
	// Valid maps keyID to the valid entry that holds the key.
	Valid map[string]ref `json:"valid"`
	// Users: per user ID the generations of its newest valid entry.
	Users map[string]*userState `json:"users"`
	// Epochs: per mailbox ID the number of valid epoch entries (1..n).
	Epochs map[string]uint32 `json:"epochs"`
	// Addresses: per subjectID of an address its valid assignments in
	// log order (strictly increasing valid_from).
	Addresses map[string][]addrState `json:"addresses"`
	// Certs: valid platform certificates by file name.
	Certs map[string]*certState `json:"certs"`
	// Succs: valid successions of the platform identity by generation.
	Succs map[uint32]*succState `json:"succs"`
	// Invalid lists the entries that failed the rules (doc.go "Audit":
	// the client warns about them).
	Invalid []InvalidEntry `json:"invalid"`

	f        *files
	ids      []Identity
	subjects map[string][]ref        // subjectID -> valid entries in log order
	chains   map[string]*store.Chain // mailbox ID -> chain of its valid epochs
}

// ref is a valid entry: its index and leaf hash.
type ref struct {
	Index int64     `json:"i"`
	Leaf  tlog.Hash `json:"leaf"`
	Seq   int64     `json:"seq"`
}

type userState struct {
	Root   []byte      `json:"root"`
	Idents [][]byte    `json:"idents"` // identity key of generation g at g-1
	Certs  []tlog.Hash `json:"certs"`  // SHA-256 of the encoding of certificate g at g-1
}

type addrState struct {
	ValidFrom int64  `json:"from"`
	Mailbox   string `json:"mbx"`
	Index     int64  `json:"i"`
}

type certState struct {
	Role        uint8  `json:"role"`
	Gen         uint32 `json:"gen"`
	Pub         []byte `json:"pub"`
	IdentityGen uint32 `json:"identity_gen"`
	ValidFrom   int64  `json:"valid_from"`
	Index       int64  `json:"i"`
}

type succState struct {
	Pub       []byte `json:"pub"`
	ValidFrom int64  `json:"valid_from"`
	Index     int64  `json:"i"`
}

// InvalidEntry is an entry of the tree that failed the validity rules
// (written past Append). It occupies no key and no answer relies on it;
// the client warns (doc.go "Validity rules"). Class names the error:
// "entry", "duplicate", "order", "prerequisite", "unlogged-signer" or
// "mismatch".
type InvalidEntry struct {
	Index int64  `json:"i"`
	Class string `json:"err"`
}

const stateVersion = 1

// errIndex marks an inconsistency that comes from the state itself, not
// from the log: a key that the state records for an entry the entry
// does not hold, a count without its entries (task 07b finding 5). It
// wraps ErrConsistency; a client log that meets it discards its audit
// index and rebuilds it from entry 0 (fileLog.retry), as for a damaged
// index file.
var errIndex = fmt.Errorf("%w: the audit index contradicts the log", ErrConsistency)

// MaxIndexFile is the read limit of the audit index in the client
// directory.
const MaxIndexFile = 256 << 20

// anchorHash fingerprints the identity list: validity depends on it, so a
// client discards its index when the pin changes (doc.go "Audit").
func anchorHash(ids []Identity) tlog.Hash {
	h := sha256.New()
	h.Write([]byte("gomail/v1/translog-anchor\x00"))
	for _, id := range ids {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], id.Gen)
		h.Write(b[:])
		h.Write(id.Pub)
	}
	var out tlog.Hash
	copy(out[:], h.Sum(nil))
	return out
}

func newState(f *files, ids []Identity) *state {
	s := &state{Version: stateVersion, Anchor: anchorHash(ids), f: f, ids: ids}
	s.init()
	return s
}

func (s *state) init() {
	if s.Valid == nil {
		s.Valid = map[string]ref{}
	}
	if s.Users == nil {
		s.Users = map[string]*userState{}
	}
	if s.Epochs == nil {
		s.Epochs = map[string]uint32{}
	}
	if s.Addresses == nil {
		s.Addresses = map[string][]addrState{}
	}
	if s.Certs == nil {
		s.Certs = map[string]*certState{}
	}
	if s.Succs == nil {
		s.Succs = map[uint32]*succState{}
	}
	s.subjects = map[string][]ref{}
	for k, r := range s.Valid {
		sub := k[:strings.LastIndexByte(k, '/')]
		s.subjects[sub] = append(s.subjects[sub], r)
	}
	for _, l := range s.subjects {
		sort.Slice(l, func(i, j int) bool { return l[i].Index < l[j].Index })
	}
	s.chains = map[string]*store.Chain{}
}

// clone returns a deep copy (without the chain cache).
func (s *state) clone() *state {
	c := &state{Version: s.Version, Anchor: s.Anchor, Size: s.Size, Root: s.Root, f: s.f, ids: s.ids,
		Valid: make(map[string]ref, len(s.Valid)), Users: make(map[string]*userState, len(s.Users)),
		Epochs: make(map[string]uint32, len(s.Epochs)), Addresses: make(map[string][]addrState, len(s.Addresses)),
		Certs: make(map[string]*certState, len(s.Certs)), Succs: make(map[uint32]*succState, len(s.Succs)),
		Invalid: append([]InvalidEntry(nil), s.Invalid...)}
	for k, v := range s.Valid {
		c.Valid[k] = v
	}
	for k, v := range s.Users {
		u := *v
		u.Idents = append([][]byte(nil), v.Idents...)
		u.Certs = append([]tlog.Hash(nil), v.Certs...)
		c.Users[k] = &u
	}
	for k, v := range s.Epochs {
		c.Epochs[k] = v
	}
	for k, v := range s.Addresses {
		c.Addresses[k] = append([]addrState(nil), v...)
	}
	for k, v := range s.Certs {
		x := *v
		c.Certs[k] = &x
	}
	for k, v := range s.Succs {
		x := *v
		c.Succs[k] = &x
	}
	c.subjects = make(map[string][]ref, len(s.subjects))
	for k, v := range s.subjects {
		c.subjects[k] = append([]ref(nil), v...)
	}
	c.chains = map[string]*store.Chain{}
	return c
}

// marshal encodes the audit index.
func (s *state) marshal() ([]byte, error) { return json.Marshal(s) }

// unmarshalState decodes an audit index and checks its structure. Any
// violation is an error; the client then rebuilds the index from entry 0
// (doc.go "Audit").
func unmarshalState(data []byte, f *files, ids []Identity) (*state, error) {
	if len(data) > MaxIndexFile {
		return nil, fmt.Errorf("%w: audit index too large", ErrConsistency)
	}
	s := &state{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("%w: audit index: %v", ErrConsistency, err)
	}
	if err := s.checkStructure(); err != nil {
		return nil, err
	}
	s.f, s.ids = f, ids
	s.init()
	return s, nil
}

func (s *state) checkStructure() error {
	bad := func(what string) error { return fmt.Errorf("%w: audit index: %s", ErrConsistency, what) }
	if s.Version != stateVersion {
		return bad("version")
	}
	if s.Size < 0 || s.Size > MaxTreeSize || (s.Size == 0) != (s.Root == tlog.Hash{}) {
		return bad("size")
	}
	in := func(i int64) bool { return i >= 0 && i < s.Size }
	for k, r := range s.Valid {
		parts := strings.Split(k, "/")
		if len(parts) != 3 || len(parts[1]) != 64 || !in(r.Index) || strconv.FormatInt(r.Seq, 10) != parts[2] {
			return bad("key")
		}
		if parts[0] != KindUser.String() && parts[0] != KindEpoch.String() && parts[0] != KindAddress.String() && parts[0] != KindPlatform.String() {
			return bad("key kind")
		}
	}
	for id, u := range s.Users {
		if _, err := store.ParseID(id); err != nil || u == nil || len(u.Root) != ed25519.PublicKeySize ||
			len(u.Idents) == 0 || len(u.Idents) != len(u.Certs) || len(u.Idents) > store.MaxGenerations {
			return bad("user")
		}
		for _, k := range u.Idents {
			if len(k) != ed25519.PublicKeySize {
				return bad("user key")
			}
		}
	}
	for id, n := range s.Epochs {
		if _, err := store.ParseID(id); err != nil || n == 0 {
			return bad("epochs")
		}
	}
	for sub, l := range s.Addresses {
		if h, ok := strings.CutPrefix(sub, KindAddress.String()+"/"); !ok || len(h) != 64 || len(l) == 0 {
			return bad("address")
		}
		for i, a := range l {
			if _, err := store.ParseID(a.Mailbox); err != nil || !in(a.Index) || a.ValidFrom < 0 || i > 0 && (a.ValidFrom <= l[i-1].ValidFrom || a.Index <= l[i-1].Index) {
				return bad("address entry")
			}
		}
	}
	for name, c := range s.Certs {
		if c == nil || len(c.Pub) != ed25519.PublicKeySize || c.Gen == 0 || c.IdentityGen == 0 || !in(c.Index) ||
			(c.Role != uint8(keys.RoleAdmin) && c.Role != uint8(keys.RoleIngest)) || certName(keys.Role(c.Role), c.Gen) != name {
			return bad("certificate")
		}
	}
	for g, c := range s.Succs {
		if c == nil || g < 2 || len(c.Pub) != ed25519.PublicKeySize || !in(c.Index) {
			return bad("succession")
		}
	}
	for _, x := range s.Invalid {
		if !in(x.Index) {
			return bad("invalid entry")
		}
	}
	return s.checkKeys()
}

// checkKeys checks that Valid holds exactly the keys that Users, Epochs,
// Addresses, Certs and Succs derive from the valid entries, with the same
// indices, and that no index is recorded twice (task 07b finding 5: a
// key copied under another number, or a count without its entries,
// would otherwise answer from the index alone). The rules admit user and
// epoch entries only in sequence 1..n, so these maps determine Valid.
func (s *state) checkKeys() error {
	bad := func(what string) error { return fmt.Errorf("%w: audit index: %s", ErrConsistency, what) }
	seen := make(map[int64]bool, len(s.Valid))
	for _, r := range s.Valid {
		if seen[r.Index] {
			return bad("index recorded twice")
		}
		seen[r.Index] = true
	}
	for _, x := range s.Invalid {
		if seen[x.Index] {
			return bad("invalid entry recorded as valid or twice")
		}
		seen[x.Index] = true
	}
	// Every entry below Size is either valid (one key) or invalid
	// (replay records exactly one of them), so the counts cover the
	// reference size (task 14b point 7: an index with the size and root
	// of the reference head but empty tables would answer "no entry" for
	// everything). The indices are distinct and below Size (checkStructure),
	// so this count is a full cover.
	if int64(len(seen)) != s.Size {
		return bad("the entries do not cover the reference size")
	}
	n := 0
	want := func(kid string, index int64) error {
		r, ok := s.Valid[kid]
		if !ok || (index >= 0 && r.Index != index) {
			return bad("valid keys do not match the entries")
		}
		n++
		return nil
	}
	for id, u := range s.Users {
		uid, _ := store.ParseID(id)
		for g := range u.Idents {
			if err := want(keyID(Key{Kind: KindUser, Subject: uid[:], Seq: int64(g + 1)}), -1); err != nil {
				return err
			}
		}
	}
	for id, c := range s.Epochs {
		// want fails at the first missing key, so a huge count costs
		// no more than len(Valid) lookups.
		mid, _ := store.ParseID(id)
		for e := uint32(1); e <= c; e++ {
			if err := want(keyID(Key{Kind: KindEpoch, Subject: mid[:], Seq: int64(e)}), -1); err != nil {
				return err
			}
		}
	}
	for sub, l := range s.Addresses {
		for _, a := range l {
			if err := want(sub+"/"+strconv.FormatInt(a.ValidFrom, 10), a.Index); err != nil {
				return err
			}
		}
	}
	for name, c := range s.Certs {
		if err := want(keyID(Key{Kind: KindPlatform, Subject: []byte(name)}), c.Index); err != nil {
			return err
		}
	}
	for g, c := range s.Succs {
		if err := want(keyID(Key{Kind: KindPlatform, Subject: []byte(succName(g))}), c.Index); err != nil {
			return err
		}
	}
	if n != len(s.Valid) {
		return bad("valid keys without their entries")
	}
	return nil
}

// ----------------------------------------------------------------- rules

// errSame reports that the key is held by a valid entry with exactly the
// same encoding (Append is idempotent then).
var errSame = errors.New("translog: same entry already logged")

// change is an admitted entry, recorded by commit or forgotten by abort.
type change struct {
	commit func(index int64)
	abort  func()
	same   int64
}

// errClass names the error class of an invalid entry.
func errClass(err error) string {
	switch {
	case errors.Is(err, ErrUnloggedSigner):
		return "unlogged-signer"
	case errors.Is(err, ErrPrerequisite):
		return "prerequisite"
	case errors.Is(err, ErrDuplicate):
		return "duplicate"
	case errors.Is(err, ErrOrder):
		return "order"
	case errors.Is(err, ErrMismatch):
		return "mismatch"
	case errors.Is(err, ErrEntry):
		return "entry"
	}
	return "consistency"
}

// admit checks the decoded entry e (content obj, leaf hash of its
// encoding) against the valid entries of s (doc.go "Validity rules"). On
// success s is unchanged until the returned change is committed; errSame
// reports the index of a valid entry with the same encoding in
// change.same.
func (s *state) admit(e *Entry, obj any, leaf tlog.Hash) (*change, error) {
	kid := keyID(e.Key)
	if r, ok := s.Valid[kid]; ok {
		if r.Leaf == leaf {
			return &change{same: r.Index}, errSame
		}
		return nil, fmt.Errorf("%w: key taken by entry %d", ErrDuplicate, r.Index)
	}
	var apply func(int64)
	abort := func() {}
	var err error
	switch o := obj.(type) {
	case *store.User:
		apply, err = s.admitUser(o)
	case *store.Epoch:
		apply, abort, err = s.admitEpoch(o, e.Content)
	case *store.AddressAssignment:
		apply, err = s.admitAddress(o)
	case *keys.PlatformCert:
		apply, err = s.admitCert(o)
	case *keys.PlatformSuccession:
		apply, err = s.admitSucc(o)
	default:
		err = fmt.Errorf("%w: unknown record", ErrEntry)
	}
	if err != nil {
		return nil, err
	}
	sub := subjectID(e.Kind, e.Subject)
	return &change{
		commit: func(index int64) {
			r := ref{Index: index, Leaf: leaf, Seq: e.Seq}
			s.Valid[kid] = r
			s.subjects[sub] = append(s.subjects[sub], r)
			apply(index)
		},
		abort: abort,
	}, nil
}

// replay applies entry index (its encoding data) to s, which must hold
// exactly the entries before it. An entry that fails the rules is
// recorded as invalid; the error is returned for the caller's warning.
func (s *state) replay(index int64, data []byte) error {
	if index != s.Size {
		return fmt.Errorf("%w: replay out of order", ErrConsistency)
	}
	e, obj, err := decodeEntry(data, index)
	if err == nil {
		var ch *change
		ch, err = s.admit(e, obj, LeafHash(data))
		switch {
		case errors.Is(err, errSame):
			err = fmt.Errorf("%w: copy of entry %d", ErrDuplicate, ch.same)
		case errors.Is(err, ErrConsistency):
			// Not a verdict on the entry: the files of earlier entries
			// changed. s is unchanged.
			return err
		case err == nil:
			ch.commit(index)
		}
	}
	if err != nil {
		s.Invalid = append(s.Invalid, InvalidEntry{Index: index, Class: errClass(err)})
	}
	s.Size++
	return err
}

func (s *state) admitUser(u *store.User) (func(int64), error) {
	id := u.ID.String()
	n := len(u.Generations)
	have := 0
	us := s.Users[id]
	if us != nil {
		have = len(us.Idents)
	}
	switch {
	case n <= have:
		// admit found no valid entry with this key, yet the state holds
		// a newer one of the user.
		return nil, fmt.Errorf("%w: user generation %d", errIndex, n)
	case n > have+1:
		return nil, fmt.Errorf("%w: user entry with %d generations is missing", ErrPrerequisite, n-1)
	}
	certs := make([]tlog.Hash, n)
	for i, c := range u.Generations {
		b, err := c.Encode()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		certs[i] = sha256.Sum256(b)
	}
	if us != nil {
		// Binds ID and root (S16): every later entry extends the first.
		if !bytes.Equal(us.Root, u.RootPub) {
			return nil, fmt.Errorf("%w: user entry names another root key", ErrOrder)
		}
		for i := 0; i < have; i++ {
			if certs[i] != us.Certs[i] {
				return nil, fmt.Errorf("%w: user entry changes generation %d", ErrOrder, i+1)
			}
		}
	}
	return func(int64) {
		ns := &userState{Root: append([]byte(nil), u.RootPub...), Certs: certs}
		for _, c := range u.Generations {
			ns.Idents = append(ns.Idents, append([]byte(nil), c.IdentityPub...))
		}
		s.Users[id] = ns
	}, nil
}

// chain returns the chain of the valid epochs of mailbox m, built from
// the entries (checked against their leaves) when not cached.
func (s *state) chain(m store.ID) (*store.Chain, error) {
	mid := m.String()
	if c, ok := s.chains[mid]; ok {
		return c, nil
	}
	c := store.NewChain()
	for n := uint32(1); n <= s.Epochs[mid]; n++ {
		k := Key{Kind: KindEpoch, Subject: m[:], Seq: int64(n)}
		r, ok := s.Valid[keyID(k)]
		if !ok {
			return nil, fmt.Errorf("%w: audit index lacks epoch %d", errIndex, n)
		}
		// The entries are checked against the leaves the state recorded,
		// without a proof: a difference may come from the state or from
		// the files; errIndex lets a client rebuild its index, and the
		// rebuild proves every entry (task 07b finding 5).
		e, obj, _, err := s.f.readEntryLeaf(r.Index, r.Leaf)
		if err != nil {
			return nil, fmt.Errorf("%w: epoch %d: %v", errIndex, n, err)
		}
		ep, ok := obj.(*store.Epoch)
		if !ok || !e.Key.Equal(k) {
			return nil, fmt.Errorf("%w: entry %d is not epoch %d", errIndex, r.Index, n)
		}
		if err := c.Add(ep, e.Content); err != nil {
			return nil, fmt.Errorf("%w: logged epoch chain: %v", errIndex, err)
		}
	}
	s.chains[mid] = c
	return c, nil
}

func (s *state) admitEpoch(e *store.Epoch, content []byte) (func(int64), func(), error) {
	mid := e.MailboxID.String()
	have := s.Epochs[mid]
	switch {
	case e.Number <= have:
		// admit found no valid entry with this key, yet the state counts
		// it.
		return nil, nil, fmt.Errorf("%w: epoch %d", errIndex, e.Number)
	case e.Number > have+1:
		return nil, nil, fmt.Errorf("%w: epoch %d of the mailbox is not logged", ErrPrerequisite, e.Number-1)
	}
	us := s.Users[e.SignerID.String()]
	if us == nil || uint64(len(us.Idents)) < uint64(e.SignerGen) {
		return nil, nil, fmt.Errorf("%w: generation %d", ErrUnloggedSigner, e.SignerGen)
	}
	if uint64(len(us.Idents)) > uint64(e.SignerGen) {
		// 2.2 rule 4: revoked before this entry.
		return nil, nil, fmt.Errorf("%w: signer generation %d was revoked before", ErrOrder, e.SignerGen)
	}
	if err := e.VerifySignature(us.Idents[e.SignerGen-1]); err != nil {
		return nil, nil, fmt.Errorf("%w: epoch signature: %v", ErrOrder, err)
	}
	c, err := s.chain(e.MailboxID)
	if err != nil {
		return nil, nil, err
	}
	if err := c.Add(e, content); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrOrder, err)
	}
	// The chain now holds e; abort forgets the cached chain.
	return func(int64) { s.Epochs[mid] = e.Number }, func() { delete(s.chains, mid) }, nil
}

func (s *state) admitAddress(a *store.AddressAssignment) (func(int64), error) {
	sub := subjectID(KindAddress, []byte(a.Address))
	list := s.Addresses[sub]
	if len(list) > 0 && a.ValidFrom <= list[len(list)-1].ValidFrom {
		return nil, fmt.Errorf("%w: valid_from does not increase", ErrOrder)
	}
	c := s.Certs[certName(keys.RoleAdmin, a.AdminGen)]
	if c == nil {
		return nil, fmt.Errorf("%w: admin certificate %d is not logged", ErrPrerequisite, a.AdminGen)
	}
	if c.ValidFrom > a.ValidFrom {
		return nil, fmt.Errorf("%w: assignment before the admin certificate", ErrOrder)
	}
	if err := a.Verify(c.Pub); err != nil {
		return nil, fmt.Errorf("%w: admin signature", ErrOrder)
	}
	return func(index int64) {
		s.Addresses[sub] = append(s.Addresses[sub], addrState{ValidFrom: a.ValidFrom, Mailbox: a.MailboxID.String(), Index: index})
	}, nil
}

// identityKey returns the key of identity generation gen: from the
// anchor's list, else from a valid succession (ErrPrerequisite).
func (s *state) identityKey(gen uint32) (ed25519.PublicKey, error) {
	if k, ok := IdentityKey(s.ids, gen); ok {
		return k, nil
	}
	if sc := s.Succs[gen]; sc != nil {
		return sc.Pub, nil
	}
	return nil, fmt.Errorf("%w: identity generation %d is neither pinned nor logged", ErrPrerequisite, gen)
}

func (s *state) admitCert(c *keys.PlatformCert) (func(int64), error) {
	if c.Gen > 1 && s.Certs[certName(c.Role, c.Gen-1)] == nil {
		return nil, fmt.Errorf("%w: certificate of generation %d is not logged", ErrPrerequisite, c.Gen-1)
	}
	k, err := s.identityKey(c.IdentityGen)
	if err != nil {
		return nil, err
	}
	if err := c.Verify(k); err != nil {
		return nil, fmt.Errorf("%w: certificate signature", ErrOrder)
	}
	return func(index int64) {
		s.Certs[certName(c.Role, c.Gen)] = &certState{Role: uint8(c.Role), Gen: c.Gen, Pub: append([]byte(nil), c.Pub...),
			IdentityGen: c.IdentityGen, ValidFrom: c.ValidFrom, Index: index}
	}, nil
}

func (s *state) admitSucc(sc *keys.PlatformSuccession) (func(int64), error) {
	prev, err := s.identityKey(sc.Gen - 1)
	if err != nil {
		return nil, err
	}
	if err := sc.Verify(prev, sc.Gen-1); err != nil {
		return nil, fmt.Errorf("%w: succession signature", ErrOrder)
	}
	if k, ok := IdentityKey(s.ids, sc.Gen); ok && !k.Equal(sc.Pub) {
		return nil, fmt.Errorf("%w: succession %d names another key than the pin", ErrMismatch, sc.Gen)
	}
	return func(index int64) {
		s.Succs[sc.Gen] = &succState{Pub: append([]byte(nil), sc.Pub...), ValidFrom: sc.ValidFrom, Index: index}
	}, nil
}
