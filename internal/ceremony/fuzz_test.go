package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog/translogtest"
	"github.com/tim-riep/go-mail/internal/witness"
)

// Fuzz targets of task 26E for what the ceremony reads from disk: the
// export directory of a ceremony (readExport, and Publish of it into an
// empty data directory) and platform/ of the data directory
// (checkDataPlatform). The input describes the entries of the directory
// (fuzzEntries); every input gets directories of its own under
// t.TempDir.

// heapAllocated returns the bytes the heap allocated while f ran
// (runtime.MemStats.TotalAlloc, whatever was freed again).
func heapAllocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// fuzzAllocBase bounds the heap one input may allocate besides
// fuzzAllocPerByte for every byte of input: readExport reads at most
// maxExportFiles files of store.MaxRecordFile bytes (4 MiB), and the
// entries near that limit are made by the harness, not by the input.
const (
	fuzzAllocBase    = 32 << 20
	fuzzAllocPerByte = 256
)

// Kinds of a fuzz entry (fuzzEntry.kind, low two bits); kindBig pads
// the content of a file with zero bytes to about store.MaxRecordFile.
const (
	kindFile = iota
	kindDir
	kindSymlink // to a regular file with the content, outside the directory
	kindHard    // a hard link to the regular file before it (a file if none)
	kindBig     = 4
)

// fuzzEntry is one entry of a directory made from the input.
type fuzzEntry struct {
	kind uint8
	name string
	data []byte
}

// fuzzEntries cuts the input into entries: a kind byte, a name length
// byte, the name, a 2-byte big-endian content length and the content;
// a short entry takes what is left.
func fuzzEntries(in []byte) []fuzzEntry {
	var out []fuzzEntry
	for len(in) >= 2 {
		kind, nl := in[0], int(in[1])
		in = in[2:]
		nl = min(nl, len(in))
		name := string(in[:nl])
		in = in[nl:]
		dl := 0
		if len(in) >= 2 {
			dl = int(binary.BigEndian.Uint16(in))
			in = in[2:]
		}
		dl = min(dl, len(in))
		out = append(out, fuzzEntry{kind: kind, name: name, data: in[:dl]})
		in = in[dl:]
	}
	return out
}

// joinEntries is the inverse of fuzzEntries, for seeds.
func joinEntries(es ...fuzzEntry) []byte {
	var out []byte
	for _, e := range es {
		out = append(out, e.kind, byte(len(e.name)))
		out = append(out, e.name...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.data)))
		out = append(out, e.data...)
	}
	return out
}

// made is what writeEntries put under one name.
type made struct {
	kind uint8 // kindFile (also for a hard link), kindDir or kindSymlink
	data []byte
}

// writeEntries makes the entries in dir (which exists); the targets of
// symbolic links go to aside. Names that cannot be a directory entry, or
// repeat one, are skipped. It returns what each name holds.
func writeEntries(t *testing.T, dir, aside string, es []fuzzEntry) map[string]made {
	out := map[string]made{}
	last := ""
	for i, e := range es {
		if e.name == "" || e.name == "." || e.name == ".." || strings.ContainsAny(e.name, "/\x00") {
			continue
		}
		if _, ok := out[e.name]; ok {
			continue
		}
		p := filepath.Join(dir, e.name)
		data := e.data
		if e.kind&kindBig != 0 {
			data = append(bytes.Clone(data), make([]byte, max(0, store.MaxRecordFile-2+len(data)%4-len(data)))...)
		}
		var err error
		kind := e.kind & 3
		switch {
		case kind == kindDir:
			err = os.Mkdir(p, 0o700)
		case kind == kindSymlink:
			target := filepath.Join(aside, strconv.Itoa(i))
			if err = os.WriteFile(target, data, 0o600); err == nil {
				err = os.Symlink(target, p)
			}
		case kind == kindHard && last != "":
			err = os.Link(filepath.Join(dir, last), p)
			kind, data = kindFile, out[last].data
		default:
			kind = kindFile
			err = os.WriteFile(p, data, 0o600)
		}
		if err != nil {
			// A name the file system refuses (too long, not valid UTF-8 on
			// some systems) is skipped.
			continue
		}
		out[e.name] = made{kind: kind, data: data}
		if kind == kindFile {
			last = e.name
		}
	}
	return out
}

// platformName is the grammar of the file names of section 4 in
// platform/, as a pattern (readExport and checkDataPlatform use
// parsePlatformName); the generation must also fit in 32 bits.
var platformName = regexp.MustCompile(`^(identity-([1-9][0-9]*)\.(pub|succ)|(admin|ingest)-([1-9][0-9]*)\.(pub|cert))$`)

func validPlatformName(name string) bool {
	m := platformName.FindStringSubmatch(name)
	if m == nil {
		return false
	}
	g := m[2] + m[5]
	_, err := strconv.ParseUint(g, 10, 32)
	return err == nil
}

// fuzzCeremony is the platform of the ceremony targets: a root with
// identity generations 1 to 3, the pin of generation 2 (identities 1 and
// 2, one witness) and the files a ceremony writes for it. good holds the
// files that are valid under the pin; beyond those of generation 3,
// which the pin does not know yet.
type fuzzCeremony struct {
	pin    *store.PlatformPin
	known  map[uint32]ed25519.PublicKey
	good   map[string][]byte
	beyond map[string][]byte
}

func newFuzzCeremony(f *testing.F) *fuzzCeremony {
	seed := keys.Seed{26, 0xe}
	root := keys.DerivePlatform(&seed)
	f.Cleanup(root.Zero)
	must := func(b []byte, err error) []byte {
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	id := map[uint32]ed25519.PrivateKey{}
	for g := uint32(1); g <= 3; g++ {
		k, err := root.IdentityKey(g)
		if err != nil {
			f.Fatal(err)
		}
		id[g] = k
	}
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	c := &fuzzCeremony{good: map[string][]byte{}, beyond: map[string][]byte{}}
	put := func(into map[string][]byte, name string, data []byte) { into[name] = data }
	succ := func(g uint32) []byte {
		s, err := keys.NewPlatformSuccession(id[g-1], g, pub(id[g]), testNow.UnixMilli())
		if err != nil {
			f.Fatal(err)
		}
		return must(s.Encode())
	}
	cert := func(idGen uint32, role keys.Role, g uint32) (pubKey, certData []byte) {
		var k ed25519.PrivateKey
		var err error
		if role == keys.RoleAdmin {
			k, err = root.AdminKey(g)
		} else {
			k, err = root.IngestKey(g)
		}
		if err != nil {
			f.Fatal(err)
		}
		pc, err := keys.NewPlatformCert(id[idGen], idGen, role, g, pub(k), testNow.UnixMilli())
		if err != nil {
			f.Fatal(err)
		}
		return pub(k), must(pc.Encode())
	}
	put(c.good, "identity-1.pub", pub(id[1]))
	put(c.good, "identity-2.pub", pub(id[2]))
	put(c.good, "identity-2.succ", succ(2))
	put(c.beyond, "identity-3.pub", pub(id[3]))
	put(c.beyond, "identity-3.succ", succ(3))
	for _, x := range []struct {
		idGen uint32
		role  keys.Role
		name  string
		gen   uint32
		into  map[string][]byte
	}{
		{1, keys.RoleAdmin, "admin", 1, c.good}, {1, keys.RoleIngest, "ingest", 1, c.good},
		{2, keys.RoleAdmin, "admin", 2, c.good}, {2, keys.RoleIngest, "ingest", 2, c.good},
		{3, keys.RoleIngest, "ingest", 3, c.beyond},
	} {
		p, cd := cert(x.idGen, x.role, x.gen)
		put(x.into, store.PlatformFileName(x.name, x.gen, "pub"), p)
		put(x.into, store.PlatformFileName(x.name, x.gen, "cert"), cd)
	}
	wseed := bytes.Repeat([]byte{0x26}, ed25519.SeedSize)
	wkey := witness.Key{Name: "w1", Pub: pub(ed25519.NewKeyFromSeed(wseed))}
	put(c.good, WitnessesFile, must((&witness.Witnesses{List: []witness.Key{wkey}, Min: 1}).Encode()))
	c.pin = &store.PlatformPin{Gen: 2, Pub: pub(id[2]), Origin: "go-mail.test/log",
		Witnesses: []store.Witness{{Name: wkey.Name, Pub: wkey.Pub}}, MinWitnesses: 1,
		Identities: []store.PlatformIdentity{{Gen: 1, Pub: pub(id[1])}, {Gen: 2, Pub: pub(id[2])}}}
	if _, err := c.pin.Encode(); err != nil {
		f.Fatal(err)
	}
	ids, err := PinIdentities(c.pin)
	if err != nil {
		f.Fatal(err)
	}
	c.known = map[uint32]ed25519.PublicKey{}
	for _, i := range ids {
		c.known[i.Gen] = i.Pub
	}
	return c
}

// seeds adds the exports of a ceremony and variants to the corpus.
func (c *fuzzCeremony) seeds(f *testing.F) {
	files := func(from map[string][]byte, kind uint8, names ...string) []fuzzEntry {
		var es []fuzzEntry
		for _, n := range names {
			es = append(es, fuzzEntry{kind: kind, name: n, data: from[n]})
		}
		return es
	}
	g, b := c.good, c.beyond
	initExport := files(g, kindFile, "identity-1.pub", "admin-1.pub", "admin-1.cert", "ingest-1.pub", "ingest-1.cert", WitnessesFile)
	succExport := files(g, kindFile, "identity-2.pub", "identity-2.succ", "admin-2.pub", "admin-2.cert", "ingest-2.pub", "ingest-2.cert")
	f.Add(joinEntries(initExport...))
	f.Add(joinEntries(append(initExport, succExport...)...))
	f.Add(joinEntries(succExport...))
	f.Add(joinEntries(append(initExport, files(b, kindFile, "identity-3.pub", "identity-3.succ", "ingest-3.pub", "ingest-3.cert")...)...))
	f.Add(joinEntries(append(initExport, fuzzEntry{kind: kindSymlink, name: "admin-2.cert", data: g["admin-2.cert"]})...))
	f.Add(joinEntries(append(initExport, fuzzEntry{kind: kindHard, name: "ingest-2.cert"})...))
	f.Add(joinEntries(append(initExport, fuzzEntry{kind: kindDir, name: "admin-2.cert"})...))
	f.Add(joinEntries(append(initExport, fuzzEntry{kind: kindBig, name: "ingest-2.cert", data: g["ingest-2.cert"]})...))
	f.Add(joinEntries(fuzzEntry{kind: kindFile, name: "identity-01.pub", data: g["identity-1.pub"]},
		fuzzEntry{kind: kindFile, name: "ingest-4294967296.cert"}, fuzzEntry{kind: kindFile, name: ".tmp-x"}))
	f.Add(joinEntries(files(g, kindFile, "admin-1.cert")[0], fuzzEntry{kind: kindFile, name: "admin-2.cert", data: g["admin-1.cert"]}))
	// Empty files under valid names (review of task 26E, B3): an empty
	// identity key equals the missing key of a generation the pin does
	// not know (identity-3.pub), so only the check of the generation
	// against the pin refuses it.
	for _, name := range []string{"identity-3.pub", "identity-1.pub", "identity-2.succ", "admin-1.cert", "ingest-3.cert", "admin-1.pub"} {
		f.Add(joinEntries(fuzzEntry{kind: kindFile, name: name}))
	}
	f.Add(joinEntries(append(initExport, fuzzEntry{kind: kindFile, name: "identity-3.pub"})...))
	// One file more than maxExportFiles, each empty under a valid name.
	var many []fuzzEntry
	for i := 1; i <= maxExportFiles+1; i++ {
		many = append(many, fuzzEntry{kind: kindFile, name: store.PlatformFileName("admin", uint32(i), "pub")})
	}
	f.Add(joinEntries(many...))
	f.Add(joinEntries(many[:maxExportFiles]...))
	f.Add([]byte{})
}

// FuzzReadExport makes Out/platform/ of an export directory from the
// input and reads it with readExport, as Publish does first. Nothing may
// panic; an export that readExport accepts holds at most maxExportFiles
// entries, each a regular file of at most store.MaxRecordFile bytes
// under a name of section 4 or witnesses.rec, and it returns exactly
// those files with their content. Then Publish writes the export into an
// empty data directory (with a log that records): what it accepts, it
// writes and logs only as the genuine files of the platform that are
// valid under the pin (the fuzzer cannot sign, so every certificate,
// succession and key Publish takes must be one of them byte for byte).
// The heap that readExport and Publish each allocate is bounded.
func FuzzReadExport(f *testing.F) {
	c := newFuzzCeremony(f)
	c.seeds(f)
	unv, err := translogtest.NewUnverified(true)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		base := t.TempDir()
		out, aside := filepath.Join(base, "out"), filepath.Join(base, "aside")
		for _, d := range []string{filepath.Join(out, "platform"), aside} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		es := writeEntries(t, filepath.Join(out, "platform"), aside, fuzzEntries(in))
		// used counts the heap of readExport and Publish only.
		var files map[string]platformFile
		var wrec []byte
		var err error
		used := heapAllocated(func() { files, wrec, err = readExport(out) })
		limit := uint64(fuzzAllocBase + fuzzAllocPerByte*len(in))
		if used > limit {
			t.Fatalf("readExport allocated %d bytes for %d bytes of input (bound %d)", used, len(in), limit)
		}
		if err != nil {
			return
		}
		if bad := checkExport(es, files, wrec); bad != "" {
			t.Fatal(bad)
		}
		st, err := store.Init(filepath.Join(base, "data"))
		if err != nil {
			t.Fatal(err)
		}
		log := &recLog{Unverified: unv}
		used = heapAllocated(func() { err = Publish(PublishOptions{From: out, Data: st, Log: log, Pin: c.pin}) })
		if used > limit {
			t.Fatalf("Publish allocated %d bytes for %d bytes of input (bound %d)", used, len(in), limit)
		}
		if err != nil {
			return
		}
		if bad := c.onlyGood(st, log); bad != "" {
			t.Fatal(bad)
		}
	})
}

// checkExport reports the first rule of readExport that the accepted
// export (files, wrec) breaks against what the directory held (es), ""
// if none.
func checkExport(es map[string]made, files map[string]platformFile, wrec []byte) string {
	if len(es) > maxExportFiles {
		return fmt.Sprintf("accepted %d entries", len(es))
	}
	n := 0
	for name, m := range es {
		switch {
		case m.kind != kindFile:
			return fmt.Sprintf("accepted %s, which is no regular file", name)
		case len(m.data) > store.MaxRecordFile:
			return fmt.Sprintf("accepted %s of %d bytes", name, len(m.data))
		case name == WitnessesFile:
			if wrec == nil || !bytes.Equal(wrec, m.data) {
				return "witnesses.rec not returned as it is"
			}
			continue
		case !validPlatformName(name):
			return fmt.Sprintf("accepted the name %q", name)
		}
		pf, ok := files[name]
		if !ok || !bytes.Equal(pf.data, m.data) || pf.name != name ||
			store.PlatformFileName(pf.role, pf.gen, pf.ext) != name {
			return fmt.Sprintf("%s not returned as it is", name)
		}
		n++
	}
	if len(files) != n {
		return fmt.Sprintf("returned %d files for %d in the directory", len(files), n)
	}
	if _, ok := es[WitnessesFile]; !ok && wrec != nil {
		return "returned a witnesses.rec the directory does not hold"
	}
	return ""
}

// onlyGood reports a file of platform/ in st or an entry of log that is
// not a genuine file of the platform valid under the pin, "" if none.
func (c *fuzzCeremony) onlyGood(st *store.Store, log *recLog) string {
	ents, err := os.ReadDir(st.Path("platform"))
	if err != nil {
		return err.Error()
	}
	for _, e := range ents {
		data, err := os.ReadFile(st.Path("platform", e.Name()))
		if err != nil || !e.Type().IsRegular() {
			return fmt.Sprintf("platform/%s written as no regular file (%v)", e.Name(), err)
		}
		if g, ok := c.good[e.Name()]; !ok || !bytes.Equal(g, data) {
			return fmt.Sprintf("Publish wrote platform/%s, which is not the genuine file", e.Name())
		}
	}
	for name, data := range log.logged {
		if g, ok := c.good[name]; !ok || !bytes.Equal(g, data) {
			return fmt.Sprintf("Publish logged %s, which is not the genuine file", name)
		}
	}
	return ""
}

// FuzzCheckDataPlatform makes platform/ of a data directory from the
// input and runs checkDataPlatform with the pin of generation 2 on
// platform/ opened by openPlatformDir, as Publish does before it reads
// the export. Nothing may panic; when it accepts, every regular file
// under a name of section 4 that it checks (identity keys, successions
// and certificates; the public keys of admin and ingest generations are
// not its business, nor are links and other entries) is the genuine
// file of that name that is valid under the pin, byte for byte: no
// identity generation the pin does not know, nothing that contradicts
// its identity list or fails to verify. The heap that checkDataPlatform
// allocates is bounded.
func FuzzCheckDataPlatform(f *testing.F) {
	c := newFuzzCeremony(f)
	c.seeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		base := t.TempDir()
		st, err := store.Init(filepath.Join(base, "data"))
		if err != nil {
			t.Fatal(err)
		}
		aside := filepath.Join(base, "aside")
		if err := os.Mkdir(aside, 0o700); err != nil {
			t.Fatal(err)
		}
		es := writeEntries(t, st.Path("platform"), aside, fuzzEntries(in))
		// platform/ opened as Publish opens it (openPlatformDir, backlog
		// 72): checkDataPlatform lists and reads through that root.
		pd, _, err := openPlatformDir(st)
		if err != nil {
			t.Fatal(err)
		}
		var cerr error
		used := heapAllocated(func() { cerr = checkDataPlatform(st, pd, c.pin, c.known) })
		if err := pd.Close(); err != nil {
			t.Fatal(err)
		}
		if cerr == nil {
			for name, m := range es {
				f, ok := parsePlatformName(name)
				if m.kind != kindFile || !ok || f.ext == "pub" && f.role != "identity" {
					continue
				}
				if g, ok := c.good[name]; !ok || !bytes.Equal(g, m.data) {
					t.Fatalf("accepted platform/%s, which is not the genuine file valid under the pin", name)
				}
			}
		}
		if limit := uint64(fuzzAllocBase + fuzzAllocPerByte*len(in)); used > limit {
			t.Fatalf("allocated %d bytes for %d bytes of input (bound %d)", used, len(in), limit)
		}
	})
}
