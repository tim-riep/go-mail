package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// ErrServer reports that a server runs on the data directory: it holds
// the server lock locks/server (9.1, D70), which Publish holds itself
// for its whole run. The error wraps store.ErrLocked as well.
var ErrServer = errors.New("ceremony: a server runs on the data directory")

// maxExportFiles bounds the number of files in Out/platform/ that
// Publish reads (one ceremony writes at most six).
const maxExportFiles = 64

// platformFile is a parsed file name of section 4: <role>-<gen>.<ext>.
type platformFile struct {
	name string
	role string // identity, admin, ingest
	gen  uint32
	ext  string // pub, cert, succ
	data []byte
}

// parsePlatformName parses a file name of platform/ other than
// witnesses.rec; it accepts only the canonical form of
// store.PlatformFileName and the combinations of section 4.
func parsePlatformName(name string) (platformFile, bool) {
	base, ext, ok := strings.Cut(name, ".")
	if !ok {
		return platformFile{}, false
	}
	i := strings.LastIndexByte(base, '-')
	if i < 0 {
		return platformFile{}, false
	}
	role, num := base[:i], base[i+1:]
	g, err := strconv.ParseUint(num, 10, 32)
	if err != nil || g == 0 {
		return platformFile{}, false
	}
	f := platformFile{name: name, role: role, gen: uint32(g), ext: ext}
	if store.PlatformFileName(role, f.gen, ext) != name {
		return platformFile{}, false
	}
	switch {
	case role == "identity" && (ext == "pub" || ext == "succ"):
	case (role == "admin" || role == "ingest") && (ext == "pub" || ext == "cert"):
	default:
		return platformFile{}, false
	}
	return f, true
}

func roleOf(name string) keys.Role {
	if name == "ingest" {
		return keys.RoleIngest
	}
	return keys.RoleAdmin
}

// readExport reads Out/platform/ of an export directory strictly: only
// regular files with the names of section 4, each at most
// store.MaxRecordFile bytes.
func readExport(from string) (map[string]platformFile, []byte, error) {
	dir := filepath.Join(from, "platform")
	d, err := os.Open(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrOutDir, err)
	}
	ents, err := d.ReadDir(maxExportFiles + 1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	if len(ents) > maxExportFiles {
		return nil, nil, fmt.Errorf("%w: too many files", ErrOutDir)
	}
	files := map[string]platformFile{}
	var wrec []byte
	for _, e := range ents {
		name := e.Name()
		if !e.Type().IsRegular() {
			return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrOutDir, name)
		}
		f, ok := parsePlatformName(name)
		if !ok && name != WitnessesFile {
			return nil, nil, fmt.Errorf("%w: unexpected file %s", ErrOutDir, name)
		}
		data, err := store.ReadFileLimited(filepath.Join(dir, name), store.MaxRecordFile)
		if err != nil {
			return nil, nil, err
		}
		if name == WitnessesFile {
			wrec = data
			continue
		}
		f.data = data
		files[name] = f
	}
	return files, wrec, nil
}

// readData reads platform/<name> of the data directory; a missing file
// is (nil, nil).
func readData(st *store.Store, name string) ([]byte, error) {
	b, err := st.ReadPlatformFile(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// unknownGen reports a file that names an identity generation the pin
// does not know (operating rule of Q10 point 5).
func unknownGen(name string, g, pinGen uint32) error {
	return fmt.Errorf("%w: %s names identity generation %d, the pin knows 1 to %d; install the new pin (on the server as well) before publish (Q10 point 5)",
		translog.ErrMismatch, name, g, pinGen)
}

// checkDataPlatform applies the start check of gomail-server
// (checkPlatformPin, Q10 point 5) to platform/ of the data directory:
// no identity generation the pin does not know (identity-<g>.pub,
// identity-<g>.succ, a certificate issued by such a generation) and
// nothing that contradicts the pin's identity list (translog.ErrMismatch);
// a file that does not decode is refused as well (fail closed). Beyond
// the start check it verifies the signature of every succession (with
// the pin's key of generation g-1) and of every certificate (with the
// pin's key of its identity_gen; task 15g point 2b): a file of
// platform/ that does not verify is translog.ErrMismatch, never counted
// and never logged; the operator removes it on purpose after finding out
// where it came from. Other files (witnesses.rec, temporary files) are
// not looked at here; the successions in the log are checked by
// checkDataLog.
func checkDataPlatform(st *store.Store, pin *store.PlatformPin, known map[uint32]ed25519.PublicKey) error {
	ents, err := os.ReadDir(st.Path("platform"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		f, ok := parsePlatformName(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		if f.role == "identity" && f.gen > pin.Gen {
			return unknownGen("platform/"+f.name, f.gen, pin.Gen)
		}
		if f.ext == "pub" && f.role != "identity" {
			continue
		}
		data, err := st.ReadPlatformFile(f.name)
		if err != nil {
			return err
		}
		switch f.ext {
		case "pub":
			if !known[f.gen].Equal(ed25519.PublicKey(data)) {
				return fmt.Errorf("%w: platform/%s contradicts the identity list of the pin", translog.ErrMismatch, f.name)
			}
		case "succ":
			if err := checkDataSucc(f.name, f.gen, data, known); err != nil {
				return err
			}
		case "cert":
			c, err := keys.DecodePlatformCert(data)
			if err != nil {
				return fmt.Errorf("platform/%s: %w", f.name, err)
			}
			if c.IdentityGen > pin.Gen {
				return unknownGen("platform/"+f.name, c.IdentityGen, pin.Gen)
			}
			if c.Role != roleOf(f.role) || c.Gen != f.gen {
				return fmt.Errorf("%w: platform/%s certifies another key than its name says", translog.ErrMismatch, f.name)
			}
			if err := c.Verify(known[c.IdentityGen]); err != nil {
				return fmt.Errorf("%w: platform/%s does not verify with identity generation %d of the pin (%w); check where it came from and remove it",
					translog.ErrMismatch, f.name, c.IdentityGen, err)
			}
		}
	}
	return nil
}

// checkDataSucc checks the succession platform/<name> of the data
// directory (generation g, content data) against the identity list of
// the pin: it names generation g with the list's key and its signature
// verifies with the list's key of generation g-1 (task 15g point 2b).
// Anything else is translog.ErrMismatch (a file that does not decode is
// the error of keys): such a file neither counts as the predecessor of a
// succession nor is it logged.
func checkDataSucc(name string, g uint32, data []byte, known map[uint32]ed25519.PublicKey) error {
	s, err := keys.DecodePlatformSuccession(data)
	if err != nil {
		return fmt.Errorf("platform/%s: %w", name, err)
	}
	if s.Gen != g || !s.Pub.Equal(known[g]) {
		return fmt.Errorf("%w: platform/%s contradicts the identity list of the pin", translog.ErrMismatch, name)
	}
	if err := s.Verify(known[g-1], g-1); err != nil {
		return fmt.Errorf("%w: platform/%s does not verify with identity generation %d of the pin (%w); check where it came from and remove it",
			translog.ErrMismatch, name, g-1, err)
	}
	return nil
}

// checkDataLog extends the start check to the successions in the log
// (task 15g point 3): a valid entry identity-<g>.succ with g above the
// pin's generation names a generation the pin does not know
// (translog.ErrMismatch, Q10 point 5), even when the files of that
// generation are gone from platform/. So neither an old pin nor, after
// the files were removed, a foreign one gets past it (for a foreign pin
// the certificates of platform/ fail checkDataPlatform). For the anchor
// of the pin a succession above its list is valid only after the valid
// succession of the generation before it (translog doc.go "Validity
// rules"), so the valid successions above the list form an unbroken run
// from pin.Gen+1 on: the first generation without a valid entry ends
// the search, and the highest one found is reported.
func checkDataLog(log translog.Log, pin *store.PlatformPin) error {
	top := pin.Gen
	for g := uint64(pin.Gen) + 1; g <= math.MaxUint32; g++ {
		name := store.PlatformFileName("identity", uint32(g), "succ")
		es, err := log.Lookup(translog.KindPlatform, []byte(name))
		if err != nil {
			return fmt.Errorf("ceremony: looking up %s in the log: %w", name, err)
		}
		if len(es) == 0 {
			break
		}
		top = uint32(g)
	}
	if top > pin.Gen {
		return unknownGen("the log entry "+store.PlatformFileName("identity", top, "succ"), top, pin.Gen)
	}
	return nil
}

// witnessFile decodes a witnesses.rec (of the export or of the data
// directory, named by where) and reports whether it holds the witnesses
// and the quorum of the pin (fields 5 and 6). A file that does not
// decode is an error (fail closed, also with ReplaceWitnesses).
func witnessFile(where string, data []byte, pin *store.PlatformPin) (*witness.Witnesses, bool, error) {
	w, err := witness.DecodeWitnesses(data)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", where, err)
	}
	return w, sameWitnesses(w.List, w.Min, pinWitnesses(pin), pin.MinWitnesses), nil
}

// errWitnessFile reports a witnesses.rec that differs from the pin:
// translog.ErrMismatch, never a silent replacement (task 15b point 1).
func errWitnessFile(where, hint string) error {
	return fmt.Errorf("%w: %s differs from the witnesses and the quorum of the pin%s", translog.ErrMismatch, where, hint)
}

// replaceHint tells how a change of the witnesses made on purpose
// (succeed --witness/--min-witnesses) reaches the working copy of a data
// directory that has one (task 15f point 2).
const replaceHint = "; publish --replace-witnesses (ReplaceWitnesses) replaces it by the pin's"

// succChain decides whether the succession identity-<g>.succ of a
// generation g >= 2 is there for what Publish logs (task 15g points 1
// and 2a): an identity key identity-<g>.pub, a succession
// identity-<g+1>.succ and a certificate issued by generation g each need
// it, logged before them. It counts only
//
//   - in the export: Publish logs it in this run, successions by
//     generation, before every certificate; its own predecessor is
//     needed in turn;
//   - as a valid entry of the log (Log.Lookup, which returns valid
//     entries only, judged against the pin's identity list);
//   - in data/platform/ without a valid log entry (a crash between file
//     and log entry): only if it verifies against the pin's identity
//     list (checkDataSucc) and its own predecessor is there by the same
//     rule; Publish then logs it first (relog).
//
// A file in data/platform/ alone never counts. Without the succession
// an older pin cannot follow the chain: a client whose pin ends below g
// needs every succession up to g logged before an entry that depends on
// it, and an entry logged too early stays invalid for it for good (the
// key is taken for the newer anchors). Generation 1 needs none.
type succChain struct {
	files map[string]platformFile // the export
	st    *store.Store
	log   translog.Log
	known map[uint32]ed25519.PublicKey
	ok    map[uint32]bool         // generations found to be there
	relog map[uint32]platformFile // from data/platform/, to log first
}

// need reports translog.ErrPrerequisite when the succession of
// generation g, or one it depends on, is not there for by (the file
// name of what needs it); see succChain.
func (c *succChain) need(g uint32, by string) error {
	var found []platformFile
	var seen []uint32
	for ; g >= 2 && !c.ok[g]; g-- {
		name := store.PlatformFileName("identity", g, "succ")
		if _, ok := c.files[name]; ok {
			seen = append(seen, g)
			continue
		}
		es, err := c.log.Lookup(translog.KindPlatform, []byte(name))
		if err != nil {
			return fmt.Errorf("ceremony: looking up %s in the log: %w", name, err)
		}
		if len(es) > 0 {
			break
		}
		data, err := readData(c.st, name)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("%w: %s needs %s, which is neither in the export nor a valid entry of the log: publish the export of the succession to generation %d first",
				translog.ErrPrerequisite, by, name, g)
		}
		// Checked by checkDataPlatform already; again on what is logged.
		if err := checkDataSucc(name, g, data, c.known); err != nil {
			return err
		}
		seen = append(seen, g)
		found = append(found, platformFile{name: name, role: "identity", gen: g, ext: "succ", data: data})
	}
	for _, s := range seen {
		c.ok[s] = true
	}
	for _, f := range found {
		c.relog[f.gen] = f
	}
	return nil
}

// OpenLog opens the operator log of the data directory st as
// gomail-server does (translog.Open with the identity list and the
// origin of pin, the witnesses and the quorum of the pin as Known,
// Witnesses and MinWitnesses; D80): the tiles must match tree.rec, and
// the newest published head, if any, must open with a valid log
// signature (Head). Publish uses it when PublishOptions.Log is nil.
func OpenLog(st *store.Store, pin *store.PlatformPin) (translog.Log, error) {
	ids, err := PinIdentities(pin)
	if err != nil {
		return nil, err
	}
	ws := &witness.Witnesses{List: pinWitnesses(pin), Min: pin.MinWitnesses}
	wvs, err := ws.Verifiers()
	if err != nil {
		return nil, err
	}
	l, err := translog.Open(translog.Options{Store: st, Identities: ids, Origin: pin.Origin, Known: note.VerifierList(wvs...),
		Witnesses: wvs, MinWitnesses: ws.Min})
	if err != nil {
		return nil, err
	}
	// No published head yet (a new platform) is ErrStale; every other
	// failure of the newest head stops publish.
	if _, err := l.Head(); err != nil && !errors.Is(err, translog.ErrStale) {
		return nil, fmt.Errorf("ceremony: newest head of the log: %w", err)
	}
	return l, nil
}

func runPublish(opts PublishOptions) error {
	if opts.From == "" || opts.Data == nil || opts.Pin == nil {
		return fmt.Errorf("%w: From, Data and Pin are required", ErrOptions)
	}
	ids, err := PinIdentities(opts.Pin)
	if err != nil {
		return err
	}
	pin := opts.Pin
	st := opts.Data
	// The server must not run (9.1, D70): it judges the log and platform/
	// against the pin it started with. Publish holds the server lock for
	// its whole run, so that no server starts meanwhile either.
	release, err := st.HoldRoleLock(store.RoleServer)
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			return fmt.Errorf("%w (locks/server): stop it, publish, then start it with the new pin: %w", ErrServer, err)
		}
		return err
	}
	defer release()
	if err := hook("publish-lock"); err != nil {
		return err
	}

	// Identity keys: exactly the pin's list. A generation above it is
	// one the pin does not know: the operator installs the new pin first
	// (Q10 point 5), in the export as in data/platform/.
	known := map[uint32]ed25519.PublicKey{}
	for _, id := range ids {
		known[id.Gen] = id.Pub
	}
	if err := checkDataPlatform(st, pin, known); err != nil {
		return err
	}
	files, wrec, err := readExport(opts.From)
	if err != nil {
		return err
	}
	if wrec != nil {
		// The export's must be the pin's, with ReplaceWitnesses as well.
		where := "export " + WitnessesFile
		_, same, err := witnessFile(where, wrec, pin)
		if err != nil {
			return err
		}
		if !same {
			return errWitnessFile(where, "")
		}
	}
	haveW, err := readData(st, WitnessesFile)
	if err != nil {
		return err
	}
	// oldW is the working copy to replace (ReplaceWitnesses), nil if
	// none is replaced.
	var oldW *witness.Witnesses
	if haveW != nil {
		where := "platform/" + WitnessesFile
		w, same, err := witnessFile(where, haveW, pin)
		if err != nil {
			return err
		}
		if !same {
			if !opts.ReplaceWitnesses {
				return errWitnessFile(where, replaceHint)
			}
			oldW = w
		}
	}
	log := opts.Log
	if log == nil {
		if log, err = OpenLog(st, pin); err != nil {
			return err
		}
	}
	if err := checkDataLog(log, pin); err != nil {
		return err
	}
	chain := &succChain{files: files, st: st, log: log, known: known, ok: map[uint32]bool{}, relog: map[uint32]platformFile{}}

	var succs []platformFile
	for _, f := range files {
		if f.role == "identity" && f.gen > pin.Gen {
			return unknownGen(f.name, f.gen, pin.Gen)
		}
		if f.ext != "succ" {
			continue
		}
		s, err := keys.DecodePlatformSuccession(f.data)
		if err != nil {
			return err
		}
		if s.Gen != f.gen {
			return fmt.Errorf("%w: %s holds generation %d", ErrOutDir, f.name, s.Gen)
		}
		if f.gen < 2 {
			return fmt.Errorf("%w: %s", translog.ErrOrder, f.name)
		}
		if !known[f.gen].Equal(s.Pub) {
			return fmt.Errorf("%w: %s contradicts the pin", translog.ErrMismatch, f.name)
		}
		if err := s.Verify(known[f.gen-1], f.gen-1); err != nil {
			return fmt.Errorf("%w: %s: %w", translog.ErrOrder, f.name, err)
		}
		if err := chain.need(f.gen, f.name); err != nil {
			return err
		}
		succs = append(succs, f)
	}

	// Public keys and certificates.
	var certs []platformFile
	for _, f := range files {
		switch {
		case f.role == "identity" && f.ext == "pub":
			if !known[f.gen].Equal(ed25519.PublicKey(f.data)) {
				return fmt.Errorf("%w: %s differs from the trusted identity", ErrIdentity, f.name)
			}
			// No identity key without its succession (task 15g point 1):
			// a key of generation g >= 2 alone is the state of the
			// compromise case, which is locked (Q19).
			if err := chain.need(f.gen, f.name); err != nil {
				return err
			}
		case f.ext == "pub":
			if _, ok := files[store.PlatformFileName(f.role, f.gen, "cert")]; !ok {
				return fmt.Errorf("%w: %s without certificate", ErrOutDir, f.name)
			}
		case f.ext == "cert":
			c, err := keys.DecodePlatformCert(f.data)
			if err != nil {
				return err
			}
			if c.Role != roleOf(f.role) || c.Gen != f.gen {
				return fmt.Errorf("%w: %s certifies another key", ErrOutDir, f.name)
			}
			pub, ok := files[store.PlatformFileName(f.role, f.gen, "pub")]
			if !ok || !c.Pub.Equal(ed25519.PublicKey(pub.data)) {
				return fmt.Errorf("%w: %s without matching public key", ErrOutDir, f.name)
			}
			idKey, ok := known[c.IdentityGen]
			if !ok {
				return unknownGen(f.name, c.IdentityGen, pin.Gen)
			}
			if err := c.Verify(idKey); err != nil {
				return fmt.Errorf("%w: %s: %w", translog.ErrOrder, f.name, err)
			}
			// The issuing generation's succession is logged before the
			// certificate (a client with an older pin checks it with the
			// key the succession names).
			if err := chain.need(c.IdentityGen, f.name); err != nil {
				return err
			}
			if f.gen > 1 {
				prev := store.PlatformFileName(f.role, f.gen-1, "cert")
				if _, ok := files[prev]; !ok {
					if _, err := st.ReadPlatformCert(roleOf(f.role), f.gen-1); err != nil {
						if errors.Is(err, store.ErrNotFound) {
							return fmt.Errorf("%w: %s needs %s", translog.ErrPrerequisite, f.name, prev)
						}
						return err
					}
				}
			}
			certs = append(certs, f)
		}
	}

	// Existing files: identical ones are skipped, others refused before
	// anything is written.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var todo []string
	for _, n := range names {
		have, err := readData(st, n)
		if err != nil {
			return err
		}
		if have == nil {
			todo = append(todo, n)
			continue
		}
		if !bytes.Equal(have, files[n].data) {
			return existsErr(files[n])
		}
	}

	// Files first (translog doc.go "Who writes": record first, then log
	// entry), public keys before the records that name them.
	sort.SliceStable(todo, func(i, j int) bool {
		return files[todo[i]].ext == "pub" && files[todo[j]].ext != "pub"
	})
	for _, n := range todo {
		if err := st.WritePlatformFile(n, files[n].data); err != nil {
			if !errors.Is(err, store.ErrExists) {
				return err
			}
			have, rerr := readData(st, n)
			if rerr != nil {
				return rerr
			}
			if !bytes.Equal(have, files[n].data) {
				return existsErr(files[n])
			}
		}
		if err := hook("publish-file"); err != nil {
			return err
		}
	}
	if haveW == nil || oldW != nil {
		// The working copy of the server, from the pin (the export's
		// witnesses.rec is the same, checked above): written when the
		// data directory has none, or replaced on purpose
		// (ReplaceWitnesses, task 15f point 2), atomically and under the
		// server lock, after every check passed.
		w := wrec
		if w == nil {
			if w, err = checkTrust(pin.Origin, pinWitnesses(pin), pin.MinWitnesses); err != nil {
				return err
			}
		}
		if err := store.WriteFileAtomic(st.Path("platform", WitnessesFile), w); err != nil {
			return err
		}
		if oldW != nil && opts.WitnessesReplaced != nil {
			opts.WitnessesReplaced(oldW, &witness.Witnesses{List: pinWitnesses(pin), Min: pin.MinWitnesses})
		}
	}
	if err := hook("publish-log"); err != nil {
		return err
	}

	// Log: successions by generation (the export's and those of
	// data/platform/ that were not logged yet, task 15g point 2a), then
	// certificates by role and generation.
	for _, f := range chain.relog {
		succs = append(succs, f)
	}
	sort.Slice(succs, func(i, j int) bool { return succs[i].gen < succs[j].gen })
	sort.Slice(certs, func(i, j int) bool {
		ri, rj := roleOf(certs[i].role), roleOf(certs[j].role)
		if ri != rj {
			return ri < rj
		}
		return certs[i].gen < certs[j].gen
	})
	for _, f := range append(succs, certs...) {
		if err := log.AppendPlatform(f.name, f.data); err != nil {
			return fmt.Errorf("ceremony: logging %s: %w", f.name, err)
		}
	}
	return nil
}

// existsErr reports a file of the data directory with other content;
// for a certificate or succession it is also a duplicate log key.
func existsErr(f platformFile) error {
	if f.ext == "pub" {
		return fmt.Errorf("%w: %s with other content", store.ErrExists, f.name)
	}
	return fmt.Errorf("%w: %w: %s with other content", store.ErrExists, translog.ErrDuplicate, f.name)
}
