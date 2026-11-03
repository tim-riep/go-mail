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
	"time"

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
// store.MaxRecordFile bytes. platform/ is opened with store.OpenDir
// (task 20b point 5): a FIFO there is ErrOutDir at once, not a hang.
func readExport(from string) (map[string]platformFile, []byte, error) {
	dir := filepath.Join(from, "platform")
	d, err := store.OpenDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrOutDir, err)
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
// key is taken for the newer anchors). Generation 1 needs none, and
// neither does a generation g whose predecessor g-1 the pin revokes
// (field 7, D93 (4)): it entered the identity list by Succeed with
// Compromised, without succession; a client knows it from the pin
// alone (an older pin cannot follow it at all, it needs the client
// update), and the chain starts anew at g.
type succChain struct {
	files map[string]platformFile // the export
	st    *store.Store
	log   translog.Log
	known map[uint32]ed25519.PublicKey
	rev   []translog.Revoked      // field 7 of the pin
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
		if _, ok := translog.FindRevoked(c.rev, store.KeyRoleIdentity, g-1); ok {
			// After a compromise of g-1: g needs no succession.
			seen = append(seen, g)
			break
		}
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
// gomail-server does (translog.Open with the identity list, the
// revocation list (field 7, D93) and the origin of pin, the witnesses
// and the quorum of the pin as Known, Witnesses and MinWitnesses; D80):
// the tiles must match tree.rec, and the newest published head, if
// any, must open with a valid log signature (Head). Publish uses it when
// PublishOptions.Log is nil.
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
	l, err := translog.Open(translog.Options{Store: st, Identities: ids, Revoked: revokedOf(pin.Revoked), Origin: pin.Origin,
		Known: note.VerifierList(wvs...), Witnesses: wvs, MinWitnesses: ws.Min})
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
	rev := revokedOf(pin.Revoked)
	// Field 7 against the log and data/platform/ (D93); next is the
	// smallest log index an entry appended now can get, as far as the
	// newest published head tells.
	var next int64
	if len(rev) > 0 {
		h, err := checkRevocations(log, pin)
		if err != nil {
			return err
		}
		if err := checkSuccessors(log, files, rev); err != nil {
			return err
		}
		next = h.Size
		if opts.RevocationsChecked != nil {
			opts.RevocationsChecked(h)
		}
		if opts.RevokedHead != nil {
			if err := revokedHead(log, h, opts.RevokedHead); err != nil {
				return err
			}
		}
		if opts.IngestGap != nil {
			if err := ingestGaps(log, files, rev, opts.IngestGap); err != nil {
				return err
			}
		}
	}
	chain := &succChain{files: files, st: st, log: log, known: known, rev: rev, ok: map[uint32]bool{}, relog: map[uint32]platformFile{}}

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
			// No identity key without its succession (task 15g point 1),
			// unless the pin revokes its predecessor (compromise, D93
			// (4); succChain).
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
			// The predecessor <role>-<g-1>.cert must be in the export or a
			// valid entry of the log, as Append requires it (translog
			// doc.go "Validity rules"): checked here, before any file is
			// written (attack review 21c F1: a detour to generation g+1
			// past an invalid entry of generation g left its files in
			// data/platform/). A file in data/platform/ alone does not
			// count; nor does an invalid entry (for example the thief's
			// certificate that field 7 invalidates).
			if f.gen > 1 {
				prev := store.PlatformFileName(f.role, f.gen-1, "cert")
				if _, ok := files[prev]; !ok {
					es, err := log.Lookup(translog.KindPlatform, []byte(prev))
					if err != nil {
						return fmt.Errorf("ceremony: looking up %s in the log: %w", prev, err)
					}
					if len(es) == 0 {
						return fmt.Errorf("%w: %s needs %s, which is neither in the export nor a valid entry of the log: publish the export of %s generation %d first",
							translog.ErrPrerequisite, f.name, prev, f.role, f.gen-1)
					}
				}
			}
			certs = append(certs, f)
		}
	}

	// Field 7 (D93 (2)): nothing that the pin's revocations make invalid
	// at the index it would get is written or logged; the successions
	// relogged from data/platform/ included.
	for _, f := range chain.relog {
		if err := checkNotRevoked(log, f, f.gen-1, rev, next); err != nil {
			return err
		}
	}
	for _, f := range succs {
		if err := checkNotRevoked(log, f, f.gen-1, rev, next); err != nil {
			return err
		}
	}
	for _, f := range certs {
		c, err := keys.DecodePlatformCert(f.data)
		if err != nil {
			return err
		}
		if err := checkNotRevoked(log, f, c.IdentityGen, rev, next); err != nil {
			return err
		}
	}

	// Existing files: identical ones are skipped; one with other content
	// is replaced only when its name is free in the log (freeName), and
	// refused otherwise, before anything is written.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var todo []string
	replace := map[string]bool{}
	for _, n := range names {
		have, err := readData(st, n)
		if err != nil {
			return err
		}
		if have == nil {
			todo = append(todo, n)
			continue
		}
		if bytes.Equal(have, files[n].data) {
			continue
		}
		free, why, err := freeName(st, log, files, n)
		if err != nil {
			return err
		}
		if !free {
			return existsErr(opts.From, st, files[n], why)
		}
		todo = append(todo, n)
		replace[n] = true
	}

	// Files first (translog doc.go "Who writes": record first, then log
	// entry), public keys before the records that name them (so that a
	// crash between the replacement of a public key and that of its
	// certificate leaves a certificate that differs and is replaced on
	// the next run).
	sort.SliceStable(todo, func(i, j int) bool {
		return files[todo[i]].ext == "pub" && files[todo[j]].ext != "pub"
	})
	for _, n := range todo {
		if replace[n] {
			// Under the server lock, after every check, atomically.
			if err := store.WriteFileAtomic(st.Path("platform", n), files[n].data); err != nil {
				return err
			}
		} else if err := st.WritePlatformFile(n, files[n].data); err != nil {
			if !errors.Is(err, store.ErrExists) {
				return err
			}
			have, rerr := readData(st, n)
			if rerr != nil {
				return rerr
			}
			if !bytes.Equal(have, files[n].data) {
				return existsErr(opts.From, st, files[n], " (written meanwhile)")
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

// freeName decides whether platform/<n> of the data directory, which
// differs from the export's file n, may be replaced by it (attack review
// 21c F1; translog doc.go "Reading for the operator": a certificate that
// field 7 makes invalid holds no key, and <role>-<g>.cert is reissued
// under the new identity with the same name). A certificate or
// succession is replaced when the log holds no valid entry of its name
// under the pin (Log.Lookup returns valid entries only): the entry there
// is invalid (such as the thief's certificate issued with a revoked
// identity generation at or above its revoked_at_size, class "revoked")
// or there is none (a file left by a crash before its log entry, which
// gives nobody anything: translog doc.go "Platform generations"). The
// public key <role>-<g>.pub of an admin or ingest generation is replaced
// only together with its certificate: when <role>-<g>.cert of the data
// directory differs from the export's and is replaced by this rule.
// Everything else is refused; why completes the message (existsErr).
// The caller has checked the export's files already (signature, pin,
// field 7, prerequisites).
func freeName(st *store.Store, log translog.Log, files map[string]platformFile, n string) (bool, string, error) {
	f := files[n]
	cert := n
	if f.ext == "pub" {
		if f.role == "identity" {
			return false, "", nil
		}
		cert = store.PlatformFileName(f.role, f.gen, "cert")
		have, err := readData(st, cert)
		if err != nil {
			return false, "", err
		}
		if have == nil || bytes.Equal(have, files[cert].data) {
			return false, fmt.Sprintf(", while platform/%s is missing there or the same: a public key is replaced only together with its certificate", cert), nil
		}
	}
	es, err := log.Lookup(translog.KindPlatform, []byte(cert))
	if err != nil {
		return false, "", fmt.Errorf("ceremony: looking up %s in the log: %w", cert, err)
	}
	if len(es) > 0 {
		return false, fmt.Sprintf(", and %s is a valid entry of the log under this pin: a valid entry is never replaced", cert), nil
	}
	return true, "", nil
}

// existsErr reports a file of the data directory with other content than
// the export's file f (export directory from), naming both files; for a
// certificate or succession it is also a duplicate log key. why
// completes the message.
func existsErr(from string, st *store.Store, f platformFile, why string) error {
	what := fmt.Sprintf("%s with other content than %s of the export%s",
		st.Path("platform", f.name), filepath.Join(from, "platform", f.name), why)
	if f.ext == "pub" {
		return fmt.Errorf("%w: %s", store.ErrExists, what)
	}
	return fmt.Errorf("%w: %w: %s", store.ErrExists, translog.ErrDuplicate, what)
}

// checkRevocations checks field 7 of pin against the log (D93;
// PublishOptions, Publish) and returns the newest published head it
// checked against: the head must exist and carry the witness quorum of
// the pin (the boundaries come from a witness-confirmed head of this
// log), every revoked_at_size must be at most its size and every
// revoked_at_time - 1 ms (the time of the head the boundary was read
// from, D93 addendum) at most its time (a later boundary would leave
// entries of a compromised generation valid that this log already
// holds: a mistyped value or a head of another log) and not before
// minHeadTime (a time in seconds); the certificate of every revoked
// admin or ingest generation must be a valid entry of the log below that
// element's revoked_at_size (a mistyped generation would leave the
// compromised one valid, and without such a certificate no certificate
// of the role can become valid any more: translog doc.go "Reading for
// the operator"), and its revoked_at_time must lie after the
// certificate's valid_from unless that lies after the head's time (the
// generation would never have been valid: attack review 21c F2). A
// revoked identity generation is in the identity list of the pin by
// store.CheckPinRevoked. Every failure is ErrRevocation.
//
// The newest published head is the one the operator log opens (OpenLog,
// translog Log.Head of an operator): with the log signature of any
// valid ingest certificate of the committed tree, also of a generation
// that field 7 revokes at the head's time (attack review 21c F3). Its
// witness cosignatures are what the check relies on. Such a head is
// reported (PublishOptions.RevokedHead): "gomail-server log repair"
// moves it out of heads/ afterwards.
func checkRevocations(log translog.Log, pin *store.PlatformPin) (*translog.Head, error) {
	h, err := log.Head()
	if err != nil {
		return nil, fmt.Errorf("%w: the pin revokes platform generations, but the newest published head of the log does not open (%w); the boundary must come from a witness-confirmed head of this log",
			ErrRevocation, err)
	}
	cos := map[string]bool{}
	for _, s := range h.Sigs {
		for _, w := range pin.Witnesses {
			if s.Name == w.Name && s.Name != translog.LogSignerName {
				cos[s.Name] = true
			}
		}
	}
	if len(cos) < pin.MinWitnesses {
		return nil, fmt.Errorf("%w: the newest published head of the log (size %d) carries %d of the %d witness signatures the pin requires",
			ErrRevocation, h.Size, len(cos), pin.MinWitnesses)
	}
	for _, r := range pin.Revoked {
		what := fmt.Sprintf("%s generation %d", RoleName(r.Role), r.Gen)
		if r.AtSize > h.Size {
			return nil, fmt.Errorf("%w: the pin revokes %s from log index %d, beyond the newest witness-confirmed head of the log (size %d): the boundary comes from no head of this log",
				ErrRevocation, what, r.AtSize, h.Size)
		}
		if r.AtTime-1 > h.Time {
			return nil, fmt.Errorf("%w: the pin revokes %s from time %d, the boundary of a head of time %d, later than the newest witness-confirmed head of the log (time %d): the boundary comes from no head of this log",
				ErrRevocation, what, r.AtTime, r.AtTime-1, h.Time)
		}
		if r.AtTime-1 < minHeadTime {
			return nil, fmt.Errorf("%w: the pin revokes %s from time %d (%s), the boundary of a head before %s: a time in seconds instead of milliseconds?",
				ErrRevocation, what, r.AtTime, rfc3339(r.AtTime), rfc3339(minHeadTime))
		}
		if r.Role == store.KeyRoleIdentity {
			continue
		}
		name := store.PlatformFileName(RoleName(r.Role), r.Gen, "cert")
		es, err := log.Lookup(translog.KindPlatform, []byte(name))
		if err != nil {
			return nil, fmt.Errorf("ceremony: looking up %s in the log: %w", name, err)
		}
		// Lookup returns valid entries only, judged with field 7 of this
		// pin: a certificate of the revoked generation at an index at or
		// above r.AtSize is invalid by r itself (translog doc.go
		// "Validity rules"), so a valid one lies below r.AtSize.
		if len(es) == 0 {
			return nil, fmt.Errorf("%w: the pin revokes %s, whose certificate %s is no valid entry of the log below index %d: a mistyped generation, or one that locks the role for good (no %s certificate could become valid any more); check the generation",
				ErrRevocation, what, name, r.AtSize, RoleName(r.Role))
		}
		// A revoked_at_time at or before valid_from of the generation
		// leaves it no time at which it signs or assigns validly: a time in
		// seconds, or a head older than the generation (attack review 21c
		// F2). A generation not valid yet at the newest head (valid_from
		// after its time) is revoked before it acts, which is allowed.
		c, err := keys.DecodePlatformCert(es[0].Content)
		if err != nil {
			return nil, err
		}
		if r.AtTime <= c.ValidFrom && c.ValidFrom <= h.Time {
			return nil, fmt.Errorf("%w: the pin revokes %s from time %d (%s), not after valid_from %d (%s) of %s, although the generation was valid at the newest head of the log (time %d): it would never have been valid; a time in seconds, or the head of the boundary is older than the generation",
				ErrRevocation, what, r.AtTime, rfc3339(r.AtTime), c.ValidFrom, rfc3339(c.ValidFrom), name, h.Time)
		}
	}
	return h, nil
}

// rfc3339 returns a time in milliseconds since 1970 UTC in RFC 3339
// with fractional seconds (for messages).
func rfc3339(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano) }

// revokedHead calls report when the log key that signed the newest
// published head h (the one checkRevocations checked against) is revoked
// by field 7 at or before the time of h: by the element of its ingest
// generation or, by the cascade of D93, of the identity generation that
// certified it (translog.LogKey Revoked and RevokedAt, the earlier of
// the two). The operator log opens its newest head with every valid
// ingest certificate of the committed tree, whatever field 7 says about
// the head's time (translog: Log.Head of an operator); clients refuse
// such a head (CheckHead), and "gomail-server log repair" moves it to
// log/heads-revoked/ (translog doc.go "Heads that field 7 makes
// foreign"). If the boundary of the pin was read from that head, or from
// a head it replaced in heads/ (the same size, signed again later), no
// witness-confirmed head the boundary comes from is left afterwards
// (attack review 21c F3). A log that is no translog.Operator (a test's)
// is not looked at.
func revokedHead(log translog.Log, h *translog.Head, report func(h *translog.Head, gen uint32, at int64)) error {
	op, ok := log.(translog.Operator)
	if !ok {
		return nil
	}
	ks, err := op.LogKeys()
	if err != nil {
		return fmt.Errorf("ceremony: log keys of the operator log: %w", err)
	}
	for _, k := range ks {
		if k.Verifier == nil {
			continue
		}
		if _, err := note.Open(h.Note, note.VerifierList(k.Verifier)); err != nil {
			continue
		}
		if k.Revoked && h.Time >= k.RevokedAt {
			report(h, k.Gen, k.RevokedAt)
		}
		return nil
	}
	return nil
}

// ingestRevokedAt returns the valid certificate ingest-<gen>.cert of the
// log (nil when there is none) and, when the revocation list rev revokes
// the generation at some time, that time: the own element of field 7 or
// the element of the identity generation that certified it (the cascade
// of D93), the earlier one.
func ingestRevokedAt(log translog.Log, rev []translog.Revoked, gen uint32) (*keys.PlatformCert, int64, bool, error) {
	name := store.PlatformFileName("ingest", gen, "cert")
	es, err := log.Lookup(translog.KindPlatform, []byte(name))
	if err != nil {
		return nil, 0, false, fmt.Errorf("ceremony: looking up %s in the log: %w", name, err)
	}
	if len(es) == 0 {
		return nil, 0, false, nil
	}
	c, err := keys.DecodePlatformCert(es[0].Content)
	if err != nil {
		return nil, 0, false, err
	}
	at, revoked := int64(0), false
	if r, ok := translog.FindRevoked(rev, store.KeyRoleIngest, gen); ok {
		at, revoked = r.AtTime, true
	}
	if r, ok := translog.FindRevoked(rev, store.KeyRoleIdentity, c.IdentityGen); ok && (!revoked || r.AtTime < at) {
		at, revoked = r.AtTime, true
	}
	return c, at, revoked, nil
}

// checkSuccessors refuses a new certificate ingest-<g+1>.cert of the
// export (not yet a valid entry of the log) whose predecessor ingest
// generation g the pin revokes at time A (ingestRevokedAt) with a
// valid_from after A (ErrRevocation, D93 addendum): from A on g signs no
// head validly, and until valid_from no other generation would.
func checkSuccessors(log translog.Log, files map[string]platformFile, rev []translog.Revoked) error {
	for _, f := range files {
		if f.role != "ingest" || f.ext != "cert" || f.gen < 2 {
			continue
		}
		c, err := keys.DecodePlatformCert(f.data)
		if err != nil {
			return err
		}
		_, at, revoked, err := ingestRevokedAt(log, rev, f.gen-1)
		if err != nil {
			return err
		}
		if !revoked || c.ValidFrom <= at {
			continue
		}
		es, err := log.Lookup(translog.KindPlatform, []byte(f.name))
		if err != nil {
			return fmt.Errorf("ceremony: looking up %s in the log: %w", f.name, err)
		}
		if len(es) > 0 && bytes.Equal(es[0].Content, f.data) {
			continue // logged before; Append is idempotent
		}
		atText := time.UnixMilli(at).UTC().Format(time.RFC3339Nano)
		return fmt.Errorf("%w: %s is valid from %d (%s), after ingest generation %d is revoked (%d, %s): no ingest generation would sign heads in between; make it valid from %s (ingest-rotate --valid-from)",
			ErrRevocation, f.name, c.ValidFrom, time.UnixMilli(c.ValidFrom).UTC().Format(time.RFC3339Nano), f.gen-1, at, atText, atText)
	}
	return nil
}

// checkNotRevoked reports translog.ErrRevoked when the pin's revocation
// list rev makes the certificate or succession f invalid at the log
// index it would get (D93 (2), translog doc.go "Validity rules"): issued
// by identity generation issuer (a certificate's identity_gen, g-1 for
// identity-<g>.succ) that is revoked, a succession to a revoked identity
// generation, or the certificate of a revoked admin or ingest
// generation. next is the newest published head's size: no entry
// appended now gets a smaller index, and checkRevocations made every
// boundary at most next, so every listed generation is revoked for it.
// An entry that is already a valid entry of the log with the same
// content stays as it is (Append is idempotent).
func checkNotRevoked(log translog.Log, f platformFile, issuer uint32, rev []translog.Revoked, next int64) error {
	if len(rev) == 0 {
		return nil
	}
	var why string
	switch {
	case translog.RevokedAtIndex(rev, store.KeyRoleIdentity, issuer, next):
		why = fmt.Sprintf("issued by identity generation %d", issuer)
	case f.ext == "succ" && translog.RevokedAtIndex(rev, store.KeyRoleIdentity, f.gen, next):
		why = fmt.Sprintf("a succession to identity generation %d", f.gen)
	case f.ext == "cert" && translog.RevokedAtIndex(rev, uint8(roleOf(f.role)), f.gen, next):
		why = fmt.Sprintf("%s generation %d", f.role, f.gen)
	default:
		return nil
	}
	es, err := log.Lookup(translog.KindPlatform, []byte(f.name))
	if err != nil {
		return fmt.Errorf("ceremony: looking up %s in the log: %w", f.name, err)
	}
	for _, e := range es {
		if bytes.Equal(e.Content, f.data) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s: %s, which the pin revokes (field 7); nothing written", translog.ErrRevoked, f.name, why)
}

// ingestGaps calls report for every ingest generation of the log that
// the revocation list rev revokes at some time (ingestRevokedAt) whose
// successor has a valid_from after that time (a valid entry of the log;
// a new one in the export is refused by checkSuccessors), or that has no
// successor in the log or the export (validFrom 0); see
// PublishOptions.IngestGap. The ingest generations of the log are
// consecutive from 1 (translog: ingest-<g>.cert needs ingest-<g-1>.cert).
func ingestGaps(log translog.Log, files map[string]platformFile, rev []translog.Revoked, report func(gen uint32, at, validFrom int64)) error {
	for g := uint32(1); g < math.MaxUint32; g++ {
		c, at, revoked, err := ingestRevokedAt(log, rev, g)
		if err != nil {
			return err
		}
		if c == nil {
			return nil
		}
		if !revoked {
			continue
		}
		next, _, _, err := ingestRevokedAt(log, rev, g+1)
		if err != nil {
			return err
		}
		_, inExport := files[store.PlatformFileName("ingest", g+1, "cert")]
		switch {
		case next != nil && next.ValidFrom > at:
			report(g, at, next.ValidFrom)
		case next == nil && !inExport:
			report(g, at, 0)
		}
	}
	return nil
}
