package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
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

// errChanged reports an entry of data/platform/ that another process
// replaced while readEntry read it (review of task 24 A, F3): Publish
// refuses instead of taking it for the export's file.
var errChanged = errors.New("ceremony: an entry of platform/ changed while publish read it")

// readEntry reads platform/<name> of the data directory for the
// comparison with the export's file of that name (backlog 54 and 55),
// platform/witnesses.rec for the comparison with the pin, and a
// succession that succChain.need relogs from data/platform/ (review of
// task 25 A, H5): it looks at the entry itself first (os.Lstat). A
// missing entry is (nil, "", nil). A symbolic link, a dangling one as
// well, is (nil, linkSymbolic, nil) and is never read; a regular file
// with another name besides (a hard link, Nlink > 1) is (nil, linkHard,
// nil). Temporary files of store that a crash left in platform/ are no
// other names here: Publish removes them under the server lock before
// (runPublish), so any name besides counts (review of task 24 A2, N1).
// Whatever such an entry
// points to, it is never taken for the export's file (its target, or the
// file under its other name, can change after publish, and with it what
// server and clients read); it is replaced by the export's file when
// freeName frees the name and refused otherwise (linkErr), before
// anything is written. Every other entry is opened with
// store.OpenRegularIn and read from that descriptor: a regular file, or
// store.ErrNotRegular for a FIFO, a device or a directory, refused before
// anything is written (none of them is replaced: a directory cannot be
// renamed over). The descriptor must be the file os.Lstat saw, and after
// the read the name must still be that file and no link (os.SameFile on
// both sides, review of task 24 A, F3): an entry replaced in between,
// also by a symbolic link to the same file, is errChanged, never taken
// for the export's file. The hard link check uses the last os.Lstat; a
// failure of that os.Lstat other than a missing name is reported with
// its own error (review of task 25 A). Everything goes through pd,
// platform/ as Publish opened it (openPlatformDir, backlog 72): os.Lstat
// is Root.Lstat, the open store.OpenRegularIn; st names the entry in
// messages.
func readEntry(st *store.Store, pd *os.Root, name string) ([]byte, string, error) {
	b, link, err := lreadEntry(st, pd, name, "publish")
	if link != "" {
		b = nil
	}
	return b, link, err
}

// linkSymbolic and linkHard are the kinds of link lreadEntry reports.
const (
	linkSymbolic = "a symbolic link"
	linkHard     = "a hard link"
)

// lreadEntry is readEntry that also returns the content of a hard link
// (link linkHard), for checkDataPlatform, which checks every regular
// file of platform/ whatever its other names. at names the hook points
// ("<at>-open <name>", "<at>-recheck <name>", for tests).
func lreadEntry(st *store.Store, pd *os.Root, name, at string) ([]byte, string, error) {
	p := st.Path("platform", name)
	fi, err := lstatIn(pd, name, p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, linkSymbolic, nil
	}
	if err := hook(at + "-open " + name); err != nil {
		return nil, "", err
	}
	f, ofi, err := store.OpenRegularIn(pd, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", changedErr(p, "is gone")
	}
	if err != nil {
		// os.Root refuses a symbolic link that leaves platform/ (an
		// absolute one as well) instead of following it: an entry
		// replaced by one before the open is reported as replaced, as
		// one replaced by a link inside it (SameFile below). The entry
		// os.Lstat saw was no link, so a link now is a replacement even
		// when it got the inode number of the file it replaced, which
		// the removal freed (review of task 26 package B, N3:
		// os.SameFile alone missed that).
		if !errors.Is(err, store.ErrNotRegular) {
			if now, lerr := pd.Lstat(name); lerr == nil && (now.Mode()&fs.ModeSymlink != 0 || !os.SameFile(fi, now)) {
				return nil, "", changedErr(p, "was replaced before it was opened")
			}
		}
		return nil, "", err
	}
	defer f.Close()
	if !os.SameFile(fi, ofi) {
		return nil, "", changedErr(p, "was replaced before it was opened")
	}
	b, err := readLimited(f, ofi, name)
	if err != nil {
		return nil, "", err
	}
	if err := hook(at + "-recheck " + name); err != nil {
		return nil, "", err
	}
	// os.Lstat of a symbolic link describes the link itself, never the
	// opened file: a link now is refused here as well.
	fi, err = lstatIn(pd, name, p)
	if errors.Is(err, fs.ErrNotExist) || err == nil && !os.SameFile(fi, ofi) {
		return nil, "", changedErr(p, "was replaced while it was read")
	}
	if err != nil {
		return nil, "", fmt.Errorf("ceremony: looking at %s again after reading it: %w", p, err)
	}
	if nlink(fi) > 1 {
		return b, linkHard, nil
	}
	return b, "", nil
}

// lstatIn is Root.Lstat of name in pd with the error of os.Lstat of its
// path p (the messages stay those of a path).
func lstatIn(pd *os.Root, name, p string) (fs.FileInfo, error) {
	fi, err := pd.Lstat(name)
	var pe *fs.PathError
	if errors.As(err, &pe) {
		pe.Op, pe.Path = "lstat", p
	}
	return fi, err
}

// changedErr reports the entry p that changed while readEntry read it,
// or, for checkDataPlatform, after platform/ was listed (errChanged);
// how says what and when.
func changedErr(p, how string) error {
	return fmt.Errorf("%w: %s %s; another process writes platform/ during publish: stop it, look at the entry and run the same publish again",
		errChanged, p, how)
}

// readLimited reads the open regular file f (fi its Stat, name for
// messages) as store.ReadFileLimited does: at most store.MaxRecordFile
// bytes, the size checked before anything is allocated.
func readLimited(f *os.File, fi fs.FileInfo, name string) ([]byte, error) {
	const limit = store.MaxRecordFile
	if fi.Size() > limit {
		return nil, fmt.Errorf("%w: %s has %d bytes, at most %d", store.ErrTooLarge, name, fi.Size(), limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s grew beyond %d bytes", store.ErrTooLarge, name, limit)
	}
	return b, nil
}

// nlink returns the number of names of the file fi from its system data
// (the field Nlink of syscall.Stat_t, whose type differs between
// systems), or 1 where the system gives none.
func nlink(fi fs.FileInfo) uint64 {
	v := reflect.ValueOf(fi.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 1
	}
	n := v.FieldByName("Nlink")
	if !n.IsValid() || !n.CanUint() {
		return 1
	}
	return n.Uint()
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
// where it came from; Publish never heals such a file (freeName). Other
// files (witnesses.rec, temporary files) are not looked at here, nor are
// entries that are no regular files (a symbolic link is not followed):
// under a name of the export the comparison of runPublish never takes
// one, nor a hard link, for the export's file (readEntry). A regular
// file is read without following a link (lreadEntry); one replaced
// meanwhile, by a link as well, is errChanged. The successions in the
// log are checked by checkDataLog. platform/ is listed and read through
// pd, as Publish opened it (openPlatformDir, backlog 72). A failing
// listing names platform/ by its path, in context (review of task 26
// package B, H1: platform/ removed after the open).
func checkDataPlatform(st *store.Store, pd *os.Root, pin *store.PlatformPin, known map[uint32]ed25519.PublicKey) error {
	ents, err := store.ReadDirIn(pd)
	if err != nil {
		return fmt.Errorf("ceremony: listing platform/: %w", err)
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
		// Read without following a link (lreadEntry; review of task 25 A,
		// H5): an entry that the listing showed as a regular file and that
		// is a symbolic link or gone now changed during publish, after the
		// listing (review of task 25 A2, H4: the message says so).
		data, link, err := lreadEntry(st, pd, f.name, "check")
		if err != nil {
			return err
		}
		if link == linkSymbolic {
			return changedErr(st.Path("platform", f.name), "was replaced by a symbolic link after platform/ was listed")
		}
		if data == nil {
			return changedErr(st.Path("platform", f.name), "was removed after platform/ was listed")
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

// witnessLinkErr reports a symbolic or hard link (readEntry says which)
// as platform/witnesses.rec without ReplaceWitnesses: never taken for the
// pin's witnesses (its target, or the file under its other name, can
// change after publish), refused before anything is written.
func witnessLinkErr(st *store.Store, link string) error {
	return fmt.Errorf("%w: %s is %s, never taken for the witnesses of the pin; nothing written: look at the link and remove it by hand, or publish --replace-witnesses (ReplaceWitnesses) replaces it by the pin's",
		store.ErrExists, st.Path("platform", WitnessesFile), link)
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
//     rule; Publish then logs it first (relog). It is read as a name of
//     the export is (readEntry): a symbolic or hard link there is never
//     logged through, Publish refuses before anything is written.
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
	pd    *os.Root // platform/ of st as Publish opened it
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
		// Read as the names of the export are (readEntry; review of task
		// 25 A, H5): what is logged is what was read and checked, and a
		// symbolic or hard link is never logged through.
		data, link, err := readEntry(c.st, c.pd, name)
		if err != nil {
			return err
		}
		if link != "" {
			return fmt.Errorf("%w: %s is %s, never logged through it: %s needs %s, which is neither in the export nor a valid entry of the log; nothing written: look at the link and remove it by hand, then publish the export of the succession to generation %d",
				translog.ErrPrerequisite, c.st.Path("platform", name), link, by, name, g)
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

// errPlatformLink reports platform/ of the data directory as a symbolic
// link (review of task 25 A, L1).
var errPlatformLink = errors.New("ceremony: platform/ of the data directory is a symbolic link")

// checkPlatformDir refuses platform/ of the data directory when it is a
// symbolic link (os.Lstat), whatever it points to, before Publish
// removes or writes anything: gomail-server init makes it a directory,
// and publish reaches no entry of platform/ through a link. The message
// names where the link points (os.Readlink, quoted: someone else chose
// it), or the link alone when os.Readlink fails (review of task 25 A2,
// H3). A missing platform/, or one that cannot be looked at, is refused
// here as well, with the error of os.Lstat in context (H6): no step
// after it works without platform/ (its listing fails), and none of
// them would name it. It returns what os.Lstat saw, for openPlatformDir.
func checkPlatformDir(st *store.Store) (fs.FileInfo, error) {
	p := st.Path("platform")
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("ceremony: looking at platform/: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		const hint = "; nothing removed or written: look at the link and where it points, and put the directory itself in its place"
		if target, rerr := os.Readlink(p); rerr == nil {
			return nil, fmt.Errorf("%w: %s points to %q"+hint, errPlatformLink, p, target)
		}
		return nil, fmt.Errorf("%w: %s"+hint, errPlatformLink, p)
	}
	return fi, nil
}

// errPlatformReplaced reports platform/ of the data directory replaced
// between the os.Lstat of checkPlatformDir and its open (backlog 72), or
// after the open, before the log (review of task 26 package B, H2).
var errPlatformReplaced = errors.New("ceremony: platform/ of the data directory was replaced during publish")

// platformStillOpened reports whether the path p of platform/ leads, at
// this moment, to the directory that Publish opened (ri: Root.Stat(".")
// of its root): os.Lstat(p) is no symbolic link and os.SameFile with
// ri. Publish holds that directory open, so its inode number is not
// free for another file while Publish runs, also when the directory is
// removed: os.SameFile against ri cannot be fooled by a reused inode
// number, unlike os.SameFile against the os.Lstat of checkPlatformDir,
// whose directory may be gone by the open (review of task 26 package B,
// N1). That holds where an inode number identifies a file while it is
// open, as on the local file systems of Linux.
func platformStillOpened(p string, ri fs.FileInfo) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&fs.ModeSymlink == 0 && os.SameFile(fi, ri)
}

// openPlatformDir opens platform/ of the data directory once for all of
// Publish (backlog 72; review of task 25 A2, N1 and H7): checkPlatformDir
// first, then os.OpenRoot; the directory opened must be the one os.Lstat
// saw (os.SameFile), and after the open the path must still lead to it,
// without a symbolic link (platformStillOpened; review of task 26
// package B, N1), or Publish refuses before it removes or writes
// anything (errPlatformReplaced). It returns the root and what
// Root.Stat(".") saw, for the check before the log.
//
// The second check closes the bypass of the first by a reused inode
// number: platform/ removed after the os.Lstat and a symbolic link put
// in its place that leads to a new directory elsewhere, which got the
// freed inode number; os.SameFile with the os.Lstat of checkPlatformDir
// held, and Publish worked outside the data directory. Now the path
// leads to the opened directory itself at the second check, and that
// comparison is exact. What is left:
//   - Publish works in the directory under the path at the second
//     check, which is not always the one checkPlatformDir looked at
//     (with a reused inode number both checks pass, but then it is
//     platform/ by then).
//   - A swap after the second check does not change where Publish
//     lists, reads, writes, renames, removes temporary files and fsyncs:
//     all of that goes through the returned root, relative to its
//     descriptor, also when the directory is moved out of the data
//     directory. Publish then refuses before the log
//     (platformStillOpened once more, errPlatformReplaced), and what it
//     wrote stays in the directory it opened. A swap between that check
//     and the log entries is not seen.
//
// The open resolves "<platform>/." so that only a directory opens: a
// FIFO or a file put in place of platform/ meanwhile is syscall.ENOTDIR
// at once, never an open that waits for a writer (os.OpenRoot opens
// without O_NONBLOCK). A symbolic link put there is followed and then
// refused. A failure of the open keeps the message it had when the
// listing of RemoveTempReport was the first step after
// checkPlatformDir. The operator log does not go through the root:
// OpenLog (translog.Open) lists platform/ and reads its ingest
// certificates and successions by the path, for the keys of the log,
// and takes only those that verify in a chain from the identity list of
// the pin; a platform/ swapped before that can make the log fail to
// open or lack a key, never give it a key that the pin does not
// certify.
func openPlatformDir(st *store.Store) (*os.Root, fs.FileInfo, error) {
	fi, err := checkPlatformDir(st)
	if err != nil {
		return nil, nil, err
	}
	if err := hook("publish-platform"); err != nil {
		return nil, nil, err
	}
	p := st.Path("platform")
	pd, err := os.OpenRoot(p + string(filepath.Separator) + ".")
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			pe.Path = p
		}
		return nil, nil, fmt.Errorf("ceremony: removing temporary files of platform/: %w", err)
	}
	ri, err := pd.Stat(".")
	if err != nil {
		pd.Close()
		return nil, nil, fmt.Errorf("ceremony: looking at platform/ after opening it: %w", err)
	}
	replaced := fmt.Errorf("%w: %s is no longer the directory publish looked at; nothing removed or written: another process writes the data directory: stop it, look at platform/ and run the same publish again",
		errPlatformReplaced, p)
	if !os.SameFile(fi, ri) {
		pd.Close()
		return nil, nil, replaced
	}
	if err := hook("publish-platform-opened"); err != nil {
		pd.Close()
		return nil, nil, err
	}
	if !platformStillOpened(p, ri) {
		pd.Close()
		return nil, nil, replaced
	}
	return pd, ri, nil
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
	// Temporary files (".tmp-") in platform/ are left by a crash: Publish
	// is the only program that writes platform/ of a data directory in
	// use (gomail-server init writes witnesses.rec into an empty one), and
	// it holds the server lock, which keeps out a second Publish. They are
	// removed first, so that a crash of store.CreateFileAtomic between its
	// link and its remove leaves no second name that readEntry would take
	// for a hard link, and so that no ".tmp-" name can hide one (review of
	// task 24 A2, N1): every other name of a file counts from here on.
	// Each name removed is reported (TempRemoved; review of task 25 A,
	// L2), also when Publish refuses afterwards. platform/ itself must be
	// no symbolic link (checkPlatformDir), or the files would be removed
	// and written where it points; it is opened once (openPlatformDir,
	// backlog 72) and everything below goes through that descriptor.
	pd, pdInfo, err := openPlatformDir(st)
	if err != nil {
		return err
	}
	defer pd.Close()
	if err := store.RemoveTempReportIn(pd, opts.TempRemoved); err != nil {
		return fmt.Errorf("ceremony: removing temporary files of platform/: %w", err)
	}

	// Identity keys: exactly the pin's list. A generation above it is
	// one the pin does not know: the operator installs the new pin first
	// (Q10 point 5), in the export as in data/platform/.
	known := map[uint32]ed25519.PublicKey{}
	for _, id := range ids {
		known[id.Gen] = id.Pub
	}
	if err := checkDataPlatform(st, pd, pin, known); err != nil {
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
	// witnesses.rec is a file of the export as well (Init writes it): a
	// symbolic or hard link there is never taken for the pin's witnesses
	// (readEntry), as under the other names of the export. It counts as a
	// working copy that differs: replaced with ReplaceWitnesses (the rule
	// that frees this name), refused otherwise before anything is written.
	haveW, wlink, err := readEntry(st, pd, WitnessesFile)
	if err != nil {
		return err
	}
	if wlink != "" && !opts.ReplaceWitnesses {
		return witnessLinkErr(st, wlink)
	}
	// oldW is the working copy to replace (ReplaceWitnesses), nil if
	// none is replaced or if it is a link (whose content is not read).
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
	chain := &succChain{files: files, st: st, pd: pd, log: log, known: known, rev: rev, ok: map[uint32]bool{}, relog: map[uint32]platformFile{}}

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

	// Existing files: identical regular files are skipped, and missing
	// ones are written, unless a valid entry of the log holds the name
	// with other content (loggedOther); one with other content, and a
	// symbolic or hard link whatever it points to (readEntry), is
	// replaced only when its name is free in the log or its valid entry is
	// the export's file (freeName), and refused otherwise, before
	// anything is written.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var todo []string
	replace := map[string]bool{}
	for _, n := range names {
		have, link, err := readEntry(st, pd, n)
		if err != nil {
			return err
		}
		if have == nil && link == "" {
			if err := loggedOther(opts.From, st, log, files[n], "is missing"); err != nil {
				return err
			}
			todo = append(todo, n)
			continue
		}
		if link == "" && bytes.Equal(have, files[n].data) {
			if err := loggedOther(opts.From, st, log, files[n], "is the same as "+filepath.Join(opts.From, "platform", n)); err != nil {
				return err
			}
			continue
		}
		free, why, err := freeName(st, pd, log, files, n)
		if err != nil {
			return err
		}
		if !free {
			if link != "" {
				return linkErr(opts.From, st, files[n], link, why)
			}
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
			// Under the server lock, after every check, atomically; the
			// rename replaces a symbolic or hard link itself, never its
			// target or the file under its other name.
			if err := store.WriteFileAtomicIn(pd, n, files[n].data); err != nil {
				return err
			}
		} else if err := store.CreateFileAtomicIn(pd, n, files[n].data); err != nil {
			if !errors.Is(err, store.ErrExists) {
				return err
			}
			// The name was missing above (a dangling link is not missing for
			// readEntry): another process wrote it meanwhile. A link written
			// meanwhile is never taken for the export's file either.
			have, link, rerr := readEntry(st, pd, n)
			if rerr != nil {
				return rerr
			}
			if link != "" {
				return linkErr(opts.From, st, files[n], link, written)
			}
			if !bytes.Equal(have, files[n].data) {
				return existsErr(opts.From, st, files[n], written)
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
		// (ReplaceWitnesses, task 15f point 2; a link as well), atomically
		// and under the server lock, after every check passed. The rename
		// replaces a link itself, never its target.
		w := wrec
		if w == nil {
			if w, err = checkTrust(pin.Origin, pinWitnesses(pin), pin.MinWitnesses); err != nil {
				return err
			}
		}
		if err := store.ReplaceFileIn(pd, WitnessesFile, w); err != nil {
			return err
		}
		// witnesses.rec is replaced from here on: the callbacks report it
		// also when only the fsync of platform/ fails now, and Publish
		// returns that error after them (backlog 83: before, the
		// replacement went unreported for good).
		serr := syncPlatform(pd)
		after := &witness.Witnesses{List: pinWitnesses(pin), Min: pin.MinWitnesses}
		if oldW != nil && opts.WitnessesReplaced != nil {
			opts.WitnessesReplaced(oldW, after)
		}
		if wlink != "" && opts.WitnessesLinkReplaced != nil {
			opts.WitnessesLinkReplaced(wlink, after)
		}
		if serr != nil {
			return serr
		}
	}
	if err := hook("publish-log"); err != nil {
		return err
	}
	// Nothing is logged for files written into a directory that is no
	// longer platform/ by its path (review of task 26 package B, H2):
	// platform/ was swapped after the open, and what Publish wrote is in
	// the directory it opened, wherever that is now, while server and
	// clients read the path. Nothing is undone: a repeat of the same
	// publish works in what platform/ is then (a symbolic link there is
	// refused by checkPlatformDir) and logs what this one did not.
	if p := st.Path("platform"); !platformStillOpened(p, pdInfo) {
		return fmt.Errorf("%w: %s is no longer the directory publish opened and wrote to; nothing logged: another process writes the data directory: stop it, look at platform/ and run the same publish again",
			errPlatformReplaced, p)
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

// syncPlatform fsyncs platform/ through pd after witnesses.rec was
// renamed into it. The hook "publish-sync witnesses.rec" stands for a
// failing fsync in tests (backlog 83): its error is returned instead,
// and the fsync is not made.
func syncPlatform(pd *os.Root) error {
	if err := hook("publish-sync " + WitnessesFile); err != nil {
		return err
	}
	return store.SyncDirIn(pd)
}

// freeName decides whether platform/<n> of the data directory, which
// differs from the export's file n or is a symbolic or hard link
// (readEntry), may be replaced by it (attack review 21c F1; translog
// doc.go "Reading for the operator": a certificate that field 7 makes
// invalid holds no key, and <role>-<g>.cert is reissued under the new
// identity with the same name). A certificate or succession is replaced when the log holds no
// valid entry of its name under the pin (Log.Lookup returns valid
// entries only): the entry there is invalid (such as the thief's
// certificate issued with a revoked identity generation at or above its
// revoked_at_size, class "revoked") or there is none (a file left by a
// crash before its log entry, which gives nobody anything: translog
// doc.go "Platform generations"). It is also replaced when the valid
// entry of its name is exactly the export's file: the entry of the data
// directory is then foreign (written over the logged file after an
// earlier publish, for example by a thief with write access to
// data/platform/, or a link), and the export puts back what the
// log holds, so that running the same publish again heals that entry
// (attack review 21c R-low, task 22 point 1). The public key
// <role>-<g>.pub of an admin or ingest generation is replaced together
// with its certificate (when <role>-<g>.cert of the data directory
// differs from the export's or is a link, and is replaced by
// this rule), and when the export's <role>-<g>.cert is the valid entry
// of the log: Publish has checked that the export's public key is the
// one that certificate names. Everything else is refused, above all a
// valid entry with other content than the export's file and every
// identity-<g>.pub; why completes the message (existsErr, linkErr). The
// caller has checked the export's files already (signature, pin, field
// 7, prerequisites).
//
// Healing reaches only what checkDataPlatform lets through. Before any
// name is looked up in the log, it refuses a regular file of
// data/platform/ that does not decode, does not verify with the pin,
// certifies another key than its name says or names an identity
// generation the pin does not know (garbage, a certificate with a wrong
// signature or under a wrong name), and a foreign identity-<g>.pub. Such
// a file is never healed: the operator removes it by hand (backlog 56;
// RUNBOOK 7.3, "Fremde Dateien in platform/").
func freeName(st *store.Store, pd *os.Root, log translog.Log, files map[string]platformFile, n string) (bool, string, error) {
	f := files[n]
	cert := n
	if f.ext == "pub" {
		if f.role == "identity" {
			return false, "", nil
		}
		cert = store.PlatformFileName(f.role, f.gen, "cert")
	}
	es, err := log.Lookup(translog.KindPlatform, []byte(cert))
	if err != nil {
		return false, "", fmt.Errorf("ceremony: looking up %s in the log: %w", cert, err)
	}
	if len(es) > 0 {
		// files[cert] exists: Publish refuses a .pub of the export
		// without its certificate.
		if len(es) == 1 && bytes.Equal(es[0].Content, files[cert].data) {
			return true, "", nil
		}
		return false, fmt.Sprintf(", and %s is a valid entry of the log under this pin with other content than the export's%s", cert, validKept), nil
	}
	if f.ext == "pub" {
		// A link as the certificate is never the export's
		// (readEntry): the certificate is replaced, and its key with it.
		have, link, err := readEntry(st, pd, cert)
		if err != nil {
			return false, "", err
		}
		if link == "" && (have == nil || bytes.Equal(have, files[cert].data)) {
			return false, fmt.Sprintf(", while platform/%s is missing there or the same and is no valid entry of the log: a public key is replaced only together with its certificate or under its logged certificate", cert), nil
		}
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

// validKept ends the reason of freeName and loggedOther for a name
// with a valid entry of the log with other content than the export's.
const validKept = ": a valid entry is never replaced"

// written completes the messages of the "written meanwhile" branch.
const written = " (written meanwhile)"

// linkErr reports a link (a symbolic link, a dangling one as well, or a
// hard link: readEntry says which) under the name of the export's file f
// in platform/ of the data directory whose name freeName does not free
// (backlog 54 and 55), or one written meanwhile: Publish neither takes it
// for the export's file nor replaces it, and refuses before anything is
// written (meanwhile: before the log, after other files possibly). The
// message names the link, not its target; why completes it as in
// existsErr, and the errors are those of existsErr. When a valid
// entry of the log holds the name, removing the link does not help: the
// export that holds the logged file heals it, and a thief's entry needs
// a reissue under the next generation (RUNBOOK 7.3).
func linkErr(from string, st *store.Store, f platformFile, link, why string) error {
	hint := "look at the link and remove it by hand"
	if strings.HasSuffix(why, validKept) {
		cert := f.name
		if f.ext == "pub" {
			cert = store.PlatformFileName(f.role, f.gen, "cert")
		}
		hint = fmt.Sprintf("look at the link; publish the export that holds the logged %s, which replaces the link, or, if that entry is the thief's, reissue under the next generation (RUNBOOK 7.3)", cert)
		if f.ext == "succ" {
			// A succession is not reissued under another generation.
			hint = fmt.Sprintf("look at the link; publish the export that holds the logged succession %s, which replaces the link, or, %s", cert, succThiefHint)
		}
	}
	done := "nothing written"
	if why == written {
		done, hint = "nothing logged", "look at the link, remove it by hand and run the same publish again"
	}
	what := fmt.Sprintf("%s is %s, never taken for %s of the export%s; %s: %s",
		st.Path("platform", f.name), link, filepath.Join(from, "platform", f.name), why, done, hint)
	if f.ext == "pub" {
		return fmt.Errorf("%w: %s", store.ErrExists, what)
	}
	return fmt.Errorf("%w: %w: %s", store.ErrExists, translog.ErrDuplicate, what)
}

// succThiefHint completes the remedy of linkErr and loggedOther for a
// succession whose name has a valid entry of the log: unlike a
// certificate, a succession is not reissued under the next generation,
// and a valid one the operator did not make means a compromised
// identity or root (review of task 25 A).
const succThiefHint = "if that entry is not from a ceremony of your own, decide by RUNBOOK 7.3.1 (identity or root compromised)"

// loggedOther refuses a certificate or succession f of the export whose
// name has a valid entry of the log with other content, when
// platform/<name> of the data directory is equal to f (review of task 24
// A, F4) or missing (review of task 24 A2, N3); state says which ("is
// the same as <export file>", "is missing"). It refuses before anything
// is written: logging f would fail as a duplicate only after f and
// other files are written. A public key goes with its certificate: the
// export holds <role>-<g>.cert with every <role>-<g>.pub, and that name
// is checked on its own.
func loggedOther(from string, st *store.Store, log translog.Log, f platformFile, state string) error {
	if f.ext == "pub" {
		return nil
	}
	es, err := log.Lookup(translog.KindPlatform, []byte(f.name))
	if err != nil {
		return fmt.Errorf("ceremony: looking up %s in the log: %w", f.name, err)
	}
	if len(es) == 0 || len(es) == 1 && bytes.Equal(es[0].Content, f.data) {
		return nil
	}
	hint := fmt.Sprintf("publish the export that holds the logged %s or, if that entry is the thief's, reissue under the next generation (RUNBOOK 7.3)", f.name)
	if f.ext == "succ" {
		// A succession is not reissued under another generation (review
		// of task 25 A).
		hint = fmt.Sprintf("publish the export that holds the logged succession %s or, %s", f.name, succThiefHint)
	}
	return fmt.Errorf("%w: %w: %s %s, and %s is a valid entry of the log under this pin with other content than %s of the export%s; nothing written: %s",
		store.ErrExists, translog.ErrDuplicate, st.Path("platform", f.name), state, f.name, filepath.Join(from, "platform", f.name), validKept, hint)
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
// the operator"); for an ingest element, revoked_at_time must lie after
// the certificate's valid_from unless that lies after the head's time
// (the generation would never have been valid: attack review 21c F2;
// for an admin element revoked_at_time has no meaning, D93 (2), and
// only the lower bound minHeadTime applies, task 22 point 2). A
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
		// For an admin element revoked_at_time has no meaning (D93 (2):
		// what an admin generation assigns is judged by log index, from
		// revoked_at_size on), so only the lower bound minHeadTime above
		// applies to it; a repair with an older head (attack review 21a
		// F3) is not refused for it (spec review of 21c, task 22 point 2).
		if r.Role != store.KeyRoleIngest {
			continue
		}
		// A revoked_at_time at or before valid_from of the ingest
		// generation leaves it no time at which it signs validly: a time in
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
