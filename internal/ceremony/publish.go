package ceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

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

func runPublish(opts PublishOptions) error {
	if opts.From == "" || opts.Data == nil || opts.Log == nil || opts.Pin == nil {
		return fmt.Errorf("%w: From, Data, Log and Pin are required", ErrOptions)
	}
	ids := opts.Identities
	if ids == nil {
		var err error
		if ids, err = PinIdentities(opts.Pin); err != nil {
			return err
		}
	} else if opts.Pin.Dev {
		return fmt.Errorf("%w: development pin", ErrIdentity)
	} else if err := translog.CheckIdentities(ids, translog.Identity{Gen: opts.Pin.Gen, Pub: opts.Pin.Pub}); err != nil {
		return fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	files, wrec, err := readExport(opts.From)
	if err != nil {
		return err
	}
	st := opts.Data

	// Identity keys: the anchor's list, then successions above it, each
	// verified with the key of the generation before (export first, then
	// data/platform/), as the validity rules of the log do.
	known := map[uint32]ed25519.PublicKey{}
	for _, id := range ids {
		known[id.Gen] = id.Pub
	}
	var succs []platformFile
	for _, f := range files {
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
		if listed, ok := known[s.Gen]; ok && !listed.Equal(s.Pub) {
			return fmt.Errorf("%w: %s contradicts the pin", translog.ErrMismatch, f.name)
		}
		succs = append(succs, f)
	}
	for g := uint32(len(ids)) + 1; g != 0; g++ {
		name := store.PlatformFileName("identity", g, "succ")
		if f, ok := files[name]; ok {
			s, _ := keys.DecodePlatformSuccession(f.data) // decoded above
			if err := s.Verify(known[g-1], g-1); err != nil {
				return fmt.Errorf("%w: %s: %w", translog.ErrOrder, name, err)
			}
			known[g] = s.Pub
			continue
		}
		// A succession already in the data directory counts only if it
		// verifies; anything else there is ignored, not trusted.
		data, err := readData(st, name)
		if err != nil {
			return err
		}
		if data == nil {
			break
		}
		s, err := keys.DecodePlatformSuccession(data)
		if err != nil || s.Gen != g || s.Verify(known[g-1], g-1) != nil {
			break
		}
		known[g] = s.Pub
	}
	for _, f := range succs {
		prev, ok := known[f.gen-1]
		if !ok || known[f.gen] == nil {
			return fmt.Errorf("%w: %s", translog.ErrPrerequisite, f.name)
		}
		s, _ := keys.DecodePlatformSuccession(f.data)
		if err := s.Verify(prev, f.gen-1); err != nil {
			return fmt.Errorf("%w: %s: %w", translog.ErrOrder, f.name, err)
		}
	}

	// Public keys and certificates.
	var certs []platformFile
	for _, f := range files {
		switch {
		case f.role == "identity" && f.ext == "pub":
			k, ok := known[f.gen]
			if !ok {
				return fmt.Errorf("%w: %s", translog.ErrPrerequisite, f.name)
			}
			if !k.Equal(ed25519.PublicKey(f.data)) {
				return fmt.Errorf("%w: %s differs from the trusted identity", ErrIdentity, f.name)
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
				return fmt.Errorf("%w: %s: identity generation %d unknown", translog.ErrPrerequisite, f.name, c.IdentityGen)
			}
			if err := c.Verify(idKey); err != nil {
				return fmt.Errorf("%w: %s: %w", translog.ErrOrder, f.name, err)
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
	if wrec != nil {
		// TODO(task-07): compare with the witnesses of the pin (fields 5
		// and 6) once store.PlatformPin has them.
		if _, err := witness.DecodeWitnesses(wrec); err != nil {
			return err
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

	// Files: public keys before the records that name them.
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
	if wrec != nil {
		if err := store.WriteFileAtomic(st.Path("platform", WitnessesFile), wrec); err != nil {
			return err
		}
	}
	if err := hook("publish-log"); err != nil {
		return err
	}

	// Log: successions by generation, then certificates by role and
	// generation.
	sort.Slice(succs, func(i, j int) bool { return succs[i].gen < succs[j].gen })
	sort.Slice(certs, func(i, j int) bool {
		ri, rj := roleOf(certs[i].role), roleOf(certs[j].role)
		if ri != rj {
			return ri < rj
		}
		return certs[i].gen < certs[j].gen
	})
	for _, f := range append(succs, certs...) {
		if _, err := opts.Log.Append(translog.KindPlatform, f.data); err != nil {
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
