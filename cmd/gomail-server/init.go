package main

// "gomail-server init" (task 15h, SPEC-ISSUES S80): the production way to
// create the data directory. Before it, only the development ceremony
// (gomail-ceremony init --dev, a build with the tag gomail_dev) created
// one; a production build had none.
//
// Reading of task 15h (one way, not two): init creates the data
// directory, "gomail-ceremony publish" writes into an existing one only.
// The data directory belongs to the server host and its group gomail
// (9.1); init runs there, as the operator of the server, before the
// first publish. publish keeps all of its checks before writing and
// never creates a data directory.
//
// Task 15k finding 2: init follows no symbolic link at --data or at the
// last element of its parent (fail closed; an operator gives the path
// without the link), and works relative to descriptors after its checks:
// the parent is opened as an os.Root, the root is created in it with
// mkdirat (never MkdirAll) or, if it exists and is empty, opened in it,
// and every later step (mkdirat, fchmod, openat for witnesses.rec) is
// relative to the root. Each directory is checked to be the entry its
// parent holds under that name (os.SameFile with Lstat, no link), so a
// directory swapped for a link or for another directory between the
// checks and the creation is refused, and nothing outside is changed.
// The rollback removes only what init created, by identity.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/tim-riep/go-mail/internal/ceremony"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// dirModeBits are the bits of a directory mode compared with
// store.DirPerm (permissions, setuid, setgid, sticky).
const dirModeBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// dataGroup is the group of the data directory that 9.1 names.
const dataGroup = "gomail"

// initDirs are the directories init creates below the root, in this
// order: the top-level directories of store.Init (store.Open checks
// them), locks/ (9.1) and log/ (translog.Dir), all empty.
var initDirs = []string{"platform", "users", "invites", "mailboxes", "spool", "work", "locks", translog.Dir}

// errWitnessFile reports a --witnesses file whose witnesses or quorum
// differ from the pin (task 15k finding 4: no translog prefix, the data
// directory does not exist yet).
var errWitnessFile = errors.New("--witnesses weicht von Zeugen und Quorum des Pins ab")

// errInitRace reports that --data, its parent or a directory init made
// was replaced or appeared between the checks and the creation (task 15k
// finding 2): another process works on the path; init changed nothing
// outside what it created and removed that again.
var errInitRace = errors.New("während init verändert")

// initHook is the injection point of init after its checks of the paths
// ("checked", before anything is created) and after the directories are
// created ("created", before the final check and witnesses.rec); a
// non-nil error stops init there. nil in production, set only by tests
// of this package (task 15k finding 2).
var initHook func(stage, root string) error

// initCmd is "gomail-server init --data <dir> --pin <file> [--witnesses
// <file>]". It creates an empty data directory after section 4
// (store.Init: the top-level directories and locks/, plus an empty log/;
// rights 2770, every entry checked, the group of the process) and writes
// platform/witnesses.rec, the server's working copy of the pinned
// witnesses, from the pin, or the file given with --witnesses, which
// must hold exactly the witnesses and the quorum of the pin. It writes
// nothing else: no platform key, no certificate, no log entry; those
// come with "gomail-ceremony publish".
//
// It refuses, before it creates anything, when the pin cannot be read
// or is not valid (store.DecodePlatformPin, ceremony.PinIdentities,
// translog.CheckQuorum, translog.CheckOrigin), when the pin is a
// development pin (dev = 1) in a build without the development ceremony
// (checkDevPin), when --witnesses differs from the pin (errWitnessFile),
// when --pin or --witnesses is not a regular file (readRegular: a FIFO
// is refused, not waited for), when --data or the last element of its
// parent is a symbolic link, when --data exists and is not an empty
// directory, and when the parent directory of --data is missing (init
// creates the last element only). After creating it refuses, and
// removes again the directories it made (rollbackInit), when the rights
// of the new directories are not exactly 2770, the process is not in
// their group, a path was replaced meanwhile (errInitRace) or ctx ends
// (SIGINT, SIGTERM).
func initCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("init", flag.ContinueOnError)
	fset.SetOutput(stderr)
	data := fset.String("data", "", "neues Datenverzeichnis (fehlt oder ist leer, kein symbolischer Link)")
	pinFile := fset.String("pin", "", "Pin der Plattform (identity-<gen>.pin, nicht im Datenverzeichnis)")
	wFile := fset.String("witnesses", "", "witnesses.rec aus dem Export der Zeremonie (muss dem Pin entsprechen)")
	pos, err := parse(fset, args)
	if err != nil || len(pos) != 0 || *data == "" || *pinFile == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	pin, wrec, err := initWitnesses(*pinFile, *wFile)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := initData(ctx, *data, wrec)
	if err != nil {
		return fail(stderr, err)
	}
	if pin.Dev {
		fmt.Fprintln(stderr, devPinWarning)
	}
	if res.groupName != "" && res.groupName != dataGroup {
		// TODO(ask): 9.1 names the group gomail; init checks only that the
		// process belongs to the group of the data directory and warns
		// about another name (a test machine may have no group gomail).
		fmt.Fprintf(stderr, "WARNUNG: Gruppe des Datenverzeichnisses ist %s, nicht %s (9.1)\n", res.groupName, dataGroup)
	}
	from := "aus dem Pin"
	if *wFile != "" {
		from = "aus --witnesses (entspricht dem Pin)"
	}
	fmt.Fprintf(stdout, "Datenverzeichnis:  %s  (Abschnitt 4, Rechte 2770%s)\n", res.root, res.group())
	fmt.Fprintf(stdout, "Zeugen:            platform/%s %s (%d Zeugen, Quorum %d)\n", ceremony.WitnessesFile, from, len(pin.Witnesses), pin.MinWitnesses)
	fmt.Fprintf(stdout, "Weiter:            gomail-ceremony publish --from <export> --data %s --pin <pin>, dann gomail-server serve\n", res.root)
	return 0
}

// initWitnesses reads and checks the pin and returns it with the bytes
// of platform/witnesses.rec: the encoding of the pin's witnesses and
// quorum, or the file wFile, which must decode strictly, be canonical
// and hold the same witnesses with the same quorum in any order (as
// "gomail-ceremony publish" compares them, errWitnessFile otherwise).
// Pin and wFile are read with readRegular.
func initWitnesses(pinFile, wFile string) (*store.PlatformPin, []byte, error) {
	pin, err := readPinFile(pinFile)
	if err != nil {
		return nil, nil, err
	}
	if err := checkDevPin(pin); err != nil {
		return nil, nil, err
	}
	if !pin.Dev {
		if _, err := ceremony.PinIdentities(pin); err != nil {
			return nil, nil, fmt.Errorf("Pin: %w", err)
		}
	}
	if err := translog.CheckQuorum(pin.MinWitnesses, len(pin.Witnesses)); err != nil {
		return nil, nil, fmt.Errorf("Pin: %w", err)
	}
	if err := translog.CheckOrigin(pin.Origin); err != nil {
		return nil, nil, fmt.Errorf("Pin: %w", err)
	}
	want := &witness.Witnesses{Min: pin.MinWitnesses}
	for _, w := range pin.Witnesses {
		want.List = append(want.List, witness.Key{Name: w.Name, Pub: w.Pub})
	}
	if wFile == "" {
		b, err := want.Encode()
		if err != nil {
			return nil, nil, fmt.Errorf("Pin: %w", err)
		}
		return pin, b, nil
	}
	b, err := readRegular(wFile, store.MaxRecordFile)
	if err != nil {
		return nil, nil, fmt.Errorf("--witnesses: %w", err)
	}
	got, err := witness.DecodeWitnesses(b)
	if err != nil {
		return nil, nil, fmt.Errorf("--witnesses: %w", err)
	}
	if enc, err := got.Encode(); err != nil || !bytes.Equal(enc, b) {
		return nil, nil, fmt.Errorf("--witnesses: %w: not canonically encoded", witness.ErrWitnesses)
	}
	if !sameWitnessSet(got, want) {
		return nil, nil, errWitnessFile
	}
	return pin, b, nil
}

// sameWitnessSet reports whether a and b hold the same witnesses (name
// and key) with the same quorum, in any order.
func sameWitnessSet(a, b *witness.Witnesses) bool {
	if a.Min != b.Min || len(a.List) != len(b.List) {
		return false
	}
	for _, x := range a.List {
		found := false
		for _, y := range b.List {
			found = found || (x.Name == y.Name && x.Pub.Equal(y.Pub))
		}
		if !found {
			return false
		}
	}
	return true
}

// initResult describes a data directory created by initData.
type initResult struct {
	root      string
	gid       int
	hasGID    bool
	groupName string
}

func (r *initResult) group() string {
	switch {
	case !r.hasGID:
		return ""
	case r.groupName != "":
		return ", Gruppe " + r.groupName
	}
	return ", Gruppe " + strconv.Itoa(r.gid)
}

// initState is what initData opened and created, for createData and
// rollbackInit.
type initState struct {
	parent  *os.Root    // the parent directory of the root
	base    string      // the name of the root in parent
	root    *os.Root    // the root, once checked to be parent's entry base
	rootF   *os.File    // the root opened through root, for fstat and fchmod
	rootFI  fs.FileInfo // identity of the root
	created bool        // init created the root (mkdirat in parent)
	chmoded bool        // init changed the mode of an existing root
	oldMode fs.FileMode // the mode of an existing root before init
	made    map[string]fs.FileInfo
	plat    *os.Root    // platform/, once checked to be made["platform"]
	wrecFI  fs.FileInfo // platform/witnesses.rec, once init linked it
}

func (s *initState) close() {
	if s.plat != nil {
		s.plat.Close()
	}
	if s.rootF != nil {
		s.rootF.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
	if s.parent != nil {
		s.parent.Close()
	}
}

// initStage runs initHook and ends init when ctx is done (SIGINT,
// SIGTERM: main's signal.NotifyContext).
func initStage(ctx context.Context, stage, root string) error {
	if initHook != nil {
		if err := initHook(stage, root); err != nil {
			return err
		}
	}
	return initCanceled(ctx)
}

// initCanceled reports a done ctx.
func initCanceled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("init abgebrochen: %w", err)
	}
	return nil
}

// initData creates the data directory dir, which must be missing (with
// an existing parent) or an empty directory, and neither it nor the last
// element of its parent may be a symbolic link (usageError). It checks
// the paths, then opens the parent and works relative to it
// (createData). On a failure after it started creating, it removes what
// it made (rollbackInit).
func initData(ctx context.Context, dir string, wrec []byte) (*initResult, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	parentPath, base := filepath.Dir(root), filepath.Base(root)
	if parentPath == root {
		return nil, usageError{"--data darf nicht die Wurzel des Dateisystems sein"}
	}
	pli, err := os.Lstat(parentPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, usageError{"das Elternverzeichnis von --data fehlt; init legt nur die letzte Stufe an"}
	case err != nil:
		return nil, err
	case pli.Mode()&fs.ModeSymlink != 0:
		return nil, usageError{"das Elternverzeichnis von --data ist ein symbolischer Link; init folgt keinem (den Pfad ohne Link angeben)"}
	case !pli.IsDir():
		return nil, usageError{"das Elternverzeichnis von --data ist kein Verzeichnis"}
	}
	var existing fs.FileInfo
	li, err := os.Lstat(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case li.Mode()&fs.ModeSymlink != 0:
		return nil, usageError{"--data ist ein symbolischer Link; init folgt keinem (den Pfad ohne Link angeben)"}
	case !li.IsDir():
		return nil, usageError{"--data ist kein Verzeichnis"}
	default:
		empty, err := emptyDir(root)
		if err != nil {
			return nil, err
		}
		if !empty {
			return nil, errNotEmpty
		}
		existing = li
	}
	if err := initStage(ctx, "checked", root); err != nil {
		return nil, err
	}
	s := &initState{base: base, made: map[string]fs.FileInfo{}}
	defer s.close()
	if s.parent, err = os.OpenRoot(parentPath); err != nil {
		return nil, err
	}
	if pi, err := s.parent.Stat("."); err != nil || !os.SameFile(pi, pli) {
		return nil, fmt.Errorf("Elternverzeichnis von --data %w", errInitRace)
	}
	res, err := createData(ctx, s, root, existing, wrec)
	if err != nil {
		rollbackInit(s)
		return nil, err
	}
	return res, nil
}

// errNotEmpty refuses an existing data directory with an entry.
var errNotEmpty = usageError{"das Datenverzeichnis existiert und ist nicht leer; init legt nur ein neues an und ändert kein bestehendes"}

// openChecked opens name in r as a directory and checks that it is the
// directory r holds under that name (Lstat, no symbolic link: os.Root
// follows links inside r, and a link swapped in after the open is found
// by the identity).
func openChecked(r *os.Root, name string) (*os.File, fs.FileInfo, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	li, err := r.Lstat(name)
	if err != nil || !li.IsDir() || !fi.IsDir() || !os.SameFile(fi, li) {
		f.Close()
		return nil, nil, fmt.Errorf("%s %w", name, errInitRace)
	}
	return f, fi, nil
}

// createData creates or opens the root in s.parent, gives it
// store.DirPerm, checks rights and group, creates initDirs with
// store.DirPerm, checks the layout and writes platform/witnesses.rec,
// all relative to descriptors.
func createData(ctx context.Context, s *initState, rootPath string, existing fs.FileInfo, wrec []byte) (*initResult, error) {
	if existing == nil {
		if err := s.parent.Mkdir(s.base, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil, fmt.Errorf("--data entstand %w; init ändert es nicht", errInitRace)
			}
			return nil, err
		}
		s.created = true
	}
	r, err := s.parent.OpenRoot(s.base)
	if err != nil {
		// Gone, or a link that leads out of the parent.
		return nil, fmt.Errorf("--data %w (%v)", errInitRace, err)
	}
	s.root = r
	f, fi, err := openChecked(s.parent, s.base)
	if err != nil {
		return nil, fmt.Errorf("--data %w", errInitRace)
	}
	s.rootF = f
	ri, err := r.Stat(".")
	if err != nil || !os.SameFile(ri, fi) {
		return nil, fmt.Errorf("--data %w", errInitRace)
	}
	if existing != nil && !os.SameFile(fi, existing) {
		return nil, fmt.Errorf("--data %w", errInitRace)
	}
	if s.created {
		// The directory init made belongs to the process; another one at
		// that name was swapped in.
		if uid, ok := fileOwner(fi); !ok || uid != os.Geteuid() {
			return nil, fmt.Errorf("--data %w (Eigentümer)", errInitRace)
		}
	}
	s.rootFI = fi
	if existing != nil {
		names, err := f.Readdirnames(1)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(names) != 0 {
			return nil, errNotEmpty
		}
		s.oldMode = fi.Mode() & dirModeBits
	}
	if fi.Mode()&dirModeBits != store.DirPerm {
		if err := f.Chmod(store.DirPerm); err != nil {
			return nil, err
		}
		s.chmoded = existing != nil
	}
	rfi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	res := &initResult{root: rootPath}
	res.gid, res.hasGID = fileGroup(rfi)
	if res.hasGID {
		if !inGroup(res.gid) {
			return nil, fmt.Errorf("der Prozess gehört nicht zur Gruppe %d des Datenverzeichnisses (9.1: Gruppe %s); init als Benutzer der Gruppe ausführen", res.gid, dataGroup)
		}
		if g, err := user.LookupGroupId(strconv.Itoa(res.gid)); err == nil {
			res.groupName = g.Name
		}
	}
	// A setgid bit the system dropped, because the process is not in the
	// group, is found here.
	if rfi.Mode()&dirModeBits != store.DirPerm {
		return nil, fmt.Errorf("Datenverzeichnis: Rechte %v statt 2770 (9.1)", rfi.Mode()&dirModeBits)
	}
	if s.created {
		if err := syncDirIn(s.parent, "."); err != nil {
			return nil, err
		}
	}
	for _, name := range initDirs {
		if err := initCanceled(ctx); err != nil {
			return nil, err
		}
		if err := mkdirChecked(s, res, name); err != nil {
			return nil, err
		}
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := initStage(ctx, "created", rootPath); err != nil {
		return nil, err
	}
	if err := checkNewData(s); err != nil {
		return nil, err
	}
	if err := writeWitnesses(s, wrec); err != nil {
		return nil, err
	}
	return res, nil
}

// mkdirChecked creates name in the root with mode 0700, checks that the
// directory it opens is that entry, records it in s.made, and gives it
// store.DirPerm through its descriptor; the result must have exactly
// store.DirPerm and the group of the root.
func mkdirChecked(s *initState, res *initResult, name string) error {
	if err := s.root.Mkdir(name, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("Datenverzeichnis: %s entstand %w", name, errInitRace)
		}
		return err
	}
	d, fi, err := openChecked(s.root, name)
	if err != nil {
		return err
	}
	defer d.Close()
	s.made[name] = fi
	if err := d.Chmod(store.DirPerm); err != nil {
		return err
	}
	fi, err = d.Stat()
	if err != nil {
		return err
	}
	// The identity with the final mode: a directory made in its place
	// after a removal may reuse the inode, but not the mode 2770 unless
	// it was given that mode on purpose.
	s.made[name] = fi
	if fi.Mode()&dirModeBits != store.DirPerm {
		return fmt.Errorf("Datenverzeichnis: %s hat Rechte %v statt 2770 (9.1)", name, fi.Mode()&dirModeBits)
	}
	if g, ok := fileGroup(fi); res.hasGID && (!ok || g != res.gid) {
		return fmt.Errorf("Datenverzeichnis: %s hat eine andere Gruppe als das Datenverzeichnis", name)
	}
	return nil
}

// checkNewData checks the root just filled: it holds exactly initDirs,
// each the directory init made (identity) and empty.
func checkNewData(s *initState) error {
	f, err := s.root.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	if len(names) != len(initDirs) {
		return fmt.Errorf("Datenverzeichnis: %d Einträge statt %d %w", len(names), len(initDirs), errInitRace)
	}
	for _, name := range names {
		want, ok := s.made[name]
		if !ok {
			return fmt.Errorf("Datenverzeichnis: fremder Eintrag %w", errInitRace)
		}
		d, fi, err := openChecked(s.root, name)
		if err != nil {
			return err
		}
		sub, err := d.Readdirnames(1)
		d.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if !sameEntry(fi, want) {
			return fmt.Errorf("Datenverzeichnis: %s %w", name, errInitRace)
		}
		if len(sub) != 0 {
			return fmt.Errorf("Datenverzeichnis: %s ist nicht leer", name)
		}
	}
	return nil
}

// writeWitnesses creates platform/witnesses.rec with wrec and mode
// store.FilePerm, never replacing a file (store.ErrExists), the way
// store.CreateFileAtomic does but relative to platform/: a temporary
// file (O_EXCL, fchmod, fsync), a hard link to its name, removal of the
// temporary name, fsync of platform/.
func writeWitnesses(s *initState, wrec []byte) error {
	p, err := s.root.OpenRoot("platform")
	if err != nil {
		return err
	}
	s.plat = p
	if pi, err := p.Stat("."); err != nil || !os.SameFile(pi, s.made["platform"]) {
		return fmt.Errorf("platform %w", errInitRace)
	}
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return err
	}
	tmp := ".tmp-" + hex.EncodeToString(rnd[:])
	tf, err := p.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer p.Remove(tmp)
	err = tf.Chmod(store.FilePerm)
	if err == nil {
		_, err = tf.Write(wrec)
	}
	if err == nil {
		err = tf.Sync()
	}
	var tfi fs.FileInfo
	if err == nil {
		tfi, err = tf.Stat()
	}
	if cerr := tf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := p.Link(tmp, ceremony.WitnessesFile); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: platform/%s", store.ErrExists, ceremony.WitnessesFile)
		}
		return err
	}
	s.wrecFI = tfi
	if err := p.Remove(tmp); err != nil {
		return err
	}
	return syncDirIn(p, ".")
}

// syncDirIn fsyncs the directory name in r.
func syncDirIn(r *os.Root, name string) error {
	d, err := r.Open(name)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// emptyDir reports whether the directory dir has no entry (the check
// before init opens anything; createData checks again on the
// descriptor).
func emptyDir(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(names) == 0, nil
}

// sameEntry reports whether a and b are the same file (device and
// inode) with the same mode.
func sameEntry(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode()
}

// rollbackInit undoes what createData made, relative to the descriptors
// and only by identity (os.SameFile with the Lstat of the entry, never a
// link): platform/witnesses.rec if init linked it, the directories of
// s.made (sameEntry; Remove, so only empty ones; a foreign or replaced
// entry and a directory with content stay), then the root if init
// created it (same file, owned by the process, empty only, never by
// path), or else the mode an existing root had before.
// Errors are ignored: the error that led here is reported.
func rollbackInit(s *initState) {
	if s.plat != nil && s.wrecFI != nil {
		if li, err := s.plat.Lstat(ceremony.WitnessesFile); err == nil && li.Mode().IsRegular() && os.SameFile(li, s.wrecFI) {
			s.plat.Remove(ceremony.WitnessesFile)
		}
	}
	if s.root != nil {
		for name, fi := range s.made {
			if li, err := s.root.Lstat(name); err == nil && li.IsDir() && sameEntry(li, fi) {
				s.root.Remove(name)
			}
		}
	}
	if s.rootFI == nil {
		return
	}
	if s.created {
		uid, ok := 0, false
		li, err := s.parent.Lstat(s.base)
		if err == nil {
			uid, ok = fileOwner(li)
		}
		if err == nil && li.IsDir() && os.SameFile(li, s.rootFI) && ok && uid == os.Geteuid() {
			s.parent.Remove(s.base)
		}
		return
	}
	if s.chmoded {
		s.rootF.Chmod(s.oldMode)
	}
}
