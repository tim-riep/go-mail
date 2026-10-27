package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Start checks of "gomail-server serve" (task 15).

// platformName matches the generation files of platform/ (section 4):
// identity-<g>.pub, identity-<g>.succ, admin-<g>.cert, ingest-<g>.cert
// and their .pub files.
var platformName = regexp.MustCompile(`^(identity|admin|ingest)-([1-9][0-9]{0,9})\.(pub|cert|succ)$`)

// checkPlatformPin enforces the operating rule of task 07 finding Q10
// (5) (translog doc.go "Tasks" point 11): after a succession of the
// platform identity the operator installs the new pin on the server
// before ceremony.Publish and before the server restarts. The server
// refuses to start (translog.ErrMismatch) when platform/ names an
// identity generation the pin does not know (identity-<g>.pub or
// identity-<g>.succ with g above the pin's generation, a certificate
// issued by such a generation), or when it contradicts the pin's
// identity list (identity-<g>.pub or identity-<g>.succ of a listed
// generation with another key). Otherwise the server would judge the
// new successions and certificates against another identity list than
// the clients. A file that does not decode is refused as well (fail
// closed). Other files of platform/ (witnesses.rec, temporary files)
// are not looked at.
func checkPlatformPin(st *store.Store, pin *store.PlatformPin) error {
	entries, err := os.ReadDir(st.Path("platform"))
	if err != nil {
		return err
	}
	listed := func(g uint32) ed25519.PublicKey {
		for _, id := range pin.Identities {
			if id.Gen == g {
				return id.Pub
			}
		}
		return nil
	}
	unknown := func(name string, g uint32) error {
		return fmt.Errorf("%w: platform/%s nennt die Identitätsgeneration %d, der Pin (--pin) kennt nur 1 bis %d; "+
			"nach einer Nachfolge zuerst den neuen Pin auf dem Server installieren (Betriebsregel, Q10 Punkt 5)",
			translog.ErrMismatch, name, g, pin.Gen)
	}
	contradicts := func(name string) error {
		return fmt.Errorf("%w: platform/%s widerspricht der Identitätsliste des Pins (--pin)", translog.ErrMismatch, name)
	}
	for _, e := range entries {
		m := platformName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			continue
		}
		g, name := uint32(n), e.Name()
		switch {
		case m[1] == "identity" && m[3] == "cert":
			continue // no such file in section 4
		case m[1] == "identity":
			if g > pin.Gen {
				return unknown(name, g)
			}
			data, err := st.ReadPlatformFile(name)
			if err != nil {
				return err
			}
			want := listed(g)
			if m[3] == "pub" {
				if !bytes.Equal(data, want) {
					return contradicts(name)
				}
				continue
			}
			s, err := keys.DecodePlatformSuccession(data)
			if err != nil {
				return fmt.Errorf("platform/%s: %w", name, err)
			}
			if s.Gen != g || !s.Pub.Equal(want) {
				return contradicts(name)
			}
		case m[3] == "cert":
			data, err := st.ReadPlatformFile(name)
			if err != nil {
				return err
			}
			c, err := keys.DecodePlatformCert(data)
			if err != nil {
				return fmt.Errorf("platform/%s: %w", name, err)
			}
			if c.IdentityGen > pin.Gen {
				return unknown(name, c.IdentityGen)
			}
		}
	}
	return nil
}

// checkDataDir checks the rights of 9.1 (D70) on the data directory and
// its top-level entries: nothing may be open to others (refused: files
// 0660, directories 2770); a directory without setgid, an entry the
// group cannot read and write and a group of the data directory the
// server does not belong to are warnings, because the client (another
// user of the group gomail) may then fail on files the server writes.
//
// Only the root and its top-level entries are checked (task 15c finding
// 8), not the whole tree: deeper directories inherit the group and the
// setgid bit from these through setgid (2770), and the programs create
// files and directories with the rights of 9.1 (store.FilePerm,
// store.DirPerm). A deeper entry changed by hand is not found here; the
// start message says so.
func checkDataDir(st *store.Store, logger *slog.Logger) error {
	// Symbolic links are followed: the rights that count are those of the
	// file or directory the server reads and writes.
	root, err := os.Stat(st.Root)
	if err != nil {
		return err
	}
	if !root.IsDir() {
		return fmt.Errorf("das Datenverzeichnis ist kein Verzeichnis")
	}
	entries, err := os.ReadDir(st.Root)
	if err != nil {
		return err
	}
	infos := []fs.FileInfo{root}
	names := []string{"."}
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(st.Root, e.Name()))
		if err != nil {
			return err
		}
		infos, names = append(infos, fi), append(names, e.Name())
	}
	for i, fi := range infos {
		mode := fi.Mode()
		if mode.Perm()&0o007 != 0 {
			return fmt.Errorf("%s im Datenverzeichnis ist für andere zugänglich (Rechte %04o; 9.1: Dateien 0660, Verzeichnisse 2770)", names[i], mode.Perm())
		}
		if mode.Perm()&0o060 != 0o060 {
			logger.Warn("data directory entry not readable and writable by the group (9.1)", "entry", names[i], "mode", fmt.Sprintf("%04o", mode.Perm()))
		}
		if fi.IsDir() && mode&fs.ModeSetgid == 0 {
			logger.Warn("data directory entry without setgid; new files do not inherit the group gomail (9.1)", "entry", names[i])
		}
	}
	if gid, ok := fileGroup(root); ok && !inGroup(gid) {
		logger.Warn("the server is not in the group of the data directory (9.1: group gomail)", "gid", gid)
	}
	logger.Info("data directory rights checked (9.1): root and top-level entries only; deeper entries inherit the group through setgid", "entries", len(infos))
	return nil
}

// checkDiskSpace reports at the start when the free space of the data
// directory cannot be determined (task 15c finding 5: NetBSD and Windows,
// where package syscall has no statfs; ingest refuses every mail then,
// 5.1, fail closed).
func checkDiskSpace(space func() (free, total uint64, err error), logger *slog.Logger) {
	if _, _, err := space(); err != nil {
		logger.Warn("free space of the data directory unknown: the server accepts no mail until DiskSpace is set (5.1)", "reason", err.Error())
	}
}

// checkLocks is the start check of 9.1 ("Testsperre", D70) on the
// server side. The server holds locks/server exclusively from
// ingest.New on; a second server on the data directory fails there. Here
// it checks that its own lock is in force through a second open file
// description (store.CheckPeerLock on its own role: on Linux an OFD lock
// conflicts with every other description, so a file system that accepts
// record locks without enforcing them fails here). Whether a client's
// lock is in force is only logged by default: a server cannot require a
// running client (D70); the client refuses to work without an effective
// server lock (gomailctl). With requireClient (--require-client-lock,
// task 15c finding 3) ingest.New has already required it
// (Config.PeerCheck), and a client lock that is not in force is refused
// here as well.
func checkLocks(st *store.Store, requireClient bool, logger *slog.Logger) error {
	if err := st.CheckPeerLock(store.RoleServer); err != nil {
		return fmt.Errorf("Testsperre: die Serversperre locks/server ist nicht wirksam (9.1): %w", err)
	}
	switch err := st.CheckPeerLock(store.RoleClient); {
	case err == nil:
		logger.Info("client lock in force (9.1)")
	case requireClient:
		return fmt.Errorf("Testsperre: --require-client-lock verlangt eine wirksame Client-Sperre locks/client (9.1): %w", err)
	case errors.Is(err, store.ErrPeerLock):
		logger.Info("no client lock held; clients check the server lock when they start (9.1)")
	default:
		return fmt.Errorf("Testsperre: locks/client: %w", err)
	}
	return nil
}

// checkHead is the start check of the log: SignHead runs every check of
// a head without writing anything (translog Operator.SignHead: tree.rec
// not rolled back below a published head or an existing entry, the
// committed tree extends the newest published head, the root hash
// recomputed from the entries, the files synced, the ingest generation
// covers now). An inconsistent log stops the start; invalid entries
// written past Append are an alert only, as for every head.
func checkHead(op translog.Operator, signer note.Signer, now time.Time, logger *slog.Logger) error {
	h, err := op.SignHead(signer, now)
	var inv *translog.InvalidEntriesError
	if h != nil && errors.As(err, &inv) {
		logger.Error("invalid entries in the log (written past Append); every audit skips them", "count", len(inv.Entries))
		err = nil
	}
	if err != nil {
		return fmt.Errorf("Transparenzlog beim Start: %w", err)
	}
	logger.Info("log checked", "size", h.Size)
	return nil
}
