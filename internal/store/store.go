package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
)

// Size limits of files read from the data directory (DECISIONS D48).
const (
	MaxUserFile      = 512 << 10
	MaxRecordFile    = 64 << 10 // epoch.rec, mailbox.rec, notes, certificates
	MaxWrapFile      = 16 << 10
	MaxMetaFile      = 512 << 10
	MaxPendingFile   = 2 << 20
	MaxAddressesFile = 16 << 20
	MaxInviteFile    = 4 << 10
	MaxJournalFile   = 256 << 10
	MaxMailFile      = envelope.MaxFileSize
)

// Store is a data directory.
type Store struct {
	Root string
}

// topDirs are created by Init.
var topDirs = []string{"platform", "users", "invites", "mailboxes", "spool", "work"}

// Init creates the layout of section 4 below root (if missing), sets the
// root to DirPerm (9.1) and returns the store. New directories get
// DirPerm; the group (gomail) is the administrator's choice when creating
// root and is inherited through setgid.
func Init(root string) (*Store, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := MkdirAll(root); err != nil {
		return nil, err
	}
	if err := chmodDir(root); err != nil {
		return nil, err
	}
	for _, d := range append(topDirs, locksDir) {
		if err := MkdirAll(filepath.Join(root, d)); err != nil {
			return nil, err
		}
	}
	return &Store{Root: root}, nil
}

// Open returns the store at root, which must have been initialized.
func Open(root string) (*Store, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, d := range topDirs {
		fi, err := os.Stat(filepath.Join(root, d))
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("%w: %s is not an initialized data directory", ErrNotFound, root)
		}
	}
	return &Store{Root: root}, nil
}

// ------------------------------------------------------------------ paths

// Path joins elements below the root.
func (s *Store) Path(elem ...string) string {
	return filepath.Join(append([]string{s.Root}, elem...)...)
}

// Rel returns path relative to the root with slashes (for journals).
func (s *Store) Rel(path string) (string, error) {
	r, err := filepath.Rel(s.Root, path)
	if err != nil {
		return "", err
	}
	r = filepath.ToSlash(r)
	if !safeRel(r) {
		return "", fmt.Errorf("store: path outside the data directory")
	}
	return r, nil
}

// Abs resolves a journal path.
func (s *Store) Abs(rel string) (string, error) {
	if !safeRel(rel) {
		return "", fmt.Errorf("store: unsafe relative path")
	}
	return s.Path(filepath.FromSlash(rel)), nil
}

func epochDir(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func (s *Store) SpoolDir() string          { return s.Path("spool") }
func (s *Store) WorkDir() string           { return s.Path("work") }
func (s *Store) UserFile(id ID) string     { return s.Path("users", id.String(), "user.rec") }
func (s *Store) InviteFile(code ID) string { return s.Path("invites", code.String()+".json") }
func (s *Store) AddressesFile() string     { return s.Path("addresses.json") }
func (s *Store) MailboxDir(id ID) string   { return s.Path("mailboxes", id.String()) }
func (s *Store) MailboxFile(id ID) string  { return filepath.Join(s.MailboxDir(id), "mailbox.rec") }
func (s *Store) NoteFile(id ID) string     { return filepath.Join(s.MailboxDir(id), "epoch-fallback.rec") }
func (s *Store) EpochDir(id ID, n uint32) string {
	return filepath.Join(s.MailboxDir(id), "epochs", epochDir(n))
}
func (s *Store) EpochFile(id ID, n uint32) string {
	return filepath.Join(s.EpochDir(id, n), "epoch.rec")
}
func (s *Store) MailDir(id, folder ID) string {
	return filepath.Join(s.MailboxDir(id), "mail", folder.String())
}
func (s *Store) PendingDir(id ID, n uint32) string {
	return filepath.Join(s.MailboxDir(id), "pending", epochDir(n))
}

func (s *Store) WrapFile(id ID, n uint32, user ID) string {
	return filepath.Join(s.EpochDir(id, n), "members", user.String()+".wrap")
}
func (s *Store) MailFile(id, folder, mail ID) string {
	return filepath.Join(s.MailDir(id, folder), mail.String()+".gml")
}
func (s *Store) MetaFile(id, folder, mail ID) string {
	return filepath.Join(s.MailDir(id, folder), mail.String()+".meta.gml")
}
func (s *Store) PendingFile(id ID, n uint32, file ID) string {
	return filepath.Join(s.PendingDir(id, n), file.String()+".gml")
}

// ------------------------------------------------------------------ users

// CreateUser writes users/<id>/user.rec; it fails with ErrExists if the
// user exists.
func (s *Store) CreateUser(u *User) error {
	data, err := u.Encode()
	if err != nil {
		return err
	}
	if err := MkdirAll(filepath.Dir(s.UserFile(u.ID))); err != nil {
		return err
	}
	return CreateFileAtomic(s.UserFile(u.ID), data)
}

// ReadUser reads and verifies user.rec of id: structure, generation chain
// and that the ID in the record is the ID of its directory.
func (s *Store) ReadUser(id ID) (*User, []byte, error) {
	data, err := ReadFileLimited(s.UserFile(id), MaxUserFile)
	if err != nil {
		return nil, nil, err
	}
	u, err := DecodeUser(data)
	if err != nil {
		return nil, nil, err
	}
	if u.ID != id {
		return nil, nil, fmt.Errorf("%w: user.rec of %s names another user", ErrRecord, id)
	}
	return u, data, nil
}

// ---------------------------------------------------------------- invites

type inviteJSON struct {
	Created int64 `json:"created"`
}

// CreateInvite writes invites/<code>.json for a new random code and
// returns the code (2.2).
func (s *Store) CreateInvite(nowMillis int64) (ID, error) {
	code, err := NewID(nil)
	if err != nil {
		return ID{}, err
	}
	data, _ := json.Marshal(inviteJSON{Created: nowMillis})
	if err := CreateFileAtomic(s.InviteFile(code), data); err != nil {
		return ID{}, err
	}
	return code, nil
}

// ErrInvite reports an unknown or used invitation code.
var ErrInvite = errors.New("store: unknown or used invitation code")

// ConsumeInvite takes the invitation code out of use. Exactly one caller
// succeeds: the file is renamed away atomically before it is deleted, so
// a code is never used twice, even after a crash (then it is lost).
func (s *Store) ConsumeInvite(code ID) error {
	src := s.InviteFile(code)
	if _, err := ReadFileLimited(src, MaxInviteFile); err != nil {
		return ErrInvite
	}
	claimed := s.Path("invites", tmpPrefix+"used-"+code.String())
	if err := os.Rename(src, claimed); err != nil {
		return ErrInvite
	}
	if err := SyncDir(filepath.Dir(src)); err != nil {
		return err
	}
	return RemoveDurable(claimed)
}

// -------------------------------------------------------------- addresses

// ErrAddress reports a malformed address.
var ErrAddress = errors.New("store: malformed address")

// NormalizeAddress returns the canonical form of a mailbox address used
// as key in addresses.json: lowercase ASCII local@domain, at most 254
// bytes (DECISIONS D53). Internationalized addresses are not supported in
// the PoC.
func NormalizeAddress(a string) (string, error) {
	if len(a) == 0 || len(a) > 254 {
		return "", ErrAddress
	}
	at := strings.IndexByte(a, '@')
	if at <= 0 || at == len(a)-1 || strings.Count(a, "@") != 1 {
		return "", ErrAddress
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("\"(),:;<>[\\]", c) >= 0 {
			return "", ErrAddress
		}
	}
	domain := a[at+1:]
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", ErrAddress
	}
	return strings.ToLower(a), nil
}

type addressesJSON struct {
	Addresses map[string]string `json:"addresses"`
}

// Addresses is the working copy addresses.json: address to mailbox (2.3).
type Addresses map[string]ID

// LoadAddresses reads addresses.json. A missing file is an empty table.
// Every key must be a normalized address and every value a mailbox ID.
func (s *Store) LoadAddresses() (Addresses, error) {
	data, err := ReadFileLimited(s.AddressesFile(), MaxAddressesFile)
	if errors.Is(err, ErrNotFound) {
		return Addresses{}, nil
	}
	if err != nil {
		return nil, err
	}
	var aj addressesJSON
	if err := json.Unmarshal(data, &aj); err != nil {
		return nil, fmt.Errorf("%w: addresses.json: %v", ErrRecord, err)
	}
	out := make(Addresses, len(aj.Addresses))
	for a, m := range aj.Addresses {
		na, err := NormalizeAddress(a)
		if err != nil || na != a {
			return nil, fmt.Errorf("%w: addresses.json has a malformed address", ErrRecord)
		}
		id, err := ParseID(m)
		if err != nil {
			return nil, fmt.Errorf("%w: addresses.json has a malformed mailbox id", ErrRecord)
		}
		out[a] = id
	}
	return out, nil
}

// AddAddress assigns address to mailbox in addresses.json under the
// addresses lock. An existing assignment to another mailbox is an error.
func (s *Store) AddAddress(address string, mailbox ID) (string, error) {
	a, err := NormalizeAddress(address)
	if err != nil {
		return "", err
	}
	unlock, err := lockFile(s.Path("addresses.lock"))
	if err != nil {
		return "", err
	}
	defer unlock()
	cur, err := s.LoadAddresses()
	if err != nil {
		return "", err
	}
	if old, ok := cur[a]; ok && old != mailbox {
		return "", fmt.Errorf("%w: %s is assigned to another mailbox", ErrExists, a)
	}
	cur[a] = mailbox
	aj := addressesJSON{Addresses: make(map[string]string, len(cur))}
	for k, v := range cur {
		aj.Addresses[k] = v.String()
	}
	data, err := json.MarshalIndent(aj, "", "  ")
	if err != nil {
		return "", err
	}
	return a, WriteFileAtomic(s.AddressesFile(), append(data, '\n'))
}

// --------------------------------------------------------------- platform

func (s *Store) platformFile(name string) string { return s.Path("platform", name) }

// PlatformFileName returns "<role>-<gen>.<ext>" (section 4).
func PlatformFileName(role string, gen uint32, ext string) string {
	return fmt.Sprintf("%s-%d.%s", role, gen, ext)
}

// WritePlatformFile writes a public platform file (key, certificate,
// succession). Existing files are never replaced.
func (s *Store) WritePlatformFile(name string, data []byte) error {
	return CreateFileAtomic(s.platformFile(name), data)
}

// ReadPlatformFile reads a public platform file.
func (s *Store) ReadPlatformFile(name string) ([]byte, error) {
	return ReadFileLimited(s.platformFile(name), MaxRecordFile)
}

// ReadPlatformCert reads and decodes <role>-<gen>.cert and checks that it
// is a certificate of that role and generation and that <role>-<gen>.pub
// holds the same key. The signature is checked by the caller with the
// trusted identity.
func (s *Store) ReadPlatformCert(role keys.Role, gen uint32) (*keys.PlatformCert, error) {
	name := "admin"
	if role == keys.RoleIngest {
		name = "ingest"
	}
	data, err := s.ReadPlatformFile(PlatformFileName(name, gen, "cert"))
	if err != nil {
		return nil, err
	}
	c, err := keys.DecodePlatformCert(data)
	if err != nil {
		return nil, err
	}
	if c.Role != role || c.Gen != gen {
		return nil, fmt.Errorf("%w: %s-%d.cert certifies another key", ErrRecord, name, gen)
	}
	pub, err := s.ReadPlatformFile(PlatformFileName(name, gen, "pub"))
	if err != nil {
		return nil, err
	}
	if !ed25519.PublicKey(pub).Equal(c.Pub) {
		return nil, fmt.Errorf("%w: %s-%d.pub differs from its certificate", ErrRecord, name, gen)
	}
	return c, nil
}

// -------------------------------------------------------------- mailboxes

// LockMailbox takes the exclusive lock of a mailbox (a POSIX record lock
// on mailboxes/<id>/lock, see lock_unix.go) and waits for it. Writers of
// mailbox.rec, epochs, notes and the commit of received mails hold it;
// there is no global lock.
//
// Over NFS a reader must open and read a file such as mailbox.rec only
// after it holds the lock: taking the lock makes the NFS client check its
// cache of the files opened afterwards, while a file opened before may
// still show cached contents (K8).
func (s *Store) LockMailbox(id ID) (func(), error) {
	if err := MkdirAll(s.MailboxDir(id)); err != nil {
		return nil, err
	}
	return lockFile(filepath.Join(s.MailboxDir(id), "lock"))
}

// LockMailboxes locks several mailboxes in a fixed order (by ID) so that
// concurrent callers cannot deadlock.
func (s *Store) LockMailboxes(ids []ID) (func(), error) {
	sorted := append([]ID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i][:]) < string(sorted[j][:]) })
	var unlocks []func()
	release := func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
	for i, id := range sorted {
		if i > 0 && id == sorted[i-1] {
			continue
		}
		u, err := s.LockMailbox(id)
		if err != nil {
			release()
			return nil, err
		}
		unlocks = append(unlocks, u)
	}
	return release, nil
}

// WriteMailbox replaces mailbox.rec.
func (s *Store) WriteMailbox(m *Mailbox) error {
	data, err := m.Encode()
	if err != nil {
		return err
	}
	if err := MkdirAll(s.MailboxDir(m.ID)); err != nil {
		return err
	}
	return WriteFileAtomic(s.MailboxFile(m.ID), data)
}

// ReadMailbox reads mailbox.rec and checks that it belongs to id.
func (s *Store) ReadMailbox(id ID) (*Mailbox, error) {
	data, err := ReadFileLimited(s.MailboxFile(id), MaxRecordFile)
	if err != nil {
		return nil, err
	}
	m, err := DecodeMailbox(data)
	if err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("%w: mailbox.rec of %s names another mailbox", ErrRecord, id)
	}
	return m, nil
}

// WriteEpoch creates epochs/<n>/epoch.rec, content.pub and meta.pub. An
// existing epoch is never replaced (epochs are append-only, 2.4).
func (s *Store) WriteEpoch(e *Epoch) ([]byte, error) {
	data, err := e.Encode()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.EpochFile(e.MailboxID, e.Number)); err == nil {
		return nil, fmt.Errorf("%w: epoch %d", ErrExists, e.Number)
	}
	dir := s.EpochDir(e.MailboxID, e.Number)
	if err := MkdirAll(filepath.Join(dir, "members")); err != nil {
		return nil, err
	}
	// The public key files are copies for readers of section 4; the
	// signed epoch.rec is authoritative. They are written first so that a
	// visible epoch.rec always has them.
	if err := WriteFileAtomic(filepath.Join(dir, "content.pub"), e.ContentPub.Bytes()); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(filepath.Join(dir, "meta.pub"), e.MetaPub.Bytes()); err != nil {
		return nil, err
	}
	if err := CreateFileAtomic(s.EpochFile(e.MailboxID, e.Number), data); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadEpoch reads epochs/<n>/epoch.rec and checks that it belongs to
// mailbox id and number n. It returns the raw bytes for the chain hash.
// The signature and the chain are checked by the caller.
func (s *Store) ReadEpoch(id ID, n uint32) (*Epoch, []byte, error) {
	data, err := ReadFileLimited(s.EpochFile(id, n), MaxRecordFile)
	if err != nil {
		return nil, nil, err
	}
	e, err := DecodeEpoch(data)
	if err != nil {
		return nil, nil, err
	}
	if e.MailboxID != id || e.Number != n {
		return nil, nil, fmt.Errorf("%w: epochs/%d/epoch.rec names mailbox or epoch differently", ErrChain, n)
	}
	return e, data, nil
}

// WriteWrap writes members/<user>.wrap of epoch n, replacing an older
// wrap (a new generation needs a new wrap, 2.2).
func (s *Store) WriteWrap(id ID, n uint32, user ID, data []byte) error {
	if err := MkdirAll(filepath.Dir(s.WrapFile(id, n, user))); err != nil {
		return err
	}
	return WriteFileAtomic(s.WrapFile(id, n, user), data)
}

// ReadWrap reads members/<user>.wrap of epoch n.
func (s *Store) ReadWrap(id ID, n uint32, user ID) ([]byte, error) {
	return ReadFileLimited(s.WrapFile(id, n, user), MaxWrapFile)
}

// ListEpochs returns the numbers of the epoch directories, sorted.
// Entries that are not canonical decimal numbers are ignored.
func (s *Store) ListEpochs(id ID) ([]uint32, error) {
	return listNumbers(filepath.Join(s.MailboxDir(id), "epochs"))
}

func listNumbers(dir string) ([]uint32, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []uint32
	for _, e := range entries {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || n == 0 || epochDir(uint32(n)) != e.Name() || !e.IsDir() {
			continue
		}
		out = append(out, uint32(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ----------------------------------------------------------- mail files

// ListMails returns the mail IDs in a folder (files <id>.gml), sorted.
// Names that are not canonical IDs are ignored.
func (s *Store) ListMails(id, folder ID) ([]ID, error) {
	return listIDs(s.MailDir(id, folder), ".gml", ".meta.gml")
}

// ListPending returns the file IDs in pending/<n>/, sorted.
func (s *Store) ListPending(id ID, n uint32) ([]ID, error) {
	return listIDs(s.PendingDir(id, n), ".gml", "")
}

// ListPendingEpochs returns the epochs that have a pending directory.
func (s *Store) ListPendingEpochs(id ID) ([]uint32, error) {
	return listNumbers(filepath.Join(s.MailboxDir(id), "pending"))
}

func listIDs(dir, suffix, exclude string) ([]ID, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []ID
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, suffix) || exclude != "" && strings.HasSuffix(name, exclude) {
			continue
		}
		id, err := ParseID(strings.TrimSuffix(name, suffix))
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out, nil
}

// ReadMail reads an encrypted mail file.
func (s *Store) ReadMail(id, folder, mail ID) ([]byte, error) {
	return ReadFileLimited(s.MailFile(id, folder, mail), MaxMailFile)
}

// ReadMeta reads an encrypted metadata file.
func (s *Store) ReadMeta(id, folder, mail ID) ([]byte, error) {
	return ReadFileLimited(s.MetaFile(id, folder, mail), MaxMetaFile)
}

// ReadPending reads a term list or marker.
func (s *Store) ReadPending(id ID, n uint32, file ID) ([]byte, error) {
	return ReadFileLimited(s.PendingFile(id, n, file), MaxPendingFile)
}

// ------------------------------------------------------------------ notes

// ReadNote reads epoch-fallback.rec; nil if there is none.
func (s *Store) ReadNote(id ID) (*EpochNote, error) {
	data, err := ReadFileLimited(s.NoteFile(id), MaxRecordFile)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n, err := DecodeEpochNote(data)
	if err != nil {
		return nil, err
	}
	if n.MailboxID != id {
		return nil, fmt.Errorf("%w: note names another mailbox", ErrRecord)
	}
	return n, nil
}

// WriteNote replaces epoch-fallback.rec. The caller holds the mailbox lock.
func (s *Store) WriteNote(n *EpochNote) error {
	data, err := n.Encode()
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.NoteFile(n.MailboxID), data)
}

// RemoveNote deletes epoch-fallback.rec.
func (s *Store) RemoveNote(id ID) error { return RemoveDurable(s.NoteFile(id)) }

// ListFolders returns the folder directories below mail/, sorted.
func (s *Store) ListFolders(id ID) ([]ID, error) {
	entries, err := os.ReadDir(filepath.Join(s.MailboxDir(id), "mail"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []ID
	for _, e := range entries {
		if fid, err := ParseID(e.Name()); err == nil && e.IsDir() {
			out = append(out, fid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out, nil
}

// WriteFolders replaces epochs/<n>/folders.gml atomically: the list of an
// epoch changes whenever a member changes the folders (section 4).
func (s *Store) WriteFolders(id ID, n uint32, data []byte) error {
	if err := MkdirAll(s.EpochDir(id, n)); err != nil {
		return err
	}
	return WriteFileAtomic(s.FoldersFile(id, n), data)
}

// ReadFolders reads epochs/<n>/folders.gml.
func (s *Store) ReadFolders(id ID, n uint32) ([]byte, error) {
	return ReadFileLimited(s.FoldersFile(id, n), MaxMetaFile)
}

// FoldersFile is epochs/<n>/folders.gml: name and folder list of the
// mailbox, sealed for the meta key of epoch n (section 4, S20).
func (s *Store) FoldersFile(id ID, n uint32) string {
	return filepath.Join(s.EpochDir(id, n), "folders.gml")
}

// RemoveIncompleteEpoch deletes epochs/<n>/ if it has no epoch.rec (the
// leftovers of an interrupted epoch creation: wraps and public keys
// without the signed record). An existing epoch.rec is reported as
// ErrExists and nothing is removed.
func (s *Store) RemoveIncompleteEpoch(id ID, n uint32) error {
	if _, err := os.Lstat(s.EpochFile(id, n)); err == nil {
		return fmt.Errorf("%w: epoch %d", ErrExists, n)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := s.EpochDir(id, n)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(dir))
}

// RemoveTempFiles deletes the temporary files of interrupted atomic
// writes anywhere in the data directory (server start).
func (s *Store) RemoveTempFiles() error {
	return filepath.WalkDir(s.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), tmpPrefix) && d.Type().IsRegular() {
			return RemoveDurable(p)
		}
		return nil
	})
}

// LockFile takes an exclusive record lock on path (created with mode
// FilePerm if missing) without waiting; it fails with ErrLocked if
// another process or another caller in this process holds it.
func LockFile(path string) (func(), error) { return tryLockFile(path) }

// ------------------------------------------------------------ role locks

// locksDir holds the lock files of the start check (9.1).
const locksDir = "locks"

// Role is a program that works on the data directory.
type Role int

const (
	RoleServer Role = 1 + iota // gomail-server
	RoleClient                 // gomailctl
)

// ErrPeerLock reports that the other side holds no lock that is in force
// here: it does not run, or locks do not work across the file system
// (9.1, "Testsperre").
var ErrPeerLock = errors.New("store: no effective lock of the other side")

func (s *Store) roleLockFile(r Role) (string, error) {
	switch r {
	case RoleServer:
		return s.Path(locksDir, "server"), nil
	case RoleClient:
		return s.Path(locksDir, "client"), nil
	}
	return "", fmt.Errorf("store: unknown role %d", r)
}

// HoldRoleLock takes the lock of role on locks/server or locks/client
// without waiting and keeps it until release is called, for the whole
// run of the program (9.1). The server lock is exclusive: a second server
// fails with ErrLocked. The client lock is shared, because several
// clients of different users may run at the same time; a second client
// in the same process fails with ErrLocked.
func (s *Store) HoldRoleLock(role Role) (release func(), err error) {
	p, err := s.roleLockFile(role)
	if err != nil {
		return nil, err
	}
	if err := MkdirAll(filepath.Dir(p)); err != nil {
		return nil, err
	}
	return lockPath(p, role == RoleServer, false)
}

// CheckPeerLock tests the lock of the other side (9.1): it tries to take
// an exclusive lock on its lock file without waiting. If that succeeds,
// the other side holds no lock that is in force here, and CheckPeerLock
// reports ErrPeerLock (also when the lock file does not exist). If the
// lock is held, it returns nil. Any other failure is returned as it is:
// it proves nothing (fail closed). The client checks the running server
// this way; the server at its start only takes its own lock.
func (s *Store) CheckPeerLock(peer Role) error {
	p, err := s.roleLockFile(peer)
	if err != nil {
		return err
	}
	switch err := probeLock(p); {
	case errors.Is(err, ErrLocked):
		return nil
	case err == nil:
		return fmt.Errorf("%w: %s is not locked", ErrPeerLock, filepath.Base(p))
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s does not exist", ErrPeerLock, filepath.Base(p))
	default:
		return err
	}
}
