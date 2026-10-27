// Package witness is the witness of 2.7 ("Zeugen (verbindlich)") and the
// HTTP protocol between the log server and its witnesses. Task 03 fixes
// the interface; task 08 builds the witness and the program
// gomail-witness, task 11 the server side of the protocol.
//
// A witness is a small service on another machine or with another
// operator. It keeps, per log origin, the last head it cosigned, checks
// every new head for consistency with it and cosigns only then. It never
// cosigns two heads of one origin and size with different hashes: for
// each log there is at most one view per witness (2.7). Clients accept a
// head only with cosignatures of MinWitnesses pinned witnesses
// (translog.Verifier).
//
// # Program
//
//	gomail-witness keygen --name <name> --key <file>
//	gomail-witness serve --log <url> --log-key <vkey> [--log-key <vkey>] --origin <origin>
//	                     --key <file> --state <dir> [--interval 10s]
//
// keygen writes a note signer key ("PRIVATE+KEY+<name>+<hash>+<base64>",
// one line, rights 0600, never replaced) and prints the verifier key line
// "<name>+<hash>+<base64>" for witnesses.rec and the client pin. The
// name follows CheckName. serve polls the log (pull); --log-key is the
// verifier key of the log signer (translog.LogSignerName with the ingest
// key, Q4) and is repeated during an ingest rotation, because the
// witness cannot verify ingest certificates itself (Reading: the witness
// operator adds the new key after "gomail-ceremony ingest-rotate").
// --origin pins the origin. Additions to 9.2, proposed by task 03: 9.2
// names only "gomail-witness serve --log <url> --key <file>"; the
// command "gomail-witness keygen" and the flags --log-key, --origin,
// --state and --interval are additions.
//
// # Protocol (HTTP, standard library only)
//
// All bodies are text/plain; charset=utf-8. Error bodies are one line of
// ASCII without data from the request. Requests and responses larger
// than their limits are refused (413) before they are read further.
//
//	GET  /gomail/log/head
//	     200  the newest candidate head: a note (translog.Head) signed by
//	          the log, with the cosignatures collected so far
//	     404  the server has not signed a head yet
//	GET  /gomail/log/consistency?from=<n>&to=<m>
//	     n, m decimal without sign or leading zeros,
//	     1 <= n <= m <= translog.MaxTreeSize
//	     200  the proof tlog.ProveTree(m, n), one base64 hash per line
//	          (FormatProof); empty body for n == m
//	     400  malformed, n > m or m > translog.MaxTreeSize (refused
//	          before tlog runs, task 03b finding A5)
//	     404  m larger than the size of the newest candidate head
//	POST /gomail/log/cosign
//	     body: the head as returned by Witness.Cosign: the same text as a
//	          candidate or published head with exactly two signature
//	          lines, the log signature and the witness's own
//	          cosignature; the witness never forwards the cosignatures
//	          of other witnesses that the candidate carried (task 03c
//	          finding 8d)
//	     200  stored; the server opened the body with the log key and
//	          the keys of its working copy witnesses.rec, discarded
//	          every line by a key it does not know (never stored, never
//	          a reason to refuse), merged the verified cosignature into
//	          the candidate and, once the candidate has witnesses.rec's
//	          minimum, wrote heads/<size>.sig
//	          (translog.Operator.PublishHead). Only lines the server
//	          verified are ever kept or stored (finding A2-10)
//	     400  not a well-formed head, or no valid cosignature of a
//	          witness in witnesses.rec left after discarding unknown
//	          lines (nothing to merge)
//	     403  a line with a known name and key hash whose signature does
//	          not verify (the log signature or a cosignature): it is
//	          never merged, because it would make the stored note
//	          unopenable for every client (finding A2-10)
//	     409  the text is neither the current candidate nor the published
//	          head of that size (the witness fetches again)
//	     405  wrong method on any path; 404 any other path
//
// Reading: the witness pulls and posts back (the server needs no route
// to the witness and the witness opens no port). The alternative, the
// server pushing heads to a witness endpoint as in the C2SP witness
// protocol, needs a listening witness; it can be added later without
// changing the head format.
//
// # Rules of the witness (Witness.Cosign)
//
//  1. The head opens with one of the configured log keys (ErrSignature)
//     and has the configured origin (ErrOrigin).
//  2. head time <= own clock + translog.MaxClockSkew (ErrTime).
//  3. No state for the origin: trust on first use, cosign.
//  4. State has Fork set: refuse (ErrFork), permanently.
//  5. size < stored size: refuse (ErrConsistency); not permanent, the
//     server may serve an old candidate after a restart.
//  6. size == stored size: hash differs (whatever its time line; the
//     hash is compared first) -> store the head as fork evidence, set
//     Fork, refuse (ErrFork) permanently: two heads of one
//     size signed by the log key prove a split view. Same hash: time >=
//     stored time (ErrTime), cosign (refresh for freshness). Reading
//     (task 03b, finding S5): 2.7 forbids two heads of one size "with
//     different content"; the hash commits to the tree, so the same hash
//     with a time line not earlier (>=) is the same view, and
//     re-signing it is the only way to keep heads inside the 24 hours
//     of 2.3 while the log does not grow (translog doc.go "Heads").
//  7. size > stored size: size <= translog.MaxTreeSize, time >= stored
//     time (ErrTime) and translog.CheckTreeProof(proof, size, hash,
//     stored size, stored hash) (ErrConsistency; not permanent, because
//     an unsigned proof proves nothing against the log).
//  8. The new state is written durably (atomic replace, fsync) before
//     the cosignature leaves the witness, so a crash can never make the
//     witness forget a head it signed.
//
// # State (--state <dir>, rights 0700)
//
//	<dir>/lock                       record lock: one witness per state directory
//	<dir>/<hex SHA-256(origin)>.head the last cosigned head (signed note, as returned)
//	<dir>/<hex SHA-256(origin)>.fork evidence: the refused head of a fork
//
// The key file is outside the state directory. The state directory holds
// no private key.
//
// New creates a missing state directory with rights 0700 and refuses one
// that grants any right to group or others (whoever can delete a .fork
// file could make the witness forget a fork), a key file with rights
// other than owner-only and a key file inside the state directory. The
// stored head is read back only if it carries a valid cosignature by the
// witness's own key and the configured origin (ErrState otherwise); the
// log signature in it is not checked again, so that removing a rotated
// --log-key keeps the state usable. A .fork file sets Fork whatever it
// holds (fail closed).
//
// # Readings of task 08
//
//   - Proof: with no stored head and for a head of the stored size the
//     proof must be empty (ErrConsistency), as for the client
//     (translog.Verifier.CheckHead). Poll requests a proof only for a
//     head larger than the stored one.
//   - Order: the rules run in the order 4, 1, 2, 5, 6, 7 (a forked
//     witness refuses everything first). A head of the stored size with
//     another hash but a time beyond the clock skew is refused with
//     ErrTime and is not recorded as a fork.
//   - Exactly one log signature: a head that carries valid signatures by
//     two configured log keys is refused (ErrProtocol), because the
//     cosign body has exactly two lines (translog.MaxSignatures). The log
//     signature is forwarded only in its canonical base64 encoding
//     (ErrProtocol otherwise).
//   - Repetition: Ed25519 signatures are deterministic, so the
//     cosignature of an unchanged head is the same line. Poll does not
//     post it again when the candidate already carries that exact line,
//     and Cosign rewrites the state only when the stored note changes.
//   - POST answers: 200 and 409 end the round without error (409: the
//     next round fetches the new candidate); 400, 403 and every other
//     status are ErrProtocol. Network failures are ErrUnavailable.
//   - HTTP: every request, from sending it to reading the whole
//     response, ends after Config.Timeout (RequestTimeout by default;
//     ErrUnavailable). A body is read at most up to its limit plus one
//     byte (MaxHeadNote, MaxProofBody, MaxErrorBody), then the
//     connection is dropped. The protocol knows no redirects: New uses
//     a copy of a client given in Config.HTTP whose CheckRedirect
//     returns http.ErrUseLastResponse, so a 3xx is a status like any
//     other (ErrProtocol) and the caller's client is not changed.
//   - Fork evidence: when the .fork file cannot be written, Fork is
//     still set in memory and the error wraps ErrFork and ErrState;
//     Serve ends with it like with any fork, so the witness never runs
//     on without the evidence on disk (task 08b).
//   - Log lines of the witness carry sizes, the first four bytes of the
//     root hash in hex, status codes and the text of this package's
//     error variables only (never a body or an error from the network).
package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// HTTP paths of the protocol.
const (
	PathHead        = "/gomail/log/head"
	PathConsistency = "/gomail/log/consistency"
	PathCosign      = "/gomail/log/cosign"
	ContentType     = "text/plain; charset=utf-8"
)

// Limits.
const (
	// MaxWitnesses is the most witnesses in witnesses.rec and the pin;
	// a head carries at most one cosignature per witness besides the log
	// signature (translog.MaxSignatures).
	MaxWitnesses = translog.MaxWitnesses
	// MaxName is the longest witness name.
	MaxName = 64
	// MaxKeyFile is the read limit of a key file.
	MaxKeyFile = 512
	// DefaultInterval is the polling interval of serve.
	DefaultInterval = 10 * time.Second
	// RequestTimeout is the default of Config.Timeout.
	RequestTimeout = 30 * time.Second
	// MaxErrorBody is the most of a /cosign response body the witness
	// reads (and discards).
	MaxErrorBody = 1 << 10
)

// Errors. Every error of this package wraps one of them.
var (
	ErrSignature   = errors.New("witness: head is not signed by the log")
	ErrOrigin      = errors.New("witness: head of another origin")
	ErrTime        = errors.New("witness: head time out of range")
	ErrConsistency = errors.New("witness: head is not an extension of the last cosigned head")
	ErrFork        = errors.New("witness: log presented two heads of one size; cosigning stopped")
	ErrState       = errors.New("witness: unusable state directory")
	ErrKey         = errors.New("witness: unusable key")
	ErrProtocol    = errors.New("witness: protocol violation")
	ErrConfig      = errors.New("witness: invalid configuration")
	ErrUnavailable = errors.New("witness: log server not reachable")
)

// sentinels lists the error variables in the order reason checks them.
var sentinels = []error{ErrFork, ErrSignature, ErrOrigin, ErrTime, ErrConsistency, ErrState, ErrKey, ErrConfig, ErrUnavailable, ErrProtocol, ErrWitnesses}

// reason returns the text of the error variable err wraps, never the
// text of a wrapped foreign error (log lines, see the package comment).
func reason(err error) string {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "context ended"
	}
	return "witness: unexpected error"
}

// Config configures a witness (gomail-witness serve).
type Config struct {
	Log      string   // base URL of the log server (--log), http or https
	LogKeys  []string // note verifier keys of the log signer (--log-key)
	Origin   string   // pinned origin (--origin), translog.CheckOrigin
	KeyFile  string   // note signer key of the witness (--key), 0600
	StateDir string   // --state
	Interval time.Duration
	// Timeout bounds every HTTP request of the witness, from sending it
	// to reading the whole response; 0 means RequestTimeout.
	Timeout time.Duration
	Now     func() time.Time
	// HTTP is the client for the log server, nil for a default one. New
	// uses a copy whose CheckRedirect refuses to follow redirects
	// (http.ErrUseLastResponse); the client given is not changed.
	HTTP   *http.Client
	Logger *slog.Logger // IDs, sizes and status codes only
}

// State is what the witness keeps per origin.
type State struct {
	Origin string
	// Head is the last cosigned head, nil before the first.
	Head *translog.Head
	// Fork is set for good once two heads of one size differed.
	Fork bool
}

// Witness is a configured witness with its key loaded and its state
// directory locked. Its methods may be called concurrently.
type Witness struct {
	cfg    Config
	signer note.Signer
	known  note.Verifiers // the configured log keys
	own    note.Verifiers // the witness's own key
	base   *url.URL
	client *http.Client
	log    *slog.Logger
	now    func() time.Time
	// write stores a state file durably; tests replace it to simulate a
	// crash before the state is written (rule 8).
	write func(path string, data []byte) error

	mu      sync.Mutex
	release func() // nil once closed
	state   State
	stored  []byte // the note of state.Head as stored, nil before the first
}

// New loads the key, locks the state directory and reads the state.
func New(cfg Config) (*Witness, error) {
	w := &Witness{cfg: cfg, now: cfg.Now, log: cfg.Logger, write: store.WritePrivateFileAtomic}
	if w.now == nil {
		w.now = time.Now
	}
	if w.log == nil {
		w.log = slog.New(slog.DiscardHandler)
	}
	if err := translog.CheckOrigin(cfg.Origin); err != nil {
		return nil, fmt.Errorf("%w: %w: %v", ErrConfig, ErrOrigin, err)
	}
	if cfg.Interval < 0 {
		return nil, fmt.Errorf("%w: negative interval", ErrConfig)
	}
	if w.cfg.Interval == 0 {
		w.cfg.Interval = DefaultInterval
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("%w: negative timeout", ErrConfig)
	}
	if w.cfg.Timeout == 0 {
		w.cfg.Timeout = RequestTimeout
	}
	// The protocol knows no redirects; a 3xx is a protocol violation
	// like any other unexpected status. A given client is copied, so
	// the caller's client keeps its own CheckRedirect.
	c := http.Client{Timeout: w.cfg.Timeout}
	if cfg.HTTP != nil {
		c = *cfg.HTTP
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	w.client = &c
	base, err := parseBase(cfg.Log)
	if err != nil {
		return nil, err
	}
	w.base = base
	if w.known, err = logVerifiers(cfg.LogKeys); err != nil {
		return nil, err
	}
	if cfg.StateDir == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("%w: key file and state directory are required", ErrConfig)
	}
	if err := prepareStateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	if inside(cfg.KeyFile, cfg.StateDir) {
		return nil, fmt.Errorf("%w: the key file must not lie in the state directory", ErrKey)
	}
	signer, own, err := loadKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	w.signer, w.own = signer, note.VerifierList(own)
	release, err := store.LockFile(filepath.Join(cfg.StateDir, lockFile))
	if err != nil {
		return nil, fmt.Errorf("%w: lock: %w", ErrState, err)
	}
	w.release = release
	if err := w.load(); err != nil {
		release()
		return nil, err
	}
	return w, nil
}

// parseBase checks the base URL of the log server: http or https, a
// host, no user information, query or fragment.
func parseBase(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: --log must be an http or https URL without user, query or fragment", ErrConfig)
	}
	return u, nil
}

// logVerifiers parses the configured verifier keys of the log signer.
func logVerifiers(vkeys []string) (note.Verifiers, error) {
	if len(vkeys) == 0 {
		return nil, fmt.Errorf("%w: no log key", ErrKey)
	}
	var list []note.Verifier
	for _, k := range vkeys {
		v, err := note.NewVerifier(k)
		if err != nil {
			return nil, fmt.Errorf("%w: log key: %v", ErrKey, err)
		}
		if v.Name() != translog.LogSignerName {
			return nil, fmt.Errorf("%w: a log key must have the name %s", ErrKey, translog.LogSignerName)
		}
		for _, o := range list {
			if o.KeyHash() == v.KeyHash() {
				return nil, fmt.Errorf("%w: log key given twice", ErrKey)
			}
		}
		list = append(list, v)
	}
	return note.VerifierList(list...), nil
}

// inside reports whether path lies in dir, after resolving symbolic
// links where possible.
func inside(path, dir string) bool {
	rel, err := filepath.Rel(resolve(dir), resolve(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolve returns the absolute path of p with symbolic links resolved
// in p or, if p does not exist, in its directory.
func resolve(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		return r
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(a)); err == nil {
		return filepath.Join(r, filepath.Base(a))
	}
	return a
}

// State returns the state for the configured origin.
func (w *Witness) State() (*State, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.release == nil {
		return nil, fmt.Errorf("%w: witness closed", ErrState)
	}
	s := w.state
	if s.Head != nil {
		h := *s.Head
		h.Sigs = append([]note.Signature(nil), h.Sigs...)
		h.Note = append([]byte(nil), h.Note...)
		s.Head = &h
	}
	return &s, nil
}

// Close releases the state directory. Calling it twice is harmless.
func (w *Witness) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.release != nil {
		w.release()
		w.release = nil
	}
	return nil
}

// openHead applies rule 1 to a signed head from the server: at most
// translog.MaxHeadNote bytes, exactly one valid signature by a
// configured log key (ErrSignature without one, ErrProtocol with two or
// a non-canonical encoding of it), a strict head text (ErrProtocol) and
// the configured origin (ErrOrigin).
func (w *Witness) openHead(msg []byte) (*translog.Head, error) {
	if len(msg) > translog.MaxHeadNote {
		return nil, fmt.Errorf("%w: signed head too long", ErrProtocol)
	}
	h, err := translog.OpenHead(msg, w.known)
	if err != nil {
		var unverified *note.UnverifiedNoteError
		var invalid *note.InvalidSignatureError
		if _, nerr := note.Open(msg, w.known); errors.As(nerr, &unverified) || errors.As(nerr, &invalid) {
			return nil, fmt.Errorf("%w: %v", ErrSignature, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if len(h.Sigs) != 1 {
		return nil, fmt.Errorf("%w: head carries %d log signatures", ErrProtocol, len(h.Sigs))
	}
	raw, err := base64.StdEncoding.DecodeString(h.Sigs[0].Base64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != h.Sigs[0].Base64 {
		return nil, fmt.Errorf("%w: log signature not in canonical base64", ErrProtocol)
	}
	if h.Origin != w.cfg.Origin {
		return nil, ErrOrigin
	}
	return h, nil
}

// Cosign applies the rules of the package documentation to a signed
// head and a consistency proof from the stored head, stores the new
// state and returns the body of POST /gomail/log/cosign: the head text
// with exactly the log signature and the witness's own cosignature, no
// other line of the candidate (task 03c finding 8d). The stored state
// keeps the same two lines.
func (w *Witness) Cosign(head []byte, proof tlog.TreeProof) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.release == nil {
		return nil, fmt.Errorf("%w: witness closed", ErrState)
	}
	if w.state.Fork { // rule 4
		return nil, ErrFork
	}
	h, err := w.openHead(head) // rule 1
	if err != nil {
		return nil, err
	}
	if h.Time > w.now().UnixMilli()+translog.MaxClockSkew.Milliseconds() { // rule 2
		return nil, fmt.Errorf("%w: head lies in the future", ErrTime)
	}
	last := w.state.Head
	switch {
	case last == nil: // rule 3
		if len(proof) != 0 {
			return nil, fmt.Errorf("%w: proof without a stored head", ErrConsistency)
		}
	case h.Size < last.Size: // rule 5
		return nil, fmt.Errorf("%w: size %d below the stored size %d", ErrConsistency, h.Size, last.Size)
	case h.Size == last.Size: // rule 6
		if h.Hash != last.Hash {
			return nil, w.fork(head)
		}
		if h.Time < last.Time {
			return nil, fmt.Errorf("%w: head older than the stored head", ErrTime)
		}
		if len(proof) != 0 {
			return nil, fmt.Errorf("%w: proof for a head of the stored size", ErrConsistency)
		}
	default: // rule 7
		if h.Size > translog.MaxTreeSize {
			return nil, fmt.Errorf("%w: size above the limit", ErrProtocol)
		}
		if h.Time < last.Time {
			return nil, fmt.Errorf("%w: head older than the stored head", ErrTime)
		}
		if err := translog.CheckTreeProof(proof, h.Size, h.Hash, last.Size, last.Hash); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConsistency, err)
		}
	}
	text, err := h.Text()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	body, err := note.Sign(&note.Note{Text: string(text), Sigs: h.Sigs[:1]}, w.signer)
	if err != nil {
		return nil, fmt.Errorf("%w: sign: %v", ErrKey, err)
	}
	if !bytes.Equal(body, w.stored) { // rule 8: durable before it leaves
		if err := w.write(w.path(headExt), body); err != nil {
			return nil, fmt.Errorf("%w: write: %w", ErrState, err)
		}
	}
	h.Note = append([]byte(nil), body...)
	w.state.Head, w.stored = h, h.Note
	return append([]byte(nil), body...), nil
}

// fork records the evidence of a split view durably and stops the
// witness for good (rule 6). Fork is set even when the evidence cannot
// be written (fail closed); the error then wraps ErrState as well.
func (w *Witness) fork(head []byte) error {
	w.state.Fork = true
	if err := w.write(w.path(forkExt), head); err != nil {
		return fmt.Errorf("%w (evidence not stored: %w: %w)", ErrFork, ErrState, err)
	}
	return ErrFork
}

// State files.
const (
	lockFile = "lock"
	headExt  = ".head"
	forkExt  = ".fork"
)

// path returns the name of a state file of the configured origin.
func (w *Witness) path(ext string) string {
	sum := sha256.Sum256([]byte(w.cfg.Origin))
	return filepath.Join(w.cfg.StateDir, hex.EncodeToString(sum[:])+ext)
}

// prepareStateDir creates a missing state directory with rights 0700 and
// refuses one that grants rights to group or others.
func prepareStateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err == nil {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("%w: %w", ErrState, err)
		}
		if err := store.SyncDir(filepath.Dir(filepath.Clean(dir))); err != nil {
			return fmt.Errorf("%w: %w", ErrState, err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: not a directory", ErrState)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: rights %04o, the state directory must be 0700", ErrState, fi.Mode().Perm())
	}
	return nil
}

// load reads the state of the configured origin (under the lock).
func (w *Witness) load() error {
	if err := store.RemoveTemp(w.cfg.StateDir); err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	w.state = State{Origin: w.cfg.Origin}
	if _, err := os.Lstat(w.path(forkExt)); err == nil {
		w.state.Fork = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	data, err := store.ReadFileLimited(w.path(headExt), translog.MaxHeadNote)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	h, err := translog.OpenHead(data, w.own)
	if err != nil {
		return fmt.Errorf("%w: stored head: %v", ErrState, err)
	}
	if h.Origin != w.cfg.Origin {
		return fmt.Errorf("%w: stored head of another origin", ErrState)
	}
	w.state.Head, w.stored = h, h.Note
	return nil
}
