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
//  6. size == stored size: hash differs -> store the head as fork
//     evidence, set Fork, refuse (ErrFork) permanently: two heads of one
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
package witness

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

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
)

// Errors. Every error of this package wraps one of them.
var (
	ErrSignature      = errors.New("witness: head is not signed by the log")
	ErrOrigin         = errors.New("witness: head of another origin")
	ErrTime           = errors.New("witness: head time out of range")
	ErrConsistency    = errors.New("witness: head is not an extension of the last cosigned head")
	ErrFork           = errors.New("witness: log presented two heads of one size; cosigning stopped")
	ErrState          = errors.New("witness: unusable state directory")
	ErrKey            = errors.New("witness: unusable key")
	ErrProtocol       = errors.New("witness: protocol violation")
	ErrNotImplemented = errors.New("witness: not implemented yet")
)

// Config configures a witness (gomail-witness serve).
type Config struct {
	Log      string   // base URL of the log server (--log)
	LogKeys  []string // note verifier keys of the log signer (--log-key)
	Origin   string   // pinned origin (--origin), translog.CheckOrigin
	KeyFile  string   // note signer key of the witness (--key), 0600
	StateDir string   // --state
	Interval time.Duration
	Now      func() time.Time
	HTTP     *http.Client
	Logger   *slog.Logger // IDs, sizes and status codes only
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
// directory locked.
type Witness struct {
	cfg    Config
	signer note.Signer
	known  note.Verifiers
}

// New loads the key, locks the state directory and reads the state.
func New(cfg Config) (*Witness, error) { return nil, ErrNotImplemented }

// State returns the state for the configured origin.
func (w *Witness) State() (*State, error) { return nil, ErrNotImplemented }

// Cosign applies the rules of the package documentation to a signed
// head and a consistency proof from the stored head, stores the new
// state and returns the body of POST /gomail/log/cosign: the head text
// with exactly the log signature and the witness's own cosignature, no
// other line of the candidate (task 03c finding 8d). The stored state
// keeps the same two lines.
func (w *Witness) Cosign(head []byte, proof tlog.TreeProof) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Poll runs one round: fetch the head, fetch the proof, Cosign, post.
func (w *Witness) Poll(ctx context.Context) error { return ErrNotImplemented }

// Close releases the state directory.
func (w *Witness) Close() error { return ErrNotImplemented }

// Serve runs Poll every cfg.Interval until ctx ends (gomail-witness
// serve). A fork stops it with ErrFork.
func Serve(ctx context.Context, cfg Config) error { return ErrNotImplemented }

// Keygen creates a witness key named name (CheckName) with randomness
// from r (crypto/rand if nil), writes the signer key to keyFile (0600,
// exclusive) and returns the verifier key line.
func Keygen(name, keyFile string, r io.Reader) (vkey string, err error) {
	return "", ErrNotImplemented
}
