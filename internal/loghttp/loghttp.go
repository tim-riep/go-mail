// Package loghttp is the server side of the HTTP protocol between the log
// server and its witnesses (task 11). The protocol itself (paths, bodies,
// status codes) is laid down in package witness ("Protocol"); this
// package serves it from the operator log (translog.Operator) of
// gomail-server.
//
// Reading of task 11: the handlers live in this package and not in
// package witness, so that the witness program carries no server code
// and the server none of the witness's state handling; both share the
// constants, FormatProof and the witnesses.rec decoder of package
// witness.
//
// # Candidate and cadence (translog doc.go "Heads", Operator.SignHead)
//
// The server keeps one candidate head in memory: the newest head it
// signed, with every cosignature collected for its text so far. Tick
// calls Operator.SignHead at most once per MinGap (one minute by
// default, "höchstens einmal je Minute"); the result becomes the new
// candidate when the committed size has grown or when HeadInterval has
// passed since the candidate was signed (re-signature of the same size
// with a new time), and is discarded otherwise. Run calls Tick every
// MinGap, so a new entry is covered by a candidate within about two
// minutes and a head is re-signed at least every HeadInterval plus
// MinGap. When SignHead refuses (an inconsistent tree, a signer that
// does not cover the time), the candidate is dropped and the error
// logged: the server serves only heads it still stands behind (GET
// /gomail/log/head then answers with the newest published head). An
// *translog.InvalidEntriesError is an alert: the head is used and the
// indices are logged.
//
// Publication: whenever a cosignature was merged into the candidate,
// the candidate is passed to Operator.PublishHead, which writes
// heads/<size>.sig once the quorum of witnesses.rec is reached
// (translog.ErrWitness before that is no error). Tick retries a
// publication that failed.
//
// # HTTP (package witness, "Protocol")
//
//	GET  /gomail/log/head         the candidate, else the newest published head; 404 without either
//	GET  /gomail/log/consistency  from, to: decimal without sign or leading zeros, exactly these two
//	                              parameters once each, 1 <= from <= to <= translog.MaxTreeSize (400);
//	                              to above the size of the head GET /head serves: 404;
//	                              200 with witness.FormatProof(ConsistencyProof(from, to))
//	POST /gomail/log/cosign       body at most translog.MaxHeadNote bytes (413), text/plain;
//	                              charset=utf-8 (400); opened with the log key, witnesses.rec and the
//	                              logged ingest keys of the committed tree (Operator.LogKeys):
//	                              a known line that does not verify 403; malformed, no strict head
//	                              text, not exactly one log signature or no witness cosignature left
//	                              after dropping unknown lines 400; the text of the candidate with
//	                              a line of the configured log key: merged, 200; the text of the
//	                              newest published head: merged into it (PublishHead, which keeps
//	                              only the log line of the generation covering the head time), 200;
//	                              anything else 409
//	any other method              405 with Allow; any other path 404
//
// GET /head and /consistency read the newest published head with
// Operator.Head, which opens it line by line (task 11b finding 5): an
// invalid witness line written into heads/ by someone with write access
// to log/ is dropped from the served note instead of making the head
// unreadable (500). A file without a valid log line stays 500.
//
// After an ingest rotation (task 11b finding 7) the server signs with
// the new generation; a witness that fetched the newest published head,
// still signed by the generation before, posts that log line with its
// cosignature. The body opens with the logged keys of the committed tree
// and PublishHead requires the generation that covers the head time, as
// for every head.
//
// Recorded readings (task 11b, no change):
//   - /cosign accepts several valid witness cosignatures in one body and
//     merges all of them; the witness program sends exactly two lines
//     (log and its own), but the server does not require that: every
//     line is verified on its own and only verified lines are kept, so
//     the milder reading admits nothing unverified.
//   - The HTTP server has timeouts and size limits but no limit on the
//     number of connections and no rate limit (10.2: required before
//     production, not in the PoC).
//
// Responses are text/plain; charset=utf-8; error bodies are one line of
// ASCII without data from the request. Bodies of POST are read at most
// up to their limit; NewHTTPServer sets timeouts for headers, bodies,
// responses and idle connections and a header limit. Log lines carry the
// path, the status, sizes and the first four bytes of a root hash in hex
// only, never a body, a query or an address.
package loghttp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/translog"
	"github.com/tim-riep/go-mail/internal/witness"
)

// DefaultMinGap is the shortest time between two calls of SignHead
// (translog doc.go: "whenever the committed size has grown since the last
// candidate, at most once a minute").
const DefaultMinGap = time.Minute

// Timeouts and limits of NewHTTPServer.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 60 * time.Second
	MaxHeaderBytes    = 8 << 10
)

// ErrConfig reports an unusable configuration.
var ErrConfig = errors.New("loghttp: invalid configuration")

// Config configures the log side of the server.
type Config struct {
	// Log is the server's operator log (Options.Origin, Witnesses and
	// MinWitnesses set).
	Log translog.Operator
	// Signer is the log key (translog.NewLogSigner with the ingest key of
	// the generation that covers the time, Q4); LogKey is its verifier
	// (translog.NewLogVerifier of the same key).
	Signer note.Signer
	LogKey note.Verifier
	// Witnesses are the verifiers of witnesses.rec (the same as
	// Options.Witnesses of Log): only their cosignatures are merged.
	Witnesses []note.Verifier
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// HeadInterval is the longest time between two signed heads; 0 means
	// translog.HeadInterval, which is also the largest value allowed.
	HeadInterval time.Duration
	// MinGap is the shortest time between two calls of SignHead; 0 means
	// DefaultMinGap. It must not exceed HeadInterval.
	MinGap time.Duration
	// Logger receives paths, status codes, sizes and hash prefixes only.
	Logger *slog.Logger
}

// Server holds the candidate and serves the protocol. Its methods may be
// called concurrently.
type Server struct {
	cfg   Config
	log   *slog.Logger
	now   func() time.Time
	known note.Verifiers

	mu      sync.Mutex
	cand    *candidate
	lastTry time.Time // last call of SignHead, zero before the first
}

// candidate is the newest signed head with the cosignatures merged.
type candidate struct {
	head     translog.Head // without Sigs and Note
	text     string
	logSig   note.Signature
	cos      []note.Signature
	note     []byte
	signedAt time.Time
	// published is the number of cosignatures at the last successful
	// PublishHead, -1 before.
	published int
}

// New checks the configuration and returns a server without candidate.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil || cfg.Signer == nil || cfg.LogKey == nil {
		return nil, fmt.Errorf("%w: log, signer and log key are required", ErrConfig)
	}
	if cfg.Signer.Name() != translog.LogSignerName || cfg.LogKey.Name() != translog.LogSignerName || cfg.LogKey.KeyHash() != cfg.Signer.KeyHash() {
		return nil, fmt.Errorf("%w: signer and log key do not belong together", ErrConfig)
	}
	if len(cfg.Witnesses) == 0 || len(cfg.Witnesses) > witness.MaxWitnesses {
		return nil, fmt.Errorf("%w: %d witnesses", ErrConfig, len(cfg.Witnesses))
	}
	for _, w := range cfg.Witnesses {
		if w == nil || w.Name() == translog.LogSignerName {
			return nil, fmt.Errorf("%w: invalid witness", ErrConfig)
		}
	}
	if cfg.HeadInterval == 0 {
		cfg.HeadInterval = translog.HeadInterval
	}
	if cfg.MinGap == 0 {
		cfg.MinGap = DefaultMinGap
	}
	if cfg.HeadInterval < 0 || cfg.HeadInterval > translog.HeadInterval || cfg.MinGap < 0 || cfg.MinGap > cfg.HeadInterval {
		return nil, fmt.Errorf("%w: head interval at most %v, at least the minimum gap", ErrConfig, translog.HeadInterval)
	}
	s := &Server{cfg: cfg, log: cfg.Logger, now: cfg.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.known = note.VerifierList(append([]note.Verifier{cfg.LogKey}, cfg.Witnesses...)...)
	return s, nil
}

// hashPrefix is the first four bytes of a root hash in hex, for logs.
func hashPrefix(h tlog.Hash) string { return hex.EncodeToString(h[:4]) }

// Tick runs one step of the cadence (package comment): SignHead when
// MinGap has passed since the last call, a new candidate when the size
// grew or HeadInterval passed, and a publication of the candidate when
// cosignatures were merged since the last one.
func (s *Server) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.lastTry.IsZero() || now.Sub(s.lastTry) >= s.cfg.MinGap || now.Before(s.lastTry) {
		s.lastTry = now
		s.sign(now)
	}
	s.publish()
}

// sign calls SignHead and adopts the head when it is due.
func (s *Server) sign(now time.Time) {
	h, err := s.cfg.Log.SignHead(s.cfg.Signer, now)
	var inv *translog.InvalidEntriesError
	if h != nil && errors.As(err, &inv) {
		idx := make([]string, 0, len(inv.Entries))
		for i, x := range inv.Entries {
			if i == 16 {
				idx = append(idx, "...")
				break
			}
			idx = append(idx, strconv.FormatInt(x.Index, 10)+":"+x.Class)
		}
		s.log.Error("invalid entries in the log (written past Append); the head covers them, every audit skips them",
			"count", len(inv.Entries), "entries", strings.Join(idx, ","))
		err = nil
	}
	if err != nil || h == nil {
		if s.cand != nil {
			s.log.Error("signing refused; candidate dropped", "reason", reason(err), "size", s.cand.head.Size)
		} else {
			s.log.Error("signing refused", "reason", reason(err))
		}
		s.cand = nil
		return
	}
	c := s.cand
	if c != nil && h.Size == c.head.Size && now.Sub(c.signedAt) < s.cfg.HeadInterval && !now.Before(c.signedAt) {
		return // neither grown nor due
	}
	if len(h.Sigs) != 1 {
		s.log.Error("signed head without exactly one log signature")
		s.cand = nil
		return
	}
	text, err := h.Text()
	if err != nil {
		s.cand = nil
		return
	}
	s.cand = &candidate{head: translog.Head{Origin: h.Origin, Size: h.Size, Hash: h.Hash, Time: h.Time},
		text: string(text), logSig: h.Sigs[0], note: append([]byte(nil), h.Note...), signedAt: now, published: -1}
	s.log.Info("head signed", "size", h.Size, "hash", hashPrefix(h.Hash))
}

// publish passes the candidate to PublishHead when cosignatures were
// merged since the last publication. Called with s.mu held.
func (s *Server) publish() {
	c := s.cand
	if c == nil || len(c.cos) == 0 || len(c.cos) == c.published {
		return
	}
	h := c.head
	h.Note = c.note
	err := s.cfg.Log.PublishHead(&h)
	switch {
	case err == nil:
		c.published = len(c.cos)
		s.log.Info("head published", "size", h.Size, "hash", hashPrefix(h.Hash), "cosignatures", len(c.cos))
	case errors.Is(err, translog.ErrWitness):
		s.log.Info("waiting for cosignatures", "size", h.Size, "cosignatures", len(c.cos))
	default:
		s.log.Error("publication refused", "size", h.Size, "reason", reason(err))
	}
}

// merge adds cosignatures to c (one line per key) and rebuilds its note.
func (c *candidate) merge(cos []note.Signature) error {
	added := false
	for _, n := range cos {
		dup := false
		for _, o := range c.cos {
			dup = dup || (o.Name == n.Name && o.Hash == n.Hash)
		}
		if !dup {
			c.cos = append(c.cos, n)
			added = true
		}
	}
	if !added {
		return nil
	}
	msg, err := note.Sign(&note.Note{Text: c.text, Sigs: append([]note.Signature{c.logSig}, c.cos...)})
	if err != nil {
		return err
	}
	c.note = msg
	return nil
}

// Candidate returns a copy of the candidate as a signed head, nil
// without one.
func (s *Server) Candidate() *translog.Head {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cand == nil {
		return nil
	}
	h := s.cand.head
	h.Note = append([]byte(nil), s.cand.note...)
	h.Sigs = append([]note.Signature{s.cand.logSig}, s.cand.cos...)
	return &h
}

// Run calls Tick at once and then every MinGap until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.MinGap)
	defer t.Stop()
	for {
		s.Tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// NewHTTPServer returns an http.Server for the handler with the timeouts
// and limits of this package. The standard library's own error log is
// discarded: it would carry remote addresses and request details.
func NewHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

// reason returns the text of the error variable of translog err wraps,
// never a wrapped foreign text.
func reason(err error) string {
	for _, e := range []error{translog.ErrConsistency, translog.ErrHead, translog.ErrWitness, translog.ErrNotInLog,
		translog.ErrStale, translog.ErrPin, translog.ErrEntry, translog.ErrIO} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "unexpected error"
}

// reply writes a text/plain response.
func reply(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", witness.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(body)
}

// ServeHTTP serves the protocol (package comment).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var code int
	var attrs []any
	switch r.URL.Path {
	case witness.PathHead:
		code, attrs = s.method(w, r, http.MethodGet, s.serveHead)
	case witness.PathConsistency:
		code, attrs = s.method(w, r, http.MethodGet, s.serveConsistency)
	case witness.PathCosign:
		code, attrs = s.method(w, r, http.MethodPost, s.serveCosign)
	default:
		code = http.StatusNotFound
		reply(w, code, []byte("not found\n"))
		s.log.Info("request", "path", "other", "status", code)
		return
	}
	s.log.Info("request", append([]any{"path", r.URL.Path, "status", code}, attrs...)...)
}

func (s *Server) method(w http.ResponseWriter, r *http.Request, m string, fn func(http.ResponseWriter, *http.Request) (int, []any)) (int, []any) {
	if r.Method != m {
		w.Header().Set("Allow", m)
		reply(w, http.StatusMethodNotAllowed, []byte("method not allowed\n"))
		return http.StatusMethodNotAllowed, nil
	}
	return fn(w, r)
}

// current returns the head GET /head serves: the candidate's note, else
// the newest published head. ok is false without either; err reports a
// published head that cannot be read.
func (s *Server) current() (size int64, msg []byte, ok bool, err error) {
	s.mu.Lock()
	if c := s.cand; c != nil {
		size, msg = c.head.Size, append([]byte(nil), c.note...)
		s.mu.Unlock()
		return size, msg, true, nil
	}
	s.mu.Unlock()
	h, err := s.cfg.Log.Head()
	if errors.Is(err, translog.ErrStale) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	return h.Size, h.Note, true, nil
}

func (s *Server) serveHead(w http.ResponseWriter, _ *http.Request) (int, []any) {
	size, msg, ok, err := s.current()
	switch {
	case err != nil:
		reply(w, http.StatusInternalServerError, []byte("internal error\n"))
		return http.StatusInternalServerError, []any{"reason", reason(err)}
	case !ok:
		reply(w, http.StatusNotFound, []byte("no head yet\n"))
		return http.StatusNotFound, nil
	}
	reply(w, http.StatusOK, msg)
	return http.StatusOK, []any{"size", size}
}

// decimal parses a size of the protocol: no sign, no leading zeros.
func decimal(v string) (int64, bool) {
	if v == "" || len(v) > 19 || (len(v) > 1 && v[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

func (s *Server) serveConsistency(w http.ResponseWriter, r *http.Request) (int, []any) {
	q := r.URL.Query()
	fs, ts := q["from"], q["to"]
	var from, to int64
	ok := len(q) == 2 && len(fs) == 1 && len(ts) == 1
	if ok {
		var ok1, ok2 bool
		from, ok1 = decimal(fs[0])
		to, ok2 = decimal(ts[0])
		ok = ok1 && ok2 && from >= 1 && from <= to && to <= translog.MaxTreeSize
	}
	if !ok {
		reply(w, http.StatusBadRequest, []byte("malformed request\n"))
		return http.StatusBadRequest, nil
	}
	size, _, have, err := s.current()
	if err != nil {
		reply(w, http.StatusInternalServerError, []byte("internal error\n"))
		return http.StatusInternalServerError, []any{"reason", reason(err)}
	}
	if !have || to > size {
		reply(w, http.StatusNotFound, []byte("beyond the head\n"))
		return http.StatusNotFound, []any{"from", from, "to", to}
	}
	p, err := s.cfg.Log.ConsistencyProof(from, to)
	if err != nil {
		reply(w, http.StatusInternalServerError, []byte("internal error\n"))
		return http.StatusInternalServerError, []any{"from", from, "to", to, "reason", reason(err)}
	}
	reply(w, http.StatusOK, witness.FormatProof(p))
	return http.StatusOK, []any{"from", from, "to", to}
}

// textPlain reports whether a Content-Type header is text/plain with
// charset utf-8 (witness.ContentType, case-insensitive).
func textPlain(v string) bool {
	mt, params, err := mime.ParseMediaType(v)
	return err == nil && mt == "text/plain" && len(params) == 1 && strings.EqualFold(params["charset"], "utf-8")
}

func (s *Server) serveCosign(w http.ResponseWriter, r *http.Request) (int, []any) {
	if r.ContentLength > translog.MaxHeadNote {
		reply(w, http.StatusRequestEntityTooLarge, []byte("request too large\n"))
		return http.StatusRequestEntityTooLarge, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, translog.MaxHeadNote))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			reply(w, http.StatusRequestEntityTooLarge, []byte("request too large\n"))
			return http.StatusRequestEntityTooLarge, nil
		}
		reply(w, http.StatusBadRequest, []byte("malformed request\n"))
		return http.StatusBadRequest, nil
	}
	if !textPlain(r.Header.Get("Content-Type")) {
		reply(w, http.StatusBadRequest, []byte("content type\n"))
		return http.StatusBadRequest, nil
	}
	code, msg, attrs := s.cosign(body)
	reply(w, code, []byte(msg))
	return code, attrs
}

// cosignKnown returns the verifiers a POST /cosign body is opened with:
// the log key, the witnesses and the log key of every valid ingest
// certificate of the committed tree (Operator.LogKeys, task 11b finding
// 7), so that a body for the published head signed by the generation
// before an ingest rotation opens. A log key with the key hash of one
// already listed is left out (note.VerifierList refuses ambiguous
// keys); when LogKeys fails, the configured keys alone are used.
func (s *Server) cosignKnown() note.Verifiers {
	ks, err := s.cfg.Log.LogKeys()
	if err != nil || len(ks) == 0 {
		return s.known
	}
	vs := append([]note.Verifier{s.cfg.LogKey}, s.cfg.Witnesses...)
	for _, k := range ks {
		dup := k.Verifier == nil
		for _, v := range vs {
			dup = dup || (v.Name() == k.Verifier.Name() && v.KeyHash() == k.Verifier.KeyHash())
		}
		if !dup {
			vs = append(vs, k.Verifier)
		}
	}
	return note.VerifierList(vs...)
}

// cosign merges the cosignatures of a POST body (package comment) and
// returns the status, the response body and log attributes.
func (s *Server) cosign(body []byte) (int, string, []any) {
	n, err := note.Open(body, s.cosignKnown())
	if err != nil {
		var invalid *note.InvalidSignatureError
		if errors.As(err, &invalid) {
			return http.StatusForbidden, "invalid signature\n", nil
		}
		return http.StatusBadRequest, "malformed head\n", nil
	}
	h, err := translog.ParseHeadText([]byte(n.Text))
	if err != nil {
		return http.StatusBadRequest, "malformed head\n", nil
	}
	attrs := []any{"size", h.Size, "hash", hashPrefix(h.Hash)}
	var logSigs, cos []note.Signature
	for _, sg := range n.Sigs {
		raw, err := base64.StdEncoding.DecodeString(sg.Base64)
		if err != nil {
			return http.StatusBadRequest, "malformed head\n", attrs
		}
		sg.Base64 = base64.StdEncoding.EncodeToString(raw)
		if sg.Name == translog.LogSignerName {
			logSigs = append(logSigs, sg)
		} else {
			cos = append(cos, sg)
		}
	}
	if len(logSigs) != 1 || len(cos) == 0 {
		return http.StatusBadRequest, "nothing to merge\n", attrs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The candidate carries the signature of the configured log key; a
	// body for it with another generation's line is not merged.
	if c := s.cand; c != nil && c.text == n.Text && logSigs[0].Hash == s.cfg.LogKey.KeyHash() {
		if err := c.merge(cos); err != nil {
			return http.StatusInternalServerError, "internal error\n", attrs
		}
		s.publish()
		return http.StatusOK, "stored\n", append(attrs, "cosignatures", len(c.cos))
	}
	// The newest published head (a witness that fetched it while the
	// server had no candidate): PublishHead merges and keeps the lines
	// of the stored head; it keeps only a log line of the generation
	// that covers the head time, which after an ingest rotation is not
	// the configured key.
	pub, err := s.cfg.Log.Head()
	if err == nil {
		if text, terr := pub.Text(); terr == nil && string(text) == n.Text {
			ph := *h
			ph.Note = body
			if err := s.cfg.Log.PublishHead(&ph); err != nil {
				return http.StatusInternalServerError, "internal error\n", append(attrs, "reason", reason(err))
			}
			return http.StatusOK, "stored\n", attrs
		}
	}
	return http.StatusConflict, "not the candidate\n", attrs
}
