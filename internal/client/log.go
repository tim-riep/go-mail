package client

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// The client log (task 14, translog doc.go "Reference head", "Withheld
// entries", "Audit", "Who writes"): every client opens the transparency
// log of the data directory as a client log, with a Verifier built from
// its pin and the reference head and own pending entries from state.json
// (D57), and an audit index in the client directory. There is no way to
// run without it (Config has no log of its own any more, and
// translogtest.Unverified is used by tests only).

// ErrLog reports that the transparency log does not confirm the state
// the client would rely on: no verified tree head with witness
// signatures at most 24 hours old (translog.ErrStale), an own entry the
// server withholds (translog.ErrWithheld), a log that contradicts the
// last verified head or an own entry (translog.ErrConsistency), or
// another client's checkpoint that shows a split view. The client then
// processes nothing new (2.3, 2.7). The error wraps the translog error.
var ErrLog = errors.New("client: the transparency log does not confirm the state; nothing new is processed (2.3, 2.7)")

// ErrAddress rejects a mail whose recipient address the log does not
// assign to the mailbox at the receipt time (2.3, "stilles Umleiten").
// It never names the address.
var ErrAddress = errors.New("client: address not assigned to this mailbox at receipt according to the log")

// ErrSuperseded rejects a user.rec of the data directory that a newer
// logged user.rec of the same user supersedes (a rolled back user.rec
// would hide a revocation, 2.3): it is not used.
var ErrSuperseded = errors.New("client: user.rec is outdated according to the log")

// logIndexFile is the audit index of the client log in the client
// directory (translog Options.IndexFile, doc.go "Audit").
const logIndexFile = "log-index.json"

// logMemory is what state.json keeps of the client log (D57, translog
// doc.go "Withheld entries"): the reference head and the own appends no
// verified head covers yet.
type logMemory struct {
	// Head is the signed note of the reference head (Verifier.Last), as
	// it was accepted with its witness cosignatures.
	Head string `json:"head,omitempty"`
	// Pending are the entries this client appended that the reference
	// head does not cover (Verifier.Pending), each with the record, so
	// that it can be appended again when a rollback of the log dropped
	// it (doc.go "Withheld entries", task 11 addendum).
	Pending []pendingMemo `json:"pending,omitempty"`
}

// pendingMemo is a Verifier.Pending entry with the record it stands for.
// The records are public: user.rec and epoch.rec as in the data
// directory.
type pendingMemo struct {
	Index  int64  `json:"index"`
	Leaf   string `json:"leaf"`
	At     int64  `json:"at"`
	Kind   uint8  `json:"kind"`
	Record []byte `json:"record"`
}

// logConn is the client log of one client (or of Register, Restore and
// DeviceLost before a Client exists).
type logConn struct {
	cfg *Config
	st  *state
	// mem keeps everything in memory (RecoverRead, first contact).
	mem bool
	log translog.Log
	v   *translog.Verifier
	// tmp is a directory of its own for the audit index of a client
	// without a client directory (RecoverRead), removed by close.
	tmp string
	// mu serializes refresh, append and the reads of the Verifier.
	mu sync.Mutex
	// records maps a pending index to its record (pendingMemo).
	records map[int64]pendingMemo
	// headSeen is the reference head as of the last refresh of this
	// process (not taken from state.json, task 14b point 4: whether a
	// checkpoint is due is decided by state.Checkpointed).
	headSeen string
	// index is the path of the audit index (translog Options.IndexFile).
	index string
}

// logHook wraps the client log of every client opened afterwards; nil
// in production. Tests of this package set it (export_test.go) to make
// a check of the real log fail.
var logHook func(translog.Log) translog.Log

// verifier builds the client Verifier from the pin (translog doc.go
// "Pin"): origin, witnesses and quorum, the current identity and the
// identity list. The clock is cfg.Now.
func (cfg *Config) verifier() (*translog.Verifier, error) {
	pin := cfg.Pin
	ws := make([]note.Verifier, 0, len(pin.Witnesses))
	for _, w := range pin.Witnesses {
		v, err := translog.NewWitnessVerifier(w.Name, w.Pub)
		if err != nil {
			return nil, err
		}
		ws = append(ws, v)
	}
	ids := make([]translog.Identity, 0, len(pin.Identities))
	for _, id := range pin.Identities {
		ids = append(ids, translog.Identity{Gen: id.Gen, Pub: id.Pub})
	}
	return &translog.Verifier{Origin: pin.Origin, Witnesses: ws, MinWitnesses: pin.MinWitnesses,
		Identity: translog.Identity{Gen: pin.Gen, Pub: pin.Pub}, Identities: ids, Now: cfg.Now}, nil
}

// headFromNote returns the head of a signed note kept in state.json. The
// note was verified when it was accepted (Verifier.CheckHead); state.json
// lies in the trust zone of the client directory (D57, translog doc.go
// "Audit"), so only its text is parsed here, strictly
// (translog.ParseHeadText). The Verifier checks its size again.
func headFromNote(msg []byte) (*translog.Head, error) {
	i := bytes.Index(msg, []byte("\n\n"))
	if i < 0 || len(msg) > translog.MaxHeadNote {
		return nil, fmt.Errorf("%w: damaged reference head in the state file", ErrLog)
	}
	h, err := translog.ParseHeadText(msg[:i+1])
	if err != nil {
		return nil, fmt.Errorf("%w: damaged reference head in the state file: %w", ErrLog, err)
	}
	h.Note = append([]byte(nil), msg...)
	return h, nil
}

// openLog opens the client log of cfg with the reference head and the
// pending entries of st. dir is the directory of the audit index (the
// client directory); empty means a directory of its own in the system's
// temporary directory, removed by close (RecoverRead). With mem nothing
// is ever written to state.json.
func openLog(cfg *Config, st *state, mem bool) (*logConn, error) {
	v, err := cfg.verifier()
	if err != nil {
		return nil, err
	}
	lc := &logConn{cfg: cfg, st: st, mem: mem, v: v, records: map[int64]pendingMemo{}}
	if st.Log != nil {
		if st.Log.Head != "" {
			if v.Last, err = headFromNote([]byte(st.Log.Head)); err != nil {
				return nil, err
			}
		}
		for _, p := range st.Log.Pending {
			var leaf tlog.Hash
			b, err := hex.DecodeString(p.Leaf)
			if err != nil || len(b) != len(leaf) {
				return nil, fmt.Errorf("%w: damaged pending entry in the state file", ErrLog)
			}
			copy(leaf[:], b)
			v.Pending = append(v.Pending, translog.Pending{Index: p.Index, Leaf: leaf, At: p.At})
			lc.records[p.Index] = p
		}
	}
	dir := cfg.Dir
	if dir == "" {
		if lc.tmp, err = os.MkdirTemp("", "gomailctl-log-"); err != nil {
			return nil, err
		}
		dir = lc.tmp
	}
	lc.index = filepath.Join(dir, logIndexFile)
	if err := lc.open(); err != nil {
		lc.close()
		return nil, err
	}
	return lc, nil
}

// open opens the client log with the Verifier and the audit index of lc.
func (lc *logConn) open() error {
	l, err := translog.Open(translog.Options{Store: lc.cfg.Store, Verifier: lc.v, IndexFile: lc.index, Now: lc.cfg.Now})
	if err != nil {
		return err
	}
	if logHook != nil {
		l = logHook(l)
	}
	lc.log = l
	return nil
}

// rebuildIndex discards the audit index and opens the client log again,
// which builds it from entry 0 against the reference head (task 14b
// point 7: an index that answers "not in the log" for an entry the log
// holds).
func (lc *logConn) rebuildIndex() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if err := os.Remove(lc.index); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return lc.open()
}

// close removes the temporary directory of the audit index, if any.
func (lc *logConn) close() {
	if lc != nil && lc.tmp != "" {
		os.RemoveAll(lc.tmp)
		lc.tmp = ""
	}
}

// persist writes the reference head and the pending entries into
// state.json (translog doc.go "Withheld entries": before the client
// relies on an append, and after every Refresh that took over a head).
// The caller holds lc.mu.
func (lc *logConn) persist() error {
	m := &logMemory{}
	if lc.v.Last != nil {
		m.Head = string(lc.v.Last.Note)
	}
	for _, p := range lc.v.Pending {
		pm := lc.records[p.Index]
		pm.Index, pm.Leaf, pm.At = p.Index, hex.EncodeToString(p.Leaf[:]), p.At
		m.Pending = append(m.Pending, pm)
	}
	for i := range lc.records {
		found := false
		for _, p := range lc.v.Pending {
			found = found || p.Index == i
		}
		if !found {
			delete(lc.records, i)
		}
	}
	lc.st.Log = m
	if lc.mem {
		return nil
	}
	return saveState(lc.cfg.statePath(), lc.st)
}

// appendRecord appends a record to the log (Log.Append) and persists the
// pending entry with its record before the caller relies on it.
func (lc *logConn) appendRecord(kind translog.Kind, content []byte) (int64, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	idx, err := lc.log.Append(kind, content)
	if err != nil {
		return idx, err
	}
	for _, p := range lc.v.Pending {
		if p.Index == idx {
			lc.records[idx] = pendingMemo{Kind: uint8(kind), Record: append([]byte(nil), content...)}
		}
	}
	return idx, lc.persist()
}

// refresh runs Refresh and then always CheckFresh (translog doc.go
// "Tasks" 11 (c)). It persists the reference head when Refresh took one
// over (success, and ErrWithheld or ErrStale, which come with the new
// head) and reports whether the reference head changed. An own entry
// found replaced after a rollback of the log (ErrConsistency) is removed
// from the pending entries and appended again (repairPending). Every
// failure that stops processing is ErrLog with a warning; a new head
// that CheckHead refused (ErrHead, ErrWitness) only warns, and the old
// reference head counts while it is fresh.
func (lc *logConn) refresh() (bool, error) {
	if lc.cfg.BeforeRefresh != nil {
		lc.cfg.BeforeRefresh()
	}
	lc.mu.Lock()
	defer lc.mu.Unlock()
	before := lc.headSeen
	now := lc.cfg.Now()
	_, rerr := lc.log.Refresh(now)
	if rerr != nil && errors.Is(rerr, translog.ErrConsistency) {
		if err := lc.repairPending(); err != nil {
			return false, err
		}
		_, rerr = lc.log.Refresh(now)
	}
	if errors.Is(rerr, translog.ErrOlderHead) {
		// Task 14b point 2: the newest published head is an older view
		// of the same log; the reference head stays and counts while it
		// is fresh (CheckFresh below).
		lc.cfg.Warn("WARNUNG: Im Transparenzlog ist nur ein älterer Baumkopf veröffentlicht als der zuletzt geprüfte (älterer Kopf veröffentlicht); der geprüfte bleibt maßgeblich, solange er höchstens 24 Stunden alt ist.")
		rerr = nil
	}
	if rerr == nil || errors.Is(rerr, translog.ErrStale) {
		if err := lc.persist(); err != nil {
			return false, err
		}
	}
	if rerr != nil && !errors.Is(rerr, translog.ErrStale) {
		switch {
		case errors.Is(rerr, translog.ErrConsistency), errors.Is(rerr, translog.ErrIO), errors.Is(rerr, translog.ErrPin):
			lc.cfg.Warn("WARNUNG: Das Transparenzlog widerspricht dem zuletzt geprüften Baumkopf oder einem eigenen Eintrag; der Client verarbeitet nichts mehr.")
			return false, fmt.Errorf("%w: %w", ErrLog, rerr)
		default:
			lc.cfg.Warn("WARNUNG: Der neueste Baumkopf des Transparenzlogs ist ungültig (Signatur, Zeugen oder Zeit) und wird nicht übernommen.")
		}
	}
	if err := lc.fresh(); err != nil {
		return false, err
	}
	changed := lc.v.Last != nil && string(lc.v.Last.Note) != before
	if lc.v.Last != nil {
		lc.headSeen = string(lc.v.Last.Note)
	}
	return changed, nil
}

// fresh is CheckFresh with a clear warning. The caller holds lc.mu.
func (lc *logConn) fresh() error {
	err := lc.log.CheckFresh(lc.cfg.Now())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, translog.ErrWithheld):
		lc.cfg.Warn("WARNUNG: Der Server hält einen eigenen Eintrag im Transparenzlog zurück: ein neuerer Baumkopf enthält ihn nicht (2.7). Der Client verarbeitet keine neuen Signaturen.")
	case errors.Is(err, translog.ErrStale):
		lc.cfg.Warn("WARNUNG: Kein Baumkopf des Transparenzlogs mit Zeugensignatur, der höchstens 24 Stunden alt ist (2.3). Der Client verarbeitet keine neuen Signaturen.")
	default:
		lc.cfg.Warn("WARNUNG: Das Transparenzlog bestätigt den Zustand nicht (eigener Eintrag ersetzt oder Log widersprüchlich); der Client verarbeitet nichts mehr.")
	}
	return fmt.Errorf("%w: %w", ErrLog, err)
}

// repairPending handles an own entry that a rollback of the log by one
// dropped (translog doc.go "Withheld entries", task 11 addendum (b)):
// the record of every pending entry whose index in log/entries holds
// another entry, or none, is appended again (a new index and a new
// pending entry); the caller refreshes again. The files of log/ only
// select the candidates; Refresh decides against a verified head.
//
// Atomic (task 14b point 5): an entry and its record leave
// Verifier.Pending and state.json only after its record was appended
// again, together with the new entry (one write of state.json). When the
// append fails, the old entry stays, state.json is not touched for it,
// and the next refresh (the next start) finds it again and tries once
// more; nothing is ever lost. ErrDuplicate on that append means that
// another entry took the key: it is reported, and the entry stays (the
// client stays stopped, fail closed).
func (lc *logConn) repairPending() error {
	var again []translog.Pending
	for _, p := range lc.v.Pending {
		data, err := store.ReadFileLimited(filepath.Join(lc.cfg.Store.Root, filepath.FromSlash(translog.EntryPath(p.Index))), translog.MaxEntryFile)
		pm, ok := lc.records[p.Index]
		if (err == nil && translog.LeafHash(data) == p.Leaf) || !ok || len(pm.Record) == 0 {
			continue
		}
		again = append(again, p)
	}
	if len(again) == 0 {
		return nil
	}
	lc.cfg.Warn("WARNUNG: Ein eigener Eintrag fehlt im Transparenzlog (Rückschritt des Logs); er wird erneut eingetragen.")
	for _, old := range again {
		pm := lc.records[old.Index]
		before := append([]translog.Pending(nil), lc.v.Pending...)
		idx, err := lc.log.Append(translog.Kind(pm.Kind), pm.Record)
		if err == nil && idx == old.Index {
			err = fmt.Errorf("%w: appended again at the same index %d", translog.ErrConsistency, idx)
		}
		if err != nil {
			// The old state: Append adds a pending entry only on success,
			// but the list is restored in any case.
			lc.v.Pending = before
			if errors.Is(err, translog.ErrDuplicate) {
				lc.cfg.Warn("WARNUNG: Ein eigener Eintrag des Transparenzlogs wurde durch einen fremden mit demselben Schlüssel ersetzt.")
			}
			return fmt.Errorf("%w: own entry appended again: %w", ErrLog, err)
		}
		var keep []translog.Pending
		for _, p := range lc.v.Pending {
			if p.Index != old.Index || p.Leaf != old.Leaf {
				keep = append(keep, p)
			}
		}
		lc.v.Pending = keep
		lc.records[idx] = pendingMemo{Kind: pm.Kind, Record: pm.Record}
		if err := lc.persist(); err != nil {
			return err
		}
	}
	return nil
}

// head returns the reference head, nil before the first.
func (lc *logConn) head() *translog.Head {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.v.Last == nil {
		return nil
	}
	h := *lc.v.Last
	return &h
}
