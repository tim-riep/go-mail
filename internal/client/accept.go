package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// Signatures of a revoked generation on files outside the log (2.2 rule
// 4, SPEC-ISSUES S13, task 06b B).
//
// Such a file is never valid by itself after the revocation, because its
// time cannot be proven. Two local proofs that this client checked it
// while the signer's generation was still valid make it usable:
//
//   - The own wrap: after every successful check (keysFor) the client
//     writes epochs/<n>/members/<me>.accept, a countersignature of its
//     current generation over the SHA-256 of the whole .wrap file
//     (store.WrapAccept, short name wrap-accept). A wrap signed by a
//     revoked generation counts only if such an acceptance of the
//     reader's current generation names exactly its hash.
//   - Other files (folders.gml, metadata after a flag change, index
//     segments; task 09b): the client remembers in state.json, per file
//     (per content for a segment, task 09c: segmentMemo), the hash,
//     signer and generation of the last version it verified
//     with a valid generation, and the size of the reference tree of the
//     log it verified against (checkMemo). A file signed by a revoked
//     generation is used only if this record names exactly its hash,
//     signer and generation and the log entry that revokes the
//     generation is not in that tree, so the check came before the
//     revocation the log shows (checkedBefore); then the client signs it
//     again with its own identity (a new file: version + 1 for kind meta,
//     a new segment of this device for kind index). Otherwise it warns,
//     naming only the file (folders.gml of an epoch, the mail ID, the
//     segment), and does not use it. The record of a segment content
//     that this client signed again or merged is marked as such
//     (checkMemo.Next, task 09d): copies and files put back are ignored
//     while the successor is there, and used without counting for a
//     merge while it is not (task 09f), so nobody without a key makes
//     the client sign or merge a content twice, and state.json does not
//     grow by it.
//
// Records in the log (epoch.rec) keep CheckRevokedSignature (task 14) and
// the chain rule checkSignerGen.

// checkMemo is the local check record of one file outside the log.
type checkMemo struct {
	Hash   string `json:"hash,omitempty"`   // SHA-256 of the whole file, hex
	Signer string `json:"signer,omitempty"` // user ID of the signer
	Gen    uint32 `json:"gen,omitempty"`    // generation of the signer
	// Tree is the size of the reference tree of the log when the client
	// verified the file (task 09b). A record without it (0) never counts.
	Tree int64 `json:"tree,omitempty"`
	// Next marks the record of an index segment whose content this
	// client issued again (resignSegment) or merged (mergeSegments): the
	// name of the result that holds its postings now (resultID), the
	// first 128 bits (hex) of the SHA-256 of the segment (task 09d), or,
	// for a result of several segments, of the hash over all of them
	// (task 09g). The record keeps Hash, which binds it to
	// the content, and drops signer, generation and tree, so that it
	// never counts for a takeover again and does not grow (supersede).
	// A segment with this content is ignored while the successor (or a
	// segment this client merged it into later) is there: its postings
	// are in it, so neither a copy nor a file put back is signed again or
	// merged again. While the successor is not there, the content is used
	// if it checks, but counts for MergeThreshold never again (task 09f);
	// the next merge names its own result here (changed in place).
	Next string `json:"next,omitempty"`
	// Part marks the record of an index segment that this client wrote
	// as one of several segments of a merge result or of a segment issued
	// again (noteResult, task 09g): the name of that result (resultID),
	// which the records of the contents it took in hold as Next. Such a
	// content is spent only while every part is there (successors.used).
	// It is set once, when the segment is written, and kept when the
	// record is marked (supersede) or checked again (recordChecked).
	Part string `json:"part,omitempty"`
}

// errNotChecked is the cause of a file outside the log that a revoked
// generation signed and that this client did not check before the
// revocation (2.2 rule 4): it is not used.
var errNotChecked = errors.New("client: signed by a revoked generation and not checked by this client before the revocation")

// foldersMemo is the key of folders.gml of epoch n in mailboxState.Checked.
func foldersMemo(n uint32) string { return "folders/" + strconv.FormatUint(uint64(n), 10) }

// metaMemo is the key of the metadata of mail id in mailboxState.Checked.
func metaMemo(id store.ID) string { return "meta/" + id.String() }

// segmentMemo is the key of the index segment data of device dev (its
// file_id) in epoch n in mailboxState.Checked: epoch, device and the
// SHA-256 of the file, not the sequence number (task 09c). The sequence
// number is not bound into the file (Q11), so anybody with write access
// to the data directory, without any key, can copy a valid segment to
// ever new sequence numbers; byte-equal copies share one record and
// leave state.json as it is. A record is only ever made for a file that
// checked with a valid generation, so the number of records grows with
// the segments written by members, not with the copies.
func segmentMemo(n uint32, dev store.ID, data []byte) string {
	return segmentMemoSum(n, dev, sha256.Sum256(data))
}

// segmentMemoSum is segmentMemo for the SHA-256 sum of the file.
func segmentMemoSum(n uint32, dev store.ID, sum [32]byte) string {
	return "index/" + strconv.FormatUint(uint64(n), 10) + "/" + dev.String() + "/" + hex.EncodeToString(sum[:])
}

// oldSegmentMemo is the key of the check record of segment ref of epoch n
// in the format before task 09c, per file name (index/<n>/<device>-<seq>).
// Such records are no longer made, but they name the SHA-256 of the file
// they were made for, so they still prove the check of exactly that
// content at that place (task 09d, finding low 3): readSegment uses one
// for the file at its place whose hash it names, and nothing else.
func oldSegmentMemo(n uint32, ref store.IndexSegmentRef) string {
	return "index/" + strconv.FormatUint(uint64(n), 10) + "/" + ref.Device.String() + "-" + strconv.FormatUint(ref.Seq, 10)
}

// segmentSuperseded reports whether this client issued the content sum
// of segment ref of epoch n again or merged it (checkMemo.Next): through
// the record of the content, or through a record in the format before
// task 09c for the file at this place that names this content.
func (c *Client) segmentSuperseded(mbx store.ID, n uint32, ref store.IndexSegmentRef, sum [32]byte) bool {
	return c.segmentNext(mbx, n, ref, sum) != ""
}

// segmentNext returns the successor (checkMemo.Next: the first 128 bits
// of its SHA-256, hex) that the records of segmentSuperseded name for the
// content sum of segment ref of epoch n, "" if none.
func (c *Client) segmentNext(mbx store.ID, n uint32, ref store.IndexSegmentRef, sum [32]byte) string {
	if m := c.checkedMemo(mbx, segmentMemoSum(n, ref.Device, sum)); m != nil && m.Next != "" {
		return m.Next
	}
	if m := c.checkedMemo(mbx, oldSegmentMemo(n, ref)); m != nil && m.Next != "" && m.Hash == hex.EncodeToString(sum[:]) {
		return m.Next
	}
	return ""
}

// successors are the records of the segment contents of one epoch that
// this client merged or issued again (checkMemo.Next) and of the parts of
// its results of several segments (checkMemo.Part), for one run of
// readSegments (task 09f, 09g).
type successors struct {
	// next maps the first 128 bits (hex) of a content to its successor.
	next map[string]string
	// parts maps the name of a result of several segments (resultID) to
	// the SHA-256 (hex) of every segment whose record names it.
	parts map[string][]string
	// done holds the answers of used: 1 while it is worked out, 2 used,
	// 3 not used.
	done map[string]uint8
}

// successorsOf collects the successors of the segment records of epoch n
// of mailbox mbx.
func (c *Client) successorsOf(mbx store.ID, n uint32) *successors {
	prefix := "index/" + strconv.FormatUint(uint64(n), 10) + "/"
	s := &successors{next: map[string]string{}, parts: map[string][]string{}, done: map[string]uint8{}}
	for k, m := range c.mailboxState(mbx).Checked {
		if m == nil || len(m.Hash) != 64 || !strings.HasPrefix(k, prefix) {
			continue
		}
		if m.Next != "" {
			s.next[m.Hash[:32]] = m.Next
		}
		if m.Part != "" && !slices.Contains(s.parts[m.Part], m.Hash) {
			s.parts[m.Part] = append(s.parts[m.Part], m.Hash)
		}
	}
	return s
}

// used reports whether the successor id of a content this client merged
// or issued again holds its postings among the segments of the run
// (there: the first 128 bits, hex, of every content that checked), so
// that the content is spent (task 09f, finding low 1; task 09g, N1 of
// 09f). A successor of one segment is used if that segment is there, or
// if the successor this client merged it into later (next) is used. A
// result of several segments (parts) is used only if the records of its
// parts name exactly the segments its name was made of (resultID) and
// every part is used in the same sense: a content whose successor is
// there only in part is not spent, and its postings are not lost. Every
// successor is a segment this client wrote after the content, so the
// chains lead to newer contents; each id is worked out once per run, and
// one met again while it is worked out (no record makes that) is not
// used.
func (s *successors) used(id string, there map[string]bool) bool {
	if id == "" {
		return false
	}
	switch s.done[id] {
	case 1, 3:
		return false
	case 2:
		return true
	}
	s.done[id] = 1
	ok := false
	if hashes, isResult := s.parts[id]; isResult {
		sums := make([][32]byte, 0, len(hashes))
		for _, h := range hashes {
			var sum [32]byte
			if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
				copy(sum[:], b)
				sums = append(sums, sum)
			}
		}
		ok = len(sums) == len(hashes) && resultID(sums) == id
		for _, h := range hashes {
			ok = ok && (there[h[:32]] || s.used(s.next[h[:32]], there))
		}
	} else {
		ok = there[id] || s.used(s.next[id], there)
	}
	s.done[id] = 3
	if ok {
		s.done[id] = 2
	}
	return ok
}

// supersede notes in the check records of the content sum of device dev
// in epoch n that its postings are in the result next (checkMemo.Next,
// task 09d; resultID, task 09g): the record of the content, and every
// record in the format before task 09c of the same epoch and device that
// names this content. Each record is changed in place and does not grow:
// Hash stays, signer, generation and tree are dropped, Next takes the
// name of the result (128 bits), and Part, the result the content is part
// of itself, stays. A record marked before with another successor (a
// content used again because its successor was not there, readSegments,
// task 09f) takes the new one, in place as well. No record is made: a
// content without one has none afterwards either (it was taken over
// through a record in the old format, or it was not checked by this
// client). It reports whether a record changed; the caller saves the
// state.
func (c *Client) supersede(mbx store.ID, n uint32, dev store.ID, sum [32]byte, next string) bool {
	ms := c.mailboxState(mbx)
	if ms.Checked == nil || next == "" {
		return false
	}
	hash := hex.EncodeToString(sum[:])
	changed := false
	set := func(m *checkMemo) {
		if m == nil || m.Next == next {
			return
		}
		*m = checkMemo{Hash: hash, Next: next, Part: m.Part}
		changed = true
	}
	set(ms.Checked[segmentMemoSum(n, dev, sum)])
	prefix := "index/" + strconv.FormatUint(uint64(n), 10) + "/" + dev.String() + "-"
	for k, m := range ms.Checked {
		if m != nil && m.Hash == hash && strings.HasPrefix(k, prefix) {
			set(m)
		}
	}
	if changed {
		c.dirty = true
	}
	return changed
}

// checkedMemo returns the check record of file key of mailbox mbx, nil if
// there is none.
func (c *Client) checkedMemo(mbx store.ID, key string) *checkMemo {
	ms := c.mailboxState(mbx)
	if ms.Checked == nil {
		return nil
	}
	return ms.Checked[key]
}

// noteChecked records that this client verified data, signed by
// generation gen of signer while that generation was valid, as file key
// of mailbox mbx, and saves the state if the record changed.
func (c *Client) noteChecked(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) error {
	if !c.recordChecked(mbx, key, data, signer, gen) {
		return nil
	}
	return c.save()
}

// noteCheckedLater is noteChecked without saving: the record is noted in
// the state in memory (c.dirty), and the operation saves it once with
// saveSeen, like the versions of metadata (task 09, addendum), so that a
// List of many mails does not write state.json for each.
func (c *Client) noteCheckedLater(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) {
	if c.recordChecked(mbx, key, data, signer, gen) {
		c.dirty = true
	}
}

// recordChecked notes the check record of file key in the state in
// memory and reports whether it changed. A record that names the same
// file, signer and generation is kept with its tree size: the first check
// is the earliest proof.
func (c *Client) recordChecked(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) bool {
	ms := c.mailboxState(mbx)
	if ms.Checked == nil {
		ms.Checked = map[string]*checkMemo{}
	}
	m := &checkMemo{Hash: recordHash(data), Signer: signer.String(), Gen: gen, Tree: c.treeSize()}
	old := ms.Checked[key]
	if old != nil && old.Hash == m.Hash && old.Signer == m.Signer && old.Gen == m.Gen && (old.Tree > 0 || m.Tree == 0) {
		return false
	}
	if old != nil && old.Next != "" {
		// A content issued again or merged stays marked (task 09d).
		return false
	}
	if old != nil && old.Hash == m.Hash {
		// A part of a result of several segments stays one (task 09g).
		m.Part = old.Part
	}
	ms.Checked[key] = m
	return true
}

// treeSize returns the size of the reference tree of the log, 0 before
// the first head.
func (c *Client) treeSize() int64 {
	if c.lg == nil {
		return 0
	}
	if h := c.lg.head(); h != nil {
		return h.Size
	}
	return 0
}

// checkedBefore reports whether the check record of file key names
// exactly data, signer and gen and was made before the revocation of gen
// in the log (beforeRevocation).
func (c *Client) checkedBefore(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) bool {
	m := c.checkedMemo(mbx, key)
	if m == nil || m.Hash != recordHash(data) || m.Signer != signer.String() || m.Gen != gen {
		return false
	}
	return c.beforeRevocation(signer, gen, m.Tree)
}

// beforeRevocation reports whether a check against the reference tree of
// size tree came before the revocation of generation gen of signer that
// the log shows (task 09b: "Ein Prüfvermerk zählt nur, wenn er vor dem im
// Log belegten Widerruf entstanden ist"): the user entry that revokes gen
// (key user, signer, gen+1) is in the reference tree, and its index is
// not below tree, so the tree the client checked against did not hold
// it. Fail closed: no tree, no such entry or a log error is false.
func (c *Client) beforeRevocation(signer store.ID, gen uint32, tree int64) bool {
	if tree <= 0 || c.lg == nil {
		return false
	}
	ents, err := c.lg.log.Lookup(translog.KindUser, signer[:])
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.Seq == int64(gen)+1 {
			return e.Index >= tree
		}
	}
	return false
}

// revokedKey returns the identity key of the revoked generation gen of
// user id, once the caller has a local proof for the file.
func (c *Client) revokedKey(id store.ID, gen uint32) (ed25519.PublicKey, error) {
	g, _, err := c.userGen(id, gen)
	if err != nil {
		return nil, err
	}
	return g.IdentityPub, nil
}

// wrapSignerKey returns the key that checks the signature of generation
// gen of signer on the own wrap of epoch e: the key of a valid
// generation, or of a revoked one if checkAccept holds for exactly these
// bytes, or, during step 4 of DeviceLost and its continuation, if the
// seed proves it (seedProof).
func (c *Client) wrapSignerKey(e *store.Epoch, signer store.ID, gen uint32, wrap []byte) (ed25519.PublicKey, error) {
	pub, err := c.userKey(signer, gen, nil)
	if !errors.Is(err, ErrRevoked) {
		return pub, err
	}
	if pub := c.seedProof(signer, gen, wrap); pub != nil {
		return pub, nil
	}
	if aerr := c.checkAccept(e.MailboxID, e.Number, wrap); aerr != nil {
		return nil, fmt.Errorf("%w; no wrap-accept of this member countersigns it (%v); the wrap must be issued again", err, aerr)
	}
	return c.revokedKey(signer, gen)
}

// seedProof returns the identity key of this user's revoked generation
// gen for the own wrap data, if DeviceLost holds the key store of gen
// (prevGen: the old key store, or derived from the seed, whose
// possession proves gen) and the wrap is made for gen and signed by it:
// a wrap that step 2 could not countersign (its chain did not check then)
// stays usable for step 4 and the continuation, which seal it again for
// the new generation and countersign it. Its keys must still equal
// epoch.rec (openOwnWrap, Matches), so a planted file never yields other
// keys than the epoch's. nil otherwise.
func (c *Client) seedProof(signer store.ID, gen uint32, wrap []byte) ed25519.PublicKey {
	if c.prevKs == nil || c.rk != nil || signer != c.me {
		return nil
	}
	p := c.prevGen(gen)
	if p == nil {
		return nil
	}
	f, err := envelope.Parse(wrap)
	if err != nil || len(f.Recipients) != 1 || store.ID(f.Recipients[0].ID) != c.me || f.Recipients[0].Gen != gen {
		return nil
	}
	return p.Identity.Public().(ed25519.PublicKey)
}

// prevGen returns the key store of this user's revoked generation gen
// that DeviceLost holds (c.prevKs), nil if it holds none.
func (c *Client) prevGen(gen uint32) *keys.Keystore {
	for _, ks := range c.prevKs {
		if ks != nil && ks.Generation == gen {
			return ks
		}
	}
	return nil
}

// checkAccept reports nil if members/<me>.accept of epoch n of mbx is
// signed by the current generation of this user (its user.rec in the data
// directory) and names exactly wrap.
func (c *Client) checkAccept(mbx store.ID, n uint32, wrap []byte) error {
	if c.rk != nil {
		return fmt.Errorf("%w: the recovery recipient has no wrap-accept", ErrRevoked)
	}
	a, err := c.st.ReadAccept(mbx, n, c.me)
	if err != nil {
		return err
	}
	if h := sha256.Sum256(wrap); !bytes.Equal(a.WrapHash[:], h[:]) {
		return fmt.Errorf("%w: the wrap-accept of epoch %d names another wrap", ErrRevoked, n)
	}
	g, revoked, err := c.userGen(c.me, a.UserGen)
	if err != nil {
		return err
	}
	if revoked {
		return fmt.Errorf("%w: the wrap-accept of epoch %d is signed by generation %d", ErrRevoked, n, a.UserGen)
	}
	return a.Verify(g.IdentityPub)
}

// acceptWrap countersigns the own wrap data of epoch e that keysFor has
// just checked (2.2 rule 4: "Wer sie einmal erfolgreich geprüft hat,
// signiert sie sofort selbst gegen"), once per epoch and wrap: nothing is
// written if an acceptance of the current generation names it already.
// A client opened with RecoverRead, or whose key store does not hold the
// current generation of user.rec (an interrupted DeviceLost), writes
// nothing. A failed write is a warning; the keys stay usable.
func (c *Client) acceptWrap(e *store.Epoch, data []byte) {
	if c.rk != nil || c.noAccept || c.ks == nil {
		return
	}
	if c.checkAccept(e.MailboxID, e.Number, data) == nil {
		return
	}
	if _, revoked, err := c.userGen(c.me, c.ks.Generation); err != nil || revoked {
		return
	}
	if err := c.writeAccept(e.MailboxID, e.Number, data, c.ks); err != nil {
		c.warn("WARNUNG: Gegenzeichnung der Verpackung der Epoche %d von %s nicht geschrieben: %s.", e.Number, e.MailboxID, warnCause(err))
	}
}

// acceptOwnWraps checks every own wrap of the epochs of ch that are not
// discarded (keysFor), which countersigns each one that checks, and
// folders.gml of each such epoch, which records it (check record): Sync
// does it, so that both proofs exist while the generations that signed
// the files are still valid, even for epochs this client has not read
// yet. A file that does not check is skipped; keysFor and foldersAt
// report it.
func (c *Client) acceptOwnWraps(ch *chain) {
	mbx := ch.mailbox.ID
	for _, e := range ch.epochs {
		if ch.discarded[e.Number] || !c.ownWrapExists(mbx, e.Number) || c.proofsExist(mbx, e.Number) {
			continue
		}
		if _, err := c.keysFor(ch, e); err == nil {
			c.foldersAt(ch, e.Number)
		}
	}
}

// proofsExist reports, without checking signatures, whether the own wrap
// of epoch n has an acceptance of the key store's generation naming its
// hash and folders.gml a check record naming its hash. Both were written
// after a check, so acceptOwnWraps need not check the files again; whether
// they still prove anything is decided when they are used.
func (c *Client) proofsExist(mbx store.ID, n uint32) bool {
	if c.rk != nil || c.ks == nil {
		return false
	}
	wrap, err := c.st.ReadWrap(mbx, n, c.me)
	if err != nil {
		return false
	}
	a, err := c.st.ReadAccept(mbx, n, c.me)
	if err != nil || a.UserGen != c.ks.Generation || a.WrapHash != sha256.Sum256(wrap) {
		return false
	}
	folders, err := c.st.ReadFolders(mbx, n)
	m := c.checkedMemo(mbx, foldersMemo(n))
	return err == nil && m != nil && m.Tree > 0 && m.Hash == recordHash(folders)
}

// writeAccept writes members/<me>.accept of epoch n over wrap, signed by
// the identity of ks (store.WriteAccept replaces an older acceptance).
func (c *Client) writeAccept(mbx store.ID, n uint32, wrap []byte, ks *keys.Keystore) error {
	a := &store.WrapAccept{MailboxID: mbx, Epoch: n, UserID: c.me, WrapHash: sha256.Sum256(wrap), UserGen: ks.Generation}
	if err := a.Sign(ks.Identity); err != nil {
		return err
	}
	return c.st.WriteAccept(a)
}

// resignFolders signs folders.gml of epoch e again after the client took
// it over (it was signed by a revoked generation and the check record
// names it): a new file with the same name and folders (l, inbox), header
// version one above v and above every version seen, signed by this user.
// Only a user member of e whose key store holds its current generation
// and that may write does it; the mailbox lock is taken unless the
// running change holds it, and the file is replaced only while it is still
// old. It returns the version of the file in place afterwards.
func (c *Client) resignFolders(ch *chain, e *store.Epoch, old []byte, l *store.FolderList, inbox store.ID, v uint32) (uint32, error) {
	mbx := ch.mailbox.ID
	if c.writable() != nil || c.ks == nil || !c.isUserMember(e) {
		return v, nil
	}
	if _, revoked, err := c.userGen(c.me, c.ks.Generation); err != nil || revoked {
		return v, nil
	}
	if c.locked != mbx && !c.skipLock {
		unlock, err := c.st.LockMailbox(mbx)
		if err != nil {
			return v, err
		}
		defer unlock()
	}
	cur, err := c.st.ReadFolders(mbx, e.Number)
	if err != nil || !bytes.Equal(cur, old) {
		// Changed meanwhile: the next read checks the new file.
		return v, err
	}
	k := foldersMemo(e.Number)
	next := max(v, c.mailboxState(mbx).Folders[fmt.Sprint(e.Number)])
	if next == ^uint32(0) {
		return v, fmt.Errorf("%w: version of folders.gml exhausted", ErrArgument)
	}
	next++
	plain, err := l.Encode()
	if err != nil {
		return v, err
	}
	sealed, err := c.sealMeta(e, inbox, plain, next)
	keys.Wipe(plain)
	if err != nil {
		return v, err
	}
	if err := c.st.WriteFolders(mbx, e.Number, sealed); err != nil {
		return v, err
	}
	c.warn("Hinweis: folders.gml der Epoche %d von %s war von einer widerrufenen Generation signiert; sie wurde übernommen und neu signiert.", e.Number, mbx)
	if err := c.noteChecked(mbx, k, sealed, c.me, c.ks.Generation); err != nil {
		return next, err
	}
	if crash("folders-resigned") {
		return next, errCrashed
	}
	return next, nil
}
