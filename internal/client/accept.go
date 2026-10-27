package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
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
//   - Other files (folders.gml; segments and metadata are task 09): the
//     client remembers in state.json, per file, the hash, signer and
//     generation of the last version it verified (checkMemo). A file
//     signed by a revoked generation is used only if this record names
//     exactly its hash, signer and generation; then the client signs it
//     again with its own identity (a new file, version + 1 for kind meta).
//     Otherwise it warns and does not use it.
//
// Records in the log (epoch.rec) keep CheckRevokedSignature (task 14) and
// the chain rule checkSignerGen.

// checkMemo is the local check record of one file outside the log.
type checkMemo struct {
	Hash   string `json:"hash"`   // SHA-256 of the whole file, hex
	Signer string `json:"signer"` // user ID of the signer
	Gen    uint32 `json:"gen"`    // generation of the signer
}

// foldersMemo is the key of folders.gml of epoch n in mailboxState.Checked.
func foldersMemo(n uint32) string { return "folders/" + strconv.FormatUint(uint64(n), 10) }

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
	ms := c.mailboxState(mbx)
	if ms.Checked == nil {
		ms.Checked = map[string]*checkMemo{}
	}
	m := &checkMemo{Hash: recordHash(data), Signer: signer.String(), Gen: gen}
	if old := ms.Checked[key]; old != nil && *old == *m {
		return nil
	}
	ms.Checked[key] = m
	return c.save()
}

// checkedBefore reports whether the check record of file key names
// exactly data, signer and gen.
func (c *Client) checkedBefore(mbx store.ID, key string, data []byte, signer store.ID, gen uint32) bool {
	m := c.checkedMemo(mbx, key)
	return m != nil && m.Hash == recordHash(data) && m.Signer == signer.String() && m.Gen == gen
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
	return err == nil && m != nil && m.Hash == recordHash(folders)
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
