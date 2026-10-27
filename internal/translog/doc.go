// Design of the transparency log for milestone M1 (task 03, reworked
// after the verification in task 03b and again in tasks 03c and 03d;
// "finding Sn/An" refers to the findings listed in
// docs/tasks/03b-interfaces-rework.md, "finding 03c-n" to finding n of
// docs/tasks/03c-interfaces-rework-2.md, "finding 03d-n" to finding n of
// docs/tasks/03d-interfaces-rework-3.md).
//
// This file holds no code. It fixes the interface that tasks 07 (log),
// 08 (witness), 10 (ceremony), 11 (server side), 14 (client) and 15
// (ingest, server, ceremony, store) implement. Section numbers refer to
// docs/PLAN.md (specification 1.4), Kn to docs/PHASE2-KLAERUNGEN.md, Qn
// to docs/QUESTIONS.md, Dn to docs/DECISIONS.md, Sn to
// docs/SPEC-ISSUES.md. Where the specification is silent, the reading
// chosen here is marked "Reading" and proposed for DECISIONS.md.
//
// # Reference head
//
// Every Check method of Log answers relative to one tree, the reference
// head:
//
//   - Client log (Options.Verifier set): the last head the Verifier
//     accepted with CheckHead, persisted by the client in state.json
//     (D57) as the full signed note. Before the first accepted head
//     every Check fails with ErrStale or ErrNotInLog.
//   - Operator log (server, ceremony; Options.Verifier nil): the
//     committed tree of log/tree.rec. The server is the operator of the
//     log; its checks (ingest) confirm that a record is logged, not that
//     witnesses have seen it. Protection against the server is the
//     client's job.
//
// # File format of data/log/ (section 4)
//
//	log/lock                      record lock (9.1), held by every writer
//	log/tree.rec                  gomail/v1/rec/log-tree: committed size, root hash
//	log/entries/<index>.rec       gomail/v1/rec/log-entry, written once
//	log/tree/tile/8/<L>/<N>[.p/<W>]  tlog tiles of height 8, every path written once
//	log/heads/<size>.sig          signed head (note) with all cosignatures
//	log/keys/<kind>/<hex SHA-256(subject)>/<seq>   index of the entry with that key
//
// Files are written with store.CreateFileAtomic (entries, tiles, keys:
// exclusive, never replaced) or store.WriteFileAtomic (tree.rec, heads:
// replaced atomically), with the rights of section 9.1, and read with
// store.ReadFileLimited (entries MaxEntryFile, heads MaxHeadNote, tiles
// 256*32 bytes, tree.rec and keys rec-sized). Two exceptions of task 07,
// both for files that only a writer past Append can have put there: a
// tile that exists with exactly the bytes to write is accepted (other
// bytes: ErrConsistency), and a key file that names another index is
// replaced, because keys/ is derived data that no reader trusts alone.
//
// Entry (EntrySchema): kind (1 user, 2 epoch, 3 address, 4 platform),
// subject, seq, content. The content is the unchanged canonical encoding
// of the logged record, byte for byte the file in the data directory.
// Subject and seq form the duplicate key (Key) and are always derived
// from the content (KeyOf); a stored key that differs is ErrEntry. The
// index is the position, not part of the encoding.
//
// Leaf hash: tlog.RecordHash(encoding of the entry) = SHA-256(0x00 ||
// entry), interior nodes tlog.NodeHash (RFC 6962), so proofs are those of
// tlog.ProveRecord/ProveTree, checked with tlog.CheckRecord/CheckTree
// behind the size limit (CheckRecordProof, CheckTreeProof).
//
// Tree hashes. Reading: tiles, not one file per hash. Alternatives were
// (a) one file per stored hash, about two files of 32 bytes per entry,
// and (b) one append-only hash file, which would change a file in place
// (forbidden by the store invariants and not crash-safe without a
// journal). Tiles of height 8 (tlog.Tile, path tlog.Tile.Path) are the
// native format of the Go checksum database: a full tile never changes,
// a partial tile of another width has another path, so every tile file
// is written exactly once; superseded partial tiles may be deleted once
// the full tile exists. HashReaders come from tlog.TileHashReader (client,
// verified against a head) or from reading tiles directly (operator).
//
// tree.rec is the commit point. Append under log/lock: read tree.rec
// (size n); refuse with ErrConsistency, deleting nothing, when
// entries/<n+1>.rec exists or a head in heads/ names a size above n
// (finding 03d-3); remove the leftovers of an interrupted append at
// exactly index n (entries/<n>.rec, its key file, the tiles of
// tlog.NewTiles(8, n, n+1)); write entries/<n>.rec, those tiles, the
// key file; then tree.rec with n+1 and tlog.TreeHash(n+1). One crashed
// append leaves at most the one entry n behind, because the next append
// needs tree.rec = n+1 first; anything beyond n+1, or a signed head
// beyond n, means that tree.rec was rolled back or damaged. Removing
// such entries would make the rollback irreversible (their bytes are
// nowhere else); refusing keeps tree.rec repairable from the entries
// and heads (see "What write access to log/ gives an attacker").
// Readers read tree.rec first and never look beyond its size, so they
// need no lock: everything below the size is immutable. On open, the
// root hash recomputed from the tiles must equal tree.rec
// (ErrConsistency otherwise).
//
// Lock: log/lock is a POSIX record lock as store uses for mailboxes
// (task 02: OFD locks on Linux, fcntl elsewhere). Appends and head
// writes hold it; readers do not. The lock is never held together with a
// mailbox lock in the other order: a client that appends an epoch n > 1
// takes the mailbox lock first, then log/lock (lock order mailbox, log).
// Epoch 1 is appended without any mailbox lock (finding 03d-4): before
// its log entry the mailbox exists nowhere in the data directory, so
// nobody else can hold its lock, and store.LockMailbox would create
// mailboxes/<id>/ and reveal the ID before the entry is logged (see "Who
// writes").
//
// # Heads (Q4, 3.7 last paragraph, 2.7)
//
// A head is a note (golang.org/x/mod/sumdb/note) with the text
//
//	<origin>\n<size>\n<root hash base64>\ntime <ms since 1970 UTC>\n
//
// (Head, ParseHeadText). The log signs with signer name LogSignerName
// ("gomail-log"); the key is a parameter (NewLogSigner), with Q4 the
// ingest key of the current generation. Witnesses sign the same text
// with their own note keys (plain note signatures, Ed25519, algorithm 1),
// so the time line is covered by every signature. Reading: plain note
// cosignatures instead of the C2SP "cosignature/v1" format, because the
// specification names the note format and x/mod/sumdb/note verifies only
// algorithm 1.
//
// heads/<size>.sig holds the signed note: the log signature and every
// witness cosignature collected for that text. The server writes it only
// once the head has the minimum number of cosignatures of its working
// copy witnesses.rec (Operator.PublishHead); a fresh candidate lives in
// the server process until then and is served to witnesses over HTTP
// (package witness). The server stores only signature lines it verified
// itself (Operator.PublishHead); an invalid cosignature is dropped, never
// written (finding A2-10, see OpenHead: one invalid line by a known key
// makes the note unopenable, a denial of service, not a loss of trust).
//
// Reading (finding S5): a head of the same size is replaced only by one
// with the same hash and a time not earlier than the stored one (time >=
// stored time; re-signing every HeadInterval for freshness, an equal
// time is a harmless repetition). This module uses ">=" everywhere for
// it: Verifier.CheckHead, Operator.PublishHead and the witness (finding
// 03c-8a). There are never two heads of one size with different hashes.
// Witnesses cosign such a re-signature and clients accept it.
// The specification forbids "two heads of one size with different
// content" (2.7); the root hash commits to the whole tree, so a head
// with the same hash shows the same log and is no second view, while
// the time line must move for the 24-hour limit of 2.3 to be met when
// the log does not grow. Alternatives, an empty heartbeat entry per
// interval or a separate signed time statement, grow the log or add a
// second signed format. Consequence: a server can keep re-signing an
// old size and withhold a newer entry; the witnesses cannot see that,
// so the appending client must (see "Withheld entries").
//
// Origin. Reading: the origin is fixed by the ceremony and pinned in the
// client (identity-<gen>.pin, see "Pin" below) and in the witness
// configuration; a head with another origin is rejected. The
// specification does not name it; Q4 leaves it open.
//
// # Size limit (finding A5)
//
// tlog.CheckTree and tlog.CheckRecord do not return for tree sizes above
// 2^62 (maxpow2 overflows). MaxTreeSize (2^40, reasons there) bounds
// every size and index this module accepts: ParseHeadText and Head.Text,
// DecodeEntry, tree.rec, Log.Entry, InclusionProof, ConsistencyProof,
// the Verifier (CheckHead also checks a Last read back from state.json)
// and the witness protocol. Every proof is checked through
// CheckTreeProof and CheckRecordProof, which refuse larger sizes before
// tlog runs.
//
// # Duplicate keys (K2 rules 3 and 4)
//
//	user      (user ID, generation)          generation = generations in the user.rec
//	epoch     (mailbox ID, epoch number)
//	address   (address, valid_from)
//	platform  (file name)                    e.g. ingest-2.cert, identity-2.succ
//
// The first valid entry with a key is the only valid one; Append refuses
// a second (ErrDuplicate). This replaces K2 rule 3 (first write under the
// mailbox lock) by the order of the log (K2 rule 4). Only valid entries
// (see "Validity rules") occupy a key: an invalid entry that reached the
// tree past Append is skipped and does not block the key for the real
// record (finding A2). store keeps refusing a second epoch.rec with the
// same number, so in practice the file that store accepted is the one
// that gets logged; for an epoch.rec that can never be logged see "Who
// writes". The first entries of a subject, user (u, 1) and epoch (m, 1),
// are bound to nothing but their own content; that they cannot be taken
// away from their creator is the business of the writing order in "Who
// writes" (finding 03c-1).
//
// # Validity rules
//
// An entry is valid when it is well formed (ErrEntry), its key is not
// taken by an earlier valid entry (ErrDuplicate) and it satisfies the
// rules below against the valid entries before it and the identity
// anchor: the identity list of a pin, Verifier.Identities for clients
// and Options.Identities for operators, which take it from a pin as
// well (finding 03d-2). Validity is a function of the log prefix and
// the anchor, so every client and operator with the same pin reaches
// the same verdict. Pins of one platform carry the same key for the
// same generation and differ only in length; an older pin lacks a
// generation that came without a logged succession (compromise case of
// 2.3) and judges entries that need it as missing a prerequisite until
// the client update brings the newer pin ("Audit"). The rules are
// applied (finding A2 and S6)
//
//   - by Append, under log/lock against the committed tree: nothing that
//     violates them is appended (ErrOrder if it can never become valid,
//     ErrPrerequisite if an entry it depends on is missing);
//   - by the server before signing (Operator.SignHead), which alerts;
//   - by every client while auditing: an invalid entry is skipped, it
//     occupies no key, Lookup never returns it, and the client warns
//     (a server that signs over it did not check, or someone wrote
//     log/ past Append; the tree is append-only, so it stays there).
//
// Rules by kind (all signatures with keys the log itself provides; the
// prerequisite entries must be valid and logged before the entry):
//
//   - user: content decodes with store.DecodeUser, which verifies the
//     chain of generation certificates against the root (and, from task
//     02 on, the root's signature over user.rec). The first entry of a
//     user has exactly one generation; the entry with n generations
//     follows the entry with n-1 of the same user (ErrPrerequisite if
//     missing), with the same user ID and root key and byte-identical
//     certificates 1..n-1 (binds ID and root, S16; ErrOrder).
//   - epoch (m, n), checked against the valid epoch entries (m, 1) to
//     (m, n-1) replayed through store.Chain, so that:
//     n > 1: the entry (m, n-1) is valid and logged before
//     (ErrPrerequisite); prev_hash equals SHA-256 of the content of
//     (m, n-1); the signer is a user member of (m, n-1) and of (m, n)
//     and his member entry in (m, n) carries exactly signer_gen;
//     discards and begin follow store.Chain (K2 rules 1, 2 and 4).
//     n = 1: no prev_hash; the signer is a user member of the epoch
//     itself with generation signer_gen, and his user entry is logged
//     before (as below). Nothing else binds (m, 1) to the creator of the
//     mailbox; see "Who writes" for the order that protects it.
//     In both cases the user entry (signer_id, signer_gen) is valid and
//     logged before (ErrUnloggedSigner, an ErrPrerequisite; 2.2 rule 3: a
//     generation is valid only from its entry on), the user entry
//     (signer_id, signer_gen+1), which revokes it, is not logged before
//     (ErrOrder; 2.2 rule 4: a thief of a revoked device cannot take
//     epoch numbers away from the remaining members), and the signature
//     verifies with the identity key of generation signer_gen from the
//     logged user entry (ErrOrder).
//     Every chain violation is ErrOrder. Without these rules any
//     registered user with write access could log (m, n) for a foreign
//     mailbox and, first entry wins, lock its members out (finding A2).
//   - address: entries of one address have strictly increasing
//     valid_from in log order (ErrOrder; Reading: without it a backdated
//     assignment could be inserted between two existing ones); the
//     admin certificate admin-<admin_gen>.cert is valid and logged
//     before (ErrPrerequisite), its valid_from is <= the assignment's
//     valid_from, and the admin signature verifies with its key
//     (ErrOrder).
//   - platform: a certificate <role>-<g>.cert with g > 1 follows
//     <role>-<g-1>.cert (ErrPrerequisite). The key of identity
//     generation i is the one in the anchor's identity list (pin field
//     8, Verifier.Identities, see "Pin") when the list has i; above the
//     list (successions newer than the pin) it is the key named by the
//     valid succession identity-<i>.succ logged before (ErrPrerequisite
//     if missing). A certificate verifies with the key of its
//     identity_gen, a succession identity-<g>.succ with the key of
//     generation g-1 (ErrOrder if a signature fails). Hence
//     identity-<g>.succ follows identity-<g-1>.succ (ErrPrerequisite)
//     only when g-1 is not in the anchor's list; generations of the list
//     need no logged succession (finding 03d-2: after a compromise,
//     generation g-1 exists only by pin, without a succession, and the
//     rule "g > 2 follows g-1" could never be met). A succession
//     identity-<g>.succ whose g is in the list must name exactly the
//     list's key of generation g (ErrMismatch otherwise: the log
//     contradicts the pin; the entry is invalid for this anchor and the
//     client warns; finding 03c-3). The anchor of an operator log is
//     the identity list of its pin (Options.Identities, finding 03d-2),
//     not a chain derived from logged successions.
//
// Revocation of platform generations by the pin (field 7) enters the
// rules only if Q8 is decided as proposed (see "Platform generations").
//
// # Who writes (9.1: server and client share the data directory)
//
// An entry is appended by the process that creates the record, under
// log/lock:
//
//	client     user (Register: generation 1; device lost: generation n > 1)
//	client     epoch (CreateMailbox: epoch 1; createEpoch: epoch n > 1)
//	client     any member: epoch.rec of others found unlogged, and the
//	           signer's user.rec it depends on (see below)
//	server     address (gomail-server address add)
//	ceremony   platform (certificates and successions; see ceremony.Publish)
//
// First entries of a subject (finding 03c-1). The entries user (u, 1)
// and epoch (m, 1) are bound to nothing but their own content: any
// registered user can log a user.rec with one generation for any user ID
// and an epoch 1 for any mailbox ID in which he is the signing member.
// If the creator wrote the file to the data directory first, another
// user who sees the new ID there could log his own entry first, and the
// real one would be ErrDuplicate for good. For first entries the client
// therefore reverses the order (task 14):
//
//  1. it persists the exact record, the bytes it will later write to
//     the data directory, in its client directory (atomic write, never in
//     the data directory; like state.json part of the client's state,
//     D57), together with everything else step 3 writes (below);
//  2. it appends that record to the log. Append is idempotent: after a
//     crash the client appends the same bytes from its client directory
//     again. ErrDuplicate means that somebody else logged the ID first;
//     the client stops with that error and never writes step 3;
//  3. only then it writes the files into the data directory:
//     users/<id>/user.rec in Register, the mailbox in CreateMailbox;
//     afterwards CreateMailbox removes its copy from the client
//     directory, and Register sets Registered in state.json (Keygen's
//     user.rec stays, as today).
//
// The copy of step 1 holds everything step 3 needs, so that a crash
// between steps 2 and 3 can always be finished from the client directory
// alone (finding 03d-5); the client resumes at step 2 when it finds such
// a copy (CreateMailbox) or a state.json that is not Registered yet
// (Register):
//
//   - Register: the record is users/<id>/user.rec, which Keygen already
//     keeps in the client directory. The invitation is consumed before
//     step 2 (store.ConsumeInvite, so that a code never registers two
//     users), and right after it the client sets the flag InviteUsed in
//     state.json (atomic write). Resuming with InviteUsed set skips
//     ConsumeInvite (which would fail on the used code) and continues
//     with step 2. A crash between ConsumeInvite and the flag loses the
//     code, as store.ConsumeInvite documents for its own crash; nothing
//     is logged yet, and the user registers with a new code and the same
//     ID. Reading: the alternative, consuming the code only after the
//     log entry, would let a mistyped code log an orphan user entry and
//     still needs a flag for the crash between ConsumeInvite and step 3.
//   - CreateMailbox: epoch.rec 1, the finished wrap of the epoch keys
//     for the creator (the envelope of store.WriteWrap, already
//     encrypted to his unwrap key and signed, byte for byte the file of
//     step 3; Reading: no new format for encrypted EpochKeys is needed),
//     the sealed folders.gml and the mailbox.rec naming epoch 1, written
//     to the client directory before step 2 with epoch.rec last. A copy
//     without epoch.rec is a leftover from before step 2 and is deleted;
//     a copy with it resumes at step 2. Step 3 takes the mailbox lock
//     (which creates mailboxes/<id>/), writes the wrap, folders.gml,
//     epoch.rec 1 and mailbox.rec in this order (the wrap first, as
//     today: an epoch without a wrap for its member would be unusable),
//     and then appends the supply of later epochs under the same lock
//     like any epoch n > 1. Before step 2 there is no mailbox lock and
//     no directory (finding 03d-4, "Lock").
//
// Until step 3 the new ID appears nowhere but in the log, which already
// holds the real entry. An epoch (m, 1) is valid only when its signer is
// a user member of the epoch and his user entry (signer_id, signer_gen)
// is logged before ("Validity rules"), so the user entry of Register
// always precedes the first mailbox. A file that step 3 finds already
// present with other content was written by someone with write access to
// the data directory (a denial of service like deleting it; every reader
// sees ErrMismatch against the log).
//
// Later entries (user generation n > 1, epoch n > 1): record first, then
// log entry. The validity rules bind them to their creator (a user entry
// extends the logged one with certificates signed by the logged root; an
// epoch entry is signed by a member of (m, n-1)), so nobody else can take
// their key. A crash in between leaves a record that is not logged; every
// Check on it fails (fail closed) until it is appended again, which
// Append allows because it is idempotent for identical content. The
// address assignment is logged before addresses.json is changed, because
// addresses.json is only the server's working copy.
//
// Unlogged epoch.rec (finding S4, finding 03c-2). An epoch.rec in store
// without a log entry would block its number for good (store refuses a
// second file with the same number). Protocol, task 14:
//
//  1. Every member that finds an epoch.rec without a valid log entry
//     (CheckEpoch: ErrNotInLog, not ErrPending) appends it itself,
//     under the mailbox lock (lock order mailbox, log). Append is
//     idempotent, so concurrent members do no harm. On ErrPrerequisite
//     for an earlier epoch it first appends the missing earlier epochs
//     of the mailbox from store.
//  2. On ErrUnloggedSigner (the user entry (signer_id, signer_gen) is
//     not in the log) the member appends users/<signer>/user.rec from
//     the data directory itself (idempotent and checked by the validity
//     rules like every append, so it cannot log anything the signer did
//     not sign) and then the epoch again. If that does not yield the
//     generation, the epoch can never be logged and counts as ErrOrder
//     (step 3): the user.rec is missing or does not decode, its Append
//     fails with ErrOrder, or it holds fewer than signer_gen
//     generations. Reading: ErrPrerequisite of that user append (an
//     earlier generation of the signer was never logged and its user.rec
//     is gone) counts as well; nobody but the signer could ever log that
//     generation, and a signer who signs an epoch with an unlogged
//     generation broke the order above. Otherwise one such epoch.rec
//     would block its number and the mailbox for good (ErrPrerequisite
//     for every other member).
//  3. Append returns ErrOrder (the signer was revoked before the entry,
//     the signature or the chain is wrong, or step 2 failed): the record
//     can never be logged. Only then may a member replace it in store,
//     under the mailbox lock, by a new epoch.rec with the same number
//     that it creates and appends as usual.
//  4. Append returns ErrDuplicate: another epoch with this number is
//     logged and is the valid one (K2 rule 4); the file in store
//     contradicts the log (ErrMismatch for every reader). It is never
//     replaced by a new epoch. TODO(ask): whether a member may replace
//     it by exactly the logged content (which some member logged
//     without writing store, breaking this protocol).
//
// store cannot ask the log itself (translog imports store). Built by
// task 07, used by task 14: store.ReplaceEpoch(mailbox, number, old,
// new []byte, unloggable func(old []byte) bool) takes the mailbox lock
// itself (the caller must not hold it: the lock is not reentrant within
// a process) and replaces only when the stored bytes equal old, new is
// a valid epoch.rec of the same mailbox and number, and unloggable(old)
// reports true; unloggable runs under the mailbox lock, so the client
// passes a function that runs steps 1 and 2 (taking log/lock inside, lock
// order mailbox, log) and reports whether the outcome is ErrOrder. The
// client appends the new epoch.rec afterwards like any epoch n > 1.
// store refuses every other replacement as today (ErrExists).
//
// Resuming (task 07 finding Q10 (3)): store.EnsureUser and
// store.EnsureEpoch are CreateUser and WriteEpoch for step 3 of the
// first entries and for a crash between record and log entry: a file
// that exists with exactly the bytes to write counts as written, and
// ErrExists is reported only for other content. CreateMailbox removes
// its copy from the client directory right after mailbox.rec is
// written (task 14).
//
// Only the server signs heads (it holds the log key, Q4) and only it
// writes heads/. Witnesses never write to the data directory; they talk
// to the server over HTTP.
//
// # What write access to log/ gives an attacker (2.7 "Garantien")
//
// In the PoC every process with write access to the data directory can
// write log/. Such an attacker (a compromised client, or the server
// itself) can:
//
//   - append entries without the lock or with wrong keys, delete or
//     change entries, tiles, keys or tree.rec. Before signing, the server
//     re-reads every new entry, recomputes the tree from the entries and
//     applies the validity rules; it alerts on invalid entries, which
//     every audit skips and which occupy no key. A forged entry needs a
//     valid signature by a member, a root or the admin key to be of any
//     use; an epoch entry for a foreign mailbox is invalid (finding A2).
//     Changes below a signed head make inclusion and consistency proofs
//     fail (ErrConsistency): "Entfernen oder Ändern eines Logeintrags"
//     is detected.
//   - stop the log for good (finding 03c-7) by overwriting or deleting
//     an entry below a signed head. The tree no longer matches the
//     signed heads: SignHead stops with ErrConsistency and signs no new
//     head, every client refuses the proofs from the changed files
//     (ErrConsistency), and MaxHeadAge after the last good head every
//     client stops with ErrStale. Nothing false is accepted (fail
//     closed), but the log stays down: only the original bytes match the
//     signed heads, and nobody but a backup has them. Recovery is only
//     from a backup of log/ covering the newest candidate any witness
//     cosigned (finding 03d-6), not merely the newest published head:
//     a witness stores a candidate when it cosigns it, before the
//     server has the quorum and publishes it; it refuses every head
//     smaller than the stored one (package witness, rule 5) and stops
//     for good on a head of the stored size with another hash (rule 6),
//     which a log rebuilt from an older backup would soon present. Entries appended after the backup are appended
//     again by their writers (Append is idempotent, the first-entry
//     copies in the client directories survive). This is a permanent
//     denial of service by anybody with write access to the data
//     directory, of the same kind as deleting log/; 2.7 promises
//     detection, not availability.
//   - change tiles or keys/, or roll back or damage tree.rec (finding
//     03d-3). Tiles and keys/ are derived data: the server recomputes
//     them from the entries. tree.rec is repairable as well, because
//     Append never deletes an entry beyond committed size + 1 and refuses
//     (ErrConsistency) as soon as entries/<n+1>.rec exists or heads/
//     names a size above n: the repair (an operator action of task 11)
//     sets tree.rec to the largest m for which entries 0 to m-1 exist
//     and decode, m is at least the size of every head in heads/, and
//     the root hashes recomputed from the entries equal those of the
//     signed heads of size <= m. Not covered (task 15d): any rollback of
//     tree.rec to a size n in which the attacker also removes
//     entries/<n+1>.rec and that no published head covers (no head in
//     heads/ above n). refuse looks at entries/<n+1>.rec and heads/
//     only, so a new process (a restart) does not detect it and accepts
//     the smaller tree; the running process detects it through seen
//     (operatorCur), a client through its reference head and its Pending
//     leaf. The window is therefore the entries appended since the
//     newest published head, normally the appends of one HeadInterval
//     (removing heads/ as well is the point "delete or roll back heads/"
//     below, which witnesses and clients detect). The next Append of
//     the new process removes entry n as a leftover and appends at n;
//     the entries from n+2 on stay as orphans, refuse makes the Append
//     after that fail (ErrConsistency), and RepairTree reports them
//     (OrphanEntriesError with their count) and removes nothing: the
//     operator removes them on purpose and repairs again (task 15d
//     point 2). The writers of the dropped entries notice (a client
//     through its Pending leaf, ErrConsistency once a head covers the
//     index with another entry, or ErrWithheld) and append again.
//     TestOperatorShrunkTree (rework15c_test.go) shows both sides of
//     the gap: the running process refuses, a new process accepts the
//     smaller tree; TestRepairTreeOrphans (rework15d_test.go) the
//     orphans.
//   - delete or roll back heads/: clients keep their last verified head
//     and accept only extensions (ErrConsistency); without a newer head
//     they become stale after 24 hours and stop (ErrStale).
//   - write a signature line with the name and key hash of a pinned
//     witness but an invalid signature into heads/<n>.sig: the head no
//     longer opens for clients (note.Open fails on it). Denial of
//     service only, as deleting the file is; the server never stores
//     such a line itself (finding A2-10). The operator log opens heads/
//     line by line (Head, Refresh, task 11b finding 5) and hands on only
//     the lines that verified, so the server keeps serving the head to
//     its witnesses, and the next cosignature merged by PublishHead
//     writes the file without the line.
//   - write heads without the log key: no valid log signature (ErrHead).
//     With the log key (a compromised server) it can sign any head, but
//     clients accept only heads cosigned by MinWitnesses witnesses, and
//     a witness never cosigns two heads of one size with different
//     hashes. "verschiedene Sichten" is detected only within the bound
//     of "Witness quorum": exactly when fewer than 2*min - n of the n
//     pinned witnesses collude with the server; then the second view
//     gets no valid head. With 2*min <= n even honest witnesses do not
//     prevent it, which is why pin and witnesses.rec require 2*min > n.
//   - withhold an entry (finding S2): the server keeps re-signing an old
//     size with fresh times; witnesses cosign (same hash), ErrStale
//     never fires. "Zurückhalten eines Widerrufs über 24 Stunden" is
//     detected by the appending client: once a verified head with a time
//     more than HeadInterval after its append still does not cover its
//     entry, that is ErrWithheld, a hard error (see "Withheld
//     entries"). A server that signs no head at all, or that keeps the
//     time line of its heads from passing the append time +
//     HeadInterval, is caught by the shorter limit MaxPendingHeadAge
//     (ErrStale) no later than 24 hours after the append (finding
//     03d-7). Other clients cannot notice
//     an entry that was never covered; the appending client is the one
//     that can.
//   - an address assignment that is never logged makes the client
//     reject mail for that address (ErrNotInLog): "stilles Umleiten" is
//     detected.
//
// Not detected (2.7 "Nicht garantiert"): the server together with
// 2*min - n or more witnesses (with min = n: all required witnesses, as
// 2.7 says; with min < n fewer suffice, see "Witness quorum"); a client
// cut off from all witnesses is blocked by the 24-hour limit, not
// deceived. The first head a new device accepts is trust on first use,
// protected only by the witnesses.
//
// # Witness quorum (2.7, finding S1)
//
// A quorum of min out of n pinned witnesses is admissible only when
// 2*min > n (CheckQuorum): the pin and witnesses.rec are rejected
// otherwise, and a Verifier with such a quorum accepts no head. Even
// then a split view is excluded only while fewer than 2*min - n
// witnesses collude (derivation at CheckQuorum):
//
//	n  min  2*min-n  split view excluded with colluding witnesses
//	1  1    1        none (PoC, 2.7: one witness)
//	2  1    0        never; rejected
//	3  2    1        none (2.7 "2 aus 3")
//	3  3    3        up to 2 (any one witness down blocks all clients)
//	4  3    2        up to 1, and one witness may be down
//
// 2.7's "2 of 3" therefore tolerates no colluding witness; to tolerate
// one of three, min must be 3. SPEC-ISSUES proposal in the report of
// task 03b.
//
// # Withheld entries (finding S2, finding 03c-5)
//
// Muss-Regel for clients (task 14): for every own Append the client
// keeps Pending{index, leaf hash, time At by its own clock} in
// state.json (Verifier.Pending). Refresh drops a pending entry once a
// verified head covers it and the record proof for its index verifies
// with its leaf (ErrConsistency otherwise). Verified means that the head
// passed CheckHead first (task 07c finding 2): a head that CheckHead
// refuses (no quorum: ErrWitness; another origin, a time in the future:
// ErrHead) is never used for this check, so it cannot make the client
// believe that its entry was replaced; Refresh returns the error of
// audit or CheckHead and nothing else changes.
//
// Pending entry after a rollback by one (see "What write access to log/
// gives an attacker"): tree.rec was set back before a head covered the
// own entry, the next Append of another writer removed it as a leftover
// and took its index, and the first verified head covering the index
// holds the other entry. Refresh then returns ErrConsistency, keeps the
// old reference head and the client log remembers the verdict:
// CheckFresh and Refresh report it until a Refresh passes the Pending
// check again against a verified tree at least as large, with or
// without a new head. Until then Refresh takes over no head, not even
// one that passed CheckHead and the Pending check but is smaller than
// the tree in which the entry was found replaced (task 11, strictest
// reading): it returns ErrConsistency with the old reference head. The
// caller (task 14) removes the entry from Verifier.Pending, appends the
// record again (the key of the removed entry is free again, so the
// record gets a new index and a new Pending entry) and calls Refresh;
// ErrDuplicate on that Append means that the other entry took the key,
// which the caller reports. The client log's cached state of the
// committed tree still holds the removed entry; that Append discards it
// silently and rebuilds it once from the audit index (task 11), so the
// caller sees no ErrConsistency for it.
//
// A pending entry is withheld when a newer verified head appeared after
// the append that does not cover it: the reference head has
// Time > At + HeadInterval and Size <= Index. Then Refresh and
// Verifier.Fresh return ErrWithheld (which wraps ErrStale), ErrPending
// on the own entry turns into a hard error, and the client processes no
// new signatures and warns. A server that signs heads covers every
// committed entry within HeadInterval (Operator.SignHead), so a head
// signed more than HeadInterval after the append that still leaves the
// entry out shows that the server withholds it.
//
// When no newer head appears at all (server down, witnesses
// unreachable), that is an outage and not withholding: the entry stays
// ErrPending (everything that depends on it fails closed), and only the
// freshness limit applies (ErrStale). Reading, finding 03c-5: the rule
// of task 03b (ErrWithheld HeadInterval after the append, whether or
// not a newer head appeared) turned every outage of an hour into a stop
// of the client and so shortened the availability limit of 2.3 from 24
// hours to one; comparing head times tells withholding from outage.
//
// The bound (finding 03d-7). Head times are the server's: a server can
// keep re-signing the old size with a time line that stays at At +
// HeadInterval (witnesses accept an equal time, "Heads"), so no head
// ever counts as newer and ErrWithheld never fires. With the plain
// limit the client would stop only when now - Last.Time > MaxHeadAge,
// that is up to HeadInterval + MaxHeadAge = 25 hours after the append,
// while 2.7 promises that "Zurückhalten eines Widerrufs über 24
// Stunden" is detected. Reading (strictest): while an uncovered Pending
// entry exists, the freshness limit is MaxPendingHeadAge = MaxHeadAge -
// HeadInterval = 23 hours (Verifier.Fresh, ErrStale). Either the head
// time passes At + HeadInterval (ErrWithheld) or it stays at most there
// and the client stops no later than At + HeadInterval +
// MaxPendingHeadAge = At + 24 hours, by the client's clock. Both
// comparisons use the same number Last.Time, so the bound holds
// whatever the offset between the server's clock and the client's. The
// alternative, reading 2.7's 24 hours as counted from the end of the
// HeadInterval the server has to cover an entry, would keep the plain
// limit but allows 25 hours. The price of the strict reading is that an
// outage stops a client with a pending entry after 23 hours instead of
// 24.
//
// Clocks: At is the client's clock, the head time the server's.
// CheckHead refuses heads more than MaxClockSkew in the client's future,
// so while the server's clock does not run ahead of the client's by more
// than MaxClockSkew (otherwise the client refuses its fresh heads
// anyway), a head signed before the append has a time below At +
// MaxClockSkew < At + HeadInterval and never counts as newer. A client
// clock that runs ahead only delays the verdict.
//
// # Audit (client)
//
// A client log reads and proves every entry between its old and its new
// reference head on Refresh (entries are rare: users, epochs, addresses,
// certificates), applies the validity rules and keeps an index
// subject -> entries in the client directory (never in the data
// directory; like state.json it is part of the client's security, D57).
// A new device builds the index from entry 0.
//
// Trust zone (task 07c finding 5). The index lies in the client
// directory beside state.json and belongs to the same trust zone:
// whoever can write it can as well write Verifier.Last into state.json.
// Write access to the client directory is a compromise of the client
// (D57), against which this design does not protect. The structural
// checks of the index (checkStructure and checkKeys: field ranges, the
// valid keys matching what was derived from them, every index below the
// reference size; and the anchor, size and root of the reference head)
// and the checks of an entry it names (included) protect against
// damage, not against an attacker. When a Check method or Lookup uses
// an entry the index names, it reads the entry from the data directory
// and checks it again: its inclusion in the reference tree (proof
// against Verifier.Last), its leaf and its key must be those the index
// recorded (otherwise the index is discarded and rebuilt). The verdict
// of the validity rules (valid or invalid, and what was derived from a
// valid entry) is taken from the index and not recomputed. Lookup and
// the Check methods answer from this index, so, under the assumption
// that only the client itself writes its client directory, "no entry"
// is complete with respect to the reference head.
//
// The index stores, per entry, its validity and what was derived from
// it (key, signer, generation keys, valid_from); every entry is decoded
// and validated exactly once. Validity depends on the anchor ("Validity
// rules"): when a client update brings a new pin, the client discards
// the index and rebuilds it from entry 0 against the new identity list
// (finding 03d-2). Decoding is not free (finding A-11): a
// user entry with 1,024 generations costs about 100 ms, because
// store.DecodeUser verifies every certificate. MaxContent stays at
// store.MaxUserFile, which bounds that cost per entry.
//
// # Address assignments (2.3, finding S7, finding 03c-4, Q9)
//
// Reading: the assignment in force at receipt time at is the valid
// entry of the address with the greatest valid_from <= at
// (Log.CheckAddress), with no upper bound on valid_from. TODO(Q9): the
// upper bound of task 03b (valid_from at most the time of the head that
// first covered the entry in the auditing client) is dropped, because
// that head differs from client to client (the first head of a new
// device covers everything), so two clients could judge the same mail
// differently; a check rule of the client must give every client the
// same verdict.
//
// The gap stays open and is named here: an admin key can log an
// assignment whose valid_from lies before its logging (but after the
// previous assignment's valid_from, by the order rule of "Validity
// rules") and so legitimize mails delivered to the new mailbox before it
// was logged; an assignment dated in the future takes effect later
// without a new log entry and, through the strictly increasing
// valid_from, blocks every assignment of the address dated before it.
// Q9 proposes a signed field issued in the address record (valid_from >=
// issued; the entry counts only when it is covered by a head whose time
// is at most issued + 24 h), which bounds backdating to 24 hours with
// the same verdict in every client. Until Q9 is decided only the order
// rule is checked.
//
// # Platform generations (2.3, Q8, finding S3)
//
// Strictest reading without Q8 (applied by task 14): an ingest key of
// generation g signs validly only metadata with a receipt time before
// valid_from of ingest-<g+1>.cert, as soon as that certificate is a
// valid entry of the log (Log.CheckPlatform), and only heads with a
// time before it (Verifier.LogKeys). A thief of an old ingest key thus
// cannot sign mail received after the rotation. Consequence for the
// ceremony: valid_from of a new ingest certificate is the switch time;
// see ceremony.IngestRotate.
//
// Log keys (finding 03c-6, finding 03d-1). The ingest certificates from
// which a client builds Verifier.LogKeys come from platform/ of the data
// directory. Opening a head and judging it are separate steps:
//
//   - Opening: every ingest-<g>.cert in platform/ that verifies against
//     the pin's identity list (field 8, or a generation above it named
//     by a succession from platform/ that verifies in a chain from the
//     list) yields a LogKey whose verifier opens heads, whatever its log
//     status. Refresh reads platform/ anew before it opens the newest
//     head. Without this the first head after a rotation, signed by g+1
//     alone, could not be opened (note.Open drops the only log
//     signature as unknown): ingest-<g+1>.cert becomes a logged entry
//     only in the tree of that very head, so a key set fixed at Open or
//     built from logged entries only would never contain it. A
//     certificate in platform/ that is not logged gives a writer of the
//     data directory nothing: it needs the identity's signature, and it
//     signs no head validly.
//   - Judging (CheckHead rule 2, LogKey.Covers): generation g signed a
//     head validly only when it was valid at the head's time line in
//     the tree of that head: ingest-<g>.cert is a valid entry in that
//     tree (LogKey.Logged, together with the successions its issuing
//     generation depends on), valid_from of ingest-<g>.cert <= head
//     time, head time < valid_from of ingest-<g+1>.cert as soon as that
//     certificate is a valid entry in the same tree (not superseded),
//     and, only if Q8, g is not revoked. Refresh audits the entries the
//     new head covers before it judges the head and sets Logged and
//     Until from that audit, so a rotation certificate logged in the
//     same step counts.
//
// The server signs heads with generation g+1 from valid_from of
// ingest-<g+1>.cert on, once that certificate is in the log
// (Operator.SignHead, ceremony.IngestRotate); a head with a time at or
// after that valid_from signed only by generation g is ErrHead. For a
// given tree exactly one generation covers each time, so a head carries
// exactly one log signature (MaxSignatures, finding 03d-10).
//
// Only if Q8 is decided as proposed, pin field 7 lists (role, gen,
// revoked_at_size) (Revoked.AtSize). Entries with an index below
// revoked_at_size that depend on the generation stay valid (as for
// users, 2.2 rule 4), and metadata whose receipt time lies before the
// head time of size revoked_at_size stay valid; everything else signed
// by the generation is rejected. TODO(ask), Q8: heads of one size are
// re-signed with times not earlier (Reading in "Heads"), so "the head time of
// size revoked_at_size" is not unique and not recoverable from the log
// for a new device; proposal: field 7 also carries that time
// (revoked_at_time, ms), set by the issuer of the update.
//
// # Client checkpoints (2.7 "Abgleich zwischen Clients")
//
// Requirement on task 02 (finding S8): the record gomail/v1/rec/checkpoint
// does not exist in store yet; task 02 adds it in parallel, and this
// design needs exactly these fields: user_id (16 bytes), device_id (16
// bytes), origin (string, at most 128 bytes, MaxOrigin), size (I64, at
// most MaxTreeSize), root_hash (32 bytes), head_time (I64), user_gen
// (U32), sig; domain "checkpoint"; file
// checkpoints/<user-id>-<device-id>.rec. user_id and user_gen name the
// signing identity; device_id is a random ID per client directory,
// created once; origin, size, root_hash and head_time are the origin,
// size, hash and time line of the client's reference head. A client
// writes its checkpoint after every Refresh that changed the reference
// head, into every mailbox it is a member of, and checks the others'
// with Verifier.CheckCheckpoint.
//
// store.Checkpoint (task 02) has exactly these fields; since task 07 it
// requires 1 <= size <= MaxTreeSize (store.MaxCheckpointSize), like
// Head: a head of the empty log is never signed, so a checkpoint of size
// 0 names no head.
//
// Check rules for the caller of Verifier.CheckCheckpoint (task 14),
// before the call; a checkpoint that fails one is ignored with a
// warning, because it says nothing about the log:
//
//  1. the file decodes strictly (store.DecodeCheckpoint) and its name is
//     <user_id>-<device_id>.rec of exactly these fields;
//  2. user_id is a user member of the mailbox in whose checkpoints/ the
//     file lies: a member of the head epoch of the mailbox's chain as
//     the client verified it (CheckEpoch); a checkpoint of a non-member
//     is ignored, whoever wrote it;
//  3. user_gen is the current generation of user_id according to the
//     log: the user entry (user_id, user_gen) is valid in the reference
//     tree (CheckGeneration) and no entry (user_id, user_gen+1) is
//     (ErrSuperseded): a revoked device cannot speak for the user;
//  4. the signature (domain "checkpoint") verifies with the identity key
//     of user_gen from that logged user entry.
//
// Role of head_time (Reading, strictest; TODO(ask)): it enters no
// proof, but it orders the two views. All head times are the server's
// clock, and the server never signs a smaller size after a larger one,
// so a checkpoint smaller than the reference head must have head_time <=
// Last.Time; a smaller checkpoint with a later time shows that the
// server kept re-signing an old size for the other client after it
// showed this one a newer tree (withholding, seen from outside):
// ErrConsistency. For the same size the times may differ either way
// (re-signatures, "Heads"); a larger checkpoint is ErrPending.
//
// # Pin (Q4; task 07 changes store)
//
// The client's trust anchor identity-<gen>.pin (gomail/v1/rec/platform-pin,
// D58) is extended by task 07; proposal:
//
//	1 gen            u32     as today: the current identity generation
//	2 pub            32 B    as today: its key
//	3 dev            u8      as today; accepted only with client.Config.AllowDevIdentity (tests; task 14)
//	4 origin         string  log origin, CheckOrigin rules
//	5 witnesses      list of gomail/v1/rec/witness (1 name string, 2 pub 32 B)
//	6 min_witnesses  u32     CheckQuorum: 1 <= min <= len(witnesses) and 2*min > len(witnesses)
//	7 revoked        only if Q8 is decided as proposed: list of
//	                 gomail/v1/rec/platform-revoked
//	                 (1 role u8, 2 gen u32, 3 revoked_at_size i64), optional
//	8 identities     list of gomail/v1/rec/platform-identity (1 gen u32,
//	                 2 pub 32 B): every identity generation from 1 to gen
//	                 in ascending order, at most MaxIdentities
//
// A pin that violates field 6 is rejected when it is decoded (finding
// S1), as is one whose field 8 fails CheckIdentities: generations 1 to
// gen without gap, distinct keys, last element equal to fields 1 and 2.
//
// Built by task 07 (store.PlatformPin, store.DecodePlatformPin): fields
// 4 to 6 and 8 are required, field 7 is not part of the schema (a pin
// with it is refused like any unknown field). store.PlatformPin carries
// the identity list (Identities, store.PlatformIdentity), so that
// ceremony.PublishOptions.Pin (*store.PlatformPin) supplies the whole
// list for Options.Identities, and the witnesses (store.Witness); the
// witness element gomail/v1/rec/witness is store.WitnessSchema, and
// witness.WitnessSchema refers to it. store keeps its own constants of
// the same value (store.MaxPinFile, MaxPinWitnesses, MaxPinIdentities,
// MaxOrigin) because it cannot import translog; TestStoreLimits checks
// that they agree. Requirement on task 14: client.Config does not have
// AllowDevIdentity yet (ceremony/api.go names it); task 14 adds it and
// refuses a pin with dev = 1 unless it is set (only tests set it, no
// command line flag), replacing today's coupling of the dev flag to
// --insecure-no-log.
//
// Size (finding 03d-9, correcting "below 10 KiB" of task 03c): one
// element of field 8 costs 82 bytes in the canonical encoding, so the
// identity list with MaxIdentities = 256 generations takes about 21 KiB,
// and the largest pin, with MaxWitnesses = 16 witnesses with names of 64
// bytes and an origin of 128 bytes besides, about 23 KiB (TestPinSize
// measures it: 23,343 bytes). Task 07 reads pins with the limit
// MaxPinFile = 64 KiB (store.ReadPlatformPin), which also leaves room
// for field 7 should Q8 be decided as proposed: at most MaxRevoked = 512
// elements (task 07 finding Q10 (1)); with all of them, of the four
// proposed components including revoked_at_time, the largest pin takes
// 62,264 bytes (TestPinSize).
//
// Field 8 (finding 03c-3). Reading: a new device gets the pin of the
// current generation, say identity-2.pin, and has to check admin-1.cert
// and ingest-1.cert, which identity 1 signed. The log holds no
// succession below generation 2 that would give it the key of identity
// 1, and taking identity-1.pub from the data directory would trust
// whoever writes it. So the pin carries the whole list of identity
// generations; fields 1 and 2 stay the current one (unchanged meaning for
// existing readers). A certificate is checked with the key of its
// identity_gen from the list (CheckPlatform, IdentityKey); a succession
// identity-<g>.succ in the log whose g is in the list must name the
// list's key (ErrMismatch otherwise); generations above the list come
// from valid successions in the log as before. ceremony.Init writes the
// list with one element, ceremony.Succeed the old list plus the new
// generation.
//
// Field 7 is TODO(ask), Q8: 2.3 distributes a compromised identity
// generation by client update but has no record for a compromised
// ingest or admin generation. Until Q8 is decided pins carry no field 7,
// Verifier.Revoked stays empty and no rule of this design depends on it;
// its shape above is the one to build if Q8 is decided as proposed (see
// "Platform generations"; a fourth component revoked_at_time is proposed
// there). The witness element schema is store.WitnessSchema since task
// 07 (see above).
//
// # Additions to 9.2
//
// Not named in 9.2 and proposed by this design: "gomail-ceremony
// succeed" and "gomail-ceremony publish" (ceremony/api.go),
// "gomail-witness keygen" and the flags --log-key, --origin, --state and
// --interval of "gomail-witness serve" (package witness; 9.2 names only
// --log and --key), and the flag --pin <file> of gomail-server, the pin
// whose identity list anchors the server's validation
// (Options.Identities, finding 03d-2). Task 11 adds the flags
// --log-listen <addr> and --head-interval <duration> of "gomail-server
// serve" and the command "gomail-server log repair --data <dir> --pin
// <file>" (RepairTree). Task 15c adds the flag --require-client-lock of
// "gomail-server serve" (a client lock locks/client in force at the
// start, ingest.Config.PeerCheck; off by default, reading D70 of 9.1).
//
// # Tasks
//
//   - 07: Open, client and operator log, Append protocol with the
//     validity rules, tiles, tree.rec, keys/, Lookup, proofs, Verifier
//     (quorum, Pending, ErrWithheld), audit index, all Check methods;
//     move Unverified to translogtest; store: pin fields 4 to 6 and 8
//     with the quorum and identity list rules (field 7 only if Q8 is
//     decided as proposed), read limit MaxPinFile, a blocking exported
//     record lock for log/lock, store.ReplaceEpoch (see "Who writes");
//     Append refuses instead of deleting beyond index n (finding
//     03d-3); LogKeys from platform/ before opening a head (finding
//     03d-1); MaxPendingHeadAge in Fresh (finding 03d-7); MaxRevoked,
//     store.EnsureUser and store.EnsureEpoch, the wording of Refresh
//     (task 07 finding Q10 (1), (3), (6)). Built in impl.go (Open, the
//     client and the operator log), state.go (validity rules, audit
//     index as JSON in Options.IndexFile) and files.go (log/); SignHead
//     and PublishHead of the operator log returned ErrNotImplemented
//     until task 11. Superseded partial tiles are not deleted.
//   - 08: witness (package witness).
//   - 11: Operator.SignHead and PublishHead in the server, HTTP handlers
//     of package witness, re-signing every HeadInterval, the repair of
//     tree.rec from entries and heads (finding 03d-3). Built by task 11:
//     operator.go (SignHead, PublishHead, RepairTree,
//     InvalidEntriesError; Options.Origin, Witnesses and MinWitnesses),
//     the HTTP side in the new package loghttp instead of package
//     witness (candidate in memory, signing cadence, handlers),
//     "gomail-server serve --pin --log-listen --head-interval" and
//     "gomail-server log repair". Duties from Q10 (QUESTIONS.md),
//     binding for task 11:
//     (2) SignHead signs a tree only after it has itself synced log/,
//     log/entries/ and the tree files (fsync of the files and the
//     directories): a tree.rec that is visible is not yet durable, and
//     a head over a tree lost in a crash could never be matched again;
//     (4) a backup of log/ must cover every candidate the server ever
//     handed to a witness (finding 03d-6, "What write access ...");
//     after losing such a candidate the only way out is a new origin,
//     that is a new log with new pins and witness configurations;
//     (5) operating rule: after a succession of the platform identity
//     the operator installs the new pin on the server (--pin) before
//     ceremony.Publish and before the server restarts, so that the
//     server judges the new successions and certificates against the
//     same identity list as the clients.
//     Task 11b (findings of the verification of task 11): SignHead has
//     the injection point "sync" between the sync of the tree and the
//     signature, and the synced paths are pinned by a test; "gomail-server
//     address add" checks under addresses.lock, before Append, that the
//     address is free or assigned to the same mailbox in addresses.json
//     and in the log (no reassignment in the PoC); Head and Refresh of
//     the operator log open heads/ line by line; Operator.LogKeys gives
//     the log side the logged ingest keys for /cosign bodies of a head
//     signed before a rotation; pin and data directory are compared with
//     symbolic links resolved. Recorded readings, unchanged by 11b:
//     (a) RepairTree fails closed on every file in heads/ that it cannot
//     read as a head of the log (no log signature by a valid ingest
//     certificate, another size or origin, a root the entries do not
//     give); the operator deletes such a file and repairs again;
//     (b) PublishHead does not check the head time against the server's
//     own clock: SignHead signs with the injected time, and a head time
//     in the future is refused by the witness (its rule 2) and by the
//     client (MaxClockSkew in CheckHead);
//     (c) RepairTree checks the log signature of a head with every
//     valid ingest certificate, not with the generation that covers the
//     head time: the covering generation is a rule of PublishHead and of
//     the client (CheckHead), and a head that violates it is refused
//     there, not repaired;
//     (d) POST /gomail/log/cosign (package loghttp) accepts several
//     valid witness cosignatures in one body, a milder reading than the
//     "exactly two lines" of the witness program; every line is verified
//     on its own and only verified lines are kept;
//     (e) package loghttp has timeouts and size limits but no limit on
//     connections and no rate limit (10.2, before production).
//   - 10: the ceremony (package ceremony, api.go).
//   - 14: the client order for first entries (Register and
//     CreateMailbox: client directory, Append, then data directory; "Who
//     writes", findings 03c-1, 03d-4 and 03d-5), logging the signer's
//     user.rec for an unlogged epoch.rec (finding 03c-2), rebuilding the
//     audit index on a new pin (finding 03d-2), the client sites below.
//     Fixed for task 14 by task 11 (addendum of task 11):
//     (a) the function unloggable the client passes to
//     store.ReplaceEpoch runs under the mailbox lock that ReplaceEpoch
//     holds (lock order mailbox, log: Append takes log/lock inside) and
//     reports errors.Is(err, ErrOrder) for err = Append(KindEpoch, old);
//     before it decides, it runs steps 1 and 2 of "Unlogged epoch.rec":
//     on ErrUnloggedSigner (checked first, it is an ErrPrerequisite) it
//     appends users/<signer>/user.rec of the data directory and then old
//     again, on any other ErrPrerequisite it appends the missing earlier
//     epochs of the mailbox from store and then old again; a signer's
//     user append that fails with ErrOrder or ErrPrerequisite, or that
//     yields fewer than signer_gen generations, makes old unloggable
//     (true), every other error false (fail closed: nothing replaced);
//     (b) a Pending entry found replaced after a rollback by one
//     (Refresh: ErrConsistency, "Withheld entries"): the caller removes
//     it from Verifier.Pending, persists state.json, appends the record
//     again (new index, new Pending entry) and calls Refresh; Refresh
//     takes over no head until then;
//     (c) after every Refresh the client calls CheckFresh, whatever
//     Refresh returned, before it relies on the log (Log.Refresh).
//   - 15: the server, ingest, ceremony and store sites below; the
//     server's pin (--pin, Options.Identities, finding 03d-2).
//     Built by task 15 (the ceremony part, point 3 of the task, is
//     deferred to task 15b): ingest checks before every delivery
//     CheckEpoch for the whole chain up to the head of mailbox.rec and
//     refuses a head below the newest valid epoch entry of the mailbox
//     (Lookup(KindEpoch), ingest.ErrRollback: the residual risk of D71),
//     CheckUser, CheckGeneration and CheckRevokedSignature for the
//     signers, CheckAddress at the receipt time for every recipient
//     (550 without a valid assignment in the log, 451 for other log
//     failures), CheckPlatform for its own ingest certificate at the
//     start, and refuses to sign once ingest-<g+1>.cert in the log is
//     valid from the receipt time on (ingest.ErrSuperseded, "Platform
//     generations"). gomail-server serve always runs with the log (no
//     --insecure-no-log), checks platform/ against the identity list of
//     its pin at the start (translog.ErrMismatch for a generation the
//     pin does not know: operating rule (5) above) and the log head
//     with SignHead, and refuses to start on an inconsistent log.
//     Role locks (9.1, D70): the server holds locks/server exclusively
//     from ingest.New on and checks that the lock is in force through a
//     second open file description; gomailctl holds locks/client
//     (shared) and refuses unless store.CheckPeerLock finds the server
//     lock in force. "address add" reads the admin key through its
//     resolved path outside the data directory; the check under
//     addresses.lock and the Append stay one hold, the write of
//     addresses.json follows (reading in cmd/gomail-server).
//     Task 15c (findings of the verification of task 15): ingest checks
//     the ingest generation again in the commit under the mailbox locks
//     (ingest-<g+1>.cert logged while the data arrive: 451). A committed
//     tree that shrinks while a process runs is handled differently by
//     the two kinds of log (strictest reading for the operator; "What
//     write access to log/ gives an attacker" stays as it is for the
//     client):
//     client log: its checks answer from the audit index of the
//     verified reference head (ref), so a cached state of the committed
//     tree that the tree no longer extends is rebuilt silently from ref
//     (getCur, task 11 addendum point 2), and nothing the client
//     accepts depends on tree.rec;
//     operator log: its checks answer from the committed tree itself,
//     so it fails closed. A tree.rec smaller than the largest tree the
//     process has accepted, of that size with another root, or not
//     extending it is ErrConsistency for Lookup, every Check method,
//     Append, SignHead and PublishHead, without a silent rebuild
//     (operatorCur); view also applies refuse (an entry beyond the next
//     index or a published head beyond the size), so a new process that
//     never saw the larger tree fails the same way. Only a new process
//     heals, after "gomail-server log repair" (RepairTree) where the
//     files show the rollback; a rollback with entries/<n+1>.rec
//     removed that no published head covers stays the gap named above
//     (task 15d). Head keeps serving the
//     published heads with the log keys of the last accepted tree.
//     ingest answers ErrConsistency with 451 (the server accepts no
//     mail), loghttp.Tick logs the refusal of SignHead and drops its
//     candidate. "gomail-server serve --require-client-lock" requires
//     a client lock in force at the start (ingest.Config.PeerCheck; off
//     by default, D70).
//     Task 15d (low findings of the verification of task 15c): a test
//     of refuse in SignHead for a new process
//     (TestSignHeadRefuseEntryBeyond); RepairTree reports files
//     entries/<i>.rec with i >= m as an OrphanEntriesError
//     (ErrConsistency with their count) before it writes anything and
//     removes nothing, and "gomail-server log repair" prints how many
//     entries it reported (and that it dropped none); the gap above is
//     named as every rollback with entries/<n+1>.rec removed since the
//     newest published head. The behaviour of refuse, view and Append
//     is unchanged.
//
// # Open phase-3 log sites
//
// The sites carry the TODO tag that HANDOFF.md lists under "Alle
// TODO(phase3-...)"; neither this file nor the package comment in
// translog.go spells the tag out, so that a grep for it finds the sites
// only (finding 03c-8e). The count (finding 03d-8) is the output of
//
//	grep -rnE --include='*.go' 'TODO\(phase3-translog\)' . | wc -l
//
// in the module root: 28 at the base of task 03 (commit ba8b343); 27
// since task 02 (the site in internal/store/records.go, the binding of
// user ID and root key, was resolved by the root's signature over
// user.rec), and 27 after task 07, one line per site. The pattern
// escapes the parentheses, so this file, which contains it only in
// escaped form, does not match it. By file after task 07:
// internal/client 10 (client.go 2, mailbox.go 5, read.go 2, keygen.go
// 1), internal/ingest/delivery.go 4, cmd/gomail-server/main.go 1,
// internal/ceremony/ceremony.go 1,
// internal/translog/translogtest/unverified.go 11 (Unverified, moved
// there from translog.go by task 07 with its marks). The table has one
// row per site; Unverified is one row for its 11 methods, so it has 17
// rows for the 27 sites. The figure 31
// in task 03 and ORCHESTRATION.md counted mentions in the documents as
// well (HANDOFF.md, PHASE2-KLAERUNGEN.md K2 rule 4, ORCHESTRATION.md).
// Wave 1 tasks running in parallel (01, 02) may add sites; they are
// resolved by the same task as their neighbours. At the base of task 11
// (commit ad67baf) the count is 31: client tasks merged after task 07
// added internal/client/recovery.go 1, members.go 2 and one more in
// mailbox.go (internal/client 14). Task 11 resolves the site in
// cmd/gomail-server/main.go ("address add" appends with
// Append(KindAddress) to the operator log of --pin before AddAddress;
// only --insecure-no-log still uses Unverified until task 15): 30 sites.
// Task 15 resolves the four sites in internal/ingest/delivery.go (the
// server's ingest checks against its operator log, see the rows below)
// and the one in ceremony.InitDev (the certificates go into the operator
// log of the new data directory, which also gets witnesses.rec): 25
// sites, internal/client 14 (task 14) and translogtest 11. gomail-server
// has no --insecure-no-log any more and imports no translogtest;
// gomailctl keeps the switch until task 14 builds the client log, and
// gomail-ceremony until task 15b takes the ceremony to the log.
//
//	file, function                         check today            replaced by (new interface)                          task
//	client/client.go Open                  CheckFresh             Refresh(now), head into state.json, CheckFresh       14
//	client/client.go Open                  CheckUser (own)        CheckUser (+ErrSuperseded), checkpoint after Refresh 14
//	client/mailbox.go createEpoch          AppendEpoch            Append(KindEpoch, data), remember index in state;     14
//	                                                              epoch 1 (CreateMailbox): client dir, Append, data dir
//	client/mailbox.go userKey              CheckUser (signer)     CheckUser                                            14
//	client/mailbox.go userKey              CheckGeneration        CheckGeneration                                      14
//	client/mailbox.go userKey              CheckRevokedSignature  CheckRevokedSignature (index order)                  14
//	client/mailbox.go checkEpoch           CheckEpoch             CheckEpoch + Lookup(KindEpoch, mbx) for the head      14
//	client/read.go ingestKeyFor            CheckPlatform          CheckPlatform (identity list), LogKeys from certs    14
//	client/read.go checkMeta               CheckAddress           CheckAddress (newest valid_from <= receipt, Q9)      14
//	client/keygen.go Register              AppendUser             client dir, Append(KindUser, data), then user.rec    14
//	ingest/delivery.go chooseEpoch         CheckEpoch             CheckEpoch (operator log) + Lookup(KindEpoch) head   15 (done)
//	ingest/delivery.go userKey             CheckUser              CheckUser (operator log)                             15 (done)
//	ingest/delivery.go userKey             CheckGeneration        CheckGeneration (operator log)                       15 (done)
//	ingest/delivery.go userKey             CheckRevokedSignature  CheckRevokedSignature (operator log)                 15 (done)
//	cmd/gomail-server main.go address      AppendAddress          Append(KindAddress, enc) (done by task 11)            11
//	ceremony/ceremony.go InitDev           AppendPlatform         Append(KindPlatform, data) to the operator log        15 (done);
//	                                                              real ceremony: Publish                                15b (10)
//	translog/translogtest Unverified x11   accept everything      --insecure-no-log removed (moved there by task 07)   15
//
// Not a tagged site, but changed by this design:
//
//	store/store.go epoch.rec writes        exclusive create only  + store.ReplaceEpoch after Append ErrOrder           07 (store), 14
//	client sync                            none                   append unlogged epoch.rec of others and the           14
//	                                                              signer's user.rec ("Who writes")
//	client directory                       state.json only        + first-entry copies (Register, CreateMailbox)        14
//	client/keygen.go Register              consume, write, log    ConsumeInvite, InviteUsed in state.json, Append,      14
//	                                                              user.rec; resume skips ConsumeInvite (03d-5)
//	client/mailbox.go CreateMailbox        lock, write, log       copy (epoch.rec 1, wrap, folders.gml, mailbox.rec),   14
//	                                                              Append without mailbox lock, then lock and write
//	                                                              data dir, supply under the lock (03d-4, 03d-5)
//	client state.json                      head only              + Verifier.Pending, ErrWithheld                       14
//
// Without a call site today (task 14): client checkpoints
// (Verifier.CheckCheckpoint), successions of the platform identity
// (CheckPlatform on identity-<gen>.succ), compromised platform
// generations (pin field 7, only if Q8), the identity list of the pin
// (field 8), the comparison of mailbox.rec with the newest logged epoch
// (Lookup), withheld own entries (ErrWithheld).

package translog
