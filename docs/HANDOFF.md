# Übergabe nach Phase 1

Stand: Phase 1 ist umgesetzt: der erste durchgehende Ablauf mit Registrierung, Postfach, Empfang per SMTP und Lesen, alles verschlüsselt und geprüft, beschränkt auf Postfächer mit genau einem Mitglied (Meilensteine 2 und 3 aus Spezifikation 11). Grundlage ist `docs/PLAN.md` in Version 1.2 (Abschnitt 14 listet die Änderungen gegenüber 1.1). Dieses Dokument richtet sich an Phase 2 und ist die verbindliche Beschreibung der Pakete, ihrer Invarianten und Grenzen. Entscheidungen stehen in `docs/DECISIONS.md` (Phase 1 ab D47), offene Punkte der Spezifikation in `docs/SPEC-ISSUES.md`, der Ablauf von Hand in `docs/RUNBOOK.md`.

**Zwei Entscheidungen stehen aus** (SPEC-ISSUES S11 und S13, Vorschläge dort): die Normalisierung eingegebener Seed-Wörter und die Gültigkeit von Signaturen widerrufener Generationen. Umgesetzt ist jeweils die strengste Lesart, markiert mit `TODO(S11)` und `TODO(S13)`; kein Dateiformat hängt davon ab.

## Überblick

```
internal/rec       kanonische Kodierung (3.6), strikter Decoder, NFC-Prüfung
internal/keys      Seed, BIP-39, HKDF (2.2, 2.3), Zertifikate, Signaturdomänen (3.7), Schlüsselspeicher
internal/shamir    Aufteilung über GF(256), Anteile als 30 Wörter (2.3)
internal/envelope  Dateiformat .gml (3): HPKE-Verpackung, STREAM-Inhalt, Signatur
internal/store     Datenverzeichnis (4): atomares Schreiben, Sperren, alle Datensätze von Phase 1
internal/translog  Schnittstelle zum Transparenzlog (2.7); einzige Umsetzung Unverified
internal/smtpd     SMTP-Zustandsmaschine mit den Grenzen aus 5.1
internal/ingest    Annahme, Spool-Transaktion, Metadaten, Marker, Vorverarbeitung (5.2 bis 5.4)
internal/client    Schlüsselerzeugung, Registrierung, Postfach, Vorrat, Lesepfade mit allen Prüfungen (2.4, 7)
internal/ceremony  Entwicklungszeremonie (2.3, nur --dev)
internal/testenv   Plattform, Benutzer und Postfächer für Tests (nur Tests)
internal/e2e       Ende-zu-Ende-Tests und Lauf der Programme nach RUNBOOK
cmd/gomail-server  serve, invite create, address add
cmd/gomailctl      keygen, register, mailbox create, sync, list, read, inspect
cmd/gomail-ceremony init --dev
```

Abhängigkeiten: `envelope -> keys -> rec`, `shamir -> keys`, `store -> envelope, keys, rec`, `translog -> store`, `ingest -> smtpd, store, envelope, translog`, `client -> store, envelope, keys, translog`, `ceremony -> store, keys, translog`. `smtpd` hängt von keinem Paket des Projekts ab. Nur Standardbibliothek, `golang.org/x/crypto/argon2` und `golang.org/x/text/unicode/norm` (v0.43.0); `x/mod` kommt erst mit dem Log. Go 1.26 (getestet mit 1.26.10).

Prüfen:

```
go vet ./...
go test -race ./...
GOARCH=386 go test ./...             # -race gibt es auf 386 nicht
go test -cover ./internal/...
go test -run '^$' -fuzz '^FuzzDecodeRecords$' -fuzztime 5m ./internal/store/   # je Fuzz-Ziel
```

Testvektoren liegen unter `internal/<paket>/testdata/`, die Generatoren unter `internal/<paket>/testdata/gen/` (`go run ./testdata/gen` im Paketverzeichnis). Die `.gml`-Dateien aus Phase 0 (Rahmen ohne Typbytes) liegen unter `internal/envelope/testdata/phase0/` und müssen abgelehnt werden.

## rec

### API

```go
type Kind uint8            // U8, U32, I64, Bytes, String, List
type Field struct { Num uint8; Name string; Kind Kind; Required bool; Size, MaxLen int; Elem *Schema; MaxCount int }
type Schema struct { Type string; Fields []Field }
func NewSchema(typ string, fields ...Field) (*Schema, error)
func MustSchema(typ string, fields ...Field) *Schema          // panics on a bad schema (programming error)
func (s *Schema) Prefix() []byte                               // Typ || 0x00

type Record
func New(s *Schema) *Record
func (r *Record) SetU8/SetU32/SetI64/SetBytes/SetString/SetList(num, v) *Record   // verkettbar, erster Fehler bleibt
func (r *Record) Err() error
func (r *Record) Encode() ([]byte, error)
func Decode(s *Schema, data []byte) (*Record, error)
func (r *Record) Has(num) bool; U8/U32/I64/Bytes/String/List(num)   // Nullwert bei Abwesenheit, nie Panic
const MaxRecordSize, MaxValueLen = 1 << 20; MaxTypeLen = 64
var ErrBadType, ErrTruncated, ErrFieldOrder, ErrUnknownField, ErrBadLength, ErrTooLong, ErrTooMany,
    ErrMissingField, ErrBadString, ErrNotNormalized, ErrKind, ErrSchema
```

### Invarianten
- Ein Schema wird einmal gebaut und danach nicht verändert. Feldnummern 1..255, aufsteigend; `Bytes` hat genau eines von `Size` und `MaxLen`; `String` braucht `MaxLen`; `List` braucht `Elem` und `MaxCount`.
- `Decode` ist strikt: Was es annimmt, kodiert `Encode` byte-identisch zurück. Teilergebnisse gibt es nicht.
- Strings müssen gültiges UTF-8 in NFC sein und dürfen kein Nullbyte enthalten; `rec` normalisiert nie, es lehnt ab. Aufrufer, die Benutzereingaben annehmen, normalisieren vorher selbst mit `norm.NFC.String`.
- `Bytes` und `List` liefern Kopien; `SetBytes` kopiert die Eingabe. Listenelemente werden beim `Encode` erneut geprüft.
- `rec.Kind` ist die Feldart und hat nichts mit `envelope.Kind` (Dateiart) zu tun.

### Grenzen
- Keine Normalisierungsfunktion, nur die Prüfung über `golang.org/x/text/unicode/norm` (Unicode 15.0.0 in v0.43.0). Die UTF-8-Prüfung bleibt getrennt, weil `x/text` ungültige Bytes als normalisiert meldet. Beim Anheben von `x/text` die Unicode-Version beachten: Strings, die unter einer neueren Version anders normalisieren, würden von älteren Clients abgelehnt.
- Kein streamendes Dekodieren; Eingaben sind Byte-Slices bis `MaxRecordSize`.

## keys

### API

```go
type Seed [32]byte
func NewSeed(r io.Reader) (*Seed, error)                      // nil = crypto/rand
func (s *Seed) Words() ([]string, error)                      // 24 BIP-39-Wörter
func SeedFromWords(words []string) (*Seed, error)             // exakt 24, exakt wie in der Liste
func (s *Seed) Zero(); func Wipe(b []byte)
func Wordlist() []string; LookupWord(w string) (int, bool); Word(i int) (string, bool)
const WordlistSHA256

func DeriveUser(seed *Seed) *UserRoot
func (u *UserRoot) RootKey() (ed25519.PrivateKey, error)
func (u *UserRoot) IdentityKey(gen uint32) (ed25519.PrivateKey, error)
func (u *UserRoot) UnwrapKey(gen uint32) (*ecdh.PrivateKey, error)
func (u *UserRoot) Zero()
func DerivePlatform(seed *Seed) *PlatformRoot
func (p *PlatformRoot) IdentityKey/AdminKey/IngestKey(gen uint32) (ed25519.PrivateKey, error)
func (p *PlatformRoot) Zero()

func Sign(priv ed25519.PrivateKey, domain string, body []byte) ([]byte, error)   // "gomail/v1/sig/"+domain+0x00+body, domain aus der Tabelle in 3.7
func KnownDomain(d string) bool; RecordDomain(s *rec.Schema) (string, error)
const DomainPlatformCert, DomainPlatformSuccession, DomainUserGen, DomainEpoch, DomainAddress, DomainCheckpoint, DomainMail, DomainMeta, DomainPending, DomainWrap, DomainIndex
func Verify(pub ed25519.PublicKey, domain string, body, sig []byte) bool

type GenerationCert struct { Gen uint32; IdentityPub ed25519.PublicKey; UnwrapPub *ecdh.PublicKey; Created int64; Revokes uint32; Signature []byte }
func NewGenerationCert(root ed25519.PrivateKey, gen uint32, identityPub ed25519.PublicKey, unwrapPub *ecdh.PublicKey, created int64) (*GenerationCert, error)
func (c *GenerationCert) Encode() ([]byte, error); DecodeGenerationCert([]byte) (*GenerationCert, error)
func (c *GenerationCert) Verify(rootPub ed25519.PublicKey) error
func VerifyGenerationChain(rootPub ed25519.PublicKey, certs []*GenerationCert) error

type PlatformCert struct { Role Role; Gen uint32; Pub ed25519.PublicKey; IdentityGen uint32; ValidFrom int64; Signature []byte }   // 2.3, Version 1.1
func NewPlatformCert(identity ed25519.PrivateKey, identityGen uint32, role Role, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformCert, error)
func DecodePlatformCert([]byte) (*PlatformCert, error); (c *PlatformCert) Encode(); Verify(identityPub) error
type PlatformSuccession struct { Gen uint32; Pub ed25519.PublicKey; ValidFrom int64; Signature []byte }   // gomail/v1/rec/platform-succ
func NewPlatformSuccession(prev ed25519.PrivateKey, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformSuccession, error)
func DecodePlatformSuccession([]byte); (s *PlatformSuccession) Encode(); Verify(prevPub, prevGen) error

type Keystore struct { Generation uint32; Identity ed25519.PrivateKey; Unwrap *ecdh.PrivateKey }
func (k *Keystore) Seal(passphrase []byte, r io.Reader) ([]byte, error)   // Argon2id 64 MiB/3/4, r: 16 Byte Salt, 12 Byte Nonce
func OpenKeystore(data, passphrase []byte) (*Keystore, error)
func (k *Keystore) Zero()
func WriteKeystoreFile(path string, data []byte) error; ReadKeystoreFile(path string) ([]byte, error)
var GenerationCertSchema, PlatformCertSchema, PlatformSuccessionSchema, KeystoreHeaderSchema, KeystoreContentSchema
var ErrWordlist, ErrWordCount, ErrUnknownWord, ErrChecksum, ErrGeneration, ErrZeroed, ErrDomain, ErrSignature,
    ErrCert, ErrKeystore, ErrPassphrase, ErrKDFParams
```

### Invarianten
- Generationen beginnen bei 1 und sind lückenlos; `VerifyGenerationChain` verlangt die vollständige Folge ab 1. Ob eine Signatur einer widerrufenen Generation vor dem Widerruf im Log stand (2.2 Punkt 4), prüft Phase 6 mit dem Transparenzlog.
- `RootKey` nur kurz im Speicher halten und mit `keys.Wipe` löschen; `UserRoot.Zero` nach der Ableitung aufrufen. Der Seed wird nie gespeichert.
- Signaturdomänen sind die Kurznamen aus 3.7 (Version 1.2) als Konstanten `Domain*`; `Sign` und `Verify` nehmen keine anderen an, `RecordDomain(schema)` liefert den Kurznamen eines Datensatztyps (DECISIONS D47). Ein neuer signierter Typ braucht eine neue Zeile in 3.7 und in `keys`.
- `Decode*` prüft Struktur, nicht Signatur; `Verify` immer aufrufen.
- Der Schlüsselspeicher enthält nur die aktuelle Generation. Beim Öffnen werden KDF-Parameter aus dem Kopf innerhalb fester Grenzen übernommen (64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads); schwächere als die Spezifikation nie.
- Die Passphrase ist `[]byte` (damit sie überschreibbar ist) und darf nicht leer sein.

### Grenzen
- `ecdh.PrivateKey` lässt sich nicht überschreiben; `Keystore.Zero` löscht den Ed25519-Schlüssel und gibt den X25519-Schlüssel nur frei.
- Kein `user.rec` (Phase 2): Es braucht `user_id`, `root_pub`, die Liste der Generationszertifikate und eine Signatur der Identität; `rec.List` mit `GenerationCertSchema` als Elementschema ist dafür vorgesehen.
- Benutzereingaben für Seed-Wörter werden nicht normalisiert (SPEC-ISSUES S11).

## shamir

### API

```go
const SecretSize = 32; ShareSize = 37; ShareWords = 30
type Share struct { ID uint16; Threshold uint8; Index uint8; Y [32]byte }
func Split(secret []byte, threshold, count int, r io.Reader) ([]*Share, error)   // r: 2 Byte ID, dann 32*(threshold-1) Koeffizienten
func Combine(shares []*Share) ([]byte, error)
func (s *Share) Bytes() []byte; ShareFromBytes([]byte) (*Share, error)
func (s *Share) Words() []string; ShareFromWords([]string) (*Share, error)
func (s *Share) Zero()
var ErrParams, ErrSecretSize, ErrShare, ErrDuplicate, ErrMismatch, ErrInsufficient, ErrWordCount, ErrUnknownWord, ErrChecksum
```

### Invarianten
- `Combine` liefert bei konsistenten Anteilen das Geheimnis, bei einem falschen oder manipulierten Anteil einen falschen Wert ohne Fehler. Das rekonstruierte Geheimnis muss anders geprüft werden (Probe-Rekonstruktion in der Zeremonie, Vergleich der abgeleiteten öffentlichen Schlüssel).
- Anteile sind so geheim wie das Geheimnis. Nach Gebrauch `Zero`.
- Die Kennung erkennt vermischte Aufteilungen, die Prüfsumme Tippfehler; beides ist kein Integritätsschutz gegen Angreifer.

### Grenzen
- Nur 32-Byte-Geheimnisse. Nicht SLIP-39-kompatibel.

## envelope

### API

```go
const Magic = "GOML"; FormatVersion = 1; Suite1 Suite = 1
const ChunkSize = 65536; MaxBlocks = 800; MaxContentSize = 800*65536; MaxRecipients = 4
const MaxHeaderSize = 4096; MaxRecipientsSize = 16384; MaxTrailerSize = 1024; MaxExtraSize = 4096; MaxFileSize
const ElemBlock = 0x01; ElemLastBlock = 0x02; ElemTrailer = 0x03   // Typbytes der Elemente nach dem Empfängerteil
type Kind uint8          // KindMail=1, KindMeta, KindPending, KindWrap, KindIndex; String() liefert den Domänennamen
type RecipientType uint8 // RecipientEpochContent=1, RecipientEpochMeta, RecipientUserUnwrap, RecipientRecovery
type SignerType uint8    // SignerIngest=1, SignerUser

type Header struct { Kind Kind; MailboxID [16]byte; Epoch uint32; FileID [16]byte; NoncePrefix [7]byte; ChunkSize uint32; Created int64 }
type Recipient struct { Type RecipientType; ID [16]byte; Gen uint32; PublicKey *ecdh.PublicKey }
type Signer struct { Type SignerType; ID [16]byte; Gen uint32; Key ed25519.PrivateKey; Extra []byte }
type SealOptions struct { Rand io.Reader; Signer *Signer }     // Rand: 7 Byte Nonce-Präfix, dann 32 Byte Dateischlüssel
func Seal(hdr Header, recipients []Recipient, plaintext []byte, opts *SealOptions) ([]byte, error)
func NewWriter(w io.Writer, hdr Header, recipients []Recipient, opts *SealOptions) (*Writer, error)
func (w *Writer) Write(p []byte) (int, error); Close() error

type File struct { Suite Suite; Header Header; Recipients []RecipientEntry; Trailer *Trailer }
func Parse(data []byte) (*File, error)                        // ohne Schlüssel, strukturell vollständig; nimmt genau ElemBlock* ElemLastBlock ElemTrailer? an
func (f *File) Bytes() []byte; FileHash() [32]byte
func (f *File) VerifySignature(pub ed25519.PublicKey, extra []byte) error
func (f *File) Decrypt(key RecipientKey) ([]byte, error)      // fail closed
type RecipientKey struct { Type RecipientType; ID [16]byte; Gen uint32; PrivateKey *ecdh.PrivateKey }
type OpenOptions struct { ExpectedSuite Suite; Key RecipientKey; ResolveSigner func(SignerRef) (ed25519.PublicKey, error); AllowUnsigned bool; Extra []byte }
func Open(data []byte, opts OpenOptions) (*File, []byte, error)
func CheckSuiteTransition(prev, next Suite) error
var HeaderSchema, RecipientSchema, RecipientsSchema, TrailerSchema, SignedSchema
var ErrMagic, ErrVersion, ErrSuite, ErrTruncated, ErrTooLarge, ErrHeader, ErrHeaderSize, ErrRecipients, ErrRecipientsSize,
    ErrBlockSize, ErrEmptyBlock, ErrElementType, ErrElement, ErrTrailer, ErrTrailerSize, ErrNoRecipient, ErrUnwrap, ErrDecrypt,
    ErrSignature, ErrSigner, ErrUnsigned, ErrSignaturePolicy, ErrWrap, ErrRandom, ErrClosed
```

### Invarianten für Aufrufer
- Jede Datei bekommt einen neuen Dateischlüssel und einen neuen Nonce-Präfix (beide zieht der Schreiber). Nie eine Datei durch Verändern einer bestehenden erzeugen; immer neu versiegeln (3.3 Regel 1).
- `FileID` im Kopf muss der ID im Dateinamen entsprechen; das prüft die Ablage, nicht `envelope`. Ebenso prüft die Ablage `MailboxID` und `Epoch` gegen den Ort der Datei und die Epochenkette (2.4).
- `OpenOptions.ExpectedSuite` kommt aus der signierten `epoch.rec` der Datei-Epoche; `CheckSuiteTransition` beim Prüfen der Epochenkette aufrufen.
- Signaturpolitik: Mail-Dateien mit `AllowUnsigned`, alle anderen mit `ResolveSigner`. `envelope` koppelt `AllowUnsigned` nicht an die Dateiart, weil Abschnitt 7 für Index-Dateien keine Signatur nennt; die Ablage muss die Politik je Dateiart setzen und darf `AllowUnsigned` nie pauschal verwenden. Der Resolver setzt Abschnitt 7 um: unbekannter Schlüssel, fehlendes Zertifikat, Widerruf, kompromittierte Generation führen zu einem Fehler. `Extra` muss beim Prüfen gleich dem beim Signieren sein; Phase 3 legt für Metadaten den Datensatz fest (Postfach-ID, Epoche, Mail-ID, Empfangszeit, Ingest-Generation, Hashes der Mail- und Metadaten-Datei, Versionszähler).
- Eine Mail-Datei (unsigniert) schützt ihren Empfängerteil nicht gegen Änderungen an fremden Einträgen. Der Client prüft deshalb den SHA-256 der Mail-Datei aus den signierten Metadaten. `FileHash` liefert den Hash aller Bytes vor dem Trailer-Element; bei einer unsignierten Datei ist das die ganze Datei.
- Dateiaufbau nach dem Empfängerteil (Version 1.1): Elemente `Typbyte || uint32 Länge || Inhalt`, genau in der Folge `0x01* 0x02 0x03?`. Eine unsignierte Datei endet mit dem `0x02`-Element. Das Typbyte eines Blocks muss zum Letzter-Block-Flag im Nonce passen; sonst scheitert die Authentifizierung.
- `RecipientRecovery` (Typ 4) gehört nach 2.4 nur in `epochs/<n>/members/recovery.wrap`, nie in Mail- oder Metadatendateien. `envelope` nimmt Typ 4 in jeder Datei an (3.1); die Ablage setzt die Regel aus 2.4 beim Schreiben und Lesen durch. Dateien sind unveränderlich: der Empfängerteil wird nie nachträglich ergänzt.
- `SealOptions.Rand` und der Reader von `Keystore.Seal` sind für Testvektoren gedacht. Im Betrieb immer `nil` übergeben (crypto/rand); ein fester Reader würde Nonce-Präfix und Dateischlüssel wiederverwenden.
- `Parse` braucht die ganze Datei; Dateien sind auf `MaxFileSize` begrenzt. Für Dateien aus dem Dateisystem die Größe vor dem Lesen prüfen.
- Streaming beim Schreiben: `NewWriter` schreibt sofort Präambel, Kopf und Empfängerteil; erst `Close` macht die Datei gültig. Bei Abbruch die Datei verwerfen (passt zum `spool/`-Verfahren in 5.2).
- Der Schreiber überschreibt `Header.NoncePrefix` und `Header.ChunkSize`.

### Grenzen
- Kein streamendes Lesen in Phase 0.1: `Parse` braucht die ganze Datei, obwohl der Elementrahmen seit Version 1.1 streamendes Parsen erlauben würde. Entschlüsselung puffert den gesamten Klartext (bis 50 MiB).
- Nur Suite 1. Suite 2 braucht andere Feldgrößen im Empfängerteil; vier Einträge passen in `MaxRecipientsSize` (S12).
- HPKE-Kapselungen sind nicht reproduzierbar; deterministische Vektoren decken Präambel, Kopf und Blöcke ab.

## store

### API

```go
type ID [16]byte                       // zufällig, Text: base32 klein, 26 Zeichen
func NewID(r io.Reader) (ID, error); ParseID(s string) (ID, error); (ID) String(); IsZero()

// Dateioperationen: atomar, mit fsync von Datei und Verzeichnis
func WriteFileAtomic(path string, data []byte) error   // ersetzt
func CreateFileAtomic(path string, data []byte) error  // nur wenn nicht vorhanden (ErrExists)
func RenameDurable(src, dst string) error; RemoveDurable(path string) error; MkdirAll(dir string) error; SyncDir(dir string) error
func ReadFileLimited(path string, max int64) ([]byte, error)   // Größe vor dem Lesen geprüft
func RemoveTemp(dir string) error

type Store struct{ Root string }
func Init(root string) (*Store, error); Open(root string) (*Store, error)
// Pfade nach Abschnitt 4: UserFile, InviteFile, AddressesFile, MailboxDir/File, FoldersFile, NoteFile,
// EpochDir/File, WrapFile, MailDir, MailFile, MetaFile, PendingDir/File, SpoolDir, WorkDir; Rel/Abs für Journale
func (s *Store) CreateUser(*User) error; ReadUser(ID) (*User, []byte, error)
func (s *Store) CreateInvite(nowMillis int64) (ID, error); ConsumeInvite(ID) error
func NormalizeAddress(string) (string, error); (s) LoadAddresses() (Addresses, error); AddAddress(addr string, mbx ID) (string, error)
func (s *Store) WritePlatformFile(name string, data []byte) error; ReadPlatformFile(name) ([]byte, error)
func (s *Store) ReadPlatformCert(role keys.Role, gen uint32) (*keys.PlatformCert, error)   // prüft .pub gegen .cert, nicht die Signatur
func (s *Store) LockMailbox(ID) (func(), error); LockMailboxes([]ID) (func(), error)
func (s *Store) WriteMailbox(*Mailbox) error; ReadMailbox(ID) (*Mailbox, error)
func (s *Store) WriteEpoch(*Epoch) ([]byte, error); ReadEpoch(ID, n) (*Epoch, []byte, error); ListEpochs(ID)
func (s *Store) WriteWrap(mbx, n, user, data); ReadWrap(mbx, n, user)
func (s *Store) ListFolders, ListMails, ListPending, ListPendingEpochs; ReadMail, ReadMeta, ReadPending, ReadFolders, WriteFolders
func (s *Store) ReadNote(ID) (*EpochNote, error); WriteNote(*EpochNote) error; RemoveNote(ID) error

// Datensätze (Typ-Strings gomail/v1/rec/...): user, mailbox, epoch (+ epoch-member), epoch-keys,
// mail-meta (+ rcpt), meta-signed, pending (+ pending-entry, term), epoch-note, journal (+ move),
// address, platform-key, platform-pin, mailbox-name, folders (+ folder)
type User struct{ ID; RootPub; Generations []*keys.GenerationCert }      // DecodeUser prüft die Kette
type Mailbox struct{ ID; Epoch uint32 /* Kopf */; Inbox ID; Name []byte /* versiegelt */ }
type Epoch struct{ MailboxID; Number; Begin; Reason; Suite; ContentPub, MetaPub; Members []Member; PrevHash; SignerID; SignerGen; Signature }
func (e *Epoch) Sign(identity) error; VerifySignature(pub) error; Member(ID) (Member, bool)
func EpochHash(data []byte) [32]byte; CheckLink(prev *Epoch, prevData []byte, next *Epoch) error
type EpochKeys struct{ MailboxID; Epoch; Content, Meta *ecdh.PrivateKey; Index [32]byte }; (k) Matches(*Epoch) bool; Zero()
type MailMeta struct{ Version; MailID; Received; MailHash; Size; Folder; Flags; EnvelopeFrom; Recipients; From, To, Cc, Subject, Date, MessageID; Attachment; HeadersParsed }
func (m *MailMeta) SignedExtra(mbx ID, epoch uint32) ([]byte, error)
type Pending struct{ MailboxID; Epoch; Entries []PendingEntry{ MailID; Unprocessed bool; Terms []string } }
type AddressAssignment struct{ Address; MailboxID; ValidFrom; AdminGen; Signature }; Sign/Verify
func CleanText(s string, max int) string        // speicherbar nach 3.6 Regel 3
var ErrRecord, ErrChain, ErrExists, ErrNotFound, ErrTooLarge, ErrID, ErrInvite, ErrAddress
```

### Invarianten
- Alles im Datenverzeichnis wird über `store` geschrieben: atomar, mit `fsync`; nie eine Datei an Ort und Stelle verändern. `epoch.rec`, Plattformdateien und `user.rec` werden nur exklusiv angelegt, nie ersetzt.
- Jede Datei wird mit `ReadFileLimited` gelesen; die Grenzen stehen in `store.go` (DECISIONS D48).
- Lesefunktionen prüfen Ort gegen Inhalt (`user.rec` gegen das Verzeichnis, `epoch.rec` gegen Postfach und Nummer, Notizen gegen das Postfach), nicht Signaturen. Signaturen und die Kette prüft der Aufrufer.
- Sperren: Commit einer Annahme, Schreiben einer Begriffsliste, Anlegen von Epochen und `mailbox.rec` halten die Sperre des Postfachs; mehrere Postfächer nur über `LockMailboxes`.
- Dekodierte Datensätze sind kanonisch: optionale Felder stehen nur, wenn sie einen Wert tragen; leere optionale Zeichenketten oder Kennzeichen mit dem Wert 0 werden abgelehnt.

## translog

```go
type Log interface {
    Verified() bool
    AppendUser(user store.ID, userRec []byte) error
    AppendEpoch(mailbox store.ID, number uint32, epochRec []byte) error
    AppendAddress(addressRec []byte) error
    AppendPlatform(name string, data []byte) error
    CheckUser(user store.ID, userRec []byte) error
    CheckGeneration(user store.ID, gen uint32) error
    CheckRevokedSignature(user store.ID, gen uint32, signed []byte) error
    CheckEpoch(mailbox store.ID, number uint32, epochRec []byte) error
    CheckAddress(address string, mailbox store.ID, at int64) error
    CheckPlatform(name string, data []byte) error
    CheckFresh(now time.Time) error
}
type Unverified struct{}                      // nimmt alles an
func NewUnverified(insecureNoLog bool) (*Unverified, error)   // ErrNoLog ohne den Schalter
const Warning                                  // gibt der Client bei jedem Start aus
```

- Jede Stelle, die das Log braucht, ruft diese Schnittstelle auf und bricht bei einem Fehler ab (getestet mit einem Log, das einzelne Prüfungen verweigert: `client/log_test.go`). Phase 3 ersetzt nur die Umsetzung.
- Ein Client lehnt eine Entwicklungsidentität ab, sobald `Verified()` wahr ist.

### Alle `TODO(phase3-translog)`

| Stelle | Prüfung oder Eintrag | Spezifikation |
|---|---|---|
| `client/client.go`, `Open` | `CheckFresh`: Baumkopf mit Zeugensignatur höchstens 24 Stunden alt | 2.3, 2.7 |
| `client/client.go`, `Open` | `CheckUser`: eigene `user.rec` im Log | 2.7 |
| `client/mailbox.go`, `userKey` | `CheckUser`: `user.rec` des Unterzeichners im Log | 2.7 |
| `client/mailbox.go`, `userKey` | `CheckGeneration`: Generation erst ab ihrem Logeintrag gültig | 2.2 Punkt 3 |
| `client/mailbox.go`, `userKey` | `CheckRevokedSignature`: Signatur einer widerrufenen Generation vor dem Widerruf geloggt | 2.2 Punkt 4, S13 |
| `client/mailbox.go`, `checkEpoch` | `CheckEpoch`: `epoch.rec` im Log | 2.7 |
| `client/mailbox.go`, `createEpoch` | `AppendEpoch` | 2.7 |
| `client/read.go`, `ingestKeyFor` | `CheckPlatform`: Zertifikat im Log, Generation nicht als kompromittiert markiert | 2.3, 7 |
| `client/read.go`, `checkMeta` | `CheckAddress`: Adresse zur Empfangszeit diesem Postfach zugeordnet | 2.3 |
| `client/keygen.go`, `Register` | `AppendUser`: die Generation gilt erst ab dem Eintrag | 2.2 Punkt 3 |
| `cmd/gomail-server`, `address add` | `AppendAddress`: signierte Zuordnung | 2.3 |
| `ceremony/ceremony.go`, `InitDev` | `AppendPlatform`: Zertifikate | 2.7 |
| `store/records.go`, `UserSchema` | Bindung von Benutzer-ID und Root nur über das Log (S16) | 2.2, 2.7 |
| `translog/translog.go` | alle elf Methoden von `Unverified` | 2.7 |

Noch ohne Aufrufstelle, weil die Funktion erst später kommt: Vermerke der Clients (`checkpoints/`), Nachfolgen der Plattformidentität (`identity-<gen>.succ`), Widerruf kompromittierter Plattformgenerationen.

## smtpd

```go
type Backend interface { Accepting() error; Recipient(address string) error; Begin(Session, from string, rcpts []string) (Delivery, error) }
type Delivery interface { Write([]byte) (int, error); Commit() error; Abort() }
type Session struct{ ID, Helo, RemoteIP string }
type Config struct{ Hostname; MaxSize; MaxRecipients; CommandTimeout; DataTimeout; MaxConns; MaxConnsPerIP; MinRate; RateWindow; MaxMailsPerIP; RateMemory; Now; Logger }
func NewServer(Config, Backend) *Server; (s) Serve(net.Listener) error; Close() error
var ErrUnknownRecipient /*550*/, ErrDiskFull /*452*/, ErrTemporary /*451*/, ErrClosed
```

- `250` nach `DATA` erst, wenn `Commit` ohne Fehler zurückkam. Bei jedem Abbruch ruft die Sitzung `Abort`.
- Der Server schreibt den `Received`-Header als erstes in die Zustellung; Inhalte, Header und Adressen loggt er nie (nur Sitzungs-ID, Größen, Statuscodes).
- Grenzen und Antworten: DECISIONS D54. Zeitlimits und die Mindestrate laufen über `Config.Now` und Lese-Deadlines.

## ingest

```go
type Config struct{ Store; Log; IngestKey; IngestGen; Now; Logger; MinFree; DiskSpace; QueueMemory; WorkLimit; BatchSize; BatchAge }
func New(Config) (*Ingest, error)            // prüft den Schlüssel gegen ingest-<gen>.cert
func (in *Ingest) Recover() error            // vor dem Start: Rollback offener Transaktionen, spool/ und work/ leeren
func (in *Ingest) Start(); Flush() error; Close() error
func (in *Ingest) Accepting() error; Recipient(string) error; Begin(...)   // smtpd.Backend
func Terms(header []byte, received time.Time) ([]string, bool)          // 5.4
```

### Invarianten
- Ablauf je Mail: Epochenwahl bei `DATA` (D50), Verschlüsselung je Postfach nach `spool/<txn>/<postfach>/mail.gml`, danach `meta.gml` und `marker.gml`, Journal, Umbenennungen, Löschen des Journals (Commit, D52). Kein Klartext auf der Platte; die Warteschlange lagert nur verschlüsselt aus.
- `Recover` muss vor dem ersten `Begin` laufen. Ein Journal, das sich nicht dekodieren lässt oder Pfade außerhalb des Datenverzeichnisses nennt, stoppt den Start.
- Absturzpunkte für Tests: Paketvariable `crashHook`, nur in Tests gesetzt.
- Der Server prüft die Signatur der gewählten `epoch.rec` gegen `user.rec` des Unterzeichners, aber nicht die ganze Kette und nicht das Log; das ist Aufgabe des Clients.

## client

```go
type Config struct{ Store; Dir; Pin *store.PlatformPin; Log; Now; Warn func(string) }
func Keygen(Config, passphrase []byte, Prompter) (store.ID, error)
func Register(Config, code store.ID) (store.ID, error)
func Open(Config, passphrase []byte) (*Client, error)
func (c *Client) CreateMailbox(name string) (store.ID, error)
func (c *Client) Sync() error
func (c *Client) List(mbx, folder store.ID) ([]*Mail, error)   // folder 0 = Posteingang
func (c *Client) Read(mbx, id store.ID) (*Mail, []byte, error)
func (c *Client) OpenPending(mbx, epoch, file) (*store.Pending, error)
func (c *Client) MailboxName(store.ID) (string, error); Folders(store.ID) ([]store.Folder, error); Mailboxes() []store.ID; UserID(); Close()
func Inspect(data []byte) ([]byte, error)
const SupplyMonths = 3; ImmediateDelay = 5 * time.Minute; InboxName = "INBOX"
var ErrNotRegistered, ErrRegistered, ErrConfirm, ErrDevIdentity, ErrPlatform, ErrUserRecord, ErrRollback, ErrEpoch,
    ErrStaleEpoch, ErrReplay, ErrMailHash, ErrMismatch, ErrSigner, ErrWrap, ErrNotFound
```

### Prüfungen beim Lesen (Reihenfolge)
1. Epochenkette ab 1: jede `epoch.rec` am richtigen Ort, verknüpft (`CheckLink`), signiert von einem Mitglied der Vorgängerin, im Log; Kopf aus `mailbox.rec` nicht unter dem gemerkten, gemerkte Epoche unverändert (D57). Bei einem Bruch gilt nur der Teil davor; jede Abweichung erzeugt eine Warnung.
2. Verpackung: signiert von einem Mitglied der Epoche (aktuelle Generation, S13), Kopf passend, Schlüssel gleich den öffentlichen Schlüsseln der `epoch.rec` (D61).
3. Metadaten: Art, Postfach, `file_id`, Epoche in der Kette, Suite, Signatur durch einen Ingest-Schlüssel mit Zertifikat der hinterlegten Identität, Felder aus Abschnitt 7 signiert, `received = created`, Zertifikat zur Empfangszeit gültig, Epochenregel (D50), Adresse über das Log, Version nicht kleiner als gesehen (D51).
4. Mail (nur `Read`): SHA-256 der ganzen Datei gleich den Metadaten, dann Kopf (Art, Postfach, Epoche, `file_id`, ohne Trailer), dann Entschlüsselung mit Freigabe erst nach dem letzten Block.

### Invarianten
- `List` zeigt nur Mails, die alle Prüfungen bestanden haben, und warnt für jede andere; `Read` gibt bei jedem Fehler nichts heraus.
- Der Client schreibt ins Datenverzeichnis nur Epochen, Verpackungen, `folders.gml`, `mailbox.rec` und `user.rec`; alles mit privatem Inhalt ist verschlüsselt.
- Der lokale Zustand (`state.json`) ist Teil der Sicherheit (Schutz gegen Zurückspielen). Geht er verloren, beginnt der Client wieder bei Vertrauen beim ersten Kontakt (2.7, neues Gerät).

## ceremony und Programme

- `ceremony.InitDev(data, keys, now, log)`, `ReadKey(path, role)`, `ReadPin(path)`; Dateien und Regeln in DECISIONS D58.
- `gomail-server serve` liest den Ingest-Schlüssel aus einer Datei außerhalb des Datenverzeichnisses, lauscht nur auf Loopback (sonst `--isolated-test-network`), ruft `Recover`, startet die Vorverarbeitung und beendet sich sauber bei SIGINT/SIGTERM (offene Begriffslisten werden geschrieben).
- `gomailctl` liest die Passphrase aus `GOMAILCTL_PASSPHRASE`, `--passphrase-file` oder einer Zeile von stdin (sichtbar, siehe Grenzen).
- Ohne `--insecure-no-log` starten `serve`, `address add`, `gomailctl` und die Zeremonie nicht.

## Datenverzeichnis in Phase 1

```
data/
  platform/identity-1.pub, admin-1.pub, admin-1.cert, ingest-1.pub, ingest-1.cert
  users/<user-id>/user.rec
  invites/<code>.json
  addresses.json, addresses.lock
  mailboxes/<postfach-id>/
    mailbox.rec, folders.gml, lock, epoch-fallback.rec (nur nach einem Rückfall)
    epochs/<n>/epoch.rec, content.pub, meta.pub, members/<user-id>.wrap
    mail/<ordner-id>/<mail-id>.gml, <mail-id>.meta.gml
    pending/<n>/<mail-id>.gml (Marker), <batch-id>.gml (Begriffslisten)
  spool/<txn-id>/<postfach-id>/{mail,meta,marker}.gml, journal.rec   (nur während einer Annahme)
  work/<zufall>.bin                                                   (verschlüsselt, nur bei Last)
```

Nicht angelegt werden in Phase 1: `log/`, `checkpoints/`, `index/`, `platform/identity-<gen>.succ`, `platform/witnesses.rec`.

## Bekannte Grenzen
- Kein Transparenzlog, keine Zeugen: siehe die Tabelle oben. Alles, was laut 2.7 erst das Log garantiert (Aufspalten von Sichten, stilles Umleiten von Adressen, zurückgehaltene Widerrufe, Bindung von Benutzer-ID und Root), ist in Phase 1 nicht geschützt.
- Nur ein Mitglied je Postfach; die Formate (Mitgliederliste, Verpackung je Benutzer) tragen mehrere.
- Keine Benutzersignaturen auf Metadaten (Flags); der Client lehnt sie ab. Kein Indexieren von `pending/` (Phase 5), nur `OpenPending`.
- Nur die hinterlegte Generation der Plattformidentität; Nachfolgen und kompromittierte Generationen sind nicht umgesetzt.
- Server und Client prüfen die Ingest-Signatur der Metadaten nur mit Schlüssel (S22).
- `flock` ist über NFS oder SSHFS (Abnahme mit getrennten Maschinen, 9.1) nicht verlässlich; dort schreiben Server und Client nicht dieselben Dateien gleichzeitig, aber `epoch-fallback.rec` und `mailbox.rec` brauchen dann einen anderen Schutz.
- Uhren: Epochenwahl und Prüfung hängen an den Uhren von Server und Client; der Vorlauf von fünf Minuten deckt nur mäßige Abweichungen (S19).
- Die Passphrase wird auf dem Terminal sichtbar eingegeben, weil `x/term` nicht zugelassen ist; die Datei oder die Umgebungsvariable verwenden.
- Mails, die der Server nach dem Commit, aber vor `250` verliert, stellt der Absender doppelt zu.
- `ecdh.PrivateKey` (Epochenschlüssel im Speicher des Clients) lässt sich nicht überschreiben (DECISIONS D04).
- Die Mindestrate wird in festen 60-Sekunden-Fenstern gemessen; ein Absender, der in jedem Fenster knapp 60 KB schickt, darf `DATA` bis zum Zeitlimit von 10 Minuten ausdehnen.
- Mehrere Empfängerpostfächer vervielfachen den Spool: eine Mail von 25 MB an 100 Postfächer schreibt 2,5 GB und hält 100 Dateien offen; bei 20 Verbindungen im schlimmsten Fall rund 50 GB. Die Prüfung auf 10 % freien Platz greift nur bei `MAIL FROM` und `DATA`, danach erst ENOSPC (`452`). Eine Obergrenze für den Spool insgesamt fehlt.
- Bleibt das Rückgängigmachen nach einem Fehler beim Verschieben selbst hängen (Dateisystemfehler), liegen Teile einer Mail bis zum nächsten Serverstart im Postfach; `Recover` räumt sie dann auf.
- Der Server vertraut beim Prüfen der Epochenkette Epoche 1 beim ersten Kontakt; ein Benutzer mit Schreibzugriff könnte ein neues Postfach mit eigener Epoche 1 an eine fremde Adresse hängen, wenn er auch `addresses.json` ändern kann. Dagegen schützt erst das Log (Adresszuordnungen und Epochen sind dort eingetragen).
- Dateirechte 0600/0700: Server und Client müssen in der Entwicklung als derselbe Betriebssystembenutzer laufen oder gemeinsame Gruppenrechte bekommen (9.1 verlangt für die Abnahme getrennte Maschinen).

## Testabdeckung

`go test -cover` (Phase 1):

| Paket | Abdeckung | Mindestwert |
|---|---|---|
| `store` | 90,2 % | 85 % |
| `ingest` | 88,9 % | 85 % |
| `client` | 87,5 % | 85 % |
| `smtpd` | 91,9 % | – |
| `translog` | 100 % | – |
| `ceremony` | 79,1 % | – |
| `rec`, `shamir`, `envelope`, `keys` | 99,6 %, 100 %, 93,5 %, 88,5 % | – |

Die nicht abgedeckten Zeilen in `store`, `ingest` und `client` fallen in vier Gruppen; keine gibt Daten heraus, alle brechen ab und reichen den Fehler weiter:

| Gruppe | Beispiele | Begründung |
|---|---|---|
| Fehler des Dateisystems | `store/fs.go` (`MkdirAll`, `writeTemp`, `WriteFileAtomic`, `RenameDurable`, `ReadFileLimited` nach `Stat`), `store/store.go` (Anlegen von Verzeichnissen in `WriteEpoch`, `WriteWrap`, `WriteMailbox`, `CreateUser`), `ingest/delivery.go` (`Mkdir`, `OpenFile`, `Sync`, `Close`, Schreiben von Metadaten und Marker, Journal, Löschen des Journals), `ingest/ingest.go` (`Recover`: `RemoveAll`, `SyncDir`), `ingest/queue.go` (Schreiben der Begriffsliste, Löschen der Marker), `client` (Schreiben von Verpackung, Ordnern, `mailbox.rec`, `state.json`) | Treten nur bei Ein-/Ausgabefehlern, vollem Datenträger oder fehlenden Rechten auf. Stellvertretend getestet sind: ENOSPC als `452` (`TestDiskSpaceAndErrors`), Fehler beim Verschieben mit Rücknahme (`TestMoveFailureIsUndone`), fehlende Verzeichnisse und Dateien in allen Lesepfaden, Absturz an jedem Schritt (`TestCrashDuringReceipt`). |
| Fehler von `crypto/rand` | `store.NewID`, `tempFile`, Nonces und Schlüssel in `ingest/queue.go`, Epochenschlüssel in `client/mailbox.go` | `crypto/rand` schlägt auf unterstützten Systemen nicht fehl; der Fehler wird trotzdem weitergegeben. |
| Kodierfehler geprüfter Strukturen | `rec.Encode` in `User.Encode`, `Epoch.Sign`, `AddressAssignment.Sign`, `sealPending`, `writeMeta`, `createEpoch` | Die Werte sind vorher geprüft (feste Längen, bereinigte Zeichenketten); `rec.Encode` kann dann nicht fehlschlagen. |
| Nicht erreichbare Prüfungen | `ecdh.X25519().NewPublicKey/NewPrivateKey` in `DecodeEpoch`, `DecodeEpochKeys` (32 Byte werden immer angenommen); `ParseID` nach erfolgreicher Zeichenprüfung; Kürzung in `CleanText`, wenn `cut > len(s)`; `hpke`-Fehlerpfade in `envelope`; Rückfall auf `time.Now` und `statfs` in `ingest.New` (Tests setzen beides) | Absicherungen gegen spätere Änderungen; die Bedingungen sind durch vorherige Prüfungen ausgeschlossen. |

Die Programme unter `cmd/` haben keinen Mindestwert; ihr Ablauf ist zusätzlich durch `TestRunbook` (gebaute Programme, alle Schritte des RUNBOOK) abgedeckt, der nicht in die Abdeckung der Pakete eingeht.

### Nicht abgedeckte Zeilen der Pakete aus Phase 0 (Stand Phase 0.1)

Die Zeilennummern in `envelope/envelope.go` sind seit Phase 1 um eins verschoben (ein Import mehr).

`go test -cover` (Phase 0.1): `rec` 99,6 %, `shamir` 100 %, `envelope` 93,5 %, `keys` 88,3 % (für `keys` ist kein Mindestwert gefordert). Nicht abgedeckte Zeilen in den drei Paketen mit Mindestanforderung:

| Datei | Zeilen | Code | Begründung |
|---|---|---|---|
| rec/rec.go | 439-441 | `checkValue` in `Encode` für Listen schlägt fehl | Elemente werden bereits in `SetList` geprüft und die Slice kopiert; der zweite Aufruf ist eine Absicherung gegen spätere Änderung der Element-Records, die kein Test erzwingen kann, ohne die Prüfung in `SetList` zu umgehen. |
| envelope/envelope.go | 214-216, 278-280, 341-343 | `Encode`-Fehler in `Header.encode`, `encodeRecipients`, `Trailer.encode` | Die Werte stammen aus validierten Strukturen mit festen Größen; `rec.Encode` kann dann nicht fehlschlagen. Die Zweige geben den Fehler nur weiter (fail closed). |
| envelope/open.go | 71-73 | `hpke.NewDHKEMPrivateKey` schlägt fehl | Die Kurve wird vorher geprüft (`Curve() == ecdh.X25519()`); die Funktion schlägt nur bei anderen Kurven fehl. |
| envelope/open.go | 83-85 | entpackter Dateischlüssel hat nicht 32 Byte | `wrapped_key` hat per Schema 48 Byte, AES-GCM liefert daraus immer 32 Byte; Absicherung. |
| envelope/open.go | 90-92 | `contentAEAD` schlägt fehl | Siehe seal.go 221-232. |
| envelope/parse.go | 145-147 | mehr als 800 Blöcke | Durch `MaxFileSize` (am Anfang von `Parse`) ist ein 801. Block nicht erreichbar, weil Kopf, Empfängerteil und Trailer höchstens etwa 21,5 KiB Spielraum lassen, ein Blockelement aber 65.557 Byte braucht; die Prüfung bleibt als eigenständige Garantie. `TestParseTooManyBlocksAndTooLarge` prüft, dass 801 Blöcke abgelehnt werden (über die Dateigröße). |
| envelope/parse.go | 189-191, 193-195, 214-216 | `Encode`-Fehler in `Bytes` | `Bytes` wird nur auf Dateien aufgerufen, die `Parse` angenommen hat; deren Strukturen kodieren immer. |
| envelope/seal.go | 78-83 | `Write`/`Close` in `Seal` schlagen fehl | `Seal` schreibt in einen `bytes.Buffer` (schlägt nie fehl) und prüft die Größe vorher; die Fehlerpfade sind für den `Writer` getestet (`TestWriterOutputErrors`). |
| envelope/seal.go | 158-160 | `hdr.encode` schlägt fehl | Validierte Kopffelder mit festen Größen. |
| envelope/seal.go | 168-170, 177-179 | `hpke.NewDHKEMPublicKey`, `sender.Seal` schlagen fehl | Kurve vorher geprüft; `Seal` schlägt im Base-Modus mit gültigem Kontext nicht fehl. `NewSender` (Punkt kleiner Ordnung) ist getestet. |
| envelope/seal.go | 183-188 | `encodeRecipients` schlägt fehl; Empfängerteil über 16 KiB | Validierte Einträge; vier Einträge der Suite 1 belegen etwa 0,6 KiB. Die Grenze wird relevant für Suite 2 (S12). |
| envelope/seal.go | 192-194, 221-232 | `contentAEAD`: HKDF, `aes.NewCipher`, `cipher.NewGCM` schlagen fehl | Feste Schlüssellänge 32 und feste Parameter; diese Funktionen schlagen nur bei falschen Längen fehl. |
| envelope/seal.go | 238-240 | `emit` bei gesetztem `w.err` | `Write` und `Close` prüfen `w.err` vor dem Aufruf; Absicherung gegen neue Aufrufer. |
| envelope/seal.go | 290-293 | 801. Block im Schreiber | Die Größenprüfung in `Write` (`MaxContentSize`) macht einen 801. Block unerreichbar; die Prüfung bleibt als eigenständige Garantie. `TestWriterLimits` prüft die Grenze über die Größe. |
| envelope/seal.go | 346-360 | `signedStructure`, `keys.Sign`, `Trailer.encode` schlagen in `Close` fehl | Der Signer wird in `NewWriter` validiert (Typ, Generation, Schlüssellänge, `Extra` bis 4 KiB); danach können diese Aufrufe nicht fehlschlagen. |

Alle nicht abgedeckten Zeilen sind Fehlerzweige, die Fehler nur weiterreichen oder Grenzen ein zweites Mal prüfen. Keiner gibt Daten heraus.

## Unabhängige Prüfung in Phase 1

Zwei Subagenten prüften ohne Kenntnis von DECISIONS, HANDOFF, SPEC-ISSUES und der Commit-Historie.

**Spezifikation** (`store`, `ingest`, `client` gegen 2.4, 4, 5, 7). Behoben:
- A1: Fehlte die Epoche n+1 (entfernt oder ersetzt, `mailbox.rec` zurückgesetzt), prüfte der Client die Epochenregel für Mails der Epoche n nicht; eine nach Beginn von n+1 für n verschlüsselte Mail wurde geöffnet. Jetzt merkt sich der Client die Beginnzeiten und lehnt ab, wenn die Regel nicht entscheidbar ist (`TestStaleEpochWithNextEpochRemoved`, `TestBrokenChainWithoutMemory`).
- A2: Ein Absturz zwischen dem Anlegen neuer Epochen und dem Schreiben von `mailbox.rec` blockierte das Postfach dauerhaft und überschrieb dabei die Verpackung einer bestehenden Epoche. Jetzt übernimmt der Client gültige Epochen jenseits des Kopfs, räumt abgebrochene Epochenverzeichnisse auf und ersetzt nie eine vorhandene `epoch.rec` (`TestSupplyCrashRecovers`).
- B1: Der Server verschlüsselte für jede `epoch.rec` mit gültiger Benutzersignatur, auch von einem registrierten Nichtmitglied. Jetzt prüft er die Kette wie der Client und fragt das Log (`TestServerRejectsForeignEpoch`).
- B2: Eine monatliche Epoche, Sekunden vor Monatsbeginn angelegt, konnte eine korrekt angenommene Mail zur "veralteten" machen. Jetzt beginnt keine Epoche früher als fünf Minuten nach dem Anlegen (`TestSupplyAtMonthEnd`).
- B3: Schlug `mlock` fehl, wurde trotzdem nach `work/` ausgelagert. Jetzt nicht mehr (`TestNoSpillWithoutMlock`). Der erweiterte AES-Schlüssel im Speicher bleibt eine Grenze.
- B5: Begriffslisten wurden nicht gegen `valid_from` des Zertifikats geprüft und Ablehnungen nicht immer gemeldet (`TestPendingBeforeCertificate`).
- C3, C4, C8, C12: Begriffe aus dem Umschlag (Bcc), Aufräumen von `.tmp-*` beim Start, Sperre des Client-Verzeichnisses, offene Begriffslisten gegen die Speichergrenze.

Zur Kenntnis genommen: B4 (bleibt ein Rückgängigmachen hängen, liegen Teile bis zum nächsten Start im Postfach; nur bei Dateisystemfehlern), C1 und C2 (Auslegungen, S16 und D56), C5 (Leser können während der Umbenennungen kurz einen Marker oder Metadaten ohne Mail sehen; der Client listet nur Mails mit Datei), C6 (Doppelzustellung nach Commit ohne `250`), C7 (Generation des Unterzeichners wird nicht mit der Mitgliederliste abgeglichen, wichtig erst mit Generationswechseln in Phase 2), C9 (Dateirechte 0600/0700 passen nicht zu getrennten Betriebssystembenutzern mit gemeinsamem Verzeichnis), C10 (Abweichungen im Verzeichnisaufbau, S21), C11 (der Server kann das Ingest-Zertifikat mangels Plattformidentität nur gegen seinen Schlüssel abgleichen).

**Angreifer** (nur Datenverzeichnis nach dem Ende-zu-Ende-Lauf und Quellcode; Schreibzugriff auf das Datenverzeichnis ohne Schlüssel, entfernter SMTP-Client). Kein Klartext gefunden (sichtbar nur die Empfängeradresse in `addresses.json`, wie in Abschnitt 4 vorgesehen); kein Austausch einer Mail oder ihrer Metadaten, kein Unterschieben einer Epoche, kein Zurückspielen blieb unbemerkt; kein Absturz über SMTP. Behoben:
- B: Der unsignierte Zeiger auf den Posteingang in `mailbox.rec` ließ sich umbiegen, `list` zeigte dann ohne Warnung nichts. Jetzt kommt der Posteingang aus der signierten `folders.gml`, und der Client warnt bei Abweichung und bei unbekannten Ordnern (`TestInboxPointerRedirected`).
- C: Der Arbeiter der Vorverarbeitung hatte keinen Schutz gegen Panics; jetzt abgefangen. Antworten auf abgewiesene Verbindungen liefen in unbegrenzt vielen Goroutinen; jetzt höchstens 16, `Close` wartet auf sie (`TestRefusalsAreBounded`).
Zur Kenntnis genommen: Eine Mail mit 25 MB an 100 Postfächer schreibt 2,5 GB in den Spool und versiegelt 100-mal (begrenzt durch die Konstanten und den freien Platz, siehe Grenzen). Nur wegen des fehlenden Logs möglich (nicht als Fund gezählt): Zurückspielen gegenüber einem Client ohne Vorgeschichte, Umleiten von Adressen, widerrufene Generationen, unbemerktes Löschen von Mails.

### Unabhängige Prüfung in Phase 0.1 (Verlauf)

Ein Subagent ohne Kenntnis von DECISIONS, SPEC-ISSUES und HANDOFF prüfte `envelope` und `rec` gegen 3.1 bis 3.6 der Version 1.1 und fand keine Abweichung von der Spezifikation. Behoben (Commit 3b8cb50): Der Schreiber überschrieb seinen Klartextpuffer nur im Erfolgsfall; `Kind.String` lieferte für unbekannte Dateiarten einen Kunstnamen, den `keys.Sign` als Domäne angenommen hätte. Zur Kenntnis genommen, nicht geändert: `SealOptions.Rand` erlaubt Aufrufern die Wiederverwendung von Zufall (siehe Invarianten); `Decrypt` leitet das Flag aus der Position in der Blockliste ab, die `Parse` als `0x01* 0x02` garantiert; `Parse` kopiert die ganze Datei (bis 50 MiB) und hält sie für `FileHash`.

## Fuzzing

Fuzz-Ziele aus Phase 0: `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`. Neu in Phase 1:

- `store.FuzzDecodeRecords`: alle Datensätze von `store` (Benutzer, Postfach, Epoche, Epochenschlüssel, Metadaten, Begriffslisten, Vermerk, Journal, Plattformschlüssel und -identität, Adresszuordnung, Name, Ordner); angenommen wird nur, was byte-identisch zurückkodiert.
- `smtpd.FuzzCommands`: beliebige Eingaben auf Befehlsebene; jede Antwortzeile wohlgeformt, nichts über der Größengrenze zugestellt.
- `smtpd.FuzzData`: beliebige Daten nach `DATA`; zugestellt wird genau das Ergebnis einer Referenz für Dot-Unstuffing, ungültige Eingaben nie.
- `ingest.FuzzTerms`: beliebige Header; alle Begriffe und Metadatenfelder speicherbar (UTF-8, NFC, ohne Nullbyte, innerhalb der Grenzen), keine doppelten Begriffe.

Ergebnis Phase 1: FUZZ_RESULTS

## Was Phase 2 als Erstes wissen muss

1. **S11 und S13 entscheiden lassen, bevor `device lost`, Wiederherstellung und Teilen gebaut werden.** Beide Stellen sind heute die strengste Lesart (`TODO(S11)` in `client/keygen.go` und `cmd/gomailctl`, `TODO(S13)` in `client/mailbox.go`, `userKey`). Nach dem Vorschlag zu S13 muss `device lost` alles neu ausstellen, was die alte Generation außerhalb des Logs signiert hat (Verpackungen für andere Mitglieder, Name, `folders.gml`, geänderte Metadaten).
2. **Mehrere Mitglieder:** Die Mitgliederliste der Epoche und die Verpackungen je Benutzer tragen sie schon. Zu bauen sind das Verpacken für andere (Empfänger `user-unwrap` mit ihrer aktuellen Generation, signiert vom Verpackenden), die Prüfung "Unterzeichner ist Mitglied der Vorgängerin" mit Generationsabgleich (Prüfung C7), `revoke` mit sofortiger Epoche und `share` mit Auswahl der Epochen. `createEpoch` in `client/mailbox.go` schreibt heute nur die eigene Verpackung.
3. **Name und Ordnerliste hängen an Epoche 1** (S20). Ein Mitglied, das nur spätere Epochen bekommt, kann sie nicht lesen. Vor `share --from` entscheiden.
4. **Metadaten mit Benutzersignatur** (Flags) lehnt der Client heute ab (`checkMeta`). Mit Flag-Änderungen kommen: eigene Signaturpolitik (Mitglied der Epoche, aktuelle Generation), neue Datei mit höherer Version, `extra` wie bei Ingest (S22 beachten).
5. **Lokaler Zustand ist Sicherheit:** `state.json` schützt gegen Zurückspielen. Kopplung neuer Geräte (2.7) muss ihn übertragen, sonst beginnt das neue Gerät bei Vertrauen beim ersten Kontakt.
6. **Server und Kette:** `ingest.chooseEpoch` prüft die ganze Kette bei jeder Annahme. Bei vielen Epochen lohnt ein Zwischenspeicher je Postfach, der an den Hash der `epoch.rec`-Dateien gebunden ist.
7. **Absturzsicherheit beim Client:** Epochen werden vor `mailbox.rec` geschrieben, Verpackungen vor `epoch.rec`. Jede neue Schreibfolge (Teilen, Entziehen) braucht dieselbe Überlegung, was nach einem Absturz übrig bleibt und wie der nächste Lauf es übernimmt oder aufräumt.
8. **Tests:** `internal/testenv` baut Plattform, Benutzer und Postfächer in einem Aufruf; `client/tamper_test.go` zeigt, wie man gefälschte Mails mit beliebigem Schlüssel, beliebiger Epoche und Version erzeugt; `ingest/crash_test.go` die Einspritzpunkte.
