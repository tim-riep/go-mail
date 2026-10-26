# Übergabe nach Phase 0.1

Stand: Phase 0 (kryptografisches Fundament) ist umgesetzt und getestet; Phase 0.1 hat `envelope` und `rec` auf die Version 1.1 der Spezifikation gebracht (Elementrahmen mit Typbytes, Empfängertyp 4, höchstens vier Empfänger, NFC über `golang.org/x/text`). Dieses Dokument richtet sich an die nächste Phase. Es beschreibt die öffentliche API der vier Pakete, die Invarianten, die Aufrufer einhalten müssen, bekannte Grenzen und offene Punkte. Entscheidungen stehen in `docs/DECISIONS.md`, Spezifikationslücken in `docs/SPEC-ISSUES.md`. Die Spezifikation ist `docs/PLAN.md` in Version 1.1 (Abschnitt 13 listet die Änderungen gegenüber 1.0).

## Überblick

```
internal/rec       kanonische Kodierung (3.6), strikter Decoder, NFC-Prüfung
internal/keys      Seed, BIP-39, HKDF (2.2, 2.3), Zertifikate, Schlüsselspeicher
internal/shamir    Aufteilung über GF(256), Anteile als 30 Wörter (2.3)
internal/envelope  Dateiformat .gml (3): HPKE-Verpackung, STREAM-Inhalt, Signatur
```

Abhängigkeiten: `envelope -> keys -> rec`, `shamir -> keys`. Nur Standardbibliothek, `golang.org/x/crypto/argon2` und `golang.org/x/text/unicode/norm` (v0.43.0, in `go.mod` festgelegt). Go 1.26 (getestet mit 1.26.10).

Prüfen:

```
go vet ./...
go test -race ./...
go test -cover ./internal/...
GOARCH=386 go test ./internal/...      # 32-bit: Längenfelder ab 2^31 (Fund der unabhängigen Prüfung); -race gibt es auf 386 nicht
go test -run '^$' -fuzz '^FuzzDecode$' -fuzztime 5m ./internal/rec/   # je Fuzz-Ziel
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

## Testabdeckung

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

## Unabhängige Prüfung in Phase 0.1

Ein Subagent ohne Kenntnis von DECISIONS, SPEC-ISSUES und HANDOFF prüfte `envelope` und `rec` gegen 3.1 bis 3.6 der Version 1.1 und fand keine Abweichung von der Spezifikation. Behoben (Commit 3b8cb50): Der Schreiber überschrieb seinen Klartextpuffer nur im Erfolgsfall; `Kind.String` lieferte für unbekannte Dateiarten einen Kunstnamen, den `keys.Sign` als Domäne angenommen hätte. Zur Kenntnis genommen, nicht geändert: `SealOptions.Rand` erlaubt Aufrufern die Wiederverwendung von Zufall (siehe Invarianten); `Decrypt` leitet das Flag aus der Position in der Blockliste ab, die `Parse` als `0x01* 0x02` garantiert; `Parse` kopiert die ganze Datei (bis 50 MiB) und hält sie für `FileHash`.

## Fuzzing

Fuzz-Ziele: `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`. Jedes prüft: kein Panic, Annahme nur mit byte-identischer Rückkodierung, Entschlüsselung manipulierter Dateien scheitert (oder liefert bei fremden Empfängereinträgen denselben Klartext). Gefundene Fälle legt `go test` unter `testdata/fuzz/<Ziel>/` ab und sie laufen danach als Regressionstests. Phase 0.1: alle zehn Ziele je 5 Minuten ohne Fund (Ausführungen: rec.FuzzDecode 16,6 Mio., rec.FuzzIsNFC 18,7 Mio., keys.FuzzParseWordlist 5,5 Mio., keys.FuzzSeedFromWords 15,6 Mio., keys.FuzzDecodeGenerationCert 16,5 Mio., keys.FuzzOpenKeystore 18,9 Mio., shamir.FuzzShareFromWords 15,6 Mio., shamir.FuzzShareFromBytes 20,6 Mio., shamir.FuzzCombine 12,7 Mio., envelope.FuzzParseAndOpen 4,7 Mio.); die Saat von `envelope.FuzzParseAndOpen` enthält die Phase-0-Dateien und ungültige Elementfolgen. In Phase 0 fand `keys.FuzzDecodeGenerationCert` nach zwei Minuten ein Zertifikat mit ausdrücklich kodiertem `revokes = 0`, das angenommen wurde, aber nicht byte-identisch zurückkodierte; der Decoder lehnt diese Form jetzt ab, der Fall liegt unter `internal/keys/testdata/fuzz/FuzzDecodeGenerationCert/`.

## Offene Punkte für die nächsten Phasen

1. `user.rec`, `epoch.rec`, `mailbox.rec` und die Verpackungen (`members/<user>.wrap` als `.gml` mit `KindWrap` und `RecipientUserUnwrap`) als Datensätze festlegen; Schemas in `store`.
2. Den Datensatz `extra` der Ingest-Signatur für Metadaten (Abschnitt 7) festlegen; dann liefert `envelope` die Signatur ohne Änderung.
3. Den Hash der Mail-Datei in den Metadaten definieren (ganze Datei oder `FileHash`) und beim Lesen prüfen (SPEC-ISSUES S06).
4. Wiederherstellungsempfänger (`RecipientRecovery`) beim Schreiben eintragen; nachträgliche Einträge in signierten Dateien bleiben ausgeschlossen (S09, Version 1.1).
5. Resolver für Signaturen: Zertifikatskette (`PlatformCert` über Identität, Identitätsnachfolge), Generationskette des Benutzers, Widerrufe aus dem Log, Aktualitätsgrenze 24 h (2.3).
6. Eingabenormalisierung für Seed-Wörter und Shamir-Wörter in `gomailctl` (S11).
7. Beim Lesen einer Mail (Phase 1 ff.) die Prüfung aus Abschnitt 7 der Version 1.1 umsetzen: Metadaten signiert, SHA-256 der ganzen Mail-Datei gleich dem Wert in den Metadaten, Kopffelder gleich den Metadaten.
8. Zeremonie-Werkzeug: `shamir.Split` für den Plattform-Root, Probe-Rekonstruktion, Vergleich über die abgeleiteten öffentlichen Schlüssel.
