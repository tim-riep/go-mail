# Übergabe nach M1 (Entwurf)

Stand: 03.11.2026, Entwurf aus Auftrag 20c. Code bei Commit 3e06f23 auf dem Arbeitsbranch `claude/quirky-keller-hjsl5i` (alle Pakete der Wellen 1 bis 4, 13e/13f, 15i bis 15n, 19/19b, 20a und die Linie 09b bis 09g zusammengeführt). Grundlage ist `docs/PLAN.md` in Version 1.4. Auftrag 20b (kleine Nacharbeiten im Produktivcode) läuft parallel und ist nicht enthalten. Messungen, Fuzzing, Abdeckung und die Abnahme nach 10.2 laufen noch; ihre Stellen tragen den Platzhalter „wird mit Auftrag 20 eingetragen“.

Dieses Dokument beschreibt Pakete, Invarianten, Build und Grenzen für die nächste Phase. Es verweist, statt zu wiederholen:
- Entscheidungen: `docs/DECISIONS.md` (Phase 1 ab D47, Phase 2 und M1 ab D63, zuletzt D91).
- Offene Punkte der Spezifikation: `docs/SPEC-ISSUES.md` (bis S94); Fragen an den Auftraggeber: `docs/QUESTIONS.md` (Q1 bis Q22).
- Bekannte Grenzen und Restrisiken: `docs/AUDIT.md` Abschnitt 5 (R1 bis R44); Prüfpfade: AUDIT Abschnitt 6.
- Betrieb von Hand: `docs/RUNBOOK.md`, nachgefahren von `TestRunbook`.
- Entwurf des Transparenzlogs: `internal/translog/doc.go` (verbindlich).
- Verlauf der Aufträge und Prüfungen: `docs/ORCHESTRATION.md` Abschnitt 4. Einordnung der gesammelten Hinweise: `docs/tasks/20-triage.md`.

Die Abschnitte zu `rec`, `keys`, `shamir`, `envelope` und `smtpd` sind seit Phase 1 kaum verändert und stehen weiter hier, mit Nachträgen. Die übrigen Pakete beschreibt dieser Stand neu. Tabellen und Prüfberichte aus Phase 0 und Phase 1 stehen am Ende unter „Verlauf“.

## Stand je M1-Kriterium

Die Kriterien stehen in `docs/ORCHESTRATION.md` Abschnitt 1, „M1-Kriterien A–F“. Als erfüllt gilt hier nur, was im Branch gebaut und durch Tests oder Dokumente belegt ist.

| Kriterium | Stand | Was fehlt |
|---|---|---|
| **A** Phase 2 vollständig (2.2, 2.4, 2.5, 6, 7, 9) | Gebaut: Generationen mit `device lost`, `restore`, `keygen --shares`; Prüfvermerke und Übernahme nach 2.2 Punkt 4 für alle Dateiarten außerhalb des Logs (D84, D91). Epochen mit Gründen, `discards`, sofortige und geplante Epochen, Vorrat (D63, D68, D71). `mailbox share`, `revoke`, Leser vergangener Zeiträume (D75, D86). Ordnerliste je Epoche; Flags mit Versionsregel (K4, D79); Index, Suche, Zusammenfassen (D79, D91). Sperren und Rechte nach 9.1 (D70, D81); Befehle nach 9.2 (D86, D87). | Befehle, die an offenen Fragen hängen: `mailbox rotate` (Q7), `--server-search` (Q3, nicht M1), `--delegate` (Q6; Art 3 nur in der API), `recovery …` (Q1; nur interne API). Q18: Ein alleiniges Mitglied ohne geprüfte Ordnerliste hat keinen Ausweg (AUDIT R21). |
| **B** Transparenzlog, Zeuge, Vermerke, 24 h, kein `--insecure-no-log` | Gebaut: Log auf `tlog` (D78), Serverseite mit `loghttp` (D80), Prüfungen in `ingest` und Server (D81), Client am Log mit Vermerken und 24-Stunden-Regel (D88), `gomail-witness` (D74). `--insecure-no-log` ist überall ein Nutzungsfehler. Alle `TODO(phase3-translog)` im Produktivcode sind aufgelöst. | Im Produktivcode nichts. Die 11 Marken `TODO(phase3-translog)` im Testdouble `internal/translog/translogtest` (`Unverified`, nur für `testenv`) sind veraltet und sollten umbenannt werden. Mehrere Zeugen im Betrieb folgen erst vor echten Mails (2.7, AUDIT 1.3). |
| **C** Zeremonie `init --shares 3-of-5`, `ingest-rotate`, `reshare`, Probe; `--dev` nur für Tests | Gebaut (D82, D85 mit Nachträgen): dazu `succeed` und `publish` über das Log; `--dev` nur im Build mit `gomail_dev`; Terminalregeln mit Abbruchpfad. | Kompromissfall: `succeed --compromised` ist gesperrt (Q19, Haltepunkt 2; AUDIT R17). Der Pflichttest aus 10.1 „Signatur einer kompromittierten … Identitätsgeneration“ liegt übersprungen vor (`TestVerifyCompromisedIdentityStillIssues`). |
| **D** `docs/MEASUREMENTS.md`, reproduzierbar | Messumgebung gebaut: `internal/bench`, `scripts/bench.sh` (D77, 12d). | `docs/MEASUREMENTS.md` fehlt; Auftrag 17 misst auf ruhiger Maschine. Wird mit Auftrag 20 eingetragen. |
| **E** Abnahme nach 10.2 | Volllauf des Orchestrators auf dem Stand der Linie 09g grün: gofmt, vet, `-race` mit und ohne Tags, 386, `internal/e2e` (ORCHESTRATION, Verlauf 09g). Zwei-Maschinen-Skript im lokalen Modus durchgelaufen (D83). | Zuordnung der Pflichttests aus 10.1, Läufe mit Protokoll, Fuzzing je Ziel 10 Minuten, Abdeckung je Paket: wird mit Auftrag 20 eingetragen. Zwei Maschinen über NFSv4: **bedingt**, weil es hier weder NFS noch eine zweite Maschine gibt (D83, AUDIT R36). Ob der übersprungene Pflichttest (Q19) Kriterium E berührt, entscheidet Auftrag 20. |
| **F** HANDOFF, AUDIT, RUNBOOK mit `TestRunbook` | `docs/AUDIT.md` auf dem Stand nach D91 (Aufträge 18, 18b, 18c, 20c). `docs/RUNBOOK.md` mit `TestRunbook` (Zeremonie 3 aus 5, Zeuge, drei Benutzer; D89). Dieses Dokument als Entwurf. | Abschluss dieses Dokuments mit den Zahlen aus Auftrag 20. Redaktionelle Vorschläge für das RUNBOOK in `docs/tasks/20-triage.md` (R-1 bis R-3). |

Nicht in M1 (ORCHESTRATION Abschnitt 1): Löschen von Epochen, Volltextsuche, QR, TLS und Missbrauchsschutz, Padmé, Hardware-Schlüssel, IMAP, Oberflächen über die Kommandozeile hinaus.

## Überblick

```
internal/rec       kanonische Kodierung (3.6), strikter Decoder, NFC-Prüfung
internal/keys      Seed, BIP-39, HKDF (2.2, 2.3), Zertifikate, Signaturdomänen (3.7), Schlüsselspeicher
internal/shamir    Aufteilung über GF(256), Anteile als 30 Wörter (2.3)
internal/envelope  Dateiformat .gml (3): HPKE-Verpackung, STREAM-Inhalt, Signatur, Kopffeld 8
internal/words     Eingabe von Seed- und Anteilswörtern (2.2): NFKD, Kleinschreibung, Grenzen
internal/store     Datenverzeichnis (4): atomares Schreiben, Sperren und Rechte (9.1), alle Datensätze
internal/translog  Transparenzlog (2.7) auf tlog: Einträge, Köpfe, Beweise, Verifier, Audit-Index
internal/loghttp   HTTP-Seite des Logs zwischen Server und Zeuge
internal/witness   Zeuge nach 2.7: Regeln, Zustand, Fork-Nachweis
internal/smtpd     SMTP-Zustandsmaschine mit den Grenzen aus 5.1
internal/terms     Begriffsregeln aus 5.4 und D55, einmal für Server und Client
internal/ingest    Annahme, Spool-Transaktion, Metadaten, Begriffslisten, Logprüfungen (5.2 bis 5.4)
internal/client    Benutzer, Postfächer, Generationen, Lesepfade, Index und Suche, Flags, Log (2, 6, 7)
internal/ceremony  Schlüsselzeremonie und Veröffentlichung (2.3)
internal/bench     Messungen (nur Tests und Benchmarks)
internal/testenv   Plattform, Benutzer und Postfächer für Tests (nur mit -tags gomail_dev)
internal/e2e       Ende-zu-Ende-Tests, Programme nach RUNBOOK, Zwei-Maschinen-Skript
cmd/gomail-server  init, serve, invite create, address add, log repair
cmd/gomailctl      keygen, register, restore, mailbox create/share/revoke, device lost, sync,
                   list, read, search, flag, inspect
cmd/gomail-ceremony init, ingest-rotate, reshare, succeed, publish
cmd/gomail-witness keygen, serve
scripts/           bench.sh (Messungen), two-host-test.sh (Test nach 9.1)
```

PLAN 9.3 nennt ein Paket `search`. Die Suche liegt in `internal/client` (`Search` in `search.go`, `Index` in `index.go`), weil sie die Schlüssel und Prüfregeln des Clients braucht; die Begriffsregeln liegen in `internal/terms`.

Abhängigkeiten im Produktivcode: `envelope -> keys -> rec`; `shamir -> keys`; `words -> keys`; `store -> envelope, keys, rec`; `translog -> keys, rec, store`; `witness -> translog, store, keys, rec`; `loghttp -> translog, witness`; `terms -> store`; `ingest -> smtpd, store, envelope, keys, terms, translog`; `client -> store, envelope, keys, rec, shamir, terms, translog, words`; `ceremony -> keys, shamir, store, translog, witness, words`. `smtpd` hängt von keinem Paket des Projekts ab. Nur Standardbibliothek und `golang.org/x/crypto` v0.58.0, `golang.org/x/mod` v0.42.0 (`sumdb/tlog`, `sumdb/note`), `golang.org/x/text` v0.43.0 (`go.mod`); `x/sys` nur indirekt. Go 1.26, getestet mit 1.26.10 (`GOTOOLCHAIN=go1.26.10`).

## Bauen und testen

### Build-Tags

- **`gomail_dev`:** Entwicklungszeremonie `gomail-ceremony init --dev` und `ceremony.InitDev`, Entwicklungs-Pins. Ohne das Tag enthält kein Programm den Pfad, der den Plattform-Root in eine Datei schreibt (D85 (3)). Produktionsbinaries lehnen einen Entwicklungs-Pin ab (D87 (3), D88 (1)).
- **`gomail_test`:** Testschalter `GOMAIL_TEST_MIN_FREE` (Grenze für freien Platz statt 10 %), `GOMAIL_TEST_DEV_IDENTITY` (Entwicklungs-Pin im Client), `GOMAIL_TEST_HEAD_GAP` (Abstand der Köpfe) und `GOMAILCTL_TEST_KEYGEN_PIPE` (`keygen` ohne Terminal, für Skripte). Das Produktionsbinary enthält keinen davon (`TestNoTestSwitchInProduction`, AUDIT R35).
- **`ceremony_notty`:** Tests der Zeremonie ohne Terminal (D82 (5)).
- Die Tests in `internal/client`, `internal/ingest`, `internal/bench`, `cmd/gomailctl` und `cmd/gomail-server` und die `testenv`-Tests in `internal/e2e` brauchen eine Entwicklungsplattform. Sie sind nur mit `-tags gomail_dev,gomail_test` aussagekräftig; ohne Tags überspringen sie sich (D85 (3), D88 (9) mit Nachtrag). Die Belege für den Produktionsbuild laufen nur ohne Tags. Kein Lauf allein deckt alles; welcher Lauf was trägt, steht in AUDIT 6.1.
- `internal/e2e` baut seine Programme selbst, in der Regel mit `gomail_dev,gomail_test`; `TestRunbook` und `TestInitProduction` nur mit `gomail_test` (D89 (2)). Für seine Server setzt es `GOMAIL_TEST_MIN_FREE` selbst. Andere Läufe auf einer Platte mit weniger als 10 % frei brauchen `GOMAIL_TEST_MIN_FREE=0.000001` (nur im Testbuild wirksam).

### Befehle

```
export GOTOOLCHAIN=go1.26.10
gofmt -l .
go vet ./...
go vet -tags gomail_dev,gomail_test ./...
GOOS=openbsd go vet ./...                                           # ebenso freebsd, netbsd, dragonfly, darwin
go test ./...                                                       # Lauf 1: Produktionsbuild
go test -tags gomail_dev ./cmd/gomailctl                            # Lauf 2: TestKeygenPipeProduction
go test -race -p 2 -tags gomail_dev,gomail_test -timeout 60m ./...  # Lauf 3
GOARCH=386 go test -p 2 -tags gomail_dev,gomail_test -timeout 60m ./...
go test -run '^$' -fuzz '^FuzzX$' -fuzztime 10m ./internal/<paket>  # je Fuzz-Ziel
scripts/two-host-test.sh --local …                                 # Test nach 9.1 ohne zweite Maschine (RUNBOOK 9)
scripts/bench.sh                                                    # Messungen (D77)
```

`-race` gibt es auf 386 nicht. Der Standard von `go test -timeout` ist 10 Minuten; `internal/client` braucht länger, daher `-timeout 60m` (mindestens 40 Minuten).

### Laufzeiten (Richtwerte, 4 Kerne)

| Lauf | Dauer | Quelle |
|---|---|---|
| `internal/client` mit `-race` | 25 bis 35 Minuten (1489 s nach 14, 2003 s nach 09e) | `docs/tasks/20-notes.md` |
| `internal/client` unter 386 | etwa 15 bis 30 Minuten (868 s nach 14, 1733 s nach 09e) | `docs/tasks/20-notes.md` |
| `cmd/gomail-ceremony` mit `-race` | knapp unter 10 Minuten; `TestPTYSignalSalvo` allein 250 bis 470 s | `docs/tasks/20-notes.md` (15n) |
| `TestRunbook` | etwa 35 s | D89 |
| Volllauf aller Pakete | wird mit Auftrag 20 eingetragen | – |

Unter Last sind `TestPTYQuitInCommit` (einmal 61 s) und `TestTwoHostScript` (einmal gescheitert) als Ausreißer aufgefallen; Auftrag 20 beobachtet sie (`docs/tasks/20-triage.md`, Nr. 138 und 152).

### Testvektoren

Testvektoren liegen unter `internal/<paket>/testdata/`, die Generatoren unter `internal/<paket>/testdata/gen/` (`go run ./testdata/gen` im Paketverzeichnis). Die Vektoren der Phase-0-Pakete (`rec`, `keys`, `shamir`, `envelope`) dürfen sich nicht ändern; jeder Auftrag prüft vor dem Commit, dass `git diff --stat 38626a9 -- internal/{rec,keys,shamir,envelope}/testdata` leer ist. Die `.gml`-Dateien aus Phase 0 (Rahmen ohne Typbytes) liegen unter `internal/envelope/testdata/phase0/` und müssen abgelehnt werden.

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
const DomainPlatformCert, DomainPlatformSuccession, DomainUserGen, DomainEpoch, DomainAddress, DomainCheckpoint, DomainUser, DomainInvite, DomainWrapAccept, DomainMail, DomainMeta, DomainPending, DomainWrap, DomainIndex
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
- Generationen beginnen bei 1 und sind lückenlos; `VerifyGenerationChain` verlangt die vollständige Folge ab 1. Ob eine Signatur einer widerrufenen Generation vor dem Widerruf im Log stand (2.2 Punkt 4), prüfen Log und Client (`CheckRevokedSignature`, D88; Prüfvermerke für Dateien außerhalb des Logs, D84, D91).
- `RootKey` nur kurz im Speicher halten und mit `keys.Wipe` löschen; `UserRoot.Zero` nach der Ableitung aufrufen. Der Seed wird nie gespeichert.
- Signaturdomänen sind die Kurznamen aus 3.7 (Version 1.2) als Konstanten `Domain*`; `Sign` und `Verify` nehmen keine anderen an, `RecordDomain(schema)` liefert den Kurznamen eines Datensatztyps (DECISIONS D47). Ein neuer signierter Typ braucht eine neue Zeile in 3.7 und in `keys`.
- `Decode*` prüft Struktur, nicht Signatur; `Verify` immer aufrufen.
- Der Schlüsselspeicher enthält nur die aktuelle Generation. Beim Öffnen werden KDF-Parameter aus dem Kopf innerhalb fester Grenzen übernommen (64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads); schwächere als die Spezifikation nie.
- Die Passphrase ist `[]byte` (damit sie überschreibbar ist) und darf nicht leer sein.

### Grenzen
- `ecdh.PrivateKey` lässt sich nicht überschreiben; `Keystore.Zero` löscht den Ed25519-Schlüssel und gibt den X25519-Schlüssel nur frei.
- `user.rec` ist seit Auftrag 02 ein signierter Datensatz in `store` (Kurzname `user`, D68).
- `SeedFromWords` bleibt exakt; die Normalisierung der Eingabe (S11) macht `internal/words` (D85 (5)).

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

Nachtrag seit Phase 1: Kopffeld 8 `version` (`Header.Version`, Version 1.4, D66), Pflicht und mindestens 1 für Art `meta`; `meta-signed` nur aus Kopf und Hashes (Auftrag 01).

### Invarianten für Aufrufer
- Jede Datei bekommt einen neuen Dateischlüssel und einen neuen Nonce-Präfix (beide zieht der Schreiber). Nie eine Datei durch Verändern einer bestehenden erzeugen; immer neu versiegeln (3.3 Regel 1).
- `FileID` im Kopf muss der ID im Dateinamen entsprechen; das prüft die Ablage, nicht `envelope`. Ebenso prüft die Ablage `MailboxID` und `Epoch` gegen den Ort der Datei und die Epochenkette (2.4).
- `OpenOptions.ExpectedSuite` kommt aus der signierten `epoch.rec` der Datei-Epoche; `CheckSuiteTransition` beim Prüfen der Epochenkette aufrufen.
- Signaturpolitik: Mail-Dateien mit `AllowUnsigned`, alle anderen mit `ResolveSigner`. `envelope` koppelt `AllowUnsigned` nicht an die Dateiart (Indexsegmente sind seit Version 1.4 signiert, D79 (1)); die Ablage muss die Politik je Dateiart setzen und darf `AllowUnsigned` nie pauschal verwenden. Der Resolver setzt Abschnitt 7 um: unbekannter Schlüssel, fehlendes Zertifikat, Widerruf, kompromittierte Generation führen zu einem Fehler. `Extra` muss beim Prüfen gleich dem beim Signieren sein; für Metadaten ist es `gomail/v1/rec/meta-signed` (`store.MetaSignedSchema`, Abschnitt 7, K6).
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

Datenverzeichnis nach Abschnitt 4 (Version 1.4). Was seit Phase 1 dazukam, steht in D68 bis D70, D73, D78, D87 und D91; die API steht in `internal/store`.

### Invarianten
- Alles im Datenverzeichnis wird über `store` geschrieben: atomar, mit `fsync` von Datei und Verzeichnis; nie eine Datei an Ort und Stelle verändern. `epoch.rec`, Plattformdateien und `user.rec` werden nur exklusiv angelegt. Einzige Ausnahme: `ReplaceEpoch` ersetzt eine nie loggbare `epoch.rec` unter der Postfachsperre, und nur wenn der Aufrufer per `unloggable` belegt, dass das Log sie mit `ErrOrder` verweigert (D88 (4)).
- Jede Datei wird mit `ReadFileLimited` gelesen: Größe vor dem Lesen geprüft, geöffnet mit `O_NONBLOCK`, nur reguläre Dateien (D48, D87 Nachtrag 20a). Andere Öffnungen ohne diesen Schutz: AUDIT R41.
- Lesefunktionen prüfen Ort gegen Inhalt, nicht Signaturen. Signaturen, Kette (`store.Chain`, D64, D68) und Log prüft der Aufrufer.
- Sperren nach 9.1 in der Lesart D70: POSIX-Satzsperren (OFD unter Linux), Rollensperren `locks/server` (exklusiv) und `locks/client` (geteilt), Postfachsperren; mehrere Postfächer nur über `LockMailboxes`. Rechte 2770/0660, Gruppe `gomail` (D70, D81 (4)).
- Nur `gomail-server init` legt ein Datenverzeichnis an (D87).
- Dekodierte Datensätze sind kanonisch; leere optionale Felder werden abgelehnt.
- `CleanText` ersetzt Steuerzeichen einschließlich C1 und Bidi (D86 (3)).

## translog, witness, loghttp

Verbindlicher Entwurf: `internal/translog/doc.go` (Abschnitte „Reference head“, „Validity rules“, „Who writes“, „Unlogged epoch.rec“, „Withheld entries“, „What write access to log/ gives an attacker“, „Witness quorum“, „Platform generations“). Umsetzung D78 (Log), D80 (Serverseite), D81 (Ingest und Server), D88 (Client), D74 (Zeuge).

- `translog.Log` ist die Schnittstelle für alle Prüfungen und Einträge; `translog.Open` liefert ein Client-Log (mit `Verifier`, Referenzkopf aus `state.json`) oder ein Operator-Log (Server, Zeremonie; Referenz ist `log/tree.rec`).
- Das Urteil über einen Eintrag ist eine Funktion von Logpräfix und Anker; jeder Client urteilt gleich. Köpfe gelten nur mit dem Quorum der Zeugen nach Schlüsseln; ein Kopf ist höchstens 24 Stunden alt (23 Stunden mit offenem eigenem Eintrag).
- Operator-Log fail closed: ein geschrumpftes oder beschädigtes `tree.rec` stoppt Annahme und Signatur bis `gomail-server log repair` und Neustart (D81 (3)); `RepairTree` meldet verwaiste Einträge und löscht nichts.
- `loghttp`: `GET /gomail/log/head`, `GET /gomail/log/consistency`, `POST /gomail/log/cosign`; Zeitlimits und Größengrenzen, keine Verbindungsobergrenze (AUDIT R8).
- `witness`: acht Regeln aus 2.7, Zustand vor der Gegensignatur dauerhaft, Fork beendet den Dienst (Exit 3).
- `translogtest.Unverified` nimmt alles an und dient nur `testenv` (Serverseite der Testplattform); kein Programm nutzt es.

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
- Seit Auftrag 01 kündigt `EHLO` `SIZE` 26.214.400 an (25 MiB, 5.1); gezählt werden nur die Daten des Absenders (S62).

## ingest

`ingest.New` prüft Ingest-Schlüssel gegen sein Zertifikat, das Zertifikat im Log und `valid_from` gegen die Uhr des Servers ohne Toleranz (D90); dann nimmt es die Serversperre, auf Verlangen prüft es die Client-Sperre, zuletzt, dass die Generation nicht abgelöst ist (`internal/ingest/ingest.go`, `New`).

### Invarianten
- Ablauf je Mail: Epochenwahl bei jedem `DATA` unter der Sperre (K8, D71), Verschlüsselung je Postfach im Spool, Metadaten und Marker, Journal, Umbenennungen (D50, D52). Kein Klartext auf der Platte; die Warteschlange lagert nur verschlüsselt aus (`mlock`, sonst nicht).
- Gegen das Log geprüft werden `epoch.rec` und `user.rec` des Signierers, die Adresszuordnung (bei RCPT, in `Begin` und im Commit) und die eigene Ingest-Generation (in `New`, `Begin` und im Commit). Jeder Logfehler ist `451`; gegen eine ungeloggte oder zurückgesetzte Epoche wird nie verschlüsselt (D81 (1)).
- Jede eigene Signatur wird vor dem Commit ohne Schlüssel selbst geprüft (D73).
- `Recover` muss vor dem ersten `Begin` laufen. `BatchSize` höchstens `store.MaxBatch` (D81 (6)).
- Unbekannter freier Platz ist fail closed (`451`, S81); die 10-%-Grenze ist nur im Testbuild veränderbar.
- Absturzpunkte für Tests: Paketvariable `crashHook`, nur in Tests gesetzt.

## terms und words

- `internal/terms` hält die Regeln aus D55 einmal: Begriffe einer Mail (`List`), Anfragen (`Query`), Thread-Wurzel (`ThreadRoot`), Anhang (`HasAttachment`). `ingest.Terms` und `client.metaTerms` rufen sie auf (D91 (1)). Für Mails ohne Begriffsliste bildet der Client `thread:` aus der eigenen Message-ID (S23, Q12).
- `internal/words` normalisiert Seed- und Anteilswörter (NFKD, Kleinschreibung, beliebiger Leerraum) und prüft `MaxTokens` und `MaxInput` vor der Normalisierung (D85 (5)). `internal/client/words.go` ist nur noch eine Hülle darüber.

## client

Einstieg: `Keygen`, `Register`, `Restore`, `DeviceLost`, `Open`; am `Client`: `CreateMailbox`, `Share`, `Revoke`, `Sync`, `List`, `Read`, `Search`, `Index`, `SetFlags`, `SetFolders`, `Rename`, `Mailboxes`; dazu `Inspect`. `Config` trägt Datenverzeichnis, Client-Verzeichnis und Pin; das Log baut der Client selbst (D88 (1)).

### Prüfungen
- Jede Operation beginnt mit `ready()`: `Refresh` beim Öffnen, danach `CheckFresh` (24-Stunden-Regel); `Sync` und `DeviceLost` refreshen zusätzlich (D88 (1)).
- Vor jeder Verwendung: `CheckUser`, `CheckGeneration`, `CheckRevokedSignature`, `CheckEpoch` für jede Epoche, `CheckAddress` für jede Mail, `CheckPlatform` (D88 (2)). Danach die Lesepfade aus 2.4 und 7: Kette ab Epoche 1 (`store.Chain`, `checkSignerGen` als lokale Schranke, Q13), Verpackung, Metadaten mit Versionsregel und Merkzettel (Epoche, Empfangszeit, Mail-Hash, SHA-256 der Metadatei), Mail nur mit passendem Hash.
- Signaturen einer widerrufenen Generation außerhalb des Logs zählen nur mit Prüfvermerk vor dem Widerruf und werden dann neu signiert (D84, D91; AUDIT R27).
- Vermerke anderer Mitglieder (`checkpoints/`) werden in beide Richtungen verglichen; `Unconfirmed` bleibt bis zum Vermerk eines anderen Benutzer-Mitglieds (D88 (5), (6); Q20).

### Invarianten
- **Kein Pfad verkleinert den lokalen Zustand eines Postfachs** (D84 (2), S74). Einträge in `Checked` dürfen an Ort und Stelle in fester Größe geändert werden (D91 (6)).
- Wachstum von `state.json` ist begrenzt mit dokumentierter Rate; gelesen wird bis 64 MiB (`loadState`). Ohne Schlüssel bei Schreibzugriff: AUDIT R27 (a); im ehrlichen Betrieb: AUDIT R43.
- `List` zeigt nur Mails, die alle Prüfungen bestanden haben, und warnt für jede andere; `Read` gibt bei jedem Fehler nichts heraus. Warnungen nennen nur IDs, Nummern und feste Ursachen (`warnCause`).
- Erste Einträge nach „Who writes“: erst Log, dann Datei (`Register`, `CreateMailbox` über `new-mailboxes/`), Epochen und Generationen erst Datei, dann Log (D88 (3)).
- Schreibfolgen sind absturzsicher: was nach einem Absturz übrig bleibt, übernimmt oder räumt der nächste Lauf (Vormerkungen `Reissue`, `ErrPartial`). Ausnahme bis 20b: `keygen` (AUDIT R33).
- Der lokale Zustand ist Teil der Sicherheit. Ohne ihn beginnt ein Gerät bei Vertrauen beim ersten Kontakt (2.7; AUDIT R20, R22).

## ceremony und Programme

- `gomail-ceremony`: `init --shares k-of-n` (Standard 3 aus 5) mit Probe-Rekonstruktion, `ingest-rotate`, `reshare`, `succeed` (ohne `--compromised`, Q19), `publish` über das Log mit `--replace-witnesses` (D82, D85). Terminalregeln mit Abbruchpfad, `outputGrace`, `confirmDelay` (D85 Nachträge; RUNBOOK 2; AUDIT R1 bis R5). Schlüsselverzeichnis `--keys` über `os.Root`, 0700, kein Symlink im letzten Element.
- `gomail-server`: `init` (einziger Weg zum Datenverzeichnis, D87), `serve --pin --log-listen` (Startprüfungen RUNBOOK 1.6; Serversperre vor dem Laden des Ingest-Schlüssels, D88 (8)), `invite create`, `address add` (Logeintrag vor `addresses.json`, Admin-Schlüssel außerhalb des Datenverzeichnisses), `log repair`.
- `gomailctl`: Befehle nach 9.2 und `restore`, `flag` (D86, S92). Exit-Codes 0, 1, 2, 3 (`ErrPartial`), 130. Seed und Anteile nur am Terminal, Wörter ohne Echo; die Passphrase vom Terminal mit Echo (R31). Jeder Befehl außer `inspect` verlangt eine wirksame Serversperre.
- `gomail-witness`: `keygen`, `serve --log --log-key --origin --key --state` (S68).

## Datenverzeichnis

Auszug; maßgeblich sind Abschnitt 4, `internal/store` und `internal/translog/doc.go`.

```
data/
  platform/identity-<g>.pub, identity-<g>.succ (g ≥ 2), admin-<g>.pub/.cert, ingest-<g>.pub/.cert, witnesses.rec
  users/<user-id>/user.rec
  invites/<code>.json
  addresses.json, addresses.lock
  locks/server, locks/client
  log/lock, tree.rec, entries/<i>.rec, tree/tile/…, heads/<size>.sig, keys/…
  mailboxes/<postfach-id>/
    mailbox.rec, epoch-fallback.rec (nur nach einem Rückfall)
    epochs/<n>/epoch.rec, folders.gml, members/<user-id>.wrap, members/<user-id>.accept, members/recovery.wrap
    mail/<ordner-id>/<mail-id>.gml, <mail-id>.meta.gml
    pending/<n>/…                         Marker und Begriffslisten
    index/<n>/<device-id>-<lfd>.gml       Indexsegmente
    checkpoints/<user-id>-<device-id>.rec Vermerke der Clients
  spool/, work/                           nur während einer Annahme bzw. bei Last
```

Client-Verzeichnis (Standard `~/.config/gomailctl`, nie im Datenverzeichnis): `keystore`, Kopie der eigenen `user.rec`, `state.json`, Audit-Index des Logs, `new-mailboxes/`, `lock` (AUDIT 3).

## Bekannte Grenzen

Vollständig in `docs/AUDIT.md` Abschnitt 5 (R1 bis R44), jeweils mit Beleg. Für die Übergabe besonders:

- **Q19, kompromittierte Plattformidentität** (R17): kein Weg im Code; bei Kompromittierung neue Zeremonie mit neuem Origin und neuen Pins.
- **Wachstum des Client-Zustands** (R27 (a), R43): ohne Schlüssel bei Schreibzugriff je nach Geräten und Größe der Epoche in Tagen bis Monaten bis 64 MiB; im ehrlichen Betrieb rund 70 000 Mails je Client-Verzeichnis. Abhilfe nach M1 (Q22 Variante B).
- **Verfügbarkeit bei Schreibzugriff:** Sperre durch frei signierten Vermerk (R23), nicht loggbare Epoche 1 (R24), dem Log widersprechende Epoche (R25), nicht reguläre Dateien (R26, R41), Lesegrenze der Segmente (R42), Neuausstellung, die nie gelingt (R44). 2.7 verspricht Erkennung, nicht Verfügbarkeit.
- **Zwei Maschinen nur bedingt** (R36): NFSv4-Sperren und Cache-Verhalten ungeprüft.
- **Zielplattformen** (R40): Terminalbehandlung auf BSD und Darwin nur per `go vet` geprüft, nie ausgeführt; PTY-Tests nur unter Linux. plan9 und js/wasm übersetzen die Terminalteile gewollt nicht; Windows lehnt die Zeremoniebefehle ab.
- **Terminal in `gomailctl`** (R6): Ein statisch per `mknod` angelegter Terminalknoten auf einem anderen Dateisystem (etwa in einem chroot) hat ein anderes `st_dev` und wird verweigert; das ist die sichere Richtung. Auf den BSDs ohne `/dev/tty` im Dateisystem entfällt die Unterscheidung der Sitzungen.
- **Ohne S-Punkt, offen mit `TODO(ask)`:** Passphrase mit Echo und Löschen des Seeds vor der Abfrage der Kontrollwörter (D86, R31); Gruppenname bei `gomail-server init` nur Warnung (D87 (4), R34); neuer `init` statt Nachfolge bei kompromittiertem Root (Nachtrag zu Q19, R17).
- **Aus Phase 1 weiter offen** (R38): Spool-Vervielfachung bei vielen Empfängerpostfächern, Mindestrate in festen 60-Sekunden-Fenstern, Doppelzustellung bei Verlust zwischen Commit und `250`.
- **Kein Klartext, aber Metadaten sichtbar** (R37): Root während des Empfangs liest neue Mails; Größen, Zeiten, Mitgliedschaften und Trefferzahlen bleiben sichtbar.

## Offene Fragen

Alle Fragen mit Stand stehen in `docs/QUESTIONS.md` und AUDIT 7.1. Die drei, die das Verhalten nach M1 am stärksten bestimmen:

| Frage | Gegenstand | Stand | Gebaut bis zur Antwort |
|---|---|---|---|
| Q18 | alleiniges Mitglied nach einem Widerruf ohne geprüfte `folders.gml` | offen (Haltepunkt 1) | Ablehnung ohne Ausweg: `List`, `Rename`, `SetFolders` scheitern, `Read` geht; `sync` und `device lost` enden mit Exit 3 und fester Ursache (D84 (3), D88 (7), `TODO(Q18)` in `internal/client/devicelost.go`). Vorbeugung: Postfächer mit mindestens zwei Benutzer-Mitgliedern führen (RUNBOOK 8.4). AUDIT R21. |
| Q19 | Nachfolge nach Kompromittierung der Plattformidentität | offen, **Haltepunkt 2** | `succeed --compromised` gesperrt (Nutzungsfehler, `ErrCompromised`, `TODO(Q19)`); Pflichttest aus 10.1 übersprungen. Vorschlag in Q19: Logeintrag `revocation-<g>.rec` der neuen Identität. Zusätzlich offen: wann ein neuer `init` statt einer Nachfolge nötig ist. AUDIT R17, S76. |
| Q20 | Markierung „noch kein bestätigter Zustand“ nach Wiederherstellung | offen (Haltepunkt 1) | strengste Lesart: `Unconfirmed` bleibt bis zum Vergleich mit dem Vermerk eines **anderen** Benutzer-Mitglieds; ein eigenes zweites Gerät zählt nicht; ein alleiniges Mitglied bleibt dauerhaft markiert (nur Warnung; D88 (6), `TODO(Q20)` in `internal/client`). AUDIT R22. |

Weiter offen und für den Betrieb mit echten Mails wichtig: Q8 (Widerruf von Ingest- und Admin-Generationen, kein Pin-Feld 7), Q9 (zeitliche Bindung von Adresszuordnungen), Q4 (Logschlüssel ist der Ingest-Schlüssel). Entschieden in dieser Phase: Q22 (Variante A, D91).

## Testabdeckung

Wird mit Auftrag 20 eingetragen: `go test -cover` je Paket unter `internal/` (mit `-tags gomail_dev,gomail_test`, wo nötig), Mindestwerte 85 % je Paket und 90 % für `rec`, `keys`, `shamir`, `envelope`, `translog` (M1-Kriterium E).

Letzter bekannter Wert: `internal/client` 87,9 % (09g, ORCHESTRATION Verlauf). Die Werte aus Phase 1 stehen unter „Verlauf“.

## Fuzzing

Wird mit Auftrag 20 eingetragen: jedes Ziel 10 Minuten, Protokolle unter `docs/acceptance/<datum>/fuzz-*.log`.

25 Ziele (AUDIT 6.4): `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`, `store.FuzzDecodeRecords`, `smtpd.FuzzCommands`, `smtpd.FuzzData`, `ingest.FuzzTerms`, `words.FuzzNormalize`, `translog.FuzzParseHeadText`, `translog.FuzzDecodeEntry`, `translog.FuzzOpenHead`, `translog.FuzzProofs`, `translog.FuzzAuditIndex`, `witness.FuzzParseProof`, `witness.FuzzDecodeWitnesses`, `witness.FuzzCosign`, `witness.FuzzPoll`, `loghttp.FuzzServer`.

10.1 verlangt Fuzzing für den `.gml`-Parser, den SMTP-Parser und das Einlesen von Shamir-Anteilen; alle drei sind abgedeckt. Kein eigenes Ziel haben die Prüfpfade des Clients (Kette, Vermerke, `state.json`) und die Zeremonie; `internal/terms` deckt `ingest.FuzzTerms` über `ingest.Terms`.

## Unabhängige Prüfungen bis M1

Jedes Paket hatte nach `docs/ORCHESTRATION.md` Abschnitt 2 einen oder zwei Prüfer (Spezifikation und Angreifer für sicherheitskritische Pakete). Funde, Nacharbeitsrunden und Abweichungen von Regel 6 stehen je Paket in ORCHESTRATION Abschnitt 4 und in der Begründung des D-Eintrags. Funde niedrig, die nach der Zusammenführung offen blieben, sind in `docs/tasks/20-triage.md` eingeordnet. Zahlen für den Abschlussbericht (Prüfrunden, Funde nach Schwere): wird mit Auftrag 20 eingetragen.

## TODO-Inventar

Vorkommen in `cmd` und `internal` am Stand 3e06f23, einschließlich Tests (`grep -rhoE 'TODO\([^)]*\)' cmd internal --include=*.go`):

| Marke | Zahl | Bedeutung |
|---|---|---|
| `TODO(ask)` | 25 | strengste Lesart, wo die Spezifikation schweigt; ohne eigene Frage oder mit Verweis auf Q8, Q11, Q20 |
| `TODO(phase3-translog)` | 11 | nur im Testdouble `translogtest`; veraltet, umzubenennen |
| `TODO(Q1)`, `TODO(Q15)`, `TODO(Q19)` | je 8 | Wiederherstellungsempfänger, Neuausstellung für Leser vergangener Zeiträume, Kompromissfall |
| `TODO(Q20)` | 7 | Markierung `Unconfirmed` |
| `TODO(Q12)` | 5 | Thread-Wurzel ohne Begriffsliste |
| `TODO(Q9)`, `TODO(Q6)` | je 3 | Adresszuordnung, Vertretung |
| `TODO(Q13)`, `TODO(Q18)` | je 2 | `checkSignerGen`, alleiniges Mitglied |
| `TODO(Q3)`, `TODO(Q4)`, `TODO(Q7)` | je 1 | Serversuche, Logschlüssel, `mailbox rotate` |
| `TODO(task-13)` | 1 | `ShowShares` in `internal/client/keygen.go`; Auftrag 20b Punkt 2 |

Außerhalb von Go: `scripts/two-host-test.sh` trägt noch `TODO(task-15b)` (Pin und Zeuge einer echten Zeremonie); der Produktionsweg steht im Kommentar darunter und in RUNBOOK 1.

## Was die nächste Phase als Erstes wissen muss

1. **Q19 vor jedem Betrieb mit echten Mails entscheiden.** Ohne Kennzeichnung einer kompromittierten Identität in Pin, Nachfolge oder Log ist eine Kompromittierung nur durch eine neue Plattform zu heilen. Mit Q8 zusammen entscheiden (Widerruf von Ingest- und Admin-Generationen).
2. **Wachstum des Client-Zustands begrenzen** (Q22 Variante B oder Grenze je Epoche), bevor große Postfächer oder viele Geräte kommen (AUDIT R27 (a), R43). Dafür braucht D84 (2) eine Ausnahme.
3. **Zwei echte Maschinen mit NFSv4** fahren (`scripts/two-host-test.sh` ohne `--local`, RUNBOOK 9), erst dann ist M1-Kriterium E ohne Einschränkung erfüllt.
4. **Vor 10.2 Punkt 1:** TLS, Ratenbegrenzung (auch `loghttp`, R8), Missbrauchsschutz; mehrere Zeugen im Betrieb (R15).
5. **Lokaler Zustand ist Sicherheit:** `state.json` schützt gegen Zurückspielen und trägt die Prüfvermerke. Eine Kopplung neuer Geräte (2.7, nicht in M1) muss ihn übertragen. Jede neue Schreibfolge im Client braucht dieselbe Überlegung, was nach einem Absturz übrig bleibt, und die Regel D84 (2).
6. **Tests:** `internal/testenv` (`New`, `NewLogged`) baut Plattform, Log, Zeuge, Benutzer und Postfächer; `internal/client/tamper_test.go` zeigt gefälschte Mails, `takeover09*_test.go` die Angriffe auf die Übernahme, `cmd/gomail-ceremony/abort15m_*` und `blocked15n_*` die Terminalangriffe (AUDIT 6.5).

## Verlauf

Die folgenden Abschnitte sind der Stand von Phase 0 und Phase 1 und bleiben zur Nachvollziehbarkeit erhalten.

### Testabdeckung in Phase 1

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

#### Nicht abgedeckte Zeilen der Pakete aus Phase 0 (Stand Phase 0.1)

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

### Unabhängige Prüfung in Phase 1

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

#### Unabhängige Prüfung in Phase 0.1 (Verlauf)

Ein Subagent ohne Kenntnis von DECISIONS, SPEC-ISSUES und HANDOFF prüfte `envelope` und `rec` gegen 3.1 bis 3.6 der Version 1.1 und fand keine Abweichung von der Spezifikation. Behoben (Commit 3b8cb50): Der Schreiber überschrieb seinen Klartextpuffer nur im Erfolgsfall; `Kind.String` lieferte für unbekannte Dateiarten einen Kunstnamen, den `keys.Sign` als Domäne angenommen hätte. Zur Kenntnis genommen, nicht geändert: `SealOptions.Rand` erlaubt Aufrufern die Wiederverwendung von Zufall (siehe Invarianten); `Decrypt` leitet das Flag aus der Position in der Blockliste ab, die `Parse` als `0x01* 0x02` garantiert; `Parse` kopiert die ganze Datei (bis 50 MiB) und hält sie für `FileHash`.

### Fuzzing in Phase 1

Fuzz-Ziele aus Phase 0: `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`. Neu in Phase 1:

- `store.FuzzDecodeRecords`: alle Datensätze von `store` (Benutzer, Postfach, Epoche, Epochenschlüssel, Metadaten, Begriffslisten, Vermerk, Journal, Plattformschlüssel und -identität, Adresszuordnung, Name, Ordner); angenommen wird nur, was byte-identisch zurückkodiert.
- `smtpd.FuzzCommands`: beliebige Eingaben auf Befehlsebene; jede Antwortzeile wohlgeformt, nichts über der Größengrenze zugestellt.
- `smtpd.FuzzData`: beliebige Daten nach `DATA`; zugestellt wird genau das Ergebnis einer Referenz für Dot-Unstuffing, ungültige Eingaben nie.
- `ingest.FuzzTerms`: beliebige Header; alle Begriffe und Metadatenfelder speicherbar (UTF-8, NFC, ohne Nullbyte, innerhalb der Grenzen), keine doppelten Begriffe.

Ergebnis Phase 1: alle 14 Ziele je 5 Minuten ohne Fund, kein neuer Fall unter `testdata/fuzz/`. Ausführungen:

| Ziel | Ausführungen | Ziel | Ausführungen |
|---|---|---|---|
| rec.FuzzDecode | 27,4 Mio. | shamir.FuzzShareFromBytes | 34,2 Mio. |
| rec.FuzzIsNFC | 29,1 Mio. | shamir.FuzzCombine | 25,4 Mio. |
| keys.FuzzParseWordlist | 14,5 Mio. | envelope.FuzzParseAndOpen | 12,1 Mio. |
| keys.FuzzSeedFromWords | 14,0 Mio. | store.FuzzDecodeRecords | 24,7 Mio. |
| keys.FuzzDecodeGenerationCert | 18,2 Mio. | smtpd.FuzzCommands | 3,6 Mio. |
| keys.FuzzOpenKeystore | 24,5 Mio. | smtpd.FuzzData | 8,5 Mio. |
| shamir.FuzzShareFromWords | 20,4 Mio. | ingest.FuzzTerms | 3,1 Mio. |

Die Ziele von `store`, `smtpd` und `ingest` liefen auf dem Stand nach den Korrekturen aus den Prüfungen. Bei `smtpd` und `ingest` zeigt der Fuzzer zeitweise 0 Ausführungen je Sekunde; das ist das Minimieren neuer Eingaben, keine einzelne Eingabe brauchte länger als eine halbe Sekunde (geprüft). Der Regressionsfall `revokes = 0` aus Phase 0 liegt zusätzlich mit dem neuen Typ-String `user-gen` vor.
