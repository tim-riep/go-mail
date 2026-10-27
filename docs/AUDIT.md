# Prüfpaket für das externe Audit

Stand: 27.10.2026, Arbeitsbranch `claude/quirky-keller-hjsl5i`: Code bei Commit ef083df (Pakete 01 bis 16 einschließlich 13, 14, 15b und 15h zusammengeführt), Dokumente bei 8928e2e (bereinigte `docs/SPEC-ISSUES.md` mit S88 bis S92, M1-Kriterien A–F in `docs/ORCHESTRATION.md` Abschnitt 1); zwischen beiden Commits hat sich kein Code geändert. Grundlage: `docs/PLAN.md` Version 1.4 (im Folgenden „Spezifikation“, Abschnittsnummern ohne Präfix), `docs/PHASE2-KLAERUNGEN.md` (Kn), `docs/DECISIONS.md` (Dn), `docs/SPEC-ISSUES.md` (Sn), `docs/QUESTIONS.md` (Qn), `internal/translog/doc.go` (verbindlicher Entwurf des Transparenzlogs) und `docs/ORCHESTRATION.md` (Verlauf der Prüfungen je Paket).

Noch nicht im Branch und **in Arbeit (siehe ORCHESTRATION, Verlauf)**: die Nacharbeiten der Zeremonie 15i (SIGPIPE), 15l (stderr-Terminal, geschlossenes fd 2), 15m (Abbruchpfad ohne wartende Terminal-Aufrufe) und 15n (dritte Nacharbeit der Terminalregeln: Schreibfehler und gestoppte Ausgabe im normalen Pfad, Doppel-Enter), 13e (zwei `/dev/tty`-Deskriptoren aus verschiedenen Sitzungen) sowie 09b (S13 für Metadaten und Indexsegmente, gemeinsame Begriffsregeln, Testlücken aus 09). Wo dieses Dokument Grenzen der Terminalbehandlung oder der Übernahme nach 2.2 Punkt 4 nennt, beschreibt es den Stand bei ef083df; die Aufträge liegen unter `docs/tasks/15i-*.md`, `15l-*.md`, `15m-*.md`, `15n-*.md`, `13e-*.md`, `09b-*.md`.

Dieses Dokument wiederholt die Spezifikation nicht. Es sagt, was geprüft werden soll, wo die Belege liegen, welche Grenzen bekannt sind und welche Fragen offen sind.

---

## 1. Zweck und Umfang

### 1.1 Zweck

Der PoC ist nach 10.2 abgeschlossen, wenn alle Pflichttests grün sind und die Trennung von Client und Server auf getrennten Maschinen nachgewiesen ist. Vor jedem Betrieb mit echten Mails verlangt 10.2 zusätzlich eine unabhängige Prüfung von `keys`, `shamir`, `envelope` und des SMTP-Empfangs sowie von Betriebssystemrechten, Logging und Deployment. Dieses Paket bereitet diese Prüfung vor und erweitert sie um die Teile, deren Sicherheit das Versprechen aus 8 und die Garantien aus 2.7 tragen: Transparenzlog, Zeuge, Schlüsselzeremonie und die Prüfregeln des Clients.

### 1.2 Was M1 abdeckt

M1 ist in `docs/ORCHESTRATION.md` Abschnitt 1, „M1-Kriterien A–F“, festgelegt. Die Tabelle nennt, was davon im Branch gebaut ist.

| Bereich | Umfang im Branch | Pakete |
|---|---|---|
| Kryptografische Formate | kanonische Kodierung (3.6), Schlüsselableitung und Schlüsselspeicher (2.2, 2.3), Shamir mit Wortformat, `.gml` mit HPKE, STREAM und Signatur (3.1 bis 3.5), Kopffeld 8 `version` | `rec`, `keys`, `shamir`, `envelope`, `words` |
| Ablage | Datenverzeichnis nach 4, atomares Schreiben, POSIX-Satzsperren (OFD unter Linux), Rechte 2770/0660, Rollensperren, `gomail-server init` | `store`, `cmd/gomail-server` |
| Empfang | SMTP nach 5.1 ohne TLS, Verschlüsselung beim Lesen, Spool-Transaktion, Begriffslisten, flüchtiger Schlüssel, Selbstprüfung jeder eigenen Signatur ohne Schlüssel, Logprüfungen bei RCPT, Beginn und Commit | `smtpd`, `ingest` |
| Postfächer | Epochenkette mit Gründen und `discards`, sofortige und geplante Epochen, Vorrat, Teilen, Entzug, Vertretung (Art 3, ohne Befehl), Wiederherstellungsempfänger (nur interne API), Ordnerliste je Epoche | `store`, `client` |
| Generationen | `device lost`, `restore`, `keygen --shares`, `wrap-accept`, Prüfvermerke, Übernahme nach 2.2 Punkt 4 | `client`, `cmd/gomailctl` |
| Suche und Flags | Indexsegmente je Gerät, Zusammenfassen ab 16, Suche mit den Operatoren aus 5.4, Flags mit Versionsregel (K4) | `client` |
| Transparenzlog | `tlog`-Kacheln, Gültigkeitsregeln je Eintragsart, Audit-Index, signierte Köpfe mit Zeitzeile, Zeugenquorum, zurückgehaltene Einträge, Vermerke der Clients, 24-Stunden-Regel, Reparatur | `translog`, `loghttp`, `client`, `ingest` |
| Zeuge | acht Regeln, Fork-Nachweis, Pull über HTTP | `witness`, `cmd/gomail-witness` |
| Zeremonie | `init --shares`, Probe-Rekonstruktion, `ingest-rotate`, `reshare`, `succeed` (ohne Kompromissfall), `publish` über das Log, Terminalregeln, Commit-Fenster | `ceremony`, `cmd/gomail-ceremony` |
| Betrieb | Zwei-Maschinen-Skript (lokaler Modus durchgelaufen, NFSv4-Pfad nur vorbereitet, D83), Messumgebung | `scripts/two-host-test.sh`, `internal/bench` |

### 1.3 Was M1 nicht abdeckt

Nicht gebaut und nicht Gegenstand dieses Audits, außer als Randbedingung:

- **Löschen von Epochen** (Crypto-Shredding nach 2.6, Grund `deleted`; D63, PHASE2-KLAERUNGEN „Bewusst nicht in Phase 2“). Damit fehlen auch die Bestätigungsvermerke der Clients aus 2.6.
- **Volltextindex** im Client (6.4) und damit `--server-search off` (Q3).
- **Kopplung neuer Geräte per QR-Code** (2.7, Tabelle „Neue Geräte“). Ein zweites Gerät oder eine Wiederherstellung ohne vorhandenes Gerät vertraut beim ersten Kontakt (siehe 5.4, R22).
- **TLS, STARTTLS, SMTP-Anmeldung, Schutz gegen Missbrauch** über die Grenzen aus 5.1 hinaus (5.1, 10.2 Punkt 1). Der Server bindet ohne `--isolated-test-network` nur an Loopback.
- **Padmé** und jeder andere Schutz gegen Verkehrsanalyse (8 „Größen und Zeitpunkte“).
- **Hardware-Schlüssel** und Schlüssel je Gerät (2.2 letzter Absatz).
- **IMAP**, Webmail, HTTP-API zwischen Client und Server (das Datenverzeichnis wird dem Client per NFS bereitgestellt, 9.1).
- SPF, DKIM, DMARC; Absenderprüfung (7 „Was die Ingest-Signatur aussagt“).
- Suite 2 (3.5); mehrere Zeugen im Betrieb mit echten Mails (2.7: „Mehrere Zeugen … folgen vor dem Betrieb mit echten Mails“; gebaut und getestet ist das Quorum für beliebige n).
- Befehle, die an offenen Fragen hängen: `mailbox rotate` (Q7), `recovery …` (Q1), `--delegate` (Q6), signierte Einladungen (Q2), `succeed --compromised` (Q19, gesperrt).

---

## 2. Bedrohungsmodell je Rolle

Grundlage ist 8 („Was wer sehen kann“, „Sicherheitsversprechen“, „Bedrohungsmodell“) und 2.7 („Garantien“, „Nicht garantiert“). Die Tabelle ordnet die Rollen den Entscheidungen zu, die das Modell im Code festlegen.

| Rolle | Fähigkeiten im Modell | Was erkannt oder verhindert wird | Was nicht | Quellen |
|---|---|---|---|---|
| **Server-Prozess** (Root auf der Server-Maschine, hält den Ingest-Schlüssel) | sieht jede eingehende Mail im Klartext; signiert Metadaten, Begriffslisten und Logköpfe mit dem Ingest-Schlüssel; schreibt das Datenverzeichnis | gespeicherte Daten bleiben unlesbar (kein privater Schlüssel eines Mitglieds im Datenverzeichnis); verschiedene Sichten nur mit Zeugen (siehe unten); Metadaten mit Empfangszeit ab `valid_from` von `ingest-<g+1>.cert` werden von g nicht mehr angenommen | Klartext neuer Mails; gefälschte Mails mit gültiger Ingest-Signatur (`TestForgedMailWithIngestKeyIsAccepted` zeigt, dass der Client sie annimmt: die Signatur belegt nur die Annahme durch den Ingest-Schlüssel, 7); Verfügbarkeit | 8, 7, D71, D73, D81, Q4 |
| **Schreibzugriff auf Datenverzeichnis und `log/`** (Server, kompromittierter Client, NFS-Angreifer mit Gruppenrechten) | Dateien anlegen, ändern, löschen, zurückspielen; Einträge am `log/lock` vorbei schreiben; `tree.rec` zurücksetzen; Köpfe löschen | Entfernen oder Ändern von Logeinträgen unter einem signierten Kopf (Konsistenzbeweis); Zurückspielen von `epoch.rec`, `mailbox.rec`, Metadaten, `folders.gml` gegenüber einem Client mit Zustand; `mailbox.rec` hinter der neuesten geloggten Epoche (`ErrRollback`, auch im Server); ungeloggte Adresszuordnung; Zurückhalten eines eigenen Eintrags über 24 Stunden; fremde Epochennummern (Gültigkeitsregel „Unterzeichner ist Mitglied“) | jede Form des Vorenthaltens und der dauerhaften Blockade (2.7 verspricht Erkennung, nicht Verfügbarkeit); Rückschritt um Einträge seit dem letzten veröffentlichten Kopf gegenüber einem neuen Prozess (R12) | `translog/doc.go` „What write access to log/ gives an attacker“, D71, D75 (3), D78, D81 (3), D88 (2) und (4) |
| **Dieb mit altem Schlüsselspeicher** (und Passphrase) eines Mitglieds | hat Identität und Entpackschlüssel einer Generation; kann bis zum Widerruf alles, was das Mitglied kann | nach dem Logeintrag der neuen Generation: keine loggbare Epoche mehr (`ErrOrder`), keine gültige Datei außerhalb des Logs (Verpackungen, Flags, Segmente, `folders.gml`) mit der widerrufenen Generation, außer bei einem Client mit Prüfvermerk (nächste Spalte); keine Neuausstellung von Verpackungen auf Grundlage seiner Vorlagen (Q15, strengste Lesart); `device lost` lässt sich nicht durch Strohmann-Postfächer festnageln | was er vor dem Widerruf gelesen oder als gültigen Logeintrag hinterlassen hat; Dateien, die ein Client vor dem Widerruf geprüft hat, bleiben für diesen Client gültig (Prüfvermerk `Checked` in `state.json`, Übernahme mit Neusignatur nach 2.2 Punkt 4 und S13; im Branch für Verpackungen und `folders.gml`, R27); ein vor dem Widerruf angelegtes Postfach, das den Benutzer nennt, wird nach `restore`/`device lost` beim ersten Kontakt übernommen (R20) | 2.2 Punkt 4, D84, D88, Q13, Q15, S13, S75 |
| **Kolludierende Mitglieder, Strohmann** | gültige eigene Generation; Gegensignaturen (`wrap-accept`) auf beliebige Dateien; frei signierte Vermerke | Strohmann-Verpackungen werden nicht neu ausgestellt (nur Mitgliederliste der signierten `epoch.rec` und Vorlagen gültiger Mitgliedsgenerationen); ein Strohmann-Postfach blockiert keine Generation | dauerhafte Sperre eines Mit-Benutzers über einen frei signierten Vermerk (R23); Verwerfen bereits begonnener Epochen über einen früh gewählten Beginn (R29); was ein Mitglied gelesen hat, behält es (2.5) | D84, D88, Q15, S35, S72 |
| **Zeugen** | signieren Köpfe mit eigenem `note`-Schlüssel; sehen nur Köpfe und Konsistenzbeweise (Hashes), keine Einträge | ein Zeuge signiert nie zwei Köpfe gleicher Größe mit verschiedenem Hash; geteilte Sicht ist ausgeschlossen, solange weniger als `2·min − n` Zeugen mit dem Server kolludieren; Pin und `witnesses.rec` verlangen `2·min > n` | Server plus `2·min − n` Zeugen (im PoC mit 1 aus 1: der eine Zeuge, R15); Verweigerung durch Zeugen blockiert nach 24 Stunden (Erkennung, keine Verfügbarkeit) | 2.7, D72 (5), D74, S50, `translog/doc.go` „Witness quorum“ |
| **Netz** | liest und verändert SMTP (ohne TLS), HTTP zwischen Server und Zeuge (ohne TLS), NFS (sec=sys) | Integrität von Köpfen und Beweisen über Signaturen; Zeuge folgt keinen Weiterleitungen, Körper begrenzt | Vertraulichkeit des SMTP-Verkehrs (8: nicht im Modell); NFS mit sec=sys gibt jedem, der eine gid fälschen kann, Schreibzugriff auf das Datenverzeichnis; Überlastung des Log-HTTP (R8) | 5.1, 8, 9.1, D74, D80 (5), D83 |
| **Admin-Schlüssel** | signiert Adresszuordnungen (Einladungen sind noch unsigniert, Q2) | Umzuordnung einer Adresse ist ohne Logeintrag unwirksam und im Log sichtbar; `valid_from` steigt streng je Adresse | Rückdatierung einer Zuordnung (Q9, R18); kein Gültigkeitsende einer Admin-Generation nach einem Wechsel (Q8) | 2.3, D72 (10), D80 (7), Q8, Q9 |
| **Zeremonie-Teilnehmer, Anteilsinhaber** | k Anteile rekonstruieren den Plattform-Root | Anteile erscheinen nur am Terminal und nur dem jeweiligen Inhaber; Probe-Rekonstruktion vor jedem Schreiben | k kolludierende Inhaber haben den Root; `reshare` macht alte Anteile nicht ungültig (S31); Kompromittierung der Identität ist nicht abbildbar (Q19, R17) | 2.3, D82, D85, S31 |

Ausdrücklich außerhalb des Modells (8): ein kompromittiertes, entsperrtes Gerät eines Mitglieds; Seitenkanäle; Angreifer im Netz zwischen Absender und Server.

---

## 3. Vertrauenszonen

| Zone | Inhalt | Wer schreibt | Schutz | Annahme |
|---|---|---|---|---|
| **Client-Verzeichnis** (Standard `~/.config/gomailctl`, nie im Datenverzeichnis) | `keystore` (AES-256-GCM, Argon2id), Kopie der eigenen `user.rec`, `state.json` (Referenzkopf als signierte `note`, Pending-Einträge, je Postfach höchste Epoche mit Hash, verworfene Epochen, Beginnzeiten, gesehene Versionen, Prüfvermerke `Checked`, bestätigte Wiederherstellungsschlüssel, `Checkpointed`, `Unconfirmed`), Audit-Index des Logs, Kopien erster Einträge (`new-mailboxes/`), `lock` | nur der Client des Benutzers | Rechte 0600/0700, atomares Schreiben, Prozesssperre | Schreibzugriff auf diese Zone ist eine Kompromittierung des Clients. Strukturprüfungen des Audit-Index schützen gegen Beschädigung und Verwechslung, nicht gegen einen Angreifer (D57, D76, D78 (4); `translog/doc.go` „Audit“). Der gespeicherte Referenzkopf wird ohne erneute Signaturprüfung geparst (`doc.go` „Tasks“, Punkt 14, `TODO(ask)`). Unveränderliche Regel: kein Pfad verkleinert den lokalen Zustand eines Postfachs (D84 (2), S74). |
| **Pin** `identity-<gen>.pin` | Identitätsgeneration und Schlüssel, Liste aller Identitätsgenerationen (Feld 8), Origin, Zeugen, Quorum, Entwicklungskennzeichen | Zeremonie (`init`, `succeed`), verteilt vom Betreiber per Client-Update | **unsigniert**; außerhalb des Datenverzeichnisses (Server: mit aufgelösten Symlinks geprüft); höchstens 64 KiB; Quorum- und Listenregeln beim Dekodieren | Der Pin ist der Vertrauensanker von Client und Server. Wer ihn ersetzen kann, bestimmt Identität, Zeugen und Origin. Ein Entwicklungs-Pin wird von Produktionsbinaries abgelehnt (D87 (3), D88 (1)). Kein Feld 7 für Widerrufe (Q8). |
| **Datenverzeichnis** | öffentliche Schlüssel, signierte Datensätze, verschlüsselte `.gml`, `addresses.json` und `invites/` (Klartext-Arbeitsdateien), `witnesses.rec` (unsignierte Arbeitskopie), `log/`, `locks/` | Server, Clients, `gomail-ceremony publish`, `gomail-server init` | Gruppe `gomail`, 2770/0660, keine privaten Schlüssel | nicht vertrauenswürdig für Integrität; jede Prüfung des Clients geht vom Schlimmsten aus (2.7). Sichtbar bleiben Größen, Zeitstempel, Mitgliedschaften, Adresszuordnungen, Trefferzahlen (4, 8). |
| **Server-Maschine** | Ingest-Schlüssel (0600, außerhalb des Datenverzeichnisses), Pin, Prozess mit Klartext während des Empfangs, flüchtiger Schlüssel für `work/` (mit `mlock`) | Betreiber | Rollensperre `locks/server` (seit 14 vor dem Laden des Ingest-Schlüssels), Prüfung der Plattform gegen den Pin beim Start | Root dort sieht neue Mails (8). |
| **Admin** | Admin-Schlüssel | Administrator, getrennt vom Server | `address add` verlangt den Schlüssel außerhalb des Datenverzeichnisses | wie Tabelle in 2 |
| **Zeugen** | `note`-Schlüssel (0600), Zustandsverzeichnis (0700, gesperrt) mit dem letzten gegengezeichneten Kopf je Origin, Fork-Nachweis | Betreiber des Zeugen, andere Maschine | Zustand vor der Gegensignatur dauerhaft; Fork beendet den Dienst dauerhaft (Exit 3) | unabhängiger Betreiber; `--log-key` wird nach einer Ingest-Rotation von Hand ergänzt (der Zeuge prüft keine Zertifikate). |
| **Zeremonie-Rechner** | Plattform-Root (nur im Speicher), Anteile (nur am Terminal), Schlüsselverzeichnis `--keys` (0700, eigener Benutzer, kein Symlink im letzten Element, `os.Root`), Export | Zeremonie | offline, Live-System; Terminalregeln (D82 (2), D85 (4)) | Die Uhr des Rechners bestimmt `valid_from` (R7). Getippte Anteile bleiben bis zur Speicherbereinigung in Go-Zeichenketten (S33). Betriebsregel: nur an der Linux-Konsole, ohne tmux, screen, script oder Emulator mit Verlauf (S32). |

---

## 4. Kryptografische Bausteine und Signaturdomänen

**Bitte an die Prüfer:** Die Trennung der Domänen ist ein Schwerpunkt. Prüft insbesondere, dass kein Schlüssel zwei Nachrichtenmengen signiert, die sich überschneiden können, und dass jede Ableitung und jede AAD eindeutig getrennt ist.

### 4.1 Bausteine (keine eigenen Primitive)

| Baustein | Herkunft | Verwendung | Code | Vektoren |
|---|---|---|---|---|
| Ed25519 | `crypto/ed25519` | alle Signaturen | `internal/keys/cert.go` (`Sign`, `Verify`, mit Präfix nach 3.7); die Logsignatur ruft `ed25519.Sign` direkt über den Kopftext (`logSigner.Sign` in `internal/translog/head.go`, siehe 4.2) | `internal/keys/testdata/cert_vectors.json` |
| X25519, HPKE (DHKEM X25519, HKDF-SHA256, AES-256-GCM, Base-Modus) | `crypto/ecdh`, `crypto/hpke` | Verpacken des Dateischlüssels (3.2) | `internal/envelope` | `internal/envelope/testdata/hpke` (RFC 9180, Regressionstest) |
| AES-256-GCM in STREAM | `crypto/aes`, `crypto/cipher` | Inhalt (3.3) | `internal/envelope` | `internal/envelope/testdata/*.gml`, `vectors.json` |
| AES-256-GCM ohne STREAM (eine Nachricht je Nonce) | `crypto/aes`, `crypto/cipher` | Schlüsselspeicher; ausgelagerte Spool-Daten in `work/` unter dem flüchtigen Schlüssel | `internal/keys/keystore.go`, `internal/ingest/queue.go` | `internal/keys/testdata/keystore_vector.json` |
| HKDF-SHA256 | `crypto/hkdf` | Benutzer- und Plattformschlüssel (2.2, 2.3), Inhaltsschlüssel (3.3) | `internal/keys/derive.go`, `internal/envelope` | `internal/keys/testdata/derive_vectors.json` |
| HMAC-SHA256 | `crypto/hmac` | Suchmarken (6.1) mit dem Indexschlüssel der Epoche | `internal/client/index.go` | – |
| Argon2id | `golang.org/x/crypto` | Schlüsselspeicher (Grenzen vor dem Aufruf geprüft) | `internal/keys/keystore.go` | `internal/keys/testdata/keystore_vector.json` |
| Shamir über GF(256) | eigene Umsetzung nach OpenBao-Vorbild, ohne Tabellen | Plattform-Root, Benutzer-Seed (`--shares`) | `internal/shamir` | `internal/shamir/testdata/vectors.json` |
| Merkle-Baum, Beweise | `golang.org/x/mod/sumdb/tlog` (hinter `MaxTreeSize = 2^40`, weil `tlog` ab 2^62 nicht zurückkehrt) | Transparenzlog | `internal/translog` | – |
| `note` | `golang.org/x/mod/sumdb/note` | Logköpfe, Zeugensignaturen | `internal/translog/head.go`, `internal/witness` | – |
| NFC-Prüfung, NFKD der Worteingabe | `golang.org/x/text` | kanonische Kodierung (3.6), Worteingabe (2.2) | `internal/rec`, `internal/words` | `internal/rec/testdata/records.json` |
| Zufall | `crypto/rand` (in Tests injizierbar, D03) | Schlüssel, Nonces, IDs | überall | – |

Die Vektoren der Phase-0-Pakete dürfen sich nicht ändern; jeder Umsetzungsauftrag prüft sie vor dem Commit auf Byte-Gleichheit (`docs/tasks/00-vorgaben.md`).

### 4.2 Signaturdomänen nach 3.7

Regel: `sig = Ed25519("gomail/v1/sig/" || Kurzname || 0x00 || signierte Bytes)`. Die signierten Bytes sind bei Datensätzen die kanonische Kodierung ohne Signaturfeld, die selbst mit Typ-String und Nullbyte beginnt (3.6 Regel 5); bei `.gml` die Struktur `gomail/v1/rec/signed` mit `file_hash`, `signer_type`, `signer_id`, `signer_gen` und dem art-spezifischen Datensatz `extra` (S53). Die Kurznamen stehen in `internal/keys/cert.go`; `TestDomainTable` und `TestDomainsOfVersion13` (`internal/keys`) prüfen Eindeutigkeit und Vollständigkeit, `TestSignatureDomainBinding` und `TestUnknownKindNeverSignedOrVerified` (`internal/envelope`) die Bindung an die Dateiart.

| Schlüssel | signiert unter Kurzname | Prüfpunkt für das Audit |
|---|---|---|
| Benutzer-Root | `user-gen`, `user` | Root nur kurz aus dem Seed; zwei Domänen, ein Schlüssel |
| Benutzer-Identität (Generation g) | `epoch`, `checkpoint`, `wrap-accept`, `.gml` der Arten `wrap`, `meta` (Flags ab Version 2 **und** `folders.gml`, die als Art `meta` abgelegt ist, S57), `index` | Bitte prüfen: `folders.gml` und Metadaten teilen die Domäne `meta`; getrennt werden sie über Kopf (`file_id`, Ort), Inhaltstyp und `extra`. Ist ausgeschlossen, dass eine Signatur über eine Ordnerliste als Metadatenversion gilt oder umgekehrt? |
| Plattformidentität g | `platform-cert`; `platform-succ` für g+1 | Nachfolge signiert die vorherige Generation; im Kompromissfall gibt es keinen Widerruf (Q19) |
| Admin | `address` (`invite` ist definiert, Einladungen sind aber unsigniertes JSON, Q2) | – |
| Ingest g | `.gml` der Arten `meta` (Version 1) und `pending`; **zusätzlich Logköpfe als `note`** mit Signer-Name `gomail-log` (Q4) | Die Trennung beruht darauf, dass ein `note`-Text kein Nullbyte enthält, jede 3.7-Nachricht aber eines (Begründung an `NewLogSigner`, `internal/translog/head.go`). Bitte bestätigen. `signer_id` der Ingest-Signatur ist 16 Nullbytes (S55). |
| Zeuge | `note`-Gegensignatur über denselben Kopftext | eigener Schlüssel, keine 3.7-Domäne |
| – (definiert, ungenutzt) | `mail` (`keys.DomainMail`, `envelope.KindMail`) | Mail-Dateien tragen keine Signatur; der Client lehnt eine Mail mit Trailer ab (`internal/client/read.go`). Gebunden sind sie über `mail_hash` (SHA-256 der ganzen verschlüsselten Datei, Feld 4 von `gomail/v1/rec/mail-meta`) in den signierten Metadaten der Art `meta`. |

### 4.3 Weitere Domänen-Strings

| String | Zweck | Code |
|---|---|---|
| Salt `gomail/v1/user-seed`, `gomail/v1/platform-root`; Labels `gomail/v1/user/{root,identity,unwrap}`, `gomail/v1/platform/{identity,admin,ingest}` mit `0x00 || uint32` | HKDF-Ableitung (2.2) | `internal/keys/derive.go` |
| `gomail/v1/wrap` `0x00` Typ ID Generation (36 Byte fester Breite) | HPKE-`info` (3.2) | `internal/envelope/envelope.go` |
| `gomail/v1/aad/wrap`, `gomail/v1/aad/block` | AAD über Präambel und Kopf (3.2, 3.3) | `internal/envelope` |
| `gomail/v1/content` | HKDF-`info` des Inhaltsschlüssels | `internal/envelope` |
| `gomail/v1/aad/keystore` | AAD des Schlüsselspeichers über Kopf und Parameter | `internal/keys/keystore.go` |
| `gomail/v1/work` `0x00` Postfach Epoche Mail-ID | AAD der ausgelagerten Spool-Daten (AES-256-GCM unter dem flüchtigen Schlüssel) | `internal/ingest/queue.go` (`spillAAD`) |
| `gomail/v1/share` | Prüfsumme des Anteilsformats | `internal/shamir/share.go` |
| `gomail/v1/translog-anchor` | Fingerabdruck der Identitätsliste im Audit-Index | `internal/translog/state.go` |
| Blatt-Hash `SHA-256(0x00 || Eintrag)`, Knoten nach RFC 6962 | Merkle-Baum | `tlog` |

Suchmarken sind `HMAC(Indexschlüssel, Begriff)` ohne eigenes Präfix; der Begriff trägt selbst sein Präfix (`from:`, `day:` …, 5.4). Bitte prüfen, ob das für alle Begriffsarten eindeutig ist.

---

## 5. Bekannte Grenzen und Restrisiken

Nummeriert R1 bis R40. „In Arbeit“ heißt: ein Auftrag liegt vor, das Ergebnis ist nicht im Branch (siehe ORCHESTRATION).

### 5.1 Zeremonie und Terminal

- **R1 Ctrl-S-Fenster.** Ab `openTerm` ist die Software-Flusssteuerung auf stdin und stdout aus (D85 (4)); ein XOFF, das vor dem Start getippt wurde, hält die Ausgabe nur bis dahin an, also bevor ein Anteil erscheint (`TestPTYFlowControl`). Offen: Liegt stderr auf einem **dritten** Terminal, bleibt dessen Flusssteuerung an; ein XOFF dort blockiert das Löschen auf stderr, das vor dem Löschen auf stdout läuft, und der Anteil bleibt nach dem Abbruch auf stdout stehen. In Arbeit: 15l. Offen aus der Prüfung von 15m: Ein angehaltenes oder volles stderr-Terminal (an der Linux-Konsole genügt Scroll Lock) hält im normalen Pfad die Aufforderung „Anteil notiert?“ fest, während der Anteil auf stdout sichtbar bleibt; dasselbe gilt für ein wiederholtes `TCOOFF` auf stdout. Stand: in Arbeit (15n). Quelle: D82 „Für AUDIT“, Q17, `docs/tasks/15l-ceremony-stderr-terminal.md`, `docs/tasks/15n-ceremony-blocked-output.md` Fund 2.
- **R2 Fenster vor dem Löschen.** Zwischen der Ausgabe eines Anteils und dem Löschen (Bestätigung des Inhabers oder Abbruchpfad) liegt ein kurzes Fenster. Abfangbare Signale laufen auch darin über den Abbruchpfad, und nach dem letzten Löschen erscheint nichts mehr (`TestSignalDisplayRace`). SIGKILL und SIGSTOP lassen sich nicht abfangen: der Anteil bleibt stehen, Echo und Flusssteuerung bleiben aus (`stty sane`). Verlauf und Scrollback eines Terminal-Emulators liegen außerhalb des Programms (Betriebsregel S32). Offen aus der Prüfung von 15m: Ein Doppel-Enter mit Abstand bestätigt für den nächsten Inhaber. Kommt das zweite Enter erst nach dem Verwerfen der Eingabe an, beantwortet es die Aufforderung für Inhaber 2, und dessen Anteil erscheint, während Inhaber 1 noch vor dem Bildschirm sitzt (`TestPTYDoubleEnter` prüft nur beide Enter in einem Schreibvorgang). Stand: in Arbeit (15n). Quelle: D82, Paketkommentar `cmd/gomail-ceremony/main.go`, `docs/tasks/15n-ceremony-blocked-output.md` Fund 3.
- **R3 Zwei-Terminal-Betrieb.** stdin und stdout dürfen verschiedene Terminals sein (S78). Seit 15b wird die Flusssteuerung auf beiden geräumt, Bildschirmschreiben läuft nicht unter der Sperre des Signalhandlers, und jeder Schritt des Abbruchpfads wartet höchstens 400 ms (`TestPTYTwoTerminals`). Offen: `TCSETSF` auf stdin wartet unter Linux, bis ein blockierter Schreibvorgang auf demselben Terminal abgeflossen ist; liegen stdin und stderr oder stdout auf einem angehaltenen oder vollen Terminal, kann der Abbruch hängen, und ein angehaltenes oder volles stdout-Terminal verliert das Löschen beim Exit. In Arbeit: 15m. Offen aus der Prüfung von 15m: Teilt ein anderer Prozess die offene Dateibeschreibung von stdout (Hintergrundjob derselben Shell) und setzt `O_NONBLOCK`, endet ein Clear auf einem vollen Terminal mit `EAGAIN`. Der Fehler wird verworfen, das Löschen gilt als erledigt, und der Anteil bleibt stehen, auch bei Exit 130; im normalen Pfad wird danach schon Inhaber 2 aufgerufen. Stand: in Arbeit (15n). Quelle: Q17, D85 (4), `docs/tasks/15m-ceremony-abort-path.md`, `docs/tasks/15n-ceremony-blocked-output.md` Fund 1.
- **R4 SIGPIPE in `gomail-ceremony`.** Alle Prompts gehen nach stderr. Ist stderr eine Pipe ohne Leser, beendet die Go-Laufzeit das Programm beim nächsten Schreiben durch SIGPIPE, **ohne** Abbruchpfad: ein gezeigter Anteil bleibt auf dem Bildschirm, die Flusssteuerung bleibt aus. `gomailctl` ist dagegen geschützt (SIGPIPE für die ganze Laufzeit umgeleitet, D86 (2), `TestRelayBrokenPipe`). In Arbeit: 15i, mit den Ergänzungen aus 15m (SIGPIPE schon vor `openTerm`, SIGXFSZ). Quelle: `docs/tasks/15i-ceremony-sigpipe.md`.
- **R5 Geschlossenes oder nicht beschreibbares fd 2.** Ist fd 2 beim Start geschlossen, belegt die Laufzeit den Platz selbst; Prompts sind unsichtbar, die Zeremonie wartet an einem unsichtbaren „Anteil notiert?“. In Arbeit: 15l, 15m.
- **R6 Zwei `/dev/tty`-Deskriptoren in `gomailctl`.** Zwei über `/dev/tty` geöffnete Deskriptoren aus verschiedenen Sitzungen gelten als dasselbe Terminal (`sameTerminal` vergleicht nur `st_rdev` 5:0). Beobachtet: Echo auf A aus, Wörter auf A, Löschen auf B; nichts sichtbar, kein Leck. In Arbeit: 13e (Q21, D86).
- **R7 Zeremonie-Uhr ohne NTP.** `valid_from` von Zertifikaten und Nachfolgen kommt aus `--valid-from` oder der Uhr des Offline-Rechners; ein `valid_from` in der Vergangenheit wird bei `ingest-rotate` abgelehnt (S26). `init` zeigt die Uhr vor dem ersten Prompt, `succeed` beim Signieren; das RUNBOOK verlangt, die Uhr vorher zu stellen. Eine falsch gehende Uhr verschiebt den Umschaltzeitpunkt der Ingest-Generation (Mailverlust beim Client, kein Leck). Quelle: D82 (6), S26.

### 5.2 Log, Köpfe, Zeit

- **R8 `loghttp` ohne Verbindungsobergrenze und Ratenbegrenzung.** Zeitlimits und Größengrenzen sind gesetzt, eine Grenze für gleichzeitige Verbindungen und Anfragen fehlt; jede `/cosign`-Anfrage öffnet und prüft Signaturen. 10.2 verlangt das vor dem Betrieb. Quelle: D80 (5), `internal/loghttp/loghttp.go`, `translog/doc.go` „Tasks“ 11 (e).
- **R9 Testsperre ohne Authentifizierung.** Die Prüfung nach 9.1 weist nach, dass POSIX-Satzsperren über das Dateisystem wirken, nicht wer sie hält. Jeder Prozess mit Schreibzugriff auf `locks/` kann eine Seite vortäuschen. Der Server prüft die Client-Sperre nur mit `--require-client-lock`, und kein Befehl hält sie dauerhaft (S82, S83). Quelle: D81 (4), S84.
- **R10 `newestHeadSize` linear in der Zahl der Kopfdateien.** Wer viele Dateien in `log/heads/` anlegt, verlangsamt jeden Lauf (Denial of Service, keine Fehlannahme). Quelle: D78 (7), D81 „Für AUDIT“, `TestNewestHeadSize`.
- **R11 Fremder Pin bei leerem `platform/` ohne Kopf.** `publish --replace-witnesses` ersetzt `witnesses.rec` nur nach bestandenen Prüfungen gegen den Pin; ist `platform/` leer und noch kein Kopf veröffentlicht, gibt es nichts, woran ein fremder Pin scheitert. Wer so schreiben kann, kann die Datei ohnehin direkt schreiben. Der Server warnt bei Abweichung zwischen Pin und `witnesses.rec` nur. Quelle: D85 „Restfall“, `internal/ceremony/api.go`.
- **R12 Rückschritt um Einträge seit dem letzten veröffentlichten Kopf.** Setzt ein Angreifer `tree.rec` auf n zurück und entfernt `entries/<n+1>.rec`, und deckt kein veröffentlichter Kopf den Bereich, nimmt ein **neuer** Serverprozess (Neustart) den kleineren Baum an; der laufende Prozess verweigert (`operatorCur`). Von den Clients bemerken es nur die Schreiber der verlorenen Einträge über ihre Pending-Prüfung (`ErrConsistency` oder `ErrWithheld`) und hängen neu an. Fenster: die Einträge seit dem neuesten veröffentlichten Kopf, normalerweise die eines `HeadInterval`. Ohne Zeugen wird kein Kopf veröffentlicht (`heads/<n>.sig` erst mit dem Quorum der Gegensignaturen); dann wächst das Fenster, bis die Clients nach 24 Stunden stoppen (`ErrStale`). Quelle: D81 Nachtrag 15d, `translog/doc.go` „What write access …“, `TestOperatorShrunkTree`, `TestLogPendingAfterRollback`.
- **R13 `RepairTree`.** Betreiberaktion unter der Serversperre. Sie prüft die Logsignatur eines Kopfs mit jedem gültigen Ingest-Zertifikat, nicht nur mit der Generation, die die Kopfzeit deckt (Lesart 11b (c); die deckende Generation prüfen `PublishHead` und der Client). Verwaiste Einträge jenseits der reparierten Größe werden gemeldet, nie gelöscht. Ein kombiniertes Verkürzen bleibt still und wird nur über die Zeugen erkannt. Eine Sicherung von `log/` muss jeden Kandidaten decken, den ein Zeuge je gegengezeichnet hat; ohne sie ist der einzige Ausweg ein neuer Origin mit neuen Pins (Q10 Punkt 4). Quelle: D80 (3), D81, `translog/doc.go`.
- **R14 24-Stunden-Regel und Zeitquelle.** Kopfzeiten sind die Uhr des Servers, `Pending.At` die Uhr des Clients. Köpfe mehr als `MaxClockSkew` (5 min) in der Zukunft lehnen Zeuge und Client ab; die Zeit darf nie rückwärts laufen, gleiche Zeit ist erlaubt. Ein Server kann eine alte Größe mit frischer Zeit weiter signieren (Zeugen sehen das nicht); dagegen steht nur die Pending-Regel des anhängenden Clients mit `MaxPendingHeadAge = 23 h`. Ein Ausfall von Server oder Zeugen stoppt jeden Client nach 24 Stunden (23 Stunden mit offenem Pending-Eintrag). Uhrenabweichungen über fünf Minuten führen zu abgelehnten Mails (Verlust, kein Leck; 2.4 Regel 4). NTP ist Pflicht und wird nicht geprüft. Quelle: 2.3, 2.4, D72 (6), `translog/doc.go` „Heads“ und „Withheld entries“.
- **R15 Zeugenquorum im PoC.** Mit einem Zeugen (1 aus 1) genügt ein kolludierender Zeuge für zwei Sichten; auch „2 aus 3“ aus 2.7 toleriert keinen kolludierenden Zeugen (`2·min − n = 1`). Quelle: S50, `translog/doc.go` „Witness quorum“.
- **R16 Logschlüssel ist der Ingest-Schlüssel (Q4).** Wer den Ingest-Schlüssel hat, signiert Metadaten **und** Logköpfe; gegen falsche Köpfe stehen nur die Zeugen. Quelle: Q4, S48, D72 (2).

### 5.3 Plattformgenerationen und Adressen

- **R17 Q19: kompromittierte Plattformidentität.** Weder Pin noch Nachfolge noch Log können eine Identitätsgeneration als kompromittiert kennzeichnen. Nach einer Nachfolge im Kompromissfall listet der neue Pin die alte Generation weiter (damit alte Zertifikate prüfbar bleiben); wer deren Schlüssel hat, stellt weiter Ingest- und Admin-Zertifikate aus, die `publish`, Log und Clients annehmen (Übernahme von Ingest und Admin). Deshalb ist `succeed --compromised` **gesperrt** (Nutzungsfehler, Exit 2, `ceremony.ErrCompromised`, `TODO(Q19)`); der Pflichttest aus 10.1 liegt als übersprungener Test vor (`TestVerifyCompromisedIdentityStillIssues`). Ohne Entscheidung bleibt bei Kompromittierung nur eine neue Zeremonie mit neuem Origin und neuen Pins für alle Clients. Offen ist zusätzlich (Nachtrag zu Q19, ohne eigenen S-Punkt): 2.3 sagt nicht, wann bei kompromittiertem Root (Anteile) ein neuer `init` mit neuem Origin statt einer Nachfolge nötig ist. Wie sich der Befund nachstellen lässt, steht in 6.5. Quelle: Q19, D85 (6), S76.
- **R18 Q8 und Q9.** Es gibt keinen Widerruf einer kompromittierten Ingest- oder Admin-Generation (kein Pin-Feld 7). Gebaut ist nur: Ingest-Generation g signiert gültig bis `valid_from` von `ingest-<g+1>.cert`. Eine Admin-Generation hat nach einem Wechsel kein Ende, und es gibt keine Admin-Rotation. Adresszuordnungen: `valid_from` wählt der Admin frei; eine später geloggte, rückdatierte Zuordnung schreibt Mails nachträglich einem Postfach zu; eine in die Zukunft datierte blockiert alle früher datierten derselben Adresse. Quelle: Q8, Q9, S24, S25, S27, `translog/doc.go` „Address assignments“ und „Platform generations“.
- **R19 Adressen im Klartext außerhalb von `addresses.json`.** `gomail-server address add <adresse>` nimmt die Adresse als Argument (lesbar über `/proc/<pid>/cmdline` für jeden lokalen Benutzer, auch außerhalb der Gruppe `gomail`) und gibt sie bei Erfolg auf stdout aus (`<adresse> -> <postfach>`); Fehlertexte nennen sie nicht. Die Logeinträge `address` enthalten die Adresse wie `addresses.json` (Abschnitt 4 erlaubt das). Das Zwei-Maschinen-Skript übergibt Absender und Empfänger in der Kommandozeile von `curl`. Quelle: S87, D80 „Für AUDIT“, D83.

### 5.4 Client, Generationen, Mitglieder

- **R20 Erstkontakt eines nie geöffneten Postfachs (2.7).** Nach `restore` oder `device lost` übernimmt der Client jedes Postfach, dessen Kopf den Benutzer nennt und dessen Kette prüft (`adoptMemberships`), mit einem Hinweis, ohne Rückfrage. Das gilt auch für ein Postfach, das ein Dieb mit der gestohlenen Generation **vor** deren Widerruf angelegt und geloggt hat: dessen Epochen sind nach 2.2 Punkt 4 gültig. Quelle: S75 (offen), D84.
- **R21 Q18: alleiniges Mitglied ohne Ausweg.** Ist `folders.gml` der neuesten Epoche von der eigenen, inzwischen widerrufenen Generation signiert und fehlt der lokale Prüfvermerk, kann ein alleiniges Mitglied die Epoche `generation-revoked` nicht anlegen; `List`, `Rename`, `SetFolders` scheitern dauerhaft (nur `Read` einzelner Mails geht). Die Ursache wird korrekt benannt. Quelle: Q18, S73, `TestVerifyStuckSoleMember`.
- **R22 Phase-2-Grenze „frisch per Restore aufgesetzter Client vertraut beim ersten Kontakt“ und wie das Log sie schließt (Q20).** Ohne Log vertraute ein Client ohne lokalen Zustand jeder gültig signierten Kette; der Schutz gegen einen Dieb mit Schreibzugriff war nur für Clients mit Vorgeschichte nachgewiesen. Mit dem Log (Auftrag 14) gilt: (a) jede Epoche und jede Generation muss gültiger Logeintrag sein, eine `mailbox.rec` hinter der neuesten geloggten Epoche ist `ErrRollback`; (b) der erste Kopf eines neuen Geräts ist Vertrauen beim ersten Kontakt, abgesichert durch das Zeugenquorum; (c) Zeugen prüfen nur Konsistenz, nicht Vollständigkeit: einem neuen Gerät von Anfang an eine eigene, zeugenbestätigte Sicht zu zeigen, verhindert nur der Abgleich mit Vermerken anderer Mitglieder. Deshalb bleibt die Markierung `Unconfirmed` (Warnung bei jedem Befehl), bis der Vermerk eines **anderen** Benutzer-Mitglieds mit dem eigenen Referenzkopf übereinstimmt; der Vermerk eines eigenen zweiten Geräts zählt nicht; ein alleiniges Mitglied bleibt dauerhaft markiert (nur Warnung). Nicht geschlossen: Server zusammen mit `2·min − n` Zeugen beim ersten Kontakt eines alleinigen Mitglieds; R20. Quelle: Q20, D88 (6), `TestLogUnconfirmedUntilCheckpoint`.
- **R23 Sperre über einen frei signierten Vermerk.** Größe, Wurzel und Kopfzeit eines Vermerks sind nicht an einen veröffentlichten Kopf gebunden. Ein gültiges, kolludierendes Mitglied kann einen Vermerk signieren, der eine geteilte Sicht vortäuscht, und damit einen Mit-Benutzer dauerhaft stoppen (`ErrConsistency`). 2.7 verspricht Erkennung, nicht Verfügbarkeit. Quelle: D88 „Restrisiko“.
- **R24 Nicht loggbare Epoche 1.** Eine Epoche 1, die nie geloggt werden kann, ist nicht reparierbar (es gibt keine Vorgängerin, deren Mitglieder ersetzen dürften): Denial of Service durch Schreibzugriff. Quelle: D88 „Restrisiko“.
- **R25 Dem Log widersprechende Epoche.** Eine `epoch.rec`, deren Append `ErrDuplicate` liefert (eine andere Epoche dieser Nummer ist geloggt), ersetzt kein Client, auch nicht durch den geloggten Inhalt; das Postfach bleibt für Änderungen gesperrt, bis der Betreiber die Datei nach Prüfung des Logeintrags entfernt. Quelle: `translog/doc.go` „Unlogged epoch.rec“ Schritt 4, `TestLogDuplicateNeverReplaced`.
- **R26 Nicht reguläre Dateien an Prüfstellen.** Ein Verzeichnis oder eine FIFO an `epochs/<n+1>/epoch.rec` bleibt liegen (nicht als ungültig beweisbar), jede Änderung am Postfach scheitert dauerhaft; eine FIFO blockiert `store.ReadFileLimited`, weil das Öffnen vor der Typprüfung wartet. Das betrifft auch `gomail-ceremony` beim Lesen von Eingabedateien (`gomail-server init` liest mit `O_NONBLOCK`). Quelle: S42, D87 „Zurückgestellt“.
- **R27 S13 für Metadaten und Indexsegmente nicht übertragen.** Die Übernahmeregel aus 2.2 Punkt 4 (gültig mit Prüfvermerk, dann Neusignatur) gilt im Branch für Verpackungen und `folders.gml`, nicht für Benutzersignaturen auf Metadaten (Flags, Version ≥ 2) und für Indexsegmente: dort gilt die strengste Lesart (`TODO(S13)` in `internal/client/read.go` und `internal/client/index.go`). Nach `device lost` eines Mitglieds werden seine Flag-Versionen und Segmente abgelehnt (Verfügbarkeit, fail closed). Stand: in Arbeit (09b mit Nachtrag nach 14; ORCHESTRATION, Verlauf 18). Ebenfalls nach 09b zurückgestellt (D79): der SHA-256 der Metadatendatei im Merkzettel (heute nur Epoche, `created` und Mail-Hash); die doppelten Begriffsregeln in `internal/client/terms.go` und `internal/ingest/terms.go`, deren Gleichheit nur ein Test prüft (`TestMetaTermsMatchServer`); `from:` und `to:` aus gekürzten Metadatenwerten (4096 Byte, Umschlagabsender 320 Byte), die bei überlangen Headern von den Begriffen des Servers abweichen können. Quelle: D79, `docs/tasks/09b-client-search-rework.md`.
- **R28 `checkSignerGen` nur im Client (Q13).** Die zusätzliche Kettenregel „Generation eines Unterzeichners sinkt nicht“ setzt nur der Client durch; der Server prüft die Logreihenfolge (`CheckRevokedSignature`), nicht diese Regel. Folge im Widerspruchsfall: Verlust (Clients lehnen ab), kein Leck. Quelle: Q13, S71.
- **R29 Verwerfen begonnener Epochen (S35).** Der Beginn einer sofortigen Epoche wird gegen keine Uhr geprüft; ein Mitglied kann ihn früh legen und so bereits begonnene Epochen verwerfen, deren Mails die Clients danach ablehnen.
- **R30 Indexsegment-Laufnummer nicht gebunden (Q11).** `file_id` eines Segments ist nur die Gerätekennung; der Server kann ein gültiges Segment unter weitere Laufnummern desselben Geräts kopieren und so das Zusammenfassen ab 16 früher auslösen. Keine Falschtreffer, kein Leck.

### 5.5 Programme, Rechte, Speicher, Betrieb

- **R31 Passphrase mit Echo.** Vom Terminal gelesen, ist die Passphrase des Schlüsselspeichers sichtbar (`TODO(ask)` in `cmd/gomailctl/main.go`); Alternativen sind `--passphrase-file` und `GOMAILCTL_PASSPHRASE` (für denselben Benutzer über `/proc/<pid>/environ` lesbar). Seed- und Anteilswörter werden dagegen mit Echo aus gelesen. Ebenfalls offen und ohne S-Punkt: `keygen` löscht den Seed vom Bildschirm, bevor es die Kontrollwörter abfragt; 2.2 sagt dazu nichts (`TODO(ask)` in `cmd/gomailctl/cmd_keygen.go`). Quelle: D86 „Offen“.
- **R32 Geheimnisse im Speicher.** Überschrieben wird, soweit Go es zulässt (D04): `ecdh.PrivateKey`, Go-Zeichenketten und `bufio`-Puffer (getippte Wörter, S33) bleiben bis zur Speicherbereinigung. Der erweiterte AES-Schlüssel des flüchtigen `work/`-Schlüssels liegt im Speicher; ohne `mlock` wird nicht ausgelagert (`TestNoSpillWithoutMlock`).
- **R33 Halbes Client-Verzeichnis nach Signal in `keygen`.** `keygen` legt Schlüsselspeicher und `user.rec` vor `state.json` an; ein Signal im Schreibfenster hinterlässt ein Verzeichnis, das `keygen` danach ablehnt (Verfügbarkeit). Quelle: D86 „Zurückgestellt“.
- **R34 `gomail-server init` unter root.** Die Eigentümerprüfung der angelegten Wurzel ist unter root wirkungslos; Inode-Wiederverwendung wird über Modus und Eigentümer abgefangen. Heißt die Gruppe nicht `gomail`, nur Warnung (`TODO(ask)` in `cmd/gomail-server/init.go`, D87 (4), ohne S-Punkt). Quelle: D87.
- **R35 Testschalter.** `GOMAIL_TEST_MIN_FREE`, `GOMAIL_TEST_DEV_IDENTITY`, `GOMAIL_TEST_HEAD_GAP`, `GOMAILCTL_TEST_KEYGEN_PIPE` und `init --dev` existieren nur in Builds mit den Tags `gomail_test` bzw. `gomail_dev`. Das ist kein Restrisiko, solange nur Produktionsbuilds ausgeliefert werden. Belege: `TestNoTestSwitchInProduction`, `TestDevPinRefusedInProduction`, `TestInitDevProduction`, `TestUsageNoDev` und `TestProductionBuild` im Lauf ohne Tags, `TestKeygenPipeProduction` im Lauf mit nur `gomail_dev`; im Lauf mit beiden Tags sind sie übersprungen oder nicht übersetzt (6.1). Bitte das Build- und Auslieferungsverfahren daraufhin prüfen.
- **R36 Zwei Maschinen nur bedingt nachgewiesen.** In der Entwicklungsumgebung gab es weder NFSv4 noch eine zweite Maschine. Durchgelaufen ist der lokale Modus des Skripts; der Zwei-Maschinen-Pfad ist nur über einen ssh-Ersatz und auf Syntax geprüft. Ungeprüft sind damit die Wirkung der Satzsperren über NFS und die Annahme aus K8, dass der Linux-NFS-Client beim Sperren seinen Cache für `mailbox.rec` neu prüft. Quelle: D83.
- **R37 Klartext beim Empfang und Metadaten.** Root während des Empfangs liest neue Mails (8); sichtbar bleiben Größen, Zeiten, Mitgliedschaften, Trefferzahlen (L1 bis L4 aus 8). Ohne Volltext gibt es kein `--server-search off` (Q3).
- **R38 SMTP-Grenzen statt Missbrauchsschutz.** Grenzen aus 5.1 sind umgesetzt (Verbindungen, Rate je IP, Mindestrate, Größe, Plattenplatz); offen aus Phase 1: Spool-Vervielfachung bei vielen Empfängerpostfächern (eine Mail von 25 MiB an 100 Postfächer schreibt 2,5 GB), Mindestrate in festen 60-Sekunden-Fenstern, Doppelzustellung bei Verlust zwischen Commit und `250`. Unbekannter freier Platz ist fail closed (`451`, S81). Quelle: HANDOFF „Bekannte Grenzen“.
- **R39 Adressen nicht umzuordnen.** `address add` lehnt eine anderswo zugeordnete Adresse ab (`TODO(ask)`); ein fremder Schreiber von `addresses.json` zwischen Prüfung und Schreiben bleibt ein Rest-Wettlauf. Quelle: D80 (7), D80 „Zurückgestellt“.
- **R40 Zielplattformen.** Terminalbehandlung nur auf Linux, macOS und den BSDs; andere Systeme lehnen die Zeremoniebefehle ab, plan9 und js/wasm übersetzen nicht (D82 (2)). PTY-Tests laufen nur unter Linux. `go vet` mit `GOOS=openbsd` scheitert im Testpaket `internal/bench` (`Statfs_t.Bavail`); Produktivcode ist nicht betroffen. Unter DragonFly erkennt `gomailctl` die Master der alten BSD-Pseudoterminals (`/dev/ptyXX`) nicht als Pty-Master, nur die von `/dev/ptmx` (`TIOCISPTMASTER`, `TODO(ask)` in `cmd/gomailctl/tty_master_dragonfly.go`).

Zahl: 40 Einträge, davon 7 ganz oder teilweise in Arbeit (R1 bis R6, R27).

---

## 6. Prüfpfade für Auditoren

### 6.1 Werkzeugkette und Läufe

```
export GOTOOLCHAIN=go1.26.10
go vet ./...
go vet -tags gomail_dev,gomail_test ./...
go test ./...                                                       # Lauf 1: Produktionsbuild
go test -tags gomail_dev ./cmd/gomailctl                            # Lauf 2
go test -race -tags gomail_dev,gomail_test -timeout 60m ./...       # Lauf 3
GOARCH=386 go test -tags gomail_dev,gomail_test -timeout 60m ./...
```

Kein Lauf allein deckt alles. Die Testschalter und die Entwicklungszeremonie hängen an Build-Tags (R35), und die Belege für den Produktionsbuild liegen in Dateien mit `!gomail_test` bzw. `!gomail_dev` oder überspringen sich in einem Build mit Tags:

| Lauf | trägt | Ergebnis der genannten Tests am Stand dieses Dokuments |
|---|---|---|
| 1 `go test ./...` (ohne Tags) | Produktionsbuild: kein Testschalter, kein Dev-Pin, kein `init --dev` | `TestNoTestSwitchInProduction`, `TestDevPinRefusedInProduction` (`cmd/gomail-server`), `TestInitDevProduction` (`internal/ceremony`), `TestUsageNoDev` und `TestProductionBuild` (`cmd/gomail-ceremony`): PASS. `TestKeygenPipeProduction` und `TestLogDevPinRefused`: SKIP (brauchen die Entwicklungsplattform). |
| 2 `go test -tags gomail_dev ./cmd/gomailctl` | `keygen` ohne Testschalter auf einer Entwicklungsplattform | `TestKeygenPipeProduction`: PASS. Nur in diesem Lauf wird der Test übersetzt (`!gomail_test`) und überspringt sich nicht (`newCLI` braucht `gomail_dev`). |
| 3 mit `gomail_dev,gomail_test` | alle Tests, die eine Entwicklungsplattform brauchen (`testenv`) | `TestLogDevPinRefused` und `TestProductionBuild`: PASS. `TestNoTestSwitchInProduction`, `TestDevPinRefusedInProduction`: SKIP. `TestKeygenPipeProduction`, `TestInitDevProduction`, `TestUsageNoDev`: nicht übersetzt. |

Die Ergebnisse in der Tabelle sind mit `-run` auf die genannten Tests geprüft; die vollständigen Läufe führt Auftrag 20 aus.

Ohne `gomail_dev` überspringen sich die Tests, die über `testenv.New` eine Entwicklungsplattform brauchen. Das betrifft große Teile von `internal/client`, `internal/ingest`, `cmd/gomailctl`, `cmd/gomail-server` und `internal/bench` sowie die `testenv`-Tests in `internal/e2e` (D85 (3), D88 (9)). In `internal/ceremony` und `cmd/gomail-ceremony` überspringt sich nichts: Entwicklungs- und Produktionsvariante stehen dort in getrennten Dateien (`initdev_dev_test.go`, `dev_dev_test.go` mit `gomail_dev`; `initdev_test.go`, `dev_test.go` ohne), deshalb braucht es Lauf 1 und Lauf 3. Die übrigen Pakete hängen nicht von Tags ab.

`internal/e2e` setzt `GOMAIL_TEST_MIN_FREE` für die gestarteten Server selbst (`testMinFree` in `cli_test.go`). Seine Programme baut es selbst mit `-tags gomail_dev,gomail_test` (`buildTags`), unabhängig von den Tags des Testlaufs. Einzige Ausnahme ist `TestInitProduction`: Es baut nur mit `gomail_test` (`prodTags` in `init15h_test.go`), damit die Programme keine Entwicklungszeremonie enthalten. Deshalb laufen `TestRunbook`, `TestProgramsRefuse`, `TestInitProduction`, `TestSuccessionEndToEnd` und `TestTwoHostScript` auch in Lauf 1.

`internal/client` braucht unter `-race` etwa 25 Minuten. PTY-Tests der Zeremonie und von `gomailctl` laufen nur unter Linux. Die Messungen laufen mit `scripts/bench.sh` (D77), der Test nach 9.1 mit `scripts/two-host-test.sh` (`--local` ohne zweite Maschine).

### 6.2 Regel → Test

| Regel (Abschnitt) | Test(s) | Datei(en) |
|---|---|---|
| Kanonische Kodierung, strikter Decoder (3.6) | `TestDecodeRejects`, `TestRecordVectors` | `internal/rec/rec_test.go`, `records_test.go` |
| HKDF-Ableitung, BIP-39 (2.2) | `TestDeriveVectors`, `TestBIP39Vectors` | `internal/keys/derive_test.go`, `seed_test.go` |
| Argon2-Grenzen vor dem Aufruf, Schlüsselspeicher (2.2) | `TestKeystoreRejects`, `TestKeystoreVector` | `internal/keys/keystore_test.go`, `vectors_test.go` |
| Domänen eindeutig (3.7) | `TestDomainTable`, `TestDomainsOfVersion13`, `TestSignatureDomainBinding` | `internal/keys/cert_test.go`, `domains_test.go`, `internal/envelope/envelope_test.go` |
| Generationszertifikate, Nachfolge (2.2, 2.3) | `TestGenerationCertRejects`, `TestPlatformSuccession`, `TestCertVectors` | `internal/keys/cert_test.go`, `vectors_test.go` |
| Shamir: Schwelle, keine Integrität (2.3) | `TestThresholdProperty`, `TestCombineWithTamperedShareGivesOtherSecret`, `TestVectors` | `internal/shamir/shamir_test.go`, `vectors_test.go` |
| HPKE-Einbindung, Punkte kleiner Ordnung (3.2) | `TestHPKEVectors`, `TestHPKELowOrderPoints` | `internal/envelope/hpke_test.go` |
| STREAM: Abschneiden, Vertauschen, Flag (3.3) | `TestEveryTruncationFails`, `TestDecryptRejectsBlockManipulation`, `TestTwoMailsSwapped`, `TestOpenNeverReturnsPartialPlaintext` | `internal/envelope/parse_test.go`, `property_test.go` |
| Suite-Regeln (3.5), Kopffeld 8 (3.1) | `TestSuiteTransition`, `TestHeaderVersionRule` | `internal/envelope/envelope_test.go`, `version_test.go` |
| Epochenkette, Gründe, `discards` (2.4) | `TestChain`, `TestReasons`, `TestIncompleteDiscards`, `TestDiscardedAndImmediateEpochsMails` | `internal/store/epoch_test.go`, `internal/client/pins_test.go`, `discard_test.go` |
| Zurückspielen (2.4, 7) | `TestEpochRecRemovedReplacedAndRollback`, `TestOlderMetadataVersion`, `TestFoldersReplay`, `TestFlagsReplayAndForgery`, `TestMailForOlderEpochAfterNewBegan` | `internal/client/tamper_test.go`, `folders_test.go`, `flags_test.go` |
| Mail nur mit passendem Hash, Kopf gegen Inhalt (7) | `TestMailFileSwapped`, `TestMetaHeaderVersionDiffersFromContent`, `TestUncertifiedIngestKey` | `internal/client/tamper_test.go` |
| Verpackung nur von Benutzer-Mitglied mit gültiger Generation (2.4, D75 (4)) | `TestWrapSignedByUserMemberOnly`, `TestWrapOfRevokedSignerGeneration` | `internal/client/pins_test.go` |
| Entzug, Wettlauf, K2 (2.5) | `TestRevoke`, `TestRemovedMemberSignsReplacement`, `TestEpochRace`, `TestRecoveryCannotCreateEpochs` | `internal/client/members_test.go`, `recovery_test.go` |
| Generationen, Übernahme, Strohmann (2.2 Punkt 4, Q15) | `TestStrawmanSelfAcceptDeviceLost`, `TestColludingPastReaderDeviceLost`, `TestPlantedWrapSync`, `TestAcceptOfOwnRevokedGeneration`, `TestH2StrawmanCannotBlockGenerations`, `TestDeviceLostAlwaysNewGeneration` | `internal/client/generations_test.go`, `rewrap_test.go`, `translog14b_test.go`, `generations3_test.go` |
| Lokaler Zustand wird nie kleiner (S74) | `TestMissingMailboxKeepsState`, `TestRollbackMemoryKeptByDeviceLost`, `TestH1HiddenMailboxRecDuringContinuation` | `internal/client/generations4_test.go`, `translog14b_test.go` |
| Gültigkeitsregeln des Logs je Art | `TestUserRules`, `TestEpochRules`, `TestAddressRules`, `TestPlatformRules`, `TestInvalidEntries` | `internal/translog/log_test.go` |
| Manipulation unter einem Kopf, Rückschritt | `TestTamper`, `TestRollback`, `TestOperatorShrunkTree`, `TestRepairTreeOrphans`, `TestStartRolledBackTree`, `TestTreeRolledBackWhileRunning` | `internal/translog/log_test.go`, `rework15c_test.go`, `rework15d_test.go`, `cmd/gomail-server/main_test.go`, `internal/ingest/rework15c_test.go` |
| Kopfregeln, Quorum, geteilte Sicht (2.7) | `TestHeadRules`, `TestQuorum`, `TestQuorumInPin`, `TestSplitView` (translog und witness), `TestLogSplitView`, `TestPublishSameSizeOtherHash` | `internal/translog/log_test.go`, `limits_test.go`, `rework11b_test.go`, `internal/witness/cosign_test.go`, `internal/client/translog14_test.go` |
| Zurückgehaltene Einträge, 24 Stunden (2.3) | `TestWithheld`, `TestLogWithheldOwnEntry`, `TestLogStaleStops`, `TestLogPendingAfterRollback` | `internal/translog/log_test.go`, `internal/client/translog14_test.go`, `translog14b_test.go` |
| Vermerke der Clients (2.7) | `TestCheckpoint`, `TestCheckOlderHead`, `TestLogCheckpointAheadCompared`, `TestLogOlderHeadOnly`, `TestLogUnconfirmedUntilCheckpoint` | `internal/translog/log_test.go`, `rework14b_test.go`, `internal/client/logrework_test.go` |
| Widerrufene Generation über das Log (2.2 Punkt 3 und 4, K2) | `TestLogThiefEpochRevokedGeneration`, `TestLogForeignUserSuperseded`, `TestLogUnloggableHeadHealed`, `TestLogDuplicateNeverReplaced` | `internal/client/translog14_test.go`, `translog14b_test.go`, `logrework_test.go` |
| Erste Einträge vor der Datei („Who writes“) | `TestLogRegisterFirstEntry`, `TestLogCreateMailboxFirstEntry` | `internal/client/translog14b_test.go` |
| Ingest-Rotation, Gültigkeitsende | `TestIngestRotation`, `TestLogIngestSuperseded`, `TestGenerationRecheckedAtCommit` | `internal/translog/log_test.go`, `internal/client/translog14b_test.go`, `internal/ingest/rework15c_test.go` |
| Stilles Umleiten einer Adresse (2.3) | `TestAddressNotLogged`, `TestAddressRecheckInCommit`, `TestLogAddressNotAssigned`, `TestAddressReassign` | `internal/ingest/log_test.go`, `rework15c_test.go`, `internal/client/translog14_test.go`, `cmd/gomail-server/rework11b_test.go` |
| Server: Epoche nur geloggt, kein Rückschritt, fremde Epoche (K8, D81) | `TestEpochNotLogged`, `TestRollbackDetected`, `TestServerRejectsForeignEpoch`, `TestEpochChangesDuringData`, `TestSelfCheckRefusesDelivery`, `TestCrashDuringReceipt` | `internal/ingest/log_test.go`, `review_test.go`, `epochs_test.go`, `selfcheck_test.go`, `crash_test.go` |
| Zeuge: acht Regeln, Fork dauerhaft | `TestSizeRegression`, `TestTime`, `TestForkEvidenceNotWritten`, `TestForkOlderTime`, `TestCrashBeforeWrite` | `internal/witness/cosign_test.go`, `rework_test.go` |
| Server-Seite des Logs | `TestSignHeadSyncHook`, `TestKnownPoisonedHead`, `TestForkedWitness`, `TestEndToEnd` | `internal/translog/rework11b_test.go`, `internal/loghttp/rework11b_test.go`, `loghttp_test.go` |
| SMTP-Grenzen (5.1) | `TestSizeLimitDuringData`, `TestConnectionLimits`, `TestHourlyLimit`, `TestSlowSenderIsDisconnected` | `internal/smtpd/smtpd_test.go` |
| Kein Klartext auf Platte, in Logs, Warnungen | `TestNoPlaintext`, `TestNoPlaintextIndex`, `TestTwoHostScript` | `internal/e2e/e2e_test.go`, `internal/client/noplain_index_test.go`, `internal/e2e/twohost_test.go` |
| Sperren und Rechte (9.1) | `TestPermissions`, `TestRoleLocks`, `TestTwoDescriptors`, `TestSecondServer`, `TestSecondServerBeforeKey`, `TestPeerLock`, `TestRequireClientLock`, `TestClientDirectoryLock` | `internal/store/lock_unix_test.go`, `cmd/gomail-server/main_test.go`, `rework14_test.go`, `rework15c_test.go`, `cmd/gomailctl/main_test.go`, `internal/client/review_test.go` |
| Datenverzeichnis anlegen ohne Wettlauf (D87) | `TestInitRaceSymlink`, `TestInitFIFO`, `TestInitProduction` | `cmd/gomail-server/rework15k_test.go`, `rework15k_unix_test.go`, `internal/e2e/init15h_test.go` |
| Zeremonie: Probe, Schlüsselverzeichnis, Absturz, Publish | `TestInitProbeFails`, `TestPickRandom`, `TestKeyDirSwap`, `TestPublishOrder`, `TestPublishCrash`, `TestVerifySuccessionGap`, `TestPublishForeignPinReplace` | `internal/ceremony/api_test.go`, `pick_test.go`, `keydir_test.go`, `publish_test.go`, `succession15f_test.go`, `succession15g_test.go` |
| Zeremonie: Terminal und Signale (D82, D85) | `TestPTYSignals`, `TestPTYFlowControl`, `TestPTYDoubleEnter`, `TestPTYQuitInCommit`, `TestPTYSignalSalvo`, `TestPTYTwoTerminals`, `TestCloseKeepsSignals`, `TestSignalDuringCommit`, `TestSignalDisplayRace`, `TestEchoOffFailsClosed` | `cmd/gomail-ceremony/pty_linux_test.go`, `signals15b_linux_test.go`, `main_test.go` |
| `gomailctl`: Seed und Wörter nur am Terminal (D86) | `TestPtyKeygen`, `TestPtyWordsEchoOff`, `TestPtyWordsStdoutRedirected`, `TestPtyMaster`, `TestRelayBrokenPipe`, `TestAbortSignals`, `TestKeygenPipeProduction` | `cmd/gomailctl/pty_linux_test.go`, `pty13d_linux_test.go`, `keygen_pipe_test.go` |
| Trennung der Builds (Läufe nach 6.1) | `TestProductionBuild`, `TestNoTestSwitchInProduction`, `TestDevPinRefusedInProduction`, `TestInitDevProduction`, `TestUsageNoDev`, `TestKeygenPipeProduction`, `TestLogDevPinRefused` | `cmd/gomail-ceremony/build_test.go`, `dev_test.go`, `cmd/gomail-server/rework15c_test.go`, `rework15k_test.go`, `internal/ceremony/initdev_test.go`, `cmd/gomailctl/keygen_pipe_test.go`, `internal/client/translog14_test.go` |
| Ende zu Ende mit Log, Zeuge, Nachfolge | `TestLogEndToEnd` (translog und e2e), `TestSuccessionEndToEnd`, `TestRunbook` | `internal/translog/log_test.go`, `internal/e2e/log_test.go`, `succession_test.go`, `cli_test.go` |
| **Pflichttest ohne Umsetzung** (10.1 „Signatur einer kompromittierten … Identitätsgeneration“) | `TestVerifyCompromisedIdentityStillIssues` (übersprungen, Q19) | `internal/ceremony/succession15f_test.go` |

Die vollständige Zuordnung der Pflichttests aus 10.1 erstellt Auftrag 20.

### 6.3 Mutationsnachweise

Die Prüfberichte liegen nicht im Repository. Die Aufträge unter `docs/tasks/` nennen je Fund die Mutation, die ein neuer Test brechen muss; die Umsetzer haben die Brechung in ihren Berichten nachgewiesen. Genannt seien (nicht wiederholt):

- `client` Mitglieder und Epochen: 21 Mutationen (D75); Nichtmitglied-Prüfung der Verpackung und Kettenregeln 6/7 aus Client-Sicht (06d); Zweig „widerrufene Generation“ in `checkAccept` (06e); Mitgliedsprüfung des Vorlagen-Unterzeichners (06f); `Matches` und Seed-Beleg nur für eigene Signaturen (06h); Fehler aus `userKey`/`CheckEpoch` gelten nicht als ersetzbar (06b).
- `store`/Epochenregel: Regeln 6 und 7 von `Chain.Add` decken sich gegenseitig (02b); Toleranz nur für sofortige Epochen (02c).
- `translog`: `maxLeavesPerRead` (07c); `syncTree` vor der Signatur und „nie zwei Köpfe gleicher Größe“ in `PublishHead` (11b); `refuse` in `SignHead` (15d).
- `ingest`: Adressprüfung im Commit (`stillValid`, 15c).
- Zeremonie: zufällige Probe-Auswahl (10b); Schreiben über `os.Root` (10c); Rücklesen des ECHO-Bits (10d); SIGTERM/SIGHUP (10e).
- Bekannt überlebend, zurückgestellt nach Auftrag 20: Absenkverbot in `commitHead` (D88).

### 6.4 Fuzz-Ziele

25 Ziele: `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`, `store.FuzzDecodeRecords`, `smtpd.FuzzCommands`, `smtpd.FuzzData`, `ingest.FuzzTerms`, `words.FuzzNormalize`, `translog.FuzzParseHeadText`, `translog.FuzzDecodeEntry`, `translog.FuzzOpenHead`, `translog.FuzzProofs`, `translog.FuzzAuditIndex`, `witness.FuzzParseProof`, `witness.FuzzDecodeWitnesses`, `witness.FuzzCosign`, `witness.FuzzPoll`, `loghttp.FuzzServer`.

```
go test -run '^$' -fuzz '^FuzzX$' -fuzztime 10m ./internal/<paket>
```

Kein eigenes Fuzz-Ziel haben die Prüfpfade des Clients (Kette, Vermerke, `state.json`) und die Zeremonie; die Eingabe der Wörter deckt `words.FuzzNormalize`. Die Läufe von je 10 Minuten führt Auftrag 20 aus.

### 6.5 Angriffe nachstellen

Die Angriffe der Prüfer lassen sich aus dem Repository nachbauen, mit einer Ausnahme: Die Tests zu 15i, 15l, 15m, 15n und 13e kommen erst mit diesen Aufträgen ins Repository. Bis dahin sind die Zeilen, deren Vorlage diese Aufträge sind, nur nach der Beschreibung hier und den Testvorgaben in den Aufträgen nachzubauen, nicht aus Tests des Repositorys. Die Testumgebung `internal/testenv` (nur mit `-tags gomail_dev`) liefert Server, Zeuge, Clients mit echtem Log und eine steuerbare Uhr (`testenv.NewLogged`); die Programme lassen sich mit `go build -tags gomail_dev,gomail_test` bauen und mit einer Entwicklungsplattform betreiben (`gomail-ceremony init --dev`, `GOMAIL_TEST_DEV_IDENTITY=1` für `gomailctl`).

| Angriff | Ablauf | Erwartung | Vorlage |
|---|---|---|---|
| Geteilte Sicht | Datenverzeichnis kopieren, in Kopie A und B verschiedene Einträge anhängen, in beiden einen Kopf gleicher Größe mit dem Ingest-Schlüssel signieren und dem Zeugen vorlegen | Zeuge signiert nur den ersten, schreibt einen Fork-Nachweis und beendet sich mit Exit 3; Client stoppt bei einem Vermerk mit anderer Wurzel | `internal/witness/cosign_test.go` `TestSplitView`, `internal/client/translog14_test.go` `TestLogSplitView`; mit kolludierenden Zeugen `internal/translog/log_test.go` `TestSplitView` |
| Rückschritt von `tree.rec` | `log/tree.rec` auf kleinere Größe setzen, `entries/<n+1>.rec` entfernen, Server neu starten | laufender Prozess verweigert; neuer Prozess nimmt an (R12); Schreiber des verlorenen Eintrags meldet `ErrConsistency` und hängt neu an | `TestOperatorShrunkTree`, `TestRepairTreeOrphans`, `TestLogPendingAfterRollback` |
| Zurückhalten eines Eintrags | Server signiert die Größe vor einem Eintrag weiter mit frischer Zeit | `ErrWithheld` beim anhängenden Client, spätestens nach 24 Stunden `ErrStale` | `TestWithheld`, `TestLogWithheldOwnEntry` |
| Dieb nach `device lost` | Schlüsselspeicher vor `device lost` kopieren; danach Epoche mit Generation 1 signieren und schreiben; Verpackung für einen Strohmann mit Generation 1 signieren, Strohmann gegenzeichnen lassen | Epoche nie loggbar und beim nächsten Wechsel ersetzt; keine Neuausstellung für den Strohmann | `TestLogThiefEpochRevokedGeneration`, `TestStrawmanSelfAcceptDeviceLost`, `TestColludingPastReaderDeviceLost` |
| Postfach festnageln | Strohmann-Postfach, das den Benutzer als Mitglied ohne Verpackung nennt; `mailbox.rec` während `device lost` entfernen | zweites `device lost` erzeugt trotzdem eine neue Generation; Zustand bleibt erhalten | `TestH2StrawmanCannotBlockGenerations`, `TestH1HiddenMailboxRecDuringContinuation`, `TestMissingMailboxKeepsState` |
| Adresse umleiten | `addresses.json` ändern, ohne zu loggen; oder Zuordnung im Log auf anderes Postfach | Server antwortet `550`/`451`; Client zeigt die Mail nicht, Meldung ohne Adresse | `TestAddressNotLogged`, `TestLogAddressNotAssigned` |
| Kompromittierte Identität | In einer Wegwerfkopie des Repositorys in `TestVerifyCompromisedIdentityStillIssues` das `t.Skip` entfernen und beim Aufruf von `Succeed` `Compromised: true` weglassen. Das ergibt die normale Nachfolge 1 → 2; Generation 1 bleibt in der Liste von Pin 2, wie im Kompromissfall. Dann `go test -run '^TestVerifyCompromisedIdentityStillIssues$' ./internal/ceremony` (ohne Tags). | Der Test scheitert: `publish` mit Pin 2 nimmt `ingest-3.cert` und `admin-2.cert` an, die Identität 1 nach der Nachfolge ausgestellt hat. Wird diese Prüfung mit `t.Error` statt `t.Fatal` fortgesetzt, meldet der Test zusätzlich, dass `ingest-3.cert` im Operator-Log von Pin 2 gültig ist (R17). Die Variante mit `Compromised: true` lässt sich so nicht nachstellen. Ohne Skip endet `Succeed` mit `ErrCompromised`; die Sperre sitzt in `runSucceed` (`internal/ceremony/init.go`), nicht in `cmd/gomail-ceremony`. Entfernt man auch sie, verweigert `Publish` den Export der Generation 2, weil `identity-2.succ` fehlt (`translog.ErrPrerequisite`, Regel aus 15g, S91), bevor ein Zertifikat geprüft wird. Nach einer Antwort auf Q19 muss der Test mit `Compromised: true` und ohne Skip bestehen. | `internal/ceremony/succession15f_test.go` |
| Wettlauf bei `init` | zwischen Prüfung und Anlegen `--data` durch Symlink ersetzen (Einspritzpunkt `initHook`) | Verweigerung, fremdes Verzeichnis unverändert | `TestInitRaceSymlink` |
| Entwicklungs-Pin im Produktionsbuild | Pin aus `init --dev` an einen ohne Tags gebauten Server oder Client geben | Exit 2 vor jeder Sperre | `TestDevPinRefusedInProduction`, `TestLogDevPinRefused` |
| Terminal: XOFF, zwei Terminals, Signalsalve | Zeremonie an einem Pseudoterminal starten, vor dem Start `0x13` in den Eingabepuffer schreiben; stdout auf ein zweites Pseudoterminal legen, dessen Master niemand liest; Signale in schneller Folge senden, auch während des Commits | Exit 130 ohne sichtbaren Anteil und mit wiederhergestellten Modi, oder Exit 0 mit vollständigem Export, nie ein Teilzustand | `TestPTYFlowControl`, `TestPTYTwoTerminals`, `TestPTYSignalSalvo`, `TestPTYQuitInCommit` |
| Terminal: offene Punkte (R1 bis R5) | stderr an eine Pipe hängen, deren Leser sich nach dem ersten Prompt beendet; stderr auf ein drittes Pseudoterminal mit XOFF; fd 2 vor dem Start schließen; stdin und stderr auf Terminal A (angehalten), stdout und damit der Anteil auf Terminal B, dann SIGINT; `O_NONBLOCK` auf der gemeinsamen Dateibeschreibung von stdout setzen, während dessen Terminal voll ist; stderr-Terminal anhalten, während ein Anteil auf stdout steht; Doppel-Enter mit 0,2 bis 500 ms Abstand | heute: Tod durch SIGPIPE mit sichtbarem Anteil, hängender Abbruch oder hängender normaler Pfad mit sichtbarem Anteil, Clear als erledigt gezählt, Anteil 2 erscheint vor Inhaber 1; nach 15i/15l/15m/15n: Abbruchpfad mit gelöschtem Anteil oder Exit 2, die Aufforderung wird bei zu früher Eingabe wiederholt | Aufträge 15i, 15l, 15m, 15n (Testvorgaben dort) |
| `/dev/tty` aus zwei Sitzungen | in Sitzung 1 `/dev/tty` als Deskriptor 5 öffnen, mit `setsid` eine zweite Sitzung mit anderem Pseudoterminal als stdin starten, `gomailctl device lost <&5 >/dev/tty` | heute angenommen (R6); nach 13e Exit 1 vor der Passphrase | Auftrag 13e |
| FIFO als `epoch.rec` | `mkfifo mailboxes/<id>/epochs/<n+1>/epoch.rec` | jede Änderung am Postfach scheitert bzw. wartet (R26) | `internal/client/invalid_epoch_test.go` als Vorlage |
| Kopfdateien fluten | viele Dateien unter `log/heads/` anlegen | linear langsamer, keine Fehlannahme (R10) | `TestNewestHeadSize` |
| Klartextsuche | eindeutigen Marker in Header und Text senden, Verarbeitung nach `work/` erzwingen, Datenverzeichnis, Client-Verzeichnis und Logausgaben durchsuchen | kein Treffer | `TestNoPlaintext`, `TestNoPlaintextIndex` |

---

## 7. Offene Entscheidungen

### 7.1 Fragen Q1 bis Q21

| Frage | Gegenstand | Stand | Gebaut bis zur Antwort |
|---|---|---|---|
| Q1 | Wiederherstellungsempfänger: Ableitung, Kennung, Wiederaufnahme | offen | interne API (Art 2, `recovery.wrap`, nur lesend), kein Befehl (`TODO(Q1)`) |
| Q2 | Einladungen signiert oder JSON | offen | unsigniertes JSON ohne Ablauf |
| Q3 | `--server-search off` ohne Volltext | offen (nicht M1) | nicht gebaut |
| Q4 | Schlüssel und Zeit des Baumkopfs | offen | Ingest-Schlüssel als `gomail-log`, Zeitzeile `time <ms>` (Vorschlag gebaut) |
| Q5 | Grund der Epoche 1 und der Ausweich-Epoche | entschieden (D63) | `regular` |
| Q6 | Vertretung als eigene Mitgliedsart | offen | Art 3 als strengste Lesart, kein Befehl |
| Q7 | Grund für `mailbox rotate` | offen | nicht gebaut |
| Q8 | Widerruf von Plattformgenerationen | offen | Ingest-Generation endet bei `valid_from` der Nachfolgerin; kein Pin-Feld 7; kein Ende für Admin |
| Q9 | Zeitliche Bindung von Adresszuordnungen | offen | jüngste Zuordnung mit `valid_from ≤ Empfangszeit`, ohne Obergrenze |
| Q10 | Entwurf 03 mit sechs niedrigen Funden | entschieden (Orchestrator) | Punkte in 07 und 11 umgesetzt |
| Q11 | Laufnummer eines Indexsegments | offen | `file_id` = Gerätekennung |
| Q12 | Thread-Wurzel in den Metadaten | offen | `thread:` aus der eigenen Message-ID für Mails ohne Begriffsliste |
| Q13 | Regel `checkSignerGen` | offen | nur im Client |
| Q14 | Zeremonie nach drei Runden | entschieden (Runde 10e) | – |
| Q15 | Neuausstellung für Leser vergangener Zeiträume | offen | nur mit Vorlage einer gültigen Mitgliedsgeneration |
| Q16 | 06b nach fünf Runden | entschieden (Runde 06h) | – |
| Q17 | Zeremonie nach 10e | entschieden (Zusammenführung, Punkte in 15b) | – |
| Q18 | alleiniges Mitglied ohne geprüfte Ordnerliste | offen | Ablehnung ohne Ausweg |
| Q19 | kompromittierte Plattformidentität | offen, **Haltepunkt 2** | `succeed --compromised` gesperrt; M1-Kriterium C (ORCHESTRATION Abschnitt 1, „M1-Kriterien A–F“) ohne den Kompromissfall |
| Q20 | Markierung „noch kein bestätigter Zustand“ | offen | bleibt bis zum Vermerk eines anderen Benutzer-Mitglieds |
| Q21 | `gomailctl` nach drei Runden | entschieden (Zusammenführung, Punkte in 13e) | 13e in Arbeit |

### 7.2 Offene Punkte in SPEC-ISSUES

Stand der bereinigten SPEC-ISSUES (Abschnitte „Stand M1“ und „Stand Welle 4“ mit dem Nachtrag nach Auftrag 18). Als „offen“ geführt sind 21 Punkte: S23 (Q12), S24 (Q8), S25 (Q8), S27 (Q9), S28 (Q4, Q8), S35, S43 (Q1), S44 (Q1), S48 (Q4), S52, S69, S71 (Q13), S72 (Q15), S73 (Q18), S75, S76 (Q19), S83, S87, S88 (R23), S89 (R24), S90 (Q11, R30).

- S77 (`publish --replace-witnesses`, D85 (2)) und S80 (`gomail-server init`, D87) sind im Code gelöst und stehen als klarstellende Punkte für 9.2.
- Neu und klarstellend: S91 (Nachfolgekette der Plattformidentität beim Veröffentlichen, Regel aus 15g) und S92 (Befehle `restore` und `flag`).
- S34 ist geprüft: Der Code lehnt einen Symlink im letzten Element von `--keys` ab (D82 (4)).
- Als „bekannte Grenze“ klarstellend: S33, S42, S84.

Ohne S-Punkt, aber in DECISIONS oder QUESTIONS als offen vermerkt (jeweils mit `TODO(ask)` im Code, wo angegeben):

- Passphrase mit Echo und Löschen des Seeds vor der Abfrage der Kontrollwörter (D86, R31).
- Gruppenname bei `gomail-server init` (D87 (4), R34).
- Neuer `init` statt Nachfolge bei kompromittiertem Root (Nachtrag zu Q19, R17).
- Master alter BSD-Pseudoterminals unter DragonFly (R40).

Die M1-Kriterien stehen in `docs/ORCHESTRATION.md` Abschnitt 1, „M1-Kriterien A–F“. Q19 und S76 betreffen Kriterium C (Zeremonie, ohne den Kompromissfall erfüllbar). Ob der übersprungene Pflichttest aus 10.1 (6.2) Kriterium E berührt, entscheidet die Zuordnung der Pflichttests in Auftrag 20.

---

## 8. Empfehlung für das externe Audit

### 8.1 Reihenfolge und Schwerpunkte

1. **Gültigkeitsregeln von `translog`** (`internal/translog/doc.go` „Validity rules“, „Who writes“, „Unlogged epoch.rec“, „Withheld entries“, „Platform generations“; `state.go`, `impl.go`, `operator.go`, `verifier.go`). Prüfen, dass das Urteil eine Funktion von Logpräfix und Anker ist und jeder Client gleich urteilt; Doppelungsschlüssel und erste Einträge; Zeitlinie der Köpfe und die 23-Stunden-Schranke; `refuse`/`operatorCur`; `RepairTree`. Dazu die Fragen Q4, Q8, Q9, Q19 als Bewertungsauftrag: Reicht die strengste Lesart, oder ist eine Formatänderung vor dem Betrieb zwingend?
2. **Ingest-Commit-Pfad** (`internal/ingest/delivery.go`, Spool-Transaktion, K8). Prüfen, dass unter den Postfachsperren Kopf, Kette, Verwerfung, Adresszuordnung und Ingest-Generation erneut geprüft werden, bevor `250` gesendet wird; Selbstprüfung ohne Schlüssel; Absturz in jeder Phase; kein Klartext auf der Platte. Danach `smtpd` gegen 5.1 (10.2 Punkt 2).
3. **Client-Generationen** (`internal/client/devicelost.go`, `mailbox.go`, `members.go`, `logcheck.go`, `log.go`). Übernahme nach 2.2 Punkt 4, Neuausstellung nur aus der signierten Mitgliederliste, Unveränderlichkeit des lokalen Zustands, erste Einträge, Vermerke und `Unconfirmed`; die Strohmann- und Dieb-Szenarien aus 6.5. Bewertung von R20, R21, R23, R27; die Übernahme für Metadaten und Segmente erst nach dem Merge von 09b.
4. **Zeremonie und Terminal** (`cmd/gomail-ceremony/main.go`, `tty_*.go`, `internal/ceremony`; zum Vergleich `cmd/gomailctl/screen.go`). Erst nach dem Merge von 15i, 15l, 15m, 15n und 13e prüfen, sonst doppelte Arbeit. Schwerpunkte: Abbruchpfad unter allen Belegungen von stdin, stdout, stderr; Commit-Fenster; Probe-Rekonstruktion; `publish` gegen Pin und Log.
5. **Kryptografische Pakete aus Phase 0** (`rec`, `keys`, `shamir`, `envelope`) und die Domänentrennung aus 4: verlangt von 10.2 Punkt 2, klein und stabil, gut parallel zu 1 bis 3.
6. **Betrieb** (Rechte nach 9.1, Build-Tags, Logausgaben, NFSv4 auf zwei echten Maschinen, R36).

### 8.2 Erwartete Dauer

Umfang im Branch: etwa 37.000 Zeilen Produktivcode, davon rund 8.700 in `internal/client`, 6.800 in `internal/translog` (einschließlich 1.230 Zeilen Entwurf in `doc.go`), 4.100 in `internal/store`, 4.400 in Zeremonie und `gomail-ceremony`, 4.200 in den Phase-0-Paketen. Schätzung für ein Team, das Go und `tlog` kennt:

| Schwerpunkt | Personentage |
|---|---|
| 1 `translog` mit Zeuge und `loghttp` | 6–8 |
| 2 Ingest-Commit-Pfad und `smtpd` | 3–4 |
| 3 Client-Generationen und Logprüfungen | 6–8 |
| 4 Zeremonie und Terminal | 3–4 |
| 5 Phase-0-Pakete und Domänen | 4–5 |
| 6 Betrieb, Zwei-Maschinen-Test | 2–3 |
| Einarbeitung, Bericht | 3–4 |
| **Summe** | **27–36** |

Mit zwei Prüfern parallel also etwa drei bis vier Wochen. Die Schätzung setzt voraus, dass 15i, 15l, 15m, 15n, 13e und 09b vorher zusammengeführt sind und dass die Testläufe aus 6.1 einmal vollständig grün vorliegen (Auftrag 20).
