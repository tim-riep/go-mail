# Auftrag 03: Schnittstellen für Transparenzlog, Zeuge und Zeremonie

Welle 1. Sicherheitskritisch (Entwurf von Log, Beweisen, Signaturen). Die festen Vorgaben stehen in `docs/tasks/00-vorgaben.md` und gelten wörtlich. Du legst **nur Schnittstellen** fest: Typen, Funktionssignaturen, Fehlerwerte, Dateiformate, Protokoll, jeweils mit Verweis auf die Spezifikation, und schreibst keine Umsetzung über das hinaus, was Typen und Dokumentation brauchen. Die Umsetzung übernehmen die Aufträge 07 (Log), 08 (Zeuge), 10 (Zeremonie), 11 (Server-Seite), 14 und 15 (Einbau).

## Zu lesen (vollständig)

1. `docs/PLAN.md`: 1 (Grundsätze), 2.2 (Generationen Punkt 3 und 4), 2.3 (vollständig, besonders Adresszuordnungen, Widerrufe und Aktualität, Wechsel der Identität, Zeremonie), 2.7 (vollständig), 3.7 (letzter Absatz), 4 (`log/`, `checkpoints/`, `witnesses.rec`), 9.1, 9.2 (`gomail-witness`, `gomail-ceremony`), 9.3, 10.1 („Negativtests für Schlüssel und Zustände“)
2. `docs/PHASE2-KLAERUNGEN.md`: K2 (Regel 3 und 4), K7
3. `docs/QUESTIONS.md`: Q4 (Vorschlag für Schlüssel und Zeitstempel des Kopfs); du baust die Schnittstelle so, dass der Signierschlüssel des Logs ein Parameter ist
4. `docs/HANDOFF.md`: Abschnitte `translog`, „Alle `TODO(phase3-translog)`“, `ceremony und Programme`, „Bekannte Grenzen“
5. `docs/DECISIONS.md`: D17, D20, D53, D57, D58, D59; `docs/SPEC-ISSUES.md`: S13, S16
6. Code: `internal/translog/translog.go` und Test, alle Aufrufstellen (`grep -rn "TODO(phase3-translog)"`), `internal/ceremony/ceremony.go`, `internal/store/records.go` (Datensätze `address`, `platform-pin`, `platform-key`, `user`, `epoch`), `internal/keys/cert.go` (Zertifikate, Nachfolge), `cmd/gomail-server/main.go`, `cmd/gomail-ceremony/main.go`
7. Dokumentation von `golang.org/x/mod/sumdb/tlog` und `golang.org/x/mod/sumdb/note` (`go doc`, Version v0.42.0; das Modul ist über den Proxy erreichbar, `go get golang.org/x/mod@v0.42.0`)

Hinweis: Auftrag 02 legt parallel in `store` den Datensatz `gomail/v1/rec/checkpoint` fest (Felder: `user_id`, `device_id`, `origin`, `size`, `root_hash`, `head_time`, `user_gen`, `sig`, Domäne `checkpoint`, Datei `mailboxes/<id>/checkpoints/<user-id>-<device-id>.rec`). Verwende genau diese Felder; brauchst du andere, schreibst du das in den Bericht statt `store` zu ändern.

## Umfang

### A. Paket `translog` (Schnittstelle, additiv)

1. Dateiformat von `data/log/` nach Abschnitt 4: `entries/`, `tree/`, `heads/<n>.sig`, dazu Sperre und Größe. Lege fest: Aufbau eines Eintrags (ein kanonischer Datensatz `gomail/v1/rec/log-entry` mit Art, Schlüssel und Inhalt; Arten: `user`, `epoch`, `address`, `platform`; der Inhalt ist die unveränderte Kodierung des eingetragenen Datensatzes), die Blatt-Hash-Funktion (`tlog.RecordHash` über die Kodierung des Eintrags), Ablage der Baum-Hashes (Kacheln nach `tlog.Tile` oder je Hash eine Datei; wähle und begründe), Ablage des Kopfs als `note` (Checkpoint-Format `origin\n<größe>\n<hash base64>\n` plus Erweiterungszeile `time <ms>` nach Q4), Name des Signers (`gomail-log`), Datei `heads/<größe>.sig` mit Logsignatur und allen Gegensignaturen der Zeugen, Schlüssel zur Erkennung von Doppelungen (K2 Regel 3 und 4: für `epoch` das Paar Postfach und Nummer, für `user` die Benutzer-ID je Generation, für `address` die Adresse je `valid_from`, für `platform` der Dateiname), Sperrdatei `log/lock` (Satzsperre wie in `store`).
2. Go-Typen in `internal/translog` (neue Dateien, `translog.go` nur additiv): `Entry` (Art, Schlüssel, Inhalt, Index), `Head` (Origin, Size, Hash, Time, Signaturen), `Proof`-Typen (`tlog.RecordProof`, `tlog.TreeProof` dürfen direkt verwendet werden), die erweiterte Schnittstelle `Log` (bestehende elf Methoden bleiben; neu: `Append*` liefern den Index; `Head() (Head, error)`, `Entry(index) (Entry, error)`, `InclusionProof(index, size)`, `ConsistencyProof(from, to)`, `Lookup(kind, key) ([]Entry, error)`), die Verifiziererseite für den Client (`Verifier` mit hinterlegtem Log-Schlüssel, Zeugenschlüsseln, Mindestzahl der Zeugen, letztem geprüften Kopf aus `state.json`; `CheckHead(head)` prüft Logsignatur, Zeugensignaturen, Konsistenz zum letzten Kopf, Zeit nicht in der Zukunft über die injizierte Uhr; `Fresh(now)` prüft die 24 Stunden aus 2.3), Fehlerwerte (`ErrNotInLog`, `ErrDuplicate`, `ErrConsistency`, `ErrHead`, `ErrWitness`, `ErrStale`, `ErrNoLog` bleibt). Lege für jede der elf Prüfmethoden in einem Kommentar fest, welche Beweise sie führt und welchen Kopf sie voraussetzt (etwa: `CheckEpoch` = Eintrag `epoch` mit genau dieser Kodierung im Log, Inklusionsbeweis gegen den zuletzt geprüften Kopf; `CheckGeneration` = Eintrag `user` mit dieser Generation vorhanden; `CheckRevokedSignature(user, gen, signed)` = der signierte Datensatz steht als Eintrag vor dem Eintrag, der `gen` widerruft; `CheckAddress(address, mailbox, at)` = die jüngste Zuordnung mit `valid_from ≤ at` nennt dieses Postfach; `CheckFresh` = Kopf jünger als 24 Stunden mit Zeugensignaturen).
3. Wer schreibt: Im PoC teilen Server und Client das Datenverzeichnis. Lege fest, dass Einträge von dem Prozess angefügt werden, der den Datensatz erzeugt (Client: `user`, `epoch`; Server: `address`; Zeremonie: `platform`), unter `log/lock`, und dass nur der Server Köpfe signiert. Dokumentiere, was ein Angreifer mit Schreibzugriff auf `log/` erreichen kann und was die Zeugen davon aufdecken (2.7 Garantien).
4. `Unverified` bleibt in diesem Auftrag bestehen und erfüllt die erweiterte Schnittstelle (leere Antworten); der Umzug nach `translogtest` ist Auftrag 07.

### B. Paket `witness` und Programm `gomail-witness` (Schnittstelle)

1. Protokoll zwischen Server und Zeuge über HTTP (nur Standardbibliothek): Pfade, Methoden, Inhalte als Text (`note`-Format) oder Base64, Fehlercodes. Vorschlag, den du prüfen und festlegen sollst: `GET /gomail/log/head` liefert den jüngsten signierten Kopf; `GET /gomail/log/consistency?from=<n>&to=<m>` liefert den Konsistenzbeweis (Hashes base64, eine je Zeile); `POST /gomail/log/cosign` nimmt vom Zeugen den gegensignierten Kopf an, der Server prüft die Signaturen und ergänzt `heads/<größe>.sig`. Der Zeuge fragt mit `--log <url>` ab (Pull), prüft Konsistenz zu seinem gespeicherten Kopf und Zeit (nicht älter als sein letzter, nicht in der Zukunft seiner Uhr um mehr als fünf Minuten), signiert nur dann mit und verweigert für ein Log mit demselben Origin und derselben Größe jeden zweiten Kopf mit anderem Hash dauerhaft (2.7). Lege fest, was der Zeuge dauerhaft speichert (`--state <verzeichnis>`: je Origin der letzte Kopf) und wie sein Schlüssel aussieht (`--key <datei>`: `note`-Signer-Schlüssel, erzeugt mit `gomail-witness keygen`, Dateirechte 0600; öffentlicher Verifizierschlüssel als `note`-Verifier-Zeile).
2. `witnesses.rec` (Abschnitt 4): Datensatz `gomail/v1/rec/witnesses` mit der Liste der Zeugen (Name, öffentlicher Schlüssel) und der Mindestzahl; **unsigniert** im Datenverzeichnis nur als Arbeitskopie des Servers (welche Zeugen er anspricht). Verbindlich für den Client ist die Zeugenliste in `identity-<gen>.pin` (Q4): erweitere `PlatformPin` im Entwurf um die Zeugenliste und die Mindestzahl (die Änderung an `store` selbst macht Auftrag 07; hier nur die Festlegung).
3. Go-Typen in `internal/witness` (neues Paket): `Config`, `State`, Fehlerwerte, die Funktionssignaturen `Serve`, `Cosign(head) (note, error)`, `Keygen`, HTTP-Pfadkonstanten. Keine Umsetzung.

### C. Zeremonie (2.3, Schnittstelle)

`internal/ceremony/api.go` (neu): Signaturen und Dokumentation für `Init(opts) (*Result, error)` mit `Shares k-of-n` (Anteile als 30 Wörter nach `shamir`, Ausgabe nur über den übergebenen `io.Writer`, nie in eine Datei; Probe-Rekonstruktion aus drei zufällig gewählten Anteilen; Abbruch, wenn die rekonstruierte Identität nicht zum exportierten öffentlichen Schlüssel passt), `IngestRotate(opts)` (Anteile einlesen, neue Ingest-Generation, Zertifikat, Log-Eintrag, alter Schlüssel bleibt zum Prüfen alter Signaturen gültig), `Reshare(opts)` (neue Aufteilung, alte Anteile ungültig; dokumentiere, dass alte Anteile nicht zurückgerufen werden können und was das bedeutet), `Succeed(opts)` für `identity-<gen>.succ` (2.3 „Wechsel der Identität“), jeweils mit `ErrNotImplemented` als Rumpf. Eingabe der Wörter über eine `Prompter`-Schnittstelle wie in `client.Keygen` (S11-Normalisierung in der Kommandozeile). Lege fest, welche Dateien jede Zeremonie schreibt (Dateinamen nach Abschnitt 4 und D58) und was `--dev` künftig bedeutet: nur mit dem Testkennzeichen `Dev` in `identity-<gen>.pin`, das der Client ausschließlich annimmt, wenn seine `Config` ein Feld `AllowDevIdentity` trägt, das nur Tests setzen (kein Befehlszeilenschalter).

### D. Aufzulösende `TODO(phase3-translog)`

Erstelle in `internal/translog/doc.go` eine Tabelle aller 31 Stellen (`grep -rn "TODO(phase3-translog)"`) mit der Methode der neuen Schnittstelle, die sie ersetzt, und dem Auftrag (14 Client, 15 Server/Ingest/Zeremonie/Store), der sie auflöst.

## Nicht Teil des Auftrags

Umsetzung von Log, Zeuge, Zeremonie, Serverseite, Clientprüfungen; Änderungen an `store`, `client`, `ingest`, `cmd`.

## Darf ändern

`internal/translog/**` (additiv; bestehende Methoden und `Unverified` bleiben lauffähig), `internal/witness/**` (neu), `internal/ceremony/api.go` (neu, nur Signaturen, Typen, Fehler, Dokumentation), `go.mod`/`go.sum` (nur `golang.org/x/mod v0.42.0` hinzufügen, falls die Typen es brauchen).

## Fertig-Kriterien

* Das Modul kompiliert, `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...` grün; `translog` behält seine Abdeckung über Tests der Typen (Kodierung von `Entry`, `Head`-Parsen, Doppelungsschlüssel).
* Jede Festlegung verweist auf den Abschnitt der Spezifikation oder auf Q4; wo die Spezifikation schweigt, steht die Lesart begründet im Kommentar und im Bericht als Vorschlag für `DECISIONS.md`.
* Bericht nach `00-vorgaben.md`; zusätzlich: Liste aller Entwurfsentscheidungen mit Alternativen, Angriffe gegen den Entwurf, die du selbst gesehen hast, und was Aufträge 07, 08, 10, 11, 14, 15 jeweils bauen müssen (je drei bis sechs Zeilen).
