# Auftrag 02: `store` nach Spezifikation 1.4 (Datensätze, Ablage, Sperren)

Welle 1. Sicherheitskritisch (signierte Datensätze, Epochenkette, Sperren). Die festen Vorgaben stehen in `docs/tasks/00-vorgaben.md` und gelten wörtlich. Dieser Auftrag erlaubt ausdrücklich genau eine Änderung an `internal/keys/cert.go`: die drei Kurznamen aus Abschnitt C.

## Zu lesen (vollständig)

1. `docs/PLAN.md`: 2.2 (Generationen, Registrierung), 2.4, 2.5, 2.7 (Vermerke), 3.6, 3.7, 4, 6.2, 7, 9.1, 15, 16
2. `docs/PHASE2-KLAERUNGEN.md`: K1, K2, K4, K5, K7, K8
3. `docs/QUESTIONS.md`: Q1, Q2, Q5, Q6 (Mitgliedsart Vertretung)
4. `docs/HANDOFF.md`: Abschnitte `store`, `client` (Prüfungen beim Lesen), „Was Phase 2 als Erstes wissen muss“ Punkte 2, 3, 7
5. `docs/DECISIONS.md`: D48, D49, D50, D53, D56, D57, D59, D61, D62; `docs/SPEC-ISSUES.md`: S13, S16, S17, S18, S20
6. Code: `internal/store/**` vollständig, `internal/keys/cert.go` (Domänentabelle), `internal/envelope/envelope.go` (Kopf, `SignedSchema`), und die Aufrufer von `store`: `internal/client/*.go`, `internal/ingest/*.go`, `internal/ceremony/ceremony.go`, `internal/testenv/testenv.go`, `internal/e2e/*.go`, `cmd/*/main.go`

## Umfang

### A. `epoch.rec`: feste Gründe und `discards` (2.4, K1)

1. `Reason`: genau die sechs Werte aus 2.4 in dieser Reihenfolge: `ReasonRegular = 1`, `ReasonMemberAdded = 2`, `ReasonMemberRemoved = 3`, `ReasonDelegationEnded = 4`, `ReasonRecoveryChanged = 5`, `ReasonGenerationRevoked = 6`. Die alten Werte (initial, monthly, substitution, deleted, immediate) entfallen. `(Reason) Immediate() bool` ist wahr für 2 bis 6 (Q5: `member-added` gilt in M1 als sofort). Epoche 1 trägt `regular`; die Regel „Grund initial nur für Epoche 1“ entfällt.
2. Neues signiertes Feld `discards`: Liste von Datensätzen `gomail/v1/rec/epoch-discard` mit Feld 1 `number` (uint32). Regeln im Decoder: streng aufsteigend, jede Nummer kleiner als die eigene, höchstens `MaxDiscards` (wähle 1.024) Einträge; nur bei `Immediate()` erlaubt, bei `regular` muss die Liste fehlen (Regel 2). Das Feld liegt vor den Unterzeichnerfeldern; nummeriere die Felder von `EpochSchema` neu (zum Beispiel 9 `discards`, 10 `prev_hash`, 11 `signer_id`, 12 `signer_gen`, 13 `sig`). `store` hat keine festgeschriebenen Vektoren; der Fuzz-Korpus wird neu erzeugt.
3. Kettenprüfer ohne Ein-/Ausgabe, von Client und Server gemeinsam benutzt: `type Chain struct{...}`, `func NewChain() *Chain`, `func (c *Chain) Add(e *Epoch, data []byte) error`, `func (c *Chain) Head() *Epoch`, `func (c *Chain) Epoch(n uint32) *Epoch`, `func (c *Chain) Discarded(n uint32) bool`, `func (c *Chain) Begin(n uint32) (int64, bool)`. `Add` prüft in dieser Reihenfolge und bricht beim ersten Fehler ab (`ErrChain`): gleiche Postfach-ID; Nummer = Kopf + 1 (die erste Epoche muss 1 sein); `prev_hash` = SHA-256 der Kodierung der Vorgängerin (bei 1 kein `prev_hash`); Suite nicht älter (3.5); Unterzeichner ist Mitglied der Art Benutzer der Vorgängerin **und** der neuen Epoche, und sein Eintrag in der neuen Epoche trägt genau `signer_gen` (K2 Regel 1 und 2, HANDOFF C7); bei `member-removed` ist der Unterzeichner kein entferntes Mitglied (folgt aus „Mitglied der neuen Epoche“); `discards` enthält genau alle bisher nicht verworfenen Epochen der Kette, deren Beginn später als der Beginn der neuen Epoche liegt, keine mehr und keine weniger (Regel 1), und bei `regular` darf keine bisher nicht verworfene Epoche einen späteren Beginn haben; Beginn der neuen Epoche nicht vor dem Beginn der letzten nicht verworfenen Vorgängerin (Regel 4: verworfene werden übersprungen); eine verworfene Epoche wird nie wieder gültig (eine Epoche, die eine schon verworfene Nummer nennt, wird abgelehnt). Signaturen prüft `Chain` nicht; das bleibt beim Aufrufer (er braucht `user.rec`), wie heute bei `CheckLink`. `CheckLink` entfällt oder wird zu einer dünnen Hülle über `Chain`.
4. `Epoch.check()`: Mitgliedsarten 1 Benutzer, 2 Wiederherstellung, 3 Vertretung (Q6, `TODO(Q6)`); höchstens ein Wiederherstellungsempfänger; der Unterzeichner steht als Benutzer-Mitglied in der eigenen Mitgliederliste mit Generation `signer_gen`.

### B. `folders.gml` je Epoche mit Name (4, S20)

1. Pfad `epochs/<n>/folders.gml` (`FoldersFile(mbx, n)`); die bisherige `mailboxes/<id>/folders.gml` entfällt.
2. Klartext `gomail/v1/rec/folders`: Feld 1 `mailbox_id`, Feld 2 `epoch` (uint32), Feld 3 `name` (String ≤ 256, Pflicht, kein Leerraum nur), Feld 4 `folders` (Liste wie bisher, mindestens ein Ordner). `DecodeFolders(mbx, epoch, data)` prüft Postfach und Epoche. `MailboxNameSchema`, `EncodeMailboxName`, `DecodeMailboxName` und `Mailbox.Name` entfallen; `mailbox.rec` enthält nur noch `mailbox_id`, `epoch` (Kopf) und `inbox`.
3. `WriteFolders(mbx, n, data)` ersetzt atomar (die Liste darf sich ändern), `ReadFolders(mbx, n)`.

### C. `user.rec` signiert, `wrap-accept`, Kurznamen (2.2, 3.7, S13, S16)

1. `internal/keys/cert.go`: Domänentabelle um `DomainUser = "user"`, `DomainInvite = "invite"`, `DomainWrapAccept = "wrap-accept"` ergänzen (nur diese drei Zeilen und die Liste in `KnownDomain`); Tests dafür in einer **neuen** Datei `internal/keys/domains_test.go` (Auftrag 01 ändert die bestehenden `keys`-Tests). Vektoren von `keys` bleiben byte-identisch (`git diff --stat internal/keys/testdata` leer).
2. `gomail/v1/rec/user` erhält ein letztes Feld `sig` (64 Byte): Signatur des Benutzer-Roots unter `user` über den Datensatz ohne `sig`. `User.Sign(root ed25519.PrivateKey)`, `User.Encode()` verlangt die Signatur, `DecodeUser` prüft die Signatur gegen `root_pub` im Datensatz (fail closed) und weiterhin die Generationenkette. Aufrufer: `client/keygen.go` (`Keygen` erzeugt den Root ohnehin und signiert dort; `Register` schreibt die signierte Datei), `testenv`.
3. Datensatz `gomail/v1/rec/wrap-accept`: Feld 1 `mailbox_id`, 2 `epoch`, 3 `user_id`, 4 `wrap_hash` (SHA-256 der ganzen `.wrap`-Datei), 5 `user_gen`, 6 `sig` (Signatur der Identität des Mitglieds unter `wrap-accept` über den Datensatz ohne `sig`). Typ `WrapAccept` mit `Sign`, `Verify`, `Encode`, `DecodeWrapAccept`. Datei `epochs/<n>/members/<user-id>.accept` (`AcceptFile`, `WriteAccept` ersetzend, `ReadAccept`). Die Übernahmeregeln (2.2 Punkt 4) baut Auftrag 06.

### D. Vermerke der Clients und Indexsegmente (2.7, 4, 6.2, K5)

1. `gomail/v1/rec/checkpoint`: 1 `user_id`, 2 `device_id` (16 Byte), 3 `origin` (String ≤ 128), 4 `size` (int64, Baumgröße), 5 `root_hash` (32 Byte), 6 `head_time` (int64, ms), 7 `user_gen`, 8 `sig` unter `checkpoint`. Typ `Checkpoint` mit `Sign`, `Verify`, `Encode`, `DecodeCheckpoint`. Datei `mailboxes/<id>/checkpoints/<user-id>-<device-id>.rec` (`CheckpointFile`, `WriteCheckpoint` ersetzend, `ReadCheckpoint`, `ListCheckpoints`). Die Bedeutung der Felder legt Auftrag 03 fest; hier nur Format und Grenzen.
2. Indexsegment, Klartext `gomail/v1/rec/index-segment`: 1 `mailbox_id`, 2 `epoch`, 3 `postings` (Liste von `gomail/v1/rec/posting`: 1 `mark` 32 Byte, 2 `mail_ids` Bytes, Länge Vielfaches von 16, höchstens `MaxPostingIDs` = 4.096 IDs). Höchstens `MaxPostings` = 16.384 Einträge; `EncodeIndexSegment` lehnt ab, was kodiert `rec.MaxRecordSize` überschreitet; Marken streng aufsteigend (eindeutig), IDs je Marke streng aufsteigend. Pfade `index/<n>/<device-id>-<lfd>.gml` mit `lfd` dezimal ohne führende Nullen (`IndexSegmentFile(mbx, n, device, seq)`, `ListIndexSegments(mbx, n) ([]IndexSegmentRef, error)` mit Gerät und Laufnummer, `WriteIndexSegment` exklusiv, `ReadIndexSegment`, `RemoveIndexSegment`). Grenze beim Lesen 4 MiB.

### E. Sperren und Rechte (9.1, K8)

1. POSIX-Satzsperren statt `flock`: unter Linux OFD-Sperren (`F_OFD_SETLK` = 37, `F_OFD_SETLKW` = 38 über `syscall.FcntlFlock`), auf den anderen Unix-Systemen `F_SETLK`/`F_SETLKW`. `x/sys` darf nicht importiert werden. Sperren beziehen sich auf die ganze Datei. Dokumentiere die Semantik von Prozess-Sperren (ein `close` auf irgendeinen Deskriptor derselben Datei gibt die Sperre frei) und stelle sicher, dass je Sperre genau ein Deskriptor offen ist.
2. Rechte: Dateien im Datenverzeichnis 0660, Verzeichnisse 2770 (setgid), gesetzt ausdrücklich nach dem Anlegen (`Chmod`), weil `umask` Gruppenbits entfernen kann. `Init` setzt das Wurzelverzeichnis auf 2770. Die Gruppe selbst (`gomail`) wird nicht vom Programm gesetzt; dokumentiere das in einem Kommentar. Schlüsselspeicher und private Schlüssel liegen nicht im Datenverzeichnis und bleiben 0600 (nicht Teil dieses Auftrags).
3. Testsperre beim Start (9.1 letzter Punkt): `type Role int` (`RoleServer`, `RoleClient`); `(s *Store) HoldRoleLock(role Role) (release func(), err error)` hält für die Laufzeit eine Sperre auf `locks/server` bzw. `locks/client`; `(s *Store) CheckPeerLock(peer Role) error` versucht eine **nicht blockierende** Sperre auf der Datei des Gegenübers und meldet `ErrPeerLock`, wenn die Sperre **gelingt** (dann hält das Gegenüber keine wirksame Sperre, also läuft es nicht oder die Sperren wirken nicht über das Dateisystem) und `nil`, wenn sie scheitert. Der Client prüft so den laufenden Server, der Server beim Start nur, dass die eigene Sperre erlangt wird; den Aufruf aus den Programmen baut Auftrag 15, Tests in `store` zeigen beide Fälle (zweiter Prozess über `exec` oder zweiter Deskriptor; OFD-Sperren konkurrieren auch innerhalb eines Prozesses).
4. `LockMailbox`, `LockMailboxes`, `LockFile`, `addresses.lock` auf die neue Sperre umgestellt; `mailbox.rec` wird in `ingest` erst nach Erwerb der Sperre gelesen (K8): das ist Auftrag 05, aber `store` bietet dafür `ReadMailboxLocked`? Nein: keine neue API, nur die Sperre; dokumentiere im Kommentar von `LockMailbox`, dass Leser unter NFS die Datei erst nach der Sperre öffnen dürfen.

### F. Hilfen für Signaturprüfung ohne Schlüssel (7)

`func MetaSignedExtra(h envelope.Header, mailHash [32]byte) ([]byte, error)` baut `meta-signed` ausschließlich aus dem Kopf (`MailboxID`, `Epoch`, `FileID`, `Created`, `Version`) und dem Hash der Mail-Datei; `MailMeta.SignedExtra` bleibt und muss für konsistente Metadaten dasselbe liefern (Test). Auftrag 01 fügt `Header.Version` hinzu; bis dessen Zusammenführung kompiliert dein Zweig gegen den heutigen Kopf: baue `MetaSignedExtra` mit einem eigenen Parameter `version uint32` statt `h.Version`, der Orchestrator stellt beim Zusammenführen um. Vermerke das im Bericht.

### G. Aufrufer mechanisch anpassen

`client`, `ingest`, `ceremony`, `testenv`, `e2e` und `cmd` müssen weiter kompilieren und alle Tests bestehen. Erlaubt sind ausschließlich die Änderungen, die deine API-Änderungen erzwingen: Gründe umbenennen (Epoche 1 `regular`, monatlich `regular`, Rückfall `regular`), `Chain` statt `CheckLink`, Name und Ordner aus `epochs/<n>/folders.gml` (der Client liest die neueste Epoche, auf die er Zugriff hat; `createEpoch` schreibt `folders.gml` für jede angelegte Epoche mit Name und aktueller Ordnerliste), `user.rec` signieren in `Keygen`/`Register`/`testenv`, `Mailbox` ohne `Name`. Keine neuen Prüfregeln, keine neuen Befehle; alles Weitere bauen Auftrag 05 und 06. Jede geänderte Zeile außerhalb von `store` und `keys/cert.go` steht mit Begründung im Bericht.

## Nicht Teil des Auftrags

Einladungen (Q2, bleibt JSON), Wiederherstellungsempfänger über das Format hinaus (Q1), Log (`log/`), K8 im `ingest`, Übernahmeregeln S13 im Client, Indexierung selbst, `--insecure-no-log`.

## Darf ändern

`internal/store/**`, `internal/keys/cert.go` (nur die drei Kurznamen) und neu `internal/keys/domains_test.go`, sowie mechanische Anpassungen in `internal/client`, `internal/ingest`, `internal/ceremony`, `internal/testenv`, `internal/e2e`, `cmd/**` nach Abschnitt G. Nicht: `internal/envelope`, `internal/rec`, `internal/shamir`, `internal/smtpd`, `internal/translog`, `internal/keys` außer wie genannt.

## Tests (Pflicht)

* Tabellentests `Chain`: gültige Kette; falscher `prev_hash`; Nummernsprung; Unterzeichner nicht Mitglied der Vorgängerin; nicht Mitglied der neuen Epoche; Generation im Mitgliedseintrag ungleich `signer_gen`; `discards` unvollständig, zu viel, bei `regular`, mit späterem Beginn fehlend; Beginn vor der letzten nicht verworfenen Vorgängerin; Beginn vor einer verworfenen Vorgängerin (erlaubt); verworfene Nummer erneut; Suite rückwärts; Epoche 1 mit `prev_hash`.
* Datensätze: Kodieren und Dekodieren byte-identisch für alle neuen und geänderten Datensätze; Ablehnung von fehlender oder falscher Signatur bei `user`, `wrap-accept`, `checkpoint`; Grenzen (Längen, Anzahlen).
* Sperren: zwei Deskriptoren konkurrieren; `CheckPeerLock` beide Fälle; Rechte 0660/2770 nach `Init`, `WriteFileAtomic`, `MkdirAll` (Test mit `umask 077` über `syscall.Umask` im Test, danach zurücksetzen).
* `FuzzDecodeRecords` um die neuen Datensätze erweitert, Korpus neu, 5 Minuten ohne Fund (Ausführungen in den Bericht).
* Alle bestehenden Tests des Moduls grün.

## Fertig-Kriterien

* `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...` fehlerfrei auf dem ganzen Modul.
* Abdeckung `store` ≥ 90 %; `client` und `ingest` nicht unter 85 %.
* `git diff --stat` für `internal/keys/testdata`, `internal/rec/testdata`, `internal/envelope/testdata`, `internal/shamir/testdata` leer.
* Bericht nach `00-vorgaben.md`; zusätzlich Vorschläge für DECISIONS zu Gründen, `discards`, `Chain`, `folders.gml`, `user`-Signatur, `wrap-accept`, Vermerk, Indexsegment, Sperren und Rechten.
