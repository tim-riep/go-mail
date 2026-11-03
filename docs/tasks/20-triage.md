# Einordnung der Hinweise aus `docs/tasks/20-notes.md` (Auftrag 20c)

Stand: Code bei 3e06f23 (Linie 09b zusammengeführt, D91), Dokumente bei bf427c2. Parallel läuft Auftrag 20b; seine Punkte stehen als „in 20b“ mit Punktnummer.

Jeder Punkt der Notizen hat genau eine Klasse. Fasst ein Spiegelstrich der Notizen mehrere Dinge mit verschiedener Klasse zusammen, ist er in Zeilen geteilt. Geprüft ist jedes „erledigt“ am Code (`grep`, Test vorhanden) am Stand 3e06f23, nicht am Wortlaut der Notizen.

Klassen:
- **erledigt**: mit Beleg (Commit, Test, D-Eintrag, Datei und Zeile).
- **in 20b**: Punkt n von `docs/tasks/20b-small-fixes.md`.
- **in 20**: nur Testcode oder Dokumentation, mit Ort. „20c“ heißt: in diesem Auftrag umgesetzt. Was DECISIONS, SPEC-ISSUES oder RUNBOOK betrifft, steht als Vorschlag am Ende.
- **Produktivcode, nicht in 20b**: Vorschlag an den Orchestrator.
- **bekannte Grenze**: mit Ort (AUDIT-Rnn, HANDOFF, SPEC-ISSUES, QUESTIONS).

Abschnitt „Anfang“ sind die Spiegelstriche vor der ersten Überschrift der Notizen.

## Tabelle

| Nr | Abschnitt | Punkt | Klasse | Beleg oder Ort |
|---|---|---|---|---|
| 1 | Anfang (Task 14) | `ReplaceEpoch` mit `unloggable` über `ErrOrder`; `Last` erst nach Refresh; `TODO(phase3-translog)` aus 06c | erledigt | `store.ReplaceEpoch` (`internal/store/store.go:537`), `unloggable` in `internal/client/mailbox.go:421`; D88 (4); `TODO(phase3-translog)` nur noch in `translogtest/unverified.go` |
| 2 | Anfang (Task 14/15) | `Options.Now` nach `Verifier.Now` | erledigt | `internal/client/log.go:122` und `:188`; D78 (6) |
| 3 | Anfang (Task 15) | Testsperre in den Programmen, Rollensperren, `--insecure-no-log` entfernen | erledigt | D81 (2) und (4), D88 (1); kein `TODO(task-15)` im Code; `TestRoleLocks`, `TestPeerLock` |
| 4 | Anfang (Task 11) | `SignHead` fsync vor der Signatur; Q10 Punkte 2, 4, 5 | erledigt | D80 (1) und (2); `TestSignHeadSyncHook` |
| 5 | Anfang (Task 11) | `headSizes` langsam bei vielen Köpfen | bekannte Grenze | AUDIT R10 (`TestNewestHeadSize`) |
| 6 | Anfang (06c) | nicht reguläre `epoch.rec` bei Kopf+1 bleibt Dauersperre | bekannte Grenze | AUDIT R26, S42 (`TestUnprovenInvalidEpochIsKept`) |
| 7 | Anfang (06c) | FIFO blockiert `ReadFileLimited` | erledigt | 20a (e799367), D87 Nachtrag 20a; `TestReadFileLimitedFIFO` |
| 8 | Anfang (12c) | Indexkosten je Mail, Segmentgröße je 1000 Mails | erledigt | 12d (e48b35b, zusammengeführt mit 0469fa3); `BenchmarkIndex`, `BenchmarkIndexSegments` in `internal/bench/index_test.go` |
| 9 | Anfang (10c) | `TODO(task-07)`: Pin-Felder 4–8 aus der Zeremonie | erledigt | D85 (1); kein `TODO(task-07)` im Code |
| 10 | Anfang (10c) | `succeed --compromised` freigeben (Sperre, `errCompromised`, Paketkommentar, `TestSucceedCompromised`, `TestUsage`) | bekannte Grenze | gesperrt wegen Q19 (Haltepunkt 2): D85 (6), AUDIT R17, S76; `TestVerifyCompromisedIdentityStillIssues` übersprungen |
| 11 | Anfang (10c) | `term.wipe` nach stderr | erledigt | D85 Nachtrag (c) 2 (stdout, dann stderr löschen); `term.wipe` in `cmd/gomail-ceremony/main.go:1733` |
| 12 | Anfang (10c) | DECISIONS: Umfang der Zeremonie, Terminalregeln | erledigt | D82 (1), (2), (4); S67 |
| 13 | Anfang (07b) | Ablauf von `unloggable`, Sperrreihenfolge Postfach → Log, fehlende Epochen und `user.rec` des Signierers anhängen | erledigt | D88 (3) und (4); `logEpoch` (`internal/client/logcheck.go:199`), aufgerufen in `internal/client/mailbox.go` (u. a. `unloggable`, `:421`) und in `epochLoggedErr` (`logcheck.go:181`) |
| 14 | Anfang (07b) | Pending-Eintrag nach Rollback blockiert Refresh; `doc.go` „Withheld entries“ | erledigt | `internal/translog/doc.go:588–600`; `TestLogPendingAfterRollback` |
| 15 | Anfang (07b) | DECISIONS: `ErrIO`, Zeugen-Verifier nur aus `NewWitnessVerifier`, Quorum nach Schlüsseln | erledigt | D78 (3) und (5) |
| 16 | Anfang (Task 20) | `shamir` `TestShareFromWordsRejects/swapped_words` zufällig | erledigt | 20a (e799367) |
| 17 | Anfang (10c) | Testseams `exit`, `commitHook`, `now`; Build-Tag `ceremony_notty` | erledigt | D82 (5) |
| 18 | Anfang (10c) | Strg-S hält den Signalhandler | bekannte Grenze | behoben mit 15b und 15l bis 15n (D85 (4) und Nachtrag); Rest AUDIT R1 (a) und (b) |
| 19 | Anfang (10d) | `TODO(task-07)` aufheben (wie Nr. 9 und 10) | erledigt | kein `TODO(task-07)` im Code; der Kompromissfall steht unter Nr. 10 |
| 20 | Anfang (10d) | 10c-spec (2): `ioctl` als Paketvariable, Test „TCSETS schluckt, ECHO bleibt“ | erledigt | `var ioctl` in `cmd/gomail-ceremony/tty_unix.go:53`; `TestEchoReadBack` (`pty_linux_test.go:1346`), `TestEchoOffFailsClosed` |
| 21 | Anfang (10d) | 10c-spec (3): Echo-Probe erst nach `signal.Notify` | erledigt | `cmd/gomail-ceremony/main.go:746` (task 10d finding 3) |
| 22 | Anfang (10d) | 10c-spec (4): Goroutine prüft `t.closed` nach der Sperre | erledigt | `cmd/gomail-ceremony/main.go:945` |
| 23 | Anfang (10d) | 10c-spec (5): `written` direkt nach `root.Link` | erledigt | `internal/ceremony/files.go:347–356` (Einspritzpunkt `link` meldet `true`) |
| 24 | Anfang (Task 15) | `--dev`/`InitDev` hinter `gomail_dev` | erledigt | D85 (3); `TestUsageNoDev`, `TestInitDevProduction` |
| 25 | Anfang (SPEC-ISSUES aus 10c) | Export vor der Probe; Uhr ohne NTP; stderr kein Terminal | erledigt | S30; RUNBOOK 10, D82 (6), AUDIT R7; S32 |
| 26 | Anfang (07c) | erster `Append` nach Rollback einmal `ErrConsistency` | erledigt | D80 (8): `getCur` baut still neu auf; `TestOwnErrCleared` (`internal/translog/rework2_test.go:111`) |
| 27 | Anfang (07c) | DECISIONS: `ownErr`, Löschung ab `ownSize`, `rebuilt`, `EvalSymlinks`, `ErrIO` | erledigt | D78 (2) und (3) |
| 28 | Anfang (09b) | Begriffsregeln in `internal/terms` | erledigt | D91 (1); `internal/terms/terms.go`, Aufrufe in `internal/ingest/terms.go` und `internal/client/terms.go` |
| 29 | Anfang (09b) | S13 für Metadaten und Segmente | erledigt | D91 (2); `checkedBefore` (`internal/client/accept.go:345`), `resignMeta` (`flags.go:224`), `resignSegment` (`index.go:825`); `TestMetaTakeover`, `TestSegmentTakeover` |
| 30 | Anfang (09b) | Datei-Hash im Merkzettel | erledigt | `noteVersion` (`internal/client/read.go:295`, `:320`); `TestMetaFileHash` |
| 31 | Anfang (09b) | `file_id` eines Segments = Gerätekennung (Q11) | bekannte Grenze | AUDIT R30, S90, Q11 |
| 32 | Anfang (09b) | Namen und Bits der Flags | erledigt | S63 |
| 33 | Anfang (09b) | nur Benutzer-Mitglieder setzen Flags | erledigt | S64 |
| 34 | Anfang (09b) | `thread:` für `unprocessed` aus der eigenen Message-ID | bekannte Grenze | S23, Q12 (offen); `TODO(Q12)` in `internal/terms/terms.go:33` |
| 35 | Anfang (09b) | `TODO(Q3)` | bekannte Grenze | Q3, nicht M1 (AUDIT 1.3) |
| 36 | Anfang | Merge-Reihenfolge 06b, 09, 09b, 12d | erledigt | alle zusammengeführt (a296a8b, 3e06f23, `git log`) |
| 37 | Anfang (11) | `Refresh` bei fortbestehendem `ownErr` | erledigt | D80 (8) |
| 38 | Anfang (11) | `getCur` nach Rollback still neu aufbauen | erledigt | D80 (8); `TestOwnErrCleared` |
| 39 | Anfang (11) | `doc.go` „Withheld entries“; doppelte Fehlerpräfixe | erledigt | Auftrag 11 Pflichtpunkt 3; `internal/translog/doc.go:586` |
| 40 | Anfang (09b) | `Search` warnt wie `List` bei Ordner außerhalb `folders.gml` | erledigt | `TestSearchWarnsHiddenFolder` (`takeover09b_test.go:498`) |
| 41 | Anfang (09b) | Warnung bei Kopie eines Segments auf andere Laufnummer | erledigt | `TestSegmentCopyWarns` (`takeover09b_test.go:544`); Q11 bleibt offen (Nr. 31) |
| 42 | Anfang (11) | Kommentar `client.go:86` „translog.Unverified“ | erledigt | kein `Unverified` mehr in `internal/client/client.go` |
| 43 | Anfang (Task 15/20) | `go vet` unter freebsd, openbsd, netbsd in `internal/ingest` | erledigt | `disk_openbsd.go`, `disk_other.go`, `mlock_other.go`; AUDIT R40 |
| 44 | Anfang (10d) | `SetTraceback("none")` wirkt nicht | erledigt | Kommentar `cmd/gomail-ceremony/main.go:208–214`; Signale über den Abbruchpfad, D82 (2) |
| 45 | Anfang (10d) | Strg-C bei Anteilseingabe erst mit Eingabetaste | erledigt | RUNBOOK 2 „Abbruch“; D82 (2) |
| 46 | Anfang (09b/10) | `client/words.go` → `internal/words` | erledigt | D85 (5); `internal/client/words.go` ist nur noch eine Hülle über `words` |
| 47 | Anfang (06b) | Obergrenze der Tokenzahl vor der Normalisierung | erledigt | D85 (5); `words.MaxTokens`, `words.MaxInput` |
| 48 | Anfang | AUDIT: Phase-2-Grenze „frisch per Restore aufgesetzter Client“ | erledigt | AUDIT R22 |
| 49 | Anfang (Task 15) | `BatchSize > store.MaxBatch` ablehnen | erledigt | `internal/ingest/ingest.go:161`; `TestBatchSizeLimit`; D81 (6) |
| 50 | Anfang (Task 17) | Kommentar von `TestIndexSegments` | erledigt | `internal/bench/index_test.go:434–438`, `TestSegmentStats` vergleicht mit den Dateien |
| 51 | Anfang (Task 17) | Tabelle: Sync und `list` erklären | in 20 | `docs/MEASUREMENTS.md` (Auftrag 17, noch nicht geliefert) |
| 52 | Anfang (11) | `loghttp` ohne Verbindungs- und Ratengrenze; Content-Type nach dem Lesen | bekannte Grenze | AUDIT R8 |
| 53 | Anfang (11) | `RepairTree` prüft deckende Generation nicht; stilles Verkürzen | bekannte Grenze | AUDIT R13 |
| 54 | Anfang (11b) | `address add --admin-key` außerhalb des Datenverzeichnisses | erledigt | `outsideData` in `cmd/gomail-server/main.go:618`; D81 (6) |
| 55 | Anfang (11b) | Paralleltest für `address add` | erledigt | `TestAddressAddParallel` (`cmd/gomail-server/rework11b_test.go:249`) |
| 56 | Anfang (11b) | Erfolgsmeldung von `address add` ohne Adresse | erledigt | Ausgabe `<adresse> -> <postfach>` (`main.go:698`), Paketkommentar 20a; AUDIT R19, S87 |
| 57 | Anfang (11b) | Müll in `heads/` stoppt `SignHead` | bekannte Grenze | D80 (3), RUNBOOK 8.2; SPEC-ISSUES: Vorschlag S-1 |
| 58 | Anfang (11b) | `ErrOrder` in `address add` (Notiz: „gleiche Millisekunde“) | Produktivcode, nicht in 20b | `valid_from` = `time.Now()` (`cmd/gomail-server/main.go:646`); `ErrOrder` nur bei einem `valid_from` vor dem letzten geloggten der Adresse (`admitAddress`, `internal/translog/state.go:590`), heute Exit 1 über `failAddr`. Gleiche Millisekunde ergibt Exit 0, 1 oder 2, nie `ErrOrder` (P-1). Vorschlag P-1 |
| 59 | Anfang (15d) | `doc.go` „What write access …“: nur Schreiber verlorener Einträge | erledigt | `internal/translog/doc.go:478–484` |
| 60 | Anfang (15d) | `TestRepairTreeOrphans` um Kacheln und `keys/` | erledigt | `internal/translog/rework15d_test.go:99–105` |
| 61 | Anfang (15d) | Kommentar `RepairTree` „log/lock“ | erledigt | `internal/translog/operator.go:622`, `:648` |
| 62 | Anfang (Task 19) | RUNBOOK „Inkonsistentes Log“, `seen`-Fall, verlorene Einträge, Abschnitte 1–6 neu | erledigt | RUNBOOK 8.1 („Läuft er bereits“), 8.3; D89 (1) |
| 63 | Anfang (16) | `gomailctl mailbox share` fehlt | erledigt | D86 (1); `cmd/gomailctl/cmd_share.go` |
| 64 | Anfang (16) | `--insecure-no-log` in `gomailctl` und Zeremonie | erledigt | D88 (1), D85 (3); `cmd/gomail-ceremony/dev_dev.go:15` |
| 65 | Anfang (16) | Testweiche `GOMAIL_E2E_HELPER=log-append` | erledigt | nicht mehr in `internal/e2e`; nur `unset` in `scripts/two-host-test.sh:121` |
| 66 | Anfang (16) | Befehl zum Halten von `locks/client` | bekannte Grenze | S83 (offen), AUDIT R9 |
| 67 | Anfang (16) | zweiter Server braucht Kopie des Ingest-Schlüssels | erledigt | D88 (8); RUNBOOK 1.6 Punkt 3; `TestSecondServerBeforeKey` |
| 68 | Anfang (16) | DECISIONS: NFS `vers=4`, gleiche gid | erledigt | D83 |
| 69 | Anfang (16) | Zeugenkopf im Zwei-Maschinen-Modus abwarten | erledigt | `scripts/two-host-test.sh` (`again`, Zeilen 977, 1000, 1084; `GOMAIL_TEST_HEAD_GAP`) |
| 70 | Anfang (16-Verif.) | `serve` liest den Ingest-Schlüssel vor der Rollensperre | erledigt | D88 (8); `TestSecondServerBeforeKey` |
| 71 | Anfang (16-Verif.) | Adresse im Klartext in `addresses.json` und Log | bekannte Grenze | AUDIT R19, S87 (Abschnitt 4 erlaubt es) |
| 72 | Anfang (16c) | `curl -q`, `set +o xtrace`, `ln -s … \|\| die`, `usage` zu `--keep` | erledigt | D83 Nachtrag 19 |
| 73 | Anfang (16c) | RUNBOOK: Signal an die Prozessgruppe | erledigt | RUNBOOK 8.5 |
| 74 | Anfang (Task 20) | `go test -race ./internal/client` über 10 min; langsame Tests bündeln | in 20 | HANDOFF „Bauen und testen“ (20c); Bündeln nur Testcode in `internal/client`, Auftrag 20 |
| 75 | Anfang (S80) | Produktionsweg zum Anlegen des Datenverzeichnisses | erledigt | D87; `gomail-server init` (`cmd/gomail-server/init.go`) |
| 76 | Anfang (S80) | S34 auf erledigt | erledigt | S34 „Stand nach Auftrag 18 (geprüft)“ |
| 77 | Anfang (S80) | Q11 ohne S-Punkt | erledigt | S90 |
| 78 | Anfang (13) | `list` ohne Absenderspalte | erledigt | D86 (1); RUNBOOK 4.4 |
| 79 | Anfang (13) | `restore` und `flag` nicht in 9.2 | erledigt | S92 |
| 80 | Anfang (13) | Worteingabe ohne Echo-Abschaltung | erledigt | D86 (2) |
| 81 | Anfang (13) | `TODO(task-13)` in `client/keygen.go` | in 20b | Punkt 2 (`internal/client/keygen.go:32`) |
| 82 | Anfang (13) | Exit 3 bei `ErrPartial` auch für `sync` | erledigt | RUNBOOK 4.10 |
| 83 | Anfang (13) | `ForceNewGeneration` entfällt | erledigt | D88 (7); nur noch ein Testkommentar (`generations3_test.go:389`); S70: Vorschlag S-6 |
| 84 | Anfang (13b) | `filesWithWords` zu empfindlich | erledigt | 20a (e799367) |
| 85 | Anfang (13b) | Testbuild-Schalter `GOMAILCTL_TEST_KEYGEN_PIPE` | erledigt | D86 (2); `TestKeygenPipeProduction` |
| 86 | Anfang (13b) | `CleanText` C1 und Bidi | erledigt | D86 (3) |
| 87 | Anfang (13b) | `TODO(ask)`: Seed vor der Abfrage gelöscht; Passphrase mit Echo | bekannte Grenze | AUDIT R31, D86 „Offen“ |
| 88 | Anfang (14) | DECISIONS aus 14: `Config.Log` entfällt, Verlierer-Epoche nur bei `ErrOrder`, Adressprüfung, Vermerk-Warnungen | erledigt | D88 (1) bis (5) |
| 89 | Anfang (14) | Testschalter `GOMAIL_TEST_DEV_IDENTITY`, `GOMAIL_TEST_HEAD_GAP` | erledigt | D88 (1) und (8); AUDIT R35 |
| 90 | Anfang (14) | gespeicherter Kopf ohne Signaturprüfung geparst; `LogKeys` nicht gespeichert | bekannte Grenze | AUDIT 3 (Client-Verzeichnis); `TODO(ask)` in `internal/translog/doc.go:1051` |
| 91 | Anfang (14) | `mailbox.rec` hinter der neuesten geloggten Epoche = `ErrRollback` für Leser | in 20 | SPEC-ISSUES: Vorschlag S-3 (Code: D81 (1), D88 (2)) |
| 92 | Anfang (14) | `address add` bleibt in Argumentform | bekannte Grenze | S87, AUDIT R19 |
| 93 | Anfang (14) | Laufzeiten `internal/client`: race 1489 s, 386 868 s | in 20 | HANDOFF „Bauen und testen“ (20c) |
| 94 | Anfang (14b) | `keygen` atomar | in 20b | Punkt 1; AUDIT R33 |
| 95 | Anfang (15i) | `TestPTYSignalSalvo` Teil „mixed“ | erledigt | 20a (e799367) |
| 96 | Anfang (15i) | `internal/bench/diskspace_unix_test.go` unter openbsd | erledigt | `internal/bench/diskspace_openbsd_test.go` (20a) |
| 97 | Anfang (15i) | D85: SIGPIPE bis Exit, EPIPE vor dem Commit, keine Prompts nach Abbruchbeginn | erledigt | D85 Nachtrag (a) |
| 98 | Anfang (D86/14b) | 2.5 „entzogen“ nach `Append` ohne deckenden Kopf; 2.4 Lesen einer geprüften Epoche nach Rollback | in 20 | SPEC-ISSUES: nicht übernommen, Beleg im Code nicht eindeutig gefunden (siehe „Vorschläge“, Hinweis S-9) |
| 99 | Anfang (D86/14b) | nie loggbare Epoche am Kopf durch Reparatur-Epoche ersetzt; Schritt 4: widersprechende Epoche ersetzt kein Client | erledigt | D88 (4); `healHead` (`internal/client/members.go:250`); `TestLogUnloggableHeadHealed`, `TestLogDuplicateNeverReplaced` |
| 100 | Anfang (D86/14b) | beidseitige Ordnung der Kopfzeiten, `ErrOlderHead`, Q20, `Checkpointed`, Register-Abhilfe, `Unconfirmed` | erledigt | D88 (3), (5), (6); `TestLogCheckpointAheadCompared`, `TestLogOlderHeadOnly`, `TestLogRegisterDuplicateRemedy`, `TestLogUnconfirmedUntilCheckpoint` |
| 101 | Anfang (15k) | `ReadFileLimited` mit `O_NONBLOCK` | erledigt | 20a, D87 Nachtrag 20a |
| 102 | Anfang (15k) | D87: `init` legt an, `publish` nur vorhanden; Symlinks; Gruppe; Dev-Pin; Inode | erledigt | D87 (1) bis (4) |
| 103 | Anfang (14b-Angreifer) | Vermerk eines kolludierenden Mitglieds sperrt dauerhaft | bekannte Grenze | AUDIT R23, S88 |
| 104 | Anfang (14b-Angreifer) | `warnContradicts` auch am Kopf | in 20b | Punkt 3 |
| 105 | Anfang (15l) | `TCSETSF` wartet auf abgeflossene Ausgabe | erledigt | 15m: `TCSETS`/`TCFLSH` (D85 Nachtrag (b)); AUDIT R3 |
| 106 | Anfang (15l) | D85: stderr Terminal, Pipe oder Datei; Reihenfolge; 400 ms | erledigt | D85 Nachtrag (a) und (c) |
| 107 | Anfang (14b-Spez.) | Test für das Absenkverbot von `commitHead` | in 20b | Punkt 8 |
| 108 | Anfang (14b-Spez.) | `doc.go` Schritt 4 „beyond the head“ | in 20b | Punkt 3 |
| 109 | Anfang (14b-Spez.) | doppelter `epochLogged`-Aufruf in `loadChain` | in 20b | Punkt 3 |
| 110 | Anfang (14b-Spez.) | SPEC-ISSUES: Kopfzeiten beidseitig als Betriebsregel | in 20 | SPEC-ISSUES: Vorschlag S-2 (Nachtrag zu S52) |
| 111 | Anfang (14b-Spez.) | Q20: Bestätigung durch eigenes zweites Gerät? | bekannte Grenze | Q20 (offen); zählt nicht (D88 (6), AUDIT R22) |
| 112 | Anfang (14b-Spez.) | Reparatur-Epoche: Grund `regular` und Beginn | in 20 | SPEC-ISSUES: Vorschlag S-4 |
| 113 | Anfang (14b-Spez.) | nicht loggbare Epoche 1 ist DoS | bekannte Grenze | AUDIT R24, S89 |
| 114 | Anfang (14b-Spez.) | Widerspruch in der Kette: Abhilfe des Betreibers | bekannte Grenze | AUDIT R25, RUNBOOK 8.3; SPEC-ISSUES: Vorschlag S-5 |
| 115 | Anfang (14c) | e2e-Lücke „Ingest-Generation 1 nach `valid_from`“ über `gomailctl` | erledigt | D88 Nachtrag 19/19b; `TestRunbook` Schritt 6 |
| 116 | Anfang (14c) | HANDOFF: Tests nur mit `-tags gomail_dev,gomail_test` aussagekräftig | in 20 | HANDOFF „Bauen und testen“ (20c) |
| 117 | Anfang (14c) | feste Wartezeiten in PTY-Tests von `gomailctl` | erledigt | 20a Punkt 8; Rest bei `TestPtyRestoreStderrClosed` ist Nr. 178 |
| 118 | Anfang (13e) | `sameTerminal`: gleiches `st_dev` bei gleichem `st_rdev` | erledigt | 20a, D86 Nachtrag 20a; `TestSameDeviceDevpts` |
| 119 | Anfang (13e) | `TestIsControllingFd`, letzter Block ohne `TIOCGPGRP` | erledigt | Kommentar `cmd/gomailctl/pty13e_linux_test.go:197–201` und am letzten Block |
| 120 | Anfang (13e) | Kommentar `sameControlling`: `TIOCGPGRP` trägt | erledigt | `cmd/gomailctl/tty_unix.go:203–207` |
| 121 | Anfang (13e) | Merge-Reihenfolge 14 vor 13e | erledigt | beide zusammengeführt (c4e9014, b03135d) |
| 122 | Merge-Prüfung 13e/13f | `isControllingFd` nur per Einheitstest belegt | bekannte Grenze | AUDIT R6 (a) |
| 123 | Merge-Prüfung 13e/13f | BSD: `isDevTTYNumber` immer falsch, chroot | bekannte Grenze | AUDIT R6 (b) |
| 124 | Merge-Prüfung 13e/13f | Sitzungs-Trailer im Commit 431ca8e | erledigt | Squash-Merge b03135d |
| 125 | Aus Auftrag 18 | veraltete Paketkommentare (`translog.go`, `unverified.go`, `ceremony.go`, `doc.go` Pin, `address add`) | erledigt | 20a Punkt 5; die Sätze stehen nicht mehr im Code |
| 126 | Aus Auftrag 18 | PLAN 9.3 nennt Paket `search` | in 20 | HANDOFF „Überblick“ (20c) |
| 127 | Aus Auftrag 18 | D87 steht vor D86 | in 20 | DECISIONS: Vorschlag D-4 |
| 128 | Aus Auftrag 18 | kein Fuzz-Ziel für Prüfpfade des Clients und die Zeremonie | bekannte Grenze | 10.1 verlangt Fuzzing nur für `.gml`, SMTP und Shamir; AUDIT 6.4, HANDOFF „Fuzzing“ |
| 129 | Aus Auftrag 18 | AUDIT nach 09b, 13e, 15m nachziehen | in 20 | AUDIT: R1–R6 mit 18c, R27, 8.1 und Kopf in 20c |
| 130 | Aus 15m | RUNBOOK: stderr zum Schreiben geöffnet, Dauer des Abbruchs, Restgrenze | erledigt | RUNBOOK 2 („stderr“, „Abbruch“, „Restgrenze“) |
| 131 | Aus 15m | `TestPTY` reshare Wortpaar-Heuristik | erledigt | 20a Punkt 6 |
| 132 | Aus 15m | `TCOOFF`+`TCOON` statt `TCOON` | erledigt | D85 Nachtrag (c) 1 |
| 133 | Aus 15m | BSD und Darwin nur per `vet` | bekannte Grenze | AUDIT R40; HANDOFF „Bekannte Grenzen“ |
| 134 | SPEC-ISSUES-Bereinigung | toter Kommentar `cmd/gomailctl/commands.go` | erledigt | 20a Punkt 5; kein `force-new-generation` im Code |
| 135 | SPEC-ISSUES-Bereinigung | Tests für S88 (Vermerk-DoS) und S89 (Epoche 1) | in 20 | Testcode `internal/client` (neue Testdatei); kein solcher Test vorhanden |
| 136 | SPEC-ISSUES-Bereinigung | ohne S-Punkt: Passphrase-Echo, Gruppenname, Q19-Nachtrag | bekannte Grenze | AUDIT R31, R34, R17 und 7.2; HANDOFF |
| 137 | Aus 18b | D88 (9) präzisieren | erledigt | D88 Nachtrag 19/19b |
| 138 | Aus 18b | `TestTwoHostScript` einmal unter Last gescheitert | in 20 | Auftrag 20 beobachtet den Volllauf (`internal/e2e`) |
| 139 | Aus 18b | AUDIT Kopf nachziehen | in 20 | AUDIT Kopf (20c) |
| 140 | Aus 18b-Nachprüfung | R35: `TestProductionBuild` | erledigt | AUDIT R35 (18c) |
| 141 | Aus 18b-Nachprüfung | 7.2: DragonFly nur `TODO(ask)` | erledigt | AUDIT 7.2 (18c) |
| 142 | Aus 18b-Nachprüfung | 6.5 CLI lehnt `--compromised` ab; 6.1 Überspringen über `ErrDev` | erledigt | AUDIT 6.5 und 6.1 (18c) |
| 143 | Aus 19 | Ingest-Schlüssel mit künftigem `valid_from` ablehnen | erledigt | D90; `TestNotYetValid`, `TestServeNotYetValid` |
| 144 | Aus 19 | D88-Nachtrag e2e-Lücke; D83-Nachtrag Skript | erledigt | D88 Nachtrag 19/19b, D83 Nachtrag 19 |
| 145 | Aus 19 | RUNBOOK 2 nimmt 15l–15n vorweg, Platzhalter `confirmDelay` | erledigt | RUNBOOK 2 „Bestätigungen“ |
| 146 | Aus 19 | Q18: zweites Benutzer-Mitglied als Vorbeugung | erledigt | RUNBOOK 8.4 |
| 147 | Aus 19 | `TestRunbook`: `--replace-witnesses`, `restore --shares` mit `shamir.Split` | erledigt | D89 (4); `TestSuccessionEndToEnd` |
| 148 | Aus 19 | Doc-Kommentar „checks, in this order“ an `serve` | erledigt | 20a Punkt 5; der Satz steht nicht mehr im Code |
| 149 | Aus 15n | D85: `outputGrace`, Wiederanlauf, `confirmDelay` | erledigt | D85 Nachtrag (d) und (e) |
| 150 | Aus 15n | RUNBOOK-Satz `confirmDelay`; Bildschirm nimmt nichts an → Exit 130 | erledigt | RUNBOOK 2 „Bestätigungen“, „Angehaltene Ausgabe“ |
| 151 | Aus 15n | Restgrenzen unvollständige Zeile, µs-Fenster | bekannte Grenze | D85 Nachtrag (f), AUDIT R2 |
| 152 | Aus 15n | `TestPTYSignalSalvo` über 60 % der Laufzeit; Ausreißer `TestPTYQuitInCommit` | in 20 | Auftrag 20 beobachtet den Volllauf (`cmd/gomail-ceremony`) |
| 153 | Aus 19b-Nachprüfung | RUNBOOK 1.6 Schritt 6: Reihenfolge in `ingest.New` | in 20 | RUNBOOK: Vorschlag R-1 |
| 154 | Aus 19b-Nachprüfung | RUNBOOK 4.7: Entzug eines Vertreters, Epoche der Mail | in 20 | RUNBOOK: Vorschlag R-2 |
| 155 | Aus 09b-Angreifer | `readSegments` hält alle Segmente im Speicher | erledigt | `maxReadSegments`, `maxReadBytes` (`internal/client/index.go:105–106`); `TestSegmentReadLimit` |
| 156 | Aus 09b-Angreifer | Vermerke aus 06b ohne `tree` zählen nicht mehr | in 20 | DECISIONS: Vorschlag D-3 (Code: `beforeRevocation`, `internal/client/accept.go:360`) |
| 157 | Aus 15n-Prüfungen | N1: `vt.confirm` in den Tests von 15m und 15n beantwortet `earlyHint` nicht (feste `answerPause`) | erledigt | 20a Punkt 7: `answerEarly` (`cmd/gomail-ceremony/pty_linux_test.go:336`), aufgerufen von `vt.confirm` (`abort15m_linux_test.go:127–140`) und `pty.confirm` (`pty_linux_test.go:309–321`) |
| 158 | Aus 15n-Prüfungen | N2: Mutation „`unblock` als No-op“ überlebt | erledigt | `TestPTYUnblockBrief` (`cmd/gomail-ceremony/exit20a_linux_test.go:85`); D85 Nachtrag 20a; AUDIT 6.3 |
| 159 | Aus 15n-Prüfungen | N3: Wiederanlauf-Goroutinen bei Exit nicht abgewartet; letzter Schritt einzelnes `TCOON` | erledigt | D85 Nachtrag 20a; `stopWaking` (`cmd/gomail-ceremony/main.go:1363`) |
| 160 | Aus 15n-Prüfungen | `TestPTYSignalSalvo` 256 s unter Last, Paket mit `-race` knapp unter 10 min | in 20 | Auftrag 20 beobachtet den Volllauf (`cmd/gomail-ceremony`), wie Nr. 152; HANDOFF „Laufzeiten“ (20c) |
| 161 | Aus 15n-Prüfungen | plan9 übersetzt nicht (gewollt) | bekannte Grenze | HANDOFF „Bekannte Grenzen“ (Zielplattformen), AUDIT R40; Kommentare `cmd/gomail-ceremony/main.go:152–154`, `internal/ceremony/ceremony.go:29–31` |
| 162 | Aus 09c | Segment-Vermerke an Epoche, `file_id`, SHA-256; Fehler am Datenverzeichnis vor dem Widerruf; Neusignatur-Fehler | erledigt | D91 (3) und (4) |
| 163 | Aus 09c | Lesegrenze 4096 Dateien und 256 MiB mit `ErrPartial` | in 20 | DECISIONS: Vorschlag D-2 (Code und `TestSegmentReadLimit` vorhanden) |
| 164 | Aus 09c | legitimes Wachstum von `state.json`, etwa 70 000 Mails bis 64 MiB | bekannte Grenze | AUDIT R43 (neu, 20c), HANDOFF; `loadState` (`internal/client/client.go:343`), `TestStateGrowthLegitimate` |
| 165 | Aus 09c | `store.ListIndexSegments` liest das ganze Verzeichnis | in 20b | Punkt 4 |
| 166 | Aus 09c | `writeSegments` schreibt eigene Vermerke nicht sofort (Fall „index weg“) | Produktivcode, nicht in 20b | `writeSegmentList` (`internal/client/index.go:432`) vermerkt ein einzelnes Segment nicht, nur Teile eines Ergebnisses aus zwei und mehr Segmenten (`noteResult`, `:1105`); `checkOwnFiles` (`devicelost.go:775`) deckt nur Segmente, die in Schritt 2 da sind. Vorschlag P-2 |
| 167 | Aus 09c | mehr als 4096 ungültige Dateien: `Search` dauerhaft `ErrPartial` | bekannte Grenze | AUDIT R42 (neu, 20c) |
| 168 | Aus 09c | Q11 offen | bekannte Grenze | AUDIT R30, S90 |
| 169 | Aus 20a | Server verweigert vor `valid_from` ohne Toleranz | erledigt | D90 |
| 170 | Aus 20a | D85: `stopWaking`, einzelnes `TCOON` | erledigt | D85 Nachtrag 20a |
| 171 | Aus 20a | D87 `ReadFileLimited`; D86 `sameDevice` | erledigt | D87 und D86, Nachträge 20a |
| 172 | Aus 20a | RUNBOOK 10: Server-Uhr gibt den Start frei | erledigt | RUNBOOK 10, Tabelle „Server-Host“ |
| 173 | Aus 09d | D84 (2) präzisieren | erledigt | D91 (6) |
| 174 | Aus 09d | D79 (1): Schwelle, Kopien einmal, keine doppelten Einträge | erledigt | D91 (4) und (5) |
| 175 | Aus 09d | D84 Schritt 4: gescheiterte Neuausstellung | erledigt | D91 (3) |
| 176 | Aus 09d | Merkmal „indexiert“ | erledigt | entfallen, D91 (7) |
| 177 | Aus 09d | AUDIT: Nachfolger gelöscht, markierter Inhalt zurückgelegt, Treffer fehlen | bekannte Grenze | AUDIT R27 (d) (20c). Für zusammengefasste Inhalte gilt der Inhalt wieder, wenn der Nachfolger fehlt (D91 (4), `successors.used` in `internal/client/accept.go:198`); ein neu signierter Inhalt einer widerrufenen Generation wird abgelehnt (`TestAttack09fRevokedReinject`) |
| 178 | Spezifikationsprüfung 20a | `TestPtyRestoreStderrClosed` wartet meist nicht | in 20b | Punkt 9 |
| 179 | Spezifikationsprüfung 20a | Test `terminalID(slave).dev == Stat(slave).Dev` | in 20b | Punkt 9 |
| 180 | Spezifikationsprüfung 20a | `wordRun`: Trenner beliebiger Länge | in 20b | Punkt 10 |
| 181 | Spezifikationsprüfung 20a | veraltete Kommentare `translog.go:43`, `doc.go:1173` | in 20b | Punkt 6 (beide Sätze noch im Code) |
| 182 | Spezifikationsprüfung 20a | `readExport` öffnet `<from>/platform` ohne Prüfung | in 20b | Punkt 5; bis dahin AUDIT R41 |
| 183 | Angreiferprüfung 20a | `resume` lässt eine blockierte Anteilszeile durch | bekannte Grenze | AUDIT R1 (b), D85 Nachtrag 20a |
| 184 | Angreiferprüfung 20a | `O_NONBLOCK` auf gemeinsamer Beschreibung trifft stdin | bekannte Grenze | AUDIT R3 |
| 185 | Angreiferprüfung 20a | weitere `os.Open` ohne `O_NONBLOCK` | in 20b | Punkt 5; Rest AUDIT R41 |
| 186 | Angreiferprüfung 20a | per `mknod` angelegter Knoten auf anderem Dateisystem wird verweigert | in 20 | HANDOFF „Bekannte Grenzen“ (20c); AUDIT R6 (c) |
| 187 | Angreiferprüfung 20a | `hasWords` findet manche Formate nicht | bekannte Grenze | AUDIT 6.2 |
| 188 | Angreiferprüfung 20a | alte Angriffsskripte beantworten vor `confirmDelay` | erledigt | nur Prüfwerkzeuge außerhalb des Repositorys, angepasst unter `verify20a-attack2` im Scratchpad |
| 189 | Aus 09e | (a) Merkmal je Art | erledigt | entfallen, D91 (7) |
| 190 | Aus 09e | (b) Grenze `merged` | erledigt | entfallen, D91 (7) |
| 191 | Aus 09e | (c) unter Neuausstellung nicht neu ausgestellt (`MaxUint32`, Fenster, `errStale`) | erledigt | D91 (3); `resignMeta` (`internal/client/flags.go:231`), `reissueMetaAndSegments` (`devicelost.go:981`) |
| 192 | Aus 09e | (d) Austausch im Fenster; `MaxUint32`-Metadatei hält die Vormerkung | bekannte Grenze | AUDIT R44 (neu, 20c) |
| 193 | Aus 09e | (e) Kopie erst nach Annahme der gleichen Datei erledigt | erledigt | D91 (4); Kommentar `internal/client/index.go:618` |
| 194 | Aus 09e | Laufzeiten und Abdeckung von 09e | in 20 | HANDOFF (20c; Zahlen von 09g); Messung in Auftrag 20 |
| 195 | Spezifikationsprüfung 09d | Testlücken: Marken vor dem Entfernen (V13, V14, V18), `reissuing` (V8) | in 20 | Testcode `internal/client`; `reissuing` wird inzwischen per `defer` zurückgesetzt (`devicelost.go:984`) |
| 196 | Spezifikationsprüfung 09d | D84 (2) „ändern ohne Wachsen“ | erledigt | D91 (6) |
| 197 | Flake 09f | `TestWordErrorsNameNoInput` | erledigt | `leakedWord` (`internal/client/generations_test.go:501–515`), genutzt in `TestWordErrorsNameNoInput` (`:572`); `TestLeakedWord` |
| 198 | Aus 18c | D85: Dauer des Abbruchs einheitlich | in 20 | DECISIONS: Vorschlag D-1; Paketkommentar schon einheitlich (`cmd/gomail-ceremony/main.go:43–44`, `:982–988`) |
| 199 | Aus 18c | HANDOFF: `mknod`-Knoten | in 20 | HANDOFF (20c), wie Nr. 186 |
| 200 | Aus 18c | R41-Stellen absichern | in 20b | Punkt 5 |
| 201 | Prüfung von 18c | 6.2: `TestHasWords`, Präfix `internal/e2e/` | in 20 | AUDIT 6.2 (20c) |
| 202 | Prüfung von 18c | R3, 6.5: Abbruch „etwa 1,5 s plus wenige `abortFloor`“ | in 20 | AUDIT R3, R1 (20c); RUNBOOK 2 „etwa 2 s“ passt |
| 203 | Prüfung von 18c | R14: „weiterlaufen bzw. neu gestartet werden“ | in 20 | AUDIT R14 (20c) |
| 204 | Prüfung von 18c | R3: Beleg aus 15b wieder aufnehmen | in 20 | AUDIT R3 (20c) |
| 205 | 09g und Merge 09b | Testlücke Einsparregel ab 32 Segmenten | in 20b | Punkt 8 |
| 206 | 09g und Merge 09b | Belegtests aus der Prüfung von 09f übernehmen | in 20b | Punkt 8 |
| 207 | 09g und Merge 09b | P3-f in `index.go` kommentieren | in 20b | Punkt 7 |
| 208 | 09g und Merge 09b | Wachstum je Epoche in `index.go` nennen | in 20b | Punkt 7 |
| 209 | 09g und Merge 09b | AUDIT R27, 6.5, 8.1 Punkt 3, Zeile 5, Kopf | in 20 | AUDIT (20c) |
| 210 | 09g und Merge 09b | D79-Nachtrag: SHA-256 der Metadatendatei im Merkzettel | erledigt | `TestMetaFileHash` (wie Nr. 30) |
| 211 | 09g und Merge 09b | D79-Nachtrag: `from:`/`to:` aus gekürzten Werten | bekannte Grenze | AUDIT R27 (20c); Kommentar `metaTerms` (`internal/client/terms.go:25`), `TestMetaTermsMatchServer` |

## Zahlen je Klasse

| Klasse | Punkte |
|---|---|
| erledigt | 126 |
| in 20b | 18 |
| in 20 | 30 |
| Produktivcode, nicht in 20b | 2 |
| bekannte Grenze | 35 |
| **Summe** | **211** |

## Produktivcode, nicht in 20b (Vorschläge an den Orchestrator)

- **P-1 (Nr. 58) `address add` mit zurückgegangener oder nachgehender Uhr.** `valid_from` ist `time.Now().UnixMilli()`, direkt und ohne einstellbare Uhr (`cmd/gomail-server/main.go:646`). Der Logschlüssel einer Zuordnung ist (`KindAddress`, Adresse, `valid_from`) (`internal/translog/entry.go:265`); `admit` sucht ihn zuerst (`internal/translog/state.go:409–413`). Daraus folgt für zwei Aufrufe in derselben Millisekunde: Gleiches Postfach und gleiche Admin-Generation ergeben byte-gleiche Einträge, weil Ed25519 deterministisch signiert (`AddressAssignment.Sign`, `internal/store/records.go:899–908`); `Append` meldet dann Erfolg mit dem vorhandenen Index (`errSame`, `internal/translog/impl.go:482–485`), Exit 0. Eine andere Admin-Generation ergibt `ErrDuplicate`, Exit 1. Ein anderes Postfach verweigert `checkAddressFree` unter `addresses.lock`, Exit 2 (`TestAddressAddParallel`). `ErrOrder` („valid_from does not increase“, `admitAddress`, `state.go:590`) entsteht nur, wenn das neue `valid_from` vor dem letzten geloggten der Adresse liegt: Die Uhr ist seitdem zurückgegangen, oder `address add` läuft auf einem anderen Rechner, dessen Uhr nachgeht. Weil ein anderes Postfach schon an `checkAddressFree` scheitert, betrifft das nur die wiederholte Zuordnung zum selben Postfach. Der Befehl endet dann mit Exit 1 und schreibt nichts (`failAddr`). Das ist fail closed, nur nicht festgelegt. Vorschlag: so lassen und in RUNBOOK 4.2 nennen (R-3), oder `valid_from` = max(jetzt, letzter geloggter Wert der Adresse + 1 ms) setzen. Ohne Sicherheitsfolge; ein Fall für nach M1.
- **P-2 (Nr. 166) eigene Segment-Vermerke sofort.** `writeSegmentList` (`internal/client/index.go:432`) legt für ein eben geschriebenes eigenes Segment keinen Prüfvermerk an; er entsteht erst beim ersten Lesen (`noteCheckedLater`, `internal/client/accept.go:298`). Nur die Teile eines Ergebnisses aus zwei und mehr Segmenten bekommen ihren Vermerk schon beim Schreiben (`noteResult`, `index.go:1105`). `device lost` vermerkt in Schritt 2 vor dem Widerruf jedes eigene Segment, das es dabei liest (`checkOwnFiles`, `internal/client/devicelost.go:775`; D91 (3)). Das deckt nur Segmente, die in Schritt 2 des widerrufenden Laufs da sind. Offen bleibt der Fall „index weg“ aus 09c: Ein eigenes Segment, das dieser Client nie gelesen hat und das in Schritt 2 verborgen ist, hat keinen Vermerk; kommt es zurück, lehnt der Client es als Datei der widerrufenen Generation ab, und seine Treffer fehlen (nur Verfügbarkeit). Der Kommentar an `missingOwnFiles` (`devicelost.go:853–858`, „its record is from before the revocation“) setzt einen Vermerk voraus, den es nur nach einem Lesen gibt. Vorschlag: Vermerk für jedes geschriebene Segment in `writeSegmentList` vor `c.save()` (wie `noteResult` für Teile) und den Kommentar an `missingOwnFiles` anpassen; Test: Segment schreiben, ohne es zu lesen, es verbergen, `device lost`, Segment zurücklegen, `Search` übernimmt es.

## Vorschläge für DECISIONS

- **D-1 (Nr. 198), D85 Nachtrag (c), letzter Satz** ersetzen durch: „Jeder Schritt wartet höchstens 400 ms (`abortWait`). `abortTotal` (1,5 s) begrenzt die Summe der Schritte; ein Schritt, der danach beginnt, wartet noch `abortFloor` (20 ms). Der Abbruch endet damit unter 2 s (`TestAbortBounded`: Schranke 2 s, gemessen 1,61 s).“ übernommen (20d): D85 Nachtrag (c); gemessen 1,56 s (Abbruchpfad), 1,61 s ist die Laufzeit des ganzen Tests.
- **D-2 (Nr. 163), Nachtrag zu D91:** „Lesegrenze der Indexsegmente (09c): Ein Lauf liest je Epoche höchstens `maxReadSegments` (4096) Dateien und `maxReadBytes` (256 MiB) (`internal/client/index.go`). Darüber liefert `Search` die gefundenen Treffer mit `ErrPartial` und einer Warnung mit fester Ursache; `Index` fasst das Gelesene zusammen, der Rest bleibt für den nächsten Lauf (`TestSegmentReadLimit`). In Schritt 4 von `device lost` ist eine Epoche über der Grenze ein Fehler des Postfachs (Vormerkung, `ErrPartial`). Mehr als 4096 ungültige Dateien halten `Search` dauerhaft bei `ErrPartial` (AUDIT R42).“ übernommen (20d): D91 Nachtrag 20d.
- **D-3 (Nr. 156), Nachtrag zu D91 (2):** „Ein Prüfvermerk ohne Baumgröße (Feld `tree`, Format vor 09b) belegt keine Prüfung vor dem Widerruf (`beforeRevocation` in `internal/client/accept.go`: fail closed). Vermerke aus 06b für `folders.gml` zählen nach dem Update deshalb nicht mehr; betroffen sind nur Client-Verzeichnisse aus der Zeit vor 09b (PoC).“ übernommen (20d): D91 Nachtrag 20d, „Zu (2)“.
- **D-4 (Nr. 127):** D86 vor D87 stellen (nur Reihenfolge, kein Inhalt). übernommen (20d): sortierte Zeilen vorher und nachher gleich.

## Vorschläge für SPEC-ISSUES

- **S-1 (Nr. 57), neuer Punkt „Fremde Dateien in `log/heads/`“** (klarstellend; 2.7, 4): „Problem: 4 sagt nicht, was mit einer Datei in `log/heads/` geschieht, die kein gültiger Kopf dieses Logs ist. Stand M1: fail closed. `SignHead` und `RepairTree` verweigern (D80 (3)); der Betreiber entfernt die Datei und repariert erneut (RUNBOOK 8.2). Der Operator liefert bei `GET /head` nur verifizierte Zeilen (D80 (4)). Vorschlag: In 4 festhalten, dass `log/heads/` nur Köpfe dieses Logs enthält und jede andere Datei den Betrieb des Logs anhält.“ übernommen (20d): S95; präzisiert: nur reguläre Dateien mit kanonischem Kopfnamen zählen, `SignHead` prüft nur den größten Kopf.
- **S-2 (Nr. 110), Nachtrag zu S52:** „Stand nach Auftrag 14b: Die Kopfzeit wird in beide Richtungen geprüft. Ein Vermerk, der größer und früher ist als der eigene Kopf, oder ein Kopf, der kleiner und später ist als ein Vermerk, ergibt `ErrConsistency` (`translog.Verifier.CheckCheckpoint`, D88 (5)). Das setzt als Betriebsregel voraus, dass der Server nie eine kleinere Größe nach einer größeren signiert. Vorschlag: Regel und Betriebsregel in 2.7 „Abgleich zwischen Clients“ aufnehmen.“ übernommen (20d): S52; berichtigt: der zweite Fall ist ein Vermerk, der kleiner und später ist als der eigene Kopf.
- **S-3 (Nr. 91), neuer Punkt „`mailbox.rec` hinter der neuesten geloggten Epoche“** (klarstellend; 2.4, 2.7): „Stand M1: Nennt `mailbox.rec` eine kleinere Epoche als die neueste geloggte Epoche des Postfachs, ist das ein Zurückspielen (`ErrRollback`), für den Server (`checkLogHead`, D81 (1)) und für jeden Client, auch einen ohne lokalen Zustand (D88 (2)). Vorschlag: In 2.4 „Schutz gegen Zurückspielen“ ergänzen: „Der Kopf eines Postfachs ist mindestens die neueste geloggte Epoche.““ übernommen (20d): S96; ergänzt: Server mit 451, `sync` eines Mitglieds repariert.
- **S-4 (Nr. 112), neuer Punkt „Reparatur-Epoche für eine nie loggbare Epoche am Kopf“** (klarstellend; 2.4, K2 Regel 4, `internal/translog/doc.go` „Unlogged epoch.rec“): „Stand M1: Ein Benutzer-Mitglied der Epoche n−1 ersetzt die nie loggbare Epoche n am Kopf durch eine neue Epoche mit derselben Nummer: Grund `regular`, Mitglieder von n−1 mit ihrer aktuellen Generation, Beginn am Monatsanfang nach dem Beginn von n−1, frühestens `ImmediateDelay` nach jetzt (`client.healHead`, D88 (4)). Der Kopf sinkt nie. Vorschlag: In 2.4 aufnehmen.“ übernommen (20d): S97.
- **S-5 (Nr. 114), neuer Punkt „Dem Log widersprechende Epoche“** (klarstellend; 2.7, K2): „Stand M1: Liefert der `Append` einer `epoch.rec` `ErrDuplicate` (eine andere Epoche dieser Nummer ist geloggt), ersetzt kein Client die Datei, auch nicht durch den geloggten Inhalt; Änderungen am Postfach scheitern, bis der Betreiber die Datei nach Prüfung des Logeintrags entfernt (`doc.go` „Unlogged epoch.rec“ Schritt 4, `TestLogDuplicateNeverReplaced`, AUDIT R25). Vorschlag: Die Abhilfe des Betreibers in 2.7 nennen.“ übernommen (20d): S98.
- **S-6 (Nr. 83), S70 „Stand nach Auftrag 18“:** letzten Satz („Ein Kommentar in `cmd/gomailctl/commands.go` …“) ersetzen durch „Der überholte Kommentar in `cmd/gomailctl/commands.go` ist mit Auftrag 20a entfernt.“ übernommen (20d): S70.
- **S-7 (Nr. 41), S90 „Stand nach Auftrag 18“:** letzten Satz ersetzen durch „Seit 09b warnt der Client, wenn ein Segmentinhalt unter einer weiteren Laufnummer desselben Geräts liegt (`TestSegmentCopyWarns`); Vermerke hängen am Inhalt, nicht an der Laufnummer (D91 (4)).“ übernommen (20d): S90.
- **S-8 (Nr. 28), S23 „Stand M1“:** „(`client/terms.go`, Auftrag 09)“ ersetzen durch „(`terms.ThreadRoot` in `internal/terms`, aufgerufen von `client.metaTerms`; D91 (1))“. übernommen (20d): S23.
- **S-9 (Nr. 98), nicht übernommen:** Die Notiz nennt „2.5 ‚entzogen‘ nach `Append` (ohne deckenden Kopf)“ und „2.4 Lesen einer geprüften Epoche nach Rollback erlaubt“ als Lesarten aus 14/14b. Im Code habe ich dafür keinen eindeutigen Beleg gefunden; RUNBOOK 4.7 sagt „Erst wenn die neue Epoche im Log steht, ist der Entzug wirksam“. Vorschlag: aus dem Bericht von 14b übernehmen, wenn er die Stellen nennt.

## Vorschläge für RUNBOOK

- **R-1 (Nr. 153), 1.6 „Startprüfungen“, Punkt 6** ersetzen durch: „6. Annahme (`ingest.New`), in dieser Reihenfolge: Ingest-Schlüssel gegen sein Zertifikat, Zertifikat im Log, Zertifikat schon gültig (`valid_from` nicht nach der Uhr des Servers, sonst Exit 2); dann nimmt sie die Serversperre und hält sie bis zum Ende; mit `--require-client-lock` die Client-Sperre; zuletzt, dass die Ingest-Generation nicht abgelöst ist (Abschnitt 6).“ Beleg: `internal/ingest/ingest.go`, `New`. übernommen (20d): RUNBOOK 1.6 Punkt 6.
- **R-2 (Nr. 154), 4.7 „Teilen und entziehen“,** nach dem Satz zu `revoke` ergänzen: „Ein Leser vergangener Zeiträume (`share --to`) ist kein Mitglied. `revoke` löscht dann nur seine Verpackungen; eine neue Epoche entsteht nicht. Grund 4 (`delegation-ended`) gibt es nur für Vertreter der Art 3, für die es keinen Befehl gibt (Q6).“ Und beim Prüfen mit `inspect`: „… nennt unter `header.epoch` die neue Epoche, bis die nächste geplante Epoche beginnt; auch deren Mitgliederliste nennt den Benutzer nicht.“ Beleg: `Revoke` in `internal/client/members.go:483` (Zweig `!listed` und Grund nach `MemberDelegate`). Hinweis: Die Notiz aus der Nachprüfung von 19b nennt für `share --to` den Grund 4; der Code legt für einen Leser vergangener Zeiträume keine Epoche an. Vor der Übernahme mit `inspect` gegenprüfen. übernommen (20d): RUNBOOK 4.7; präzisiert: keine Epoche mit sofortiger Wirkung, der Vorrat wird wie bei `sync` ergänzt.
- **R-3 (Nr. 58, nur falls P-1 so entschieden wird), 4.2:** „Ist die Uhr seit der letzten Zuordnung derselben Adresse zurückgegangen, oder läuft `address add` auf einem anderen Rechner, dessen Uhr nachgeht, scheitert der Befehl an der Reihenfolge im Log (`valid_from` steigt nicht, Exit 1); es ist nichts geschrieben. Die Uhr stellen (Abschnitt 10) und den Befehl wiederholen.“
