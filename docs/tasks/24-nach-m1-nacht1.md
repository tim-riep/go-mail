# Auftrag 24: Liste nach M1, Pakete A bis E (Nacht 09./10.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu ORCHESTRATION Abschnitt 1 bis 3 und 8.
- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), je Paket ein eigener Worktree.
- **Quelle:** `docs/tasks/backlog-nach-m1.md`, Nummern wie unten. Die Einordnung stammt von einem Agenten des Orchestrators. Prüfe jeden Punkt am heutigen Code, bevor du ihn umsetzt.
- **Nicht ändern:** Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren. Berührt ein Punkt eines davon, setzt du ihn nicht um, sondern beschreibst ihn im Bericht.
- **Dokumente:** RUNBOOK, AUDIT, DECISIONS und HANDOFF ändert kein Paket. Was sie brauchen, steht als Vorschlag mit genauem Text im Bericht. Den Doku-Nachzug macht ein eigener Auftrag nach dem Merge.
- **Umgebung:** `export GOTOOLCHAIN=go1.26.10 GOCACHE=/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/gocache`. Tags `gomail_dev,gomail_test`. Jeder `go`-Befehl läuft mit `nice -n 19`, weil fünf Pakete parallel arbeiten. `internal/client` nie als ganzes Paket testen, nur gezielt mit `-run`; das Ganze übernimmt der Volllauf des Orchestrators.
- **Fertig:**
  - gofmt;
  - `go vet ./...` mit und ohne Tags;
  - gezielte Tests unter race mit und ohne Tags und unter 386 mit Tags für die geänderten Pakete;
  - Gegenbeleg per Mutation für jeden neuen Test;
  - Phase-0-Vektoren unverändert.

  Ein Commit mit `Task: docs/tasks/24-nach-m1-nacht1.md` (Paket X), ohne Co-Authored-By, ohne Modellnamen; nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl24<x>/notes.md`. WIP-Commits nach jedem Punkt; der Container startet gelegentlich neu.
- **Bericht:** je Punkt erledigt oder nicht (mit Begründung), Läufe, Gegenbelege, Vorschläge für Dokumente, Commit-Hash, Worktree.

## Paket A: `internal/ceremony` (Nr. 54, 55, 56, 58). Sicherheitskritisch.

Dateien: `internal/ceremony/publish.go` (`runPublish`, Vergleichs- und Schreibschleife, `checkDataPlatform`, Kommentar an `freeName`), `cmd/gomail-ceremony/main.go` (nur der Kommentar um Z. 190–198), Tests.

- **54/55:** In der Vergleichsschleife jeden Namen des Exports zuerst mit `Lstat` prüfen. Ein Symlink oder ein anderer nicht regulärer Eintrag gilt nie als „gleich“, auch wenn er hängt.
  - Ist der Name nach `freeName` frei, ersetzt `store.WriteFileAtomic` den Eintrag selbst, nicht das Ziel des Links.
  - Ist er nicht frei, verweigert `publish` vor jedem Schreiben mit einer eigenen Meldung, die den Link nennt. Damit entfällt „written meanwhile“ für hängende Links.
  - Das Verhalten aus 22 bleibt, auch für Links mit anderem Zielinhalt.
- **56:** Beide Kommentare sagen, dass Dateien, die `checkDataPlatform` vorher ablehnt (Müll, falsche Signatur, falscher Name), nicht geheilt werden.
- **58:** Die Belegtests `TestV22PubUnderUnloggedSameCert` und `TestV22SymlinkOverLogged` übernehmen. Quelle: `/home/user/go-mail/.claude/worktrees/agent-a71147e2a02c6ef32/internal/ceremony/verify22spec_test.go`, an den heutigen Stand angepasst, eigener Dateiname ohne `zz_` und ohne Prüferpräfix. Gegenbeleg: Die Mutanten P1-4 (Rückfall für `.pub` ohne `bytes.Equal` in `freeName`) und P1-6 (`os.WriteFile` statt `WriteFileAtomic` in der Schreibschleife) scheitern an den Tests.
- **Neue Tests:**
  - Ein Link auf den geloggten Inhalt wird ersetzt, sein Ziel bleibt unverändert.
  - Ein hängender Link wird ersetzt bzw. mit der eigenen Meldung verweigert, und davor wurde nichts geschrieben.
- **Läufe:** `internal/ceremony` und `cmd/gomail-ceremony` vollständig unter race mit und ohne Tags und unter 386 mit Tags (`cmd/gomail-ceremony` dauert etwa 7 Minuten).

## Paket B: `internal/client` (Nr. 57, 60, 52 Testteil). Sicherheitskritisch.

Dateien: `internal/client/client.go` (nur `resolveExisting`), `internal/client/platform23_test.go`, neue Testdateien.

- **57:** In `resolveExisting` das Linkziel eines hängenden Präfixes Stück für Stück auflösen: je Komponente `Lstat`, Links folgen, `..` erst auf dem schon aufgelösten Pfad anwenden statt `filepath.Join`/`Clean` auf den ganzen Pfad. Die Grenze von 40 Sprüngen bleibt; den Kommentar dazu berichtigen.
  - Test: `L -> sub/../data/client` mit `sub` als Symlink ins Datenverzeichnis liefert `ErrInsideDataDir`.
  - Die bestehenden Fälle aus `clientdir22_test.go` und `TestResolveExisting` bleiben grün.
- **60:** Im Schlüssel-Zweig von `TestPlatformIngestCertSwapped` nach dem gescheiterten `IngestKeyFor(1)` ein zweites Mal `IngestKeyFor(1)` aufrufen und den geloggten Schlüssel erwarten, damit jeder Lauf beide Reihenfolgen abdeckt. Gegenbeleg: Die Mutation „Cache auch bei Fehler“ scheitert in jedem Lauf.
- **52, Testteil:** Ein Test, dass ein frei signierter Vermerk eines Mitglieds die Epoche dauerhaft mit `ErrLog` sperrt (S88, heutiges Verhalten). Ein Test, dass eine nicht loggbare Epoche 1 vor `healHead` `ErrChain` ergibt und nichts geschrieben wird (S89). Den Text der Warnung legt der Test nicht fest. Ist einer davon mit vertretbarem Aufwand nicht baubar, beschreib das im Bericht.
- **Läufe:** gezielt mit `-run` für die betroffenen Tests und `clientdir`-, `Platform`-, `ResolveExisting`-Tests, unter race mit Tags, 386 mit Tags und ohne Tags.

## Paket C: `cmd/gomail-server`, `address add` (Nr. 63, 41). Sicherheitskritisch.

Dateien: `cmd/gomail-server/main.go` (Funktion `address` und die Hilfen dazu), Tests in `cmd/gomail-server`.

- **63:** `git am docs/tasks/vorbereitet/backlog63-address-add.patch`. Die Nachprüfung der Serie läuft parallel beim Orchestrator. Ändere die Serie nur, wenn der Orchestrator dir Funde nachreicht.
- **41:** `valid_from` = max(jetzt, letzter gültiger `valid_from` dieser Adresse + 1 ms). Den letzten Wert liefert `log.Lookup(translog.KindAddress, []byte(addr))`.
  - **Schranke:** Liegt dieser Wert + 1 ms mehr als `translog.MaxClockSkew` nach jetzt, bleibt es beim heutigen Fehler (Exit 1). So wird eine weit in die Zukunft datierte Zuordnung, etwa die eines Diebs, nicht still fortgeschrieben (Q9, F3 aus 21a).
  - **fail closed:** Lehnt `Append` trotzdem ab, etwa mit `ErrOrder`, bleibt der Fehler bestehen.
  - Prüfe zuerst in DECISIONS D80 (Nachtrag 20j) und RUNBOOK 4.2, ob das so entschieden ist. Ist es das nicht, setzt du 41 nicht um und berichtest.
  - Tests: eine geloggte Zuordnung „in der Zukunft“ innerhalb der Schranke (gelingt mit max+1 ms) und außerhalb (Exit 1); dazu ein Fall ohne vorige Zuordnung.
- **Läufe:** `cmd/gomail-server` vollständig unter race mit und ohne Tags und unter 386 mit Tags.

## Paket D: `internal/loghttp` (Nr. 7, Teilumfang). Ein Prüfer mit Angreiferblick.

Dateien: nur `internal/loghttp/loghttp.go` und Tests in `internal/loghttp`.

- (a) Bei `/cosign` den Inhaltstyp prüfen, bevor der Körper gelesen wird.
- (b) Obergrenze für gleichzeitige Anfragen mit Signaturprüfung (Semaphore; darüber 503 ohne Lesen des Körpers). Die Grenze ist eine Konstante, im Kommentar begründet.
- (c) `MaxHeaderBytes` in `NewHTTPServer` setzen, falls dort ein `http.Server` entsteht.
- Nicht in D: eine Grenze für Verbindungen im Listener und eine Rate je Quelle. Beides steht als Rest im Bericht.
- Tests:
  - Parallele Anfragen über der Grenze bekommen 503.
  - Ein falscher Typ mit großem Körper wird abgewiesen, ohne dass gelesen wird; das belegt ein Reader, der zählt.
  - Gegenbelege per Mutation.
- `FuzzServer` (oder das vorhandene Fuzz-Ziel des Pakets) 10 Minuten mit `-parallel 1`.
- **Läufe:** `internal/loghttp` und `internal/witness` unter race mit und ohne Tags und unter 386 mit Tags.

## Paket E: Hygiene, Skripte, Testlücke in `store` (Nr. 53, 59, 61, 62, 52 Vet-Teil). Ein Prüfer.

Dateien:
- `internal/translog/translogtest/unverified.go`
- `internal/translog/doc.go` (Abschnitt „Open phase-3 log sites“)
- `internal/translog/translog.go` (Text von `ErrNoLog`)
- `scripts/two-host-test.sh` (`TODO(task-15b)`)
- `scripts/bench.sh` (`render`/`envchk`)
- `internal/store/store.go` (nur ein Testhaken im Lesepfad)
- `internal/store/platform23_test.go`

- **53:**
  - Die 11 Marken `TODO(phase3-translog)` im Testdouble werden zu sachlichen Kommentaren: Was das Double tut und warum es nur in Tests verwendet wird.
  - Den Abschnitt in `doc.go` auf den Stand nach M1 bringen.
  - `TODO(task-15b)` wird zu einem Verweis auf RUNBOOK.
  - `ErrNoLog` nennt `--insecure-no-log` nicht mehr, wenn es die Option nicht mehr gibt (prüfen).
  - Nur Kommentare und Fehlertexte; ändert ein Text eine Meldung, die RUNBOOK 8.6 zitiert, steht das im Bericht.
- **59:** Ein Testhaken in `store` (unexportierte Variable, nil in Produktion, gesetzt aus `platform23_test.go`) belegt, dass `ReadPlatformCertRaw` die `.cert` genau einmal liest. Gegenbeleg: Mutante M4 (naive Fassung `ReadPlatformCert` plus zweites `ReadPlatformFile`) scheitert.
- **61:** `scripts/bench.sh -render` bricht auch ab, wenn ein eingerücktes `--- SKIP` vorkommt oder ein Unter-Benchmark fehlt, der in den anderen Wiederholungen derselben Gruppe vorkommt.
- **62:** Werte in Anführungszeichen in der `env:`-Zeile werden entquotet verglichen, und der Kommentar „empty or unset“ wird berichtigt.
- **Sicherheitsregel bei `bench.sh`:** Rufe das Skript nie ohne gültiges `-render <datei>` auf; jeder andere Aufruf misst (D94). Fehlfälle testest du in einer Kopie im Scratchpad, in der `run()` nur `echo` ausgibt. Die vier Rohdateien unter `docs/measurements/2026-11-0{3,4}/` müssen weiter rc=0 ergeben, mit `env -u TMPDIR GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -render <f> -count 5 -o <tmp>`, und dieselbe Tabelle wie bisher erzeugen.
- **52, Vet-Teil:** `GOOS=solaris go vet ./...` und `GOOS=illumos go vet ./...` nur ausführen und das Ergebnis berichten, nicht korrigieren.
- **Läufe:** `internal/translog`, `internal/translog/translogtest` und `internal/store` unter race mit und ohne Tags und unter 386 mit Tags; `bash -n` für beide Skripte.
