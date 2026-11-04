# Abschlussbericht M1 „PoC abgeschlossen“

Stand: 04.11.2026, gegen 02:45 UTC; das Ergebnis des Volllaufs `fr-m1` und der Abschluss von 20r sind gegen 04:00 UTC nachgetragen. Arbeitsbranch `claude/quirky-keller-hjsl5i`, gelesen bei fd7b87f („docs: D94, notes on the reviews of 17, ORCHESTRATION merges“).

> **Nachtrag 04.11., 04:15 UTC (Orchestrator):** Nach Redaktionsschluss ist Auftrag 17e zusammengeführt (4f247c6). `scripts/bench.sh` lehnt jetzt Optionswerte ab, die mit `-` beginnen. Das ist der Fund, den D94 als niedrig eingestuft hatte. Die Prüfung von 17e ergab keine Funde über niedrig. **Damit entfällt der Vorbehalt D94: Kriterium D ist ohne Vorbehalt erfüllt.** Wo dieser Bericht unten „erfüllt mit Vorbehalt D94“ oder den Vorbehalt des Auftraggebers zu D94 nennt, gilt das als erledigt (DECISIONS D94, Nachtrag 17e). Das Urteil bleibt **bedingt erreicht**, allein wegen E (NFSv4 auf zwei Maschinen).

**Endstand des Codes für M1: fba4eb2** = 9ad24a5 + 22 + 23 + 23b (ORCHESTRATION, 04.11., 00:50 und 02:35 UTC). Zusammengeführt um 02:35 UTC (ORCHESTRATION):
- aed6ea4: 17 mit 17b bis 17d (MEASUREMENTS, nur `internal/bench`, `scripts` und Dokumentation);
- afad8de: Auftrag 22;
- fba4eb2: Auftrag 23 mit 23b;
- 4a6e9c1: 22d (Dokumentation zu 22 und 23);
- fd7b87f: D94, Notizen zu den Prüfungen von 17, ORCHESTRATION.

Danach zusammengeführt: 541a349, Auftrag 20r mit Nacharbeit 94190c6 (HANDOFF und AUDIT endgültig auf dem Endstand fba4eb2). Das Ergebnis von `fr-m1` trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).

Gegenüber 9ad24a5 ändert der Endstand außerhalb von `internal/bench` 18 Dateien unter `internal/` und `cmd/` (+953/−65 Zeilen, davon 9 Testdateien). Der Code gleicht der Quelle des Volllaufs `fr-m1` (1217496 im Scratchpad unter `orch/m1-final`) bis auf die Testdateien in `internal/bench` aus 17 (`git diff --stat 1217496 fba4eb2 -- internal cmd`: nur 5 Dateien unter `internal/bench`). Beim Merge waren gofmt, vet (ohne Tags, mit Tags, `GOOS=openbsd`) und Build grün, die Vektoren unverändert (ORCHESTRATION, 02:35 UTC). Bis 6d35472 waren alle Commits nach 7cde738 (Auftrag 21b) im Code nur Kommentare in `internal/translog` (dcd14d9).

Dieser Bericht wurde nur aus den Dokumenten, `git log`, `git diff`, `git grep` und den Protokollen im Scratchpad des Orchestrators erstellt. Es wurden keine Tests, Builds oder Messungen ausgeführt.

> **Hinweise zu dieser Fassung (vor der Freigabe entfernen)**
> - Fortschreibung des Entwurfs vom 03.11., 23:40 UTC (gelesen bei 1b7bd05). Neu seit damals: 20q zusammengeführt (HANDOFF und AUDIT an 9ad24a5), Abschluss-Volllauf auf 9ad24a5 grün, Abdeckung am Endstand, Messungen 17b mit den Nacharbeiten 17c und 17d, D94, Aufträge 22, 23 mit 23b und 22d geprüft und zusammengeführt, Volllauf `fr-m1` auf dem Endstand grün (67 von 67 Schritten), 20r zusammengeführt (541a349).
> - Markierungen: Die Stellen, die auf den Volllauf `fr-m1` und auf Auftrag 20r warteten, sind eingetragen (Anhang A). `[OHNE BELEG: …]` steht für eine Aussage, die keine Quelle im Repository oder im Scratchpad hat; sie ist zu belegen oder zu streichen.
> - `docs/ORCHESTRATION.md` verlangt einen „Abschlussbericht nach §7“ (Abschnitt 6, Nächste Schritte, Punkt 4). Abschnitt 7 des Orchestrierungsauftrags liegt nicht im Repository. Die Gliederung folgt deshalb dem Auftrag für diesen Bericht und Auftrag 20, Punkt (7) „Zahlen für den Abschlussbericht“ (`docs/tasks/20-acceptance.md`). Sie ist gegen §7 abzugleichen. `[OHNE BELEG: Inhalt von §7]`
> - Quellen: `docs/ORCHESTRATION.md` (Abschnitte 1, 2, 4 bis 6, Verlauf bis 04.11., 02:35 UTC), `docs/HANDOFF.md` und `docs/AUDIT.md` (mit Nachträgen 21e, 20q und 22d), `docs/DECISIONS.md` (D63 bis D94), `docs/QUESTIONS.md`, `docs/SPEC-ISSUES.md`, `docs/RUNBOOK.md`, `docs/MEASUREMENTS.md` (gelesen im Worktree von 17 bei 440e188, vor 17d; zusammengeführt mit aed6ea4), `docs/tasks/20-notes.md` (bis „Aus den Prüfungen von 17“), `docs/tasks/20-mandatory-tests.md`, `docs/tasks/20-triage.md`, `docs/tasks/20o-…` bis `23-platform-single-read.md`, `docs/tasks/q19-q8-entscheidungsvorlage.md`, `git log` des Branches. Außerhalb des Branches: die Notizen von 17b und 17c (`impl17b/notes.md`, `impl17c/notes.md`) und die Protokolle unter `orch/` im Scratchpad des Orchestrators. Wo eine Zahl von dort stammt, ist das angegeben.
> - Widersprüche zwischen den Dokumenten stehen in Anhang B. Was 20p, 20q, 21e oder spätere Commits bereinigt haben, ist dort nicht mehr aufgeführt; die entfallenen Punkte stehen am Ende von Anhang B.

---

## 1. Zusammenfassung

Seit dem 26.10.2026 wurde Phase 2 nach Spezifikation 1.4 gebaut. Dazu kamen:
- das Transparenzlog auf `golang.org/x/mod/sumdb/tlog` und der Zeuge `gomail-witness`;
- die Schlüsselzeremonie mit Shamir-Anteilen;
- seit dem 03.11. der Widerruf kompromittierter Plattformgenerationen über Pin-Feld 7 (D93, Auftrag 21);
- das Zwei-Maschinen-Skript und die Messumgebung;
- AUDIT, RUNBOOK mit `TestRunbook` und HANDOFF.

Zusammengeführt sind alle Arbeitspakete der Wellen 1 bis 4. Aus Welle 5 sind es 18, 19, die Abnahmeaufträge 20a bis 20q, der Auftrag 21 (21a bis 21e), 17 mit 17b bis 17d (MEASUREMENTS), 22, 23 mit 23b, 22d und 20r (Abschnitt 3). Seit dem Entwurf vom 03.11., 23:40 UTC, abgeschlossen:
- Abschluss-Volllauf auf 9ad24a5: grün, 67 von 67 Schritten, 23:12 bis 00:58 UTC (ORCHESTRATION, 00:58 UTC).
- Abdeckung am Endstand: kein Paket unter `internal/` unter dem Soll (ORCHESTRATION, 00:35 und 02:35 UTC; `orch/cov-final/`, `orch/cov-m1/`).
- Messungen: zwei Läufe am 04.11., 01:00 bis 01:33 UTC, auf 14bf604 (Produktivcode gleich 9ad24a5 bis auf Kommentare); `docs/MEASUREMENTS.md` nach drei Prüfrunden zusammengeführt (aed6ea4). Der letzte Fund mittel ist nach **D94** als niedrig eingestuft, eine Entscheidung des Orchestrators unter Vorbehalt des Auftraggebers (Abschnitt 7a).
- 22, 23 und 23b: geprüft, Fund mittel R48 aus der Prüfung von 22 mit 23 behoben, zusammengeführt (afad8de, fba4eb2).

Nach Redaktionsschluss (gegen 02:45 UTC) abgeschlossen:
- Volllauf `fr-m1` auf dem Endstand fba4eb2 (`orch/fr-m1/`; Quellen 1217496 und 10b1783, im Code gleich dem Endstand außerhalb von `internal/bench`): **grün, 67 von 67 Schritten, kein Fehler**, 01:32:49 bis 03:40:59 UTC (Abschnitt 2, E).
- HANDOFF und AUDIT in endgültiger Fassung auf dem Endstand fba4eb2: Auftrag 20r, Merge 541a349 mit Nacharbeit 94190c6. Das Ergebnis von `fr-m1` trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).

Stand je Kriterium (Einzelheiten in Abschnitt 2; die Urteile stimmen mit HANDOFF seit 20r überein):

| Kriterium | Stand | offen |
|---|---|---|
| A Phase 2 | **erfüllt** in der Lesart „offene Haltepunkte = strengste Lesart oder nicht freigegeben“ | an Q1, Q2, Q6, Q7, Q18 und Q20 strengste Lesart bzw. nicht freigegebene Befehle; Betriebsvoraussetzung D92; die Lesart prüft der Auftraggeber (Abschnitt 7a, Nr. 9) |
| B Transparenzlog | **erfüllt** (Marken nur im Testdouble) | 11 veraltete Marken `TODO(phase3-translog)` im Testdouble `translogtest`, auch am Endstand; ob B sie einschließt, ist auszulegen (Anhang B, Nr. 2) |
| C Zeremonie | **erfüllt**: gebaut, seit 21c mit Kompromissfall (D93); im Abschluss-Volllauf auf 9ad24a5 und im Volllauf `fr-m1` auf dem Endstand bestätigt | Abläufe RUNBOOK 7.3.3 bis 7.3.5 ohne Gesamttest (vom Kriterium nicht verlangt, Abschnitt 2, C) |
| D MEASUREMENTS | **erfüllt mit Vorbehalt D94**: gemessen, `docs/MEASUREMENTS.md` nach drei Prüfrunden zusammengeführt (aed6ea4) | letzter Fund mittel nach D94 als niedrig eingestuft (Entscheidung des Orchestrators, Abschnitt 7a); 22 und 23 nicht gemessen |
| E Abnahme 10.2 | **bedingt** | Volllauf auf 9ad24a5 und Volllauf `fr-m1` auf dem Endstand grün (je 67 von 67), Abdeckung am Endstand über dem Soll; zwei Maschinen über NFSv4 nur „bedingt“ (D83, R36) |
| F HANDOFF, AUDIT, RUNBOOK | **erfüllt** | HANDOFF und AUDIT endgültig mit 20r (541a349); das Ergebnis von `fr-m1` folgt mit einem weiteren Commit (Commit siehe ORCHESTRATION, „Stand beim Anhalten“) |

**Urteil: M1 ist bedingt erreicht.**

Begründung:
- Zwei Maschinen über NFSv4 sind in dieser Umgebung nicht möglich: Es gibt weder NFS noch eine zweite Maschine (D83, AUDIT R36). Kriterium E ist deshalb nach ORCHESTRATION Abschnitt 1 nur bedingt erfüllt. Es ist das einzige bedingte Kriterium.
- Alle anderen Kriterien sind erfüllt; der Volllauf `fr-m1` auf dem Endstand ist grün (67 von 67 Schritten). HANDOFF urteilt seit 20r ebenso: A erfüllt, B erfüllt (Marken nur im Testdouble), C erfüllt, D erfüllt mit Vorbehalt D94, E bedingt (NFSv4), F erfüllt.
- Für A gilt die Lesart „offene Haltepunkte = strengste Lesart oder nicht freigegeben“ (Abschnitt 7a, Nr. 9).
- Für D gilt D94: Der Orchestrator hat den letzten Fund mittel der Nachprüfung von 17d als niedrig eingestuft. Stößt der Auftraggeber das um, ist der Fund vor dem Urteil zu beheben (D94, „Vorbehalt“).
- Für B gilt die Auslegung aus Anhang B, Nr. 2: Die 11 Marken stehen nur im Testdouble.

Der frühere Vorbehalt „S9 offen bis zur Entscheidung zu Q19 und Q8“ ist entfallen. Der Auftraggeber hat am 03.11. Option A gewählt („A bauen“, D93). Auftrag 21 hat sie gebaut; die Tests zu S9 enthalten kein `t.Skip`, und ihre Pakete sind im Abschluss-Volllauf und im Volllauf `fr-m1` auf dem Endstand grün (Abschnitt 2, E).

---

## 2. Stand je M1-Kriterium

Die Kriterien stehen in `docs/ORCHESTRATION.md` Abschnitt 1. Als erfüllt gilt nur, was gebaut und durch Tests oder Dokumente belegt ist. Hauptquelle ist die Tabelle in HANDOFF „Stand je M1-Kriterium“. Seit 20q hat HANDOFF einen Nachtrag für 20o und Auftrag 21 (Code-Stand 9ad24a5); AUDIT hat die Nachträge 21e und 20q. Was 22, 23 und 23b ändern, steht in den Dokumenten aus 22d (4a6e9c1: AUDIT „Nachtrag 22d“ und R48, D86/D93-Nachträge, RUNBOOK); HANDOFF trägt es seit 20r (Merge 541a349) und steht damit endgültig auf dem Endstand fba4eb2.

### A: Phase 2 vollständig (2.2, 2.4, 2.5, 6, 7, 9)

**Gebaut:**
- Epochen mit Gründen und `discards`; sofortige und geplante Epochen; Vorrat (D63, D68, D71; Commit 38626a9, adf8431).
- Mitglieder: `share`, `revoke`, Leser vergangener Zeiträume (D75, D86).
- Generationen: `device lost`, `restore`, `keygen --shares`, `wrap-accept`, Prüfvermerke. Die Übernahme nach 2.2 Punkt 4 gilt für alle Dateiarten außerhalb des Logs (D84, D91; a296a8b, 3e06f23).
- Ordnerliste je Epoche; Flags mit Versionsregel (K4); Index, Suche, Zusammenfassen (D79, D91; dbb667b, 3e06f23).
- Sperren und Rechte nach 9.1 (D70, D81); Befehle nach 9.2 (D86, D87; 4748ac7, c931a31).
- `keygen` und `restore` legen das Client-Verzeichnis in einem Schritt an:
  - seit 20l über einen Deskriptor mit Identitätsprüfungen (D86 Nachträge 20b bis 20l; b155e1f, d85da00, 858b2f1, b674ae3);
  - seit 20o wird ein unfertiges Temp-Verzeichnis nicht als Client-Verzeichnis geöffnet, und Reste werden ganz oder gar nicht aufgeräumt;
  - seit 20o wird „nicht im Datenverzeichnis“ über aufgelöste Pfade geprüft (D86 Nachtrag 20o; 9e34841).
- Metadaten ab Version 2 prüft der Client seit 21b gegen den Widerruf (`checkReceivedCovered`, D93 Nachtrag 21e).
- Am Endstand (Auftrag 22, afad8de): `resolveExisting` folgt auch hängenden Symlinks (D86 Nachtrag 22, 4a6e9c1). Ein `..` nach einem Symlink im Linkziel wird weiter lexikalisch bereinigt; angelegt wird trotzdem nichts (`docs/tasks/20-notes.md`, „Aus der Angreiferprüfung von 22“, N4).
- Am Endstand (Auftrag 23 mit 23b, fba4eb2): `ingestKeyFor` liest `ingest-<g>.cert` nur einmal; Signatur, Schlüssel und Logabgleich arbeiten auf denselben Bytes (`store.ReadPlatformCertRaw`; ORCHESTRATION, 01:10 UTC; AUDIT R48).

**Belege:** Pflichttests G1 bis G9, S1 bis S6, S8, Z1, Z2 und Z4 sind vollständig zugeordnet (`docs/tasks/20-mandatory-tests.md`). Z3 ist für den Suchmarken-Index vollständig (`TestDeviceChangeTakesOverSegments`, `TestDeviceChangeThenDeviceLost`, 20h). Der Volltextteil von Z3 gehört nicht zu M1.

**Was fehlt oder eingeschränkt ist:**
- Befehle, die an offenen Fragen hängen: `mailbox rotate` (Q7, nicht gebaut), `--delegate` (Q6, Art 3 nur in der API), `recovery …` (Q1, nur interne API). `--server-search` (Q3) gehört nicht zu M1.
- Q18: Ein alleiniges Mitglied ohne geprüfte Ordnerliste hat keinen Ausweg (AUDIT R21).
- Betriebsvoraussetzung D92: Das Elternverzeichnis eines Client-Verzeichnisses darf nur für den eigenen Benutzer beschreibbar sein oder muss das Sticky-Bit tragen. Das Programm prüft das nicht (Abschnitt 8). Eine Prüfung im Programm stand auf der Kandidatenliste (ORCHESTRATION, 23:25 UTC), wurde aber nicht beauftragt; sie steht in der Liste nach M1 (Abschnitt 9).

**Stand:** A ist erfüllt in der Lesart „offene Haltepunkte = strengste Lesart oder nicht freigegeben“: An Q1, Q2, Q6, Q7, Q18 und Q20 ist die strengste Lesart gebaut oder der Befehl nicht freigegeben. So stuft HANDOFF seit 20r ein; die erste Prüfung von 20r hatte das frühere Urteil „bedingt“ als nicht belegt gemeldet (Abschnitt 2, F). Die Lesart ist eine Auslegung, die der Auftraggeber prüfen sollte (Abschnitt 7a, Nr. 9).

### B: Transparenzlog, Zeuge, Vermerke, 24 h, kein `--insecure-no-log`

**Gebaut:**
- Log auf `tlog` (D78, ad67baf); Serverseite mit `internal/loghttp` (D80, a1c10cc).
- Prüfungen in `ingest` und Server, `--insecure-no-log` entfernt (D81, 3ff099b).
- Client am Log mit Vermerken und 24-Stunden-Regel (D88, c4e9014).
- `gomail-witness` (D74, e1767dc).
- Seit 21a: Widerrufsregeln für Plattformgenerationen im Log (Pin-Feld 7, Kaskade, `ErrRevoked`, `ErrRevokedHead`; `log repair` verschiebt Köpfe einer widerrufenen Generation nach `log/heads-revoked/`; D93, 02ee7b5).
- Am Endstand (Auftrag 23): Client und `ingest.New` gleichen ein Ingest-Zertifikat mit dem Log auf denselben Bytes ab, mit denen sie Signatur und Schlüssel prüfen. Vorher konnte ein Tausch der Datei zwischen zwei Lesevorgängen den Logabgleich umgehen (R48, mittel, D93 Nachtrag 23).

ORCHESTRATION Abschnitt 4 nennt B mit dem Merge von 14 „vollständig im Arbeitsbranch“.

**Was fehlt:**
- Im Produktivcode nichts. HANDOFF sagt: „Alle `TODO(phase3-translog)` im Produktivcode sind aufgelöst.“
- Im Testdouble `internal/translog/translogtest/unverified.go` stehen noch 11 Marken `TODO(phase3-translog)` (am Endstand fba4eb2 mit `git grep` geprüft). HANDOFF nennt sie veraltet und umzubenennen. Das Kriterium verlangt wörtlich „alle `TODO(phase3-translog)` aufgelöst“ (Anhang B, Nr. 2). Die Umbenennung stand in der Kandidatenliste des Orchestrators (23:25 UTC), wurde aber nicht beauftragt.
- Mehrere Zeugen im Betrieb folgen erst vor echten Mails (2.7; AUDIT 1.3, R15).

### C: Zeremonie mit `init --shares 3-of-5`, `ingest-rotate`, `reshare`, Probe; `--dev` nur für Tests

**Gebaut:**
- `init --shares` mit Probe-Rekonstruktion, `ingest-rotate`, `reshare`, `succeed`, `publish` über das Log (D82, D85; ef8e408, 52ec07a).
- `--dev` nur im Build mit `gomail_dev` (D85 (3)).
- Terminalregeln mit Abbruchpfad (15i bis 15n, d636ffc; 20a, e799367).
- Seit 21c der Kompromissfall nach D93 (12d48cc):
  - `succeed --compromised --revoke-at-size --revoke-at-time` schreibt die kompromittierte Identität in Pin-Feld 7. Die Grenze ist die Zeit des zeugenbestätigten Kopfes plus 1 ms.
  - `revoke --role admin|ingest` und `admin-rotate`.
  - `publish` prüft Feld 7 gegen den neuesten veröffentlichten Kopf und das Log und ersetzt Dateien ungültiger Zertifikate.
  - Ablauf für den Betreiber: RUNBOOK 7.3 (21d, 21e).
- Am Endstand (Auftrag 22, afad8de; D93 Nachtrag 22, 4a6e9c1):
  - `publish` heilt `data/platform/`: Ein Name gilt auch dann als frei, wenn sein gültiger Logeintrag genau die Datei des Exports ist; eine fremde Datei unter diesem Namen ersetzt `publish` atomar durch die Exportdatei.
  - Die Prüfung „wäre nie gültig gewesen“ gilt nur noch für Ingest. Für ein Admin-Element begrenzt nur `minHeadTime` (01.01.2025) `revoked_at_time` nach unten; die Obergrenze aus dem neuesten Kopf gilt weiter (`checkRevocations`).
  - RUNBOOK 1.5, 7.3 und 8.6 beschreiben das mit 22d (ORCHESTRATION, 01:10 UTC).

**Bestätigung:** Der Abschluss-Volllauf auf 9ad24a5 ist grün (67 von 67 Schritten, ORCHESTRATION 00:58 UTC), darunter alle Schritte für `internal/ceremony`, `cmd/gomail-ceremony` und `internal/e2e` (Protokolle `orch/fr-final/`). Die `-v`-Läufe von `cmd/gomail-ceremony` auf 10b1783 (Code von `cmd/gomail-ceremony` und `internal/ceremony` gleich dem Endstand) sind grün (Abschnitt 2, E). Der Volllauf `fr-m1` auf dem Endstand mit 22 ist grün, 67 von 67 Schritten, darunter alle Schritte für `internal/ceremony`, `cmd/gomail-ceremony` (auf 10b1783) und `internal/e2e` (Abschnitt 2, E). **Stand:** C ist erfüllt.

**Was fehlt:**
- Die Abläufe RUNBOOK 7.3.3 bis 7.3.5 prüft kein Test als Ganzes mit den Programmen (HANDOFF „Was die nächste Phase als Erstes wissen muss“, Punkt 1; RUNBOOK „Nicht in `TestRunbook`“). Das verlangt Kriterium C nicht wörtlich. Für den Betrieb ist es aber eine Lücke.
- Restgrenzen: AUDIT R17, R18 (Abschnitt 8).
- Die niedrigen Restpunkte aus den Nachprüfungen von 21c hat Auftrag 22 erledigt (Punkte 1 und 2 in `docs/tasks/22-extras.md`). Neue niedrige Punkte aus den Prüfungen von 22 und 22d (Symlinks unter `data/platform/`, Kommentare, zwei Testlücken) stehen in der Liste nach M1 (Abschnitt 9).

### D: `docs/MEASUREMENTS.md`, reproduzierbar

**Gebaut:** Messumgebung `internal/bench` und `scripts/bench.sh` (D77, d4a8377; Indexmessungen 12d, e48b35b).

**Verlauf:**
- Auftrag 17 lief ab dem 03.11., 18:45 UTC, auf 374f499 allein auf der Maschine. Um 19:15 UTC wurde er gestoppt, weil Option A Code ändert (ORCHESTRATION Abschnitt 6). Seine zwei Läufe vom 03.11. (374f499) stehen in `docs/MEASUREMENTS.md` als „Vergleich mit dem Stand vor D93“, mit Rohdaten unter `docs/measurements/2026-11-03/`.
- Auftrag 17b setzte den Worktree von 17 fort (`docs/tasks/17b-measurements-endstand.md`). Lauf 1 lief am 04.11. von 01:00:33 bis 01:16:28 UTC, Lauf 2 von 01:17:54 bis 01:32:38 UTC, beide mit rc=0 (`impl17b/notes.md`; MEASUREMENTS „Ruhige Maschine“).
  - Während der Messung galt die Regel `QUIET`: von 00:58 bis 01:33 UTC startete kein anderer Agent `go`-Befehle (ORCHESTRATION, 00:58 und 01:33 UTC).
  - Die Last der letzten Minute lag vor jeder der zehn Gruppen unter 0,5; Steal 0,25 bis 0,86 % (MEASUREMENTS, Tabelle „Ruhige Maschine“).
  - Den Messagenten hielt der Orchestrator nach dessen Übergabe an; Lauf 2 startete der Orchestrator mit demselben Skript (ORCHESTRATION, 01:33 UTC).

**Gemessener Stand:** 14bf604, der Merge des Arbeitsbranchs (44cff6a) in den Worktree von 17 (`impl17b/notes.md`). Im Produktivcode gleicht 14bf604 dem Endstand 9ad24a5 bis auf Kommentare: `git diff --stat 9ad24a5 14bf604 -- internal cmd ':!internal/bench'` zeigt nur `internal/translog/doc.go` und `verifier.go`, nur Kommentarzeilen (`impl17b/notes.md`; MEASUREMENTS „Code-Stand“). Die Kennung 14bf604 gibt es nach dem Zusammenfassen nicht mehr. MEASUREMENTS belegt den Stand deshalb über die Bäume je Paket im einführenden Commit (Nacharbeit 17c). **Die Aufträge 22 und 23 sind nicht gemessen** (MEASUREMENTS „Grenzen der Messung“). Nach MEASUREMENTS berühren beide keinen Pfad, der je Mail läuft; 23 spart beim Laden eines Zertifikats ein Lesen.

**Befehl und Umgebung** (MEASUREMENTS „Angaben, die für jede Zahl gelten“):
- Befehl: `GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -count 5 -maxload 0.5`, je Gruppe ein `go test -tags gomail_dev -run '^$' -bench …` über `./internal/bench`.
- Hardware: Firecracker-VM mit 4 vCPU (Xeon 2,8 GHz) und 16 GiB, ext4 auf virtio, Go 1.26.10.
- Lockerungen: die aus D77 (`MaxConns` und `MaxConnsPerIP` 64, kein Mail-Limit je IP, eingefrorene Uhr, verworfenes Log); dazu `MinFree` 0,1 % statt 1 %.
- Ingest prüft in der Messung gegen `translogtest.Unverified`, nicht gegen das Betreiberlog. Die Prüfungen von D93 liegen deshalb nicht im Messpfad des Empfangs.

**Kennzahlen** (Median aus 10 Wiederholungen, zwei Läufe zu je 5; in Klammern kleinster und größter Wert; MEASUREMENTS „Kennzahlen auf einen Blick“):

| Kennzahl | `enc` | `proto` | `plain` |
|---|---|---|---|
| Empfang 4 KiB, 1 Verbindung, Mails/s | 108 (88,8–130) | 119 (98,0–142) | 1264 (1207–1359) |
| Empfang 1 MiB, 4 Verbindungen, MiB/s | 68,9 (64,2–77,4) | 104 (95,9–108) | 176 (162–195) |
| Empfang 10 MiB, 1 Verbindung, MiB/s | 58,1 (53,7–61,3) | 93,5 (86,1–112) | 108 (97,3–121) |
| Empfang 10 MiB, 4 Verbindungen, MiB/s | 134 (108–149) | 205 (163–225) | 226 (213–271) |

| Kennzahl | Wert |
|---|---|
| Durchsatzanteil `enc / proto` bei 1 und 10 MiB | 0,62 bis 0,70 |
| Indexierung je Mail, Begriffslisten des Servers (`terms`) | 58,5 (50,8–64,4) µs |
| Indexierung je Mail, nur Marker (`unprocessed`) | 876 (802–1113) µs |
| Index je 1000 Mails, 16 Segmente / zusammengefasst | 193 184 / 143 600 Bytes (in allen 10 Wiederholungen gleich) |
| `Sync` bei 10 000 Mails, ohne / mit Indexierung | 0,0173 (0,0158–0,0184) s / 0,347 (0,322–0,373) s |
| `List` über 10 000 Mails (kein Teil von `Sync`) | 2,46 (2,32–2,78) s |
| Server-VmRSS, 1000 Mails zu 1 MiB, 20 Verbindungen: vor / Spitze / nach der Last | 12,04 / 24,34 / 13,77 MiB |

Aussagen von MEASUREMENTS dazu:
- Bei kleinen Mails bestimmt das Ablageprotokoll den Durchsatz. `proto − plain` liegt bei 7,6 bis 8,4 ms je Mail mit einer Verbindung. Bei großen Mails kostet die Verschlüsselung 30 bis 38 % des Durchsatzes.
- Unterschiede unter etwa 20 % sind auf dieser Maschine nicht belastbar: Die Mediane der beiden Läufe liegen bis 29 % auseinander.
- Gegenüber dem 03.11. (374f499) zeigen die Client-Zahlen keine Verlangsamung durch D93. Für den Empfang sagt der Vergleich über D93 nichts, weil dessen Prüfungen nicht im Messpfad liegen. Auch `plain` war am 04.11. schneller, der Unterschied liegt also zum Teil an der Umgebung.

**Prüfung und Nacharbeit:**
- Prüfung von 17b: Alle Zahlen stimmen mit den Rohdaten. Sie fand aber 3 Funde mittel und 7 niedrige (ORCHESTRATION, 02:05 UTC):
  - zitierte Worktree-Commits nach dem Zusammenfassen unerreichbar;
  - ein Schluss zu D93 auch für den Empfang, obwohl die Logprüfungen nicht im Messpfad liegen;
  - `bench.sh` nicht fail closed bei fehlenden Gruppen.
- Nacharbeit 17c, Worktree-Commit 440e188 (`impl17c/notes.md`):
  - Bäume statt Commit-Kennung;
  - `bench.sh` gibt aus unvollständigen Rohdaten keine Tabelle aus und stellt mit `-render` vorhandene Rohdaten dar;
  - eine echte Prüfung von `GOMAIL_BENCH_MIN_FREE` in `internal/bench`;
  - `nachtrag-17c.diff` hält den Unterschied zum gemessenen Messcode fest;
  - gofmt, vet, `internal/bench` unter race und 386 grün.
- Nachprüfung von 17c: M1 bis M3 und die sieben niedrigen Punkte behoben. Neu war ein Fund mittel F1: `scripts/bench.sh -render=` mit leerem Wert startete eine volle Messung. Dazu kamen F2 und F3 (niedrig; ORCHESTRATION, 02:20 UTC; `docs/tasks/20-notes.md`, „Aus den Prüfungen von 17“) → Nacharbeit 17d. Dabei startete der Prüfer versehentlich von 02:15 bis 02:17 UTC eine Messung neben dem Volllauf `fr-m1` (Abschnitt 2, E).
- Nacharbeit 17d: F1 für leere Werte behoben, `go.mod` und `go.sum` in der Tabelle der Bäume (MEASUREMENTS „Code-Stand“ bei aed6ea4). Die Messwerte in `docs/MEASUREMENTS.md` sind seit 440e188 unverändert; geändert sind nur die Angaben zum Code-Stand und `nachtrag-17c.diff` (`git diff 440e188 aed6ea4 -- docs/MEASUREMENTS.md`).
- Nachprüfung von 17d, die dritte Prüfrunde (`docs/tasks/20-notes.md`, „Aus den Prüfungen von 17“):
  - neu ein Fund mittel M1: Ein Optionswert, der mit `-` beginnt, wird angenommen; `-o -render=F` startet eine Messung;
  - niedrig N1 (fehlende Kopfzeilen `command:`/`env:` werden nicht abgeglichen) und N2 (weitere Umgebungsvariablen nicht abgeglichen);
  - F3 aus 17c bleibt niedrig offen (fehlender Unter-Benchmark, eingerücktes `--- SKIP`).
- **D94, Entscheidung des Orchestrators:** Er stuft M1 als niedrig ein; 17 wird damit ohne offenen Fund über niedrig zusammengeführt. Begründung nach D94:
  - Der Fund betrifft nur das Einlesen der Optionen eines Entwicklerwerkzeugs und greift nur bei einem Tippfehler.
  - Er erzeugt keine falschen oder still unvollständigen Zahlen und berührt weder MEASUREMENTS noch Produktivcode, Sicherheit oder fail closed beim Darstellen.
  - Mit 17b, 17c und 17d ist die dritte Prüfrunde erreicht; eine vierte Runde nur für diesen Punkt ändert am Kriterium D nichts.
  - **Vorbehalt** (D94): Der Auftraggeber kann die Einstufung umstoßen; dann ist der Fund vor dem Urteil zu beheben. Abhilfe nach M1: `need` lehnt auch Werte ab, die mit `-` beginnen; dazu N1 und N2. Siehe Abschnitt 7a.
- Zusammenführung: aed6ea4, vor 22 und 23. So trägt der Commit, der MEASUREMENTS einführt, außerhalb von `internal/bench` und `scripts` die Bäume des gemessenen Stands (ORCHESTRATION, 02:05 und 02:35 UTC).

**Stand:** Kriterium D ist erfüllt. Die Einstufung des letzten Fundes beruht auf D94 (Vorbehalt des Auftraggebers). Die Teilergebnisse des gestoppten Laufs vom 03.11. sind nur als Vergleich verwendet, nicht als Kennzahlen.

### E: Abnahme nach 10.2

**Pflichttests aus 10.1** (`docs/tasks/20-mandatory-tests.md`, HANDOFF „Pflichttests aus 10.1“):

| Stand | Zahl | Pflichttests |
|---|---|---|
| vollständig | 27 von 30 | T1–T3, K1, K2, G1–G9, S1–S6, S8, F1–F3, Z1, Z2, Z4 |
| teilweise | 2 | S9: mit Auftrag 21 gebaut, „vollständig, sobald der Abschluss-Volllauf sie bestätigt“ (HANDOFF); der Abschluss-Volllauf auf 9ad24a5 und der Volllauf `fr-m1` auf dem Endstand sind grün (unten). Z3: Volltextteil nicht M1 |
| fehlt | 1 | S7 (Löschen von Epochen, 2.6): nicht M1 |

S9 ist seit Auftrag 21 so belegt:
- Identität: `TestVerifyCompromisedIdentityStillIssues` (`internal/ceremony/succession15f_test.go`) ohne Skip (21c). Im Test steht kein `t.Skip` mehr (bei 1b7bd05 gelesen; AUDIT 6.1 seit 20q).
- Ingest: `TestLogIngestRevoked` und `TestRevokedIngestEndToEnd` (`internal/client/revoke21b_test.go`, `internal/e2e/revoke21b_test.go`; 21b).
- Regeln: `TestRevokedCompromise` und die übrigen Tests in `internal/translog/revoke21a_test.go` und `rework21a_test.go` (21a).
- Im Abschluss-Volllauf auf 9ad24a5 sind alle Schritte von `internal/ceremony`, `internal/client`, `internal/e2e` und `internal/translog` grün. Der Lauf lief ohne `-v`; dass diese Tests einzeln liefen und sich nicht überspringen, zeigen deshalb nicht die Protokolle, sondern der Code: kein `t.Skip` in `TestVerifyCompromisedIdentityStillIssues`, die Tests in `client` und `e2e` laufen mit Tags. Damit sind es 28 von 30 vollständig; die zwei übrigen liegen außerhalb von M1.
- Im Volllauf `fr-m1` auf dem Endstand sind die S9-Tests ebenfalls bestanden, die mit `testenv` in den Schritten mit Tags. HANDOFF steht seit 20r endgültig auf dem Endstand; das Ergebnis von `fr-m1` trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).

Seit 374f499 sind 56 Testfunktionen hinzugekommen und eine entfallen (20o, 21a bis 21c; gezählt mit `git diff 374f499 HEAD -- '*_test.go'`).

**`go vet`, `-race`, 386:** Volläufe des Orchestrators mit je 67 Schritten (gofmt, vet, `-race` mit und ohne Tags und 386 je Paket, `internal/e2e`):

| Code-Stand (Worktree) | entspricht auf dem Branch | Ergebnis | Quelle |
|---|---|---|---|
| 7ffed5c (09g) | 3e06f23 | grün | ORCHESTRATION Abschnitt 5 |
| cb2344c (20b) | b155e1f ohne die Tests aus 20f und 20g | grün; die zwei `client`-Schritte nach Abbruch an der 40-Minuten-Grenze unter Last mit 60 Minuten wiederholt | ORCHESTRATION Abschnitt 6 |
| b2032d5 (20e) | d85da00 | grün; `TestPTYPromptBlocked` einmal an der 4,5-s-Grenze gescheitert, Wiederholung grün | ORCHESTRATION Abschnitt 6 |
| 302c6db (20h) | 858b2f1 | grün; `TestPTYStopLoop/6` einmal an der 4,5-s-Grenze gescheitert, Wiederholung grün | ORCHESTRATION Abschnitt 6 |
| 1d49e6d (20i und 20l) | b674ae3 ohne die Tests von 20m | grün | ORCHESTRATION Abschnitt 6; HANDOFF (Zuordnungstabelle) |
| **9ad24a5 (Abschluss-Volllauf)** | Code gleich 6d35472 bis auf Kommentare in `translog` | **grün, 67 von 67 Schritten**, ohne Wiederholung, 23:12 bis 00:58 UTC | ORCHESTRATION, 04.11., 00:58 UTC; `orch/fr-final/` |
| **1217496** (`orch/m1-final`: 9ad24a5 + 22 + 23 + 23b); gofmt, vet und `cmd/gomail-ceremony` auf 10b1783 (ohne 23b) | fba4eb2 bis auf die Testdateien in `internal/bench` aus 17 | **grün, 67 von 67 Schritten**, kein Fehler, 01:32:49 bis 03:40:59 UTC, nach drei Container-Neustarts fortgesetzt | ORCHESTRATION, 01:33, 01:42, 02:05 UTC; `orch/fr-m1/`, `orch/fr-m1-steps.txt` |

Die Zuordnung „entspricht“ steht seit 20p als Tabelle in HANDOFF; sie ist mit `git diff --stat` über `internal/`, `cmd/` und `scripts/` geprüft. Die beiden Fehlschläge an der 4,5-s-Grenze sind nach der Analyse als Stillstand der Maschine eingeordnet, nicht als Fund im Produktivcode (D85 Nachtrag 20n). Seit 20m erkennen die Tests einen Stillstand.

**Abschluss-Volllauf auf 9ad24a5** (Protokolle im Scratchpad unter `orch/fr-final/`, Skript `orch/fullrun2.sh`, über `fullrun-nice.sh` mit `nice -n 19`):
- **Schritte:** gofmt; vet als `go vet ./...` und `go vet -tags gomail_dev,gomail_test ./...`; je Paket `-race` ohne Tags, `-race` mit `gomail_dev,gomail_test` und `GOARCH=386` mit Tags. Bei `internal/e2e` gibt es keinen 386-Schritt, dafür `GOMAIL_TEST_MIN_FREE`. Zusammen 67 Schritte, alle mit `.ok`, kein `.fail`, `rev` = 9ad24a5. vet lief nur für linux/amd64 und nur mit diesen beiden Tag-Kombinationen, ohne `ceremony_notty` und ohne andere GOOS (AUDIT 6.1 nennt die übrigen Läufe; R40).
- **Dauer:** 23:12 bis 00:58 UTC, etwa 1 Stunde 46 Minuten, unter fremder Last: daneben liefen Auftrag 22 und die Abdeckung, beide mit `nice -n 19` (ORCHESTRATION, 00:10 UTC).
- **Längste Schritte** (Zeile `ok … s` der Protokolle):
  - `internal/client`: mit race und Tags 2178 s, unter 386 1755 s;
  - `cmd/gomail-ceremony`: race 433 s, race mit Tags 432 s, 386 295 s;
  - `internal/e2e`: race mit Tags 125 s, race 107 s;
  - `internal/ingest`: race mit Tags 117 s.
- **Wiederholte Schritte:** keine.
- **Übersprungene Tests:** Der Volllauf lief ohne `-v`, seine Protokolle nennen keine SKIPs. Für die Stillstandserkennung aus 20m gibt es eigene `-v`-Läufe von `cmd/gomail-ceremony` (unten). Die Skips von `TestOpenRegularNoCTTY`, `TestLockFileNoCTTY` und `TestKeystoreNoCTTY` (AUDIT 6.1) sind in keinem `-v`-Lauf geprüft.
- **Vermerk in ORCHESTRATION:** 04.11., 00:58 UTC (Commit 44cff6a).

**Volllauf auf dem Endstand** (`fr-m1`; Protokolle im Scratchpad unter `orch/fr-m1/`, Schrittzeiten in `orch/fr-m1-steps.txt`; dasselbe Skript wie bei `fr-final`): gestartet auf der lokalen Quelle `orch/m1-final` (ORCHESTRATION, 01:33 UTC).
- **Ergebnis: grün, 67 von 67 Schritten, kein Fehler.**
- **Dauer:** 01:32:49 bis 03:40:59 UTC, unter fremder Last.
- **Unterbrechungen:** Container-Neustarts gegen 01:42, 03:26 und 03:40 UTC. Der Lauf wurde jeweils über die `.ok`-Marken fortgesetzt; ein abgebrochener Schritt lief ganz neu.
- **Laufstände:** gofmt, vet und `cmd/gomail-ceremony` liefen auf 10b1783 (Endstand ohne 23b; 23b ändert nur einen Test in `client`). Alle übrigen Schritte liefen auf 1217496, im Code gleich fba4eb2 außer `internal/bench`. gofmt und vet sind auf 1217496 und auf dem Branch separat grün (ORCHESTRATION, 02:05 UTC; `orch/fr-m1/NOTE`).
- **`internal/bench`:** Die Testdateien aus 17 enthält `fr-m1` nicht. Mit ihnen ist `internal/bench` auf dem Branch (aa87a99) unter `-race`, `-race` mit Tags und 386 grün (`orch/fr-head-bench/`).
- **Störung:** Von 02:15 bis 02:17 UTC lief versehentlich eine Messung des Prüfers von 17c neben dem Volllauf. Für die Korrektheit ist das unerheblich, die Laufzeiten dieses Fensters sind gestört (ORCHESTRATION, 02:20 UTC).
- **Längste Schritte:** `racetag-internal_client` 2036 s, `386-internal_client` 1260 s; `cmd/gomail-ceremony` 438 s (`-race`), 455 s (`-race` mit Tags) und 296 s (386); `internal/e2e` 99 s (`-race`) und 109 s (`-race` mit Tags).
- **Damit bestanden:** die Tests aus 22 und 23, darunter `TestPlatformIngestCertSwapped` und `TestPlatformCertReadOnce`, sowie die S9-Tests (die mit `testenv` in den Schritten mit Tags).

**`-v`-Läufe von `cmd/gomail-ceremony`** (Nachweis zu den SKIPs aus 20m; Quelle 10b1783 = 9ad24a5 + 22 + 23; Protokolle `orch/fr-m1-v/`, Skript `orch/ceremony-v.sh`):

| Lauf | Ergebnis | Dauer | `--- PASS` | `--- SKIP` |
|---|---|---|---|---|
| `-race` | ok | 435 s | 325 | `TestStallChild`, `TestStallDetect/retry_stalled_twice/inner` |
| `-race`, Tags `gomail_dev,gomail_test` | ok | 445 s | 325 | ebenso |
| `GOARCH=386`, Tags | ok | 305 s | 325 | ebenso |

`TestStallChild` ist der Hilfsprozess der Stillstandserkennung, `TestStallDetect/retry_stalled_twice/inner` ihr Selbsttest. Kein echter Teiltest wurde von der Stillstandserkennung übersprungen (ORCHESTRATION, 02:20 UTC; `grep -- '--- SKIP'` in den drei Protokollen). 23b ändert nur Testcode in `internal/client`; die Läufe gelten deshalb auch für 1217496.

**Ohne eigenen Volllauf zusammengeführt** und vom Abschluss-Volllauf auf 9ad24a5 abgedeckt:
- 20m: nur Testcode.
- 20o: gezielte Client-Verzeichnis-Tests unter race und 386 mit Tags.
- 21a: race und 386 für `store`, `translog`, `rec` mit und ohne Tags; das ganze Modul ohne race.
- 21b und 21c: Läufe der Implementierer; beim Merge gofmt, vet mit und ohne Tags, Build des Moduls, Phase-0-Vektoren unverändert.
- 21d und 21e: nur Dokumentation und Kommentare.

Quelle für alle: ORCHESTRATION Abschnitt 6.

Zwischen dem vorletzten grünen Volllauf (b674ae3 ohne 20m-Tests) und 9ad24a5 lagen 26 Dateien Produktivcode (+2980/−488 Zeilen) und 35 Testdateien (`git diff --stat 374f499 1b7bd05`). Diese Lücke schließt der Abschluss-Volllauf.

**Nach dem Abschluss-Volllauf** zusammengeführt und seit `fr-m1` im vollständigen Volllauf geprüft: 22, 23 und 23b (18 Dateien unter `internal/` und `cmd/`, +953/−65; `git diff --stat 9ad24a5 1217496 -- internal cmd`). Die Testdateien in `internal/bench` aus 17 enthält `fr-m1` nicht; für sie gibt es die Läufe der Implementierer von 17b bis 17d (race, 386, vet; ORCHESTRATION, 02:05 UTC) und den grünen Lauf auf dem Branch (aa87a99, `orch/fr-head-bench/`). Vor `fr-m1` waren 22, 23 und 23b so geprüft:
- 22: gezielte Läufe des Implementierers grün (ORCHESTRATION, 00:35 UTC). Der eigene Volllauf auf 3cd9072 wurde zugunsten des gemeinsamen Volllaufs abgebrochen (00:50 UTC).
- 23 (ORCHESTRATION, 01:42 UTC):
  - Läufe des Implementierers: race und 386 für `store` und `ingest` grün, `client` gezielt unter race grün, e2e grün.
  - `client` gezielt unter 386 rot: Die Erwartung von `TestPlatformIngestCertSwapped/forged_then_logged` hing vom Ablauf ab; die Sicherheitseigenschaft hielt → Nacharbeit 23b.
- 23b: Gegenbeleg unter amd64 und 386 hält (ORCHESTRATION, 02:05 UTC). Die Nachprüfung tötete je 5/5 Mutationen unter amd64 und 386 (`docs/tasks/20-notes.md`, „Läufe der Prüfungen von 23“).
- Der Volllauf `fr-m1` auf dem Endstand ist grün, 67 von 67 Schritten (oben).

**Fuzzing:**
- Alle 25 Ziele liefen je 10 Minuten ohne Fund (HANDOFF „Fuzzing“):
  - 19 Ziele auf bf427c2;
  - `store.FuzzDecodeRecords` auf 84ca174 (`store` gleich 20b);
  - die 5 Ziele in `translog` auf d85da00 (nach 20e).
- Die 5 `translog`-Ziele liefen zusätzlich auf 84ca174, ebenfalls ohne Fund.
- **Neu, vierter Teil (nach 21a):** `store.FuzzDecodeRecords` und die 5 `translog`-Ziele auf 56464da, je 10 Minuten in zwei Bahnen, alle ohne Fund (`docs/tasks/20-notes.md`, „Fuzzing, vierter Teil“; Protokolle im Scratchpad `orch/fz4/`). Ausführungen in 10 Minuten:

  | Ziel | Ausführungen |
  |---|---|
  | `store.FuzzDecodeRecords` | 9.146.068 |
  | `translog.FuzzAuditIndex` | 3.137.084 |
  | `translog.FuzzDecodeEntry` | 6.929.298 |
  | `translog.FuzzOpenHead` | 6.936.251 |
  | `translog.FuzzParseHeadText` | 7.142.506 |
  | `translog.FuzzProofs` | 4.665.887 |

  Damit ist der frühere Platzhalter P4 (`store`-Fuzzing nach 20l) erledigt; der Lauf auf 56464da enthält 20l, 20o und 21a.
- Summe: 36 Läufe zu je 10 Minuten, also 360 Minuten.
- Ausführungen je Ziel in 10 Minuten: von 526.897 (`keys.FuzzParseWordlist`) bis 12.377.691 (`shamir.FuzzShareFromBytes`).
- F1 bis F3 aus 10.1 (`.gml`-Parser, SMTP-Parser, Shamir-Anteile) sind abgedeckt.

**Bezug zum Endstand** (eigene Durchsicht mit `git diff`):
- `store` ist zwischen 56464da und 9ad24a5 unverändert, `translog` nur in Kommentaren (21e).
- 23 ändert in `store` nur `store.go` (Lesefunktion `ReadPlatformCertRaw`), nicht `records.go` mit den Decodern, die `store.FuzzDecodeRecords` prüft (`git diff --stat 9ad24a5 fba4eb2 -- internal/store`).
- Von den Paketen der 19 Ziele des ersten Teils hat sich seit bf427c2 nur `internal/ingest/ingest.go` geändert (21b und 23, jeweils in `ingest.New`). Das Ziel `ingest.FuzzTerms` prüft `ingest.Terms`, das davon nicht berührt ist.
- Kein Ziel ist seit dem ersten Teil hinzugekommen. Am Endstand sind es weiter 25 Funktionen `Fuzz…` (`git grep -c 'func Fuzz'`); 22 und 23 bringen kein Ziel dazu, ihre neuen Testdateien (`heal22_test.go`, `clientdir22_test.go`, `platform23_test.go`) enthalten keins.
- HANDOFF führt den vierten Teil seit 20q.
- Die Protokolle aller vier Teile liegen weiter im Scratchpad (`orch/fz/` bis `orch/fz4/`, bei Redaktionsschluss vorhanden).

**Abdeckung am Endstand:** `go test -count=1 -cover`, ohne race, mit `nice -n 19` neben dem Volllauf. „mit Tags“ heißt `-tags gomail_dev,gomail_test`. Soll nach Kriterium E: 85 % je Paket, 90 % für `rec`, `keys`, `shamir`, `envelope` und `translog` (HANDOFF „Testabdeckung“). Quellen:
- `orch/cov-final/tabelle.md`: alle Pakete auf 9ad24a5 (ORCHESTRATION, 00:35 UTC);
- `orch/cov-m1/*.log`: die von 22 und 23 geänderten Pakete auf dem Endstand. `client`, `ingest` und `store` sind auf 1217496 gemessen (mit 23b), `ceremony` auf 10b1783 (`orch/cov-m1/rev`, `rev-client-ingest-store`). 23b ändert nur Testcode in `client`.

| Paket | ohne Tags | mit Tags | Soll | Stand der Messung |
|---|---|---|---|---|
| `internal/bench` | 92,1 % | 92,8 % | 85 % | 9ad24a5 (Messcode vor 17) |
| `internal/ceremony` | 89,8 % | 88,9 % | 85 % | Endstand (10b1783) |
| `internal/client` | 3,6 % | **88,3 %** | 85 % | Endstand (1217496) |
| `internal/e2e` | – | – | – | nur Tests (`coverage: [no statements]`) |
| `internal/envelope` | 94,0 % | 94,0 % | 90 % | 9ad24a5 |
| `internal/ingest` | 5,1 % | **90,4 %** | 85 % | Endstand (1217496) |
| `internal/keys` | 93,9 % | 93,9 % | 90 % | 9ad24a5 |
| `internal/loghttp` | 93,9 % | 93,9 % | 85 % | 9ad24a5 |
| `internal/rec` | 99,6 % | 99,6 % | 90 % | 9ad24a5 |
| `internal/shamir` | 100 % | 100 % | 90 % | 9ad24a5 |
| `internal/smtpd` | 91,9 % | 91,9 % | 85 % | 9ad24a5 |
| `internal/store` | 89,5 % | **89,6 %** | 85 % | Endstand (1217496) |
| `internal/terms` | 100 % | 100 % | 85 % | 9ad24a5 |
| `internal/testenv` | 15,1 % | 96,3 % | 85 % | 9ad24a5 |
| `internal/translog` | 93,6 % | 93,6 % | 90 % | 9ad24a5 = Endstand (22 und 23 ändern `translog` nicht) |
| `internal/translog/translogtest` | 100 % | 100 % | 85 % | 9ad24a5 |
| `internal/witness` | 95,2 % | 95,2 % | 85 % | 9ad24a5 |
| `internal/words` | 100 % | 100 % | 85 % | 9ad24a5 |

**Kein Paket liegt unter dem Soll.** Maßgeblich ist der höhere der beiden Werte: Ohne Tags überspringen sich die Tests von `client`, `ingest` und `testenv`, die eine Entwicklungsplattform brauchen (HANDOFF „Testabdeckung“). Am knappsten liegen `client` mit 88,3 % und `ceremony` mit 88,9 % (Soll 85 %). Auf 9ad24a5 lagen `client` bei 88,2 % und `ingest` bei 90,3 %; mit 23 und 23b sind es 88,3 % und 90,4 %. `ceremony` (88,9 % mit Tags) und `store` (89,6 %) sind auf 9ad24a5 und am Endstand gleich. Die Pakete, die 22 und 23 nicht ändern, haben am Endstand denselben Code wie 9ad24a5, außer den Testdateien in `internal/bench` (`git diff --stat 9ad24a5 fba4eb2 -- internal cmd`; ORCHESTRATION, 02:35 UTC: „die übrigen Pakete unverändert seit 9ad24a5“). Der Wert für `internal/bench` gilt für den Messcode von 9ad24a5. 17 und 17c ändern nur Testdateien in `internal/bench` (MEASUREMENTS „Code-Stand“); für diese ist keine Abdeckung gemessen. Die Abdeckung am Endstand gehörte zum Auftrag 20r; HANDOFF steht seit dessen Merge (541a349) endgültig auf dem Endstand fba4eb2.

**Zwei Maschinen über NFSv4: bedingt.**
- Das Skript `scripts/two-host-test.sh` ist im lokalen Modus durchgelaufen (`TestTwoHostScript`, D83, ad755d6).
- Der Zwei-Maschinen-Pfad ist nur über einen ssh-Ersatz und auf Syntax geprüft. In dieser Umgebung gibt es weder NFS noch eine zweite Maschine (ORCHESTRATION Abschnitt 1, AUDIT R36).

**Zusammengefasst:** E ist für zwei Maschinen bedingt. Der Abschluss-Volllauf auf 9ad24a5, der Volllauf `fr-m1` auf dem Endstand mit 22 und 23 (67 von 67 Schritten) und die Abdeckung am Endstand sind belegt. Bedingt bleibt E nur wegen der Zwei-Maschinen-Prüfung über NFSv4 (D83, R36).

### F: HANDOFF, AUDIT, RUNBOOK mit `TestRunbook`

**Gebaut:**
- `docs/RUNBOOK.md` mit `TestRunbook` (`internal/e2e/runbook_test.go`): Zeremonie 3 aus 5, Zeuge, drei Benutzer, Produktionsbinaries (D89, d072685).
  - Die Zeremonie läuft im Test über Testseams, nicht über das Pseudoterminal; die Terminalregeln prüfen die PTY-Tests in `cmd/gomail-ceremony` (D89 (3)).
  - Seit 20p ist das RUNBOOK aus Betreibersicht durchgesehen: Gruppen und Rechte, SSH-Tunnel für einen Zeugen auf einer anderen Maschine (1.7, nicht getestet, R47), 8.8 Sicherung, 8.9 Fork, 8.10.
  - Seit 21d und 21e beschreibt 7.3 Widerruf, Admin-Rotation und Neuausstellung nach D93.
- `docs/AUDIT.md` mit R1 bis R47, Prüfpfaden, 25 Fuzz-Zielen und einer Empfehlung von 31 bis 41 Personentagen (AUDIT 8.2, seit 20q am Stand 9ad24a5; vorher 29 bis 38). Code-Stand 858b2f1 mit den Nachträgen 20n (b674ae3), 21e (9ad24a5) und dem Vermerk zu 20q. Mit 22d (4a6e9c1) kamen der „Nachtrag 22d“ und R48 dazu; AUDIT zählt seitdem R1 bis R48.
- `docs/HANDOFF.md`, Entwurf, seit 20q mit dem „Nachtrag 20o und Auftrag 21 (Code-Stand 9ad24a5)“. Fuzzing (vierter Teil), TODO-Inventar und die Spalte „Code gemessen“ der Abdeckung sind an 9ad24a5 nachgeführt (547603e).

**Endgültig mit Auftrag 20r** (`docs/tasks/20r-handoff-final.md`; Merge 541a349 mit Nacharbeit 94190c6): HANDOFF und AUDIT stehen endgültig auf dem Endstand fba4eb2.
- Auftrag: in HANDOFF Messungen (Kriterium D), Ergebnis des Abschluss-Volllaufs mit Laufzeiten und SKIP-Nachweis, Abdeckung am Endstand, Auftrag 22 in „Bekannte Grenzen“ und der Commit-Zuordnung, Stand je Kriterium A bis F; in AUDIT das Ergebnis des Abschluss-Volllaufs (Kopf, 6.1). Die Zahlen der Prüfungen („wird mit Auftrag 20 eingetragen“) liefert Abschnitt 4 dieses Berichts; 20r trägt sie nach seinem Auftrag nicht ein (Anhang B, Nr. 6).
- Erste Prüfung: alle Zahlen bestätigt, drei Funde mittel:
  - Das Urteil „bedingt“ für A war nicht belegt. A ist jetzt erfüllt, mit strengster Lesart bzw. nicht freigegebenen Befehlen an Q1, Q2, Q6, Q7, Q18 und Q20 (Abschnitt 7a, Nr. 9).
  - R48 nannte einen Test mit Haken, der den Haken nicht nutzt.
  - Der Urteilsspalte fehlte der Vorbehalt.
- Nachprüfung: alle Funde behoben, nur noch niedrige; diese stehen in `docs/tasks/20-notes.md`.
- Urteile in HANDOFF: A erfüllt, B erfüllt (Marken nur im Testdouble), C erfüllt, D erfüllt mit Vorbehalt D94, E bedingt (NFSv4), F erfüllt.

Commit der endgültigen HANDOFF und AUDIT: 541a349 (20r mit Nacharbeit 94190c6). Das Ergebnis von `fr-m1` trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).

**Stand:** F ist erfüllt.

---

## 3. Zusammengeführte Pakete und Aufträge

Commits auf dem Arbeitsbranch nach `git log`. Zu Worktree-Commits siehe die Zuordnungstabelle in HANDOFF (seit 20p). „Runden“ heißt Prüfrunden nach ORCHESTRATION Abschnitt 4 und 6 oder dem D-Eintrag. Die Funde stehen in Abschnitt 4.

| Welle | Auftrag | Inhalt (kurz) | Commit | Entscheidung | Runden |
|---|---|---|---|---|---|
| 1 | 01 (01b) | Kopffeld 8, SIZE 25 MiB, Abdeckung `keys` | 6dc201d | D66, D67 | 2 |
| 1 | 02 (02b, 02c) | `store` nach 1.4 | 38626a9 | D68–D71 | 2 |
| 1 | 03 (03b–03d) | Schnittstellen Log, Zeuge, Zeremonie | a39c687 | D72 | 4 |
| 1 | Integrationsprüfung Welle 1 | – | – | – | 1 |
| 2 | 05 (05c) | `ingest`: Selbstprüfung ohne Schlüssel, Serversperre | 632c319 | D73 | 1 |
| 2 | 06 (06c, 06d) | `client`: Mitglieder, Epochen | adf8431 | D75 | 3 |
| 2 | 07 (07b–07d) | `translog` auf `tlog` | ad67baf | D76, D78 | 3 |
| 2 | 08 (08b) | `gomail-witness` | e1767dc | D74 | Zahl nicht angegeben |
| 3 | 09 | Index, Suche, Flags | dbb667b | D79 | 1 |
| 3 | 10 (10b–10f) | `gomail-ceremony` | ef8e408 | D82 | 4 und Merge-Prüfung 10f |
| 3 | 11 (11b) | Serverseite des Logs, `loghttp` | a1c10cc | D80 | 2 |
| 3 | 12 (12b, 12c) | Messumgebung | d4a8377 | D77 | 3 |
| 3 | 12d | Indexmessungen | e48b35b | – | 1 |
| 4 | 06b (06e–06h) | Generationen, Geräteverlust | a296a8b | D84 | 6 nach ORCHESTRATION und D84 (siehe Anhang B, Nr. 1) |
| 4 | 13 (13b–13d) | `gomailctl`-Befehle | 4748ac7 | D86 | 4 |
| 4 | 13e/13f | `/dev/tty` nur in der steuernden Sitzung | b03135d | D86 Nachtrag | 1 (Merge-Prüfung) |
| 4 | 14 (14b, 14c) | Client am Transparenzlog | c4e9014 | D88 | 2 und Merge-Prüfung 14c |
| 4 | 15 (15c) | Logprüfungen in `ingest` und Server, Rollensperren | 3ff099b | D81 | 2 |
| 4 | 15b (15f, 15g) | Zeremonie am Log | 52ec07a | D85 | 3 |
| 4 | 15d | `SignHead`-Test, `RepairTree` meldet Waisen | 221f331 | D81 Nachtrag | 1 |
| 4 | 15e | Testrennen in `cmd/gomail-server` | bb6772d | – | 1 |
| 4 | 15h/15k | `gomail-server init`, Dev-Pin nur im Dev-Build | c931a31 | D87 | 2 |
| 4 | 15i/15l/15m/15n | Terminalregeln der Zeremonie | d636ffc | D85 Nachtrag | 3 |
| 4 | 16 (16b, 16c) | Zwei-Maschinen-Skript | ad755d6 | D83 | 3 |
| 5 | 18/18b | `docs/AUDIT.md` | bb92cd9 | – | 2 |
| 5 | 18c | AUDIT-Update | a086eb5 | – | 1 |
| 5 | 19/19b | RUNBOOK, `TestRunbook` | d072685 | D89 | 2 |
| 5 | 20a | kleine Nacharbeiten | e799367 | D90 | 1 (Angreiferprüfung zweimal, die erste abgebrochen) |
| 5 | 09b–09g | S13 für Metadaten und Segmente, `internal/terms`, begrenztes Wachstum | 3e06f23 | D91 | 6 |
| 5 | 20c | Einordnung der Hinweise, AUDIT nach D91, HANDOFF-Entwurf | a76fc16 | – | 2 |
| 5 | 20d | Vorschläge in DECISIONS, SPEC-ISSUES, RUNBOOK | b2a15fa | – | 1 |
| 5 | 20f | Zuordnung der Pflichttests, Schematest | aa79032 | – | 1 |
| 5 | 20g | Abdeckung `testenv` | 2c74f2d | – | 1 |
| 5 | 20b | kleine Nacharbeiten nach der Linie 09b | b155e1f | D86 Nachtrag 20b | 1 |
| 5 | 20e | letzte kleine Nacharbeiten | d85da00 | D86, D91 Nachtrag 20e | 1 |
| 5 | 20h | Gerätewechsel-Test, `ErrClosed`, Reste mit Marker | 858b2f1 | D86 Nachtrag 20h | 1 |
| 5 | 20j | RUNBOOK, DECISIONS | 4566256 | D80, D86, D91 Nachträge | 2 |
| 5 | 20k | HANDOFF, AUDIT | 27994c6 | – | 2 |
| 5 | 20m | Erkennung eines Stillstands in den Zeremonie-Tests (nur Testcode) | 90e248b | D85 Nachtrag 20m | 2 |
| 5 | 20i | letzte niedrige Funde | 211a45b | D86, D91 Nachträge | 1 |
| 5 | 20l | Temp-Verzeichnis über Identität, kein steuerndes Terminal | b674ae3 | D86 Nachtrag 20l, D92 | Angreiferprüfung und Nachprüfung der Nacharbeit; eine Spezifikationsprüfung ist nicht dokumentiert `[OHNE BELEG]` |
| 5 | 20n | Dokumente nach 20i und 20l, D92 | 374f499 | D92 | 2 |
| 5 | Vorlage Q19/Q8 | Entscheidungsvorlage | b44ee78 | → D93 (92e43ad) | – |
| 5 | 20o | Funde niedrig der Gesamtprüfung der Client-Verzeichnisse | 9e34841 | D86 Nachtrag 20o | 1 (Spezifikation und Angriff in einer Prüfung) |
| 5 | 20p | Konsistenz der Dokumente, RUNBOOK aus Betreibersicht, R47 | 6e99c30 (mit 3eac478) | – | 2 |
| 5 | 21a | Widerruf: Pin-Feld 7, Regeln und Kaskade in `store` und `translog` | 02ee7b5 | D93 mit Nachträgen (671fc1d, 322b79e) | 2 |
| 5 | 21c | Widerruf in der Zeremonie: `succeed --compromised`, `revoke`, `admin-rotate`, `publish` | 12d48cc | D93 Nachtrag 21e | 2 |
| 5 | 21b | Widerruf in Client, `ingest`, `gomail-server` | 7cde738 | D93 Nachtrag 21e | 2 |
| 5 | 21d/21e | PLAN 2.3, 9.2, 10.1; RUNBOOK 7.3; SPEC-ISSUES, AUDIT, HANDOFF; Kommentare in `translog` | dcd14d9 | D86 Nachtrag 20o, D93 Nachtrag 21e | 2 |
| 5 | 20q | HANDOFF und AUDIT vor dem Abschluss (Anhang B des Entwurfs, Nr. 4 bis 8) | 547603e | – | 1 (Nacharbeit mit vorgegebenem Text, vom Orchestrator am Diff geprüft) |
| 5 | 17, 17b, 17c, 17d | MEASUREMENTS: gestoppt 19:15 UTC (17), gemessen am 04.11. (17b), Nacharbeit (17c, 17d) | aed6ea4 (Worktree 440e188 und 17d) | D94 (fd7b87f) | 3 (17b, Nachprüfung 17c, Nachprüfung 17d); Haltepunkt 3 erreicht, Fund nach D94 niedrig |
| 5 | 22 | Ergänzungen nach 21: `publish` heilt `data/platform/`, Admin-Widerruf, `resolveExisting`, Kommentar in `succession_test.go` | afad8de (Worktree 3cd9072) | D86, D93 Nachträge 22 (4a6e9c1) | 1 (Spezifikation und Angriff) |
| 5 | 23 (23b) | Plattformzertifikat einmal lesen (R48); 23b: Test unabhängig von der Reihenfolge | fba4eb2 (Worktree 9a9d6cb, c6fa0b3) | D93 Nachtrag 23 (4a6e9c1) | 2 (23 nach Code-Lesung, Läufe vom Orchestrator nachgeholt; Nachprüfung 23b) |
| 5 | 22d | Doku zu 22 und 23: RUNBOOK 1.5, 7.3, 8.6; D86/D93-Nachträge; AUDIT R17, R33, R48 | 4a6e9c1 (Worktree 446d27c, Nacharbeit 5d88c4b) | – | 2 |
| 5 | 20r | HANDOFF und AUDIT endgültig; Ergebnis von `fr-m1` folgt mit einem weiteren Commit (Commit siehe ORCHESTRATION, „Stand beim Anhalten“) | 541a349 (Nacharbeit 94190c6) | – | 2 (erste Prüfung, Nachprüfung) |

**Umfang:**
- Seit dem Orchestrierungsplan (5aa3b0f, 26.10.2026) hat der Branch 274 Commits, Stand fd7b87f (`git rev-list --count 5aa3b0f..fd7b87f`). Von den 25 Commits nach 1b7bd05 ändern drei Code oder Tests: aed6ea4 (nur `internal/bench` und `scripts`), afad8de und fba4eb2.
  - Bis 1b7bd05 (249 Commits) beginnen 38 nicht mit `docs`: 37 Code-Commits der Tabelle und `chore: ignore agent worktrees`.
  - Dazu kommen d072685 (`docs, e2e`, Auftrag 19) und dcd14d9 (`docs:`, aber mit Kommentaren in `internal/translog`).
  - Das ergibt 38 Commits mit Code oder Tests, dazu einen mit Code-Kommentaren. Mit aed6ea4, afad8de und fba4eb2 sind es 41 Commits mit Code oder Tests.
- Unter `docs/tasks/` liegen 106 Dateien (bei fd7b87f).
- Produktivcode (Go-Dateien ohne Tests unter `internal/` und `cmd/`, gezählt wie AUDIT 8.2 mit `git grep -c ''`):
  - 42.651 Zeilen bei 374f499;
  - 45.117 Zeilen bei 9ad24a5 (AUDIT 8.2 seit 20q);
  - 45.143 Zeilen bei dcd14d9 bis 6d35472 (Kommentare);
  - 45.237 Zeilen am Endstand fba4eb2. 22 und 23 bringen also netto 94 Zeilen.
  - AUDIT 8.2 bewertet den Zuwachs aus 20o und Auftrag 21 seit 20q (Schätzung 31 bis 41 Personentage). Die 94 Zeilen aus 22 und 23 bewertet es nicht.

---

## 4. Unabhängige Prüfungen: Statistik

**Regel:** Pakete, die Schlüssel, Signaturen, Formate, Epochen, das Log oder Prüfregeln im Client betreffen, gelten als sicherheitskritisch. Sie bekommen zwei Prüfer (Spezifikation und Angreifer, stärkeres Modell). Alle anderen bekommen einen Prüfer mit dem Standardmodell (ORCHESTRATION Abschnitt 2). Zu den Abweichungen beim Modell siehe Abschnitt 6.

**Zählweise:**
- Eine Runde ist eine Prüfung nach einer Umsetzung oder Nacharbeit, bei sicherheitskritischen Paketen meist mit beiden Rollen.
- Die Funde stehen mit ihrer Schwere aus dem Verlaufseintrag in ORCHESTRATION. Wo dieser keine Zahl nennt, stammen sie aus dem D-Eintrag, aus QUESTIONS oder aus `docs/tasks/20-notes.md`.
- „–“ heißt: Die Quelle nennt keine Zahl.

| Paket | Funde je Runde (hoch / mittel / niedrig) | Quelle |
|---|---|---|
| 01 | R1: Angreifer 0; Spezifikation 0 / 1 / 3. R2: 0 | ORCH 4 |
| 02 | R1: Spezifikation 1 / 5 / – (8 Funde), Angreifer 3 latente (dieselben Lücken). R2: nur niedrige Testlücken | ORCH 4 |
| 03 | R1: Spezifikation – / 4 / – (8 Funde); Angreifer 2 / 1 / 2. Später: 3 mittel und 7 niedrig. R4: 6 niedrig (Q10) | ORCH 4, D72 |
| Integration Welle 1 | 0 / 3 / 8 | ORCH 4 |
| 05 | Angreifer 0; Spezifikation 0 / 1 / 2 | ORCH 4 |
| 06 | erste Runde ohne Zahlen. Nach 06d: Spezifikation 0 / 2 / 5, Angreifer 0 / 0 / 2 | ORCH 4, D75 |
| 07 | Spezifikation 4 + 2 + 3, Angreifer 6 + 1 + 1 Funde über drei Runden, keiner hoch. 07b: 3 mittel; 07c: 2 mittel. Abschluss: 5 niedrig | ORCH 4, D78 |
| 08 | „je ohne offene Funde nach 08b“; keine Zahlen | ORCH 4 |
| 09 | Spezifikation 0 / 2 / 7; Angreifer 0 / 0 / 2 | ORCH 4, D79 |
| 10 | 10b–10d: 2 hoch behoben (Echo und Löschen, Terminalpflicht). Nach 10d: Angreifer 0 / 2 / 1, Spezifikation 0 / 1 / 2. Nach 10e: 1 „hoch nach der Prüfer-Skala“ (keine Sicherheitsfolge) / 1 / 1. Merge 10f: nichts über niedrig | Q14, Q17, ORCH 4 |
| 11 | R1: 0 / 2 / 5 (Spezifikation), Angreifer je 2 niedrig. R2: nichts über niedrig | ORCH 4, D80 |
| 12 | R1: 0 / 2 / 2; R2: 0 / 1 / 4; R3: 0 / 0 / 4 | ORCH 4 |
| 12d | 0 / 0 / 2 | ORCH 4 |
| 06b | 06b: 2 hoch (Spezifikation); nach 06e: 1 mittel (Angreifer); nach 06g: 1 hoch, 1 mittel, mehrere niedrig; nach 06h: 0 / 3 / – → Pflicht in 14 | Q15, Q16, ORCH 4, D84 |
| 13 | 13: 2 / 1 / –; 13b: 0 / 1 / –; 13c: 0 / 1 / –; 13d: 0 / 1 / – (ohne Sicherheitsfolge) → 13e | ORCH 4, D86 |
| 13e/13f | 0 / 0 / 2 | ORCH 4 |
| 14 | 14: 0 / 5 / 8; 14b: nichts über niedrig; Merge 14c: nichts verloren | ORCH 4, D88 |
| 15 | R1: 0 / 3 / 5; R2: 0 / 0 / 3 | ORCH 4, D81 |
| 15b | 15b: Angreifer 0; Spezifikation 1 hoch = Spezifikationslücke (Q19). 15f-Nachprüfung: 2 hoch. Abschluss: 0 / 0 / 3 | ORCH 4 |
| 15d | 0 / 0 / 4 | ORCH 4 |
| 15e | 0 | ORCH 4 |
| 15h/15k | 15h: 1 / 1 / –; 15k: 0 | ORCH 4 |
| 15i–15n | 15l: 2 / – / –; 15m: Angreifer 3 / – / –; 15n: 0 / 0 / 3 | ORCH 4 |
| 16 | R1: 3 / 2 / 4; R2: 1 / – / 7; R3: 0 / 0 / 3 | ORCH 4, D83 |
| 18/18b | 18: 0 / 3 / –; 18b: 0 / 0 / 3 | ORCH 4 |
| 18c | 0 / 0 / 4 | ORCH 5 |
| 19/19b | 19: 0 / 1 / 5; 19b: nichts über niedrig | ORCH 4, D89 |
| Linie 09b | 09b: Spezifikation nichts über niedrig, Angreifer 1 / 1 / 2. 09c: Angreifer 1 / 2 / – (ein mittel auch von der Spezifikation). 09d: Angreifer 0 / 1 / 3, Spezifikation 1 mittel. 09e: Angreifer 0 / 1 / 3, Spezifikation nichts über niedrig. 09f: Angreifer 0 / 2 / 1, Spezifikation nichts über niedrig. 09g: beide nichts über niedrig | ORCH 4, Q22, `docs/tasks/20-notes.md` |
| 20a | Spezifikation nichts über niedrig. Angreifer: erste Prüfung abgebrochen, zweite nichts über niedrig | ORCH 4 |
| 20c | R1: 0 / 2 / 6; R2: nichts über niedrig (1 neue niedrige) | ORCH 5 |
| 20d | 0 / 0 / 2 | ORCH 5 |
| 20b, 20e | je Spezifikation und Angreifer nichts über niedrig | ORCH 5, 6 |
| 20f, 20g | je nichts über niedrig | ORCH 6 |
| 20h | Spezifikation und Angreifer nichts über niedrig | ORCH 6, 20-notes |
| 20j | R1: 0 / 1 / 6; R2: nichts über niedrig | ORCH 6 |
| 20k | R1: ein Fund mittel, vom Prüfer zurückgenommen; R2: nichts über niedrig (1 Nit) | ORCH 6 |
| 20i | nichts über niedrig im Diff. Vorbestehend: 1 mittel, falls ein anderer Benutzer schreiben kann → 20l | ORCH 6, 20-notes |
| 20l | Angreifer: 1 niedrig im Diff (Nacharbeit); vorbestehend 1 mittel unter Bedingung → D92. Nachprüfung der Nacharbeit: Zahl nicht angegeben | 20-notes, D92 |
| 20m | R1: 1 / 1 / –; R2 (mit Mutanten): nichts über niedrig, 4 Restgrenzen niedrig | ORCH 6, 20-notes |
| 20n | R1: Zahl nicht angegeben → Nacharbeit; R2: nichts über niedrig (1 Nit zu R46) | ORCH 6 |
| 20o | eine Prüfung (Spezifikation und Angriff in einem, stärkeres Modell): nichts über niedrig; 1 niedrig (`resolveExisting` an hängendem Link → Auftrag 22, Punkt 3) | ORCH 6, 20-notes |
| 20p | R1: 0 / 1 / – (Pin-Verteilung beim Zeugenwechsel); R2: nichts über niedrig; Hinweis `mv -T` vom Orchestrator ergänzt | ORCH 6 |
| 21a | R1: Spezifikation 0 / 1 / – (Kopf einer ungültig gewordenen Generation sperrt `SignHead` und Reparatur); Angreifer 0 / 1 / 4 (F1 mittel: vor N zertifizierte Generationen bleiben handlungsfähig → Kaskade; F2–F5 niedrig). R2: Spezifikation (17/17 Mutanten getötet) und Angreifer nichts über niedrig; 2 niedrig offen (`doc.go` auf T + 1 ms, Warnkommentar), mit 21e erledigt | ORCH 6, 20-notes, D93 Nachtrag |
| 21c | R1: Spezifikation 0 / 0 / 3 im eigenen Code, dazu 1 mittel außerhalb (zwei e2e-Tests mit altem Text, angepasst in 21b); Angreifer 0 / 1 / 2 (Zertifikat des Diebs vor der Grenze blockiert die Neuausstellung). R2: beide nichts über niedrig (10/10 Mutanten getötet); je 1 niedrig → Auftrag 22, Punkte 1 und 2 | ORCH 6, 20-notes |
| 21b | R1: Spezifikation 0 / 0 / 3 (L1–L3); Angreifer 0 / 1 / 1 (Start mit kaskadenhaft widerrufener Ingest-Generation; „Waschen“ über Flag-Änderung). R2: beide nichts über niedrig; Restlücke von F2 braucht eine Formatänderung (nach M1, R18 (e)) | ORCH 6, 20-notes, D93 Nachtrag 21e |
| 21d/21e | R1: 0 / 1 / – (PLAN 2.3 Regel 6 widersprach der Kaskade); R2: nichts über niedrig | ORCH 6 |
| 20q | 0 / 1 / – (Commit-Bereich in AUDIT 8.2) → Nacharbeit mit vorgegebenem Text, vom Orchestrator am Diff geprüft | ORCH 6 |
| 17b–17d | 17b: 0 / 3 / 7 (alle Zahlen gegen Rohdaten bestätigt). Nachprüfung 17c: 0 / 1 / 2 (F1; F2, F3). Nachprüfung 17d: 0 / 1 / 2 (M1, nach D94 als niedrig eingestuft; N1, N2), F3 offen niedrig | ORCH 6 (02:05, 02:20, 02:35 UTC), 20-notes „Aus den Prüfungen von 17“, D94 |
| 22 | Angreifer: 0 / 0 / 4 im Diff (N1–N4), dazu 1 mittel außerhalb des Diffs (R48, Einstufung des Orchestrators) → Auftrag 23. Spezifikation: 0 / 0 / 4 (19 von 21 Mutationen getötet) | ORCH 6 (00:50, 00:55 UTC), 20-notes |
| 23 | Spezifikation und Angreifer nach Code-Lesung: nichts über niedrig, 2 niedrig (Testhaken greift erst nach `ReadPlatformCertRaw`; `address add` prüft `cert.IdentityGen` ohne Logabgleich, folgenlos). Läufe vom Orchestrator nachgeholt: Angriffstests scheitern auf der Mutante; Mutationen M1–M9 getötet außer M4 (Testlücke niedrig, bekannt) | ORCH 6 (01:10 UTC), 20-notes „Läufe der Prüfungen von 23“ |
| 23b | Nachprüfung: nichts über niedrig, 1 niedrig (jeder Lauf deckt zufällig nur eine Prüfreihenfolge ab); je 5/5 Mutationen getötet unter amd64 und 386 | 20-notes |
| 22d | R1: 0 / 1 / 5 (RUNBOOK 8.6 ohne den Fall eines vor `<N>` geloggten Zertifikats des Diebs); R2: alles behoben, 2 neue niedrig (L1, L2) | ORCH 6 (01:33 UTC), 20-notes |
| 20r | R1: alle Zahlen bestätigt, 0 / 3 / – (Urteil A „bedingt“ nicht belegt; R48 nannte einen Test mit Haken, der den Haken nicht nutzt; Vorbehalt fehlte in der Urteilsspalte); R2: alles behoben, nur noch niedrige | 20-notes; Merge 541a349 |

**Prüfungen ohne Umsetzung** (nur lesend, Ergebnisse im Scratchpad des Orchestrators unter `final/`; im Repository nur über die Fund-Kennungen in den Aufträgen 20o und 20p belegt):

| Prüfung | Funde (hoch / mittel / niedrig) | weiter in |
|---|---|---|
| Gesamtprüfung der Client-Verzeichnisse (20b bis 20l) | 0 / 0 / 7 (L1–L7) | 20o (L2–L5, L7), 20p (L1, L6) |
| Konsistenzprüfung der Dokumente | 1 / 5 / 12 (H1, M1–M5, L1–L12; Schwere der Dokumentprüfung, keine Sicherheitsfunde) | 20p |
| Durchgang durch das RUNBOOK aus Betreibersicht | 3 / 8 / 16 (H1–H3, M1–M8, L1–L16; ebenso) | 20p, 21d (M5, M8) |

**Kennzahlen.** Gezählt aus ORCHESTRATION Abschnitt 4 bis 6 (Verlauf bis 04.11., 02:35 UTC), ergänzt um den D-Eintrag und `docs/tasks/20-notes.md`, wo der Verlauf keine Zahl nennt. Zählweise:
- Eine **Prüfrunde** ist eine Prüfung nach einer Umsetzung oder Nacharbeit. Bei sicherheitskritischen Paketen zählen Spezifikations- und Angreiferprüfung derselben Fassung zusammen als eine Runde.
- Eine **Nacharbeit** ist eine Überarbeitung nach Funden, auf die eine erneute Prüfung oder eine Prüfung des Orchestrators am Diff folgt. Aufträge, die einen Fund aus der Prüfung eines anderen Auftrags beheben (13e, 20l, 23), zählen als eigene Aufträge, nicht als Nacharbeit.
- Summiert ist die Spalte „Runden“ der Tabelle in Abschnitt 3.

Ergebnis:
- **Prüfrunden: 111.** Darin sind die Integrationsprüfung der Welle 1 und die Merge-Prüfungen 10f, 13e/13f und 14c enthalten. Dazu kommen die drei Prüfungen ohne Umsetzung.
  - Bis 21e waren es 100, seit dem Entwurf vom 03.11., 23:40 UTC, kamen 11 dazu: 20q 1, 17b bis 17d 3, 22 1, 23 1, 23b 1, 22d 2, 20r 2.
  - Unsicher sind 08 (als 1 gezählt), 06b (6 nach ORCHESTRATION und D84, 4 nach den Auftragsdateien, Anhang B Nr. 1) und 20l (als 2 gezählt).
- **Nacharbeiten: etwa 56.** Näherung: 111 Runden minus 54 Zeilen der Tabelle in Abschnitt 3 (ohne die Vorlage Q19/Q8), also je Auftrag die erste Prüfung, minus die zwei Merge-Prüfungen 10f und 14c, die keiner Nacharbeit folgten. Dazu kommt die Nacharbeit von 20q, die der Orchestrator am Diff prüfte. Genau ist die Zahl nicht, weil 08, 06b und 20l unsicher sind.
- **Aufträge 20h bis 23b:** 32 Runden und 15 Nacharbeiten. Die Zählung der Runden:
  - 1 Runde je für 20h, 20i, 20o, 20q, 22, 23 und 23b;
  - 2 Runden je für 20j, 20k, 20l, 20m, 20n, 20p, 21a, 21b, 21c, 21d/21e und 22d;
  - 3 Runden für 17 (17b, Nachprüfung 17c, Nachprüfung 17d).

  Die 15 Nacharbeiten: 20j, 20k, 20l, 20m, 20n, 20p, 21a, 21b, 21c, 21d/21e, 20q, 17c, 17d, 23b und 22d.

  Funde in diesen 32 Runden:
  - hoch: 1 (20m);
  - mittel: 18, nämlich
    - bis 21e 10: 20i 1 (unter Bedingung, vorbestehend), 20j 1, 20l 1 (unter Bedingung, vorbestehend → D92), 20m 1, 20p 1, 21a 2, 21b 1, 21c 1 und 21d/21e 1;
    - seit dem Entwurf 8: 20q 1, 17b 3, 17c 1 (F1), 17d 1 (M1, nach D94 als niedrig eingestuft), 22 1 (R48, außerhalb des Diffs → 23) und 22d 1;
  - dazu 1 mittel zurückgenommen (20k) und 1 mittel außerhalb des geprüften Codes (21c, e2e-Texte);
  - niedrig: keine verlässliche Summe, weil 20h, 20k, 20l (Nachprüfung), 20n, 20p, 20q und 21d/21e keine Zahl nennen. Seit dem Entwurf sind es mindestens 28: 17 11, 22 8 (N1 der Spezifikation entspricht N4 des Angriffs), 23 2, 23b 1, 22d 7.
  - Nach der letzten Runde blieb bei keinem dieser Aufträge ein Fund über niedrig offen. Die beiden mittleren Funde unter Bedingung sind mit 20l geschlossen bzw. als Betriebsvoraussetzung D92 angenommen. Der letzte mittlere Fund von 17 ist nach D94 niedrig eingestuft (Abschnitt 7a).
- **Auftrag 20r** (nach diesem Bereich): 2 Runden und 1 Nacharbeit (94190c6). Erste Prüfung 0 / 3 / –, alle Zahlen bestätigt; Nachprüfung: alles behoben, nur noch niedrige (`docs/tasks/20-notes.md`).
- **Funde hoch in Prüfungen von Code:** mindestens 27 dokumentiert, seit dem ersten Entwurf unverändert (keine hohen in 20o bis 23b):
  - 02: 1; 03: 2; 06b: 3; 10: 3 (davon 1 ohne Sicherheitsfolge); 13: 2; 15b/15f: 3 (davon 1 Spezifikationslücke); 15h: 1; 15l: 2; 15m: 3; 16: 4; 09b: 1; 09c: 1; 20m: 1.
  - Eine vollständige Summe ist nicht möglich, weil mehrere Einträge keine Zahlen nennen (06c bis 06g teilweise, 08, 10b und 10c).
  - Die vier „hohen“ Funde der Dokumentprüfungen sind hier nicht mitgezählt.
- **Funde mittel und niedrig:** keine verlässliche Gesamtsumme, weil viele Einträge nur „Funde über niedrig“ oder Gesamtzahlen nennen. Niedrige Funde, die nach dem Merge offen blieben, sind bis 20e in `docs/tasks/20-triage.md` eingeordnet:

| Klasse | Punkte |
|---|---|
| erledigt | 126 |
| in 20b | 18 |
| in 20 | 30 |
| Produktivcode, nicht in 20b | 2 (P-1, P-2) |
| bekannte Grenze | 35 |
| **Summe** | **211** |

  - P-2 ist mit 20e erledigt (D91 Nachtrag 20e).
  - P-1 ist als bekannte Grenze mit Abhilfe nach M1 entschieden (D81 Nachtrag 20j).
  - Niedrige Funde aus 20h bis 23b sind nicht in der Triage. Sie stehen in `docs/tasks/20-notes.md`. Ein Teil ist in 20o, 20p, 21e und Auftrag 22 übernommen; der Rest steht in der Liste nach M1 (Abschnitt 9).
- **Haltepunkt 3** (nach drei Nacharbeitsrunden noch Funde) wurde ausgelöst bei:
  - 10: Q14, Q17
  - 06b: Q16
  - 13: Q21
  - Linie 09b: Q22
  - 17 (MEASUREMENTS): nach der Nachprüfung von 17d, der dritten Prüfrunde, noch ein Fund mittel. Statt einer Frage an den Auftraggeber oder einer vierten Runde hat der Orchestrator ihn nach D94 als niedrig eingestuft (Abschnitt 7a).

  In Auftrag 21 und in 22, 23 wurde er nicht erreicht: Jedes Teilpaket brauchte höchstens eine Nacharbeitsrunde.
- **Haltepunkt 2** (Sicherheitsfund, nur durch Spezifikationsänderung behebbar): Q19 und Q8. Beide sind am 03.11. durch den Auftraggeber entschieden (D93, Option A) und mit Auftrag 21 gebaut.
- Bei mindestens zwei Prüfungen brach der Bericht ab (ORCHESTRATION Abschnitt 4):
  - 03 Angreifer: vom Modellschutz abgebrochen. Der Orchestrator hat die Funde aus den Testdateien des Prüfers rekonstruiert und selbst ausgeführt.
  - 20a Angreifer: abgebrochen und wiederholt.

---

## 5. Tests, Laufzeiten, Flakes (Kurzfassung)

- **Build-Tags:** `gomail_dev` (Entwicklungszeremonie, Dev-Pins), `gomail_test` (Testschalter) und `ceremony_notty`. Kein Lauf allein deckt alles; welcher Lauf was trägt, steht in AUDIT 6.1. Das Produktionsbinary enthält keinen Testschalter (`TestNoTestSwitchInProduction`, AUDIT R35).
- **Laufzeiten** (HANDOFF „Laufzeiten“, Stand vor Auftrag 21, und Abschluss-Volllauf auf 9ad24a5 unter fremder Last, `orch/fr-final/`):
  - `internal/client` mit `-race` und Tags: ohne Last 25 bis 35 Minuten, in den früheren Volläufen 1942 bis 2449 s, unter fremder Last bis 3401 s. Im Abschluss-Volllauf 2178 s, unter 386 1755 s. Deshalb `-timeout 60m`.
  - `cmd/gomail-ceremony` mit `-race`: bisher etwa 400 bis 435 s, im Abschluss-Volllauf 432 und 433 s, unter 386 295 s. Mit `-v` auf 10b1783: 435, 445 und 305 s (`orch/fr-m1-v/`).
  - `internal/e2e` mit `-race`: bisher etwa 109 bis 135 s, im Abschluss-Volllauf 107 s (ohne Tags) und 125 s (mit Tags).
  - `TestRunbook`: etwa 35 s (HANDOFF; im Volllauf nicht einzeln ausgewiesen).
  - Volllauf gesamt: 23:12 bis 00:58 UTC, etwa 1 Stunde 46 Minuten für 67 Schritte, neben Auftrag 22 und der Abdeckung (beide `nice -n 19`). Der Volllauf `fr-m1` auf dem Endstand: 01:32:49 bis 03:40:59 UTC für 67 Schritte, unter fremder Last und mit drei Container-Neustarts (Abschnitt 2, E); darin `internal/client` mit race und Tags 2036 s, unter 386 1260 s, `cmd/gomail-ceremony` 438, 455 und 296 s, `internal/e2e` 99 und 109 s (`orch/fr-m1-steps.txt`).
- **Flakes:**
  - Die zwei Fehlschläge an der 4,5-s-Grenze der Zeremonie-Tests sind als Stillstand der Maschine eingeordnet. Analyse: 4 normale und rund 60 verfolgte Läufe, kein Fehler im Programm.
  - Seit 20m erkennen die Tests einen Stillstand, wiederholen einmal und überspringen sonst mit Messwerten; `stuckLimit` bleibt 4,5 s.
  - Restgrenzen der Erkennung (niedrig) stehen in `docs/tasks/20-notes.md`, „Aus der Prüfung von 20m“.
  - Im Abschluss-Volllauf und im Volllauf `fr-m1` scheiterte kein Schritt, auch nicht an der 4,5-s-Grenze. In den drei `-v`-Läufen von `cmd/gomail-ceremony` wurde kein echter Teiltest übersprungen; die einzigen SKIPs sind der Hilfsprozess `TestStallChild` und der Selbsttest `TestStallDetect/retry_stalled_twice/inner` (Abschnitt 2, E).
  - Neu: `TestPlatformIngestCertSwapped/forged_then_logged` (Auftrag 23) scheiterte unter 386 und mit breitem `-run`. Die Ursache war die Reihenfolge zufälliger Mail-IDs, nicht der Code; mit 23b prüft der Test unabhängig von der Reihenfolge (ORCHESTRATION, 01:42 und 02:05 UTC).
- **TODO-Inventar** (eigene Zählung am Endstand fba4eb2, `git grep -ohE 'TODO\([^)]*\)' fba4eb2 -- 'cmd/*.go' 'internal/*.go'`, wie HANDOFF seit 20q):
  - `TODO(ask)` 20 (HANDOFF bei 858b2f1: 25); `TODO(phase3-translog)` 11 (nur `translogtest`)
  - `TODO(Q1)`, `TODO(Q15)` je 8; `TODO(Q20)` 7; `TODO(Q12)` 5
  - `TODO(Q9)`, `TODO(Q6)` je 3; `TODO(Q13)`, `TODO(Q18)` je 2
  - `TODO(Q3)`, `TODO(Q4)`, `TODO(Q7)` je 1
  - `TODO(Q19)` 0: Den letzten, veralteten Kommentar in `internal/e2e/succession_test.go` hat Auftrag 22 (Punkt 4) angeglichen. HANDOFF nannte am Stand 9ad24a5 noch 1; mit 20r (541a349) steht HANDOFF endgültig auf dem Endstand fba4eb2.
  - Die Erwähnung `TODO(phase3-...)` in `internal/translog/doc.go` ist wie in HANDOFF nicht gezählt.
  - In `scripts/two-host-test.sh` zusätzlich `TODO(task-15b)`.

---

## 6. Abweichungen von den Regeln

Jede Abweichung steht hier mit der Stelle, an der sie begründet ist. „Regel 6“ ist nach QUESTIONS Q17 die Regel „Zusammenführung nur ohne offene Funde“ des Orchestrierungsauftrags.

1. **Zusammenführung mit offenen Funden (Regel 6),** jeweils auf Entscheidung des Orchestrators mit dem Mandat „entscheide du“ des Auftraggebers:
   - **10 Zeremonie:**
     - Offen beim Merge: zwei Abweichungen ohne Sicherheitsfolge (Signal nach `signal.Stop`, XOFF bei getrennten Terminals).
     - Sie wurden Pflichtpunkte 0a–0c von 15b und mit 52ec07a behoben.
     - Begründet in D82 und Q17.
   - **13 `gomailctl`:**
     - Offen beim Merge: ein Fund mittel ohne Sicherheitsfolge und ein zeitabhängiger Test.
     - Pflicht in 13e, mit b03135d behoben.
     - Begründet in D86 und Q21.
   - **06b Generationen:**
     - Nach 06h noch drei Funde mittel; sie wurden Pflichtpunkte von 14.
     - Begründet in D84 („Zusammengeführt auf Entscheidung des Orchestrators … mit drei mittleren Funden“) und Q16. D84 nennt das nicht ausdrücklich „Abweichung von Regel 6“ (Anhang B, Nr. 3).
   - **03 Entwurf:**
     - Zusammengeführt mit sechs niedrigen Funden; sie wurden Pflicht in 07 und 11.
     - Begründet in Q10 und D72. Nur Funde niedrig.
   - In 20o bis 21e wurde kein Auftrag mit einem offenen Fund über niedrig zusammengeführt (ORCHESTRATION Abschnitt 6).
2. **Zusätzliche Nacharbeitsrunden nach Haltepunkt 3:**
   - 10e: vierte Runde auf Antwort des Auftraggebers (Q14).
   - 06h: Q16, Mandat „entscheide du“.
   - 09f: vierte Runde der Linie 09b, Variante (b) des Auftraggebers.
   - 09g: fünfte Runde, Vereinfachung (A) unter dem Mandat „Deine Entscheidungen“.
   - Die Linie 09b ist in D91 ausdrücklich als „Abweichung von Regel 6“ begründet, ebenso in ORCHESTRATION Abschnitt 5 und in Q22.
   - Für 06b liegen nach den Auftragsdateien schon vor Q16 fünf Runden, also mehr als drei vor dem Haltepunkt 3. Die Zählung ist widersprüchlich (Anhang B, Nr. 1).
3. **Gemeinsamer Volllauf für 20i und 20l:**
   - Statt „Volllauf je Merge“ (ORCHESTRATION Abschnitt 2) deckt ein Volllauf auf 1d49e6d (20l auf 20i, 67 Schritte grün) beide ab. Grund: einen Durchlauf von über einer Stunde sparen.
   - Begründet in ORCHESTRATION Abschnitt 6 und im Commit-Text von 211a45b.
4. **Weitere Merges ohne eigenen Volllauf:**
   - 20m wurde mit den Läufen des Implementierers für das Paket zusammengeführt; „der Abschluss-Volllauf deckt es ab“ (ORCHESTRATION Abschnitt 6).
   - 20o: ausdrücklich als Abweichung vermerkt („kein eigener Volllauf, um Zeit zu sparen“). Der ganze `internal/client`-Lauf folgt im Abschluss-Volllauf (ORCHESTRATION Abschnitt 6).
   - 21a, 21b und 21c: zusammengeführt mit den Läufen der Implementierer und beim Merge von 21b/21c mit gofmt, vet und Build. „Der Abschluss-Volllauf folgt“ (ORCHESTRATION Abschnitt 6). ORCHESTRATION nennt das hier nicht ausdrücklich eine Abweichung.
   - Der Abschluss-Volllauf auf 9ad24a5 deckt 20m, 20o und 21a bis 21c ab; er ist grün (ORCHESTRATION, 00:58 UTC).
   - 15h/15k: Volllauf gemeinsam mit 15i (ORCHESTRATION Abschnitt 4).
   - 19/19b: nur e2e und `TestRunbook`; die übrigen Pakete waren gegenüber dem Volllauf von 13e unverändert (ORCHESTRATION Abschnitt 4).
   - Für 12d, 15d, 15e, 20f und 20g nennt ORCHESTRATION keinen Volllauf. `[OHNE BELEG: ob nach diesen Merges ein Volllauf lief]`
5. **Höhere Grenze für parallele Agenten auf Wunsch des Auftraggebers:**
   - Am 03.11., 14:45 UTC, wünschte der Auftraggeber mehr parallele Subagenten. Der Orchestrator schöpfte die Grenze aus dem Auftrag aus (6 Subagenten, 4 Umsetzer).
   - Um 18:50 UTC hob der Auftraggeber die Grenze auf („MEHR PARALLELE AGENTS“). Während der ersten Messung (17) liefen 7 Subagenten, nur ohne Tests und Builds und nur mit Schreibzugriff auf das Scratchpad.
   - Nach dem Stopp der Messung um 19:15 UTC liefen Umsetzer und Prüfer parallel: 21a, 21d, 20o, 20p, danach 21b, 21c, 21e mit ihren Prüfungen.
   - Quelle: ORCHESTRATION Abschnitt 6. `[OHNE BELEG: Höchstzahl gleichzeitiger Agenten nach 19:15 UTC]`
6. **Modell der Prüfer:**
   - Nachdem das Kontingent des stärkeren Modells erreicht war, liefen auf Anweisung des Auftraggebers auch die Prüfungen sicherheitskritischer Pakete mit dem Standardmodell. Das wich von Abschnitt 3 der Orchestrierungsvorgabe ab.
   - Ab dem 03.11. erlaubte der Auftraggeber wieder das stärkere Modell (ORCHESTRATION Abschnitte 4 und 5).
   - Betroffen sind nach den Einträgen unter anderem 14b/14c, 15l bis 15n und 16. `[OHNE BELEG: vollständige Liste der mit dem Standardmodell geprüften sicherheitskritischen Runden]`
   - Am 03.11., 22:30 UTC, wies der Auftraggeber erneut an: Erreicht das stärkere Modell sein Kontingent, laufen die Prüfungen mit dem Standardmodell weiter (ORCHESTRATION Abschnitt 6). `[OHNE BELEG: ob danach eine Prüfung mit dem Standardmodell lief; die Einträge zu 21b, 21c und 21d/21e nennen das Modell nicht]`
7. **Reihenfolge der Wellen:**
   - 05 und 06 starteten vor dem Merge von 03; die Integrationsprüfung der Welle 1 lief nach 03 (ORCHESTRATION Abschnitt 2).
   - 09 wurde vor 06b zusammengeführt, damit 12d starten konnte (ORCHESTRATION Abschnitt 4).
   - 09b wurde beim Planen der Welle 4 übersehen und erst nach 18 gestartet (ORCHESTRATION Abschnitt 4).
   - Merge-Reihenfolge in Welle 5: 20h, 20j, 20i, 20k (ORCHESTRATION Abschnitt 6); später 20p, 20o, 21a, dann 21c und 21b gemeinsam, dann 21d/21e, 20q; am 04.11. um 02:35 UTC 17, 22, 23 mit 23b und 22d.
   - 21c wurde nur zusammen mit 21b zusammengeführt, weil zwei e2e-Tests den alten Text erwarteten.
8. **Auftrag 20 aufgeteilt und erweitert:**
   - Verlangt war ein einzelner Commit `acceptance: …` (`docs/tasks/20-acceptance.md`). Ausgeführt wurde die Abnahme als 20a bis 20r mit eigenen Prüfungen. Dazu kam Auftrag 21 nach der Entscheidung zu Q19/Q8 (ORCHESTRATION Abschnitte 5 und 6).
   - Die Fuzz-Protokolle liegen nicht unter `docs/acceptance/<datum>/`, wie Auftrag 20 (3) verlangt, sondern im Scratchpad des Orchestrators (`orch/fz/` bis `orch/fz4/`). Das Verzeichnis `docs/acceptance/` gibt es bei fd7b87f nicht.
   - Fuzzing lief in zwei Bahnen gleichzeitig (HANDOFF; 20-notes, vierter Teil). Auftrag 20 (3) verlangt „nacheinander“.
   - Auch die Protokolle des Abschluss-Volllaufs, der `-v`-Läufe und der Abdeckung liegen nur im Scratchpad (`orch/fr-final/`, `orch/fr-m1/`, `orch/fr-m1-v/`, `orch/cov-final/`, `orch/cov-m1/`), nicht im Repository. Die Rohdaten der Messungen liegen dagegen im Repository (`docs/measurements/`).
9. **Entscheidungen unter Mandat und durch den Auftraggeber:**
   - Q16, Q17, Q21 und Q22 hat der Orchestrator nach „entscheide du“ bzw. „Deine Entscheidungen“ entschieden (QUESTIONS).
   - **Q19 und Q8** hat der Auftraggeber am 03.11. entschieden: „A bauen“ (D93). D93 vermerkt dazu: „die Teilfragen 2–4 der Vorlage nach ihrer Empfehlung“.
   - Die Nachträge zu D93 sind als „Entscheidung des Orchestrators im Rahmen von Option A“ gekennzeichnet:
     - Kaskade: Der Widerruf einer Identitätsgeneration wirkt auf die Admin- und Ingest-Generationen, die sie zertifiziert hat.
     - Ein Kopf einer ungültig gewordenen Generation darf Betrieb und Reparatur nicht dauerhaft sperren; `log repair` verschiebt ihn.
     - `revoked_at_time` ist die Kopfzeit plus 1 ms.

     Eine eigene Bestätigung des Auftraggebers zu diesen Nachträgen ist im Repository nicht dokumentiert `[OHNE BELEG]`. Sie ändern Prüfregeln, bleiben aber im Rahmen von Pin-Feld 7 ohne neues Format.
   - D92 nimmt einen Fund mittel unter Bedingung als Betriebsvoraussetzung an, statt ihn vor M1 zu beheben. Das ist in D92, „Einordnung“, begründet, wie die Regeln der Orchestrierung es für einen Fund über niedrig verlangen, der vor M1 nicht behoben wird.
   - D91 nimmt das Wachstum ohne Schlüssel bei Schreibzugriff als bekannte Grenze an.
   - **D94** stuft den mittleren Fund der Nachprüfung von 17d als niedrig ein, nachdem die dritte Prüfrunde erreicht war, statt eine Frage an den Auftraggeber zu stellen oder eine vierte Runde zu beauftragen. Das ist eine Entscheidung des Orchestrators mit Vorbehalt des Auftraggebers (D94; Abschnitt 7a).
   - R48 (Ingest-Zertifikat doppelt gelesen) meldete die Angreiferprüfung von 22 nur als Nebenbeobachtung außerhalb ihres Diffs. Als mittel eingestuft hat ihn der Orchestrator, und er hat ihn vor M1 mit Auftrag 23 behoben (ORCHESTRATION, 00:50 UTC).
10. **Unterbrechungen und Störungen:**
    - Neustarts des Containers: während Welle 2 (sechs Agenten verloren), am 27.10. um etwa 23:30 UTC, am 28.10. um etwa 23:00 UTC, vor dem Abschluss von 09g, am 03.11. um 06:00 UTC (Volllauf auf 20b unterbrochen) und am 04.11. um 01:42 UTC (Volllauf `fr-m1` und Prüfläufe von 23 fortsetzbar weitergeführt, der MEASUREMENTS-Agent wieder aufgenommen) sowie gegen 03:26 und 03:40 UTC (Volllauf `fr-m1` jeweils über die `.ok`-Marken fortgesetzt; ein abgebrochener Schritt lief ganz neu). Die Zwischenstände wurden als WIP-Commits gesichert (ORCHESTRATION Abschnitte 4 bis 6).
    - Anhalten auf Anweisung des Auftraggebers am 28.10. um 06:00 MEZ und am 03.11. um 07:00 MEZ. Am 03.11., 23:25 UTC: Arbeit nicht vor 06:00 MEZ (05:00 UTC) beenden (ORCHESTRATION Abschnitt 6).
    - Am 03.11. abends war die Platte voll (15 MB frei). Der Orchestrator löschte alte Scratch-Verzeichnisse abgeschlossener Aufträge (13 bis 16, Caches 09f/09g); danach 15 GB frei (ORCHESTRATION Abschnitt 6). Protokolle aus diesen Scratch-Verzeichnissen sind damit nicht mehr verfügbar. Die Volllauf- und Fuzz-Protokolle unter `orch/` sind erhalten: `orch/fz/` bis `orch/fz4/`, `orch/fr-09g/`, `fr-20b/`, `fr-20e/`, `fr-20h/`, `fr-20l/`, `fr-final/`, `fr-m1/` und `fr-m1-v/` lagen bei Redaktionsschluss vor.
    - Die Messung 17 wurde um 19:15 UTC gestoppt, weil Option A Code ändert. Am 04.11. lief sie neu (17b). Den Messagenten musste der Orchestrator nach dessen Übergabe anhalten und Lauf 2 selbst starten (ORCHESTRATION, 01:33 UTC).
    - Der Prüfer von 17c startete versehentlich von 02:15 bis 02:17 UTC eine Messung neben dem Volllauf `fr-m1`. Er brach sie ab und löschte die Reste; die Laufzeiten dieses Fensters sind gestört (ORCHESTRATION, 02:20 UTC).
    - Halb Geprüftes wurde laut ORCHESTRATION nie zusammengeführt.
11. **Endstand nach dem Abschluss-Volllauf verschoben (Aufträge 22 und 23):**
    - Um 23:45 UTC legte der Orchestrator fest: Endstand ist 9ad24a5; 22 läuft erst nach Messungen und Abnahme-Dokumenten und nur mit eigenem Volllauf. Um 00:10 UTC änderte er das: 22 lief mit `nice -n 19` neben dem Abschluss-Volllauf und ruhte während der Messungen (ORCHESTRATION, 23:45 und 00:10 UTC).
    - Um 00:50 UTC kam R48 dazu. Neuer Plan: Endstand = 9ad24a5 + 22 + 23, ein gemeinsamer Volllauf nach den Prüfungen von 23 (ORCHESTRATION, 00:50 UTC). `docs/tasks/22-extras.md` sagt dagegen weiter „Zusammengeführt wird 22 erst nach einem eigenen Volllauf, also nach M1“ (Anhang B, Nr. 8).
    - Zusammengeführt wurden 22 und 23 um 02:35 UTC, **vor** dem Ende ihres Volllaufs. Beim Merge liefen gofmt, vet (ohne Tags, mit Tags, `GOOS=openbsd`) und Build; der Volllauf `fr-m1` lief da bei `racetag-internal_client` (ORCHESTRATION, 02:35 UTC). Der Abschluss-Volllauf auf 9ad24a5 gilt für 22 und 23 nicht. Ergebnis von `fr-m1`: grün, 67 von 67 Schritten, kein Fehler (Ende 03:40:59 UTC). Der zusammengeführte Code ist damit nachträglich im vollständigen Volllauf bestätigt.
    - `fr-m1` lief auf zwei Quellen: gofmt, vet und `cmd/gomail-ceremony` auf 10b1783 (ohne 23b, das nur einen Test in `client` ändert), alle übrigen Schritte auf 1217496 (mit 23b). Die Testdateien in `internal/bench` aus 17 enthält er nicht; für sie gibt es die Läufe der Implementierer von 17b bis 17d (ORCHESTRATION, 02:05 UTC) und den grünen Lauf auf dem Branch (aa87a99: `-race`, `-race` mit Tags, 386; `orch/fr-head-bench/`).
    - Gemessen ist 9ad24a5, nicht der Endstand. Nach MEASUREMENTS und ORCHESTRATION (00:50 UTC) berühren 22 und 23 keinen Pfad, der je Mail läuft.
    - Die Prüfungen von 23 hielten zunächst nur nach Code-Lesung, weil während der Messungen keine Läufe erlaubt waren. Ihre Läufe hat der Orchestrator nach den Messungen nachgeholt (`orch/v23.sh`), statt die wartenden Prüfer laufen zu lassen; erst danach galten die Prüfungen als abgeschlossen (ORCHESTRATION, 01:10 und 01:33 UTC; `docs/tasks/20-notes.md`, „Läufe der Prüfungen von 23“).

---

## 7. Offene Fragen und Haltepunkte

Stand nach QUESTIONS und AUDIT 7.1. Gebaut ist bis zur Antwort jeweils die strengste Lesart, markiert mit `TODO(Qn)`.

| Frage | Haltepunkt | Gegenstand | Stand | Folge für M1 |
|---|---|---|---|---|
| **Q19** | 2 (und 1), aufgelöst | Nachfolge nach Kompromittierung der Plattformidentität | entschieden 03.11. (D93, Option A), gebaut mit 21c, 21a, 21b: `succeed --compromised` mit Grenze, Kaskade, Pflicht zur Neuausstellung (RUNBOOK 7.3.5); neuer `init` bei kompromittiertem Root (D93 (5), RUNBOOK 7.3.6) | C mit Kompromissfall; S9 gebaut, im Abschluss-Volllauf auf 9ad24a5 grün; Restgrenzen R17 |
| **Q8** | 1 und 2, aufgelöst | Widerruf von Ingest- und Admin-Generationen; Ende der Admin-Generation; Admin-Rotation | entschieden 03.11. (D93), gebaut: Pin-Feld 7, `revoke`, `admin-rotate`, Ende bei `valid_from` von `admin-<g+1>.cert` | Ingest-Teil von S9 gebaut; Restgrenzen R18 |
| **Q18** | 1 | alleiniges Mitglied nach Widerruf ohne geprüfte `folders.gml` | offen; Ablehnung ohne Ausweg: `List`, `Rename`, `SetFolders` scheitern, `Read` geht; Vorbeugung mit mindestens zwei Benutzer-Mitgliedern (RUNBOOK 8.4) | Einschränkung in A (AUDIT R21, S73) |
| **Q20** | 1 | Markierung „noch kein bestätigter Zustand“ nach Wiederherstellung | offen; `Unconfirmed` bleibt bis zum Vermerk eines anderen Benutzer-Mitglieds; ein alleiniges Mitglied bleibt markiert (nur Warnung) | keine Sperre, nur Warnung (AUDIT R22) |

**Zu Q19 und Q8:**
- Vorlage: `docs/tasks/q19-q8-entscheidungsvorlage.md` (b44ee78).
- Entscheidung: D93 (92e43ad); Nachträge 671fc1d (Kaskade, verschobene Köpfe), 322b79e (T + 1 ms) und Nachtrag 21e.
- Geschätzt hatte die Vorlage etwa 7 bis 8 Pakete, 15 bis 25 neue Tests und 2 bis 3 Prüfrunden. Gebaut wurde in drei Code-Aufträgen (21a bis 21c) und zwei Dokumentaufträgen (21d, 21e), mit je zwei Prüfrunden. Die Aufträge 20o und 21a bis 21c brachten zusammen 56 neue Testfunktionen; der Anteil von 20o ist nicht getrennt gezählt.

**Weitere offene Fragen** (AUDIT 7.1):
- Q1 (Wiederherstellungsempfänger)
- Q2 (Einladungen signiert oder JSON)
- Q3 (nicht M1)
- Q4 (Logschlüssel ist der Ingest-Schlüssel)
- Q6 (Vertretung)
- Q7 (`mailbox rotate`)
- Q9 (zeitliche Bindung von Adresszuordnungen)
- Q11 (Laufnummer eines Indexsegments)
- Q12 (Thread-Wurzel)
- Q13 (`checkSignerGen`)
- Q15 (Neuausstellung für Leser vergangener Zeiträume)

Entschieden sind Q5, Q8, Q10, Q14, Q16, Q17, Q19, Q21 und Q22.

In SPEC-ISSUES sind nach eigener Zählung 18 Punkte offen: S23, S27, S28 (Q4; Q8-Anteil erledigt), S35, S43, S44, S48, S52, S69, S71, S72, S73, S75, S83, S87, S88, S89, S90. Gezählt sind die Einträge mit „Art: offen“; S23 hat keine Zeile „Art“, nur „Stand M1: Offen bleibt …“. S24, S25 und S76 sind „erledigt durch D93“. AUDIT 7.2 und SPEC-ISSUES („Stand Auftrag 21 (D93)“) nennen seit 20q ebenfalls 18.

**Ohne S-Punkt, offen mit `TODO(ask)`:**
- Passphrase mit Echo, Seed vor der Abfrage der Kontrollwörter gelöscht (R31)
- Gruppenname bei `gomail-server init` (R34)
- Master alter BSD-Pseudoterminals unter DragonFly (R40)

Der frühere Punkt „neuer `init` statt Nachfolge bei kompromittiertem Root“ ist mit D93 (5) entschieden (AUDIT 7.2, RUNBOOK 7.3.6).

---

## 7a. Entscheidungen, die der Auftraggeber prüfen sollte

Diese Entscheidungen hat der Orchestrator selbst getroffen, oder sie legen eine Regel der Orchestrierung aus. Keine davon hat der Auftraggeber im Repository bestätigt. Jede lässt sich umstoßen; die Folge steht dabei.

1. **D94: Fund mittel aus der Nachprüfung von 17d als niedrig eingestuft** (Kriterium D; DECISIONS D94, fd7b87f).
   - Fund: `scripts/bench.sh` nimmt einen Optionswert an, der mit `-` beginnt; `-o -render=F` startet eine Messung statt der Darstellung. Die Prüfung stufte ihn als mittel ein.
   - Entscheidung des Orchestrators: niedrig. Begründung: Der Fund betrifft nur das Einlesen der Optionen eines Entwicklerwerkzeugs bei einem Tippfehler. Er erzeugt keine falschen oder still unvollständigen Zahlen und berührt weder MEASUREMENTS noch Produktivcode oder Sicherheit. Mit 17b, 17c und 17d war die dritte Prüfrunde erreicht.
   - Damit wich der Orchestrator vom Haltepunkt 3 ab: Statt nach drei Runden zu fragen, stufte er selbst ein.
   - **Vorbehalt** (D94): Stößt der Auftraggeber die Einstufung um, ist der Fund vor dem Urteil zu beheben. Abhilfe nach D94: `need` lehnt Werte ab, die mit `-` beginnen.
2. **Nachträge zu D93 im Rahmen von Option A**, gekennzeichnet als „Entscheidung des Orchestrators“ (DECISIONS D93; Abschnitt 6, Nr. 9): Kaskade über die Identitätsgeneration, Verschieben der Köpfe einer ungültig gewordenen Generation durch `log repair`, `revoked_at_time` = Kopfzeit + 1 ms. Mit 22 dazu: Admin-Widerruf nur mit Untergrenze, die Prüfung „wäre nie gültig gewesen“ nur für Ingest (D93 Nachtrag 22). Sie ändern Prüfregeln ohne neues Format.
3. **R48 als mittel eingestuft und vor M1 behoben** (ORCHESTRATION, 00:50 UTC): Die Prüfung meldete den Fund nur als Nebenbeobachtung. Die Einstufung brachte den Auftrag 23 und verschob den Endstand. Umstoßen hieße hier nur: Die strengere Einstufung war nicht nötig.
4. **Zusammenführung von 22 und 23 vor dem Ende ihres Volllaufs** (ORCHESTRATION, 02:35 UTC; Abschnitt 6, Nr. 11). Wäre ein Schritt von `fr-m1` gescheitert, hätte im Branch ein Code-Stand ohne grünen Volllauf gelegen. Das ist nicht eingetreten: `fr-m1` ist grün, 67 von 67 Schritten. Zu prüfen bleibt nur die Reihenfolge, also der Merge vor dem Ende des Volllaufs.
5. **D92: Betriebsvoraussetzung statt Behebung** eines Fundes mittel unter Bedingung (Elternverzeichnis eines Client-Verzeichnisses; DECISIONS D92, AUDIT R46). Das Programm prüft die Voraussetzung nicht.
6. **D91: Wachstum des Client-Zustands bei Schreibzugriff als bekannte Grenze** (DECISIONS D91, AUDIT R27 (a), R43).
7. **Auslegung der Kriterien:**
   - B: Die 11 Marken `TODO(phase3-translog)` im Testdouble `translogtest` gelten nicht als offen, weil das Kriterium Produktivcode meint (HANDOFF; Anhang B, Nr. 2).
   - E: Der lokale Modus des Zwei-Maschinen-Skripts gilt als „bedingt“ (ORCHESTRATION Abschnitt 1).
   - E: Kriterium E gilt für jedes Paket unter `internal/`, auch für Testhilfen wie `testenv` (HANDOFF „Testabdeckung“).
   - A: offene Haltepunkte zählen als erfüllt, wenn die strengste Lesart gebaut oder der Befehl nicht freigegeben ist (Nr. 9).
8. **Entscheidungen unter dem Mandat „entscheide du“** zu Q16, Q17, Q21 und Q22, darunter Zusammenführungen mit offenen Funden (Abschnitt 6, Nr. 1 und 2).
9. **Kriterium A als erfüllt eingestuft** (HANDOFF seit 20r, 541a349; Abschnitt 2, A).
   - Lesart: „offene Haltepunkte = strengste Lesart oder nicht freigegeben“. An Q1, Q2, Q6, Q7, Q18 und Q20 ist die strengste Lesart gebaut, oder der Befehl ist nicht freigegeben (`recovery …`, `--delegate`, `mailbox rotate`).
   - Die erste Prüfung von 20r fand das frühere Urteil „bedingt“ für A nicht belegt (Fund mittel); seit der Nacharbeit stuft HANDOFF A als erfüllt ein.
   - Stößt der Auftraggeber die Lesart um, ist A bedingt, solange diese Fragen offen sind. Das Urteil „M1 bedingt erreicht“ bliebe, A käme als zweites bedingtes Kriterium neben E dazu.

---

## 8. Bekannte Grenzen

AUDIT Abschnitt 5 führt R1 bis R48 mit Belegen (R48 seit 22d), ordnet sie aber **nicht nach Schwere**. Eine Bewertung nennen nur R46 (mittel unter einer Bedingung, unter D92 niedrig) und R48 (mittel, behoben mit Auftrag 23). Die folgende Auswahl übernimmt die Grenzen, die HANDOFF unter „Bekannte Grenzen“ hervorhebt, und die an offenen Fragen hängenden. Sie ist **keine Schwereeinstufung** der Quelle. `[OHNE BELEG: Einstufung „über niedrig“ je R-Eintrag; vor der Freigabe vom Orchestrator festzulegen oder diesen Hinweis stehen lassen]`

**D93: Widerruf von Plattformgenerationen, Restgrenzen** (R17, R18; HANDOFF „Bekannte Grenzen“; D93 Nachtrag 21e)
- Der Pin ist der einzige Träger des Widerrufs. Clients mit altem Pin merken nichts.
- Was ein Dieb vor der Grenze `revoked_at_size` geloggt hat, bleibt gültig. Ein Dieb mit der Identität kann vor der Grenze eigene Admin- und Ingest-Zertifikate loggen; sie handeln ab der Grenze nicht mehr (Kaskade). `publish` ersetzt ihre Dateien nur für Zertifikate ab `<N>`. Liegt ein vor `<N>` geloggtes Zertifikat des Diebs nicht in `platform/`, scheitert die Neuausstellung gleichen Namens erst beim Loggen (`docs/tasks/20-notes.md`, „Aus den Prüfungen von 22d“, L2 und Hinweis; RUNBOOK 7.3 und 8.6 seit 22d).
- Eine weit in die Zukunft datierte Adresszuordnung friert eine Adresse ein (Q9; 20-notes, 21a F3).
- Metadaten ab Version 2 nennen nur die Ingest-Generation von Version 1, nicht Schlüssel oder Zertifikats-Hash. Ein Gerät mit altem Pin kann deshalb unter Umständen eine Mail einer widerrufenen Generation „waschen“ (R18 (e)). Abhilfe nur mit einer Formatänderung nach M1.
- Die Abläufe 7.3.3 bis 7.3.5 sind als Ganzes mit den Programmen nicht getestet (Abschnitt 2, C).
- Symlinks unter `data/platform/`: Ein Symlink unter einem geloggten Namen, dessen Ziel außerhalb den geloggten Inhalt hat, überlebt `publish`; ein hängender blockiert die Heilung. Clients bleiben fail closed, der Betreiber entfernt sie von Hand (`find data/platform -type l`; 20-notes, Angreiferprüfung von 22, N1 und N2; RUNBOOK seit 22d).
- R48 (behoben mit 23): Vor Auftrag 23 konnte ein Tausch von `ingest-<g>.cert` zwischen zwei Lesevorgängen den Logabgleich umgehen. Seit 23 arbeiten Signatur, Schlüssel und Logabgleich auf denselben Bytes. Ein Test sähe eine naive Doppel-Lese-Fassung innerhalb von `store` nicht (Mutation M4 überlebt; 20-notes, „Läufe der Prüfungen von 23“).
- Betriebsregeln aus den Prüfungen, im RUNBOOK 7.3:
  - Server vor dem Ablesen der Grenze anhalten.
  - Nach Verlust immer `revoke`, nicht nur `admin-rotate`.
  - Alte Plattformzertifikate nie von Hand aus `platform/` entfernen.

**D91: Wachstum des Client-Zustands ohne Schlüssel bei Schreibzugriff** (R27 (a), R43)
- **Rate:** je Sync und angegriffener Epoche etwa 270 B · D · k (D zusammenfassende Geräte, k Segmente je Ergebnis), sobald (D − 1) · k ≥ 15. Mit einem verborgenen Segment des eigenen Ergebnisses gilt (D − 1) · k ≥ 16. Mit einem Gerät wächst der Zustand nur durch Zurücklegen von `pending`, um 300 B · k je Runde.
- **Gemessen** bei einem Sync je 5 Minuten, bis `state.json` die Lesegrenze von 64 MiB erreicht:

  | Geräte | k | Zeit |
  |---|---|---|
  | 17 | 2 | 26 Tage |
  | 2 | 17 | 24 Tage |
  | 17 | 17 | etwa 3 Tage |
  | 16 | 1 (eigenes Ergebnis sichtbar) | 55 Tage |
  | 1 (4146 Mails) | 3 | 259 Tage |

  Mehrere Epochen addieren sich.
- **Im ehrlichen Betrieb:** rund 70.000 Mails je Client-Verzeichnis (HANDOFF).
- **Einordnung:** Der Orchestrator nimmt das als bekannte Grenze an, nicht als Fund:
  - kein Stillstand in Stunden;
  - linear in den Syncs;
  - der Angreifer braucht Schreibzugriff, der ohnehin das Löschen aller Daten erlaubt;
  - die Wirkung ist sichtbar, ohne Leck.
- **Abhilfe nach M1:** Vermerke nicht mehr vorhandener Segmente aufräumen (Q22 Variante B, Ausnahme von D84 (2)) oder `state.json` je Epoche begrenzen.

**D92: Betriebsvoraussetzung für Client-Verzeichnisse** (R46)
- **Befund:** Ein offener Client schreibt nach dem Sperren über den Pfad: `state.json`, `user.rec`, den Schlüsselspeicher, `new-mailboxes/` und den Audit-Index. Wer das Elternverzeichnis beschreiben kann, kann das Client-Verzeichnis dazwischen tauschen. `device lost` überschreibt dann den Schlüsselspeicher eines anderen Client-Verzeichnisses desselben Kontos.
- **Bewertung:** mittel unter der Bedingung, dass ein anderer Benutzer ein Elternverzeichnis ohne Sticky-Bit beschreiben kann. Vorbestehend. Nachgestellt mit `TestAttack20lDeviceLostDirSwapped` (nur im Scratchpad).
- **Entscheidung:** Das Elternverzeichnis darf nur für den eigenen Benutzer beschreibbar sein oder trägt das Sticky-Bit (Eigentümer der Benutzer oder `root`). Das Programm prüft das nicht. RUNBOOK 0.3, 3.2 und 9.1 nennen den Prüfbefehl `stat -c '%U %a' <eltern>`. Unter dieser Voraussetzung gilt der Fund als niedrig.
- **Abhilfe nach M1:** ein über `Open` gehaltenes `os.Root` für alle Schreibvorgänge. Für `keygen` und `restore` ist die Klasse seit 20l geschlossen, bis auf einen Restwettlauf vor dem Umbenennen (R33; Stand nach 20o).

**An offene Fragen gebunden:**
- R16 (Q4): Der Logschlüssel ist der Ingest-Schlüssel; gegen falsche Köpfe stehen nur die Zeugen.
- R18 (Q9): rückdatierbare Adresszuordnungen innerhalb einer gültigen Generation.
- R21 (Q18), R22 (Q20), R28 (Q13), R30 (Q11).

**Verfügbarkeit bei Schreibzugriff:** 2.7 verspricht Erkennung, nicht Verfügbarkeit. Betroffen sind:
- R23: Sperre durch einen frei signierten Vermerk eines kolludierenden Mitglieds
- R24: nicht loggbare Epoche 1
- R25: dem Log widersprechende Epoche
- R26, R41: nicht reguläre Dateien
- R42: Lesegrenze der Indexsegmente
- R44: Neuausstellung, die nie gelingt

**Betrieb und Plattform:**
- R8: `loghttp` ohne Verbindungs- und Ratengrenze; 10.2 verlangt das vor dem Betrieb.
- R15: Zeugenquorum im PoC (1 aus 1).
- R36: zwei Maschinen nur bedingt.
- R40: Terminalbehandlung auf BSD und Darwin nie ausgeführt, nur per `go vet` geprüft.
- R45: `Client` ist nicht goroutinesicher.
- R47 (neu aus 20p): `--log-listen` bindet nur an Loopback. Ein Zeuge auf einer anderen Maschine braucht einen SSH-Tunnel (RUNBOOK 1.7, nicht getestet). Ein `log/` aus einer älteren Sicherung hält der Zeuge dauerhaft als Fork fest (R13, RUNBOOK 8.8, 8.9).
- R37: Klartext beim Empfang; Metadaten sichtbar.
- R38: SMTP-Grenzen statt Missbrauchsschutz, aus Phase 1.

**Nicht in M1** (ORCHESTRATION Abschnitt 1; AUDIT 1.3): Löschen von Epochen, Volltextsuche, QR-Kopplung, TLS und Missbrauchsschutz, Padmé, Hardware-Schlüssel, IMAP und Oberflächen über die Kommandozeile hinaus.

---

## 9. Nächste Schritte

**Vor dem Abschluss von M1** (ORCHESTRATION, 04.11., 02:35 UTC):
1. Erledigt: Volllauf `fr-m1` auf dem Endstand grün, 67 von 67 Schritten, 01:32:49 bis 03:40:59 UTC (Abschnitt 2, E). Das Ergebnis trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).
2. Erledigt: HANDOFF und AUDIT endgültig auf dem Endstand fba4eb2 (Auftrag 20r, Merge 541a349 mit Nacharbeit 94190c6). Die Zahlen der Prüfungen aus Abschnitt 4 trägt 20r nach seinem Auftrag nicht ein; sie stehen in diesem Bericht (Anhang B, Nr. 6).
3. Bestätigung oder Umstoßen der Entscheidungen in Abschnitt 7a durch den Auftraggeber, vor allem D94 und die Lesart für A (Nr. 9).

Erledigt seit dem Entwurf vom 03.11., 23:40 UTC: Abschluss-Volllauf auf 9ad24a5, Volllauf `fr-m1` auf dem Endstand, HANDOFF und AUDIT endgültig (20r), Abdeckung am Endstand, Messung und MEASUREMENTS (aed6ea4), Zusammenführung von 22, 23 mit 23b und 22d, Urteil (Abschnitt 1). Der frühere Schritt „`store`-Fuzzing nach 20l“ ist mit dem vierten Fuzzing-Teil (56464da) erledigt.

**Nach M1, zuerst** (HANDOFF „Was die nächste Phase als Erstes wissen muss“):
1. **Widerruf nach D93 im Betrieb erproben,** vor jedem Betrieb mit echten Mails: die Abläufe RUNBOOK 7.3.3 bis 7.3.5 mit den Programmen auf einer Testplattform durchgehen. Kein Test deckt sie als Ganzes ab.
2. **Wachstum des Client-Zustands begrenzen** (D91: Q22 Variante B oder Grenze je Epoche; braucht eine Ausnahme von D84 (2)).
3. **Zwei echte Maschinen mit NFSv4** fahren (`scripts/two-host-test.sh` ohne `--local`, RUNBOOK 9). Erst dann ist Kriterium E ohne Einschränkung erfüllt. Dazu eine Messung über NFSv4 (MEASUREMENTS „Keine NFS-Messung“).
4. **Vor 10.2 Punkt 1:** TLS, Ratenbegrenzung (auch `loghttp`, R8), Missbrauchsschutz; mehrere Zeugen im Betrieb (R15); Zeuge auf einer anderen Maschine ohne Tunnel (R47).
5. **Formatänderung für Metadaten ab Version 2:** Schlüssel oder Zertifikats-Hash des Signierers von Version 1 festhalten (R18 (e), HANDOFF Punkt 7).
6. **Externes Audit** nach AUDIT 8: geschätzt 31 bis 41 Personentage, mit zwei Prüfern etwa drei bis gut vier Wochen (AUDIT 8.2, seit 20q am Stand 9ad24a5). Vorausgesetzt ist ein vollständig grüner Volllauf mit Protokoll. Die 94 Zeilen Produktivcode aus 22 und 23 bewertet AUDIT 8.2 nicht `[OHNE BELEG: ob die Schätzung mit 22 und 23 gilt]`.

**Kleinere Arbeiten nach M1** (aus DECISIONS, den Notizen und der Kandidatenliste des Orchestrators, 23:25 UTC):
- Niedrige Restpunkte aus 21b: L1 (Exit-Code beim Start mit kaskadenhaft widerrufener Generation), L2 (nicht erreichbarer Zweig, Kommentar), L3 (Auffrischen nach `ErrOrder` ungetestet); Client-Integrationstest für den Widerruf einer Identität bis zur Mail (20-notes).
- Grenze für `valid_from` beim Anhängen einer Adresszuordnung erwägen (21a F3).
- Client über ein bei `Open` gehaltenes `os.Root` (D92 (3)); Prüfung der Betriebsvoraussetzung D92 im Programm.
- `address add` mit `valid_from` = max(jetzt, letzter geloggter Wert + 1 ms) (D81 Nachtrag 20j).
- `store`-Sperrfunktion, die den gesperrten Deskriptor liefert, damit `lockClientDir` die Inode direkt vergleicht (D86 Nachtrag 20h; 20-notes „Aus 20h“).
- Marken `TODO(phase3-translog)` in `translogtest` umbenennen (HANDOFF).
- Befehl, der für Postfach und Epoche den Logeintrag ausgibt (für RUNBOOK 8.7; 20-notes „Aus der Prüfung von 20j“).
- Kommentar „checks, in this order“ in `cmd/gomail-server/main.go` berichtigen (20-notes „Aus 20p“).
- Folgeauftrag F-3 (S7) mit dem Bau von 2.6 (Löschen von Epochen); Volltextindex (6.4).
- Offene Fragen Q1, Q6 und Q7 entscheiden, dann `recovery`, `--delegate` und `mailbox rotate` als Befehle.
- Den Q18-Vorschlag (Ausnahme für die Ordnerliste) entscheiden.

Auftrag 22 ist zusammengeführt (afad8de); der frühere Punkt „Auftrag 22, falls nicht vor dem Urteil zusammengeführt“ entfällt.

**Neue niedrige Punkte nach M1** (seit dem Entwurf; Quelle `docs/tasks/20-notes.md`, Abschnitte zu 22, 22d, 23 und 17, und D94):

*Aus den Prüfungen von 22* (Angreifer N1–N4, Spezifikation N1–N4; „Aus der Angreiferprüfung von 22“, „Aus der Spezifikationsprüfung von 22“):
- Symlinks unter `data/platform/` in `publish` ablehnen oder ersetzen. Ein Symlink unter einem geloggten Namen mit geloggtem Inhalt außerhalb überlebt `publish`; ein Dieb kann den Inhalt später ändern, Clients bleiben fail closed (Angreifer N1).
- Die Meldung bei einem hängenden Symlink unter einem geloggten Namen ist irreführend (`ErrExists … (written meanwhile)`; Angreifer N2).
- Kommentare `cmd/gomail-ceremony/main.go:193-196` und `internal/ceremony/publish.go:745` versprechen Heilung auch für Dateien, die `checkDataPlatform` vorher ablehnt (Angreifer N3, Spezifikation N2).
- `resolveExisting`: Linkziel stückweise auflösen statt lexikalisch (`..` nach einem Symlink); Kommentar „the prefix as it is“ berichtigen (Angreifer N4, Spezifikation N1).
- Testlücke: Mutanten P1-4 (`.pub`-Rückfall ohne `bytes.Equal`) und P1-6 (`os.WriteFile` statt `WriteFileAtomic`) überleben. Die Belegtests des Prüfers `TestV22PubUnderUnloggedSameCert` und `TestV22SymlinkOverLogged` (Scratchpad `verify22-spec/`) übernehmen (Spezifikation N3).

*Aus den Prüfungen von 22d* („Aus den Prüfungen von 22d“):
- L1: Ein Link als `identity-<g>.pub` oder auf FIFO oder Verzeichnis wird verweigert (`store: file exists: … with other content than … of the export`); RUNBOOK 8.6 nennt die Meldung nicht.
- L2: Liegt ein vor `<N>` geloggtes Zertifikat des Diebs nicht in `platform/`, schreibt `publish` die Neuausstellung gleichen Namens und scheitert erst beim Loggen (`translog: duplicate log entry`).
- Hinweis: D93 Nachtrag 21e „Dateien des Diebs ersetzt `publish`“ gilt nur für Zertifikate ab `<N>`; den Text angleichen.

*Aus den Prüfungen von 23 und 23b* (ORCHESTRATION, 01:10 UTC; „Läufe der Prüfungen von 23“):
- Testlücke: Der Testhaken greift erst nach `ReadPlatformCertRaw`; eine naive Doppel-Lese-Fassung innerhalb von `store` sähe kein Test (Mutation M4 überlebt).
- `address add` im Server prüft `cert.IdentityGen` ohne Logabgleich. Das ist folgenlos, weil `Append` die Zuordnung mit der geloggten Generation prüft.
- 23b: Jeder Lauf von `TestPlatformIngestCertSwapped` deckt zufällig nur eine Prüfreihenfolge ab. Vorschlag: ein zweiter Aufruf von `IngestKeyFor(1)` im Schlüssel-Zweig.

*Aus den Prüfungen von 17c und 17d und aus MEASUREMENTS* („Aus den Prüfungen von 17“; D94; MEASUREMENTS „Grenzen der Messung“):
- D94: `need` in `scripts/bench.sh` lehnt auch Werte ab, die mit `-` beginnen (der Fund mittel der Nachprüfung von 17d, als niedrig eingestuft).
- 17d N1: Kopfzeilen `command:` und `env:` je Gruppe verlangen; N2: weitere Umgebungsvariablen abgleichen.
- 17c F3: fehlender Unter-Benchmark und eingerücktes `--- SKIP` beim Darstellen erkennen.
- Messungen nachholen: Empfang mit `testenv.NewLogged`, also mit den Prüfungen von D93 im Messpfad; 374f499 und Endstand abwechselnd im selben Zeitfenster; der Endstand mit 22 und 23.

**Verweise:**
- `docs/tasks/20-notes.md`: alle niedrigen Funde seit 20h mit Fundstelle, darunter die Abschnitte oben.
- Liste der Arbeiten nach M1: Entwurf im Scratchpad des Orchestrators, `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/backlog-nach-m1.md`. Nicht im Repository; Stand c6a5fb2, also vor D93, Auftrag 21 und den Aufträgen 22 und 23. Die neuen niedrigen Punkte oben fehlen dort.

---

## Anhang A: Offene Stellen

Die Platzhalter P1 bis P9 des Entwurfs sind eingetragen oder entfallen:
- P1 (Messung): Abschnitt 2, D.
- P2 (Abschluss-Volllauf): Abschnitt 2, E.
- P3 (Abdeckung): Abschnitt 2, E.
- P5 (HANDOFF/AUDIT): Abschnitt 2, F (20r, 541a349).
- P7 (Urteil): Abschnitt 1.
- P8 (Liste nach M1): Abschnitt 9.
- P9 (Auftrag 22): zusammengeführt (afad8de).
- Die Commit-Hashes der Zusammenführung und das Ergebnis von 17d sind eingetragen (Kopf, Abschnitte 2 D und 3).

Die Stellen, die auf laufende Arbeiten warteten, sind eingetragen:
- Volllauf `fr-m1` auf dem Endstand (grün, 67 von 67 Schritten): in Abschnitt 1 (Abgeschlossen, Tabelle C und E, Begründung), 2 C, 2 E (Tabelle der Volläufe, Volllauf auf dem Endstand, nach dem Abschluss-Volllauf, Zusammenfassung), 5 (Laufzeiten), 6 Nr. 10 und 11, 7a Nr. 4 und 9;
- HANDOFF und AUDIT endgültig (20r, 541a349 mit Nacharbeit 94190c6): in Abschnitt 1 (Abgeschlossen, Tabelle F), 2 (Einleitung, A, E: S9 und Abdeckung, F), 3, 4, 5 (TODO-Inventar), 7a Nr. 9, 9 und Anhang B Nr. 6.
- Offen ist nur der Hash des Commits, der das Ergebnis von `fr-m1` nachträgt; im Text steht dafür „Commit siehe ORCHESTRATION, ‚Stand beim Anhalten‘“.

Es bleiben die Stellen mit `[OHNE BELEG: …]`:
- Inhalt von §7 des Orchestrierungsauftrags
- Spezifikationsprüfung von 20l
- Volläufe nach 12d, 15d, 15e, 20f und 20g
- vollständige Liste der mit dem Standardmodell geprüften Runden; Modell der Prüfungen nach 22:30 UTC
- Höchstzahl gleichzeitiger Agenten nach 19:15 UTC
- Bestätigung des Auftraggebers zu den D93-Nachträgen (Kaskade, verschobene Köpfe, T + 1 ms); siehe Abschnitt 7a
- ob die Audit-Schätzung mit 22 und 23 gilt
- Schwereeinstufung der R-Einträge

Belegt und deshalb entfallen: ob Teilergebnisse der gestoppten Messung verwendet werden (nur als Vergleich, Abschnitt 2, D), ob die Protokolle unter `orch/` die Aufräumaktion überstanden haben (ja, Abschnitt 6, Nr. 10), ob die Audit-Schätzung nach Auftrag 21 gilt (neu geschätzt mit 20q, AUDIT 8.2).

## Anhang B: Widersprüche und Prüfhinweise (vor der Freigabe bereinigen)

Bei fd7b87f erneut gegen die Dokumente geprüft. Die Nummern des Entwurfs sind beibehalten, damit die Verweise im Text stimmen.

1. **Zählung der Runden von 06b** (unverändert offen):
   - D84 (Überschrift „Auftrag 06b, 06c–06h“, „sechs Nacharbeitsrunden (06c–06h)“), ORCHESTRATION Abschnitt 4 („sechs Runden … 06c–06h“) und Q16 („fünf Nacharbeitsrunden“, Runden 06c bis 06g) rechnen 06c und 06d zu 06b.
   - D75 („Auftrag 06, 06c, 06d“) und ORCHESTRATION Abschnitt 4 (Stand nach 08: „06 in Nacharbeit 06c … und 06d“) rechnen sie zu 06.
   - Die Auftragsdateien nennen 06f „Runde 2“, 06g „round 3“ und 06h „rework-4“.
   - Danach hatte 06b vier Runden (06e bis 06h), nicht sechs, und Haltepunkt 3 wäre schon nach 06g fällig gewesen, nicht erst „nach fünf Runden“.
2. **Kriterium B, Auslegung** (Wortlaut bereinigt, Sache offen):
   - HANDOFF formuliert jetzt einheitlich „im Produktivcode aufgelöst“.
   - ORCHESTRATION Abschnitt 1 verlangt wörtlich „alle `TODO(phase3-translog)` aufgelöst“. In `internal/translog/translogtest/unverified.go` stehen am Endstand fba4eb2 weiter 11.
   - ORCHESTRATION Abschnitt 4 (14) nennt B „vollständig“.
   - Der Bericht legt das Kriterium so aus, dass das Testdouble nicht zählt (Abschnitt 7a, Nr. 7). Die Umbenennung stand als Kandidat in ORCHESTRATION (23:25 UTC) und ist nicht beauftragt worden.
3. **Kennzeichnung von Abweichungen von Regel 6** (unverändert offen):
   - HANDOFF „Unabhängige Prüfungen bis M1“ sagt, Abweichungen von Regel 6 stünden „in der Begründung des D-Eintrags“.
   - D82, D86 und D91 nennen sie ausdrücklich. D84 (06b mit drei Funden mittel zusammengeführt) nennt den Vorgang nicht so.
4. **`docs/tasks/20-mandatory-tests.md` zu `TestVerifyCompromisedIdentityStillIssues`** (Rest; AUDIT 6.1 seit 20q bereinigt):
   - Die Datei sagt noch „Übersprungen ist nur `TestVerifyCompromisedIdentityStillIssues` (S9, Q19)“ (Zeile 25 bei fd7b87f), Stand 20f bis 20h.
   - Als Auftragsergebnis vertretbar; maßgeblich sind HANDOFF und AUDIT 6.1 („läuft seit 21c ohne Skip“).
5. **AUDIT 7.2 gegen SPEC-ISSUES:** entfallen. Seit 20q nennen beide 18 offene Punkte; SPEC-ISSUES kennzeichnet die Zeilen „Stand M1“ in S24, S25 und S28 als „vor Auftrag 21, Verlauf“.
6. **HANDOFF nicht durchgehend auf dem Endstand** (Rest nach 20q):
   - Bereinigt mit 20q: Nachtrag für 20o und Auftrag 21 im Kopf, vierter Fuzzing-Teil, Spalte „Code gemessen“, TODO-Inventar an 9ad24a5, Einleitung „Offene Fragen“.
   - Mit 20r (541a349, Nacharbeit 94190c6) nachgeführt: HANDOFF und AUDIT stehen endgültig auf dem Endstand fba4eb2 (Messungen, Abschluss-Volllauf, Laufzeit des Volllaufs, Abdeckung am Endstand, Aufträge 22 und 23). Die erste Prüfung von 20r bestätigte alle Zahlen. Das Ergebnis von `fr-m1` trägt ein weiterer Commit nach (Commit siehe ORCHESTRATION, „Stand beim Anhalten“).
   - HANDOFF „Unabhängige Prüfungen bis M1“ verweist für die Zahlen der Prüfungen auf „Auftrag 20“. `docs/tasks/20r-handoff-final.md` nennt diesen Abschnitt nicht. Die Zahlen stehen in Abschnitt 4 dieses Berichts; HANDOFF sollte darauf verweisen oder sie übernehmen.
   - Das TODO-Inventar von HANDOFF nannte vor 20r am Stand 9ad24a5 einen `TODO(Q19)`. Am Endstand gibt es keinen mehr (22, Punkt 4).
7. **AUDIT 8.2, Umfang:** entfallen. Seit 20q nennt AUDIT 8.2 45.117 Zeilen bei 9ad24a5 und schätzt 31 bis 41 Personentage. Die 94 Zeilen aus 22 und 23 bewertet es nicht (Abschnitt 9).
8. **Endstand** (neu gefasst):
   - Die frühere Frage, ob der Abschluss-Volllauf auf 9ad24a5 statt nach 21e gilt, ist bereinigt. ORCHESTRATION legt um 23:45 UTC 9ad24a5 als Endstand fest und vermerkt den Lauf (23:45, 00:10 und 00:58 UTC).
   - Neu: `docs/tasks/22-extras.md` sagt „Zusammengeführt wird 22 erst nach einem eigenen Volllauf, also nach M1“. ORCHESTRATION hat das um 00:50 UTC geändert (gemeinsamer Volllauf mit 23), und um 02:35 UTC wurden 22 und 23 vor dem Ende dieses Volllaufs zusammengeführt (Abschnitt 6, Nr. 11). Die Auftragsdatei ist als Verlauf lesbar, widerspricht aber dem Ablauf.
   - Neu: Auftrag 20r (`docs/tasks/20r-handoff-final.md`) beschreibt `fr-m1` als „im Code gleich dem Arbeitsbranch nach dem Merge … leer bis auf `internal/bench` aus 17“. Das stimmt mit `git diff --stat 1217496 fba4eb2 -- internal cmd` überein (nur 5 Dateien unter `internal/bench`).
9. **Auftrag 20 gegen Ausführung** (unverändert offen): `docs/tasks/20-acceptance.md` verlangt Fuzz-Protokolle unter `docs/acceptance/<datum>/` und Fuzzing „nacheinander“. Das Verzeichnis gibt es bei fd7b87f nicht, und das Fuzzing lief in zwei Bahnen (HANDOFF; 20-notes, vierter Teil). Siehe Abschnitt 6, Nr. 8.
10. **§7** (unverändert offen): ORCHESTRATION verweist auf einen „Abschlussbericht nach §7“. Der Orchestrierungsauftrag mit §7 liegt nicht im Repository; die Gliederung dieses Berichts ist daher nicht dagegen geprüft.
11. **Veraltete Zahlen im Verlauf** (als Verlauf vertretbar):
    - ORCHESTRATION Abschnitt 4 (18/18b) nennt 40 Restrisiken und 27 bis 36 Personentage. AUDIT nennt heute R1 bis R48 und 31 bis 41 Personentage.
    - ORCHESTRATION Abschnitt 4 (15i–15n) nennt C „vollständig … (Kompromissfall gesperrt, Q19)“. Seit 21c ist der Kompromissfall gebaut.
    - Im Bericht gelten die Werte aus AUDIT und HANDOFF.

**Entfallen gegenüber den früheren Fassungen** (bereinigt, nachgeprüft bei 1b7bd05 bzw. fd7b87f):
- Nr. 5 und Nr. 7 des Entwurfs vom 03.11., 23:40 UTC, und der Hauptteil von Nr. 4, 6 und 8: bereinigt mit 20q (547603e) und den Einträgen in ORCHESTRATION ab 23:45 UTC.
- Früher Nr. 1, Volllauf auf 20i/20l und Stand von 20m: HANDOFF und AUDIT (Nachtrag 20n) nennen den Volllauf auf 1d49e6d jetzt grün und 20m zusammengeführt.
- Früher Nr. 3, Kriterium C: HANDOFF, QUESTIONS (Q19 entschieden) und AUDIT stimmen überein: Der Kompromissfall ist gebaut, es fehlt die Bestätigung im Abschluss-Volllauf. Die alte Formulierung in ORCHESTRATION Abschnitt 4 ist Verlauf (jetzt Nr. 11).
- Früher Nr. 6, Worktree- und Branch-Commits: HANDOFF hat seit 20p eine Zuordnungstabelle. AUDIT sagt im Kopf, dass Hashes in Klammern Worktree-Commits mit gleichem Code sind.
- Früher Nr. 2 (06b), 4 (Kriterium B), 5 (Regel 6), 7 (Verlauf), 8 (Auftrag 20) und 9 (§7) bleiben als Nr. 1, 2, 3, 11, 9 und 10.
