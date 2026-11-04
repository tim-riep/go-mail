# Auftrag 20r: HANDOFF und AUDIT endgültig (Abschluss-Volllauf, Abdeckung, Messungen)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Nur Dokumentation.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand, mit 17b zusammengeführt, falls der Orchestrator das nennt), eigener Worktree.
- Darf ändern: `docs/HANDOFF.md`, `docs/AUDIT.md`. Kein Code, keine Tests, keine anderen Dokumente. Was andere Dokumente brauchen, steht im Bericht als Vorschlag mit genauem Text.
- Endstand des Codes für M1 ist 9ad24a5 mit den Aufträgen 22 und 23 (ORCHESTRATION, Verlauf 04.11. ab 00:50 UTC; im Arbeitsbranch als eigene Commits mit `Task: docs/tasks/22-extras.md` bzw. `…/23-platform-single-read.md`). Spätere Commits ändern im Code sonst nur Kommentare in `internal/translog` und Testcode in `internal/bench` (prüfen mit `git diff --stat 9ad24a5 HEAD -- internal cmd` und nennen).

## Quellen (vom Orchestrator erzeugt, im Scratchpad `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/`)

- Abschluss-Volläufe: `fr-final/` (auf 9ad24a5) und `fr-m1/` (auf der gemeinsamen Quelle 9ad24a5 + 22 + 23, `rev` nennt den lokalen Commit; im Code gleich dem Arbeitsbranch nach dem Merge, prüfen mit `git diff <rev> HEAD -- internal cmd`, leer bis auf `internal/bench` aus 17) (je Schritt `<name>.log` mit `.ok` oder `.fail`; `rev` = Commit; `DONE`). Schritte: gofmt, vet (mit und ohne Tags), je Paket `race-`, `racetag-`, `386-` (bei `internal/e2e` nur `race-` und `racetag-` mit `GOMAIL_TEST_MIN_FREE`). Dauer je Schritt aus der Zeile `ok … <s>s` am Ende jedes Logs.
- Abdeckung: `cov-final/` (auf 9ad24a5) und `cov-m1/` (die von 22 und 23 geänderten Pakete `ceremony`, `client`, `ingest`, `store` auf der gemeinsamen Quelle; diese Werte gelten für den Endstand); `go test -count=1 -cover -timeout 60m`, ohne race, `nice -n 19`, gleichzeitig mit dem Volllauf.
- Messungen: `docs/MEASUREMENTS.md` und `docs/measurements/2026-11-04/` (aus 17b; fehlen sie, bleibt Kriterium D mit Platzhalter und der Bericht sagt es).

## Umfang

1. **Abschluss-Volllauf** in HANDOFF: Abschnitt „Stand je M1-Kriterium“ (E), „Laufzeiten“ (Zeile „Volllauf aller Pakete (Abschluss)“ mit Gesamtdauer und den längsten Schritten), „Bekannte Flakes“. Der Volllauf lief ohne `-v`; ein `t.Skipf` der Stillstandserkennung aus 20m steht deshalb nicht in seinen Logs. Dafür gibt es den Ergänzungslauf `fr-m1-v/` (`cmd/gomail-ceremony` auf der gemeinsamen Quelle mit `-v`: `race.log`, `racetag.log`, `386.log`). Prüfe dort mit `grep -n -- '--- SKIP'` und `grep -n 'did not run in both attempts'`, ob ein Teiltest übersprungen wurde, und nenne, dass dieser Nachweis aus einem eigenen Lauf stammt. Ein SKIP wird mit Test und Grund genannt. Gibt es keinen, steht das ausdrücklich da. Die Tests aus 20m und zu S9 (`TestVerifyCompromisedIdentityStillIssues`, `TestLogIngestRevoked`, `TestRevokedIngestEndToEnd`, `TestRevokedCompromise`) sind mit diesem Lauf bestanden. Belege mit Paket und Logdatei. Ein Test, der nur in einem Teil der Läufe übersetzt wird (Build-Tags), wird so genannt.
2. **Abdeckung:** Tabelle „Testabdeckung“ mit den Werten am Endstand. Die Spalte „Code gemessen“ nennt 9ad24a5 bzw. für die vier Pakete aus `cov-m1/` den Endstand mit 22 und 23. Die Herleitung der alten Werte entfällt, Verweis auf die Quelle genügt. Der Satz zum Soll bleibt. Nennen, dass die Messung unter Last lief (nice, parallel zum Volllauf), was die Prozentwerte nicht beeinflusst.
3. **Messungen:** Kriterium D in „Stand je M1-Kriterium“ und der Einstieg (Z. 36) mit den Kernzahlen aus `docs/MEASUREMENTS.md` (Durchsatz `enc`/`proto`/`plain`, Indexkosten, Sync bei 10 000 Mails, Serverspeicher) und dem Verweis.
4. **Kopf und Einstieg** von HANDOFF auf den Endstand. Kein Kriterium als erfüllt ausgeben, das nicht belegt ist. E bleibt „bedingt“ wegen NFSv4 zwei Maschinen (D83, AUDIT R36). Liste in „Stand je M1-Kriterium“ für jedes Kriterium A–F: erfüllt, bedingt oder offen, mit Beleg.
5. **AUDIT:** Kopf und Abschnitt 6.1 (Z. um 261) um den Abschluss-Volllauf auf 9ad24a5 ergänzen. Neue Abdeckungswerte, falls AUDIT welche nennt.
6. **Auftrag 22:** Nennt der Orchestrator ihn beim Start als zusammengeführt, dann trägt HANDOFF ihn in „Bekannte Grenzen“ und in der Commit-Zuordnung nach. Dazu gehört der Stand von `publish` (Heilung von `data/platform/`), Admin-Widerruf und `resolveExisting`. Sonst steht er in „Was die nächste Phase als Erstes wissen muss“ als fertig, geprüft und nicht zusammengeführt, mit Worktree-Commit.

## Fertig

- Nur die zwei Dateien geändert. Jede Zahl mit Quelle (Log oder Datei). Ein Commit mit `Task: docs/tasks/20r-handoff-final.md`, ohne Co-Authored-By, ohne Modellnamen. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20r/notes.md`.
- Bericht: geänderte Abschnitte; Ergebnis des Volllaufs (Schritte, Dauer, SKIPs); Vorschläge für andere Dokumente.
