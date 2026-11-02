# Auftrag 09g: Linie 09b vereinfachen: Merkmal „indexiert“ und Grenze `merged` entfallen, kein Datenverlust nach Wiederherstellung, begrenztes Wachstum als bekannte Grenze (Q22, Variante A)

Basis ist die Linie 09b. Dies ist die fünfte Runde, ausdrücklich auf Anweisung des Auftraggebers (Q22: „Deine Entscheidungen“).
- Feste Vorgaben: `docs/tasks/00-vorgaben.md`.
- Worktree: `/home/user/go-mail/.claude/worktrees/agent-a4b5ac897ba87ee5f`, Branch `worktree-agent-a4b5ac897ba87ee5f`, Stand 90fcbe1. Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`.
- Die Aufträge 09b bis 09f gelten weiter, **soweit dieser Auftrag nichts anderes sagt**.
- Erlaubte Pfade:
  - `internal/client/**`
  - `internal/bench/**` (nur Testcode)
  - `scripts/bench.sh` (nur der Beschreibungstext)
- Angriffs- und Belegtests im Scratchpad:
  - `verify09f-attack/kept/`: `v_attack09f_forced_merges_test.go`, `v_attack09f_restore_test.go`, `v_attack09f_split_result_test.go`, `v_attack09f_revoked_reinject_test.go`
  - `verify09f-spec/evidence/zz_v09f_spec_test.go`

## Leitregel (ersetzt die +0-Byte-Forderung aus 09c)

- **Kein Stillstand.** Ein Angreifer ohne Schlüssel darf den Client nicht in kurzer Zeit zum Stillstand bringen: kein `state.json` über 64 MiB in Minuten oder Stunden.
- **Begrenztes Wachstum ist erlaubt.** Wachstum, das je Sync und Epoche durch eine kleine Konstante begrenzt ist, darf bleiben. Es wird gemessen und als bekannte Grenze mit Rate dokumentiert.
- **Kein Datenverlust im ehrlichen Betrieb.** Zurückgespielte oder wiederhergestellte Daten aus einem Backup bleiben suchbar.
- **Bleibt unverändert:**
  - D84 (2): Kein Pfad entfernt Einträge aus `Checked`.
  - Die Übernahmeregel nach Widerruf: Vermerk vor dem Widerruf, inhaltsgebunden.

## Umsetzen

1. **Merkmal „indexiert“ entfällt** (`IndexedMarker`, `IndexedTerms`, `markIndexed`, `indexed()`).
   - Jeder gültige `pending`-Eintrag wird indexiert. Doppelte Einträge verhindert weiter die Deduplizierung gegen vorhandene, angenommene Segmente: „Index schreibt keine schon enthaltenen Einträge.“
   - Vorhandene Felder in `state.json` bleiben lesbar (`omitempty`). Sie werden ignoriert, nicht gelöscht.
   - Test aus der Angreiferprüfung `TestHonest09fBackupRestore`, Variante `data`: Nach dem Zurückholen von `pending/` und `index/` aus einem Backup bleiben alle Mails für alle Mitglieder suchbar.
2. **Grenze `merged` und `merged_result` entfallen.**
   - Zusammengefasst wird wieder ab `MergeThreshold` zählenden Segmenten.
   - Zählend sind verschiedene, gültige Segmente, deren Inhalt nicht verbraucht ist; das bleibt aus 09d/09f.
   - Die Felder bleiben lesbar und werden ignoriert.
3. **Aus 09f bleibt:** Ein Original gilt nur dann als verbraucht, wenn sein Nachfolger angenommen ist. Dabei ist **N1 zu beheben**:
   - Besteht ein Ergebnis aus mehreren Segmenten, verweisen die Vermerke auf **alle** Teile, oder auf einen Bezeichner, der alle Teile verlangt.
   - Ein Original gilt nur dann als verbraucht, wenn alle Teile angenommen sind.
   - Die Lösung muss ohne Wachstum je Zurückspielen auskommen: Der Vermerk wird an Ort und Stelle geändert, mit fester Größe, zum Beispiel ein Hash über die sortierte Liste der Teil-Hashes.
   - Test: `TestAttack09fSplitResultSpent`.
4. **Wachstum messen und dokumentieren.**
   - Szenarien für einen Angreifer ohne Schlüssel:
     - erzwungenes Zusammenfassen, mit 1, 9 und 17 Geräten (`TestAttack09fForcedMergesDevices`);
     - Zurückspielen von `pending`, mit und ohne vorheriges Löschen des Segments;
     - Kopien.
   - Messe das Wachstum je Runde und Gerät und nenne die Zahl der Runden bis 64 MiB, bei einem Sync je 5 Minuten.
   - **Abnahmekriterium:** Mit einem Gerät dauert es bis 64 MiB mindestens 30 Tage; das Wachstum ist linear in der Zahl der Syncs. Mit vielen Geräten oder großen Epochen gilt es je Gerät. Was das Kriterium nicht erfüllt, ist als offener Punkt mit Messung zu melden.
   - Die Zahlen gehören in den Paketkommentar von `index.go` und in den Bericht. AUDIT pflegt der Orchestrator.
5. **Messumgebung.** Prüfe, ob die Anpassungen aus 09f in `internal/bench` noch nötig sind, also das Zurückstellen des Client-Verzeichnisses und das Aufwärmen. Ist eine nicht mehr nötig, nimm sie zurück. Die Messgröße darf sich nicht ändern. Bringe den Text in `scripts/bench.sh` (Zeilen etwa 195–205) auf den tatsächlichen Ablauf.
6. **Niedrige Punkte aus 09f:**
   - Testlücke `metaOlder` mit `<=` statt `<`.
   - Testlücke „Kopien wiederverwendeter Inhalte“.
   - Eine ältere eigene Metadatenversion lässt jedes weitere `device lost` mit `ErrPartial` enden, weil `missingOwnFiles` greift. Das ist mit dem Commit-Text abzugleichen: Entweder zählt eine ältere Version auch dort nicht als fehlend, oder der Text wird berichtigt. Begründe die Wahl.
7. **Flake beheben:** `TestWordErrorsNameNoInput` (`generations_test.go`). Der Test darf nur dann scheitern, wenn die Meldung ein Seed-Wort als ganzes Wort enthält, das **nicht** in der festen Meldung selbst vorkommt; ein zufälliges Seed-Wort wie „word“ oder „list“ darf ihn nicht zu Fall bringen. Ändere nur den Test.

## Tests aus früheren Runden

- Alle Regressionstests aus 09b–09f bleiben grün. Ausgenommen sind die, die gerade das entfallene Verhalten festschreiben, zum Beispiel `TestPendingReplayAfterDeletion*` mit +0 Byte und `TestForeignMergesPutBack`.
- Solche Tests werden auf die neue Leitregel umgestellt: Sie prüfen das begrenzte Wachstum mit fester Obergrenze je Runde, statt sie zu löschen. Liste jede Umstellung im Bericht auf.

## Fertig

- `gofmt -l .` ist leer.
- `go vet ./...` ohne Befund, mit und ohne Tags.
- `go test -race -tags gomail_dev,gomail_test -timeout 40m` grün für `./internal/client` und `./internal/bench`.
- Ohne race grün: `./internal/e2e`, `./cmd/gomailctl`, `./internal/terms`, `./internal/ingest`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/client` grün.
- Abdeckung `client` mindestens 85 %.
- Vektoren byte-gleich.
- Mutationsnachweise für die Punkte 1–3 und 7.
- Ein Commit `client: no indexed marker and no merge limit, restored data stays searchable, multi-part successors, bounded growth measured (task 09g)` mit `Task: docs/tasks/09g-client-simplify.md`. Kein Modellname, keine Co-Authored-By-Zeile.
- **Wichtig:** Der Container wird gelegentlich neu gestartet. Committe Zwischenstände als WIP-Commits auf dem Worktree-Branch und schreibe Notizen nach `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl09g/notes.md`. Am Ende fasst du alle Commits per `git reset --soft` zu einem zusammen.
