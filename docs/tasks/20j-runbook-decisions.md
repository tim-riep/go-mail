# Auftrag 20j: RUNBOOK und DECISIONS auf den Stand nach 20b bis 20h (nur Dokumentation)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree. Der Code von 20h liegt im Branch `worktree-agent-a7b23152bafa90687` (Commit b14d798) und wird parallel zusammengeführt; lies ihn dort (`git show b14d798:<pfad>`), wo RUNBOOK sein Verhalten beschreibt.
- Darf ändern: nur `docs/RUNBOOK.md`, `docs/DECISIONS.md`, `docs/SPEC-ISSUES.md`. Kein Code, keine Tests.
- Quelle: `docs/tasks/20-notes.md` (Abschnitte ab „Aus 20b“), `docs/tasks/20-triage.md` (P-1, R-3), DECISIONS D86 (Nachträge 20b, 20e), D91 (Nachträge).

## Umfang

1. **RUNBOOK:**
   - Abhilfe bei einer Epoche am Kopf, die dem Log widerspricht („Datei durch den Inhalt des Logeintrags ersetzen, nachdem er geprüft wurde“), mit Befehlen, soweit es sie gibt.
   - `keygen`/`restore`: Ziel leer, neu oder nur mit `lock`; Temp-Verzeichnisse `.<name>.keygen-*`/`.<name>.restore-*`; Aufräumen nur mit Marker `.incomplete` durch den nächsten erfolgreichen Lauf derselben Art; ein Temp-Verzeichnis ohne Marker (Abbruch zwischen Entfernen des Markers und Umbenennen) von Hand löschen; ein Einhängepunkt als Ziel scheitert (`EBUSY`/`EXDEV`).
   - `gomail-server address add` bei zurückgegangener oder nachgehender Uhr (`ErrOrder`, P-1/R-3 in `20-triage.md`): als bekannte Grenze mit Abhilfe (Uhr prüfen, nach der Zeit des letzten Eintrags erneut).
   - `internal/client` ist nicht goroutinesicher (für Betreiber eigener Werkzeuge, ein Satz).
2. **DECISIONS:** Nachtrag 20h an D86 (Marker; nur bekannte Namen; Sperrdatei vor und nach dem Sperren verglichen, Restfall Inode-Wiederverwendung als bekannte Grenze; `ErrExists` bei verlorenem Temp-Verzeichnis; `ErrClosed` nach `Close` für alle Methoden mit Fehlerergebnis, `UserID`/`Mailboxes` liefern die IDs im Speicher). D91 (5): die Bedingung für erzwungenes Zusammenfassen an den Code angleichen ((D − 1) · k ≥ 15; der Code: `counted − len(result) ≥ MergeThreshold − 1` und `counted ≥ 16`), Zahlen der bekannten Grenze prüfen und bei Bedarf berichtigen; Entscheidung zu P-1 als „bekannte Grenze, Abhilfe nach M1“ festhalten.
3. **SPEC-ISSUES:** S94 an die Angleichung aus Punkt 2 anpassen, falls nötig.
4. `TestRunbook` (`go test -tags gomail_dev,gomail_test -run TestRunbook ./internal/e2e/`, Umgebung siehe unten) muss grün bleiben.

## Fertig

- Jede Aussage über Code mit Datei und Funktion belegt, geprüft am Code (für 20h an b14d798).
- Ein Commit mit `Task: docs/tasks/20j-runbook-decisions.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20j/notes.md`.
- Umgebung: `export GOTOOLCHAIN=go1.26.10 GOCACHE=/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/gocache`.
