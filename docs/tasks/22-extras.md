# Auftrag 22: Ergänzungen nach Auftrag 21 (Funde niedrig und kleine Härtungen)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Läuft erst nach den Messungen (Auftrag 17), weil die Messungen eine ruhige Maschine brauchen.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree.
- Darf ändern: `internal/ceremony/**`, `cmd/gomail-ceremony/**`, `internal/client/client.go` (nur `resolveExisting`), `internal/e2e/succession_test.go` (nur Kommentar), Tests dazu.
- Quelle: `docs/tasks/20-notes.md` (Abschnitte zu 21c-Nachprüfungen, 20o-Prüfung, 21e-Prüfung).

## Umfang

1. `publish` (`freeName`): Ein Name gilt auch dann als frei, wenn die Exportdatei genau dem gültigen Logeintrag entspricht; eine fremde Datei unter einem gültigen Namen wird dann durch die Exportdatei ersetzt, und eine `.pub` wird ersetzt, wenn ihr Zertifikat der gültige Eintrag ist. So heilt eine Wiederholung derselben `publish`-Ausführung `data/platform/`. Tests (Angriffstests im Scratchpad `verify21c-attack/internal/ceremony/replace21c_attack_test.go`).
2. `checkRevocations`: die Prüfung „wäre nie gültig gewesen“ (`revoked_at_time ≤ valid_from`) nur für Ingest-Elemente; für Admin bleibt die Untergrenze 2025. Test anpassen (`TestRevocationTimes` Fall 3).
3. `resolveExisting` (`internal/client/client.go`): an einem hängenden Symlink das Linkziel weiter auflösen (`os.Readlink`, relativ zum Verzeichnis des Links), damit ein hängender Link in das Datenverzeichnis als `ErrInsideDataDir` gemeldet wird. Test.
4. Kommentar in `internal/e2e/succession_test.go` (um Z. 172–178, `TODO(Q19)`, „stays locked“) an den Stand nach D93 anpassen.

## Fertig

- gofmt, `go vet` mit und ohne Tags; race mit und ohne Tags und 386 mit Tags für `internal/ceremony`, `cmd/gomail-ceremony`; gezielte `internal/client`-Tests (race, 386, Tags); `internal/e2e` `TestSuccessionEndToEnd`.
- Ein Commit mit `Task: docs/tasks/22-extras.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl22/notes.md`.
