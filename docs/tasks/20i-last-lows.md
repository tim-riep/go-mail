# Auftrag 20i: Letzte Funde niedrig im Code (aus den Prüfungen von 20b, 20e, 20h)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand) und dazu der geprüfte Stand von 20h: `git merge worktree-agent-a7b23152bafa90687` in den eigenen Worktree. 20h wird parallel zusammengeführt; der Code ist derselbe.
- Darf ändern: `internal/client/**`, `internal/store/**` (nicht die Schemata in `records.go`), `internal/testenv/testenv.go` (nur Kommentar).
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren.
- Quelle: `docs/tasks/20-notes.md` Abschnitte „Aus der Spezifikationsprüfung von 20h“, „Aus der Angreiferprüfung von 20h“, „Aus der Angreiferprüfung von 20b“, „Aus 20g“, „Aus der Prüfung von 20c“.

## Umfang

1. **Kommentar an `lockClientDir`** (`internal/client/client.go`): beschreibt genau, was der Vergleich vor und nach `store.LockFile` leistet, und nennt den Restfall (Wiederverwendung der Inode-Nummer bei mehreren gleichzeitigen Prozessen desselben Benutzers) als bekannte Grenze. Kein neues Verhalten.
2. **`ErrExists` für ein verschwundenes Temp-Verzeichnis nur, wenn Sperre oder Umbenennen ein belegtes Ziel sahen** (Angreiferprüfung 20h, niedrig); sonst der eigentliche Fehler über `errors.Is` prüfbar (z. B. `fs.ErrNotExist`). Tests für beide Fälle; `TestRunLosesTempDir` bleibt grün.
3. **`Client` ist nicht goroutinesicher, `Close` eingeschlossen:** im Paketkommentar und am Typ `Client` festhalten. Kein neues Verhalten.
4. **`store.OpenRegular` und `ReadFileLimited` öffnen zusätzlich mit `O_NOCTTY`** (unix), damit ein Terminalgerät an Stelle einer Datei nicht zum steuernden Terminal wird. Test, soweit ohne Root möglich, sonst Kommentar mit Begründung.
5. **`TestDeviceChangeThenDeviceLost`** prüft den Übernahme-Hinweis (`index.go`, „wurde übernommen und neu signiert“) für das alte Segment positiv.
6. **Kommentar an `testenv.ImmediateEpoch`**: der beschriebene Fall (reguläre Epoche mit Verwürfen) ist nicht erreichbar; Kommentar an das tatsächliche Verhalten anpassen.
7. **Kommentar an `TestAttack09fForcedMergesDevices`**: Bedingung an den Code angleichen (`counted − len(result) ≥ MergeThreshold − 1` und `counted ≥ 16`, also (D − 1) · k ≥ 15).

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...` sauber.
- `internal/store` unter race mit und ohne Tags und 386; `internal/client` gezielt (`-run` für die geänderten Tests) unter race und 386 mit Tags. Der Volllauf des Orchestrators folgt beim Merge; ganze `internal/client`-Läufe nur, wenn die Last unter 2 liegt (`uptime`), sonst dem Orchestrator überlassen.
- Abdeckung `internal/store` und `internal/client` nicht gesunken (mit Tags, ohne race; `client` nur, wenn die Last es zulässt).
- Ein Commit mit `Task: docs/tasks/20i-last-lows.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20i/notes.md`.
