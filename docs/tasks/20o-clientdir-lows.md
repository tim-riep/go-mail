# Auftrag 20o: Funde niedrig der Gesamtprüfung der Client-Verzeichnisse

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 9568de5 oder später, eigener Worktree.
- Darf ändern: `internal/client/keygen.go`, `client.go`, `devicelost.go` und Tests in `internal/client`; `internal/store/store.go` nur für Punkt 3. Parallel ändert 21b andere Stellen in `internal/client` (`read.go`, `logcheck.go`, `mailbox.go`): diese Dateien nicht anfassen.
- Quelle: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/review-clientdir/notes.md` (L2–L7).

## Umfang

1. **L2:** `Open`, `Register` und `openForDeviceLost` lehnen ein Verzeichnis mit `.incomplete` ab (fester Fehler über `errors.Is`); `removeLeftover` prüft zuerst alle Namen und entfernt nichts, wenn ein Eintrag weder Marker noch `leftoverFile` ist. Tests.
2. **L4:** `store.ErrLocked` aus `lockOnlyDir` wird wie `errInUse` gemeldet („not empty or in use by another client“), weiter prüfbar über `errors.Is(err, store.ErrLocked)`. Test.
3. **L3:** `Config.check` vergleicht Client- und Datenverzeichnis mit aufgelösten Pfaden (`filepath.EvalSymlinks`, soweit vorhanden); `createClientDir` prüft nach der eigenen Auflösung erneut, dass das Ziel nicht im Datenverzeichnis liegt. Test mit Symlink in das Datenverzeichnis.
4. **L5:** Scheitert nach dem Umbenennen nur `SyncDir(parent)` oder liefert `sameDir(dir)` einen anderen Fehler als ENOENT/`errTempReplaced`, meldet der Lauf einen eigenen Fehler, der sagt, dass `--dir` vollständig ist, die Dauerhaftigkeit aber nicht bestätigt; der Text von `errTempReplaced` nur beim Tausch. Test über die vorhandenen Fehlerhaken.
5. **L7:** Kommentar an der Sperrregistrierung (`lockPath`), dass sie unaufgelöste Pfade nutzt.

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...`; gezielte Läufe (`-run`) der Client-Verzeichnis-Tests unter race und 386 mit Tags; `store` unter race mit/ohne Tags und 386. Ganze `internal/client`-Läufe übernimmt der Orchestrator.
- Ein Commit mit `Task: docs/tasks/20o-clientdir-lows.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20o/notes.md`.
