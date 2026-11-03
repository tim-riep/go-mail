# Auftrag 20l: Temp-Verzeichnis über einen Deskriptor, Schlüsselspeicher und Sperrdateien ohne steuerndes Terminal

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand) und dazu der geprüfte Stand von 20i: `git merge worktree-agent-a26a72a61947bac17` (Commit 869a196; enthält 20h). 20h und 20i werden parallel zusammengeführt.
- Darf ändern: `internal/client/**`, `internal/store/**` (nicht die Schemata in `records.go`). Nicht `internal/keys` (Phase-0-Paket).
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren.
- Quelle: Angreiferprüfung von 20i (`docs/tasks/20-notes.md`, Abschnitt „Aus der Angreiferprüfung von 20i“), Angriffstests im Scratchpad `verify20i-attack/internal/client/attack20i_test.go`.

## Umfang

1. **Temp-Verzeichnis nur über seine Identität (F2):** `createClientDir` adressiert das Temp-Verzeichnis heute über den Pfad. Wer das Elternverzeichnis beschreiben kann, kann es zwischen den Schritten gegen ein anderes vollständiges Client-Verzeichnis tauschen; dann überschreibt `keygen`/`restore` dieses oder löscht es im Fehlerpfad (`RemoveAll(tmp)`), oder meldet Erfolg mit fremdem Inhalt am Ziel. Abhilfe: nach `MkdirTemp` das Verzeichnis über einen Deskriptor halten (`os.OpenRoot` o. ä.) und alle Schreibvorgänge relativ dazu ausführen; vor dem Umbenennen und vor jedem Entfernen prüfen, dass der Pfad noch dasselbe Verzeichnis nennt (`os.SameFile` gegen den beim Anlegen gemerkten Stand), sonst abbrechen ohne zu entfernen. Die Angriffstests `TestAttack20iVictimDirSwappedOntoTemp`, `TestAttack20iVictimDirRemovedAsTemp`, `TestAttack20iGarbageSwappedBeforeRename` als Tests übernehmen (umbenannt, ohne Präfix `zz_`/`Attack` nach Wahl); sie müssen das sichere Verhalten verlangen. Den verbleibenden Fall (F1: eigener Inhalt am Ziel wird als „in Benutzung“ gemeldet) im Kommentar an `dirTaken` nennen.
2. **Schlüsselspeicher ohne Hänger und ohne steuerndes Terminal (F3.1, R41):** `internal/client` liest den Schlüsselspeicher über `store.ReadFileLimited(path, keys.MaxKeystoreSize)` (oder die passende Grenze) und übergibt die Bytes an `keys.OpenKeystore` bzw. die vorhandene Funktion für Bytes; `keys` bleibt unverändert. Gilt für `client.Open` und `device lost`. FIFO- und Terminal-Test wie in `store` (`TestOpenRegularNoCTTY`).
3. **Sperrdateien ohne steuerndes Terminal (F3.2):** `internal/store/lock_unix.go` öffnet bestehende Sperrdateien (Rückfall nach `O_CREATE|O_EXCL` und `probeLock`) mit `O_NOCTTY` und prüft nach dem Öffnen per fstat, dass es eine reguläre Datei ist (sonst Fehler über `errors.Is`). Test.
4. **Kommentar an `maxReadSegments`** (`internal/client/index.go`): `rec.MaxRecordSize` ist 1 MiB, nicht 4 MiB.

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...` sauber; `internal/store` unter race mit und ohne Tags und 386; `internal/client` gezielt (`-run`) unter race und 386 mit Tags; ganze `internal/client`-Läufe nur bei Last unter 2, sonst dem Orchestrator überlassen.
- Abdeckung nicht gesunken (`store`; `client` nur bei geringer Last).
- Ein Commit mit `Task: docs/tasks/20l-tempdir-identity.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20l/notes.md`.
