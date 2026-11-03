# Auftrag 21b: Widerruf über Pin-Feld 7 – Client, Ingest, Server (D93)

Sicherheitskritisch. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` und dazu der Schnittstellen-Stand von 21a (der Orchestrator nennt Branch und Commit; `git merge <branch>`). 21a wird parallel fertiggestellt; bei Änderungen der Schnittstelle bekommst du eine Nachricht.
- Darf ändern: `internal/client/**` außer `keygen.go`, `client.go` (Konfigurationsteil), `devicelost.go` (dort arbeitet 20o); `internal/ingest/**`; `cmd/gomail-server/**`; `internal/e2e/**` (Tests).
- Grundlage: D93; Entscheidungsvorlage `docs/tasks/q19-q8-entscheidungsvorlage.md` Abschnitt 4 (Punkte `client`, `cmd/gomail-server`/`ingest`, Tests F-2); `docs/tasks/20-mandatory-tests.md` (S9, F-2).

## Umfang

1. **Client:** Der Client übernimmt Feld 7 aus seinem Pin in den Verifier (21a). `ingestKeyFor`: Metadaten einer widerrufenen Ingest-Generation mit Empfangszeit ab `revoked_at_time` werden abgelehnt (feste Ursache „Generation widerrufen“ in `list`/`read`, Fehler über `errors.Is`). `CheckAddress` beachtet das Ende der Admin-Gültigkeit (D93 (3)) und widerrufene Admin-Generationen.
2. **Server/Ingest:** `gomail-server serve` liest Feld 7 aus `--pin` und startet nicht mit einer widerrufenen eigenen Ingest-Generation (Exit 2, feste Meldung); `ingest.New` entsprechend.
3. **Tests (F-2 aus `20-mandatory-tests.md`):** Client-Test neben `TestLogIngestSuperseded`: nach Widerruf von Ingest-Generation 1 wird eine auf eine Zeit vor `valid_from` von Generation 2 zurückdatierte, mit Generation 1 signierte Mail nicht mehr gelistet, `Read` scheitert mit der festen Ursache; Mails vor `revoked_at_time` bleiben lesbar. Admin: Zuordnung einer widerrufenen bzw. abgelösten Admin-Generation wird abgelehnt. Server-Start mit widerrufener Generation. e2e-Test über das echte Log, soweit die Zeremonie (21c) noch nicht fertig ist mit von Hand gebautem Pin.

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...`; race mit Tags und 386 mit Tags für jedes geänderte Paket (`internal/client` ganz nur bei Last unter 3, sonst gezielt und dem Orchestrator melden); e2e mit Tags. Abdeckung nicht gesunken, `client` ≥ 85 %.
- Ein Commit mit `Task: docs/tasks/21b-revocation-client.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl21b/notes.md`.
