# Auftrag 21a: Widerruf über Pin-Feld 7 – `store` und `translog` (D93)

Sicherheitskritisch. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 92e43ad oder später, eigener Worktree.
- Darf ändern: `internal/store/**` (Pin-Schema), `internal/translog/**`, `internal/rec/allschemas_test.go` (Liste der Schemata).
- Grundlage: D93; Entscheidungsvorlage `docs/tasks/q19-q8-entscheidungsvorlage.md` Abschnitt 4 (Punkte `store` und `translog`); `internal/translog/doc.go` (vorbereitete Form, `TODO(ask)` zu Q8), `verifier.go` (`Revoked`, `MaxRevoked`, `IsRevoked`), `store/records.go` (`PlatformPinSchema`, Feld 7 „TODO(ask)“).
- Parallel arbeiten danach 21b (client, ingest, Server) und 21c (Zeremonie) auf deinem Ergebnis. Lege die öffentliche Schnittstelle früh fest (Typen, Funktionen, Fehlerwerte), committe sie als ersten WIP-Stand und beschreibe sie in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl21a/api.md`.

## Umfang

1. **Pin-Feld 7** in `store`: optionale Liste `gomail/v1/rec/platform-revoked` (1 Rolle u8 mit festen Werten für Identität, Admin, Ingest; 2 Generation u32; 3 `revoked_at_size` i64; 4 `revoked_at_time` i64 in ms). Höchstens `MaxRevoked` Elemente, keine Doppelungen (Rolle, Generation), kanonische Reihenfolge; ein Pin ohne Feld 7 bleibt byte-gleich und gültig. Kodieren, Dekodieren, Prüfen; Tests einschließlich Größengrenze und Ablehnungsfälle; `allschemas_test.go` nachführen.
2. **`translog`:** `Verifier`/`Options` übernehmen die Widerrufe aus dem Pin. Regeln nach D93 (2) und (3): Zertifikate und Nachfolgen, die eine widerrufene Identitätsgeneration ausstellt, Adresszuordnungen einer widerrufenen Admin-Generation und Zertifikate einer widerrufenen Rollengeneration sind ab Logindex `revoked_at_size` ungültig (`ErrOrder` oder ein eigener Fehler über `errors.Is`), in `Append`, im Audit und in `SignHead`; Admin-Generation g gilt nur bis `valid_from` von `admin-<g+1>.cert`. Eine Abfrage für die Clients: Ist Ingest-Generation g zur Empfangszeit t widerrufen? `TODO(ask)` zu Q8 in `translog` und `store` auflösen; `doc.go` nachführen.
3. **Tests:** Grenzen (Index N−1 gültig, N ungültig; Zeit T−1 ms gültig, T ungültig), jede Rolle, Audit über einen Baum mit Widerruf, Pin ohne Feld 7 unverändert, Admin-Ablösung.

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...`; race und 386 für `store`, `translog` und `rec` mit und ohne Tags; die übrigen Pakete bauen (`go build ./...`, `go vet ./...`). Abdeckung `translog` ≥ 90 %, `store` ≥ 85 %. Phase-0-Vektoren unverändert (`git diff --stat 38626a9 -- internal/{rec,keys,shamir,envelope}/testdata` leer).
- Ein Commit mit `Task: docs/tasks/21a-revocation-core.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl21a/notes.md`.
