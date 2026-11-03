# Auftrag 21c: Widerruf über Pin-Feld 7 – Zeremonie (D93)

Sicherheitskritisch (Terminalregeln aus D85 gelten unverändert). Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` und dazu der Schnittstellen-Stand von 21a (der Orchestrator nennt Branch und Commit; `git merge <branch>`).
- Darf ändern: `internal/ceremony/**`, `cmd/gomail-ceremony/**`.
- Grundlage: D93, D85 mit Nachträgen; Entscheidungsvorlage `docs/tasks/q19-q8-entscheidungsvorlage.md` Abschnitt 4 (Punkt `ceremony`); `TODO(Q19)` in `internal/ceremony/api.go`, `init.go`, `cmd/gomail-ceremony/main.go`; `TestVerifyCompromisedIdentityStillIssues` (`internal/ceremony/succession15f_test.go`, heute übersprungen).

## Umfang

1. **`succeed --compromised --revoke-at-size N --revoke-at-time T`** freigeben: schreibt den neuen Pin mit Feld 7 für die alte Identitätsgeneration; N und T sind Pflicht und werden gegen einen zeugenbestätigten Kopf geprüft, soweit die Zeremonie ihn kennt (sonst Plausibilität und Dokumentation). `ErrCompromised`-Sperre und `TODO(Q19)` auflösen.
2. **`revoke --role admin|ingest --generation g --revoke-at-size N --revoke-at-time T`:** neuer Pin gleicher Identitätsgeneration mit zusätzlichem Eintrag in Feld 7.
3. **`admin-rotate`:** neue Admin-Generation g+1 (Zertifikat `admin-<g+1>.cert` mit `valid_from`), analog `ingest-rotate`.
4. **`publish`:** nimmt eine Generation aus der Identitätsliste des Pins ohne `identity-<g>.succ` an, wenn der Pin sie nach `succeed --compromised` führt (heute verweigert nach 15g). Feld 7 wird in Folge-Pins übernommen.
5. **Tests:** `t.Skip` in `TestVerifyCompromisedIdentityStillIssues` entfernen, der Test muss mit `Compromised: true` grün sein; `TestSucceedCompromised` positiv; `TestUsage`; PTY-Tests der neuen Befehle nach den Terminalregeln (Anteile nur am Terminal, Abbruchpfad), soweit die Befehle Anteile zeigen oder abfragen.

## Fertig

- gofmt, `go vet` mit und ohne Tags; race mit und ohne Tags und 386 mit Tags für `internal/ceremony` und `cmd/gomail-ceremony` (`-timeout 60m`). Abdeckung `ceremony` ≥ 85 %.
- Ein Commit mit `Task: docs/tasks/21c-revocation-ceremony.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl21c/notes.md`.
