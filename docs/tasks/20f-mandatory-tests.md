# Auftrag 20f: Zuordnung der Pflichttests aus PLAN 10.1 (Teil 1 der Abnahme)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 2bbe23b oder später, in einem eigenen Worktree.
- Darf ändern: neu `docs/tasks/20-mandatory-tests.md`; neue Testdateien (nur Testcode) in Paketen außer `internal/client`, `internal/store` und `internal/translog` (dort läuft parallel 20e). Kein Produktivcode.
- Lies: `docs/PLAN.md` 10.1 und 10.2; `docs/ORCHESTRATION.md` Abschnitt 1 (M1-Kriterien A–F); `docs/HANDOFF.md`; `docs/AUDIT.md` Abschnitt 6.

## Umfang

1. **Tabelle** in `docs/tasks/20-mandatory-tests.md`: jeder Pflichttest aus 10.1 (wörtlich oder sinngemäß, mit Nummer oder Stichpunkt) → Testfunktion(en) mit Datei → Paket → benötigte Tags → Ergebnis eines gezielten Laufs (`go test -run '^Name$'`) auf dem Basis-Commit. Belege am Code, nicht an Kommentaren: Der Test muss prüfen, was 10.1 verlangt. Wo er nur einen Teil prüft, steht das in einer Spalte „Lücke“.
2. **Fehlende Tests:** Fehlt ein Pflichttest oder ein Teil davon und liegt er in einem erlaubten Paket, baue ihn (nur Testcode). Liegt er in `internal/client`, `internal/store` oder `internal/translog`, beschreibe ihn so genau, dass ein Folgeauftrag ihn bauen kann (Datei, Aufbau, Prüfung).
3. **Abdeckung je Paket** messen, ohne `-race`, mit `-tags gomail_dev,gomail_test` wo nötig, `-timeout 60m`: `go test -cover` für jedes Paket unter `internal/`. In eine zweite Tabelle mit Soll (≥ 85 %, ≥ 90 % für `rec`, `keys`, `shamir`, `envelope`, `translog`) und Ist. Für `internal/client`, `internal/store`, `internal/translog` gilt der Wert als vorläufig (20e ändert sie).

## Fertig

- gofmt und `go vet` (mit und ohne Tags) sauber; neue Tests grün unter race und 386 (mit Tags, wo nötig).
- Ein Commit mit `Task: docs/tasks/20f-mandatory-tests.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20f/notes.md` (Container startet etwa stündlich neu).
- Bericht: Zahl der Pflichttests, davon vollständig, teilweise, fehlend; gebaute Tests; Beschreibungen für Folgeaufträge; Abdeckungstabelle mit allen Paketen unter dem Soll.
