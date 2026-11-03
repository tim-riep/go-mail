# Auftrag 20q: HANDOFF und AUDIT vor dem Abschluss (nur Dokumentation)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree. Code-Stand für M1: 9ad24a5 (spätere Commits ändern nur Dokumentation und Kommentare in `translog`).
- Darf ändern: `docs/HANDOFF.md`, `docs/AUDIT.md`, `docs/SPEC-ISSUES.md` (nur Zählung/Status). Keine Testläufe (ein Volllauf läuft; danach Messungen).
- Quelle: Widersprüche aus dem Berichtsentwurf (`/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/abschlussbericht-entwurf.md`, Anhang B Punkte 4–8).

## Umfang

1. AUDIT 6.1: `TestVerifyCompromisedIdentityStillIssues` läuft seit 21c ohne Skip.
2. AUDIT 7.2 und SPEC-ISSUES: Zahl der offenen Punkte nach D93 (S24, S25, S76 erledigt) neu zählen und angleichen.
3. HANDOFF: Kopf mit Nachtrag zu 20o und Auftrag 21; Fuzzing-Abschnitt mit dem vierten Teil (`docs/tasks/20-notes.md`); Abdeckungsspalte mit Hinweis, welche Pakete seit der letzten Messung geändert wurden (Werte folgen im Abschluss); TODO-Inventar am Stand 9ad24a5 neu zählen; Einleitung „Offene Fragen“ an die Tabelle angleichen (Q19 gebaut).
4. AUDIT 8.2: Zeilenzahlen und Aufwandsschätzung am Stand 9ad24a5 neu zählen (Produktivcode ohne Tests, Pakete einzeln wie bisher), mit Begründung der neuen Schätzung für die zusätzlichen Teile aus Auftrag 21.
5. Platzhalter für Abschluss-Volllauf, Abdeckung und Messungen bleiben stehen („wird mit dem Abschluss eingetragen“).

## Fertig

- Jede Zahl belegt (Befehl in den Notizen). Ein Commit mit `Task: docs/tasks/20q-docs-prefinal.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20q/notes.md`.
