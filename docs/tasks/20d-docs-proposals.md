# Auftrag 20d: Vorschläge aus der Einordnung in DECISIONS, SPEC-ISSUES und RUNBOOK übernehmen (nur Dokumentation)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei a76fc16 oder später, in einem eigenen Worktree.
- Darf ändern: nur `docs/DECISIONS.md`, `docs/SPEC-ISSUES.md`, `docs/RUNBOOK.md` und in `docs/tasks/20-triage.md` je übernommenem Vorschlag den Vermerk „übernommen (20d)“. Kein Code, keine Tests.
- Quelle: `docs/tasks/20-triage.md`, Abschnitte „Vorschläge für DECISIONS“ (D-1 bis D-4), „Vorschläge für SPEC-ISSUES“ (S-1 bis S-9), „Vorschläge für RUNBOOK“ (R-1, R-2). R-3 nicht übernehmen (hängt an P-1, noch nicht entschieden).
- Parallel läuft Auftrag 20b (Produktivcode). Beschreibt ein Vorschlag Code, den 20b ändert, übernimm ihn so, dass er auch nach 20b stimmt, oder lass ihn mit Begründung offen.

## Umfang

1. Jeden Vorschlag vor dem Übernehmen am Code prüfen (Datei, Funktion, Konstante, Verhalten). Stimmt er nicht, nicht übernehmen und im Bericht begründen.
2. DECISIONS: D-1 bis D-3 als Nachträge an der genannten Stelle. D-4 (D86 vor D87): nur die Reihenfolge der Abschnitte, kein Inhalt geändert; danach `git diff --stat` und ein Vergleich der sortierten Zeilen vorher/nachher müssen zeigen, dass kein Text verloren ging.
3. SPEC-ISSUES: S-1, S-3, S-4, S-5 als neue Punkte mit den nächsten freien Nummern nach S94; S-2, S-6, S-7, S-8 an den genannten Stellen; S-9 nicht übernehmen.
4. RUNBOOK: R-1 und R-2. Für R-2 vorher am Code und, wenn möglich, mit einem kurzen Test (`go test -run` einer bestehenden e2e- oder gomailctl-Funktion, die `revoke` eines Lesers aufruft) belegen, dass `revoke` eines Lesers keine Epoche anlegt; ohne Beleg nicht übernehmen.
5. `TestRunbook` (internal/e2e, `-tags gomail_dev,gomail_test`) liest RUNBOOK; er muss nach der Änderung grün sein: `GOTOOLCHAIN=go1.26.10 GOCACHE=/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/gocache go test -tags gomail_dev,gomail_test -run TestRunbook ./internal/e2e/`.

## Fertig

- Nur die genannten Dateien geändert; jede Übernahme belegt.
- Ein Commit mit `Task: docs/tasks/20d-docs-proposals.md`, ohne Co-Authored-By. Nicht pushen.
- Bericht: je Vorschlag übernommen oder nicht, mit Begründung; neue S-Nummern; Ergebnis von `TestRunbook`.
