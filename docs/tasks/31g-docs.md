# Auftrag 31g: Doku-Nachzug zu Auftrag 31 und Hinweise aus den Prüfungen von 30B und 30g

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 29g und 30g.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, Stand 2e739cf oder neuer, eigener Worktree. Ein Commit mit `Task: docs/tasks/31g-docs.md`, ohne Co-Authored-By, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle.
- **Darf ändern:** `docs/AUDIT.md`, `docs/RUNBOOK.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`.
- **Quellen:** 20-notes, Einträge „Volllauf fr-n29, Zufallsfehler 2“, „30B“, „30g“, „31A“; ORCHESTRATION Abschnitt 12; Notizen `scratchpad/impl31a/`, `scratchpad/rev31a/`, `scratchpad/rev30b/`, `scratchpad/rev30g/` (je `notes.md`). Code von 31A: `git show 6cc6ba7`.

## Umfang

1. **31A:** Liste nach M1: neue Zeile „Zufallsfehler `TestPtyRestoreStderrClosed`“, erledigt mit Auftrag 31, Paket 31A (Ursache: nur der Hauptthread in `/proc/<pid>/stat`; Abhilfe: `stopChild` wartet auf alle Threads in `/proc/<pid>/task`); Rest von Nr. 178 aus `docs/tasks/20-triage.md` bzw. 20b Punkt 9. Wo AUDIT oder HANDOFF die PTY-Tests von `gomailctl` als zeitkritisch beschreiben, kurz angleichen. Kopf-Nachtrag 31g in HANDOFF, AUDIT und Liste, Code-Stand „Arbeitsbranch nach Auftrag 31“ mit dem Commit 6cc6ba7 und dem Volllauf (ORCHESTRATION, Eintrag „31A zusammengeführt“).
2. **Hinweise aus der Prüfung von 30B** (20-notes „30B“) in Nr. 121 der Liste aufnehmen.
3. **Hinweise aus der Prüfung von 30g** (20-notes „30g“): H1 „ENXIO“ nur unter Linux (HANDOFF, Nr. 119); H3 die beiden zu weit gefassten Sätze („jedes Öffnen … in welchem Modus“: `O_PATH` gelingt; „ein Rückfall lässt den Test scheitern“: nur wenn er den Fehler weitergibt, sonst hängt er nicht mehr) in AUDIT R35, RUNBOOK 0.2, HANDOFF und Liste genauer fassen.
4. **Hinweis aus der Prüfung von 29g2:** In AUDIT R35 den Satz „… und das es übersetzen könnte, ohne es zu lesen“ wie in RUNBOOK 0.2 fassen („… und das der Test nicht liest“).

## Fertig

Ein Commit; jeder Meldungstext wörtlich wie im Code; Bericht mit geänderten Stellen. Notizen: `scratchpad/impl31g/notes.md`.
