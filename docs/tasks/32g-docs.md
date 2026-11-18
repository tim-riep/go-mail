# Auftrag 32g: Doku-Nachzug zu Auftrag 32 und Hinweise aus der Prüfung von 31g

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 31g.

- **Basis:** Arbeitsbranch, Stand 9d2e5d1 oder neuer, eigener Worktree. Ein Commit mit `Task: docs/tasks/32g-docs.md`, ohne Co-Authored-By, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle.
- **Darf ändern:** `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`.
- **Quellen:** 20-notes, Einträge „31g“ und „32A“; ORCHESTRATION Abschnitt 12 („32A zusammengeführt“); Notizen `scratchpad/impl32a/`, `scratchpad/rev32a/`, `scratchpad/rev31g/` (je `notes.md`). Code von 32A: `git show c6b2ea2`.

## Umfang

1. **32A:** Liste Nr. 121: der Teil „äußeres `t`“ (mit den zwei weiteren Stellen `TestPublishRefuses` und `TestPTYNoReaderBeforeTerm`) und der Teil „Eintrag bleibt nach gescheiterter Typprüfung liegen“ sind erledigt mit Auftrag 32, Paket 32A; die übrigen Teile von Nr. 121 bleiben offen. Den Hinweis der Prüfung (Doc-Satz von `makeSocket` gilt nicht streng, wenn `bind` gelingt und `listen` scheitert) in Nr. 121 aufnehmen. Kopf-Nachtrag 32g in HANDOFF, AUDIT und Liste, kurz; Code-Stand „Arbeitsbranch nach Auftrag 32“ mit c6b2ea2 und dem Volllauf aus ORCHESTRATION.
2. **Prüfung 31g:** N1 (AUDIT R35, „verschluckt er ihn, besteht der Test“), H1 (AUDIT Kopf 31g, Verweis nur auf H3) und H2 (HANDOFF Kopf 31g, Satz zu SIGSTOP) mit den Textvorschlägen aus `scratchpad/rev31g/notes.md` umsetzen.

## Fertig

Ein Commit; Bericht mit geänderten Stellen. Notizen: `scratchpad/impl32g/notes.md`.
