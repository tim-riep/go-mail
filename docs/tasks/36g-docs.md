# Auftrag 36g: Doku-Nachzug zu Auftrag 36 (36A, 36B) und Hinweise aus 34g

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 34g.

- **Basis:** Arbeitsbranch, aktueller Stand, eigener Worktree. Ein Commit mit `Task: docs/tasks/36g-docs.md`, ohne Co-Authored-By, ohne Claude-Session-Zeile, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle außer `go env`. Patch danach nach `scratchpad/patches/36g.patch`.
- **Code:** 36B ist zusammengeführt (8024b51). 36A liegt als Patch `docs/tasks/patches/36a-558ce2b.patch` (auf c8cda58) vor und ist in Prüfung; Merge-Hash und Volllauf trägt der Orchestrator ein (Platzhalter „die Commits und den Volllauf trägt der Orchestrator ein“). Zum Lesen den Patch in einer eigenen Kopie anwenden.
- **Quellen:** `docs/tasks/36-nach-m1-nacht4b.md`; `docs/tasks/20-notes.md`, Einträge „34g“, „36A“, „36B“; ORCHESTRATION Abschnitt 14; Notizen `scratchpad/impl36a/notes.md` (Tabelle zu Nr. 128), `scratchpad/impl36b/notes.md`, `scratchpad/rev36b/notes.md`.
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`, `docs/DECISIONS.md` (nur Nachträge).

## Umfang

1. **36A:** RUNBOOK 7.2/7.3/8.6 die geänderten Meldungen wörtlich („…, moved to <aside>, is X, not the file written, and stays there: …“ u. a.); D93 Nachtrag 36 A (Temp-Name vor dem Entfernen beiseite, Fenster 2 geschlossen, neues Fenster 2', Verhalten bei scheiterndem rename); AUDIT R17 (b) und 6.2 (neue Tests, Wettlaufzahlen aus 20-notes); Liste Nr. 127 entsprechend.
2. **Nr. 128:** Liste und HANDOFF: Ergebnis der Untersuchung kurz (Sperren je Aufrufer, rmdir-Rückfall der Pfad-Varianten) und der **neue Haltepunkt** `WriteAccept` ohne Postfachsperre als **Entscheidung des Auftraggebers** (Wege: Annahme unter die Postfachsperre legen oder nur den Typ prüfen), auch in HANDOFF Punkt 9 und „Bekannte Grenzen“.
3. **36B:** AUDIT R35 und RUNBOOK 0.2 (Verzeichnis direkt an `skippedTagged`, `os.Stat` nur für Links, Dauertausch-Beleg); Liste Nr. 125 N1 und R01/R04 erledigt; Hinweis H1 der Prüfung (Link mit scheiterndem `os.Stat` still nicht durchsucht) als neuer niedriger Rest.
4. **Hinweise aus 34g** (20-notes „34g“): F1 RUNBOOK 8.6 Zeile der Ankündigung; F2 Nr. 108 und Köpfe; F3 Ursachen von `was not replaced` und Zeile `is unchanged`; F4 HANDOFF Punkt 1 dritter Zustand; F5 Stil.
5. **Köpfe:** Nachtrag 36g in HANDOFF, AUDIT, Liste.

## Fertig

Ein Commit; Meldungen wörtlich wie im Code; Bericht mit geänderten Stellen und neuen Nummern. Notizen `scratchpad/impl36g/notes.md`.
