# Auftrag 30g: Doku-Nachzug zu Auftrag 30 (Pakete 30A und 30B)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 29g (Nachträge in DECISIONS und HANDOFF erlaubt).

- **Basis:** der Doku-Stand von 29g2, Commit e79e731 (`git reset --hard e79e731` im eigenen Worktree). Ergebnis: genau ein Commit darauf mit der Zeile `Task: docs/tasks/30g-docs.md`, ohne Co-Authored-By und ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle.
- **Code:** 30A 4976e27 (auf 0854dab), 30B 1a3eeb8 (auf df5a202); lies ihn mit `git show`.
- **Quellen:** `docs/tasks/30-nach-m1-nacht3b.md`; 20-notes, Einträge „Volllauf fr-n29, Zufallsfehler“ und „30A“ (Stand am Arbeitsbranch); Notizen unter `scratchpad/impl30a/`, `scratchpad/impl30b/`, `scratchpad/rev30a/` und, falls vorhanden, `scratchpad/rev30b/` (je `notes.md`).
- **Darf ändern:** `docs/AUDIT.md`, `docs/RUNBOOK.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`.

## Umfang

- **30A:**
  - Liste: Nr. 120 erledigt mit Auftrag 30, Paket 30A (mit den vier weiteren Stellen und den Helfern `seedTypo`, `shareTypo`, `swapWords`). Neue Zeile für die Reste aus der Prüfung (`api_test.go:427` äußeres `t`; Hinweise zu `TestSeedTypo`/`TestSwapWords`; `swapWords` dreifach; `shamir_test` mit Restrisiko 2⁻³², Phase 0, nur mit Erlaubnis zu ändern).
  - HANDOFF, „Was die nächste Phase …“: ein Satz als Regel für Tests: Tippfehler in zufälligen Seeds oder Anteilen nur über einen Helfer, der den Prüfsummenfehler vorher nachweist (Seed-Prüfsumme 8 Bit; Tausch oder Kopie gleicher Wörter ändert nichts).
- **30B:**
  - AUDIT R35, RUNBOOK 0.2 und HANDOFF: Der Walk-Test nutzt einen Unix-Socket `sock.go` statt einer FIFO; jedes Öffnen scheitert sofort (ENXIO), ein Rückfall lässt den Test scheitern statt hängen; auf Linux scheitert der Test, wenn der Socket nicht angelegt werden kann, sonst Skip mit Grund. `TestReleaseSwitchesRootLink` prüft die Modulwurzel über einen Link (`releaseRoot` mit `EvalSymlinks`); `releaseEnvReads` lehnt eine Wurzel ab, die ein Link ist. Die Grenze „FIFO-Fall nur mit `mkfifo` im PATH“ entfällt.
  - Wo eine Abnahme oder MEASUREMENTS `-run`-Ausdrücke für diese Tests nennt (nur AUDIT, RUNBOOK, HANDOFF): `TestReleaseSwitchesRootLink` ergänzen.
  - Liste: Nr. 119 teilweise erledigt mit Auftrag 30, Paket 30B (FIFO-Hänger, stiller Wegfall, Prüfung der Wurzel); offen bleibt Fund D (echte Ordner `_x/`, `testdata/`, `vendor/` mit einer Go-Datei im Walk-Baum) und was sonst in Nr. 119 steht.
- **Köpfe:** Nachtrag 30g in HANDOFF, AUDIT und Liste, kurz, im Stil von 29g; Code-Stand „Arbeitsbranch nach Auftrag 29 (ohne 29B) und 30“, die Commits trägt der Orchestrator ein.
- **Nebenbei** (Fund N1 aus der Prüfung 29g2): HANDOFF nennt für 29B „Nr. 111 bis 114“; richtig ist „Nr. 111, 112 und 114“ (zwei Stellen).

## Fertig

Ein Commit; jeder Meldungstext wörtlich wie im Code; Bericht mit geänderten Stellen und offenen Punkten. Notizen: `scratchpad/impl30g/notes.md`.
