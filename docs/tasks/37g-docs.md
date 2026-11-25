# Auftrag 37g: Doku-Nachzug zu Auftrag 37 (Paket 37A) und Hinweise aus 36g5

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme wie bei 36g: Nachträge an bestehende D-Einträge (nur D93 Nachtrag 36 A) und Nachträge in HANDOFF sind erlaubt.

- **Basis:** aktueller Arbeitsbranch (fab3810 oder später), eigener Worktree, nur Dokumentation, keine `go`-Befehle. Ein Commit mit `Task: docs/tasks/37g-docs.md`. Notizen `scratchpad/impl37g/notes.md`.
- **Code:** 37A zusammengeführt als b463c4a (Endstand b7e6856 auf bfb4320, `docs/tasks/patches/37a-b7e6856.patch`); lies ihn mit `git show b463c4a:internal/store/fsroot36a_linux_test.go`.
- **Quellen:** `docs/tasks/37-nach-m1-nacht4c.md`; 20-notes „Auftrag 37, Paket 37A“ und „36g5“; ORCHESTRATION Abschnitt 14 (04:13 bis 04:27 UTC); `scratchpad/impl37a/notes.md`, `scratchpad/rev37a-1/notes.md`, `scratchpad/rev37a-2/notes.md`.

## Umfang

1. **Nr. 130:** „Teil erledigt mit Auftrag 37, Paket 37A“ (zusammengeführt als b463c4a; Store-Schritte grün, übrige aus `fr-n36a`), je Punkt der alten Zeile, was erledigt ist (Wächter, Frist/`Pdeathsig`, Marke mit Token, Muster am Zeilenanfang, Abdeckung, Variable allein schaltet nichts mehr ein, SKIP ohne Rauschen), und was **offen** bleibt: `-test.short`/`-test.cpu` nicht weitergegeben; neue Reste aus den Prüfungen von 37A (je L1 beider Prüfer, die Hinweise, u. a. `atexit_sleep_ms` unter race, SKIP ohne Marke). Bisheriges hinten als „Bisher:“ wie in den anderen Zeilen.
2. **AUDIT 6.2:** der Satz zu `TestWriteTempInErrorSwapped` um 37A ergänzen (Token, Marke, Frist, `TestFsizeChildVerdict`).
3. **Hinweise aus 36g5** (20-notes „36g5“): (1) HANDOFF Punkt 7 Quellen um „36g4“ (und „36g5“); (2) Kopf D93 Nachtrag 36 A Quellen um „36A2“; (3) Nr. 130 „meist zuerst“ → „zuerst (so in der Probe von Prüfer 1), die Reihenfolge ist aber nicht fest“, falls der Satz nach Punkt 1 noch steht; (4) Nr. 130 Abdeckung auch „H2 von Prüfer 1“, falls der Satz noch steht.
4. **Köpfe:** je ein kurzer Nachtrag 37g in HANDOFF, AUDIT und Liste (Auftrag 37 mit Paket 37A, nur Testcode; 36g5 zusammengeführt als e48f225, ein Prüfer, nur Hinweise). Zählzeile der Liste: keine neue Zeile, außer Punkt 1 verlangt sie (dann fortschreiben).

## Fertig

Ein Commit, nicht pushen; Patch mit `git format-patch -1` nach `scratchpad/patches/37g-<hash>.patch`; Bericht mit geänderten Stellen.

## Nacharbeit 37g2 (25.11.2026)

Ausgangspunkt: aktueller Arbeitsbranch (801865d oder später). Ergebnis: ein Commit, nur Dokumentation, mit `Task: docs/tasks/37g-docs.md (Nacharbeit 37g2)`. Umzusetzen: L1 und H1 bis H4 der Prüfung von 37g (20-notes „37g“, Textvorschläge in `scratchpad/rev37g/notes.md`). Bei H3 genau sagen, welche Schritte in `fr-n37a` neu liefen (die drei Store-Schritte, vet mit und ohne Tags für `internal/store`, gofmt für `internal/store`) und dass die übrigen Schritte des Volllaufs aus `fr-n36a` gelten. In den Köpfen 37g je „37g zusammengeführt als 1d56b3d, ein Prüfer“ ergänzen. Sonst nichts.
