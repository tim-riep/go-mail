# Auftrag 32: zwei niedrige Testreste aus den Prüfungen von 30A und 30B (18.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md`. Nur Testcode. Keine Echtzeitpriorität.

- **Basis:** der Arbeitsbranch, Stand cfe6786 oder neuer (Code = 6cc6ba7). Ergebnis: genau ein Commit mit `Task: docs/tasks/32-nach-m1-nacht3d.md (Paket 32A)`.
- **Notizen:** `scratchpad/impl32a/notes.md`.

## Paket 32A

1. **`internal/ceremony/api_test.go`, Fall „checksum“ in `TestInitProbeFails`** (Liste Nr. 121, Prüfung 30A): Die Closure ruft `swapWords(t, …)` mit dem äußeren `t` auf, läuft aber im Subtest. Berechne die getauschten Anteile vor der Tabelle oder reiche das `t` des Subtests durch. Prüfe den Rest des Pakets und `cmd/gomail-ceremony`, `cmd/gomailctl` auf dasselbe Muster.
2. **`internal/e2e/release28b_test.go`, `makeSocket`** (Liste Nr. 121, Prüfung 30B, Hinweis 1): Gelingt `Listen` auf einem anderen System als Linux, scheitert aber die Typprüfung, bleibt der Eintrag im Baum, und der Test endet mit FAIL statt Skip. Entferne den Eintrag in diesem Fall (`os.Remove`), so dass der Test wie beschrieben mit Skip endet; auf Linux bleibt es bei `t.Fatalf`.
3. **Läufe:** gofmt, vet mit und ohne Tags für `internal/ceremony` und `internal/e2e`; die geänderten Tests mit `-run` unter `-race` mit Tags und unter 386 mit Tags (`TestReleaseEnvReadsWalk` und `TestReleaseSwitches` auch ohne Tags); Gegenbeleg per Mutation in Kopien (für Punkt 2 etwa per Umbiegen des Linux-Zweigs).
