# Auftrag 31: Zufallsfehler in `TestPtyRestoreStderrClosed` (18.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md` (Haltepunkte, Sicherheit der Umgebung, Last). Nur Testcode.

- **Basis:** 0854dab. Ergebnis: genau ein Commit darauf mit `Task: docs/tasks/31-nach-m1-nacht3c.md (Paket 31A)`.
- **Notizen:** `scratchpad/impl31a/notes.md`.

## Paket 31A

1. **Fehler:** `TestPtyRestoreStderrClosed` (`cmd/gomailctl/pty13d_linux_test.go`) scheitert unter Last in etwa 1 von 15 Läufen mit „the first line does not reach the terminal“ nach 60 s, auf 0854dab ebenso (20-notes „Volllauf fr-n29, Zufallsfehler 2“). Der Test stoppt das Kind mit SIGSTOP (`stopChild`, Zustand aus `/proc/<pid>/stat`), tippt die erste Zeile und wartet, bis sie in der Eingabewarteschlange steht (`waitQueued`, `inputQueued > 0`).
2. **Ursache finden und belegen.** Vermutung des Orchestrators: `/proc/<pid>/stat` zeigt den Zustand des Hauptthreads; ein anderer Thread des Go-Programms kann noch laufen und die Zeile lesen, bevor der Gruppenstopp alle Threads erreicht hat. Dann steht die Zeile nie in der Warteschlange. Prüfe das (etwa alle `/proc/<pid>/task/*/stat`) und belege die Ursache mit einem Lauf, der den Fehler unter Last zuverlässiger zeigt.
3. **Abhilfe im Test, ohne feste Wartezeit**; die Prüfung bleibt so streng wie vorher (der Test prüft weiter, dass das Programm die erste Zeile liest, nachdem stderr geschlossen ist). Prüfe, ob andere Tests `stopChild` nutzen, und härte sie mit.
4. **Läufe:** gofmt, vet mit und ohne Tags für `cmd/gomailctl`; die geänderten PTY-Tests unter `-race` mit Tags mit `-count=50` unter Last (zum Beispiel parallel zu zwei CPU-Fressern), dazu derselbe Lauf auf 0854dab als Vergleich; Gegenbeleg per Mutation.
