# Auftrag 20m: Zeremonie-Tests unterscheiden Programmfehler von Stillstand der Maschine (nur Testcode)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree.
- Darf ändern: nur Testdateien (`_test.go`) in `cmd/gomail-ceremony`. Kein Produktivcode.
- Anlass: `TestPTYPromptBlocked/ABC/stopped` (Volllauf 20e) und `TestPTYStopLoop/6` (Volllauf 20h) scheiterten je einmal an `stuckLimit` (4,5 s) unter Last 2–5 mit hohem I/O-Druck. Die Analyse (Scratchpad `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/flake-promptblocked/`, Bericht im Orchestrator-Verlauf, siehe `docs/tasks/20-notes.md`) fand keinen Pfad, der den Anteil länger als etwa 3,6 s stehen lässt, solange Programm und Test Rechenzeit bekommen; beide Fehlschläge verlangen einen Stillstand von mindestens 2 s des Programms oder des lesenden Testteils.
- Die Grenze von 4,5 s wird nicht angehoben; die geprüfte Eigenschaft wird nicht gelockert.

## Umfang

1. **Stillstand erkennen** in `poll`/`exitWithin` (bzw. den Hilfen, die `TestPTYPromptBlocked`, `TestPTYStopLoop` und die übrigen Tests mit `stuckLimit` nutzen): zu Beginn und an der Frist die Wartezeit des Kindprozesses in der Run-Queue aus `/proc/<pid>/schedstat` (Summe über alle Threads unter `/proc/<pid>/task/*/schedstat`), die größte Lücke zwischen zwei Durchläufen der eigenen Abfrageschleife und den Zeitpunkt des letzten Lesens des beobachteten Terminals festhalten. Ist eine dieser Größen im Fenster über 500 ms, gilt der Lauf als nicht aussagekräftig: der Teiltest wird genau einmal wiederholt; scheitert auch die Wiederholung mit Stillstand, `t.Skip` mit den Messwerten; scheitert er ohne Stillstand, `Fatalf` wie bisher. Ohne Stillstand ändert sich das Ergebnis nicht.
2. **Diagnose vor `Fatalf`:** Zustand des Kindes aus `/proc/<pid>/stat` und `wchan` je Thread protokollieren; danach bis zu 10 s weiter beobachten, ob das Programm endet bzw. Löschen oder Abfrage erscheinen, und das mit Zeit protokollieren.
3. **Last der eigenen Stopp-Schleife begrenzen:** die Schleife mit `LockOSThread` pausiert etwa alle 1024 Durchläufe kurz (z. B. 1 µs), ohne dass der Angriff an Wirkung verliert; Beleg durch die bestehenden Prüfungen (der Abbruchpfad wird in den gestoppten Fällen weiter erreicht, wie bisher protokolliert).
4. **Nachweis:** ein Test der Erkennung selbst (z. B. ein Kind, das per `SIGSTOP` für 3 s angehalten wird, muss als Stillstand erkannt werden; ohne Anhalten nicht).

## Fertig

- gofmt, `go vet` mit und ohne Tags sauber; `go test -race` und ohne race für `cmd/gomail-ceremony` mit und ohne `-tags gomail_dev,gomail_test` grün; 386 mit Tags grün.
- Ein Commit mit `Task: docs/tasks/20m-ceremony-stall-detect.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20m/notes.md`.
- Bericht: geänderte Hilfen und Tests; Nachweis, dass ohne Stillstand nichts anders entschieden wird; Läufe.
