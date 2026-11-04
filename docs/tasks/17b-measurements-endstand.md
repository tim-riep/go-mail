# Auftrag 17b: Messungen auf dem Endstand (M1-Kriterium D, Fortsetzung von Auftrag 17)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` und der Auftrag `docs/tasks/17-measurements.md` wörtlich, mit den Abweichungen unten.

- Hintergrund: Auftrag 17 wurde am 03.11. auf 374f499 gemessen und angehalten, als mit D93 (Q19/Q8, Option A) der Code noch einmal geändert wurde. Seine Arbeit liegt im Worktree `/home/user/go-mail/.claude/worktrees/agent-a3cc941775d979ff2` (Branch `worktree-agent-a3cc941775d979ff2`, WIP-Commits b72d1d7, 6456729, fb5c488 und eine nicht committete Änderung an `docs/MEASUREMENTS.md`; Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl17/notes.md`).
- Arbeite in diesem Worktree weiter. Committe zuerst die offene Änderung als WIP und führe dann `git merge claude/quirky-keller-hjsl5i` aus. Konflikte gibt es nur, wenn der Arbeitsbranch `internal/bench` oder `scripts/bench.sh` geändert hat; dann gilt der Stand des Worktrees für `scripts/bench.sh` und die Testdateien in `internal/bench` gegen den Code des Arbeitsbranchs.
- Darf ändern: `internal/bench/**`, `scripts/bench.sh`, `docs/MEASUREMENTS.md`, `docs/measurements/**`.

## Umfang

1. Zwei Läufe `GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -count 5 -maxload 0.5` (wie in Auftrag 17, Lauf 1 und 2) auf dem Merge-Commit. Rohdaten nach `docs/measurements/2026-11-04/` mit `umgebung.txt` (Commit = Merge-Commit). Vor jedem Lauf Last prüfen (unter 0,5), sonst warten.
2. `docs/MEASUREMENTS.md`: Alle Kennzahlen aus den Läufen vom 04.11. Der Text nennt den gemessenen Commit und dass der Produktivcode dem Endstand 9ad24a5 entspricht (`git diff --stat 9ad24a5 <merge> -- internal cmd ':!internal/bench'` leer, außer Kommentaren in `internal/translog`; prüfen und nennen). Die Läufe vom 03.11. (374f499) bleiben als Vergleich unter `docs/measurements/2026-11-03/` und erscheinen in einem kurzen Abschnitt „Vergleich mit dem Stand vor D93“ (Median je Kennzahl, Abweichung in Prozent). Jede Zahl mit Befehl, Hardware, Commit und allen Lockerungen aus D77 sowie `GOMAIL_BENCH_MIN_FREE`.
3. Prüfungen am Ende (Messungen zuerst, Prüfungen danach): `gofmt -l .` leer, `go vet ./...`, `go vet -tags gomail_dev,gomail_test ./...`, `go test -tags gomail_dev ./internal/bench` grün, `go test -race -tags gomail_dev,gomail_test ./internal/bench`, `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/bench`.

## Fertig

- Ein Commit (WIP-Commits zusammengefasst, Basis = Arbeitsbranch) mit der Zeile `Task: docs/tasks/17b-measurements-endstand.md` und `Task: docs/tasks/17-measurements.md`, ohne Co-Authored-By, ohne Modellnamen. Nicht pushen.
- Bericht: Kennzahlentabelle (Median, Spanne), Last vor jedem Lauf, Vergleich zu 03.11., Prüfläufe, Commit-Hash.
