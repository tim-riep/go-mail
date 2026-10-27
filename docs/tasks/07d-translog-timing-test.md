# Auftrag 07d: Zeitlimit-Test `TestNewestHeadSize` lastunabhängig machen

Branch `worktree-agent-a45c96e154f7b4f72`, Worktree `/home/user/go-mail/.claude/worktrees/agent-a45c96e154f7b4f72` (Stand fedf03d, enthält den Merge des Arbeitsbranchs). Feste Vorgaben: `/home/user/go-mail/docs/tasks/00-vorgaben.md`. Nur `internal/translog/rework_test.go` (Test `TestNewestHeadSize`) darf geändert werden.

Befund: Im Volllauf des Orchestrators mit `GOARCH=386` auf der belasteten Maschine (vier Umsetzer parallel) schlug `TestNewestHeadSize` fehl: „40000 heads: best of five 51.759963ms (limit 50ms)“. Ein absolutes Zeitlimit von 50 ms ist unter Last nicht haltbar; der Test soll die lineare Laufzeit von `newestHeadSize` (gegen die frühere quadratische Sortierung, die bei 40.000 Namen etwa 0,5 s brauchte) sichern, nicht die Maschine messen.

Umsetzen: Der Test misst `newestHeadSize` für 4.000 und für 40.000 Namen (je bestes von fünf) und verlangt, dass die Zeit für 40.000 höchstens das 40-fache der Zeit für 4.000 beträgt (linear ≈ 10×, quadratisch ≈ 100×), zusätzlich ein großzügiges absolutes Limit von 2 s (ohne `-race`) bzw. 5 s (mit `-race`) nur als Schutz gegen Hänger. Die Mutation „Insertion-Sort/O(n²)“ (in einer Kopie) muss den Test brechen (Beleg im Bericht), der Test muss mit `-count=20` unter `-race` und unter `GOARCH=386` bestehen, während du parallel `go test -race ./internal/client` als Last laufen lässt (Beleg: Ausgabe von `-count=20 -run TestNewestHeadSize -v | grep -c PASS`).

Fertig: `gofmt -l .` leer, `go vet ./internal/translog/...`, `go test -race ./internal/translog/...`, `GOARCH=386 go test ./internal/translog/...`. Ein Commit `translog: TestNewestHeadSize checks linear scaling instead of a wall-clock limit (task 07d)`; kein Modellname.
