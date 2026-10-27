# Auftrag 02c: Testlücken nach der Nachprüfung von 02b

Branch `worktree-agent-ad1fa47a04a280ccf`, Worktree `/home/user/go-mail/.claude/worktrees/agent-ad1fa47a04a280ccf` (Stand `f8026a3`). Feste Vorgaben: `/home/user/go-mail/docs/tasks/00-vorgaben.md`. Nur Tests und Kommentare, kein Produktivcode.

1. **(niedrig) `created` der `pending`-Dateien ungetestet.** Test in `internal/ingest`: bei t zustellen, die Uhr über den Beginn einer sofortigen Epoche hinaus stellen (`testenv.ImmediateEpoch`), `Flush`, dann Marker und Begriffsliste über den Client öffnen (`OpenPending`): angenommen, `Header.Created` gleich der Empfangszeit (Marker) bzw. der frühesten Empfangszeit (Begriffsliste). Die Mutationen „`created = now()`“ an beiden Stellen müssen den Test brechen (im Bericht nachweisen).
2. **(niedrig) Toleranz nur für sofortige Epochen ungetestet.** In `internal/client` (`epochCases` in `discard_test.go`) den Fall „geplante Epoche, Empfang `Begin − 1 min` → `ErrStaleEpoch`“ für Mails und `pending` ergänzen; die Mutation „Toleranz für alle Epochen“ muss den Test brechen.
3. **(niedrig) Kommentar in `TestDiscardsRemembered`** überzieht („ersetzt durch eine reguläre Epoche“); entweder tatsächlich eine reguläre Epoche 5' anhängen (Client erkennt „ersetzt“, Verwerfung von 2 bleibt) oder den Kommentar auf das Getestete kürzen. Bevorzugt: die Ersatzkette bauen.

Fertig: `gofmt -l .` leer, `go vet ./...`, `go test -race ./internal/client ./internal/ingest ./internal/store`, `GOARCH=386 go test ./internal/client ./internal/ingest`; ein Commit `client, ingest: tests for pending created, planned-epoch tolerance and replaced chains (task 02c)`. Bericht mit Commit-ID und Mutationsnachweis.
