# Auftrag 15e: Datenrennen in Tests von `cmd/gomail-server` (Logpuffer)

Welle 4, Nacharbeit zu 15c; nur Testcode. Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei Commit 201e181; eigener Worktree.

Befund (Volllauf `go test -race ./...` nach dem Merge von 15d, Protokoll `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/fullrun-15d.log`): `TestRequireClientLock` (`cmd/gomail-server/rework15c_test.go:35`) liest `logs.String()` auf dem Puffer, den `logSetup.start` (`main_test.go`, `start`) zurückgibt, während die Server-Goroutine (`loghttp.(*Server).Tick` → `slog`) weiter hineinschreibt. Der Lauf ist lastabhängig (zwei frühere Race-Läufe waren grün).

Umsetzen: In `cmd/gomail-server` eine mutex-geschützte Puffer-Hilfe für Tests (z. B. `type lockedBuffer struct { mu sync.Mutex; b bytes.Buffer }` mit `Write` und `String`), die `logSetup.start` (und jede andere Testhilfe, die einen Puffer an einen weiterlaufenden Server gibt) statt `bytes.Buffer` verwendet; alle Leser dieser Puffer (`grep -n 'start(t)\|\.String()' cmd/gomail-server/*_test.go`) anpassen. Keine Änderung an Produktivcode, an `internal/`, an anderen Paketen.

Fertig: `gofmt -l .` leer, `go vet ./...`, `go test -race -count=10 ./cmd/gomail-server` grün (der Lauf, der das Rennen zeigte, muss mehrfach bestehen), `GOARCH=386 go test ./cmd/gomail-server`, Vektoren byte-gleich. Ein Commit `gomail-server: synchronised log buffer in tests (task 15e)`; kein Modellname. Bericht nach `00-vorgaben.md` (welche Tests den Puffer nutzen, Ergebnis des `-count=10`-Laufs).
