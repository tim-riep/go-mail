# Auftrag 20a: Kleine Nacharbeiten außerhalb von `internal/client` (gesammelte Funde niedrig vor der Abnahme)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei ed89ebf, in einem eigenen Worktree.
- `internal/client/**` wird nicht geändert, weil dort parallel 09d läuft.
- Darf ändern:
  - `cmd/gomail-ceremony/**`, `cmd/gomail-server/**`, `cmd/gomailctl/**`
  - `internal/ingest/**` außer `terms.go`
  - `internal/store/fs.go` (nur `ReadFileLimited`) und dessen Tests
  - Kommentare in `internal/translog/**` und `internal/ceremony/**`
  - Testdateien in `internal/bench`, `internal/e2e` und `internal/shamir`; in `internal/shamir` nur die Testdatei, Vektoren unverändert
- Jeder Punkt ist klein. Wenn ein Punkt mehr verlangt, als hier steht, beschreibe ihn im Bericht, statt ihn auszubauen.

## Produktivcode

1. **Ingest-Schlüssel mit künftigem `valid_from` ablehnen.** Ein zu früh gestarteter Server mit neuem Ingest-Schlüssel signiert Mails, die Clients ablehnen. `serve` bzw. `ingest.New` verweigert deshalb ein Zertifikat, dessen `valid_from` nach der aktuellen Zeit liegt. Für die Toleranz gilt `MaxClockSkew`. Ergebnis ist ein Fehler über `errors.Is` und Exit 2 mit fester Meldung. RUNBOOK 6 enthält die Betriebsregel schon; der Satz wird zu „der Server verweigert“. Tests dazu.
2. **`store.ReadFileLimited` öffnet mit `O_NONBLOCK`** und prüft danach mit fstat, ob es eine reguläre Datei ist. Damit hängt kein Leser mehr an einem FIFO im Datenverzeichnis. Das gilt auch für `gomail-ceremony`. Tests: ein FIFO an der Stelle einer gelesenen Datei ergibt einen Fehler statt eines Hängers.
3. **Zeremonie, Exit-Fenster.** Die Wiederanlauf-Goroutinen von `waking` werden vor `exit` nachweislich beendet: `stop` wartet auf `done`. Als letzter Schritt des Abbruchpfads kommt ein einzelnes, zeitlich begrenztes `TCOON` (BSD: `TIOCSTART`) ohne vorheriges `TCOOFF` auf stdout und stderr. Danach bleibt kein Terminal gestoppt zurück. Test dazu.
4. **`gomailctl` und devpts-Instanzen.** `sameTerminal` verlangt bei gleichem `st_rdev` außerhalb von `/dev/tty` zusätzlich gleiches `st_dev`. Damit gelten zwei devpts-Instanzen mit gleicher Pts-Nummer nicht als dasselbe Terminal. In `sameControlling` kommt der Kommentar dazu, dass `TIOCGPGRP` die tragende Prüfung ist. Test, soweit ohne zweite devpts-Instanz möglich; sonst einen Einheitstest mit nachgebildeten stat-Werten.
5. **Veraltete Kommentare berichtigen:**
   - `internal/translog/translog.go` und `translogtest/unverified.go`: „until task 15 … --insecure-no-log“.
   - `internal/ceremony/ceremony.go`: „only with --insecure-no-log … task 14“.
   - `internal/translog/doc.go`, Abschnitt Pin: „client.Config does not have AllowDevIdentity yet“.
   - Paketkommentar von `cmd/gomail-server`, `address add`: „no message names the address“ stimmt nicht, die Ausgabe ist `<adresse> -> <postfach>`. Der Kommentar soll beschreiben, was der Code tut.
   - Doc-Kommentar an `serve`, „checks, in this order“: an die tatsächliche Reihenfolge und an RUNBOOK 1.6 angleichen.
   - `cmd/gomailctl/commands.go`: den toten Kommentar zu `device lost --force-new-generation` bzw. `DeviceLostOptions` entfernen.

## Tests (nur Testcode)

6. **Flakes und Heuristiken:**
   - `internal/shamir` `TestShareFromWordsRejects/swapped_words` wird deterministisch: zwei verschiedene Wörter tauschen.
   - `internal/e2e/twohost_test.go` `filesWithWords`: Als Treffer zählen nur nummerierte Wörter oder Folgen von mindestens 3 aufeinanderfolgenden Wörtern des Seeds bzw. der Anteile.
   - `cmd/gomail-ceremony` `TestPTY`, reshare: Wortpaare, die auch in später angezeigten neuen Anteilen stehen, zählen nicht.
   - `TestPTYSignalSalvo`, Teil „mixed“: Die Mindestabdeckung gilt über beide Salven zusammen, damit der Test unter Last nicht kippt. Die Invariante wird nicht gelockert.
7. **Zeremonie-Tests aus der Prüfung von 15n:**
   - `vt.confirm` und `pty.confirm` beantworten den Hinweis „Eingabe zu früh“ erneut, statt bis zum Timeout zu warten.
   - Ein Test für `unblock`: `O_NONBLOCK` auf einem Terminal, das nur kurz nichts annimmt (ein einzelnes `TCOOFF`, ohne Verwerfen). Der normale Pfad muss ohne Abbruch durchlaufen. Die Mutation „`unblock` als No-op“ muss brechen.
8. **`gomailctl` PTY-Tests ohne feste Wartezeiten:** `TestPtyWordsStdoutRedirected` (100 ms), `TestPtyDoubleEnterAtHolder` (1 s) und `TestPtyRestoreStderrClosed` (200 ms) auf `p.quiet` bzw. eine Markenzeile umstellen, wie in 13e.
9. **Linux-only-Testcode unter openbsd:** `internal/bench/diskspace_unix_test.go` scheitert unter openbsd an `Statfs_t.Bavail` (dort `F_bavail`). Lösung über eine Build-Tag-Variante. `GOOS=openbsd go vet ./...` muss sauber sein.

## Fertig

- `gofmt -l .` leer.
- `go vet ./...` sauber, mit und ohne `-tags gomail_dev,gomail_test`, unter GOOS linux, freebsd, openbsd, netbsd, darwin und windows.
- `go test -race -p 2 -tags gomail_dev,gomail_test` grün für alle geänderten Pakete; ohne Tags grün für `cmd/gomail-ceremony` und `internal/ceremony`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test` grün für die geänderten Pakete.
- Vektoren byte-gleich.
- Mutationsnachweis je Produktivcode-Punkt 1–4.
- Ein Commit `small fixes before acceptance: future ingest keys refused, non-blocking reads, ceremony exit, devpts, comments, flaky tests (task 20a)` mit `Task: docs/tasks/20a-small-fixes.md`. Kein Modellname, keine Co-Authored-By-Zeile.
