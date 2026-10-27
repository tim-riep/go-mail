# Auftrag 19b: Nacharbeit `TestRunbook` und RUNBOOK (Funde der Prüfung von 19)

Welle 5. Feste Vorgaben: `docs/tasks/00-vorgaben.md`. Worktree `/home/user/go-mail/.claude/worktrees/agent-ad5abdfd1a3a449d4` (Branch `worktree-agent-ad5abdfd1a3a449d4`, Stand d51fe6f). Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`. Auftrag 19 und sein Nachtrag bleiben gültig. Kein Produktivcode.

## Fund mittel

1. **Der Entzug ist nicht geprüft.** Die Mutation `return c.immediate(ch, reason, without(head, user))` → `return c.finish(ch)` in `internal/client/members.go` (`Revoke`) überlebt `TestRunbook`. Die Verpackungen werden gelöscht, aber keine neue Epoche beginnt, und carol bleibt im Kopf. Der Test prüft nur `list` mit Exit 1.
   - Umsetzen: Nach `revoke` muss der Test belegen, was RUNBOOK 4.7 sagt. Eine neue Epoche hat sofort begonnen, sie steht im Log, und carol ist darin kein Mitglied. Nimm dafür die Befehle aus dem RUNBOOK, zum Beispiel `gomailctl inspect` von alice oder bob. Ergänze außerdem, dass eine Mail nach dem Entzug in der neuen Epoche liegt.
   - Nachweis: Die genannte Mutation an einer Wegwerfkopie im Scratchpad bricht den Test. Die Mutationen m2b (Verpackungen werden nicht gelöscht) und m2c (`Revoke` tut nichts) brechen weiter.

## Funde niedrig

2. **Erwartete Verweigerungen von `serve` hängen bei einer Regression bis zum Test-Timeout.** Betroffen sind `runbook_test.go` um die Zeilen 485, 498, 503, 697 und 737. Jeder Aufruf, der eine Verweigerung erwartet, läuft mit einer Frist von höchstens 30 s. Bei Fristablauf: Prozess beenden, Fehler mit dem Schritt melden. Nachweis: Die Mutation `checkPlatformPin` → `return nil` (`cmd/gomail-server/checks.go`) bricht den Test innerhalb der Frist.
3. **RUNBOOK 1.6:** Die Reihenfolge der Startprüfungen an `cmd/gomail-server/main.go` (`serve`) angleichen: Pin lesen, Rechte, Serversperre, Ingest-Schlüssel, Log-Seite (Pin gegen `platform/`, `witnesses.rec`, Log), `ingest.New`, Testsperre, Kopf. Alternativ „in dieser Reihenfolge“ streichen. Die Aussage „ein zweiter Server verweigert, bevor er den Schlüssel liest“ bleibt.
4. **Probe-Rekonstruktion:** `TestRunbook` prüft, dass die Zeremonie die Probe tatsächlich abgefragt hat (Zahl der `AskShare`-Aufrufe mit `want > 0` bzw. die Teilmenge). Der Prompter in `succession_test.go` darf dafür zählen.
5. **Prüfungen auf Klartextlecks aus dem alten `TestRunbook` wiederherstellen.** Text und Geheimwort einer Mail stehen weder im Server-Log noch im Datenverzeichnis. Das gilt zusätzlich zu Betreff und Adressen.
6. **RUNBOOK zur Passphrase-Datei:** Ergänzen: Rechte 0600, nicht im Datenverzeichnis, nicht auf NFS, nicht neben dem Schlüsselspeicher, nach Gebrauch löschen.

## Fertig

- `gofmt -l .` ist leer.
- `go vet ./...` ist sauber, mit und ohne `-tags gomail_dev,gomail_test`.
- `go test -race -tags gomail_dev,gomail_test ./internal/e2e` ist grün.
- `TestRunbook` läuft auch ohne Tags.
- Die Mutationsnachweise aus 1 und 2 stehen im Bericht.
- Ein Commit `e2e, docs: TestRunbook checks the revocation epoch, bounded refusals, RUNBOOK fixes (task 19b)` mit einer Zeile `Task: docs/tasks/19b-runbook-rework.md`. Kein Modellname, keine Co-Authored-By-Zeile.
