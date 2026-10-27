# Auftrag 13c: Nacharbeit `gomailctl`, Runde 2 (Funde der Prüfung von 13b)

Welle 4. Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Branch `worktree-agent-ad0b87717cb6dc4ca`, Worktree `/home/user/go-mail/.claude/worktrees/agent-ad0b87717cb6dc4ca` (Stand 7d414d3; zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`, nur Doku seither). Aufträge 13 und 13b bleiben gültig. Lies `cmd/gomailctl/tty_unix.go` (`abortSignals`, `terminalID`), `screen.go` (`openScreen`, `abort`, `sameTerminal`, `checkWordInput`, `readWords`). Angriffscode der Prüfung: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify13b/zz_attack13b_test.go` (`TestAttackB13StderrPipeClosed`, `TestAttackB18WordsStderrClosed`, B8 „devtty“, B10).

## Fund mittel

1. **SIGPIPE umgeht den Abbruchpfad.** Ist stderr eine Pipe ohne Leser, beendet die Go-Laufzeit beim Prompt-Write das Programm mit SIGPIPE: Seed bleibt stehen (vor „Seed notiert?“) bzw. Echo und Flusssteuerung bleiben aus. Umsetzen: während ein Bildschirm offen ist, `SIGPIPE` ignorieren (`signal.Ignore(syscall.SIGPIPE)` in `openScreen`, Rückgängig in `close`) **oder** `SIGPIPE` in `abortSignals` aufnehmen (dann läuft der Abbruchpfad: Löschen, Terminal wiederherstellen, Exit 130) — wähle die Variante, bei der ein Schreibfehler auf stderr nie den Prozess tötet und die Prompts weiter versucht werden (Schreibfehler ignorieren); begründe. Tests: stderr-Leser vor „Seed notiert?“ geschlossen → Seed gelöscht, Terminal wiederhergestellt, kein Tod durch Signal; dasselbe während der Worteingabe von `device lost` (Echo wieder an); Vorlage `TestAttackB13StderrPipeClosed`/`B18`.

## Funde niedrig

2. `/dev/tty` als stdout (oder stdin) gilt nicht als „dasselbe Terminal“ (st_rdev 5:0 vs. pts): Vergleich über das steuernde Terminal (`TIOCGSID`/Sitzung oder `ttyname`-Auflösung von `/dev/tty`) ergänzen; `>/dev/tty` bei `device lost`/`restore` ist dann erlaubt. Test.
3. `readWords` begrenzt die Zahl der Zeilen nicht (Endlosschleife bei endlosen Leerzeilen): Obergrenze (z. B. 64 Zeilen) mit Fehler „zu viele Zeilen“. Test.
4. Hinweis für die Zeremonie: dasselbe SIGPIPE-Verhalten in `cmd/gomail-ceremony` prüfen und im Bericht nennen (nicht hier ändern; eigener Auftrag, falls betroffen).

Fertig: `gofmt -l .` leer, `go vet ./...` (auch `-tags gomail_test`, GOOS darwin/windows für `cmd/gomailctl`), `go test -race -tags gomail_test -timeout 40m ./cmd/gomailctl`, `GOARCH=386 go test ./cmd/gomailctl`, Abdeckung ≥ 85 %, Vektoren byte-gleich. Ein Commit `gomailctl: SIGPIPE never bypasses the screen, /dev/tty counts as the same terminal, bounded word lines (task 13c)`; kein Modellname. Bericht nach `00-vorgaben.md`.
