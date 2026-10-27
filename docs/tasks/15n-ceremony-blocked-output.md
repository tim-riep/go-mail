# Auftrag 15n: Zeremonie – Schreibfehler und gestoppte Ausgabe im normalen Pfad, Doppel-Enter (Funde der Angreifer-Prüfung von 15m)

Welle 4. Sicherheitskritisch (Terminalregeln, M1-Kriterium C). **Dritte Nacharbeitsrunde dieser Linie** (15l, 15m, 15n). Bleiben danach Funde offen, greift Haltepunkt 3. Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Branch `worktree-agent-a681705c39aec1e96`, Worktree `/home/user/go-mail/.claude/worktrees/agent-a681705c39aec1e96` (Stand 1826d21; zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`). Die Aufträge 15i, 15l und 15m bleiben gültig, ebenso ihre Tests. Lies `cmd/gomail-ceremony/main.go` (Terminalteil vollständig: `prompt`, `promptLost`, `settle`, `Handover`, `flushInput`, `scrubInput`, `clear`, `wipe`, `clearBounded`, `clearOut`, `clearErr`, `bounded`, `abort`, `abortClock`, `wakeOutput`), dazu `tty_unix.go`, `tty_linux.go` und `tty_bsd.go`. Angriffscode und Protokolle des Prüfers liegen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify15m/`: `attack/nonblock.py`, `attack/errstop.py`, `attack/hold.py` mit `bin/tcooffloop` aus `attack/tcooffloop.c`, `attack/dblenter.py`, `attack/multi.py` und `logs/`.

## Fund 1 (hoch): Ein Clear mit Schreibfehler gilt als erledigt

Teilt ein anderer Prozess die offene Dateibeschreibung von stdout, kann er nach dem Start `O_NONBLOCK` setzen (Hintergrundjob derselben Shell). Nimmt das Terminal dann nichts an, endet der Clear sofort mit `EAGAIN`. `clearOut` und `clearErr` verwerfen den Fehler, und `bounded` meldet „fertig“. Es folgt weder Verwerfen noch Wiederanlauf noch ein zweiter Versuch. Der Anteil bleibt stehen, auch bei Exit 130. Im normalen Pfad ruft `wipe` danach Inhaber 2 auf, obwohl Anteil 1 noch sichtbar ist.

Umsetzen:
- `clearOut` und `clearErr` geben jeden Schreibfehler zurück, auch einen teilweisen Schreibvorgang.
- **Abbruchpfad:** Jeder Fehler zählt wie eine Zeitüberschreitung. Danach wird ausstehende Ausgabe verworfen, die Ausgabe neu gestartet und erneut geschrieben, innerhalb von `abortTotal`. Bei `EAGAIN` wird wiederholt, bis die Frist abläuft.
- **`O_NONBLOCK`:** Vor jedem Clear und jeder Anteilsausgabe wird das Flag mit `F_GETFL`/`F_SETFL` auf stdout und stderr gelöscht, wenn es gesetzt ist. Das wirkt auf die gemeinsame Dateibeschreibung. Begründe im Kommentar, warum das zulässig ist.
- **Normaler Pfad:** Vor dem Commit führen ein fehlgeschlagener Clear und ein Fehler von `display.Write` (Anteilsausgabe) wie `promptLost` in den Abbruchpfad. Inhaber 2 wird nie aufgerufen, solange der Clear von Anteil 1 nicht vollständig geschrieben ist.
- Ein teilweise geschriebener Anteil gilt als gezeigt, er muss also gelöscht werden.

## Fund 2 (hoch): Im normalen Pfad bleibt die Zeremonie mit sichtbarem Anteil hängen

(a) Ein `TCOOFF` oder ein voller Puffer auf dem stderr-Terminal, während ein Anteil auf stdout steht, hält `Anteil notiert?` dauerhaft in `write(2)` fest. Auf der Linux-Konsole genügt Scroll Lock. (b) Ein wiederholtes `TCOOFF` auf stdout gewinnt das Rennen zwischen Wiederanlauf und Clear. Danach hängt der normale Pfad mit sichtbarem Anteil, auch nachdem die Schleife endet.

Umsetzen:
- Solange ein Anteil sichtbar ist, gilt für jede Eingabeaufforderung und jeden Clear dieselbe Regel: Ausgabe des Ziel-Terminals neu starten, dann schreiben, alles zeitlich begrenzt. Hängt der Schreibvorgang, wird der Wiederanlauf bis zur Frist wiederholt.
- Die Frist ist eine Konstante, vorgeschlagen sind 2 s. Begründe den Wert im Kommentar.
- Kommt die Aufforderung innerhalb der Frist nicht durch, wird zuerst stdout gelöscht (mit der Regel aus Fund 1). Danach geht es in den Abbruchpfad, Exit 130.
- Kommt der Clear nicht durch, geht es ebenfalls in den Abbruchpfad. Der Abbruchpfad löscht dort mit Verwerfen.
- Nie bleibt die Zeremonie länger als Frist plus Abbruchdauer mit sichtbarem Anteil stehen.
- Die Restgrenze aus 15m bleibt dokumentiert: Ein Terminal, das nie wieder etwas annimmt, zeigt den Clear nie. Nach Exit 130 gibt es keine Wiederholung mehr.
- Wiederholtes `TCOOFF` durch einen Angreifer mit Zugriff auf das Terminal endet so in Exit 130 statt in einem Hänger.

## Fund 3 (hoch in der Wirkung, vorbestehend): Ein Doppel-Enter mit Abstand bestätigt für den nächsten Inhaber

Kommt das zweite Enter nach dem Verwerfen der Eingabe an, beantwortet es die Aufforderung für Inhaber 2. Bei einem menschlichen Doppeldruck liegen mehr als 0,2 ms zwischen beiden. Anteil 2 erscheint dann, während Inhaber 1 noch vor dem Bildschirm sitzt. `TestPTYDoubleEnter` prüft nur `"\n\n"` in einem einzigen Schreibvorgang.

Umsetzen:
- Eine Eingabe gilt erst als Bestätigung, wenn sie mindestens `confirmDelay` nach der vollständig geschriebenen Aufforderung eintrifft. Vorgeschlagen sind 1 s.
- Alles, was vorher eingetroffen ist, wird verworfen: nach der Wartezeit erneut `flushInput` mit nicht wartendem Aufruf aus 15m, dann `scrubInput`, dann lesen.
- Trifft während der Wartezeit Eingabe ein, wird die Aufforderung einmal wiederholt, mit dem Hinweis „Eingabe zu früh, bitte erneut bestätigen“. Der Hinweis zeigt keinen Anteil.
- Das gilt für jede Aufforderung, die einen Anteil zeigt oder einen Inhaberwechsel bestätigt.
- Keine Änderung an Dateiformaten, Datensätzen oder Signaturen. Die Anteilsnummer eintippen zu lassen ist nicht verlangt.
- Der Paketkommentar wird richtiggestellt: Ein Doppel-Enter beantwortet die nächste Aufforderung nicht, auch mit Abstand bis `confirmDelay`.

## Tests

Pseudoterminal-Tests, Vorlage sind die 15m-Tests. Die Python-Angriffe werden in Go nachgebaut.

- **Fund 1:**
  - `O_NONBLOCK` auf der gemeinsamen Beschreibung von stdout mit vollem Puffer, für die Belegungen ABA, AAA und ABC.
  - Bei SIGINT: Exit 130, und nach erneutem Lesen ist der Anteil gelöscht.
  - Bei Enter: Inhaber 2 wird nicht aufgerufen, Exit 130 und Anteil gelöscht.
  - Teilweiser Schreibvorgang einer Anteilszeile: Ergebnis gelöscht.
- **Fund 2:**
  - (a) stderr gestoppt oder voll während einer Aufforderung mit sichtbarem Anteil: nach höchstens Frist plus Abbruchdauer ist der Anteil gelöscht, Exit 130.
  - (b) `TCOOFF`-Schleife auf stdout im normalen Pfad, 20 Läufe: kein Lauf hängt länger als Frist plus Abbruchdauer mit sichtbarem Anteil. Stehen bleibt höchstens die dokumentierte Restgrenze, solange die Schleife läuft. Nach Ende der Schleife ist der Anteil gelöscht.
- **Fund 3:** Doppel-Enter mit Abstand 0,2 ms, 1 ms, 50 ms und 500 ms. Anteil 2 erscheint nicht, die Aufforderung wird wiederholt. Eine Bestätigung nach `confirmDelay` funktioniert.
- **Gegenprobe:** Jeder neue Test ist auf 1826d21 rot. Steht im Bericht.
- **Regression:** alle Tests aus 15b, 15f, 15g, 15i, 15l und 15m, insbesondere `TestPTYAbortBlockedOutput`, `TestAbortBounded`, `TestPTYSignalSalvo`, `TestPTYTwoTerminals`, `TestPTYThreeTerminals`, `TestPTYStderrUnwritable`, `TestPTYNoReaderBeforeTerm`, `TestPTYDoubleEnter` und `TestPTY`. `confirmDelay` verlängert die PTY-Tests. Halte die Gesamtdauer von `cmd/gomail-ceremony` unter `-race` unter 10 Minuten. Dafür ist ein Test-Hook erlaubt, der die Wartezeit im Test verkürzt, aber nie auf 0 setzt.
- **Pflichtfall bei echter Wartezeit:** Mindestens ein Test läuft mit der echten Wartezeit.

## Fertig

- `gofmt -l .` ist leer.
- `go vet ./...` ist sauber, mit und ohne `-tags gomail_dev,gomail_test`, für `cmd/gomail-ceremony` unter GOOS freebsd, openbsd, netbsd, darwin und dragonfly.
- `go test -race ./cmd/gomail-ceremony ./internal/ceremony` ist grün, mit und ohne `-tags gomail_dev`. Die neuen PTY-Tests werden zusätzlich allein mit `-count=5` wiederholt.
- `GOARCH=386 go test ./cmd/gomail-ceremony` ist grün.
- Die Vektoren sind byte-gleich.
- Ein Commit `gomail-ceremony: write errors and stopped output in the normal path, confirmation delay (task 15n)`, ohne Modellnamen.
- Bericht nach `00-vorgaben.md`: je Fund die Änderung, der Testname und die Gegenprobe. Dazu Vorschläge für DECISIONS und den Satz für das RUNBOOK zu `confirmDelay`.
