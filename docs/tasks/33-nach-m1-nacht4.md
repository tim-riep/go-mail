# Auftrag 33: Liste nach M1, vierte Nacht (24./25.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md` (Haltepunkte, Sicherheit der Umgebung, Last). Neu bzw. abweichend gilt:

- **Basis:** der Arbeitsbranch nach Auftrag 32 (Code-Stand c6b2ea2). Je Paket ein eigener Worktree mit `git reset --hard c6b2ea2`. Paket 29B ist nicht zusammengeführt; kein Paket ändert deshalb `internal/client` außer Testdateien, die 29B nicht berührt (`git show 9c6a373 --stat`).
- **Nummern:** aus `docs/tasks/backlog-nach-m1.md` im Stand 8a000de.
- **Commit-Zeile:** `Task: docs/tasks/33-nach-m1-nacht4.md (Paket 33X)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl33<x>/notes.md`.
- **Last:** Keine Echtzeitpriorität (`chrt`, `SCHED_FIFO`/`SCHED_RR`), CPU-Fresser nur kurz und höchstens zwei.
- **Haltepunkte** wie in Auftrag 29; dazu: Eine Meldung von `publish` darf genauer werden, aber keine Prüfung darf etwas annehmen, das sie vorher abgelehnt hat.

## Paket 33A: `publish`, Wortlaut, Kommentare, Tests (Nr. 118, Hinweise aus Nr. 95). Sicherheitskritisch.

1. **Nr. 118:**
   - Prüfe am Code, ob `was not replaced` für jeden `*os.LinkError` aus dem Umbenennen von `witnesses.rec` die genauere Meldung ist (H1: `ENOENT`, `ENOTEMPTY`, `EPERM` durch einen fremden Prozess), und für welche Fehler `is unchanged` sicher stimmt. Setze die genauere Fassung um; jede Ablehnung bleibt eine Ablehnung.
   - Berichtige den Doc-Kommentar von `store.ReplaceFileIn` (`internal/store/fsroot.go`): die temporäre Datei wird nur entfernt, wo das möglich ist (`chattr +a`), und „unverändert“ heißt „von dieser Funktion nicht ersetzt“.
   - Eine Test-Hilfe oder Prüfung dafür, dass Tests, die das Limit offener Dateien ändern, es auf den alten Wert zurücksetzen; ein direktes `syscall.Setrlimit` in künftigen Tests soll auffallen (etwa ein Test, der die Testdateien des Pakets nach `Setrlimit` durchsucht).
   - Die nicht umbrochene Kommentarzeile an `replaceFailedErr`.
2. **Hinweise aus Nr. 95:**
   - Die Meldung `opened; nothing written or logged` nennt vorher entfernte Reste `.tmp-*` nicht. Prüfe, ob die Meldung sie nennen kann (fest formuliert, ohne Inhalt), ohne den Ablauf zu ändern; sonst Grund in den Notizen.
   - Die 294 Fälle der Tauschmatrix mit nicht regulärem Anfang am eigenen Haken prüfen nichts mehr (der Haken wird nicht erreicht). Entferne sie oder lass sie etwas prüfen, ohne die übrige Matrix abzuschwächen; nenne die Zahl der Fälle vorher und nachher.
3. **Läufe:** `internal/ceremony` und `internal/store` unter race mit und ohne Tags und unter 386 mit Tags; `cmd/gomail-ceremony` unter race mit Tags; die Fallmatrix und die Tauschtests aus `scratchpad/rev27a2-robust/` (Skript in `scratchpad/impl28a/`) ohne neue Verletzung; Gegenbelege per Mutation.

## Paket 33B: Release-Prüfung (Rest von Nr. 110, Fund D aus Nr. 119)

1. **Nr. 110, Rest:** In `scripts/check-release.sh` zählt bei `grep` und `sort` in der Suche nach Testschaltern nur, ob die Zeile `-end-` ankommt, nicht ihr Status. Prüfe den Status beider Programme (fail closed: ein scheiterndes Hilfsprogramm macht das Programm nicht sauber), ohne einen Produktionsbuild fälschlich abzulehnen. Der Kopf des Skripts beschreibt danach genau, was geprüft wird. `bash -n` und `dash -n`.
2. **Nr. 119, Fund D:** Der Baum von `TestReleaseEnvReadsWalk` bekommt echte Verzeichnisse `_x/`, `.x/`, `testdata/` und `vendor/` mit Go-Dateien, die die Umgebung lesen; erwartet wird das Verhalten wie bei `go build ./...`.
3. **Nr. 119, Import solcher Verzeichnisse:** Ein Verzeichnis mit `_` oder `.` vorn oder namens `testdata`, das Go-Dateien mit einem Tag `gomail_test` oder `gomail_dev` enthält, meldet der Test als Problem (heute gibt es keines; `testdata/gen` hat kein solches Tag und bleibt ohne Problem). Prüfe am heutigen Baum, dass kein Fehlalarm entsteht.
4. **Läufe:** `bash -n`, `dash -n`, gofmt und vet für `internal/e2e` mit und ohne Tags; `TestCheckRelease`, `TestReleaseSwitches`, `TestReleaseSwitchesRootLink`, `TestReleaseEnvReadsWalk` ohne Tags, mit Tags und unter `-race` mit Tags; die Mutanten aus `scratchpad/rev28b2/mut/`, `scratchpad/impl30b/mut/` scheitern weiter; Gegenbelege für die neuen Prüfungen.

## Paket 33C: Test-Hilfen aus Auftrag 30 (Hinweise aus Nr. 121)

1. `TestSeedTypo` fängt jedes ungeprüfte feste Ersatzwort, nicht nur „abandon“ (ein Mutant mit „zoo“ überlebt heute).
2. `TestSwapWords` prüft auch einen Tausch an anderer Stelle (ein ungeprüfter Tausch mit dem letzten Wort überlebt heute).
3. Die Kopien von `swapWords` in `cmd/gomail-ceremony` und `cmd/gomailctl` bekommen je einen eigenen kleinen Test, oder ein Test stellt sicher, dass alle drei Kopien gleich sind.
4. `internal/shamir` bleibt unverändert (Phase 0).
5. **Läufe:** gofmt, vet mit und ohne Tags; die geänderten Tests unter `-race` mit Tags und 386 mit Tags (`internal/client` nur mit `-run`); Gegenbelege per Mutation.

## Paket 33D: Laufzeit der Testsuite (Nr. 27), nur Messung und Vorschlag

1. Miss die Laufzeit je Test (`go test -json` oder `-v`) für `internal/client` unter `-race` mit Tags (ein Lauf, `-timeout 90m`), für `cmd/gomail-ceremony` und `cmd/gomailctl` unter `-race` mit Tags.
2. Nenne die 25 langsamsten Tests je Paket mit Zeit und Ursache (am Code: feste Wartezeiten, große Daten, Kryptografie, Prozesse, PTY).
3. Schlage für die größten Posten Abhilfen vor, die keinen Test abschwächen: `t.Parallel` dort, wo der Test nichts Gemeinsames ändert (prüfe `t.Setenv`, Paketvariablen, Haken, Arbeitsverzeichnis), kleinere Daten mit gleicher Aussage, geteilte Vorbereitung. Schätze die Ersparnis.
4. **Kein Code.** Ergebnis ist ein Bericht in den Notizen mit Tabellen. Die Umsetzung kommt in einen späteren Auftrag.

## Fertig

Wie Auftrag 24: Läufe, Gegenbelege per Mutation, genau ein Commit auf c6b2ea2 je Paket (33D ohne Commit), Notizen. Der Bericht nennt außerdem Vorschläge für den Doku-Nachzug.

## Nacharbeit 33B2 (zweite Runde)

Ausgangspunkt ist 48e8378 (33B). Ergebnis ist genau ein Commit auf c6b2ea2, der 33B insgesamt enthält. Quelle: Prüfung 33B (`scratchpad/rev33b/notes.md`, 20-notes „33B“).

1. **F1 (niedrig):** Ein Verzeichnis, das während des Durchlaufs verschwindet (`fs.ErrNotExist` unterhalb der durchsuchten Wurzel, etwa ein Worktree, der gerade gelöscht wird), lässt `TestReleaseSwitches` nicht mehr scheitern; die Wurzel selbst bleibt ein Fehler. Ein Verzeichnis ohne `go.mod`, das gerade entsteht oder verschwindet, darf keinen falschen Treffer ergeben; prüfe, ob `.git` gezielt übersprungen werden kann (keine Go-Pakete darin) und ob `.claude/worktrees` als eigene Module sicher erkannt werden. Kein Fall darf still wegfallen, den `go build` übersetzen würde. Beleg mit dem Wettlauf aus `scratchpad/rev33b/churn.log` (Skript im selben Ordner).
2. **H1:** Kopf von `check-release.sh`: der Satz zu `-end-` wie in der Prüfung vorgeschlagen.
3. **H2:** Im echten `testdata/`-Ordner des Walk-Baums eine getaggte Datei, die die Umgebung liest (`GOMAIL_TEST_TESTDATA`); erwartet: ein Problem, der Name wird nicht gelesen.
4. **H3:** Den Fehlerweg von `skippedTagged` testen, falls ohne root-Tricks möglich (sonst Grund in den Notizen); die tote Bedingung `name != "testdata"` entfernen, wenn sie wirklich unerreichbar ist.
5. **Läufe** wie in Paket 33B, dazu der Wettlauf aus Punkt 1 (mindestens 150 Läufe, kein FAIL).

# Auftrag 34: `publish`, Prüfung nach dem Umbenennen (24./25.11.2026)

Es gelten Kopf und Regeln von Auftrag 33 oben. Commit-Zeile `Task: docs/tasks/33-nach-m1-nacht4.md (Paket 34A)`; Notizen `scratchpad/impl34a/notes.md`.

## Paket 34A. Sicherheitskritisch.

- **Basis:** 8d557b0 (Endstand von 33A; `git reset --hard 8d557b0`). Ergebnis: genau ein Commit auf 8d557b0.
- **Fund (Prüfer 2 von 33A, H1, vorbestehend):** Ersetzt ein fremder Prozess die temporäre Datei von `store.ReplaceFileIn` durch ein Verzeichnis, während `witnesses.rec` gerade fehlt (oder ein leeres Verzeichnis ist), gelingt `renameat`. `publish` meldet dann Erfolg (`WitnessesReplaced`/`WitnessesLinkReplaced`), obwohl unter dem Namen ein Verzeichnis liegt. Beleg und Test: `scratchpad/rev33a-robust/` (`real2-*.log`, `t/rev33ar_real_linux_test.go`).
1. **Abhilfe:** Nach dem Umbenennen prüfen `store.ReplaceFileIn`, `store.WriteFileAtomicIn` und `store.CreateFileAtomicIn` mit `Lstat` über die Root, dass der Name eine reguläre Datei mit Gerät und Inode der temporären Datei ist (`fstat` am Deskriptor vor dem Schließen). Sonst liefern sie einen eigenen Fehler (Sentinel, etwa `store.ErrReplacedMeanwhile`), und `publish` meldet ihn mit Pfad und Abhilfe, fest formuliert, ohne Inhalt; für `witnesses.rec` mit der Fassung „was not replaced“ bzw. einer gleich genauen. Nichts wird danach geloggt. Prüfe alle Aufrufer der drei Funktionen (`grep`), auch außerhalb von `internal/ceremony`, und dass sich für sie nur zusätzliche Ablehnungen ergeben.
2. **Restfenster** zwischen Umbenennen und `Lstat` im Kommentar nennen.
3. **Tests:** der Wettlauf aus `rev33ar_real_linux_test.go` (Temp durch Verzeichnis ersetzt, Name fehlt bzw. leeres Verzeichnis) über den Haken des Pakets reproduzierbar; erwartet Ablehnung, nichts geloggt, kein Rückruf „replaced“. Dazu je ein Test für `WriteFileAtomicIn` und `CreateFileAtomicIn`.
4. **Läufe:** `internal/store` und `internal/ceremony` unter race mit und ohne Tags und unter 386 mit Tags; `cmd/gomail-ceremony` unter race mit Tags; alle übrigen Aufrufer der drei Funktionen mit ihren Paketen unter race mit Tags; die Matrix aus `scratchpad/impl33a/` (Skript `matrix.sh`) ohne neue Verletzung und ohne Übergang von Ablehnung zu Annahme; Gegenbelege per Mutation.

# Auftrag 35: `TestRelayBrokenPipe` unter `go test -json` (24./25.11.2026)

Es gelten Kopf und Regeln von Auftrag 33 oben. Commit-Zeile `Task: docs/tasks/33-nach-m1-nacht4.md (Paket 35A)`; Notizen `scratchpad/impl35a/notes.md`. Nur Testcode.

## Paket 35A

- **Basis:** c6b2ea2. Ergebnis: genau ein Commit darauf.
- **Fehler (Messung 33D):** `TestRelayBrokenPipe` (`cmd/gomailctl/pty13d_linux_test.go`) scheitert immer unter `go test -json`: Mit `-test.v=test2json` setzt `testing` `os.Stderr = os.Stdout`; der Test legt die Pipe ohne Leser auf Deskriptor 2, schreibt aber über `os.Stderr` (jetzt Deskriptor 1), und das Schreiben gelingt. Mit `-v` und ohne `-v` ist er grün.
1. **Abhilfe:** Der Test schreibt über eine eigene Datei für Deskriptor 2 (etwa `os.NewFile(2, …)`) oder prüft genau das, was das Programm tut (`relayBrokenPipe` und die Schreibstelle im Programm am Code ansehen); er bleibt so streng wie vorher (`EPIPE` statt Abbruch durch SIGPIPE). Prüfe alle Tests des Moduls auf dasselbe Muster (`os.Stderr`/`os.Stdout` nach einem `Dup2`/`Dup3` auf 1 oder 2) und behebe sie gleich.
2. **Läufe:** gofmt, vet mit und ohne Tags; die geänderten Tests ohne `-v`, mit `-v` und mit `-json`, je unter `-race` mit Tags und 386 mit Tags; Gegenbeleg per Mutation (etwa `relayBrokenPipe` entfernt).
