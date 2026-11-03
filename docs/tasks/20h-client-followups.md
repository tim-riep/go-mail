# Auftrag 20h: Gerätewechsel-Test, Panik nach `Close`, genauere testenv-Prüfungen

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` nach dem Merge von 20e (der Orchestrator nennt den Commit), in einem eigenen Worktree.
- Darf ändern: `internal/client/**`, Testdateien in `internal/testenv`.
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren.
- Quelle: `docs/tasks/20-mandatory-tests.md` (F-1), `docs/tasks/20-notes.md` Abschnitte „Aus 20g“ und „Aus 20f und seiner Prüfung“.

## Umfang

1. **F-1, Gerätewechsel mit Übernahme der Indexsegmente (10.1 Szenario Z3 ohne Volltext):** neuer Test `internal/client/devicechange_test.go` nach der Beschreibung F-1 in `docs/tasks/20-mandatory-tests.md` (Prüfungen a bis c und die Mutation „`readSegments` übergeht Segmente anderer Geräte“, die brechen muss). Danach Zeile Z3 in `docs/tasks/20-mandatory-tests.md` nachführen (diese Datei darf zusätzlich geändert werden).
2. **Keine Panik nach `Close`:** `CreateMailbox` nach `Close` panikt (nil-Dereferenz in `prepareMailbox`, `internal/client/mailbox.go`). Jede öffentliche Methode von `*Client` liefert nach `Close` einen Fehler, prüfbar über `errors.Is` mit einem festen Fehlerwert (vorhanden oder neu, z. B. `ErrClosed`), statt zu paniken. Ein Test ruft jede öffentliche Methode nach `Close` auf (per Reflexion oder Liste, die ein zweiter Test gegen die Methodenmenge abgleicht).
3. **testenv-Fehlerpfade genauer prüfen:** In `internal/testenv/dev_test.go` prüft jeder `fatalOn`/`expectFatal`-Fall einen Teiltext der erwarteten Meldung, nicht nur, dass Fatal kam.
4. **Kommentar an `testenv.ImmediateEpoch`** ist Produktivcode von `testenv`; nicht ändern, sondern im Bericht nennen, ob der beschriebene Fall erreichbar ist.

## Fertig

- gofmt, `go vet` mit und ohne Tags, `GOOS=openbsd go vet ./...` sauber; `internal/client` und `internal/testenv` unter race mit Tags und 386 mit Tags grün (`-timeout 60m`); Abdeckung nicht gesunken.
- Ein Commit mit `Task: docs/tasks/20h-client-followups.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20h/notes.md`; fortsetzbarer Läufer für die Schlussläufe.
- Bericht: je Punkt erledigt oder nicht; Läufe; Abdeckung vorher und nachher; Liste der Methoden, die vorher nach `Close` panikten.
