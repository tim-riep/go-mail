# Auftrag 20g: Abdeckung von `internal/testenv`, Berichtigungen am Schematest (nur Testcode)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei aa79032 oder später, in einem eigenen Worktree.
- Darf ändern: neue oder geänderte Testdateien (`_test.go`) in `internal/testenv`, `internal/translog/translogtest` und `internal/rec/allschemas_test.go`. Kein Produktivcode, auch nicht in `testenv` (es gilt hier als Produktivcode des Pakets). Phase-0-Vektoren unverändert.
- Quelle: `docs/tasks/20-notes.md` Abschnitt „Aus 20f und seiner Prüfung“; `docs/tasks/20-mandatory-tests.md` (Abdeckungstabelle).

## Umfang

1. **`internal/testenv`** hat 0 % Abdeckung. M1-Kriterium E verlangt ≥ 85 % für jedes Paket unter `internal/`; das wird nicht gelockert. Schreibe Tests im Paket selbst (Build-Tag wie das Paket, `gomail_dev`), die jede exportierte Funktion und die Fehlerpfade prüfen, die ohne Eingriff in Produktivcode erreichbar sind. Ziel ≥ 85 % mit `go test -cover -tags gomail_dev,gomail_test ./internal/testenv`. Ist ein Pfad nur über einen Eingriff erreichbar, nenne ihn mit Zeile im Bericht.
2. **`internal/translog/translogtest`**: Abdeckung messen; liegt sie unter 85 %, ebenso ergänzen.
3. **`internal/rec/allschemas_test.go`** (Prüfung von 20f, niedrig):
   - `TestAllSchemasListed` sucht Schemadefinitionen mit `go/parser` und `ast.Inspect` statt per Regex: Aufrufe von `MustSchema`/`NewSchema` auf dem Import von `internal/rec` unter jedem Namen, dazu `rec.Schema`-Literale mit `Type`; Kommentare zählen nicht. Dateien mit Build-Tags werden mit ihren Tags berücksichtigt (eine Definition, die nur mit `gomail_dev` gebaut wird, darf der ungetaggte Test nicht verlangen). Nachweis durch Mutationen in einer Scratch-Kopie: Struct-Literal, Aliasimport und auskommentierter Aufruf.
   - `TestTypedRoundTripOutsideStore` entfernen (doppelt `translog.TestEntryKeysAndRoundTrip`, `witness.TestWitnessesRecord`, `store.TestRecoveryPubRoundTrip`) oder Kommentar und Umfang berichtigen; Entscheidung im Bericht begründen.
   - Kommentar zur Variante „alle Felder“: „bis 300 Byte bzw. höchstens `MaxLen`“ statt „Höchstlänge“.
   - Danach `docs/tasks/20-mandatory-tests.md` Zeile K1 und Abdeckungstabelle nachführen (diese Datei darf zusätzlich geändert werden).

## Fertig

- gofmt, `go vet` mit und ohne Tags sauber; geänderte Pakete unter race und 386 grün (mit Tags, wo nötig).
- Ein Commit mit `Task: docs/tasks/20g-test-gaps.md`, ohne Co-Authored-By. Nicht pushen. WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20g/notes.md`.
- Bericht: Abdeckung vorher und nachher je Paket; Mutationen mit Ergebnis; nicht erreichbare Pfade.
