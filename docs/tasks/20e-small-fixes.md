# Auftrag 20e: Letzte kleine Nacharbeiten im Produktivcode vor der Abnahme (Funde niedrig aus 20b, 20c)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei ce24857 oder später, dazu der geprüfte Stand von 20b: `git merge worktree-agent-a1eb92777f183eed4` (Commit cb2344c) in den eigenen Worktree. 20b wird parallel zusammengeführt; der Code ist derselbe.
- Darf ändern: `internal/client/**`, `internal/store/**` (nicht `records.go`-Schemata), `internal/translog/files.go` und dessen Tests.
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren.
- Quelle: `docs/tasks/20-notes.md`, Abschnitte „Aus 20b (Implementierer, außerhalb des Auftrags)“, „Aus der Spezifikationsprüfung von 20b“, „Aus der Angreiferprüfung von 20b“; `docs/tasks/20-triage.md` P-2.

## Produktivcode

1. **Vermerk für eigene neue Segmente (P-2):** `writeSegmentList` (`internal/client/index.go`) legt für jedes geschriebene eigene Segment vor `c.save()` einen Prüfvermerk an, wie `noteResult` für Teile. Den Kommentar an `missingOwnFiles` (`devicelost.go`) anpassen. Test: Segment schreiben, ohne es zu lesen, es verbergen, `device lost`, Segment zurücklegen, `Search` übernimmt es. Prüfe, ob D91 (6) (kein Pfad entfernt Einträge aus `Checked`) und die Wachstumsgrenze aus D91 unverändert bleiben, und nenne das zusätzliche Wachstum je Indexlauf im Bericht.
2. **`client.Restore` atomar** (`restore.go`), nach demselben Muster wie `createClientDir` aus 20b. Tests wie `TestKeygenAtomic`.
3. **Liegengebliebene Temp-Verzeichnisse:** Ein erfolgreiches `keygen` oder `restore` entfernt `.<name>.keygen-*` (bzw. das eigene Muster von `restore`) neben seinem Ziel, die älter als der eigene Lauf sind und dem eigenen Benutzer gehören; nur Verzeichnisse, keine Symlinks folgen. Test.
4. **`keygen` gegen gleichzeitiges `Open` (L1):** Bei `ENOTEMPTY` nach `lockOnlyDir` einmal wiederholen; danach Meldung „nicht leer oder in Benutzung durch einen anderen Client“ über `store.ErrExists`. `lockOnlyDir` öffnet das Verzeichnis mit `store.OpenDir`; Kommentar, dass der Inhalt von `lock` nicht geprüft wird (L2).
5. **`newestHeadSize`** (`internal/translog/files.go`) öffnet `heads/` mit `store.OpenDir`; `fs.ErrNotExist` bleibt wie bisher. FIFO-Test.
6. **Kommentare:** `ListIndexSegments` über der Grenze (Teilmenge in Verzeichnisreihenfolge; Folge für `writeSegmentList`, fail closed); `createClientDir`: ein Einhängepunkt als Ziel scheitert mit `EBUSY`/`EXDEV`.

## Fertig

- Wie `docs/tasks/20b-small-fixes.md` Abschnitt „Fertig“ (gofmt, vet einschließlich `GOOS=openbsd`, race mit und ohne Tags je geändertem Paket, e2e mit Tags, 386 mit Tags, Abdeckung nicht gesunken, `internal/client` ≥ 85 %, Vektoren unverändert, ein Commit mit `Task: docs/tasks/20e-small-fixes.md`, WIP-Commits und Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20e/notes.md`).
- Bericht: je Punkt erledigt oder nicht, mit Begründung; Läufe; Abdeckung vorher und nachher.
