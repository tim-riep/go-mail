# Auftrag 20b: Kleine Nacharbeiten nach dem Merge der Linie 09b (gesammelte Funde niedrig vor der Abnahme)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 3e06f23 (Linie 09b zusammengeführt, D91), in einem eigenen Worktree.
- Darf ändern: `internal/client/**`, `internal/store/**` (nicht `records.go`-Schemata), `internal/translog/**` (nur die genannten Stellen und Kommentare), `internal/ceremony/**` (nur die genannten Stellen), `cmd/gomailctl/**`, Testdateien in `internal/bench` und `internal/e2e`.
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients, Phase-0-Vektoren (`internal/{rec,keys,shamir,envelope}/testdata`). Berührt ein Punkt eines davon, beschreibe ihn im Bericht und baue ihn nicht.
- Jeder Punkt ist klein. Verlangt ein Punkt mehr, als hier steht, beschreibe ihn im Bericht, statt ihn auszubauen.
- Quelle der Punkte: `docs/tasks/20-notes.md` (Abschnitte in Klammern).

## Produktivcode

1. **`keygen` atomar** (Nach 14b-Merge): `internal/client/keygen.go` schreibt Schlüsselspeicher und `user.rec` vor `state.json`. Ein Signal im Fenster hinterlässt ein halbes Client-Verzeichnis, und `keygen` lehnt danach ab. Lösung: in einem Temp-Verzeichnis neben dem Ziel anlegen, fsync, dann `rename` auf das Ziel und fsync des Elternverzeichnisses. Eine Wiederaufnahme ist keine Lösung. Test: Abbruch nach jedem Schreibschritt (injizierbarer Fehler) hinterlässt entweder nichts oder ein vollständiges Verzeichnis; ein zweites `keygen` gelingt danach.
2. **`TODO(task-13)` in `internal/client/keygen.go` (ShowShares):** auflösen, ohne die Schnittstelle von `gomailctl` zu ändern. Gehört `ShowShares` zu `Prompter`, verschiebe es; sonst den TODO durch einen Kommentar ersetzen, der begründet, warum es getrennt bleibt.
3. **Client-Log** (Aus 14b-Spezifikation, Aus 14b-Angreifer):
   - doppelter `epochLogged`-Aufruf in `loadChain` (Append zweimal unter `log/lock`): auf einen Aufruf zurückführen.
   - `warnContradicts` auch am Kopf (`n == head`, `errEpochContradicts`): nur der Meldungstext, kein neuer Fehler, keine neue Prüfregel.
   - `doc.go` Schritt 4 „beyond the head“ präzisieren, so dass er beschreibt, was der Code tut.
4. **`store.ListIndexSegments`** (Aus 09c): liest das ganze Verzeichnis vor der Grenze. Auf `ReadDir(n)` mit der bestehenden Grenze umstellen; das Verhalten unter, an und über der Grenze bleibt unverändert (Test dazu, falls keiner besteht).
5. **R41-Stellen ohne `O_NONBLOCK`** (Aus der Angreiferprüfung von 20a, Aus 18c, Aus der Spezifikationsprüfung von 20a):
   - `internal/ceremony/publish.go` `readExport` öffnet `<from>/platform` mit `os.Open` ohne Prüfung;
   - `internal/ceremony/files.go:109`;
   - `internal/translog/operator.go` (die `os.Open`-Stellen um Zeile 341, 776 und 810; Verzeichnisse und `syncFile`).
   Wo eine Datei gelesen wird: öffnen nach Art von `store.ReadFileLimited` (`O_NONBLOCK`, danach fstat, nur reguläre Dateien). Wo ein Verzeichnis für fsync geöffnet wird: `O_DIRECTORY|O_NONBLOCK`, ein FIFO ergibt einen Fehler. Tests: FIFO an der jeweiligen Stelle ergibt einen Fehler über `errors.Is` statt eines Hängers.
6. **Veraltete Kommentare:** `internal/translog/translog.go:43` („Warning is printed … with Unverified“), `internal/translog/doc.go:1173` („only --insecure-no-log … until task 15“). Beschreiben, was der Code tut.
7. **`internal/client/index.go`** (Aus den Prüfungen von 09g): P3-f kommentieren; das Wachstum je Epoche aus D91 ausdrücklich nennen (etwa 270 B · D · k je Sync und angegriffener Epoche, sobald (D − 1) · k ≥ 16; ein Gerät 300 B · k), mit Verweis auf D91.

## Tests (nur Testcode)

8. **Client** (Aus 14b-Spezifikation, Aus den Prüfungen von 09g):
   - Test für das Absenkverbot von `commitHead` (über `export_test.go`); die Mutation „Absenken erlaubt“ muss brechen.
   - Einsparregel für Ergebnisse ab 32 Segmenten (Ergebnis aus zwei und mehr Segmenten, Schwelle `counted − written ≥ MergeThreshold − 1`): je ein Test knapp unter und auf der Schwelle.
   - Belegtests der Spezifikationsprüfung von 09f übernehmen, soweit `takeover09g_test.go` sie nicht schon abdeckt. Quelle: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify09g-spec/src2/internal/client/zz_v09f_spec_test.go` (an den Stand von 09g angepasst). Eigene Datei mit sprechendem Namen, kein Präfix `zz_`. Welche übernommen und welche als abgedeckt weggelassen wurden, steht im Bericht.
9. **`gomailctl`** (Aus der Spezifikationsprüfung von 20a):
   - `TestPtyRestoreStderrClosed`: erst auf `inputQueued > 0` warten oder über `quiet` mit Echo; keine feste Wartezeit.
   - Test `terminalID(slave).dev == Stat(slave).Dev`.
10. **`internal/e2e/twohost_test.go` `wordRun`** (Aus der Spezifikationsprüfung von 20a): Trenner beliebiger Länge aus Leerraum, damit ein eingerückter Seed gefunden wird. Die Erkennung darf nicht schwächer werden.

## Fertig

- gofmt, `go vet ./...` und `go vet -tags gomail_dev,gomail_test ./...` sauber; `GOOS=openbsd go vet ./...` sauber.
- `go test -race` mit und ohne `-tags gomail_dev,gomail_test` für jedes geänderte Paket grün, `internal/e2e` mit Tags (`GOMAIL_TEST_MIN_FREE` setzt der Test selbst); 386 mit Tags für jedes geänderte Paket außer `internal/e2e`. `internal/client` dauert unter race etwa 20–33 Minuten.
- Abdeckung je geändertem Paket nicht gesunken; `internal/client` ≥ 85 %.
- Phase-0-Vektoren unverändert: `git diff --stat 38626a9 -- internal/{rec,keys,shamir,envelope}/testdata` leer.
- Ein Commit mit `Task: docs/tasks/20b-small-fixes.md`, ohne Co-Authored-By.
- Der Container startet etwa stündlich neu. Committe nach jedem fertigen Punkt einen WIP-Stand im Worktree und halte in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20b/notes.md` fest, was fertig ist und was noch läuft. Am Ende werden die WIP-Commits zu einem zusammengefasst.
- Bericht: je Punkt erledigt oder nicht, mit Begründung; Läufe mit Ergebnis; Abdeckung vorher und nachher.
