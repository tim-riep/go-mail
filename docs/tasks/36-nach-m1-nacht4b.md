# Auftrag 36: Reste aus 34A und 33B (25.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“), der Kopf von `docs/tasks/29-nach-m1-nacht3.md` und der Kopf von `docs/tasks/33-nach-m1-nacht4.md` (keine Echtzeitpriorität; Patch jedes Endstands nach `scratchpad/patches/`). Commit-Zeile `Task: docs/tasks/36-nach-m1-nacht4b.md (Paket 36X)`; Notizen `scratchpad/impl36<x>/notes.md`.

## Paket 36A: `store`, Reste aus 34A (Nr. 127) und Untersuchung Nr. 128. Sicherheitskritisch.

- **Basis:** c8cda58 (= 526cb21 mit 34A, Branch `orch/n34`; Patch `docs/tasks/patches/34a-656b2c3.patch`). Ergebnis: ein Commit darauf.
1. **Fenster 2 schließen:** Vor dem Entfernen benennt `store` den Temp-Namen auf einen neuen eigenen Namen um (über die Root), prüft dort per `Lstat`/`SameFile`, und entfernt nur die eigene Datei; ein fremder Eintrag wird dabei höchstens umbenannt, nie entfernt (Vorschlag Prüfer 2 von 34A). Prüfe, ob das ein neues Fenster öffnet, und beschreibe es.
2. **EISDIR nach dem Link** bei `CreateFileAtomicIn` wie ENOENT auf `ErrReplacedMeanwhile` abbilden (N1 Prüfer 2).
3. **Tests:** Fehlerweg von `writeTempIn` mit Tausch und erzwungenem Fehler (Mutant „Temp-Name im Fehlerweg bedingungslos entfernt“ muss scheitern); `FD_CLOEXEC` des Duplikats (Vorlage `scratchpad/rev34a-spec/zz_rev_cloexec_linux_test.go`); der ENOENT-Zweig nach dem Link; Kommentar „a directory never“ auf Linux/AIX einschränken.
4. **Nr. 128, nur Untersuchung, kein Code:** Für `WriteFileAtomic`, `CreateFileAtomic` (Pfad-Varianten) und `WritePrivateFileAtomicIn`: Liste aller Aufrufer; je Aufrufer, ob zwei rechtmäßige Schreiber (Server, Ingest, Clients, mehrere Geräte) dieselbe Datei gleichzeitig schreiben können und welche Sperre das verhindert; was eine Prüfung nach dem Umbenennen dort ändern würde (neue Ablehnungen bei rechtmäßiger Nebenläufigkeit wären eine Verhaltensänderung). Ergebnis als Tabelle in den Notizen.
5. **Läufe:** `internal/store` und `internal/ceremony` unter race mit und ohne Tags und 386 mit Tags; `cmd/gomail-ceremony` unter race mit Tags; eigene Wettläufe wie in 34A (alt c8cda58 gegen neu): fremde Einträge, die `store` entfernt, sollen 0 sein; Gegenbelege.

## Paket 36B: Release-Test, N1 aus 33B2 (Nr. 125)

- **Basis:** 526cb21. Nur Testcode in `internal/e2e`.
1. **FIXB:** Ein echtes Verzeichnis `_*`, `.*` oder `testdata` geht direkt an `skippedTagged`, `os.Stat` nur noch für Links; bei `fs.ErrNotExist` `filepath.SkipDir`. Ein Ordner mit Pfad über PATH_MAX bleibt ein Fehler (ENAMETOOLONG).
2. **R01:** Test für einen verschwindenden Link `_*` mit einem Geschwister danach (darf nicht übersprungen werden). **R04:** `TestReleaseSettle` vergleicht den ganzen Text eines Problems.
3. **Läufe:** wie in 33B (gofmt, vet, die Release-Tests ohne/mit Tags, race, 386, `-count=30`), dazu ein Dauertausch-Test wie in der Prüfung von 33B2 (Ordner `_x` ↔ `_y` per `rename`, 15 s): 0 Durchläufe, die `_x` als Modulordner lesen; Gegenbelege per Mutation.

## Nacharbeit 36A2 (zweite Runde)

Ausgangspunkt ist 558ce2b (Patch `docs/tasks/patches/36a-558ce2b.patch` auf c8cda58). Ergebnis ist genau ein Commit auf c8cda58, der 36A insgesamt enthält. Quellen: 20-notes „36A“ (beide Prüfer), „36g“ (F1), Notizen `scratchpad/rev36a-spec/`, `scratchpad/rev36a-robust/` (mit Harness `t/` und `logs/enospc.log`).

1. **Keine neue Ablehnung auf dem Erfolgsweg (N1 Prüfer 2, F1 36g):** Scheitert das Umbenennen auf `aside` mit etwas anderem als `ENOENT` (etwa `ENOSPC`, `EPERM` bei `chattr +a`), fällt `dropTemp` auf den Weg vor 36A zurück: Temp-Name per `Lstat`/`SameFile` prüfen und nur die eigene Datei per unlink entfernen. Nach einem gelungenen, geprüften Link von `CreateFileAtomicIn` meldet die Funktion dann wieder Erfolg, wo c8cda58 Erfolg meldete. Gleiches im Fehlerweg (N2 Prüfer 2: die Temp-Datei bleibt bei `ENOSPC` nicht liegen).
2. **Fenster 2' gegen inotify (H1 Prüfer 2):** Prüfe den Vorschlag, die Datei statt auf einen Geschwisternamen in einen frisch angelegten eigenen Unterordner mit Modus 0700 umzubenennen, dort über den Deskriptor des Unterordners zu prüfen und zu entfernen und den Unterordner danach zu löschen (schließt 2' gegen fremde Benutzer). Setze ihn um, wenn er ohne neue Ablehnungen auf dem Erfolgsweg und mit Rückfall wie in Punkt 1 geht; sonst Grund in den Notizen und den Kommentar ergänzen (IN_MOVED_TO kündigt 2' an).
3. **Tests (N1, N2 Prüfer 1):** Fehlerweg des Umbenennens in `dropTemp` (chattr +a, Probe `scratchpad/rev36a-spec/scripts/zz_rev36_chattr_linux_test.go`; ENOSPC auf einem kleinen loop-Dateisystem, wenn als root möglich, sonst Skip mit Grund); `aside` aus zwei Aufrufen verschieden.
4. **Hinweise:** Meldung bei scheiterndem Umbenennen nennt keinen nie existierenden Namen als Ort (H2 Prüfer 1, H3 Prüfer 2); Kommentare zu Linux/AIX; zu lange Kommentarzeilen.
5. **Läufe** wie in Paket 36A, dazu der ENOSPC-Fall aus `logs/enospc.log` (alt c8cda58, 558ce2b, neu) und die Wettläufe M2–M4 aus dem Harness von Prüfer 2 (fremd entfernt unter Temp-Name und unter dem neuen Namen; falsche Erfolge außerhalb Fenster 1 = 0).

## Nacharbeit 36A3 (dritte Runde, nur Testcode)

Ausgangspunkt 24c35c6 (Patch `docs/tasks/patches/36a2-24c35c6.patch` auf c8cda58). Ergebnis: genau ein Commit auf c8cda58 mit 36A insgesamt.

- **Fehler (Volllauf `fr-n36a`):** `go test ./internal/store` (race, race mit Tags, 386 mit Tags; ohne `-count=1`, also mit Testcache) endet mit `testing: can't write /tmp/go-build…/testlog.txt: write …: file too large` und FAIL, obwohl alle Tests bestehen. Nachgestellt vom Orchestrator: `go test -tags gomail_dev,gomail_test -run TestWriteTempInErrorSwapped ./internal/store` (ohne `-count=1`) scheitert so, mit `-count=1` nicht. Ursache: Mit Testcache schreibt `go test` über `internal/testlog` jedes Öffnen, Stat und Getenv des Testprozesses in `testlog.txt`. Solange `limitFileSize` das Limit des ganzen Prozesses auf 0 hält, scheitert dieses Schreiben mit `EFBIG`; das Zurücksetzen danach hilft nicht mehr.
- **Abhilfe:** Kein Schreiben unter gesenktem Limit im Testprozess selbst. Bevorzugt: der Teil mit `RLIMIT_FSIZE` läuft in einem Kindprozess (das Testbinary erneut mit `-test.run` auf genau den Fall und einer Umgebungsvariable, ohne `-test.testlogfile`), der Elternprozess prüft das Ergebnis; jeder Fall bleibt so streng wie vorher. Alternativ ein anderer Weg zum Schreibfehler ohne Prozesslimit, falls gleich streng. Kein Produktionscode.
- **Beleg:** `go test` für `internal/store` ohne `-count=1` (Testcache an, `GOFLAGS` leer) unter race, race mit Tags und 386 mit Tags endet mit `ok`; dazu `-count=3`.
