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
