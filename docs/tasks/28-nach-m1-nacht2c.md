# Auftrag 28: Liste nach M1, zweite Nacht, dritte Welle (10./11.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Dazu kommen die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und die Abweichungen aus `docs/tasks/26-nach-m1-nacht2.md` (Kopf). Neu bzw. abweichend gilt:

- **Basis:** der Arbeitsbranch nach Auftrag 27. Je Paket ein eigener Worktree mit `git reset --hard 7e7721d`.
- **Nummern:** aus `docs/tasks/backlog-nach-m1.md` im Stand 7e7721d.
- **Commit-Zeile:** `Task: docs/tasks/28-nach-m1-nacht2c.md (Paket 28X)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl28<x>/notes.md`.
- **Haltepunkte:** Halte an und berichte, statt umzusetzen, wenn ein Punkt eines der folgenden Dinge berührt:
  - ein Dateiformat, einen signierten Datensatz, eine Signaturdomäne oder eine Prüfregel der Clients (was angenommen oder abgelehnt wird);
  - eine offene Frage (`TODO(ask)`, Q-Nummer);
  - einen neuen Befehl oder eine neue Option.
- **Sicherheit der Umgebung:**
  - Schreibe nie auf Pfade im PATH oder auf deren Linkziele, nie unter `/usr/local/go` oder `/root/go/pkg/mod`.
  - Lege Attrappen nur als neue Dateien in eigenen Ordnern an, nie mit `>` auf einen vorhandenen Pfad.
  - Mutanten nur in Kopien.
- **Platz:** Die Platte ist knapp (etwa 6 GB frei). Lege nur kleine Kopien an, nutze dünne Dateien und räume am Ende weg.
- **Last:** Jeder `go`-Befehl läuft mit `nice -n 19`. `internal/client` läuft nur mit `-run`, nie als ganzes Paket. Kein Lauf über das ganze Modul.

## Paket 28A: `publish`, Meldungen und Tests (Nr. 85, 93, 94, 95). Sicherheitskritisch.

1. **Nr. 93:**
   - Wird eine reguläre Datei zwischen `os.Lstat` und dem Öffnen eingetauscht, lehnt `lreadEntry` mit `errChanged` ab. Das gilt für jeden Fehler beim Öffnen und für eine Nicht-Datei nach dem Öffnen: Prüfe `os.SameFile` bzw. auf einen Link.
   - Die lange Meldung „remove it by hand“ und die kurze Meldung `store: … is not a regular file` gelten nur für einen Eintrag, der schon beim `Lstat` keine Datei war.
   - Berichtige die Kommentare: Ein Gerät mit Treiber wird geöffnet. Nenne das Restfenster.
   - Test: Tausch regulär → FIFO, Verzeichnis und Gerät (wo möglich) am Haken `check-open`; erwartet wird `errChanged`.
2. **Nr. 94:** `store.ErrNotRegular` aus `readEntry` in `runPublish` wird umhüllt, mit vollem Pfad und dem Hinweis aus `notRegularHint`. Das gilt für `witnesses.rec`, den Vergleich mit dem Export, das Nachloggen und „written meanwhile“. Im Zweig „written meanwhile“ sagt die Meldung, dass schon geschrieben sein kann, und zwar nur dort. `errors.Is(err, store.ErrNotRegular)` bleibt wahr.
3. **Nr. 85:**
   - Prüfe, ob die Ersatzzeile von `witnesses.rec` auch nach einem SIGKILL zwischen `rename` und Ausgabe sichtbar wird, ohne neue Option. Ein Weg wäre eine Zeile „replacing …“ vor dem `rename` und die bisherige danach.
   - Ist das ohne neue Option und ohne Formatänderung möglich, setze es um und teste es. Sonst beschreibe die Lage.
4. **Nr. 95:**
   - Test für „written meanwhile“ mit gleichem Inhalt: Er zählt nicht als geschrieben (Mutant A11/W4).
   - Test, dass ein Gerät, das `os.Lstat` schon zeigt, nie geöffnet wird. Er soll ohne root laufen, etwa mit inotify `IN_OPEN` auf `/dev/null` über einen eigenen Gerätenamen, falls möglich. Sonst nenne den Grund im Skip.
   - `platformSnapshot`/`listDir` in den Tests zeigen Verzeichnisse.
5. **Läufe:**
   - `internal/ceremony` unter race mit und ohne Tags, unter 386 mit Tags;
   - `cmd/gomail-ceremony` unter race mit Tags;
   - die Fallmatrix und die Tauschtests aus `scratchpad/rev27a-robust/` und `scratchpad/rev27a2-robust/` ohne neue Verletzung und ohne Übergang von Ablehnung zu Annahme.

## Paket 28B: `scripts/check-release.sh` (Nr. 96, 97)

1. **Nr. 96:** Ein Go-Test sammelt per `go/ast` alle `os.Getenv`/`os.LookupEnv` mit festem Namen in Nicht-Test-Dateien mit einem `gomail_test`- oder `gomail_dev`-Build-Tag. Jeden Namen gleicht er mit der Liste `switches` im Skript oder dem Muster ab. Ein Name, der nicht als Konstante vorliegt, lässt den Test scheitern.
2. **Nr. 97:**
   - **H3:** Ein mit `go test -c` gebautes Testprogramm wird erkannt. Prüfe zuerst, ob `go version -m` ein sicheres Merkmal zeigt (etwa `mod` „(devel)“ ohne VCS oder ein Testpaket als `path`). Sonst gilt eine Marke wie `testing.tRunner`. Ein Produktionsbuild darf nicht fälschlich abgelehnt werden.
   - **H1:** Die Suche nach Marken erkennt ein `tr` mit Status 0 und leerer Ausgabe, oder der Kopf nennt die Grenze genauer.
   - **H4:** `GOFLAGS=-json` wird neutralisiert, zum Beispiel mit `GOFLAGS=` für den Aufruf von `go version`, oder die Meldung sagt es.
   - **H2:** Test für „`go version` mit Status 0 ohne Ausgabe“.
3. **Läufe:**
   - `bash -n`, `dash -n`, gofmt und vet mit und ohne Tags;
   - `TestCheckRelease` und die neuen Tests ohne Tags, mit Tags, unter `-race` mit Tags und unter 386 mit Tags;
   - die Mutanten aus `scratchpad/impl27b3/mut/` scheitern weiter.

## Paket 28C: `unprocessed`, Warnungen und Tests (Nr. 102, 103, 104, 106; Testteile von Nr. 107)

1. **Nr. 104:** `warnCause` bekommt eine feste Ursache für `store.ErrNotRegular`. Danach braucht `unprocessedTerms` die lokale Sonderregel nur noch für `*fs.PathError`, oder ganz nicht mehr. Prüfe, wo `warnCause` überall greift. Ändert sich dadurch eine bestehende Warnung von `Read`, nenne sie wörtlich.
2. **Nr. 103:** Je Aufruf von `Index` und `Search` gibt es ab einer festen Schwelle (zum Beispiel 10) statt einzelner Warnungen „lässt sich nicht lesen“ eine Sammelwarnung mit Anzahl und den ersten Mail-IDs. Die Meldung ist fest formuliert und ohne Inhalt. Urteile („nur aus ihren Metadaten“) bleiben je Mail, weil sie einmalig sind.
3. **Nr. 102:** Test für `EACCES`, der nur läuft, wenn eine Datei mit Modus 000 tatsächlich `EACCES` ergibt, und sich sonst mit Grund überspringt. Prüfe ihn einmal mit `setpriv --bounding-set=-dac_override,-dac_read_search`.
4. **Nr. 106:** Test, der eine Mail ohne Trailer bzw. mit fehlendem Trailer an `openMail` gibt. Die Mutante ohne `f.Trailer != nil` muss scheitern. Gilt sie als gleichwertig, weil `envelope.Parse` das schon fängt, belege das und nenne es.
5. **Nr. 107, nur die Testteile:**
   - ein `ingest`-Test, der festhält, dass der Server die Adressen aus dem rohen Kopf nimmt (kodiertes Wort mit Komma);
   - ein Test für den Zweig „grew beyond“ von `ReadFileLimited` bei Mail-Dateien, falls ohne Eingriff in `store` erreichbar.
   - Die Abweichung des Umschlagabsenders bleibt unberührt, denn sie wäre eine Regeländerung für Suchbegriffe.
6. **Läufe:**
   - terms und ingest unter `-race` mit Tags und 386 mit Tags;
   - client mit `-run` über die neuen und betroffenen Tests (Muster wie `scratchpad/impl27c3/run.txt` plus neu) unter `-race` mit Tags und 386 mit Tags;
   - e2e `TestNoPlaintext` mit Tags.

## Paket 28D: `store.ReadFileLimited` (Nr. 105)

1. Belege den Puffer mit der Größe aus `Stat` + 1 vor, gedeckelt durch die Grenze. Lies ohne `io.ReadAll`, mit derselben Erkennung von „has N bytes“ und „grew beyond“. Fehlerwerte und Meldungen bleiben wörtlich gleich.
2. Miss die Allokation vorher und nachher, mit einer dünnen Datei bei 50 MiB.
3. Tests: Grenze genau, Grenze + 1, Wachstum beim Lesen, Schrumpfen beim Lesen, leere Datei.
4. **Läufe:**
   - `internal/store` unter race mit und ohne Tags und unter 386 mit Tags;
   - die Aufrufer von `ReadFileLimited` (per `grep`) mit ihren Paketen bzw. mit `-run` (client), unter race mit Tags.

## Fertig

Wie Auftrag 24. Der Bericht nennt außerdem Vorschläge für den Doku-Nachzug.
