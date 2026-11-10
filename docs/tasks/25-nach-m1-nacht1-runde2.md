# Auftrag 25: Reste aus den Prüfungen von Auftrag 24 (zweite Runde, Nacht 09./10.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` und die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt oben) wörtlich.

- **Basis:** die lokale Quelle `orch/n24` (Arbeitsbranch mit den Paketen A bis F aus Auftrag 24, Stand 7dfd935), je Paket ein eigener Worktree: `git reset --hard orch/n24`.
- **Quelle der Punkte:** `docs/tasks/20-notes.md`, Abschnitt „Auftrag 24 … Prüfungen“, dazu die Prüfberichte, die im Auftrag genannt sind.
- **Nicht ändern:** Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients. Die Dokumente ändert ein eigener Nachzug.
- Jeder `go`-Befehl läuft mit `nice -n 19`, weil parallel ein Volllauf läuft.

## Paket 25A: `internal/ceremony` (`publish`). Zwei Prüfer.

1. **F3:** `readEntry` prüft nach dem Öffnen am Deskriptor mit `os.SameFile` gegen das Ergebnis von `Lstat`, oder es öffnet ohne Links zu folgen (`O_NOFOLLOW`, wo verfügbar). Ein Wechsel zwischen `Lstat` und Lesen führt dann zur Ablehnung statt zu „gleich“.
2. **N1 aus der Nachprüfung von A2:** Ein `.tmp-*`-Name, der dieselbe Datei ist wie ein Name des Exports, verbirgt einen harten Link (`tempNames`). Die Abhilfe: Solche `.tmp-*` werden nur dann nicht mitgezählt, wenn sie älter als der eigene Lauf sind und zu einem Absturz passen. Alternativ zählt jeder `.tmp-*`-Name mit, und die Wiederholung nach einem Absturz entfernt `.tmp-*` vorher unter der Serversperre. Wähle die einfachere sichere Lösung, begründe sie und belege sie mit Tests (`TestRevTmpNameHidesHardLink` in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/rev24a2/internal/ceremony/rev24a2_unix_test.go`).
3. **N3 aus der Nachprüfung von A2:** Ein fehlender Name, dessen `.cert` oder `.succ` im Log einen gültigen Eintrag mit anderem Inhalt hat, wird vor dem Schreiben abgelehnt, symmetrisch zu `sameButLogged`. Vorlage ist `TestRevMissingOverValidEntry` aus derselben Datei.
4. **`witnesses.rec`:** Ein Link oder harter Link an dieser Stelle wird ebenso behandelt wie bei den Namen des Exports. `witnesses.rec` ist eine Datei des Exports; prüfe das. Vorlage: `TestRev24AWitnessesLink` in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/rev24a-robust/new/internal/ceremony/`.

## Paket 25B: Client-Verzeichnis, Meldung „Prüfung nicht möglich“. Zwei Prüfer.

Dateien: `internal/client/client.go` (`Config.check`, `insideDataDir`), `internal/client/keygen.go` (`createClientDir`), Tests.

1. **N1 aus der Nachprüfung von B2:** Kann `resolveExisting` den Pfad nicht prüfen (EACCES, ENAMETOOLONG, ELOOP, relativer Pfad), meldet der Befehl einen eigenen Fehler, der weiter `errors.Is(…, ErrInsideDataDir)` erfüllt. Der Fehler nennt die Ursache (errno), damit ein Betreiber unter einem fremden Verzeichnis „permission denied“ sieht statt „liegt im Datenverzeichnis“.
2. **N2 aus der Nachprüfung von B2:** Test für ENOTDIR. `--dir <datei>/x` ergibt weiter die Meldung „not a directory“ und nicht `ErrInsideDataDir`.

## Paket 25C: `internal/loghttp`. Ein Prüfer mit Angreiferblick.

1. **N2 aus der Nachprüfung von D2:** Vor dem Quorum ruft eine Wiederholung der öffentlichen Note des Kandidaten über `publish()` jedes Mal `PublishHead` auf. Ruf `publish()` nur noch, wenn `merge` etwas hinzugefügt hat, und berichtige den Paketkommentar („cost a verification each and nothing more“). Test mit Zähler wie `TestReplayPublishedHead`.
2. **N1 aus der Nachprüfung von D2, optional:** `SlotWait` auf 5 s erhöhen. Begründe es: Das liegt unter `WriteTimeout`, und Zeugen werden unter Überlast seltener verdrängt. Ist die Wirkung in einem kurzen Test nicht belegbar, beschreibst du nur die Wahl.

## Paket 25D: `scripts/bench.sh` (`-render`). Ein Prüfer.

1. **N1 aus der Prüfung von E:** `envof` quotiert Werte für die Shell und übergibt sie nicht über `awk -v`, das Escapes auswertet, sondern über `ENVIRON`. Eine Tabelle mit einem Wert mit Leerzeichen, `$`, Backslash oder `'` ergibt einen Befehl, der sich so ausführen lässt.
2. **N2 aus der Prüfung von E:** Eine Soll-Liste der Namen je Gruppe (aus `internal/bench`, als Daten im Skript) lässt `render` ganz fehlende Kinder erkennen und mit Exit 1 abbrechen.
3. **Sicherheitsregel:** Rufe `scripts/bench.sh` nie ohne gültiges `-render <datei>` auf. Fehlfälle prüfst du in einer Kopie im Scratchpad, in der `run()` nur `echo` ausgibt. Die vier Rohdateien unter `docs/measurements/2026-11-0{3,4}/` müssen weiter rc=0 ergeben und dieselbe Tabelle wie bisher.

## Fertig

Wie Auftrag 24: gofmt, vet, die gezielten Läufe der geänderten Pakete, Gegenbelege per Mutation, ein Commit mit `Task: docs/tasks/25-nach-m1-nacht1-runde2.md (Paket 25X)`, Bericht mit Vorschlägen für die Dokumente.
