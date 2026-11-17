# Auftrag 29: Reste aus den Prüfungen von Auftrag 28 (17./18.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/28-nach-m1-nacht2c.md`. Neu bzw. abweichend gilt:

- **Basis:** die lokale Quelle `orch/n28`, Stand 0854dab. Das ist f8fe095 mit 28A 8f15bbf, 28B 40fa7ab, 28D 3a9b333 und 28C 23d5f55, also der Code, der als Auftrag 28 zusammengeführt wird. Je Paket ein eigener Worktree mit `git reset --hard 0854dab`.
- **Quellen der Punkte:** `docs/tasks/20-notes.md`, Abschnitt „Auftrag 28 … Prüfungen“ (im Stand 0de0df0), und die Prüfnotizen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/rev28*/notes.md`.
- **Commit-Zeile:** `Task: docs/tasks/29-nach-m1-nacht3.md (Paket 29X)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl29<x>/notes.md`.
- **Haltepunkte:** Halte an und berichte, statt umzusetzen, wenn ein Punkt eines der folgenden Dinge berührt:
  - ein Dateiformat, einen signierten Datensatz oder eine Signaturdomäne;
  - eine Prüfregel der Clients (was angenommen oder abgelehnt wird, wann ein Marker gelöscht wird);
  - eine offene Frage;
  - einen neuen Befehl oder eine neue Option.
- **Sicherheit der Umgebung:**
  - Schreibe nie auf Pfade im PATH oder auf deren Linkziele, nie unter `/usr/local/go` oder `/root/go/pkg/mod`.
  - Attrappen legst du nur als neue Dateien in frisch angelegten Ordnern an.
  - Mutanten nur in Kopien.
  - Die Platte ist knapp (etwa 10 GB frei): kleine Kopien, dünne Dateien, am Ende wegräumen.
- **Last:** Jeder `go`-Befehl läuft mit `nice -n 19`. `internal/client` nur mit `-run`. Kein Lauf über das ganze Modul.

## Paket 29A: `store.ReadFileLimited`, Reste aus 28D2

1. **Erster Read bei Stat-Größe 0:** Er ist mindestens `min(512, limit)` Byte groß, wie bei `io.ReadAll`. So ergeben Sonderdateien über einen Link (etwa `/proc/self/pagemap`) wieder dasselbe wie vor 28D. Dazu ein Test mit Vergleich gegen den alten Code.
2. **Kopie bei kurzem Ergebnis nur im Schrumpffall:** Kopiert wird nur, wenn der Puffer nicht gewachsen ist. Ziel: Auch der konstruierte schlimmste Fall bleibt bei höchstens etwa 2 × max. Dazu ein Test mit genau dieser Form.
3. **Test gegen einen leeren Lesepuffer:** Ein Leser, der bei `len(p) == 0` sofort scheitert, und die Prüfung `pos + cap(p) ≤ limit`. Ein Rückfall in eine Endlosschleife soll als Fehler auffallen, nicht als Hänger.
4. **386 ab 2 GiB:** Ist `c <= cap(buf)`, endet `readAtMost` mit `ErrTooLarge`, statt `Read` einen leeren Puffer zu geben. Den Kommentar berichtigen.
5. **Hinweis an den Allokationstests:** Sie dürfen nicht parallel laufen.
6. **Läufe:**
   - `internal/store` unter race mit und ohne Tags und unter 386 mit Tags;
   - die Aufrufer `translog`, `ingest`, `witness`, `ceremony` und `cmd/gomailctl` unter race mit Tags;
   - `internal/client` mit `-run` über die Tests zu Mails und `state.json`;
   - die Differenztests und Messungen aus `rev28d-spec/` und `rev28d2-robust/` gegen den neuen Stand.

## Paket 29B: Client, Reste aus 28C/28C2

1. **Zwischenspeicher je Aufruf in `indexEpoch`:** Wie `opened` in `Search` öffnet `Index` eine Mail mit mehreren Markern nur einmal je Aufruf. Treffer, Marker, Warnungen und Urteile bleiben gleich. Ein Test zählt die Öffnungen.
2. **Unlesbare pending-Datei:** Der Kommentar `continue // warned` behauptet eine Warnung, die nicht kommt. Gib eine feste Warnung ohne Inhalt aus, ohne den Ablauf zu ändern; der Eintrag bleibt liegen. Falls das eine Prüfregel berührt, halte an.
3. **fanotify-Test härten:**
   - `time.AfterFunc(time.Minute, g.close)` in `growOnRead`;
   - `t.Cleanup(g.close)` nach jedem `growOnRead`;
   - einen Schreibfehler beim Anhängen lesen und als FAIL melden;
   - die pid des Ereignisses mit `os.Getpid()` vergleichen und fremde Ereignisse nur erlauben;
   - den Kommentar zu `io.ReadFull` berichtigen.
4. **Test:** Die Sammelwarnung kommt je Aufruf, nicht je Epoche (Mutant P8).
5. **Nicht umsetzen** (Liste): `checkMeta` macht Lesefehler still; eigener Sentinel für Lesefehler.
6. **Läufe:**
   - terms und ingest unter `-race` mit Tags;
   - client mit `-run` über `scratchpad/impl28c2/run.txt` plus die neuen Tests, unter `-race` mit Tags und unter 386 mit Tags;
   - `TestUnprocessedMailEACCES` unter `setpriv --bounding-set=-dac_override,-dac_read_search`;
   - e2e `TestNoPlaintext` mit Tags.

## Paket 29C: `publish`, Reste aus 28A2. Sicherheitskritisch.

1. **Meldung bei EEXIST durch ein fremdes Verzeichnis:** Statt „is unchanged“ heißt es dort „was not replaced“ oder eine gleich genaue Fassung. Prüfe am Code, in welchen Fehlerzweigen „unchanged“ stimmt und wo nicht.
2. **Test-Hilfe `setNofile`:** Kindprozesse, die nach dem Test gestartet werden, erben nicht mehr ein verändertes Limit, zum Beispiel über `prlimit` per Systemaufruf. Andernfalls kommt das in den Kommentar. Dazu der Hinweis, dass diese Tests nie `t.Parallel` werden.
3. **Kommentare:**
   - `WitnessesReplacing`: umhüllt wird „after the replacement is announced, whether or not this callback is set“;
   - `protected_hardlinks` beim Restfenster;
   - Rücktausch vor dem zweiten `Lstat` an der Artprüfung;
   - „the temporary file is removed again“ nur, wo das möglich ist.
4. **Läufe:**
   - `internal/ceremony` unter race mit und ohne Tags und unter 386 mit Tags;
   - `cmd/gomail-ceremony` unter race mit Tags, ganzes Paket;
   - die Fallmatrix und die Tauschtests aus `scratchpad/rev27a2-robust/` (Skript in `scratchpad/impl28a/`) ohne neue Verletzung.

## Paket 29D: `TestReleaseSwitches`, Reste aus 28B2

1. Ein symbolischer Link auf eine `.go`-Datei unter `cmd/` oder `internal/` lässt den Test scheitern. Alternativ folgt der Test dem Link und parst die Zieldatei. Wähle die sichere Variante.
2. Dateien, die go build ignoriert (Name mit `_` oder `.` vorn), werden wie bei go/build übersprungen.
3. **Läufe:**
   - gofmt und vet für `internal/e2e` mit und ohne Tags;
   - `TestCheckRelease` und `TestReleaseSwitches` ohne Tags, mit Tags und unter `-race` mit Tags;
   - die Mutanten aus `scratchpad/rev28b2/mut/` scheitern weiter.

## Fertig

Wie Auftrag 24: Läufe, Gegenbelege per Mutation, genau ein Commit auf 0854dab je Paket, Notizen. Der Bericht nennt außerdem Vorschläge für den Doku-Nachzug.
