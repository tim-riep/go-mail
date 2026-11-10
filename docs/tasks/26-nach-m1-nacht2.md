# Auftrag 26: Liste nach M1, zweite Nacht (10./11.11.2026)

Es gelten wörtlich die festen Vorgaben aus `docs/tasks/00-vorgaben.md` und die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“). Davon weicht nur Folgendes ab:

- **Basis:** die lokale Quelle `orch/n25` (Arbeitsbranch mit Auftrag 24 und den geprüften Paketen von 25, Stand 3ea40f0). Je Paket ein eigener Worktree mit `git reset --hard orch/n25`.
- **Quelle der Nummern:** die Liste nach M1 im Stand nach Auftrag 25g. Lies sie mit `git show 0c4d1a9:docs/tasks/backlog-nach-m1.md`. Prüfe jeden Punkt am heutigen Code, bevor du ihn umsetzt.
- **Commit-Zeile:** `Task: docs/tasks/26-nach-m1-nacht2.md (Paket 26X)`.
- **Notizen:** unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl26<x>/notes.md`.
- **Mutanten** baust du nur in Kopien im Scratchpad ein (`git archive` oder `cp -r`), nie im Worktree. Ein Container-Neustart darf keinen Mutanten im Baum zurücklassen.
- **WIP-Commits** nach jedem Punkt.

## Paket 26A: `internal/loghttp`, `cmd/gomail-server`, `internal/translog`, `internal/witness` (Nr. 7 Rest, 74, 75, 67, 70 ohne `bench.sh`). Sicherheitskritisch.

1. **Nr. 7, Rest: Grenze für Verbindungen und Rate je Quelle am Log-HTTP-Listener** (AUDIT R8, D80).
   - Eine feste Obergrenze gleichzeitiger Verbindungen im Listener. Ein Accept über der Grenze wird sofort geschlossen, ohne zu blockieren.
   - Eine Grenze je Quelladresse (IP, ohne Port): höchstens N gleichzeitige Verbindungen. Dazu eine Rate für neue Verbindungen oder Anfragen je Quelle, als Token-Bucket. Ein Zuviel ergibt 503 bzw. das Schließen der Verbindung.
   - Der Speicher der Tabelle je Quelle ist begrenzt; alte Einträge werden aufgeräumt. Ein Angreifer mit vielen Adressen darf ihn nicht unbegrenzt wachsen lassen.
   - Die Werte sind Konstanten im Paket. Begründe sie: Ein Zeuge stellt wenige Anfragen je Runde (`MinGap`), es gibt höchstens `witness.MaxWitnesses` Zeugen, und Clients holen Köpfe. Kein neuer Schalter, keine neue Konfigurationsdatei. Brauchte es einen Schalter, beschreibst du ihn nur.
   - Zeugen dürfen auch unter Last nicht dauerhaft ausgesperrt werden. Belege das mit einem Lasttest, der dem Flood-Test der Prüfung von 25C entspricht (`/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/rev25c/flood.sh` und die dazugehörigen Testdateien): viele Verbindungen von einer Quelle und viele Quellen über Loopback-Adressen 127.0.0.x. Der Lasttest gehört nicht in die Testdateien des Repositorys, sondern in den Scratchpad. Er läuft höchstens zweimal je 20 s.
   - Im Repository brauchen die Grenzen kurze, deterministische Tests.
   - Hinter einem Proxy: Die Grenze je Quelle wertet nur die Gegenadresse der TCP-Verbindung aus, nie `X-Forwarded-For`. Halte das im Kommentar fest.
2. **Nr. 74:** `translog.operatorLog.PublishHead` ruft `refuse(tree)` auf, wie `SignHead`. Ein Kopf wird also nicht veröffentlicht, wenn der Baum widersprüchlich ist. Test dazu.
3. **Nr. 75:** Paketkommentar von `loghttp`: „…, once SignHead yields one“.
4. **Nr. 67:** Der Protokollkommentar in `internal/witness` nennt 503 aus `loghttp` (kein Platz nach `SlotWait`, neu auch die Grenzen aus Punkt 1) und die Wiederholung in der nächsten Runde.
5. **Nr. 70, Teil ohne `bench.sh`:**
   - `ErrNoLog` und `Unverified` „melden kein Log“;
   - `internal/translog/doc.go` zu Task 14/15;
   - `translog.Warning` nennt die entfernte Option. Ist der Text nirgends ausgegeben, entferne die Option daraus.
6. **Läufe:**
   - `internal/loghttp`, `internal/translog`, `internal/witness` und `cmd/gomail-server -run 'Log|Witness'` unter race mit und ohne Tags und unter 386 mit Tags;
   - `internal/e2e -run Log` mit Tags;
   - `FuzzServer` 5 Minuten.

## Paket 26B: `internal/ceremony`, `internal/store` (Nr. 72, 73, 83). Sicherheitskritisch.

1. **Nr. 72:** `publish` öffnet `data/platform/` einmal als Verzeichnis, ohne einem Link zu folgen: `os.OpenRoot` bzw. `O_NOFOLLOW|O_DIRECTORY`, Prüfung mit `SameFile` gegen das `Lstat` aus `checkPlatformDir`. Lesen, Schreiben (temporäre Datei, `rename`), Entfernen der `.tmp-*` und `fsync` laufen danach relativ zu diesem Deskriptor bzw. über `os.Root`.
   - Ein Tausch von `platform/` gegen einen Link oder ein anderes Verzeichnis nach dem Öffnen wirkt sich nicht mehr aus: Alles geht in das geöffnete Verzeichnis, oder `publish` lehnt ab.
   - Prüfe, was `os.Root` in go1.26 kann (`OpenFile`, `Rename`, `Remove`, `Lstat`, `Mkdir`) und ob `store.WriteFileAtomic` eine Fassung für ein `*os.Root` braucht. Wenn ja, baue sie in `store` als neue Funktion, ohne das Verhalten der bestehenden zu ändern.
   - Die bisherigen Meldungen bleiben, wo der Fall gleich bleibt.
   - **Gegenbeleg:** der Wettlauf-Test `TestRev25A2PlatformFlipRace` bzw. `TestRev25A2Window` aus `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/rev25a2-robust/` (Kopien `v4`/`v4h`). Auf `orch/n25` zeigt er Schreiben und Entfernen durch den Link, mit 26B nicht mehr.
2. **Nr. 73:** `Store.RemoveTempFiles` entfernt mit `removeName` (Unlink) statt `os.Remove`. Ein Verzeichnis unter einem `.tmp-*`-Namen bleibt stehen, wie bei `RemoveTempReport`. Prüfe das Verhalten beim Serverstart: Ein `.tmp-*`-Verzeichnis darf den Start nicht neu abbrechen, wenn es das bisher nicht tat.
3. **Nr. 83:** Scheitert nach dem `rename` von `witnesses.rec` nur noch der `fsync` des Verzeichnisses, ruft `publish` den Callback trotzdem und gibt danach den Fehler zurück. Dazu ein Test mit einem Testhaken für den fsync-Fehler, nur in Testcode oder als nil-Haken wie die bestehenden.
4. **Läufe:**
   - `internal/ceremony`, `internal/store` und `internal/ingest` unter race mit und ohne Tags und unter 386 mit Tags;
   - `cmd/gomail-ceremony` unter race mit Tags;
   - `cmd/gomail-server -run 'Init|Start|Temp'` mit Tags;
   - `internal/client -run 'Store|Platform|Temp'` mit Tags;
   - die Fallmatrix aus `rev25a-robust` (`run.sh`): keine neuen Verletzungen, keine neuen Ablehnungen außer dort, wo dieser Auftrag sie verlangt.

## Paket 26C: `scripts/bench.sh` und Tests in `internal/bench` (Nr. 76 bis 82, 70 nur `bench.sh`)

**Sicherheitsregel, zwingend:**
- Rufe `scripts/bench.sh` nie ohne gültiges `-render <datei>` auf, auch nicht mit `-h`.
- Den Messweg und alle Fehlfälle prüfst du nur in Kopien im Scratchpad, in denen `run()` kein `go` aufruft (`rev25d/mksafe.sh`, `impl25d2/mksim.sh`, `rev25d2b/mkpipe.sh` unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/`).
- Halte ein falsches `go` vorn im PATH.
- `go test` über `internal/bench` nur mit `-run`, nie mit `-bench`.

1. **Nr. 76:** `go test` läuft im Hintergrund mit `wait`. Der Trap beendet bei TERM, HUP oder INT an bash auch das laufende `go test` und behält die Rohdaten. Prüfe die Prozessgruppe.
2. **Nr. 80:** Die Probe von `-raw` öffnet keine FIFO und kein anderes nicht reguläres Ziel. Bei einer vorhandenen Datei, die keine reguläre ist, prüft sie nur `-w`.
3. **Nr. 81:** `samefile` ohne `realpath -m`: `-o` und `-raw` vorab per `: >>` proben (nur reguläre oder neue Dateien), dann `-ef`, neu angelegte Probedateien wieder löschen. Nur reguläre Dateien vergleichen, also keinen Treffer bei `/dev/null`. Dazu H4 der Nachprüfung von 25D3: `-o` wird vorab geprüft.
4. **Nr. 82:** `-benchtime` ohne Nullwerte (`0x`, `0s`, `0.0s`); `µs` und `μs` sind beide erlaubt.
5. **Nr. 77 und 78:** Ein Test in `internal/bench` (ohne Messung, nur `-run`, wie `TestBenchScriptLimits`) prüft:
   - `wantnames` in `bench.sh` gegen die Namen, die die Benchmarks erzeugen (aus den Konstanten und Listen des Pakets);
   - `tablebad` gegen `envNames`.
6. **Nr. 70, Teil `bench.sh`:** die SKIP-Einrückung im Kommentar.
7. **Läufe und Regression:**
   - Die vier Rohdateien unter `docs/measurements/2026-11-0{3,4}/` mit dem echten Skript und gültigem `-render` unter mawk, gawk, onetrue awk und busybox in C und C.UTF-8. Jede ergibt rc=0 und, ohne „Erzeugt mit“, die committete Tabelle.
   - Die Fallsammlungen aus `rev25d3/` und `impl25d3/` angepasst.
   - `internal/bench` mit `-run` unter race mit und ohne Tags und unter 386 mit Tags.

## Paket 26D: Testlücken (Nr. 66, 69, 79)

1. **Nr. 66:** In `cmd/gomail-server` ein Test für den Zweig `sc.Verify` in `identityKey`, also `address add` unter einer Identität, die über eine geloggte Nachfolge gilt. Gegenbeleg: ein Mutant ohne `sc.Verify` scheitert.
2. **Nr. 69:** `TestReadPlatformCertRawReadsOnce` in `internal/store` erkennt auch ein zweites Lesen an `ReadPlatformFile` vorbei. Zum Beispiel zählt der Test das Öffnen über einen Haken an `OpenRegular`, oder er tauscht die Datei nach dem ersten Lesen aus. Gegenbeleg: Mutant M4direct aus der Prüfung von 24E. Die Prüfdateien liegen unter `scratchpad/rev24e/`; findest du sie nicht, baue den Mutanten nach der Beschreibung in `docs/tasks/20-notes.md`, Abschnitt „Auftrag 24 … Prüfungen“, Eintrag E.
3. **Nr. 79:** `TestClientDirLeftovers` überspringt ohne `CAP_CHOWN` nur den Teil mit fremdem Besitzer, der Rest läuft. Prüfe das ohne Rechte über ein kompiliertes Testbinary unter `setpriv --inh-caps=-all --bounding-set=-all`.
4. Nur Testcode. `internal/client` nur mit `-run`.

## Paket 26E: Fuzz-Ziele für die Prüfpfade des Clients und die Zeremonie (Nr. 25)

1. Neue Fuzz-Ziele, nur in Testdateien, für Parser und Prüfungen, die Daten aus dem Datenverzeichnis lesen:
   - Kette und Kopf eines Postfachs (`store.Chain` bzw. die Prüfung im Client);
   - Vermerke (`checkpoint`);
   - `state.json` des Clients;
   - in der Zeremonie das Lesen eines Exports (`readExport`) und `checkDataPlatform`.

   Wähle die Einstiegspunkte so, dass ein Ziel ohne Netz und ohne Plattenzustand außerhalb von `t.TempDir` läuft. Mit Seeds aus gültigen Testdaten.
2. Jedes Ziel prüft mindestens: kein Panic, keine Annahme ungültiger Daten, wo sich das ohne zweite Implementierung prüfen lässt, und begrenzter Speicher.
3. Jedes Ziel läuft 5 Minuten mit `-parallel 2`. Ein Fund wird im Bericht beschrieben und nicht behoben; ist er klein, behebst du ihn in einem eigenen Commit, mit Test.
4. Die bestehende Liste der Ziele (HANDOFF „Fuzzing“, AUDIT 6.4) ergänzt erst der Doku-Nachzug. Im Bericht stehen Name, Paket und Laufzeit je Ziel.
5. `internal/client` nur mit `-run`.

## Fertig

Wie Auftrag 24. Der Bericht nennt außerdem Vorschläge für den Doku-Nachzug: RUNBOOK, AUDIT, DECISIONS-Nachträge, HANDOFF, Liste nach M1.
