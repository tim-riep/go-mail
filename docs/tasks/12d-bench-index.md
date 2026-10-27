# Auftrag 12d: Messumgebung, Indexmessungen (nach Auftrag 09) und Rest aus der Prüfung von 12c

Welle 3/4, nach Zusammenführung von Auftrag 09. Feste Vorgaben: `docs/tasks/00-vorgaben.md`. Aufträge 12, 12b, 12c bleiben gültig (`docs/tasks/12-benchmarks.md` Punkte 2, 3 und `Sync/index=on`). Darf ändern: nur `internal/bench/**` und `scripts/bench.sh`.

1. **Punkt 2 (Indexkosten je Mail):** `BenchmarkIndex/pending={terms,unprocessed}`: Korpusmails mit Worker zustellen (Begriffslisten in `pending/`) bzw. mit hoher `BatchAge` ohne Flush (nur Marker); `client.Index(mbx)` messen, µs je Mail über `ReportMetric`, `ReportAllocs`.
2. **Punkt 3 (Segmentgröße je 1000 Mails):** `BenchmarkIndexSegments/mails=1000` und `TestIndexSegments`: Bytes aller `index/<n>/*.gml` nach jedem Indexlauf und nach dem Zusammenfassen ab 16 Segmenten (Zugriff über `store`).
3. **`Sync/index=on`** freischalten; die drei „ausstehend“-Zeilen in `bench.sh` entfernen.
4. **Rest aus 12c-Prüfung (niedrig):** (a) `TestBenchScriptLimits` prüft `MaxMailsPerIP == math.MaxInt32` und den Satz „kein Mail-Limit je IP und Stunde“; (b) Kommentar zu `TestServerMemoryRuns` ehrlich: Verschleppung wird über `Sys` erkannt, VmRSS/HeapInuse nur ab 5 MiB; zusätzlich engere Schwelle für den Anstieg Lauf 1 → Lauf 2 bei VmRSS (1 MiB; getrennte Prozesse streuen < 0,2 MiB) und `TestCarriesPeak` mit realistischen Spitzen; (c) Tabellenkopf: „Uhr eingefroren (kein Alters-Flush), Logausgabe verworfen“; (d) Tabellentext zu `enc − proto`: „Kettenprüfung über Cache (Hashvergleich von `epoch.rec` und `user.rec`, je Mail zweimal), Hash über den Mailstrom“.

Fertig: `gofmt`, `go vet ./...`, `go test -race -short ./internal/bench`, `GOARCH=386 go test -short ./internal/bench`, `scripts/bench.sh -short` ohne „ausstehend“-Zeilen. Ein Commit `bench: index cost and segment size, remaining table notes (task 12d)`; kein Modellname. Bericht mit ersten Zahlen (Größenordnung, Maschine belastet).
