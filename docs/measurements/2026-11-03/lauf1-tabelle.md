# Messwerte

Erzeugt mit `scripts/bench.sh` am 2026-11-03T19:12Z auf Commit d633f55.

## Umgebung

| Merkmal | Wert |
|---|---|
| env | `GOTOOLCHAIN=go1.26.10 GOMAIL_BENCH_MIN_FREE=0.1` |
| goversion | `go1.26.10` |
| numcpu | `4` |
| gomaxprocs | `4` |
| cpumodel | `Intel(R) Xeon(R) Processor @ 2.80GHz` |
| memtotal | `16477348 kB` |
| kernel | `Linux version 6.18.44-fc-v230` |
| benchdir | `/tmp` |
| benchfs | `ext4 on / (/dev/vda)` |
| goos | `linux` |
| goarch | `amd64` |
| cpu | `Intel(R) Xeon(R) Processor @ 2.80GHz` |

## Ergebnisse

Punkte nach docs/tasks/12-benchmarks.md: 1 Empfang, 2 Indexierung, 3 Indexsegmente, 4 Sync, 5 Speicher des Servers (base vor, peak während, rest nach der Last).

* Punkt 1 in drei Betriebsarten je Größe und Verbindungszahl: `enc` = Ingest vollständig; `proto` = gleiches Ablageprotokoll ohne Verschlüsselung, samt Platzprüfung (`Accepting()`, zwei statfs je Mail) und Worker (je 100 Mails eine Begriffsliste in der Größe, die Ingest für die Größenklasse schreibt, danach Löschen der 100 Marker); `plain` = Minimal-Senke (Protokollkosten = proto − plain).
* Verschlüsselungskosten = enc − proto. Darin stecken außer der Verschlüsselung: Signaturen, Selbstprüfung, Auswertung der Kopfzeilen, Adressauflösung (`addresses.json`), Lesen von `mailbox.rec`, Kettenprüfung über Cache (Hashvergleich von `epoch.rec` und `user.rec`, je Mail zweimal), Hash über den Mailstrom, Termzerlegung im Worker. Die Begriffslisten sind in beiden Betriebsarten enthalten, soweit der Worker sie im Zeitfenster schreibt (bei b.N ≥ 100); die zuletzt offene Liste schreiben beide erst nach dem Zeitfenster.
* Bei `enc` wächst das Postfachverzeichnis während des Laufs (und über die Läufe einer Größe hinweg), bei `proto` ebenfalls bis zum Ende des Laufs: `mail.gml`, `meta.gml` und die Begriffslisten löscht `proto` erst nach dem Zeitfenster.
* Lockerungen gegenüber 5.1: MaxConns 64 statt 20, MaxConnsPerIP 64 statt 5, kein Mail-Limit je IP und Stunde (Benchmark-Server); MinFree 1 % statt 10 % (Ingest und `proto`; die gemeinsam genutzte Maschine hat weniger freien Platz, die Grenze wird nicht gemessen, statfs läuft trotzdem); GOMAIL_BENCH_MEM_CONNS ist auf MaxConns (64) begrenzt.
* Punkte 1 und 5: Uhr eingefroren (kein Alters-Flush), Logausgabe verworfen (Server und Ingest); der Worker schreibt Begriffslisten nur nach je 100 Mails und beim Flush. Bei den Punkten 2 bis 4 stellt die Zustellung des Korpus (Vorbereitung, nicht gemessen) die Uhr tageweise vor, dort schreibt der Worker auch nach Alter.
* Der Lastgenerator (net/smtp) läuft im selben Prozess wie der Server; bei Punkt 5 zählen seine Verbindungspuffer mit.
* Punkt 2: `client.Index` über 1000 Mails des Korpus (10 Absender, 3 Empfänger, 30 Tage, 20 % Anhänge, Threads), je Durchlauf; vor jedem Durchlauf werden außerhalb der Zeitmessung die Segmente gelöscht und pending/ so wiederhergestellt, wie Ingest es hinterließ. Der Client bleibt offen, sein Verzeichnis unverändert; er indexiert pending/ erneut, weil kein Segment die Einträge mehr enthält. `terms` = Begriffslisten des Workers (je Liste bis 100 Mails, eine Datei); `unprocessed` = nur Marker (eine Datei je Mail; der Worker lief bei der Zustellung nicht, kein Flush), Index liest und prüft dann die Metadaten jeder Mail und löscht jede Markerdatei einzeln (RemoveDurable, ein fsync je Mail). allocs/op und B/op gelten je Durchlauf, allocs/mail und B/mail je Mail.
* Punkt 3: Korpus mit 1000 Mails im November 2026 (eine Epoche), in 16 Teilen zugestellt, nach jedem Teil `client.Index` (ein Segment je Lauf); gezählt werden die Bytes aller `index/<n>/*.gml` über `store`. Der Lauf von Teil 16 schreibt das 16. Segment und fasst im selben Lauf zusammen (ab 16 Segmenten, wenn das Ergebnis ein Segment ist). Während dieses Laufs hält die Messung die Postfachsperre, bis das 16. Segment geschrieben ist: B-unmerged = diese 16 Segmente mit allen 1000 Mails, unmittelbar vor dem Zusammenfassen, B/segment = deren Mittel; B-merged und segments-merged nach dem Zusammenfassen. Die Größen hängen nicht von der Maschine ab.
* Punkt 4: `Sync` hält den Epochenvorrat und ruft `client.Index` auf. index=off = pending/ leer (alles schon indexiert); index=on = pending/ wie nach der Zustellung (Begriffslisten aller Mails), vor jedem Sync außerhalb der Zeitmessung wiederhergestellt, Segmente gelöscht. `Sync/…/list` ist `client.List` über alle Mails des Eingangs, kein Teil von `Sync`: der Schritt, dessen Kosten mit der Zahl der Mails wachsen, solange `Sync` keine Mails liest.
* Punkt 5: jeder Lauf (jede Größe, jede Wiederholung bei -count) läuft in einem eigenen Kindprozess; Grund- und Ruhewert werden gleich vorbereitet (1 s Leerlauf, dann debug.FreeOSMemory(), dann Messung). Die Grundwerte getrennter Läufe streuen um höchstens 5 MiB (Rauschanteil, geprüft von TestServerMemoryRuns; Sys wächst in Schritten von 4 MiB); der VmRSS-Grundwert von Lauf 2 liegt höchstens 1 MiB über dem von Lauf 1 (getrennte Prozesse streuen um weniger als 0,2 MiB).
* Dieser Lauf setzt GOMAIL_BENCH_MIN_FREE=0.1: MinFree 0.1 % statt der 1 % oben (Ingest und `proto`; statfs läuft unverändert je Mail zweimal).
* Jede Zahl ist der Median aus 5 Läufen, in Klammern der kleinste und der größte Wert.

| Punkt | Benchmark | Messwerte | Befehl zum Nachmessen |
|---|---|---|---|
| 1 | Receive/mode=enc/size=4KiB/conns=1 | 0.2871 MiB/s (0.2810–0.3877), 73.50 mails/s (71.93–99.25) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=4KiB/conns=4 | 0.7701 MiB/s (0.7063–0.8106), 197 mails/s (181–208) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=1 | 3.85 MiB/s (3.63–4.13), 61.68 mails/s (58.02–66.11) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=4 | 9.47 MiB/s (9.22–10.26), 152 mails/s (148–164) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=1 | 25.35 MiB/s (23.79–29.31), 25.35 mails/s (23.79–29.31) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=4 | 52.96 MiB/s (32.39–63.35), 52.96 mails/s (32.39–63.35) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=1 | 48.57 MiB/s (40.01–52.12), 4.86 mails/s (4.00–5.21) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=4 | 80.94 MiB/s (74.00–102), 8.09 mails/s (7.40–10.19) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=1 | 0.3748 MiB/s (0.3643–0.4537), 95.96 mails/s (93.26–116) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=4 | 0.7086 MiB/s (0.6865–0.8316), 181 mails/s (176–213) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=1 | 5.59 MiB/s (5.06–6.25), 89.43 mails/s (81.01–99.94) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=4 | 10.34 MiB/s (7.52–11.94), 166 mails/s (120–191) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=1 | 32.20 MiB/s (25.73–33.68), 32.20 mails/s (25.73–33.68) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=4 | 86.15 MiB/s (74.93–97.07), 86.15 mails/s (74.93–97.07) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=1 | 79.39 MiB/s (77.00–92.74), 7.94 mails/s (7.70–9.27) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=4 | 173 MiB/s (143–188), 17.34 mails/s (14.34–18.76) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=1 | 4.38 MiB/s (4.30–4.82), 1122 mails/s (1100–1233) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=4 | 10.68 MiB/s (9.19–11.11), 2735 mails/s (2353–2843) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=1 | 27.05 MiB/s (25.91–31.08), 433 mails/s (414–497) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=4 | 87.26 MiB/s (75.74–97.65), 1396 mails/s (1212–1562) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=1 | 67.83 MiB/s (65.17–72.55), 67.83 mails/s (65.17–72.55) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=4 | 176 MiB/s (174–200), 176 mails/s (174–200) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=1 | 107 MiB/s (101–116), 10.74 mails/s (10.11–11.58) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=4 | 219 MiB/s (205–246), 21.93 mails/s (20.52–24.65) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=off | 0.0203 s/sync (0.0188–0.0226) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=off$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=on | 0.3997 s/sync (0.3799–0.4087) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=on$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/list | 2.79 s/list (2.76–2.95) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^list$' -benchtime=1s ./internal/bench` |
| 5 | ServerMemory/size=64KiB/mails=1000/conns=20 | 1.52 heapinuse-base-MiB (1.41–1.61), 4.34 heapinuse-peak-MiB (4.23–4.58), 1.24 heapinuse-rest-MiB (1.23–1.35), 153 mails/s (139–169), 11.05 rss-base-MiB (10.90–11.10), 17.44 rss-peak-MiB (17.30–17.86), 13.57 rss-rest-MiB (13.42–13.59), 12.28 sys-base-MiB (8.03–12.52), 13.37 sys-peak-MiB (13.12–17.37), 13.37 sys-rest-MiB (13.12–17.37) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=64KiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 5 | ServerMemory/size=1MiB/mails=1000/conns=20 | 2.46 heapinuse-base-MiB (2.37–2.57), 10.55 heapinuse-peak-MiB (10.43–13.77), 1.30 heapinuse-rest-MiB (1.21–1.38), 62.52 mails/s (54.54–62.65), 11.94 rss-base-MiB (11.87–12.11), 24.57 rss-peak-MiB (23.27–27.21), 13.93 rss-rest-MiB (13.40–14.20), 12.52 sys-base-MiB (12.02–12.60), 25.12 sys-peak-MiB (21.37–29.37), 25.12 sys-rest-MiB (21.37–29.37) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=1MiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 2 | Index/pending=terms | 11490 B/mail (11454–11581), 117 allocs/mail, 67.37 µs/mail (63.20–70.92), 11489529 B/op (11454090–11580946), 116583 allocs/op (116577–116588) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=terms$' -benchtime=1s ./internal/bench` |
| 2 | Index/pending=unprocessed | 70900 B/mail (68892–70992), 682 allocs/mail, 1067 µs/mail (1001–1125), 70900488 B/op (68891552–70991664), 681509 allocs/op (681488–681536) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=unprocessed$' -benchtime=1s ./internal/bench` |
| 3 | IndexSegments/mails=1000 | 143600 B-merged, 193184 B-unmerged, 12074 B/segment, 16.00 segments, 1.00 segments-merged | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndexSegments$/^mails=1000$' -benchtime=1x ./internal/bench` |

## Last und Steal je Gruppe

Load average (1, 5, 15 min) vor und nach jeder Gruppe; Steal = Anteil der Steal-Ticks an allen CPU-Ticks (`/proc/stat`, user bis steal) während der Gruppe.

| Gruppe | Beginn (UTC) | Ende (UTC) | Last vorher | Last nachher | Steal |
|---|---|---|---|---|---|
| `^BenchmarkReceive$` | 2026-11-03T18:56:50Z | 2026-11-03T19:00:27Z | 0.44/0.91/1.19 | 2.59/1.68/1.44 | 0.75 % |
| `^BenchmarkSync$` | 2026-11-03T19:02:18Z | 2026-11-03T19:03:44Z | 0.45/1.18/1.28 | 1.34/1.34/1.33 | 0.79 % |
| `^BenchmarkServerMemory$` | 2026-11-03T19:04:44Z | 2026-11-03T19:07:17Z | 0.49/1.10/1.25 | 3.06/1.96/1.55 | 0.87 % |
| `^BenchmarkIndex$` | 2026-11-03T19:09:07Z | 2026-11-03T19:11:00Z | 0.48/1.35/1.37 | 1.52/1.49/1.42 | 0.75 % |
| `^BenchmarkIndexSegments$` | 2026-11-03T19:12:10Z | 2026-11-03T19:12:48Z | 0.47/1.17/1.31 | 0.87/1.18/1.31 | 1.01 % |
