# Messwerte

Erzeugt mit `scripts/bench.sh` am 2026-11-03T19:30Z auf Commit b72d1d7.

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
| 1 | Receive/mode=enc/size=4KiB/conns=1 | 0.3546 MiB/s (0.3058–0.3836), 90.78 mails/s (78.30–98.19) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=4KiB/conns=4 | 0.7408 MiB/s (0.7252–0.7948), 190 mails/s (186–204) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=1 | 4.18 MiB/s (3.79–4.50), 66.82 mails/s (60.56–72.02) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=4 | 10.34 MiB/s (10.10–11.03), 166 mails/s (162–176) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=1 | 25.20 MiB/s (22.64–27.78), 25.20 mails/s (22.64–27.78) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=4 | 53.80 MiB/s (36.80–59.62), 53.80 mails/s (36.80–59.62) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=1 | 49.24 MiB/s (48.41–53.32), 4.92 mails/s (4.84–5.33) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=4 | 80.11 MiB/s (71.18–97.86), 8.01 mails/s (7.12–9.79) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=1 | 0.3440 MiB/s (0.3003–0.3719), 88.05 mails/s (76.88–95.20) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=4 | 0.7553 MiB/s (0.7139–0.9014), 193 mails/s (183–231) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=1 | 5.73 MiB/s (4.84–5.93), 91.74 mails/s (77.44–94.93) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=4 | 10.39 MiB/s (10.06–11.37), 166 mails/s (161–182) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=1 | 36.67 MiB/s (33.90–38.36), 36.67 mails/s (33.90–38.36) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=4 | 101 MiB/s (93.64–110), 101 mails/s (93.64–110) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=1 | 84.36 MiB/s (83.23–87.16), 8.44 mails/s (8.32–8.72) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=4 | 176 MiB/s (173–190), 17.61 mails/s (17.27–19.02) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=1 | 4.29 MiB/s (3.97–4.62), 1097 mails/s (1016–1182) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=4 | 11.49 MiB/s (9.41–11.74), 2941 mails/s (2409–3006) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=1 | 33.79 MiB/s (28.24–36.91), 541 mails/s (452–591) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=4 | 77.08 MiB/s (70.00–82.65), 1233 mails/s (1120–1322) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=1 | 63.58 MiB/s (58.38–66.60), 63.58 mails/s (58.38–66.60) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=4 | 145 MiB/s (128–153), 145 mails/s (128–153) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=1 | 88.67 MiB/s (76.53–95.99), 8.87 mails/s (7.65–9.60) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=4 | 186 MiB/s (172–221), 18.59 mails/s (17.19–22.09) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=off | 0.0217 s/sync (0.0202–0.0238) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=off$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=on | 0.4110 s/sync (0.3966–0.4293) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=on$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/list | 3.03 s/list (2.77–3.40) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^list$' -benchtime=1s ./internal/bench` |
| 5 | ServerMemory/size=64KiB/mails=1000/conns=20 | 1.53 heapinuse-base-MiB (1.52–1.59), 4.43 heapinuse-peak-MiB (4.31–4.48), 1.28 heapinuse-rest-MiB (1.24–1.35), 186 mails/s (155–191), 11.11 rss-base-MiB (11.07–11.18), 17.30 rss-peak-MiB (17.15–17.59), 13.50 rss-rest-MiB (13.43–13.75), 12.27 sys-base-MiB (8.27–12.52), 13.37 sys-peak-MiB (13.12–17.43), 13.37 sys-rest-MiB (13.12–17.43) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=64KiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 5 | ServerMemory/size=1MiB/mails=1000/conns=20 | 2.47 heapinuse-base-MiB (2.34–2.52), 10.32 heapinuse-peak-MiB (9.91–11.20), 1.23 heapinuse-rest-MiB (1.19–1.31), 62.23 mails/s (60.12–70.93), 12.06 rss-base-MiB (11.88–12.09), 23.80 rss-peak-MiB (23.18–24.65), 13.62 rss-rest-MiB (13.35–13.82), 12.28 sys-base-MiB (12.27–12.53), 21.37 sys-peak-MiB (21.12–25.37), 21.37 sys-rest-MiB (21.12–25.37) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=1MiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 2 | Index/pending=terms | 11506 B/mail (11491–11528), 117 allocs/mail, 69.46 µs/mail (67.66–71.72), 11505596 B/op (11491116–11527897), 116585 allocs/op (116575–116602) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=terms$' -benchtime=1s ./internal/bench` |
| 2 | Index/pending=unprocessed | 70981 B/mail (70473–70996), 682 allocs/mail, 1064 µs/mail (963–1105), 70980844 B/op (70472972–70996208), 681507 allocs/op (681492–681516) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=unprocessed$' -benchtime=1s ./internal/bench` |
| 3 | IndexSegments/mails=1000 | 143600 B-merged, 193184 B-unmerged, 12074 B/segment, 16.00 segments, 1.00 segments-merged | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndexSegments$/^mails=1000$' -benchtime=1x ./internal/bench` |

## Last und Steal je Gruppe

Load average (1, 5, 15 min) vor und nach jeder Gruppe; Steal = Anteil der Steal-Ticks an allen CPU-Ticks (`/proc/stat`, user bis steal) während der Gruppe.

| Gruppe | Beginn (UTC) | Ende (UTC) | Last vorher | Last nachher | Steal |
|---|---|---|---|---|---|
| `^BenchmarkReceive$` | 2026-11-03T19:13:25Z | 2026-11-03T19:17:07Z | 0.48/1.05/1.26 | 2.85/1.89/1.54 | 0.98 % |
| `^BenchmarkSync$` | 2026-11-03T19:18:57Z | 2026-11-03T19:20:23Z | 0.45/1.30/1.37 | 1.70/1.57/1.46 | 0.75 % |
| `^BenchmarkServerMemory$` | 2026-11-03T19:21:43Z | 2026-11-03T19:24:05Z | 0.45/1.20/1.34 | 3.53/2.16/1.67 | 0.83 % |
| `^BenchmarkIndex$` | 2026-11-03T19:26:06Z | 2026-11-03T19:27:58Z | 0.47/1.44/1.47 | 2.18/1.73/1.56 | 0.87 % |
| `^BenchmarkIndexSegments$` | 2026-11-03T19:29:28Z | 2026-11-03T19:30:05Z | 0.48/1.27/1.41 | 1.49/1.44/1.46 | 0.77 % |
