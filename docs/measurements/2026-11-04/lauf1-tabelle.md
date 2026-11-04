# Messwerte

Erzeugt mit `scripts/bench.sh` am 2026-11-04T01:16Z auf Commit 14bf604.

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
| 1 | Receive/mode=enc/size=4KiB/conns=1 | 0.4410 MiB/s (0.3976–0.5064), 113 mails/s (102–130) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=4KiB/conns=4 | 0.8478 MiB/s (0.8070–0.9153), 217 mails/s (207–234) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=1 | 5.66 MiB/s (5.41–5.70), 90.49 mails/s (86.52–91.24) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=4 | 11.03 MiB/s (9.03–12.42), 176 mails/s (144–199) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=1 | 30.07 MiB/s (25.48–31.81), 30.07 mails/s (25.48–31.81) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=4 | 68.74 MiB/s (64.20–77.40), 68.74 mails/s (64.20–77.40) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=1 | 60.64 MiB/s (59.25–61.32), 6.06 mails/s (5.92–6.13) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=4 | 121 MiB/s (119–149), 12.11 mails/s (11.90–14.90) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=1 | 0.5221 MiB/s (0.4392–0.5525), 134 mails/s (112–142) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=4 | 0.9196 MiB/s (0.8607–1.07), 235 mails/s (220–275) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=1 | 6.14 MiB/s (6.08–8.17), 98.23 mails/s (97.19–131) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=4 | 13.28 MiB/s (12.77–13.57), 212 mails/s (204–217) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=1 | 44.15 MiB/s (39.45–45.48), 44.15 mails/s (39.45–45.48) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=4 | 102 MiB/s (95.87–108), 102 mails/s (95.87–108) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=1 | 96.85 MiB/s (89.40–112), 9.69 mails/s (8.94–11.22) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=4 | 191 MiB/s (163–206), 19.11 mails/s (16.26–20.61) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=1 | 4.95 MiB/s (4.72–5.31), 1266 mails/s (1207–1359) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=4 | 12.84 MiB/s (11.79–13.90), 3286 mails/s (3017–3558) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=1 | 37.66 MiB/s (34.20–39.57), 602 mails/s (547–633) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=4 | 94.85 MiB/s (86.78–102), 1518 mails/s (1388–1632) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=1 | 66.43 MiB/s (64.92–68.60), 66.43 mails/s (64.92–68.60) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=4 | 191 MiB/s (178–195), 191 mails/s (178–195) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=1 | 113 MiB/s (109–121), 11.29 mails/s (10.94–12.12) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=4 | 227 MiB/s (217–249), 22.72 mails/s (21.71–24.88) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=off | 0.0177 s/sync (0.0171–0.0184) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=off$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=on | 0.3683 s/sync (0.3402–0.3726) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=on$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/list | 2.53 s/list (2.44–2.78) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^list$' -benchtime=1s ./internal/bench` |
| 5 | ServerMemory/size=64KiB/mails=1000/conns=20 | 1.51 heapinuse-base-MiB (1.45–1.54), 4.32 heapinuse-peak-MiB (4.26–4.45), 1.27 heapinuse-rest-MiB (1.16–1.28), 191 mails/s (166–200), 11.09 rss-base-MiB (11.02–11.11), 17.26 rss-peak-MiB (17.11–17.36), 13.42 rss-rest-MiB (13.36–13.49), 12.27 sys-base-MiB (8.28–12.52), 17.37 sys-peak-MiB (13.12–17.43), 17.37 sys-rest-MiB (13.12–17.43) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=64KiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 5 | ServerMemory/size=1MiB/mails=1000/conns=20 | 2.47 heapinuse-base-MiB (2.44–2.48), 11.21 heapinuse-peak-MiB (10.02–13.64), 1.23 heapinuse-rest-MiB (1.17–1.26), 71.05 mails/s (67.49–75.92), 12.04 rss-base-MiB (12.01–12.06), 24.37 rss-peak-MiB (23.94–26.05), 13.59 rss-rest-MiB (13.42–14.01), 12.27 sys-base-MiB (12.27–12.52), 25.12 sys-peak-MiB (21.37–25.37), 25.12 sys-rest-MiB (21.37–25.37) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=1MiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 2 | Index/pending=terms | 11521 B/mail (11503–11543), 117 allocs/mail, 60.70 µs/mail (57.34–64.44), 11521062 B/op (11502816–11543498), 116591 allocs/op (116575–116597) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=terms$' -benchtime=1s ./internal/bench` |
| 2 | Index/pending=unprocessed | 69986 B/mail (69885–71047), 684 allocs/mail, 945 µs/mail (904–1113), 69986324 B/op (69885440–71046840), 683496 allocs/op (683473–683512) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=unprocessed$' -benchtime=1s ./internal/bench` |
| 3 | IndexSegments/mails=1000 | 143600 B-merged, 193184 B-unmerged, 12074 B/segment, 16.00 segments, 1.00 segments-merged | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndexSegments$/^mails=1000$' -benchtime=1x ./internal/bench` |

## Last und Steal je Gruppe

Load average (1, 5, 15 min) vor und nach jeder Gruppe; Steal = Anteil der Steal-Ticks an allen CPU-Ticks (`/proc/stat`, user bis steal) während der Gruppe.

| Gruppe | Beginn (UTC) | Ende (UTC) | Last vorher | Last nachher | Steal |
|---|---|---|---|---|---|
| `^BenchmarkReceive$` | 2026-11-04T01:00:33Z | 2026-11-04T01:04:20Z | 0.41/2.28/3.01 | 2.70/2.39/2.89 | 0.72 % |
| `^BenchmarkSync$` | 2026-11-04T01:06:20Z | 2026-11-04T01:07:36Z | 0.45/1.63/2.54 | 1.50/1.75/2.51 | 0.66 % |
| `^BenchmarkServerMemory$` | 2026-11-04T01:08:46Z | 2026-11-04T01:10:59Z | 0.46/1.38/2.33 | 3.63/2.32/2.55 | 0.86 % |
| `^BenchmarkIndex$` | 2026-11-04T01:12:59Z | 2026-11-04T01:14:44Z | 0.49/1.54/2.24 | 1.48/1.61/2.19 | 0.61 % |
| `^BenchmarkIndexSegments$` | 2026-11-04T01:15:54Z | 2026-11-04T01:16:28Z | 0.46/1.27/2.02 | 1.49/1.45/2.06 | 0.85 % |
