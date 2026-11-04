# Messwerte

Erzeugt mit `scripts/bench.sh` am 2026-11-04T01:32Z auf Commit 14bf604.

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
| 1 | Receive/mode=enc/size=4KiB/conns=1 | 0.3752 MiB/s (0.3469–0.4695), 96.06 mails/s (88.80–120) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=4KiB/conns=4 | 0.8454 MiB/s (0.7824–0.9611), 216 mails/s (200–246) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=1 | 5.01 MiB/s (4.47–5.21), 80.12 mails/s (71.51–83.36) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=64KiB/conns=4 | 10.82 MiB/s (10.51–12.54), 173 mails/s (168–201) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=1 | 30.98 MiB/s (27.64–33.05), 30.98 mails/s (27.64–33.05) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=1MiB/conns=4 | 68.99 MiB/s (66.37–71.34), 68.99 mails/s (66.37–71.34) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=1 | 55.64 MiB/s (53.71–57.01), 5.56 mails/s (5.37–5.70) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=enc/size=10MiB/conns=4 | 138 MiB/s (108–143), 13.77 mails/s (10.79–14.27) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=enc$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=1 | 0.4114 MiB/s (0.3828–0.4880), 105 mails/s (98.00–125) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=4KiB/conns=4 | 0.9713 MiB/s (0.9269–0.9805), 249 mails/s (237–251) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=1 | 5.90 MiB/s (5.56–6.88), 94.44 mails/s (88.95–110) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=64KiB/conns=4 | 12.98 MiB/s (11.35–13.31), 208 mails/s (182–213) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=1 | 43.10 MiB/s (39.79–43.89), 43.10 mails/s (39.79–43.89) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=1MiB/conns=4 | 106 MiB/s (98.84–106), 106 mails/s (98.84–106) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=1 | 92.55 MiB/s (86.08–95.68), 9.26 mails/s (8.61–9.57) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=proto/size=10MiB/conns=4 | 205 MiB/s (198–225), 20.53 mails/s (19.80–22.47) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=proto$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=1 | 4.93 MiB/s (4.83–5.17), 1263 mails/s (1235–1324) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=4KiB/conns=4 | 9.16 MiB/s (8.43–10.76), 2346 mails/s (2159–2755) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=4KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=1 | 30.60 MiB/s (29.18–35.10), 490 mails/s (467–562) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=64KiB/conns=4 | 90.48 MiB/s (85.05–95.32), 1448 mails/s (1361–1525) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=64KiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=1 | 64.27 MiB/s (61.65–67.66), 64.27 mails/s (61.65–67.66) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=1MiB/conns=4 | 167 MiB/s (162–174), 167 mails/s (162–174) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=1MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=1 | 100 MiB/s (97.32–107), 10.03 mails/s (9.73–10.66) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=1$' -benchtime=1s ./internal/bench` |
| 1 | Receive/mode=plain/size=10MiB/conns=4 | 220 MiB/s (213–271), 21.97 mails/s (21.28–27.12) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=plain$/^size=10MiB$/^conns=4$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=off | 0.0163 s/sync (0.0158–0.0180) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=off$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/index=on | 0.3385 s/sync (0.3218–0.3527) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^index=on$' -benchtime=1s ./internal/bench` |
| 4 | Sync/mails=10000/list | 2.38 s/list (2.32–2.54) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^list$' -benchtime=1s ./internal/bench` |
| 5 | ServerMemory/size=64KiB/mails=1000/conns=20 | 1.55 heapinuse-base-MiB (1.52–1.60), 4.34 heapinuse-peak-MiB (4.28–4.43), 1.25 heapinuse-rest-MiB (1.20–1.32), 220 mails/s (206–223), 11.13 rss-base-MiB (11.10–11.19), 17.32 rss-peak-MiB (17.02–17.43), 13.46 rss-rest-MiB (13.32–13.61), 12.35 sys-base-MiB (12.27–12.53), 17.37 sys-peak-MiB (17.37–17.43), 17.37 sys-rest-MiB (17.37–17.43) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=64KiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 5 | ServerMemory/size=1MiB/mails=1000/conns=20 | 2.57 heapinuse-base-MiB (2.44–2.58), 10.09 heapinuse-peak-MiB (9.80–12.05), 1.34 heapinuse-rest-MiB (1.20–1.38), 83.88 mails/s (82.64–84.80), 12.12 rss-base-MiB (11.99–12.16), 24.32 rss-peak-MiB (22.84–26.11), 13.77 rss-rest-MiB (13.56–14.36), 12.28 sys-base-MiB (12.27–12.60), 25.18 sys-peak-MiB (21.37–25.43), 25.18 sys-rest-MiB (21.37–25.43) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=1MiB$/^mails=1000$/^conns=20$' -benchtime=1x ./internal/bench` |
| 2 | Index/pending=terms | 11500 B/mail (11487–11529), 117 allocs/mail, 53.70 µs/mail (50.84–59.40), 11499816 B/op (11486791–11528968), 116604 allocs/op (116594–116619) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=terms$' -benchtime=1s ./internal/bench` |
| 2 | Index/pending=unprocessed | 70502 B/mail (69458–71045), 684 allocs/mail, 819 µs/mail (802–847), 70501708 B/op (69457672–71045092), 683508 allocs/op (683473–683529) | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=unprocessed$' -benchtime=1s ./internal/bench` |
| 3 | IndexSegments/mails=1000 | 143600 B-merged, 193184 B-unmerged, 12074 B/segment, 16.00 segments, 1.00 segments-merged | `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndexSegments$/^mails=1000$' -benchtime=1x ./internal/bench` |

## Last und Steal je Gruppe

Load average (1, 5, 15 min) vor und nach jeder Gruppe; Steal = Anteil der Steal-Ticks an allen CPU-Ticks (`/proc/stat`, user bis steal) während der Gruppe.

| Gruppe | Beginn (UTC) | Ende (UTC) | Last vorher | Last nachher | Steal |
|---|---|---|---|---|---|
| `^BenchmarkReceive$` | 2026-11-04T01:17:54Z | 2026-11-04T01:21:42Z | 0.49/1.12/1.89 | 3.01/1.93/2.03 | 0.74 % |
| `^BenchmarkSync$` | 2026-11-04T01:23:32Z | 2026-11-04T01:24:43Z | 0.48/1.33/1.80 | 1.05/1.36/1.78 | 0.46 % |
| `^BenchmarkServerMemory$` | 2026-11-04T01:25:33Z | 2026-11-04T01:27:30Z | 0.45/1.14/1.68 | 2.93/1.81/1.86 | 0.43 % |
| `^BenchmarkIndex$` | 2026-11-04T01:29:20Z | 2026-11-04T01:30:51Z | 0.46/1.25/1.64 | 1.60/1.44/1.68 | 0.25 % |
| `^BenchmarkIndexSegments$` | 2026-11-04T01:32:11Z | 2026-11-04T01:32:38Z | 0.47/1.12/1.54 | 1.08/1.20/1.56 | 0.34 % |
