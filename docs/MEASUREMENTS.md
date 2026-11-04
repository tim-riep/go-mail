# Messungen (M1-Kriterium D)

Dieses Dokument beantwortet Ziel 5 des Plans („Messen, was die Verschlüsselung an Durchsatz kostet“, PLAN 1 und Meilenstein 7 in 11) mit Zahlen, die sich mit einem Befehl wiederholen lassen. Gemessen wurde am 4. November 2026 zwischen 01:00 und 01:33 UTC in zwei vollständigen Läufen von `scripts/bench.sh -count 5` auf dem Endstand (siehe „Code-Stand“). Messumgebung und Lockerungen: D77, Aufträge 12, 12b, 12c, 12d, 17 und 17b. Die Läufe vom 3. November auf dem Stand vor D93 (374f499) stehen am Ende im Abschnitt „Vergleich mit dem Stand vor D93“.

Rohdaten unter [`docs/measurements/2026-11-04/`](measurements/2026-11-04/):

| Datei | Inhalt |
|---|---|
| [`umgebung.txt`](measurements/2026-11-04/umgebung.txt) | `uname -a`, `nproc`, Modell- und Flagzeile aus `/proc/cpuinfo`, `free -m`, `df -h`, `stat -f`, Einhängeoptionen, `go version`, `go env`, Git-Commit, `uptime`, `/proc/stat` vor Lauf 1 |
| [`lauf1-raw.txt`](measurements/2026-11-04/lauf1-raw.txt), [`lauf2-raw.txt`](measurements/2026-11-04/lauf2-raw.txt) | Ausgabe von `go test` (benchstat-Format) mit Kopfzeilen zu Umgebung und Hardware, dazu je Gruppe `group-start`/`group-end` mit Uhrzeit, Load average und CPU-Ticks. Die Kopfzeile `command:` gibt den `go test`-Aufruf so wieder, wie ihn das Testprogramm sieht (ohne `-tags gomail_dev` und `-timeout 0`); der vollständige Befehl jeder Gruppe steht in `lauf*-stderr.txt` in der Zeile `bench.sh:` |
| [`lauf1-tabelle.md`](measurements/2026-11-04/lauf1-tabelle.md), [`lauf2-tabelle.md`](measurements/2026-11-04/lauf2-tabelle.md) | die von `bench.sh` erzeugte Tabelle eines Laufs: Median und Spanne der 5 Wiederholungen, jede Zahl mit dem Befehl, der sie einzeln nachmisst, alle Lockerungen |
| [`lauf1-stderr.txt`](measurements/2026-11-04/lauf1-stderr.txt), [`lauf2-stderr.txt`](measurements/2026-11-04/lauf2-stderr.txt) | Fortschrittsausgabe von `bench.sh`: je Gruppe der vollständige `go test`-Aufruf (Zeile `bench.sh:`), Last und Uhrzeit |
| [`nachtrag-17c.diff`](measurements/2026-11-04/nachtrag-17c.diff) | Änderungen an `internal/bench` und `scripts` nach der Messung (Aufträge 17c bis 17e, nur Prüfungen), siehe „Code-Stand“ |

Die Rohdaten vom 3. November liegen unverändert unter [`docs/measurements/2026-11-03/`](measurements/2026-11-03/) (gleiche Dateien ohne `nachtrag-17c.diff`).

Eine Lauftabelle lässt sich aus den Rohdaten ohne neue Messung wieder erzeugen: `env -u TMPDIR GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -render docs/measurements/2026-11-04/lauf1-raw.txt -count 5` gibt `lauf1-tabelle.md` bis auf die Zeile „Erzeugt mit …“ (Zeitpunkt, Commit) gleich aus; dasselbe gilt für Lauf 2 und für beide Läufe vom 3. November.

## Angaben, die für jede Zahl gelten

**Befehl.** Beide Läufe, aus der Wurzel des Repositorys:

```sh
export GOTOOLCHAIN=go1.26.10 GOMAIL_BENCH_MIN_FREE=0.1
scripts/bench.sh -count 5 -maxload 0.5 -o tabelle.md -raw raw.txt
```

`bench.sh` startet fünf Gruppen nacheinander, jede in einem eigenen `go test`-Prozess:

```sh
go test -tags gomail_dev -run '^$' -bench '<Gruppe>' -benchtime=<T> -count=5 -timeout 0 ./internal/bench
```

mit `<Gruppe>` = `^BenchmarkReceive$`, `^BenchmarkSync$`, `^BenchmarkIndex$` (je `-benchtime=1s`) und `^BenchmarkServerMemory$`, `^BenchmarkIndexSegments$` (je `-benchtime=1x`). Eine einzelne Zeile misst der Befehl in der Spalte „Befehl zum Nachmessen“ der Lauftabellen nach; dort steht das `-bench`-Muster je Zeile (etwa `'^BenchmarkReceive$/^mode=enc$/^size=1MiB$/^conns=4$'`), für Punkt 4 mit `GOMAIL_BENCH_SYNC_MAILS` (Standard 10 000), für Punkt 5 mit `GOMAIL_BENCH_MEM_MAILS` (Standard 1000) und `GOMAIL_BENCH_MEM_CONNS` (Standard 20). Der Schalter `-tags gomail_dev` ist nötig, weil `internal/bench` seine Plattform mit der Entwicklungszeremonie anlegt (`testenv`, `ceremony.InitDev`); er ändert nur das Paket `ceremony`, nicht `smtpd`, `ingest`, `store` oder `client`.

**Hardware und System** (aus `umgebung.txt` und den Kopfzeilen der Rohdaten):

| Merkmal | Wert |
|---|---|
| Maschine | virtuelle Maschine (Firecracker), gemeinsam genutzt |
| CPU | 4 vCPU, `Intel(R) Xeon(R) Processor @ 2.80GHz` (Modell vom Hypervisor verdeckt), `GOMAXPROCS=4`; Flags u. a. `aes`, `pclmulqdq`, `avx2`, `avx512f`, kein `sha_ni` |
| Speicher | 16 GiB (`MemTotal` 16 477 348 kB), kein Swap |
| Kernel | `Linux 6.18.44-fc-v230`, x86_64 |
| Datenverzeichnis der Messung | `/tmp` (`TMPDIR` nicht gesetzt, kein `-dir`), ext4 auf `/dev/vda` (virtio), Optionen `relatime,discard,resv_strict,resuid=65534` |
| Platz | 252 GiB, davon 10,8 % belegt (27,3 GiB, `Free` 58 891 500 von 66 053 021 Blöcken) und 11,1 GiB für Benutzer verfügbar (`Available` 2 917 378 Blöcke, 4,4 %); der übrige freie Platz (213,5 GiB) ist Reserve des Dateisystems (`resv_strict`). Am 3. November: 14,5 % belegt, 1,91 GiB für Benutzer verfügbar (`Available` 499 747 Blöcke, 0,76 %) |
| Go | `go1.26.10 linux/amd64`, `GOAMD64=v1` |

**Code-Stand.** Gemessen wurde im Worktree dieses Auftrags auf der Zusammenführung des Arbeitsbranchs (44cff6a, Endstand nach D93 und Auftrag 21) mit dem Messcode aus Auftrag 17 (`internal/bench`, `scripts/bench.sh`). Die Lauftabellen und `umgebung.txt` nennen dafür den Worktree-Commit 14bf604 ohne lokale Änderungen. Diese Kennung gibt es nach dem Zusammenfassen der Commits nicht mehr; nachprüfbar ist der Stand über die Bäume des Commits, der dieses Dokument einführt. Dieser Commit heißt unten `<commit>`; man findet ihn mit

```sh
git log --diff-filter=A --format=%H -- docs/MEASUREMENTS.md
```

Produktivcode: `cmd` und jedes Paket unter `internal` außer `internal/bench` haben in `<commit>` dieselben Bäume wie der gemessene Stand, `go.mod` und `go.sum` dieselben Dateien (Blob-Hashes):

| Pfad | Baum oder Blob (gemessen und in `<commit>`) |
|---|---|
| `cmd` | `04b277ee4b12c4b1587e40891160b3f55383f4bc` |
| `internal/ceremony` | `9f58deda2acb1639c64b66eb333fdcb2576de78d` |
| `internal/client` | `4f278df492d8a522e1c9ed3dd76b8e32b8213a93` |
| `internal/e2e` | `4ab31b7f6f2f73c38caffacc2cf5018ac163db1f` |
| `internal/envelope` | `22c49eb4ac62e6aefed70aee354d3e8c55ec47de` |
| `internal/ingest` | `41f2b1482c3c0c6fbb1a424701a602b8f5cc63f1` |
| `internal/keys` | `8ac313b49ba441a62f5c7d72aed2110e52d178e6` |
| `internal/loghttp` | `709fb8ef9ad3ba0a14416bb40805da712ef40dc3` |
| `internal/rec` | `ddca414a23dcd49005a02a227a0e47a5fce1fd70` |
| `internal/shamir` | `98d1220ed3ec0b1a2c75ed36bf37792ba0c327fa` |
| `internal/smtpd` | `7d3460d243b648435109384e0fa6539ac8290833` |
| `internal/store` | `9c24231d2f8119404f59a36aeccca2aa6cf5a0fb` |
| `internal/terms` | `62b9d654b0bf22aae442186baec17cf8fd166f05` |
| `internal/testenv` | `b760faa711698bf436403d18743816a2a50863f7` |
| `internal/translog` | `0b6c9cbf652bdff7c603bfeb0a6e3b69a9c7b205` |
| `internal/witness` | `d81f42895e63f5ff515eb01cc04c61a69726ddd6` |
| `internal/words` | `db9cfc4c67022bb24b4edfaa435d9d68f92b88b2` |
| `go.mod` | `c84b67cb8e13ce90d5bd2bd3b4be0a68cb0a7299` |
| `go.sum` | `0dc114aaf7c0364831d130056033d68156f55938` |

Nachprüfen: `git ls-tree <commit> cmd internal/ | grep -v 'internal/bench$'` gibt genau diese Bäume aus, einzeln `git rev-parse <commit>:cmd` und `git rev-parse <commit>:internal/<paket>`, die beiden Dateien mit `git rev-parse <commit>:go.mod <commit>:go.sum`. Im Produktivcode gleicht dieser Stand dem Endstand 9ad24a5 bis auf Kommentare: `git diff --stat 9ad24a5 <commit> -- internal cmd ':!internal/bench'` zeigt nur `internal/translog/doc.go` und `internal/translog/verifier.go` (31 Zeilen hinzu, 5 entfernt), und jede geänderte Zeile dort ist ein Kommentar (Hinweise zu `revoked_at_time` plus 1 ms und zur Kaskade bei `IsRevoked`, Aufträge 21d und 21e).

Messcode: Gemessen wurden die Bäume `internal/bench` = `7b69a4d652ac759d42e208ab913dbf42510c7da4` und `scripts` = `89594312e9602b00fae5730fc02fd688509a44c1`. Nach der Messung bekamen beide in den Aufträgen 17c, 17d und 17e nur Prüfungen: `bench.sh` gibt keine Tabelle aus unvollständigen Rohdaten aus (je Gruppe mindestens eine Benchmarkzeile, je Kennzahl genau `-count` Werte, sonst Exit 1), prüft `-maxload` und `-count` streng, bricht bei einer Option mit leerem Wert (etwa `-render=` oder `-o ""`) mit Exit 2 ab, bevor etwas läuft, und stellt mit `-render` vorhandene Rohdaten dar; dabei müssen `-benchtime`, `-count` und `GOMAIL_BENCH_MIN_FREE` zu den Zeilen `command:` und `env:` der Rohdaten passen, sonst Exit 1; in `internal/bench` ersetzt eine echte Prüfung von `GOMAIL_BENCH_MIN_FREE` einen Vergleich, der immer zutraf. Auftrag 17e (D94) ergänzt nur Eingabeprüfungen in `bench.sh`: Eine Option mit Wert (`-count`, `-benchtime`, `-maxload`, `-dir`, `-o`, `-raw`, `-render`) lehnt auch einen Wert ab, der mit `-` beginnt, mit Exit 2, bevor etwas läuft (bei `-o -render=F` las das Skript `-render=F` sonst als Wert von `-o` und startete eine Messung); mit `-render` verlangt jede Gruppe genau eine Zeile `command:` und eine Zeile `env:`, und die `env:`-Zeilen werden außer mit `GOMAIL_BENCH_MIN_FREE` auch mit `GOMAIL_BENCH_SYNC_MAILS`, `GOMAIL_BENCH_MEM_MAILS`, `GOMAIL_BENCH_MEM_CONNS` und `TMPDIR` dieses Aufrufs abgeglichen, sonst Exit 1. `git diff <commit> <17e> -- internal/bench scripts` zeigt nur `scripts/bench.sh`; `<17e>` ist der Commit, der `nachtrag-17c.diff` zuletzt geändert hat (`git log --format=%H -1 -- docs/measurements/2026-11-04/nachtrag-17c.diff`). Die Messlogik blieb gleich: dieselben Benchmarks, dieselben `go test`-Aufrufe, dieselbe Reihenfolge der Gruppen. Den Unterschied enthält [`nachtrag-17c.diff`](measurements/2026-11-04/nachtrag-17c.diff) (gemessener Stand gegen `<17e>`, nur `internal/bench` und `scripts`; bis 17d gegen `<commit>`). Nachprüfen in einem sauberen Checkout von `<17e>`:

```sh
git apply -R --index docs/measurements/2026-11-04/nachtrag-17c.diff
git write-tree --prefix=internal/bench/   # 7b69a4d652ac759d42e208ab913dbf42510c7da4
git write-tree --prefix=scripts/          # 89594312e9602b00fae5730fc02fd688509a44c1
```

Nach diesem Stand folgen die Aufträge 22 (`publish`, `checkRevocations`, `resolveExisting`) und 23 (das Ingest-Zertifikat wird einmal statt zweimal gelesen und je Generation und Kopf zwischengespeichert). Beide sind nicht gemessen (siehe „Grenzen der Messung“).

**Lockerungen gegenüber dem Plan (D77) und dieser Läufe.** Sie gelten nur im Testpaket `internal/bench`:

* `MaxConns` 64 statt 20, `MaxConnsPerIP` 64 statt 5, kein Mail-Limit je IP und Stunde (5.1). Der Lastgenerator läuft auf 127.0.0.1 und würde sonst abgewiesen.
* `MinFree` laut D77 1 % statt 10 %. **In beiden Läufen 0,1 %** (`GOMAIL_BENCH_MIN_FREE=0.1`, eingeführt mit Auftrag 17): Am 3. November waren für Benutzer nur 0,76 % des Dateisystems verfügbar (1,91 GiB), mit 1 % lehnte Ingest jede Mail mit `452 4.3.1` ab. Am 4. November waren 4,4 % verfügbar; der Befehl blieb nach Auftrag 17b derselbe, damit beide Tage vergleichbar sind. Die Platzprüfung läuft unverändert, zweimal `statfs` je Mail; nur die Schwelle ist niedriger. Die Kosten jeder Mail ändern sich dadurch nicht.
* Uhr eingefroren (kein Alters-Flush des Workers) und Logausgabe verworfen (Server und Ingest), bei Punkt 1 und 5. Bei den Punkten 2 bis 4 stellt die Zustellung des Korpus (Vorbereitung, nicht gemessen) die Uhr tageweise vor.
* Ingest prüft gegen den annehmenden Platzhalter `translogtest.Unverified`, nicht gegen das Betreiberlog (`testenv.New`). Die Clients arbeiten mit ihrem Client-Log auf dem echten Transparenzlog des Datenverzeichnisses (Auftrag 14). Das gilt auch für `Sync` und `List` in Punkt 4.
* Der Lastgenerator (`net/smtp`) läuft im selben Prozess und auf denselben 4 vCPU wie der Server.

**Ruhige Maschine.** Lauf 1 lief von 01:00:33 bis 01:16:28 UTC, Lauf 2 mit demselben Befehl von 01:17:54 bis 01:32:38 UTC; Lauf 2 hat der Orchestrator mit demselben Skript gestartet. Während der Messung galt die QUIET-Regel: Solange die Datei `QUIET` im Scratchpad des Orchestrators lag, starteten andere Agenten keine `go`-Befehle (`docs/tasks/23-platform-single-read.md`, „Ruhige Maschine“). Gesetzt wurde sie um 00:58 UTC, aufgehoben um 01:33 UTC (`docs/ORCHESTRATION.md`, Einträge vom 04.11. um 00:58 und 01:33 UTC). `bench.sh -maxload 0.5` wartet vor jeder Gruppe, bis die Last der letzten Minute unter 0,5 liegt, und notiert Last und CPU-Ticks vor und nach der Gruppe:

| Lauf | Gruppe | Beginn (UTC) | Last vorher (1/5/15 min) | Last nachher | Steal während der Gruppe |
|---|---|---|---|---|---|
| 1 | Receive | 01:00:33 | 0,41 / 2,28 / 3,01 | 2,70 / 2,39 / 2,89 | 0,72 % |
| 1 | Sync | 01:06:20 | 0,45 / 1,63 / 2,54 | 1,50 / 1,75 / 2,51 | 0,66 % |
| 1 | ServerMemory | 01:08:46 | 0,46 / 1,38 / 2,33 | 3,63 / 2,32 / 2,55 | 0,86 % |
| 1 | Index | 01:12:59 | 0,49 / 1,54 / 2,24 | 1,48 / 1,61 / 2,19 | 0,61 % |
| 1 | IndexSegments | 01:15:54 | 0,46 / 1,27 / 2,02 | 1,49 / 1,45 / 2,06 | 0,85 % |
| 2 | Receive | 01:17:54 | 0,49 / 1,12 / 1,89 | 3,01 / 1,93 / 2,03 | 0,74 % |
| 2 | Sync | 01:23:32 | 0,48 / 1,33 / 1,80 | 1,05 / 1,36 / 1,78 | 0,46 % |
| 2 | ServerMemory | 01:25:33 | 0,45 / 1,14 / 1,68 | 2,93 / 1,81 / 1,86 | 0,43 % |
| 2 | Index | 01:29:20 | 0,46 / 1,25 / 1,64 | 1,60 / 1,44 / 1,68 | 0,25 % |
| 2 | IndexSegments | 01:32:11 | 0,47 / 1,12 / 1,54 | 1,08 / 1,20 / 1,56 | 0,34 % |

Die Last der letzten Minute lag vor jeder Gruppe unter 0,5. Die Werte über 0,5 für 5 und 15 Minuten vor Lauf 1 stammen aus der Arbeit auf der Maschine vor der Messung, alle späteren aus der Messung selbst, weil die Gruppen kurz aufeinander folgen. Steal ist der Anteil der Steal-Ticks an allen CPU-Ticks (user bis steal in `/proc/stat`) zwischen `group-start` und `group-end`. Seit dem Start der Maschine lag er bei etwa 1,0 %.

**Lesart der Zahlen.** Jede Zelle ist der Median der 10 Wiederholungen beider Läufe (2 × 5), in Klammern der kleinste und der größte Wert dieser 10. Median und Spanne je Lauf stehen in den Lauftabellen; wie weit die Mediane der beiden Läufe auseinanderliegen, zeigt Punkt 1 unter „Wiederholbarkeit“.

## 1. Durchsatz beim Empfang mit und ohne Verschlüsselung

`BenchmarkReceive`: `smtpd` über `net/smtp` auf 127.0.0.1, eine Mail je Operation, Verbindungen bleiben offen, je Größenklasse ein Server, `-benchtime=1s`. Betriebsarten (D77):

* `enc`: Ingest vollständig (Verschlüsselung, Signaturen, Selbstprüfung, Metadaten, Marker, Worker mit Begriffslisten);
* `proto`: dasselbe Datei- und fsync-Protokoll samt Platzprüfung und Worker, ohne Kryptografie. Die Systemaufrufe im Messfenster gleichen denen von `enc` (12c);
* `plain`: Minimal-Senke, eine Datei mit einem fsync.

Verschlüsselungskosten = `enc − proto`, Protokollkosten = `proto − plain`. Was außer der Verschlüsselung in `enc − proto` steckt, steht in der Lauftabelle (Signaturen, Selbstprüfung, Kopfzeilen, Adressauflösung, `mailbox.rec`, Kettenprüfung über Cache, Hash über den Mailstrom, Termzerlegung).

Befehl je Zeile: `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkReceive$/^mode=<m>$/^size=<g>$/^conns=<c>$' -benchtime=1s -count=5 ./internal/bench`.

### Mails/s

| Größe | Verb. | `enc` | `proto` | `plain` |
|---|---|---|---|---|
| 4 KiB | 1 | 108 (88,8–130) | 119 (98,0–142) | 1264 (1207–1359) |
| 4 KiB | 4 | 217 (200–246) | 248 (220–275) | 2886 (2159–3558) |
| 64 KiB | 1 | 84,9 (71,5–91,2) | 97,9 (89,0–131) | 554 (467–633) |
| 64 KiB | 4 | 175 (144–201) | 211 (182–217) | 1508 (1361–1632) |
| 1 MiB | 1 | 30,5 (25,5–33,0) | 43,4 (39,5–45,5) | 66,3 (61,6–68,6) |
| 1 MiB | 4 | 68,9 (64,2–77,4) | 104 (95,9–108) | 176 (162–195) |
| 10 MiB | 1 | 5,81 (5,37–6,13) | 9,35 (8,61–11,2) | 10,8 (9,73–12,1) |
| 10 MiB | 4 | 13,4 (10,8–14,9) | 20,5 (16,3–22,5) | 22,6 (21,3–27,1) |

### MiB/s

MiB/s = Mails/s × Größe. Für 1 MiB sind beide Zahlen gleich.

| Größe | Verb. | `enc` | `proto` | `plain` |
|---|---|---|---|---|
| 4 KiB | 1 | 0,421 (0,347–0,506) | 0,464 (0,383–0,552) | 4,94 (4,72–5,31) |
| 4 KiB | 4 | 0,847 (0,782–0,961) | 0,970 (0,861–1,07) | 11,3 (8,43–13,9) |
| 64 KiB | 1 | 5,31 (4,47–5,70) | 6,12 (5,56–8,17) | 34,7 (29,2–39,6) |
| 64 KiB | 4 | 10,9 (9,03–12,5) | 13,2 (11,3–13,6) | 94,3 (85,0–102) |
| 1 MiB | 1 | 30,5 (25,5–33,0) | 43,4 (39,5–45,5) | 66,3 (61,6–68,6) |
| 1 MiB | 4 | 68,9 (64,2–77,4) | 104 (95,9–108) | 176 (162–195) |
| 10 MiB | 1 | 58,1 (53,7–61,3) | 93,5 (86,1–112) | 108 (97,3–121) |
| 10 MiB | 4 | 134 (108–149) | 205 (163–225) | 226 (213–271) |

### Was die Verschlüsselung kostet

Zeit je Mail aus den Medianen (1000 / Mails/s):

| Größe | Verb. | `enc` ms/Mail | `proto` ms/Mail | `plain` ms/Mail | `enc − proto` ms/Mail | `enc / proto` (Durchsatz) | `proto − plain` ms/Mail |
|---|---|---|---|---|---|---|---|
| 4 KiB | 1 | 9,29 | 8,43 | 0,791 | 0,86 | 0,91 | 7,6 |
| 4 KiB | 4 | 4,61 | 4,03 | 0,347 | 0,59 | 0,87 | 3,7 |
| 64 KiB | 1 | 11,8 | 10,2 | 1,80 | 1,6 | 0,87 | 8,4 |
| 64 KiB | 4 | 5,72 | 4,74 | 0,663 | 0,98 | 0,83 | 4,1 |
| 1 MiB | 1 | 32,8 | 23,0 | 15,1 | 9,7 | 0,70 | 8,0 |
| 1 MiB | 4 | 14,5 | 9,61 | 5,67 | 4,9 | 0,66 | 3,9 |
| 10 MiB | 1 | 172 | 107 | 92,6 | 65 | 0,62 | 14 |
| 10 MiB | 4 | 74,3 | 48,8 | 44,2 | 26 | 0,66 | 4,6 |

### Wiederholbarkeit

Median von Lauf 1 / Lauf 2 in Mails/s, in Klammern die Abweichung von Lauf 2 gegenüber Lauf 1:

| Größe | Verb. | `enc` | `proto` | `plain` |
|---|---|---|---|---|
| 4 KiB | 1 | 113 / 96,1 (−15 %) | 134 / 105 (−21 %) | 1266 / 1263 (0 %) |
| 4 KiB | 4 | 217 / 216 (0 %) | 235 / 249 (+6 %) | 3286 / 2346 (−29 %) |
| 64 KiB | 1 | 90,5 / 80,1 (−11 %) | 98,2 / 94,4 (−4 %) | 602 / 490 (−19 %) |
| 64 KiB | 4 | 176 / 173 (−2 %) | 212 / 208 (−2 %) | 1518 / 1448 (−5 %) |
| 1 MiB | 1 | 30,1 / 31,0 (+3 %) | 44,1 / 43,1 (−2 %) | 66,4 / 64,3 (−3 %) |
| 1 MiB | 4 | 68,7 / 69,0 (0 %) | 102 / 106 (+3 %) | 191 / 167 (−13 %) |
| 10 MiB | 1 | 6,06 / 5,56 (−8 %) | 9,69 / 9,26 (−4 %) | 11,3 / 10,0 (−11 %) |
| 10 MiB | 4 | 12,1 / 13,8 (+14 %) | 19,1 / 20,5 (+7 %) | 22,7 / 22,0 (−3 %) |

Ergebnis:

* **Kleine Mails (4 KiB, 64 KiB):** Den Durchsatz bestimmt das Ablageprotokoll, nicht die Verschlüsselung. `proto − plain` liegt bei 7,6 bis 8,4 ms je Mail mit einer Verbindung und bei rund 4 ms mit vier. Das sind etwa 17 fsync und 3 `renameat` je Mail gegenüber einem fsync bei `plain` (12b). `enc` kostet 0,6 bis 1,6 ms je Mail mehr als `proto` (Durchsatz 0,83 bis 0,91 von `proto`). Das liegt innerhalb der Spannen: Bei 4 KiB mit einer Verbindung überlappen sich die Spannen von `enc` (88,8–130) und `proto` (98,0–142) fast ganz.
* **Große Mails (1 MiB, 10 MiB):** Die Verschlüsselung kostet 30 bis 38 % des Durchsatzes (`enc / proto` 0,62 bis 0,70). Bei 10 MiB sind das rund 65 ms je Mail mit einer Verbindung; 10 MiB in 65 ms entsprechen rund 150 MiB/s. Mit vier Verbindungen sind es rund 26 ms je Mail. `enc` erreicht dann rund 58 MiB/s (eine Verbindung) und 134 MiB/s (vier), `proto` 94 und 205 MiB/s.
* **Wiederholbarkeit:** Die Mediane von `enc` liegen zwischen den Läufen höchstens 15 % auseinander, bei `proto` bis 21 %, bei `plain` bis 29 %. Innerhalb eines Laufs reicht die Spanne bis zum Faktor 1,38 (`enc` 64 KiB mit vier Verbindungen in Lauf 1: 144 bis 199 Mails/s), über beide Läufe bis zum Faktor 1,65 (`plain` 4 KiB mit vier Verbindungen). Unterschiede unter etwa 20 % sind auf dieser Maschine nicht belastbar.

## 2. Kosten der Indexierung im Client je Mail

`BenchmarkIndex`: `client.Index` über 1000 Mails des Korpus (10 Absender, 3 Empfänger, 30 Tage, 20 % Anhänge, Threads), je Operation. Vor jeder Operation werden außerhalb der Zeitmessung die Segmente gelöscht und `pending/` wiederhergestellt. `terms` = Begriffslisten des Ingest-Workers; `unprocessed` = nur Marker: Der Client liest und prüft die Metadaten jeder Mail selbst und löscht jede Markerdatei einzeln (ein fsync je Mail).

Befehl: `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndex$/^pending=<art>$' -benchtime=1s -count=5 ./internal/bench`

| `pending/` | µs/Mail | Allokationen/Mail | Bytes/Mail |
|---|---|---|---|
| `terms` | 58,5 (50,8–64,4) | 117 | 11 518 (11 487–11 543) |
| `unprocessed` | 876 (802–1113) | 684 | 69 993 (69 458–71 047) |

Mit Begriffslisten des Servers kostet die Indexierung rund 0,06 ms je Mail (10 000 Mails in etwa 0,6 s). Ohne sie (Marker `unprocessed`, etwa nach einem Neustart des Servers mit verlorener Vorverarbeitung, 5.3) kostet sie rund 0,9 ms je Mail, also das 15-Fache. Den Großteil davon machen das Lesen und Prüfen der Metadaten und das Löschen jeder Markerdatei mit fsync aus.

## 3. Größe der Indexsegmente je 1000 Mails

`BenchmarkIndexSegments`: 1000 Mails des Korpus im November 2026 (eine Epoche), in 16 Teilen zugestellt, nach jedem Teil `client.Index` (ein Segment je Lauf). Der 16. Lauf fasst zusammen. Gezählt werden die Bytes aller `index/<n>/*.gml` über `store`. Die Größen hängen nicht von der Maschine ab und waren in allen 10 Wiederholungen gleich.

Befehl: `GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkIndexSegments$/^mails=1000$' -benchtime=1x -count=5 ./internal/bench`

| Zustand | Segmente | Bytes | Bytes je Mail |
|---|---|---|---|
| vor dem Zusammenfassen (alle 1000 Mails) | 16 | 193 184 (12 074 je Segment) | 193 |
| nach dem Zusammenfassen | 1 | 143 600 | 144 |

Das Zusammenfassen spart 26 %. Hochgerechnet belegen 10 000 Mails zusammengefasst etwa 1,4 MB Index; das ist eine Hochrechnung, keine Messung.

## 4. Sync bei 10 000 Mails

`BenchmarkSync/mails=10000`: ein Postfach mit 10 000 Mails des Korpus, über Ingest zugestellt (Vorbereitung, nicht gemessen). Der Client ist offen und arbeitet mit seinem Client-Log auf dem echten Transparenzlog des Datenverzeichnisses. `Sync` hält den Epochenvorrat und ruft `client.Index` auf.

* `index=off`: `pending/` leer, alles schon indexiert;
* `index=on`: `pending/` wie nach der Zustellung (Begriffslisten aller 10 000 Mails), vor jedem `Sync` außerhalb der Zeitmessung wiederhergestellt, Segmente gelöscht;
* `list`: `client.List` über alle 10 000 Mails des Eingangs. **Kein Teil von `Sync`**, getrennt ausgewiesen: Das ist der Schritt, dessen Kosten mit der Zahl der Mails wachsen, solange `Sync` keine Mails liest.

Befehl: `GOMAIL_BENCH_SYNC_MAILS=10000 GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkSync$/^mails=10000$/^<teil>$' -benchtime=1s -count=5 ./internal/bench`

| Teil | Dauer |
|---|---|
| `Sync`, `index=off` | 0,0173 s (0,0158–0,0184) |
| `Sync`, `index=on` | 0,347 s (0,322–0,373) |
| `List` (kein Teil von `Sync`) | 2,46 s (2,32–2,78) |

Ein `Sync` ohne neue Mails dauert rund 17 ms. Mit den Begriffslisten aller 10 000 Mails dauert er rund 0,35 s, etwa 35 µs je Mail. Punkt 2 misst mit 1000 Mails je Lauf rund 59 µs je Mail; woher der Unterschied kommt, ist nicht untersucht. `List` über alle 10 000 Mails braucht rund 2,5 s (etwa 0,25 ms je Mail) und ist damit der teuerste der drei gemessenen Schritte.

## 5. Speicherbedarf des Servers

`BenchmarkServerMemory`: 1000 Mails über 20 Verbindungen gegen `smtpd` + Ingest (`enc`). Jede Wiederholung läuft in einem eigenen Kindprozess. `base` = vor der Last, `peak` = höchster Wert während der Last (abgetastet alle 20 ms, kürzere Spitzen fehlen), `rest` = Ruhewert nach der Last. Grund- und Ruhewert werden gleich vorbereitet: 1 s Leerlauf, dann `debug.FreeOSMemory()`, dann Messung. Der Lastgenerator läuft im selben Prozess; seine Verbindungspuffer zählen mit.

Befehl: `GOMAIL_BENCH_MEM_MAILS=1000 GOMAIL_BENCH_MIN_FREE=0.1 go test -tags gomail_dev -run '^$' -bench '^BenchmarkServerMemory$/^size=<g>$/^mails=1000$/^conns=20$' -benchtime=1x -count=5 ./internal/bench`

| Größe | Wert (MiB) | base | peak | rest |
|---|---|---|---|---|
| 64 KiB | VmRSS | 11,11 (11,02–11,19) | 17,28 (17,02–17,43) | 13,44 (13,32–13,61) |
| 64 KiB | Sys | 12,27 (8,28–12,53) | 17,37 (13,12–17,43) | 17,37 (13,12–17,43) |
| 64 KiB | HeapInuse | 1,53 (1,45–1,60) | 4,32 (4,26–4,45) | 1,25 (1,16–1,32) |
| 1 MiB | VmRSS | 12,04 (11,99–12,16) | 24,34 (22,84–26,11) | 13,77 (13,42–14,36) |
| 1 MiB | Sys | 12,28 (12,27–12,60) | 25,12 (21,37–25,43) | 25,12 (21,37–25,43) |
| 1 MiB | HeapInuse | 2,47 (2,44–2,58) | 11,04 (9,80–13,64) | 1,25 (1,17–1,38) |

Durchsatz während der Last: 203 (166–223) Mails/s bei 64 KiB und 79,3 (67,5–84,8) Mails/s bei 1 MiB.

Der Server samt Lastgenerator bleibt unter Last mit 20 Verbindungen unter 27 MiB VmRSS. Nach der Last fällt der Heap unter den Grundwert: `HeapInuse` rest 1,25 MiB gegenüber base 1,53 MiB bei 64 KiB und 2,47 MiB bei 1 MiB; VmRSS liegt 1,7 bis 2,3 MiB über dem Grundwert. `Sys` gibt die Laufzeit nicht an das System zurück, `Sys` rest gleicht deshalb `Sys` peak; `Sys` wächst in Schritten von 4 MiB. Der Bedarf wächst mit der Größe der Mails nur wenig (Datenstrom in 64-KiB-Blöcken, 5.2): 1 MiB statt 64 KiB erhöht die Spitze um rund 7 MiB VmRSS.

## Kennzahlen auf einen Blick

Median aus 10 Wiederholungen (zwei Läufe zu je 5), in Klammern der kleinste und der größte Wert. Befehl, Hardware, Commit und Lockerungen wie unter „Angaben, die für jede Zahl gelten“: `GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -count 5 -maxload 0.5`, 4 vCPU Xeon 2,8 GHz (Firecracker, 16 GiB, ext4 auf virtio), Code-Stand wie unter „Code-Stand“ (Produktivcode gleich 9ad24a5 bis auf Kommentare, Kennung in den Rohdaten 14bf604), Lockerungen aus D77 (`MaxConns` und `MaxConnsPerIP` 64, kein Mail-Limit je IP, eingefrorene Uhr, verworfenes Log) und `MinFree` 0,1 % statt 1 %.

| Kennzahl | Median (Spanne) |
|---|---|
| Empfang 4 KiB, 1 Verbindung, `enc` | 108 (88,8–130) Mails/s |
| Empfang 4 KiB, 1 Verbindung, `proto` | 119 (98,0–142) Mails/s |
| Empfang 4 KiB, 1 Verbindung, `plain` | 1264 (1207–1359) Mails/s |
| Empfang 64 KiB, 1 Verbindung, `enc` | 84,9 (71,5–91,2) Mails/s |
| Empfang 64 KiB, 1 Verbindung, `proto` | 97,9 (89,0–131) Mails/s |
| Empfang 1 MiB, 4 Verbindungen, `enc` | 68,9 (64,2–77,4) MiB/s |
| Empfang 1 MiB, 4 Verbindungen, `proto` | 104 (95,9–108) MiB/s |
| Empfang 1 MiB, 4 Verbindungen, `plain` | 176 (162–195) MiB/s |
| Empfang 10 MiB, 1 Verbindung, `enc` | 58,1 (53,7–61,3) MiB/s |
| Empfang 10 MiB, 1 Verbindung, `proto` | 93,5 (86,1–112) MiB/s |
| Empfang 10 MiB, 1 Verbindung, `plain` | 108 (97,3–121) MiB/s |
| Empfang 10 MiB, 4 Verbindungen, `enc` | 134 (108–149) MiB/s |
| Empfang 10 MiB, 4 Verbindungen, `proto` | 205 (163–225) MiB/s |
| Empfang 10 MiB, 4 Verbindungen, `plain` | 226 (213–271) MiB/s |
| Durchsatzanteil `enc / proto` aus den Medianen, 1 und 10 MiB | 0,62 bis 0,70 |
| Indexierung je Mail, `terms` | 58,5 (50,8–64,4) µs |
| Indexierung je Mail, `unprocessed` | 876 (802–1113) µs |
| Index je 1000 Mails, 16 Segmente / zusammengefasst | 193 184 / 143 600 Bytes (alle 10 gleich) |
| `Sync` bei 10 000 Mails, `index=off` | 0,0173 (0,0158–0,0184) s |
| `Sync` bei 10 000 Mails, `index=on` | 0,347 (0,322–0,373) s |
| `List` über 10 000 Mails (kein Teil von `Sync`) | 2,46 (2,32–2,78) s |
| Server-VmRSS, 1000 Mails à 1 MiB, 20 Verbindungen, base | 12,04 (11,99–12,16) MiB |
| Server-VmRSS, 1000 Mails à 1 MiB, 20 Verbindungen, peak | 24,34 (22,84–26,11) MiB |
| Server-VmRSS, 1000 Mails à 1 MiB, 20 Verbindungen, rest | 13,77 (13,42–14,36) MiB |

## Grenzen der Messung

* **Geteilte virtuelle Maschine mit 4 vCPU.** Die Maschine ist eine Firecracker-VM auf einem geteilten Host. Steal lag während der Gruppen bei 0,25 bis 0,86 %; Störungen anderer Gäste des Hosts sieht die VM nur als Steal und als schwankende Plattenlatenz. Der Lastgenerator teilt sich die 4 vCPU mit dem Server; mit 4 Verbindungen konkurrieren Generator, Server und Ingest-Worker um dieselben Kerne. Das CPU-Modell ist verdeckt („Intel(R) Xeon(R) Processor @ 2.80GHz“). Der Gast meldet `aes`, `pclmulqdq`, `avx2` und `avx512f` (Flagzeile in `umgebung.txt`). Auf einer CPU ohne diese Erweiterungen kostet die Verschlüsselung mehr.
* **Geteilte Platte.** Datenverzeichnis und Go-Cache liegen auf demselben ext4 auf `/dev/vda` (virtio, `discard`), das auch andere Arbeitsbäume trägt. Wie der Host fsync umsetzt (Schreibcache, Speichermedium), ist unbekannt. Gerade die kleinen Mails hängen an der fsync-Latenz (`proto − plain` 4 bis 8 ms je Mail). Die Zahlen sagen deshalb über eine Maschine mit lokaler SSD wenig. Zwischen den Läufen schwanken die Mediane bis 29 %, innerhalb eines Laufs reicht die Spanne bis zum Faktor 1,38.
* **Platz.** Am 4. November waren 10,8 % des Dateisystems belegt und 4,4 % für Benutzer verfügbar (11,1 GiB), am 3. November 14,5 % belegt und 0,76 % verfügbar (1,91 GiB). Der übrige freie Platz ist Reserve (`resv_strict`); voll war das Dateisystem an keinem der Tage, knapp war nur der Platz, der Benutzern zur Verfügung steht. Beide Tage liefen mit `MinFree` 0,1 % statt der 1 % aus D77 (`GOMAIL_BENCH_MIN_FREE=0.1`). Die Prüfung selbst (zwei `statfs` je Mail) ist enthalten. Mit 10 % nach 5.1 würde der Server auf dieser Maschine keine Mail annehmen. Ob der Unterschied in Belegung und verfügbarem Platz die Zuteilung von Blöcken und damit fsync beeinflusst, ist nicht getrennt gemessen; er ist ein Grund, die beiden Tage nur vorsichtig zu vergleichen.
* **Seitencache.** Mit 16 GiB RAM bleiben alle geschriebenen Dateien im Seitencache; Lesezugriffe (`List`, Index mit `unprocessed`, Kettenprüfung) messen den Cache, nicht die Platte. Kalte Caches wurden nicht gemessen.
* **Keine NFS-Messung.** Es gibt hier weder NFS noch eine zweite Maschine (D83). Für ein Datenverzeichnis über NFSv4, wie es 9.1 für getrennte Server und Clients vorsieht, ist mit deutlich höheren Kosten je fsync, Umbenennung und Sperre zu rechnen; dazu gibt es keine Zahl.
* **Builds ohne `-race`.** Gemessen wurde wie im Betrieb ohne Race-Detektor (`bench.sh` setzt kein `-race`). Die Testläufe der Vorgaben laufen mit `-race`, das die Ausführung um ein Vielfaches verlangsamt und Allokationen verändert. Zeiten aus solchen Läufen (etwa Laufzeiten in HANDOFF) sind mit diesen Zahlen nicht vergleichbar. Umgekehrt sagen diese Zahlen nichts über das Verhalten unter `-race`. Gemessen wurde eine Test-Binärdatei mit `-tags gomail_dev`. Der Schalter betrifft nur `ceremony`; die gemessenen Pfade gleichen dem Produktionsbuild.
* **Server ohne Betreiberlog.** Ingest prüft in den Messungen gegen den annehmenden Platzhalter `translogtest.Unverified`, nicht gegen das Transparenzlog wie `gomail-server serve`. Die Prüfung von Benutzer, Epoche, Adresse und Zertifikat gegen das Log (seit D93 samt Widerrufsliste aus Pin-Feld 7) fehlt deshalb in `enc` und in Punkt 5. Die Prüfungen von D93 gegen das Log liegen damit nicht im Messpfad des Empfangs: Ingest läuft gegen `translogtest.Unverified` (`internal/bench/rig_test.go:99`, `testenv.New`), und D93 ändert in `ingest` nur `New` (Widerrufsliste `Config.Revoked`, geprüft einmal beim Start, nicht je Mail). Eine Messung mit `testenv.NewLogged` steht aus.
* **Aufträge 22 und 23 nicht gemessen.** Gemessen ist der Stand vor den Aufträgen 22 (`publish`, `checkRevocations`, `resolveExisting`) und 23 (das Ingest-Zertifikat wird einmal statt zweimal gelesen und je Generation und Kopf zwischengespeichert). Beide berühren keinen Pfad, der je Mail läuft; Auftrag 23 spart beim Laden eines Zertifikats ein Lesen. Zahlen für den Stand danach gibt es nicht.
* **Eingefrorene Uhr, verworfenes Log.** Ohne Alters-Flush schreibt der Worker bei Punkt 1 und 5 Begriffslisten nur nach je 100 Mails. Bei 4 KiB und 64 KiB mit einer Verbindung liegt b.N bei etwa 1 s Messzeit um 100 (`enc` 73 bis 150, `proto` 100 bis 196). Ob eine Begriffsliste ins Messfenster fällt, wechselt deshalb von Wiederholung zu Wiederholung; das erklärt einen Teil der Streuung dort. Die Kosten der Logausgabe im Betrieb sind nicht enthalten.
* **Wenige Mails bei 10 MiB.** Bei `-benchtime=1s` misst eine Wiederholung bei `enc` mit 10 MiB nur 6 bis 18 Mails; jede einzelne Verzögerung der Platte wirkt sich voll aus.
* **Wachsende Postfächer.** Bei Punkt 1 dient ein Server allen 5 Wiederholungen und beiden Verbindungszahlen einer Größenklasse. Bei `enc` wächst das Postfachverzeichnis über die Wiederholungen hinweg; spätere Wiederholungen schreiben in größere Verzeichnisse.
* **Loopback.** SMTP läuft über 127.0.0.1 ohne Netzlatenz und ohne TLS (5.1); die Zahlen sind eine Obergrenze für den Empfang über ein Netz.

## Vergleich mit dem Stand vor D93

Am 3. November wurde mit demselben Befehl (`GOMAIL_BENCH_MIN_FREE=0.1 scripts/bench.sh -count 5 -maxload 0.5`, zwei Läufe) auf derselben Maschine der Produktivcode von 374f499 gemessen, der Stand vor D93 (Widerruf über Pin-Feld 7, Auftrag 21), mit demselben Messcode wie am 4. November: Code-Basis ist 374f499, `cmd` und die Pakete unter `internal` außer `internal/bench` hatten dieselben Bäume wie in 374f499 (`git rev-parse 374f499:cmd`, `git rev-parse 374f499:internal/<paket>`), der Messcode die Bäume `internal/bench` = `7b69a4d652ac759d42e208ab913dbf42510c7da4` und `scripts` = `89594312e9602b00fae5730fc02fd688509a44c1`, dieselben wie am 4. November gemessen. Die Lauftabellen nennen dafür die Worktree-Commits d633f55 (Lauf 1) und b72d1d7 (Lauf 2) als Kennung, `umgebung.txt` den Worktree-Commit 93b87b2; vor dem Zusammenfassen geprüft: alle drei mit denselben beiden Bäumen, Produktivcode sowie `go.mod` und `go.sum` gleich 374f499. Rohdaten: [`docs/measurements/2026-11-03/`](measurements/2026-11-03/). Seitdem haben sich unter anderem `ingest`, `client`, `store` und `translog` geändert (`git diff --stat 374f499 9ad24a5 -- internal cmd ':!internal/bench'`). Verglichen wird je Kennzahl der Median aller 10 Wiederholungen eines Tages, Abweichung = 04.11. gegenüber 03.11. Für den Empfang ist ein höherer Wert besser, für Zeiten ein niedrigerer.

Empfang in Mails/s (03.11. → 04.11.):

| Größe | Verb. | `enc` | `proto` | `plain` |
|---|---|---|---|---|
| 4 KiB | 1 | 78,6 → 108 (+37 %) | 93,5 → 119 (+27 %) | 1118 → 1264 (+13 %) |
| 4 KiB | 4 | 193 → 217 (+12 %) | 188 → 248 (+32 %) | 2768 → 2886 (+4 %) |
| 64 KiB | 1 | 64,5 → 84,9 (+32 %) | 90,6 → 97,9 (+8 %) | 478 → 554 (+16 %) |
| 64 KiB | 4 | 163 → 175 (+8 %) | 166 → 211 (+27 %) | 1280 → 1508 (+18 %) |
| 1 MiB | 1 | 25,3 → 30,5 (+21 %) | 33,8 → 43,4 (+28 %) | 65,9 → 66,3 (+1 %) |
| 1 MiB | 4 | 53,4 → 68,9 (+29 %) | 94,8 → 104 (+10 %) | 164 → 176 (+8 %) |
| 10 MiB | 1 | 4,89 → 5,81 (+19 %) | 8,41 → 9,35 (+11 %) | 9,85 → 10,8 (+10 %) |
| 10 MiB | 4 | 8,05 → 13,4 (+67 %) | 17,3 → 20,5 (+18 %) | 20,9 → 22,6 (+8 %) |

Übrige Kennzahlen:

| Kennzahl | Einheit | 03.11. | 04.11. | Abweichung |
|---|---|---|---|---|
| Indexierung `terms` | µs/Mail | 68,3 | 58,5 | −14 % |
| Indexierung `unprocessed` | µs/Mail | 1066 | 876 | −18 % |
| Allokationen je Mail, `unprocessed` | | 682 | 684 | 0 % |
| Index je 1000 Mails, 16 Segmente | Bytes | 193 184 | 193 184 | 0 % |
| Index je 1000 Mails, zusammengefasst | Bytes | 143 600 | 143 600 | 0 % |
| `Sync`, `index=off` | s | 0,0210 | 0,0173 | −18 % |
| `Sync`, `index=on` | s | 0,402 | 0,347 | −14 % |
| `List` über 10 000 Mails | s | 2,89 | 2,46 | −15 % |
| Speicher 64 KiB: VmRSS base / peak / rest | MiB | 11,09 / 17,40 / 13,54 | 11,11 / 17,28 / 13,44 | 0 / −1 / −1 % |
| Speicher 64 KiB: HeapInuse peak | MiB | 4,41 | 4,32 | −2 % |
| Speicher 64 KiB: Sys peak | MiB | 13,37 | 17,37 | +30 % |
| Speicher 64 KiB: Mails/s unter Last | | 164 | 203 | +24 % |
| Speicher 1 MiB: VmRSS base / peak / rest | MiB | 12,02 / 23,94 / 13,71 | 12,04 / 24,34 / 13,77 | 0 / +2 / 0 % |
| Speicher 1 MiB: HeapInuse peak | MiB | 10,53 | 11,04 | +5 % |
| Speicher 1 MiB: Sys peak | MiB | 23,30 | 25,12 | +8 % |
| Speicher 1 MiB: Mails/s unter Last | | 62,4 | 79,3 | +27 % |

Lesart:

* Am 4. November war jede Empfangszahl höher als am 3. November, bei `enc` um 8 bis 67 %, bei `proto` um 8 bis 32 %. Auch `plain` war um 1 bis 18 % schneller, obwohl `plain` nur `smtpd` und die Minimal-Senke aus `internal/bench` benutzt und beide an beiden Tagen gleich waren (`smtpd` seit 374f499 unverändert, der Messcode derselbe). Ein Teil des Unterschieds liegt also an der Umgebung, nicht am Code. Der deutlichste Unterschied der Umgebung ist der Platz: am 4. November 10,8 % belegt und 4,4 % für Benutzer verfügbar (11,1 GiB), am 3. November 14,5 % belegt und 0,76 % verfügbar (1,91 GiB). Dazu kommen andere Tageszeit und andere Last auf dem geteilten Host. Wie viel davon auf den Platz entfällt, ist nicht gemessen. Über D93 sagen die Empfangszahlen nichts, weil die Prüfungen von D93 gegen das Log nicht im Messpfad des Empfangs liegen (siehe „Server ohne Betreiberlog“ unter „Grenzen der Messung“).
* Im Client sind Indexierung, `Sync` und `List` um 14 bis 18 % schneller. Auch hier lässt sich Code nicht von Umgebung trennen.
* Was nicht von der Maschine abhängt, ist gleich geblieben oder fast gleich: Die Segmentgrößen sind auf das Byte gleich, die Allokationen je Mail bei `terms` gleich (117) und bei `unprocessed` um 2 höher (684 statt 682). VmRSS und `HeapInuse` liegen innerhalb von 5 %. `Sys` steigt in Schritten von 4 MiB; der Median von `Sys` peak bei 64 KiB lag am 3. November eine Stufe tiefer.
* Ergebnis: Für die Client-Zahlen (Indexierung, `Sync` und `List` mit echtem Log) zeigen die Zahlen keine Verlangsamung durch D93. Für den Empfang gilt diese Aussage nicht: Die Prüfungen von D93 gegen das Log liegen dort nicht im Messpfad, Ingest läuft gegen `translogtest.Unverified` (`internal/bench/rig_test.go:99`), und D93 ändert in `ingest` nur `New`. Wie viel D93 kostet oder spart, lässt sich wegen der geänderten Umgebung nicht beziffern; dafür müssten 374f499 und der Endstand abwechselnd im selben Zeitfenster gemessen werden.
