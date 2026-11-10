# Übergabe nach M1

Stand: 04.11.2026, Abschluss mit Auftrag 20r. Endstand des Codes für M1 ist fba4eb2 im Arbeitsbranch `claude/quirky-keller-hjsl5i`: 9ad24a5 mit Auftrag 22 (afad8de) und Auftrag 23 mit der Nacharbeit 23b (fba4eb2). Spätere Commits ändern nichts unter `internal` und `cmd` (`git diff --stat fba4eb2 HEAD -- internal cmd` leer); außer Dokumenten ändert nur 17e (4f247c6) `scripts/bench.sh`. Was 22 und 23 geändert haben, steht im „Nachtrag 20r“ unten. Eingetragen sind der Abschluss-Volllauf auf 9ad24a5 (`fr-final`, 67 von 67 Schritten grün), die Abdeckung am Endstand und die Messungen (Kriterien D und E). Volllauf auf dem Endstand (`fr-m1`): 67 von 67 Schritten grün, kein Fehler. Die folgenden Absätze bis zum Nachtrag 20r geben die früheren Stände wieder.

**Nachtrag 24g (Code-Stand: Arbeitsbranch nach Auftrag 24, 8a58052; je Paket ein Commit: A 12f86fe, B 049d478, C bc3edd3, D ba8434d, E 89fd0d5, F 8a58052, Dokumente d8f474c; Volllauf auf derselben Quelle im Code (lokal 7dfd935, `orch/fr-n24/`): 67 von 67 Schritten grün, 00:14 bis 02:02 UTC am 10.11., über einen Container-Neustart um 01:28 UTC fortgesetzt):** Nach M1 setzt Auftrag 24 (`docs/tasks/24-nach-m1-nacht1.md`, 09./10.11.2026) Punkte der Liste nach M1 um (`docs/tasks/backlog-nach-m1.md`, Nr. 7 (Teil), 37, 41, 52, 53 und 54 bis 63). Sechs Pakete:
- A, `internal/ceremony` (`publish.go`): Ein Link unter einem Namen des Exports gilt nie als dessen Datei; er wird ersetzt, wenn der Name frei ist, sonst verweigert `publish` vor dem Schreiben (D93 Nachtrag 24, AUDIT R17 (b), RUNBOOK 7.3).
- B, `internal/client` (`client.go`): `resolveExisting` löst Stück für Stück und fail closed auf (D86 Nachtrag 24 B, AUDIT R33, RUNBOOK 3.2).
- C, `cmd/gomail-server` (`main.go`): `address add` prüft `admin-<gen>.cert` auf Signatur und gegen das Log und setzt `valid_from` = max(jetzt, letzter gültiger Wert + 1 ms) bis `translog.MaxClockSkew` (D80 Nachtrag 24 C, D93 Nachtrag 24, AUDIT R48, RUNBOOK 4.2).
- D, `internal/loghttp`: Inhaltstyp vor dem Körper, höchstens `MaxVerifying` Signaturprüfungen zugleich, `Connection: close` bei frühen Antworten (D80 Nachtrag 24 D, AUDIT R8). Die Nachprüfung der Nacharbeit D2 fand nichts über niedrig.
- E: Marken und Texte nach M1 (`translogtest`, `translog/doc.go`, `ErrNoLog`, `scripts/two-host-test.sh`), Testhaken für das einmalige Lesen in `store`, `scripts/bench.sh -render` (D94 Nachtrag 24 E).
- F, `internal/store` und die Aufrufer: `store.ReadDir` über `store.OpenDir` an 16 Stellen, `emptyDir` mit `store.OpenDir` (AUDIT R41).

Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients und Phase-0-Vektoren sind unverändert. Nachgeführt sind mit 24g „Stand je M1-Kriterium“ (Kriterium B), „Bekannte Grenzen“, „TODO-Inventar“ und „Was die nächste Phase als Erstes wissen muss“; Laufzeiten, Abdeckung und Fuzzing stammen weiter von den dort genannten Ständen.

**Nachtrag 25g (Code-Stand: Arbeitsbranch nach Auftrag 25, a57ee9c; je Paket ein Commit: 25A 5635872, 25B fca9e04, 25C cdbf4ef, 25D a57ee9c, Dokumente 4f4b6e6; Volllauf auf derselben Quelle im Code (lokal 3ea40f0, `orch/fr-n25/`): 67 von 67 Schritten grün, am 10.11. 02:04 bis 08:49 UTC, unterbrochen durch einen Stillstand des Containers von 03:28 bis 08:00 UTC):** Auftrag 25 (`docs/tasks/25-nach-m1-nacht1-runde2.md`, 09./10.11.2026) behebt niedrige Reste aus den Prüfungen von Auftrag 24 (Liste nach M1 Nr. 64, 65, 68 und 71). Vier Pakete mit Nacharbeiten:
- 25A (mit 25A2, 25A3), `internal/ceremony` (`publish.go`), `cmd/gomail-ceremony`, `internal/store` (`RemoveTempReport`): `publish` folgt keinem Link mehr, auch nicht an `witnesses.rec` und beim Nachloggen einer Nachfolge, und lehnt einen Eintrag ab, der zwischen `Lstat` und Lesen wechselt; es entfernt Reste `.tmp-*` unter der Serversperre und nennt sie, lehnt `platform/` als Link ab und einen fehlenden Namen mit anders belegtem gültigem Logeintrag vor dem Schreiben (D93 Nachtrag 25 A, AUDIT R17 (b), RUNBOOK 7.2, 7.3, 8.6).
- 25B (mit 25B2), `internal/client`: eigene Meldung mit Ursache, wenn der Client `--dir` nicht gegen das Datenverzeichnis prüfen kann (D86 Nachtrag 25 B, AUDIT R33, RUNBOOK 3.2, 8.6).
- 25C (mit 25C2), `internal/loghttp`: `PublishHead` nur bei neuer Gegenzeichnung, `Tick` veröffentlicht vor `SignHead`, `SlotWait` 5 s (D80 Nachtrag 25 C, AUDIT R8).
- 25D (mit 25D2, 25D3), `scripts/bench.sh`: Quoting über `shq` und `ENVIRON`, Soll-Liste `wantnames`, gleiches Verhalten unter gawk, onetrue awk und busybox, Rohdaten bleiben bei Abbruch, Prüfungen vor der Messung mit Exit 2 (D94 Nachtrag 25 D, MEASUREMENTS „Messcode“).

Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients und Phase-0-Vektoren sind unverändert. Die Prüfungen von 25B, 25C und 25D endeten nach den Nacharbeiten ohne Fund über niedrig, ebenso die von 25A und 25A2 und beide Nachprüfungen von 25A3 (`docs/tasks/20-notes.md`, „Auftrag 25 … Prüfungen“; ORCHESTRATION Abschnitt 8). Die niedrigen Testlücken der Spezifikationsnachprüfung von 25A3 schließt die Nacharbeit 25A4 (nur Tests, „Auftrag 25, Paket 25A“; ihre Nachprüfung ohne Fund über niedrig). Die neuen niedrigen Reste stehen in der Liste nach M1 als Nr. 72 bis 83. Nachgeführt sind mit 25g „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“; Laufzeiten, Abdeckung und Fuzzing stammen weiter von den dort genannten Ständen.

**Nachtrag 26g (Code-Stand: Arbeitsbranch nach Auftrag 26, ed76444; je Paket ein Commit: 26B 5d59f7a, 26C b774de1, 26D 9f2a21d, 26E d7096e1, 26F ed76444, Dokumente 4be6031; Volllauf auf derselben Quelle im Code (lokal beff425, `orch/fr-n26/`): 67 von 67 Schritten grün, am 10.11. 12:10 bis 13:34 UTC; 26A nicht zusammengeführt; gelesen an der gemeinsamen Quelle `orch/n26`):** Auftrag 26 (`docs/tasks/26-nach-m1-nacht2.md`, 10./11.11.2026) setzt Punkte der Liste nach M1 um (Nr. 25, 66, 67, 69, 70, 72 bis 83). Fünf Pakete, vier davon mit Nacharbeiten, sind zusammengeführt, eines ist angehalten:
- 26B (mit 26B2), `internal/ceremony` (`publish.go`, `api.go`) und `internal/store` (neu `fsroot.go`, `removenamein_*.go`; `RemoveTempFiles`): `publish` öffnet `platform/` einmal (`os.Root`), prüft es vor und nach dem Öffnen und vor dem Loggen und arbeitet nur über diesen Deskriptor; ein Tausch von `platform/` wirkt bis auf ein Restfenster vor den Logeinträgen nicht mehr. `Store.RemoveTempFiles` entfernt per Unlink und lässt Verzeichnisse stehen; die Ersatzzeile von `witnesses.rec` kommt auch bei einem fsync-Fehler (Nr. 72, 73, 83; D93 Nachtrag 26 B, AUDIT R17 (b), RUNBOOK 7.2, 7.3, 8.6).
- 26C (mit 26C2), `scripts/bench.sh` und Testdateien von `internal/bench`: `go test` in eigener Prozessgruppe mit Trap und Wächter, QUIT weitergereicht, Probe von `-raw` und `-o`, `samefile` ohne `realpath`, `-benchtime` ohne Nullwerte, Test der Namen per `go/ast`; der Messcode ist unverändert (Nr. 76 bis 82, 70 zum Teil; D94 Nachtrag 26 C, MEASUREMENTS „Messcode“).
- 26D (mit 26D2), nur Tests: der Zweig `sc.Verify` in `identityKey`, das einmalige Öffnen der `.cert` unter Linux per inotify, `TestClientDirLeftovers` ohne `CAP_CHOWN` (Nr. 66, 69, 79; AUDIT R48).
- 26E (mit 26E2, 26E3 und der Anpassung an 26B), nur Tests: sechs Fuzz-Ziele für die Prüfpfade des Clients und die Zeremonie (Nr. 25; „Fuzzing“ unten, AUDIT 6.4). `FuzzState` fand einen Fall im Produktivcode: Der Client übernimmt einen Referenzkopf aus `state.json` mit fremder Origin (niedrig, AUDIT R49). Die Abhilfe ist eine Prüfregel des Clients und damit ein Haltepunkt; sie ist nicht gebaut (Liste nach M1 Nr. 92).
- 26F, aus 26A ohne die Grenzen am Listener: `PublishHead` lehnt einen zurückgesetzten Baum ab wie `SignHead` (`refuse`), dazu Kommentare in `loghttp`, `witness` und `translog` (Nr. 74, 75, 67, 70 zum Teil; D80 Nachtrag 26 F, AUDIT R8).
- 26A (Grenze für Verbindungen und Rate je Quelle am Log-HTTP-Listener, Rest von Nr. 7) ist **angehalten**: Nach drei Runden blieben zwei Funde über niedrig offen (F1 hoch, F2 mittel; `docs/tasks/20-notes.md`, Einträge 26A bis 26A3). Nichts davon ist zusammengeführt; den Weg entscheidet der Auftraggeber (ORCHESTRATION Abschnitt 10, Liste nach M1 Nr. 7, AUDIT R8).

Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients und Phase-0-Vektoren sind unverändert. Die Prüfungen von 26B, 26C, 26D, 26E und 26F endeten nach den Nacharbeiten ohne Fund über niedrig (`docs/tasks/20-notes.md`, „Auftrag 26 … Prüfungen“; ORCHESTRATION Abschnitt 10). Die neuen niedrigen Reste stehen in der Liste nach M1 als Nr. 84 bis 92. Nachgeführt sind mit 26g „Bekannte Grenzen“, „Fuzzing“ (sechs neue Ziele) und „Was die nächste Phase als Erstes wissen muss“; Laufzeiten und Abdeckung stammen weiter von den dort genannten Ständen.

Erster Stand: 03.11.2026, Stand vor der Abnahme aus Auftrag 20k (Entwurf aus 20c fortgeschrieben). Code bei Commit 858b2f1 des Arbeitsbranchs `claude/quirky-keller-hjsl5i` (Auftrag 20h; geprüft im Worktree als b14d798, Branch `worktree-agent-a7b23152bafa90687` auf df2b0af, mit gleichem Code): alle Pakete der Wellen 1 bis 4, 13e/13f, 15i bis 15n, 19/19b, 20a, die Linie 09b bis 09g, die Nacharbeiten 20b und 20e, die Tests aus 20f und 20g sowie 20h. Grundlage ist `docs/PLAN.md` in Version 1.4. 20j (RUNBOOK, DECISIONS und SPEC-ISSUES nach 20b bis 20h) ist zusammengeführt.

**Nachtrag 20n (Code-Stand b674ae3):** Im Arbeitsbranch liegen 20i als 211a45b und 20l als b674ae3, zusammengeführt nach 20m (90e248b). Geprüft wurden sie im Worktree als 869a196 und 1a57314 (Branch `worktree-agent-a43f36171b533ec65`), deren Code gleich 211a45b bzw. b674ae3 ohne die Tests aus 20m ist. Gegenüber 858b2f1 hat sich Produktivcode nur in `internal/client` und `internal/store` geändert, dazu ein Kommentar in `internal/testenv/testenv.go` (`git diff --stat 858b2f1 b674ae3 -- internal cmd scripts ':!*_test.go'`). Was sich geändert hat:
- `ErrExists` gilt nur noch bei belegtem Ziel.
- Das Temp-Verzeichnis von `keygen` und `restore` wird über einen Deskriptor gehalten und auf Identität geprüft.
- Der Schlüsselspeicher wird über `store.ReadFileLimited` gelesen.
- `O_NOCTTY` gilt in `store.OpenRegular` und für bestehende Sperrdateien.
- Dazu kommen Kommentare.

Die Abschnitte „Stand je M1-Kriterium“, „Bekannte Flakes“, „store“, „client“, „Bekannte Grenzen“, „Testabdeckung“ (Spalte „Code gemessen“), „Fuzzing“ und „TODO-Inventar“ sind daran nachgeführt. Messwerte stammen weiter von den dort genannten Ständen. Neu ist die Betriebsvoraussetzung D92 (AUDIT R46).

**Nachtrag 20o und Auftrag 21 (Code-Stand 9ad24a5, nachgeführt mit 20q):** Im Arbeitsbranch liegen 20o (9e34841, Funde niedrig aus der Prüfung der Client-Verzeichnisse, D86 Nachtrag 20o), 21a (02ee7b5, `store` und `translog`), 21c (12d48cc, Zeremonie) und 21b (7cde738, Client, Annahme, Server), jeweils mit den Nacharbeiten nach ihren Prüfungen. 9ad24a5 ist der Code-Stand für M1. Spätere Commits ändern im Code nur Kommentare in `internal/translog` (`doc.go`, `verifier.go`; dcd14d9; `git diff --stat 9ad24a5 HEAD -- internal cmd scripts`). Gegenüber b674ae3 hat sich der Produktivcode so geändert, netto um etwa 2.470 Zeilen (`git diff --stat b674ae3 9ad24a5 -- 'internal/*.go' 'cmd/*.go' ':!*_test.go'`; Zählung in AUDIT 8.2):
- 20o in `internal/client` (`client.go`, `keygen.go`, `devicelost.go`, `restore.go`): Ein Verzeichnis mit dem Marker `.incomplete` wird verweigert, Reste werden ganz oder gar nicht entfernt, Pfade werden auch aufgelöst verglichen, dazu `errNotDurable`.
- 21a in `internal/store` (`records.go`: Pin-Feld 7) und `internal/translog`: Regeln des Widerrufs, Kaskade, `ErrRevoked`, `ErrRevokedHead`, `RepairTreeResult`.
- 21c in `internal/ceremony` (`api.go`, `init.go`, `pin.go`, `publish.go`, neu `revoke.go`) und `cmd/gomail-ceremony`: `succeed --compromised`, `revoke`, `admin-rotate`, `publish` mit Feld 7.
- 21b in `internal/client` (`read.go`, `log.go`, `client.go`, `warncause.go`), `internal/ingest` (`ingest.go`) und `cmd/gomail-server`: Feld 7 bei der Annahme, in `address add`, `log repair` und im Client.

An 9ad24a5 nachgeführt sind „Stand je M1-Kriterium“, „Bekannte Grenzen“, „Offene Fragen“, „Pflichttests aus 10.1“ und „Was die nächste Phase als Erstes wissen muss“ (Aufträge 20p, 21d, 21e), mit 20q außerdem „Testabdeckung“ (Spalte „Code gemessen“), „Fuzzing“ (vierter Teil) und „TODO-Inventar“. Die Abdeckung stammt bei 20q weiter von den dort genannten Ständen. Der Abschluss-Volllauf lief auf 9ad24a5; das ist dem Stand nach 21e gleichwertig, weil dcd14d9 im Code nur Kommentare ändert. Abdeckung am Endstand und Ergebnis des Volllaufs: Nachtrag 20r.

**Nachtrag 20r (Endstand fba4eb2, Aufträge 22, 23 und 17):** Nach dem Abschluss-Volllauf auf 9ad24a5 fand die Angreiferprüfung von 22 einen Fund mittel außerhalb ihres Diffs: Das Ingest-Zertifikat wurde zweimal gelesen (AUDIT R48). Nach der Regel „kein offener Fund über niedrig“ wurde der Endstand deshalb 9ad24a5 + 22 + 23 (ORCHESTRATION, 04.11., 00:50 UTC). Zusammengeführt sind (ORCHESTRATION, 04.11., 02:35 UTC):
- aed6ea4: Auftrag 17 mit 17b bis 17d (`docs/MEASUREMENTS.md`, Rohdaten, Testcode in `internal/bench`, `scripts/bench.sh`);
- afad8de: Auftrag 22 (`docs/tasks/22-extras.md`);
- fba4eb2: Auftrag 23 mit 23b (`docs/tasks/23-platform-single-read.md`);
- danach nur Dokumente: 4a6e9c1 (22d: RUNBOOK, AUDIT R17/R33/R48, D86- und D93-Nachträge) und fd7b87f (D94);
- 4f247c6: Auftrag 17e (`scripts/bench.sh` lehnt Optionswerte ab, die mit `-` beginnen; behebt den Fund aus D94, DECISIONS D94 Nachtrag 17e). Er ändert nur `scripts/bench.sh`, MEASUREMENTS und `nachtrag-17c.diff`, nichts unter `internal` und `cmd`.

Gegenüber 9ad24a5 hat sich der Code so geändert (`git diff --stat 9ad24a5 HEAD -- internal cmd`, 23 Dateien):
- 22 in `internal/ceremony` (`publish.go`, `api.go`): `publish` heilt `data/platform/`, Admin-Widerruf nur mit Untergrenze. Dazu `resolveExisting` in `internal/client/client.go` sowie Kommentare in `cmd/gomail-ceremony/main.go` und `internal/e2e/succession_test.go` (dort entfällt das veraltete `TODO(Q19)`). Tests: `heal22_test.go`, `rework21c_test.go`, `clientdir22_test.go`, `export22_test.go`.
- 23 in `internal/store` (`store.go`, `ReadPlatformCertRaw`), `internal/client/read.go` (`ingestKeyFor`) und `internal/ingest/ingest.go` (`New`): Das Ingest-Zertifikat wird einmal gelesen; Signaturprüfung, Schlüssel und Logabgleich arbeiten auf denselben Bytes. Testhaken `certReadHook` in `read.go` und `ingest.go`, nur in Tests gesetzt. Tests: `platform23_test.go` in `client` (`TestPlatformIngestCertSwapped`, seit 23b unabhängig von der Reihenfolge der zufälligen Mail-IDs), `ingest` (`TestPlatformCertReadOnce`) und `store` (`TestReadPlatformCertRaw`), dazu `export_test.go`.
- 17: nur Testcode in `internal/bench` (`index_test.go`, `main_test.go`, `memory_test.go`, `proto_test.go`, `rig_test.go`).
- Kommentare in `internal/translog` (`doc.go`, `verifier.go`; dcd14d9, nach 9ad24a5).

Außerhalb dieser Zeilen und der Kommentare ist der Code gleich 9ad24a5; geprüft mit `git diff 9ad24a5 HEAD -- internal/translog cmd/gomail-ceremony/main.go`, wo jede geänderte Zeile ein Kommentar ist. Nachgeführt sind mit 20r „Stand je M1-Kriterium“, „Laufzeiten“, „Bekannte Flakes“, „Bekannte Grenzen“, „Pflichttests aus 10.1“, „Testabdeckung“, „TODO-Inventar“, „Was die nächste Phase als Erstes wissen muss“ und die Zuordnung der Commits.

**Worktree-Commits und Arbeitsbranch.** Geprüft, gemessen und im Volllauf getestet wurde oft auf Commits in Worktree-Branches, die nicht im Arbeitsbranch liegen; der Arbeitsbranch hat die Arbeit unter anderen Hashes. Zuordnung, geprüft mit `git diff --stat <a> <b> -- internal cmd scripts`:

| Worktree-Commit | im Arbeitsbranch | Unterschied im Code |
|---|---|---|
| 7ffed5c (Linie 09b, 09g) | 3e06f23 | keiner |
| cb2344c (20b) | b155e1f | b155e1f enthält zusätzlich die Tests aus 20f und 20g |
| bc0d0f9 (20e) | d85da00 | d85da00 enthält zusätzlich die Tests aus 20f und 20g |
| b2032d5 (Merge des Arbeitsbranchs mit 20b in den Worktree von 20e) | d85da00 | keiner |
| b14d798 (20h) und 302c6db (Merge des Arbeitsbranchs in den Worktree von 20h) | 858b2f1 | keiner |
| 869a196 (20i) | 211a45b | 211a45b enthält zusätzlich die Tests aus 20m |
| 1a57314 (20l) und 1d49e6d (Merge des Arbeitsbranchs in den Worktree von 20l) | b674ae3 | b674ae3 enthält zusätzlich die Tests aus 20m |
| 3cd9072 (22, Worktree-Branch `worktree-agent-abc2aa7e11960965f`) | afad8de | afad8de enthält zusätzlich den Testcode in `internal/bench` und `scripts/bench.sh` aus 17 (aed6ea4); sonst keiner (`git diff --stat 3cd9072 afad8de -- internal cmd ':!internal/bench'` leer) |
| 9a9d6cb (23, Worktree agent-ae257463dab78a433) | fba4eb2 | 9a9d6cb liegt auf 9ad24a5 ohne 22 und 17 und hat `internal/client/platform23_test.go` vor 23b |
| c6fa0b3 (23b, nur Testcode) | fba4eb2 | in den Dateien von 23 keiner; fba4eb2 enthält zusätzlich 22 und den Messcode aus 17 |
| 10b1783 (gemeinsame lokale Quelle 9ad24a5 + 22 + 23 vor 23b, Scratchpad `orch/m1-final`) | fba4eb2 | `internal/client/platform23_test.go` (23b), dazu `internal/bench` und `scripts/bench.sh` aus 17 |
| 1217496 (dieselbe Quelle mit 23b) | fba4eb2 | nur `internal/bench` und `scripts/bench.sh` aus 17 (`git diff 1217496 fba4eb2 -- internal cmd ':!internal/bench'` leer) |

84ca174 (WIP von 20b) und ade5ae9 (20l vor der Nacharbeit) liegen nur in Worktrees; `internal/store` von 84ca174 ist gleich dem von cb2344c.

Eingetragen sind Fuzzing, die Zuordnung der Pflichttests und die Abdeckung am Endstand (jedes Paket unter `internal/` erreicht das Soll, Abschnitt „Testabdeckung“). Der Abschluss-Volllauf auf 9ad24a5 lief mit 67 von 67 Schritten grün (Scratchpad `orch/fr-final/`, 23:12 bis 00:58 UTC). Volllauf auf dem Endstand mit 22 und 23: ebenfalls 67 von 67 Schritten grün (Scratchpad `orch/fr-m1/`, 01:32 bis 03:40 UTC, unterbrochen durch Container-Neustarts und jeweils fortgesetzt). Die Messungen stehen in `docs/MEASUREMENTS.md` (Kriterium D, gemessen am 04.11. zwischen 01:00 und 01:33 UTC, Produktivcode gleich 9ad24a5 bis auf Kommentare). Kernzahlen sind Mediane aus 10 Wiederholungen auf 4 geteilten vCPU, mit `fsync` auf virtio-ext4:
- Empfang 10 MiB über 4 Verbindungen: `enc` 134 MiB/s, `proto` 205 MiB/s, `plain` 226 MiB/s. Bei 1 und 10 MiB liegt der Anteil `enc / proto` bei 0,62 bis 0,70.
- Empfang 4 KiB über 1 Verbindung: `enc` 108 Mails/s, `proto` 119 Mails/s, `plain` 1264 Mails/s.
- Indexierung je Mail: 58,5 µs mit den Begriffslisten des Servers (`terms`), 876 µs nur mit Markern (`unprocessed`). Der Index je 1000 Mails ist in 16 Segmenten 193 184 Bytes groß, zusammengefasst 143 600 Bytes.
- `Sync` bei 10 000 Mails: 0,0173 s ohne neue Mails (`index=off`), 0,347 s mit den Begriffslisten aller 10 000 Mails (`index=on`). `List` über 10 000 Mails, kein Teil von `Sync`, braucht 2,46 s.
- Server-VmRSS bei 1000 Mails à 1 MiB über 20 Verbindungen: vor der Last 12,04 MiB, Spitze 24,34 MiB, danach 13,77 MiB.

Grenzen der Messung stehen in MEASUREMENTS, „Grenzen der Messung“: geteilte VM, kein Betreiberlog im Messpfad, 22 und 23 nicht gemessen. Für den Abschlussbericht fehlen noch die Zahlen der Prüfungen (Abschnitt „Unabhängige Prüfungen bis M1“).

Dieses Dokument beschreibt Pakete, Invarianten, Build und Grenzen für die nächste Phase. Es verweist, statt zu wiederholen:
- Entscheidungen: `docs/DECISIONS.md` (Phase 1 ab D47, Phase 2 und M1 ab D63, zuletzt D94; alle Nachträge, darunter 13e/13f, 20a, 20b, 20e, 20h, 20i, 20l, 20o und 22 an D86, 20d, 20e, 20j und 20i/20l an D91, 20j an D80, 20n und 20m an D85, 21e, 22 und 23 an D93, 17e an D94).
- Offene Punkte der Spezifikation: `docs/SPEC-ISSUES.md` (bis S98); Fragen an den Auftraggeber: `docs/QUESTIONS.md` (Q1 bis Q22).
- Bekannte Grenzen und Restrisiken: `docs/AUDIT.md` Abschnitt 5 (R1 bis R49); Prüfpfade: AUDIT Abschnitt 6.
- Messungen: `docs/MEASUREMENTS.md` mit Rohdaten unter `docs/measurements/2026-11-04/`.
- Zuordnung der Pflichttests aus 10.1 und Abdeckung je Paket im Einzelnen: `docs/tasks/20-mandatory-tests.md`; Fuzzing und Laufzeiten aus den Läufen des Orchestrators: `docs/tasks/20-notes.md`.
- Betrieb von Hand: `docs/RUNBOOK.md`, nachgefahren von `TestRunbook`.
- Entwurf des Transparenzlogs: `internal/translog/doc.go` (verbindlich).
- Verlauf der Aufträge und Prüfungen: `docs/ORCHESTRATION.md` Abschnitt 4. Einordnung der gesammelten Hinweise: `docs/tasks/20-triage.md`.

Die Abschnitte zu `rec`, `keys`, `shamir`, `envelope` und `smtpd` sind seit Phase 1 kaum verändert und stehen weiter hier, mit Nachträgen. Die übrigen Pakete beschreibt dieser Stand neu. Tabellen und Prüfberichte aus Phase 0 und Phase 1 stehen am Ende unter „Verlauf“.

## Stand je M1-Kriterium

Die Kriterien stehen in `docs/ORCHESTRATION.md` Abschnitt 1, „M1-Kriterien A–F“. Als erfüllt gilt hier nur, was im Branch gebaut und durch Tests oder Dokumente belegt ist. Für offene Haltepunkte gilt diese Regel nach ORCHESTRATION Abschnitt 3 und D65: Gebaut ist dort die strengste Lesart (`TODO(Qn)`), oder ein davon abhängiger Befehl ist nicht gebaut bzw. nicht freigegeben (D65: „kein Befehl, der davon abhängt, wird vor der Antwort ausgeliefert“); ein solcher Befehl zählt nicht als fehlend. Ausnahme ist Q2: Einladungen bleiben nach QUESTIONS Q2 („Bis zur Antwort: unverändert“) im Stand von Phase 1 (D53).

| Kriterium | Urteil | Stand und Beleg | Was fehlt |
|---|---|---|---|
| **A** Phase 2 vollständig (2.2, 2.4, 2.5, 6, 7, 9) | **erfüllt** | Gebaut: Generationen mit `device lost`, `restore`, `keygen --shares`; Prüfvermerke und Übernahme nach 2.2 Punkt 4 für alle Dateiarten außerhalb des Logs (D84, D91; seit 20e legt ein Schreiber den Vermerk für sein eigenes Segment beim Schreiben an, D91 Nachtrag 20e). Epochen mit Gründen, `discards`, sofortige und geplante Epochen, Vorrat (D63, D68, D71). `mailbox share`, `revoke`, Leser vergangener Zeiträume (D75, D86). Ordnerliste je Epoche; Flags mit Versionsregel (K4, D79); Index, Suche, Zusammenfassen (D79, D91). Sperren und Rechte nach 9.1 (D70, D81); Befehle nach 9.2 (D86, D87). `keygen` und `restore` legen das Client-Verzeichnis in einem Schritt an (D86 Nachträge 20b und 20e; Marker `.incomplete` und geprüfte Sperrdatei seit 20h, `createClientDir`, `removeLeftovers`, `lockClientDir`; seit 20l mit dem Temp-Verzeichnis über einen Deskriptor und Identitätsprüfungen, `openTempDir`, `sameDir`, D86 Nachtrag 20l). Seit 22 folgt `resolveExisting` einem hängenden Link bis zu seinem Ziel, ein Link in das Datenverzeichnis ist `errInsideDataDir` (D86 Nachtrag 22, AUDIT R33). Betriebsvoraussetzung: Das Elternverzeichnis eines Client-Verzeichnisses ist nur für den eigenen Benutzer beschreibbar oder trägt das Sticky-Bit (Eigentümer der Benutzer oder `root`; D92, RUNBOOK 0.3). Beleg: die Tests in `internal/client`, `cmd/gomailctl` und `internal/e2e`, im Abschluss-Volllauf auf 9ad24a5 grün (Scratchpad `orch/fr-final/`, `racetag-internal_client.log`, `386-internal_client.log`, `racetag-cmd_gomailctl.log`, `race-internal_e2e.log`, `racetag-internal_e2e.log`). Im Volllauf auf dem Endstand (`orch/fr-m1/`) liefen dieselben Schritte ebenfalls grün. Die Tests aus 22 zum Client-Verzeichnis (`clientdir22_test.go`: `TestClientDirDanglingLinkIntoDataDir`, `TestResolveExisting`; D86 Nachtrag 22) liefen im Volllauf auf 9ad24a5 noch nicht, wohl aber im Volllauf auf dem Endstand (`orch/fr-m1/`, `internal/client` auf 1217496): `TestClientDirDanglingLinkIntoDataDir` braucht `testenv` und ist nur in `racetag-` und `386-internal_client.log` aussagekräftig, `TestResolveExisting` läuft in allen drei Schritten. | Befehle, die an offenen Fragen hängen: `mailbox rotate` (Q7), `--server-search` (Q3, nicht M1), `--delegate` (Q6; Art 3 nur in der API), `recovery …` (Q1; nur interne API). Einladungen sind unverändert aus Phase 1, also unsigniertes JSON ohne Ablauf (Q2, D53, AUDIT 7.1; QUESTIONS Q2 „Bis zur Antwort: unverändert“); das ist keine strengste Lesart, sondern der Stand vor der Antwort. Q18: Ein alleiniges Mitglied ohne geprüfte Ordnerliste hat keinen Ausweg (AUDIT R21). Erfüllt deshalb, weil an den offenen Haltepunkten die strengste Lesart gebaut (Q6, Q18, Q20) bzw. der Befehl nicht gebaut oder nicht freigegeben ist (Q1, Q7; Q2 unverändert aus Phase 1). Die Regel oben („als erfüllt gilt nur, was gebaut ist“) gilt für offene Haltepunkte in dieser Lesart nach ORCHESTRATION Abschnitt 3 (Regel dort und D65; Stand in ORCHESTRATION Abschnitt 5 und 6; QUESTIONS Q1, Q6, Q7). `mailbox rotate`, `recovery …` und `--delegate` fehlen bis zur Antwort des Auftraggebers; AUDIT 1.3 führt sie unter „Was M1 nicht abdeckt“. „Bedingt“ sieht ORCHESTRATION Abschnitt 1 nur für E vor. |
| **B** Transparenzlog, Zeuge, Vermerke, 24 h, kein `--insecure-no-log` | **erfüllt** (bis Auftrag 24 mit der Auslegung, dass die 11 Marken `TODO(phase3-translog)` nur im Testdouble `internal/translog/translogtest/unverified.go` stehen; seit Auftrag 24, Paket E, gibt es keine mehr) | Gebaut: Log auf `tlog` (D78), Serverseite mit `loghttp` (D80), Prüfungen in `ingest` und Server (D81), Client am Log mit Vermerken und 24-Stunden-Regel (D88), `gomail-witness` (D74). `--insecure-no-log` ist überall ein Nutzungsfehler. Alle `TODO(phase3-translog)` im Produktivcode sind aufgelöst. Beleg: die Tests in `internal/translog`, `internal/witness`, `internal/loghttp`, `internal/client` und `cmd/gomail-witness`, im Abschluss-Volllauf auf 9ad24a5 grün (`orch/fr-final/`). 22 und 23 ändern daran nichts außer dem einmaligen Lesen des Ingest-Zertifikats vor dem Logabgleich (23, AUDIT R48). Im Volllauf auf dem Endstand (`orch/fr-m1/`) liefen diese Pakete ebenfalls grün. | Im Produktivcode nichts. Die 11 Marken `TODO(phase3-translog)` im Testdouble `internal/translog/translogtest` (`Unverified`, nur in Testcode und `testenv`) standen am Endstand fba4eb2 noch dort; seit Auftrag 24 (Paket E) sind sie durch sachliche Kommentare ersetzt (was das Double annimmt und warum es nur in Tests verwendet wird), der Abschnitt „Phase-3 log sites (all resolved)“ in `internal/translog/doc.go` ist auf dem Stand nach M1, und `translog.ErrNoLog` nennt `--insecure-no-log` nicht mehr (`translog: no transparency log available; refusing to start`). Mehrere Zeugen im Betrieb folgen erst vor echten Mails (2.7, AUDIT 1.3). |
| **C** Zeremonie `init --shares 3-of-5`, `ingest-rotate`, `reshare`, Probe; `--dev` nur für Tests | **erfüllt** | Gebaut (D82, D85 mit Nachträgen): dazu `succeed` und `publish` über das Log; `--dev` nur im Build mit `gomail_dev`; Terminalregeln mit Abbruchpfad. Kompromissfall mit Auftrag 21 (D93): `succeed --compromised --revoke-at-size --revoke-at-time`, `revoke`, `admin-rotate` und `publish` mit Pin-Feld 7 (21c, 12d48cc); Server, `address add`, `log repair` und Client mit Feld 7 (21b, 7cde738); Regeln in `store` und `translog` (21a, 02ee7b5). Seit 22 heilt eine Wiederholung derselben `publish`-Ausführung `data/platform/`, und `checkRevocations` prüft „wäre nie gültig gewesen“ nur für Ingest-Elemente (D93 Nachtrag 22). Beleg: `internal/ceremony` und `cmd/gomail-ceremony` im Abschluss-Volllauf auf 9ad24a5 grün, je unter `-race` ohne und mit Tags und unter 386 (`orch/fr-final/`, `race-`, `racetag-` und `386-internal_ceremony.log` und `-cmd_gomail-ceremony.log`), dazu `TestRunbook` mit Zeremonie 3 aus 5 (`internal/e2e`, `race-` und `racetag-internal_e2e.log`). Die Tests aus 22 in `internal/ceremony` (`heal22_test.go` und die mit 22 geänderte Fassung von `TestRevocationTimes`) liefen bei 9ad24a5 noch nicht. Im Volllauf auf dem Endstand (`orch/fr-m1/`) liefen `internal/ceremony`, `cmd/gomail-ceremony` und `internal/e2e` in allen ihren Schritten grün; damit bestanden auch diese Tests aus 22 (`internal/ceremony` auf 1217496). Zu `clientdir22_test.go` (Client-Verzeichnis) siehe Zeile A. | Für C nichts. Restgrenzen: AUDIT R17, R18; Ablauf: RUNBOOK 7.3. |
| **D** `docs/MEASUREMENTS.md`, reproduzierbar | **erfüllt** (der Fund aus D94 ist mit 17e behoben, 4f247c6; kein Vorbehalt mehr) | `docs/MEASUREMENTS.md` mit Rohdaten unter `docs/measurements/2026-11-04/`. Gemessen wurde am 04.11. zwischen 01:00 und 01:33 UTC in zwei Läufen von `scripts/bench.sh -count 5 -maxload 0.5`. Messumgebung `internal/bench` und `scripts/bench.sh` (D77, 12d, 17); der Produktivcode des gemessenen Stands ist gleich 9ad24a5 bis auf Kommentare (MEASUREMENTS, „Code-Stand“, mit Baum-Hashes). Reproduzierbar: Jede Zahl steht mit dem Befehl, der sie einzeln nachmisst; die Lauftabellen lassen sich mit `scripts/bench.sh -render` ohne neue Messung aus den Rohdaten erzeugen. Kernzahlen stehen oben im Einstieg. Beleg der Prüfung: Die Prüfung 17b bestätigte alle Zahlen gegen die Rohdaten und fand 3 mittel und 7 niedrig (→ 17c). Die Nachprüfung 17c fand alles behoben und neu F1 mittel (→ 17d). Die Nachprüfung 17d fand F1 behoben und neu M1 mittel, den der Orchestrator als niedrig eingestuft hat (D94; `docs/tasks/20-notes.md`, „Aus den Prüfungen von 17“). 17e behob M1, N1 und N2 (4f247c6); die Prüfung von 17e fand nichts über niedrig (DECISIONS D94 Nachtrag 17e). | Kein Vorbehalt mehr: M1 aus 17d (`scripts/bench.sh` nahm einen Optionswert an, der mit `-` beginnt; als niedrig eingestuft mit D94) ist mit 17e behoben (4f247c6, DECISIONS D94 Nachtrag 17e), ebenso N1 und N2 aus 17d; die Prüfung von 17e fand nichts über niedrig. Nach M1 bleiben F3 aus 17c und die niedrigen Punkte aus der Prüfung von 17e (`docs/tasks/20-notes.md`, „Aus der Prüfung von 17e“). Grenzen der Messung (MEASUREMENTS): geteilte VM mit 4 vCPU, keine NFS-Messung, Ingest ohne Betreiberlog im Messpfad (eine Messung mit `testenv.NewLogged` steht aus). Die Aufträge 22 und 23 sind nicht gemessen; sie berühren keinen Pfad, der je Mail läuft. |
| **E** Abnahme nach 10.2 | **bedingt** | **Abschluss-Volllauf auf 9ad24a5** (Scratchpad `orch/fr-final/`, `rev` = 9ad24a5, 23:12 bis 00:58 UTC, unter fremder Last): 67 von 67 Schritten grün, kein `.fail`. Die Schritte: gofmt, `go vet` ohne und mit Tags, je Paket `-race` ohne Tags, `-race` mit `gomail_dev,gomail_test` und 386 mit Tags; `internal/e2e` nur unter `-race`, mit Tags mit `GOMAIL_TEST_MIN_FREE`. Dauer: Abschnitt „Laufzeiten“. **Volllauf auf dem Endstand** mit 22 und 23 (`orch/fr-m1/`, Quelle 1217496, im Code gleich fba4eb2 außer `internal/bench`): 67 von 67 Schritten grün, kein `.fail`, mit demselben Skript wie `fr-final`, 01:32:49 bis 03:40:59 UTC. Unterbrochen wurde er durch Container-Neustarts gegen 01:42, 03:26 und 03:40 UTC und danach jeweils fortgesetzt (ORCHESTRATION, 04.11., 01:42 UTC und 03:26 und 03:40 UTC); der abgebrochene Schritt lief dabei ganz neu, weil das Skript über die `.ok`-Marken fortsetzt. Wegen dieser Unterbrechungen und der fremden Last (Prüfläufe, Abdeckung) ist seine Gesamtdauer kein Richtwert. gofmt, vet und alle drei Schritte von `cmd/gomail-ceremony` liefen auf 10b1783, alle Schritte ab `cmd/gomail-server` (01:57 UTC), auch `internal/ceremony` und `internal/client`, auf 1217496. Darin bestanden auch die Tests zu S9 und die aus 22 und 23 (`heal22_test.go`, `clientdir22_test.go`, die geänderte Fassung von `TestRevocationTimes`, `TestPlatformIngestCertSwapped`, `TestPlatformCertReadOnce`, `TestReadPlatformCertRaw`); die mit `testenv` sind nur in den Schritten mit Tags aussagekräftig. `internal/bench` mit den Testdateien aus 17 lief getrennt auf dem Arbeitsbranch (aa87a99, `orch/fr-head-bench/`) unter `-race`, `-race` mit Tags und 386 mit Tags grün. Vor 01:55 UTC begonnen hatten nur gofmt, vet und die drei Schritte von `cmd/gomail-ceremony`; der letzte, unter 386, begann gegen 01:52:45 UTC. Ab 01:55 UTC enthält die Quelle 23b, und gofmt und vet liefen darauf noch einmal grün (`orch/fr-m1/NOTE`, `rev2`). Die Laufzeiten zwischen 02:15 und 02:17 UTC sind durch eine versehentliche Messung gestört; in diesem Fenster lief `racetag-internal_client`. Für die Korrektheit ist das unerheblich (ORCHESTRATION, 04.11., 01:42, 02:05 und 02:20 UTC). Dieser Volllauf lief ohne die Testdateien aus 17 in `internal/bench`. Sie sind durch die Läufe der Implementierer von 17b und 17c belegt: `-race`, 386, `go vet` und `go test -tags gomail_dev` (ORCHESTRATION, 04.11., 02:05 UTC). **S9 und 20m:** Die Tests zu S9 bestanden im Abschluss-Volllauf auf 9ad24a5. `TestVerifyCompromisedIdentityStillIssues` (`internal/ceremony`, ohne Build-Tag, `race-`, `racetag-` und `386-internal_ceremony.log`) und `TestRevokedCompromise` (`internal/translog`, ohne Build-Tag, `race-`, `racetag-` und `386-internal_translog.log`) laufen in jedem Schritt. `TestLogIngestRevoked` (`internal/client`, `racetag-` und `386-internal_client.log`) und `TestRevokedIngestEndToEnd` (`internal/e2e`, `racetag-internal_e2e.log`) brauchen `testenv` und sind nur mit Tags aussagekräftig; ohne Tags überspringen sie sich. Die Tests aus 20m (`TestPTYNonblockClear`, `TestPTYPartialShare`, `TestPTYPromptBlocked`, `TestPTYStopLoop`, `TestPTYExitNotStopped`, `TestPTYUnblockBrief`, `TestStallDetect`; nur unter Linux und ohne `ceremony_notty` übersetzt) liefen in allen drei Schritten von `cmd/gomail-ceremony`. Den SKIP-Nachweis liefert ein eigener Lauf mit `-v`, siehe „Bekannte Flakes“. Ergebnis: kein echter Teiltest übersprungen. **Weitere Belege:** Pflichttests aus 10.1: 28 von 30 vollständig zugeordnet und bestanden (Abschnitt „Pflichttests aus 10.1“). Fuzzing: alle 25 Ziele je 10 Minuten ohne Fund (Abschnitt „Fuzzing“). Abdeckung am Endstand: jedes Paket unter `internal/` erreicht das Soll (Abschnitt „Testabdeckung“). Zwei-Maschinen-Skript im lokalen Modus durchgelaufen (D83). | **Bedingt** wegen zwei Maschinen über NFSv4: Es gibt hier weder NFS noch eine zweite Maschine (D83, AUDIT R36); ORCHESTRATION Abschnitt 1 nennt M1 dann „bedingt erreicht“. Außerhalb von M1 liegen S7 (Löschen von Epochen) und der Volltextteil von Z3 (ORCHESTRATION Abschnitt 1). Die zwei früheren Fehlschläge an der 4,5-s-Grenze (`TestPTYPromptBlocked` auf b2032d5, `TestPTYStopLoop/6` auf 302c6db) sind nach der Analyse als Stillstand der Maschine eingeordnet (D85 Nachträge 20n und 20m); im Abschluss-Volllauf traten sie nicht auf. |
| **F** HANDOFF, AUDIT, RUNBOOK mit `TestRunbook` | **erfüllt** (`TestRunbook` auch im Volllauf auf dem Endstand grün) | `docs/AUDIT.md` auf dem Stand 858b2f1 mit den Nachträgen 20n für b674ae3, 21e für 9ad24a5, 22d für 22 und 23 und 20r für den Endstand (Aufträge 18, 18b, 18c, 20c, 20k, 20n, 20p, 22d, 20r; R46 neu, R47 aus 20p, R48 aus der Angreiferprüfung von 22). `docs/RUNBOOK.md` mit `TestRunbook` (Zeremonie 3 aus 5, Zeuge, drei Benutzer; D89); von den Vorschlägen aus `docs/tasks/20-triage.md` hat 20d R-1 und R-2 übernommen, 20j R-3 (4.2, `address add` bei nachgehender Uhr); 20j hat außerdem RUNBOOK 3.2 „Client-Verzeichnis“ und 8.7 „Epoche widerspricht dem Log“ nachgetragen. Seit 20n nennt das RUNBOOK die Betriebsvoraussetzung D92 mit Prüfbefehl (0.3, 3.2, 9.1) und die Meldung bei einem ausgetauschten Temp-Verzeichnis (3.2, 8.6). Seit 20p (Durchgang aus Betreibersicht) nennt es Gruppe und Benutzer (1.4), die Regeln für `--keys` und `--out` (1.2), den SSH-Tunnel für einen Zeugen auf einer anderen Maschine (1.7, nicht getestet, AUDIT R47), Clients mit altem Pin nach einem Zeugenwechsel (7.2), das Vorgehen bei verwaisten Einträgen (8.2), Sicherung und Wiederherstellung (8.8), einen Fork des Zeugen (8.9) und weitere Grenzen (8.10); Einleitung und „Nicht in `TestRunbook`“ nennen, was `TestRunbook` nicht abdeckt. Seit 21d und 21e beschreibt 7.3 Widerruf, Admin-Rotation und Neuausstellung nach D93, angeglichen an den Code von 21a bis 21c (Befehle, Grenze `<T>` + 1 ms, Reihenfolge `revoke`, Rotation, `log repair`, `publish`, Verteilen, Start); 8.6 nennt die Meldungen aus 20o und Auftrag 21. Seit 22d nennt es in 1.5, 7.3 und 8.6 die Heilung durch `publish`, das Vorgehen bei fremden Dateien in `platform/` und die zugehörigen Meldungen. `TestRunbook` bestand im Abschluss-Volllauf auf 9ad24a5 (`internal/e2e`, `race-` und `racetag-internal_e2e.log`; die Programme baut der Test selbst mit `gomail_test`). Dieses Dokument mit Messungen, Fuzzing, Abdeckung, Pflichttests, Laufzeiten und Flakes. | Volllauf auf dem Endstand, in diesem Dokument und in AUDIT: eingetragen, 67 von 67 Schritten grün (`orch/fr-m1/`). `TestRunbook` hat kein Build-Tag und braucht `testenv` nicht. Es gehört zum Paket `internal/e2e`, das in `race-` und `racetag-internal_e2e.log` mit `ok` endet. Die Logs nennen keine Testnamen, weil der Lauf ohne `-v` lief. Offen sind noch die Zahlen der Prüfungen für den Abschlussbericht (Abschnitt „Unabhängige Prüfungen bis M1“). |

Nicht in M1 (ORCHESTRATION Abschnitt 1): Löschen von Epochen, Volltextsuche, QR, TLS und Missbrauchsschutz, Padmé, Hardware-Schlüssel, IMAP, Oberflächen über die Kommandozeile hinaus.

## Überblick

```
internal/rec       kanonische Kodierung (3.6), strikter Decoder, NFC-Prüfung
internal/keys      Seed, BIP-39, HKDF (2.2, 2.3), Zertifikate, Signaturdomänen (3.7), Schlüsselspeicher
internal/shamir    Aufteilung über GF(256), Anteile als 30 Wörter (2.3)
internal/envelope  Dateiformat .gml (3): HPKE-Verpackung, STREAM-Inhalt, Signatur, Kopffeld 8
internal/words     Eingabe von Seed- und Anteilswörtern (2.2): NFKD, Kleinschreibung, Grenzen
internal/store     Datenverzeichnis (4): atomares Schreiben, Sperren und Rechte (9.1), alle Datensätze
internal/translog  Transparenzlog (2.7) auf tlog: Einträge, Köpfe, Beweise, Verifier, Audit-Index
internal/loghttp   HTTP-Seite des Logs zwischen Server und Zeuge
internal/witness   Zeuge nach 2.7: Regeln, Zustand, Fork-Nachweis
internal/smtpd     SMTP-Zustandsmaschine mit den Grenzen aus 5.1
internal/terms     Begriffsregeln aus 5.4 und D55, einmal für Server und Client
internal/ingest    Annahme, Spool-Transaktion, Metadaten, Begriffslisten, Logprüfungen (5.2 bis 5.4)
internal/client    Benutzer, Postfächer, Generationen, Lesepfade, Index und Suche, Flags, Log (2, 6, 7)
internal/ceremony  Schlüsselzeremonie und Veröffentlichung (2.3)
internal/bench     Messungen (nur Tests und Benchmarks)
internal/testenv   Plattform, Benutzer und Postfächer für Tests (nur mit -tags gomail_dev)
internal/e2e       Ende-zu-Ende-Tests, Programme nach RUNBOOK, Zwei-Maschinen-Skript
cmd/gomail-server  init, serve, invite create, address add, log repair
cmd/gomailctl      keygen, register, restore, mailbox create/share/revoke, device lost, sync,
                   list, read, search, flag, inspect
cmd/gomail-ceremony init, ingest-rotate, reshare, succeed, publish
cmd/gomail-witness keygen, serve
scripts/           bench.sh (Messungen), two-host-test.sh (Test nach 9.1)
```

PLAN 9.3 nennt ein Paket `search`. Die Suche liegt in `internal/client` (`Search` in `search.go`, `Index` in `index.go`), weil sie die Schlüssel und Prüfregeln des Clients braucht; die Begriffsregeln liegen in `internal/terms`.

Abhängigkeiten im Produktivcode: `envelope -> keys -> rec`; `shamir -> keys`; `words -> keys`; `store -> envelope, keys, rec`; `translog -> keys, rec, store`; `witness -> translog, store, keys, rec`; `loghttp -> translog, witness`; `terms -> store`; `ingest -> smtpd, store, envelope, keys, terms, translog`; `client -> store, envelope, keys, rec, shamir, terms, translog, words`; `ceremony -> keys, shamir, store, translog, witness, words`. `smtpd` hängt von keinem Paket des Projekts ab. Nur Standardbibliothek und `golang.org/x/crypto` v0.58.0, `golang.org/x/mod` v0.42.0 (`sumdb/tlog`, `sumdb/note`), `golang.org/x/text` v0.43.0 (`go.mod`); `x/sys` nur indirekt. Go 1.26, getestet mit 1.26.10 (`GOTOOLCHAIN=go1.26.10`).

## Bauen und testen

### Build-Tags

- **`gomail_dev`:** Entwicklungszeremonie `gomail-ceremony init --dev` und `ceremony.InitDev`, Entwicklungs-Pins. Ohne das Tag enthält kein Programm den Pfad, der den Plattform-Root in eine Datei schreibt (D85 (3)). Produktionsbinaries lehnen einen Entwicklungs-Pin ab (D87 (3), D88 (1)).
- **`gomail_test`:** Testschalter `GOMAIL_TEST_MIN_FREE` (Grenze für freien Platz statt 10 %), `GOMAIL_TEST_DEV_IDENTITY` (Entwicklungs-Pin im Client), `GOMAIL_TEST_HEAD_GAP` (Abstand der Köpfe) und `GOMAILCTL_TEST_KEYGEN_PIPE` (`keygen` ohne Terminal, für Skripte). Das Produktionsbinary enthält keinen davon (`TestNoTestSwitchInProduction`, AUDIT R35).
- **`ceremony_notty`:** Tests der Zeremonie ohne Terminal (D82 (5)).
- Die Tests in `internal/client`, `internal/ingest`, `internal/bench`, `cmd/gomailctl` und `cmd/gomail-server` und die `testenv`-Tests in `internal/e2e` brauchen eine Entwicklungsplattform. Sie sind nur mit `-tags gomail_dev,gomail_test` aussagekräftig; ohne Tags überspringen sie sich (D85 (3), D88 (9) mit Nachtrag). Die Belege für den Produktionsbuild laufen nur ohne Tags. Kein Lauf allein deckt alles; welcher Lauf was trägt, steht in AUDIT 6.1.
- `internal/e2e` baut seine Programme selbst, in der Regel mit `gomail_dev,gomail_test`; `TestRunbook` und `TestInitProduction` nur mit `gomail_test` (D89 (2)). Für seine Server setzt es `GOMAIL_TEST_MIN_FREE` selbst. Andere Läufe auf einer Platte mit weniger als 10 % frei brauchen `GOMAIL_TEST_MIN_FREE=0.000001` (nur im Testbuild wirksam).

### Befehle

```
export GOTOOLCHAIN=go1.26.10
gofmt -l .
go vet ./...
go vet -tags gomail_dev,gomail_test ./...
GOOS=openbsd go vet ./...                                           # ebenso freebsd, netbsd, dragonfly, darwin
go test ./...                                                       # Lauf 1: Produktionsbuild
go test -tags gomail_dev ./cmd/gomailctl                            # Lauf 2: TestKeygenPipeProduction
go test -race -p 2 -tags gomail_dev,gomail_test -timeout 60m ./...  # Lauf 3
GOARCH=386 go test -p 2 -tags gomail_dev,gomail_test -timeout 60m ./...
go test -run '^$' -fuzz '^FuzzX$' -fuzztime 10m ./internal/<paket>  # je Fuzz-Ziel
scripts/two-host-test.sh --local …                                 # Test nach 9.1 ohne zweite Maschine (RUNBOOK 9)
scripts/bench.sh                                                    # Messungen (D77)
```

`-race` gibt es auf 386 nicht. Der Standard von `go test -timeout` ist 10 Minuten; `internal/client` braucht länger, daher jeder Lauf über das ganze Modul oder über `internal/client` mit `-timeout 60m`. Unter fremder Last ist auch das knapp: `internal/client` brauchte unter `-race` mit Tags bei geteilten CPUs bis 3401 s, also etwa 57 Minuten (Lauf des Implementierers von 20e, `docs/tasks/20-notes.md` „Aus 20e“); im Volllauf auf cb2344c (20b, Worktree-Commit, Zuordnung oben) scheiterten beide `client`-Schritte an einer Grenze von 40 Minuten unter Last 10 und bestanden mit 60 Minuten (ORCHESTRATION Abschnitt 6). Abschlussläufe deshalb möglichst ohne parallele Last. Der Abschluss-Volllauf auf 9ad24a5 lief neben anderen Läufen mit `nice -n 19` und bestand mit `-timeout 60m` (2178 s für `internal/client` mit Tags, Abschnitt „Laufzeiten“).

### Laufzeiten (Richtwerte, 4 Kerne)

| Lauf | Dauer | Quelle |
|---|---|---|
| `internal/client` mit `-race` und Tags | ohne Last 25 bis 35 Minuten (1489 s nach 14, 2003 s nach 09e); in den Volläufen 1942 s (09g, 7ffed5c), 2449 s (20b, cb2344c), 2338 s (20e, b2032d5), 2178 s (Abschluss, 9ad24a5); unter fremder Last bis 44 Minuten (20b) und bis 3401 s, etwa 57 Minuten (20e) | `docs/tasks/20-notes.md`; Protokolle des Orchestrators (Scratchpad `orch/fr-09g`, `orch/fr-20b`, `orch/fr-20e`, `orch/fr-final/racetag-internal_client.log`) |
| `internal/client` unter 386 mit Tags | etwa 15 bis 30 Minuten (868 s nach 14, 1733 s nach 09e, 1452 s im Volllauf auf 7ffed5c, 1755 s im Abschluss-Volllauf auf 9ad24a5) | `docs/tasks/20-notes.md`; Protokolle des Orchestrators (`orch/fr-09g`, `orch/fr-final/386-internal_client.log`) |
| `internal/client` mit `-cover` und Tags, ohne `-race` | 1334 s unter fremder Last (Lastmittel bis 15) | `docs/tasks/20-mandatory-tests.md` |
| `cmd/gomail-ceremony` mit `-race` | etwa 400 bis 435 s in den Volläufen (09g, 20b, 20e), im Abschluss-Volllauf 432,5 s ohne und 431,6 s mit Tags, unter 386 295,3 s; `TestPTYSignalSalvo` allein 250 bis 470 s | `docs/tasks/20-notes.md` (15n); Protokolle des Orchestrators |
| `internal/e2e` mit `-race` | etwa 109 bis 135 s in den Volläufen; im Abschluss-Volllauf 107,2 s ohne und 125,1 s mit Tags | Protokolle des Orchestrators (`orch/fr-final/race-internal_e2e.log`, `racetag-internal_e2e.log`) |
| `TestRunbook` | etwa 35 s | D89 |
| Volllauf aller Pakete (Abschluss) | auf 9ad24a5 106 Minuten (23:12:04 bis 00:58:09 UTC, 67 Schritte nacheinander; unter fremder Last durch Abdeckung, Auftrag 22 und einen Volllauf auf 3cd9072, jeweils mit `nice -n 19`, ORCHESTRATION, 04.11., 00:10 bis 00:50 UTC). Die längsten Schritte: `racetag-internal_client` 2178,2 s, `386-internal_client` 1755,2 s, `race-cmd_gomail-ceremony` 432,5 s, `racetag-cmd_gomail-ceremony` 431,6 s, `386-cmd_gomail-ceremony` 295,3 s, `racetag-internal_e2e` 125,1 s, `racetag-internal_ingest` 117,0 s, `race-internal_e2e` 107,2 s. Alle übrigen Schritte liegen unter 90 s. Auf dem Endstand (`orch/fr-m1/`, 67 Schritte, 01:32:49 bis 03:40:59 UTC): unterbrochen durch Container-Neustarts gegen 01:42, 03:26 und 03:40 UTC, unter fremder Last durch Prüfläufe und Abdeckung, von 02:15 bis 02:17 UTC dazu eine versehentliche Messung, während `racetag-internal_client` lief (ORCHESTRATION, 04.11., 01:42, 02:20 und 03:26 und 03:40 UTC, und Abschnitt 7 „Stand beim Anhalten (04.11.2026, 06:00 Uhr MEZ)“); eine Gesamtdauer ist deshalb kein Richtwert. Die längsten Schritte: `racetag-internal_client` 2036 s, `386-internal_client` 1260 s, `racetag-cmd_gomail-ceremony` 455 s, `race-cmd_gomail-ceremony` 438 s, `386-cmd_gomail-ceremony` 296 s, `racetag-internal_e2e` 109 s, `racetag-internal_bench` 108 s, `race-internal_e2e` 99 s (Zeile `ok … <s>s`). Alle übrigen Schritte liegen unter 90 s. | Scratchpad `orch/fr-final/` (Dauer aus der Zeile `ok … <s>s` am Ende jedes Logs, Gesamtdauer aus den Zeitstempeln von `gofmt.log` und `DONE`); ORCHESTRATION, 04.11., 00:58 UTC |

### Bekannte Flakes

- **Eingeordnet als Stillstand der Maschine, kein Fund im Produktivcode:** die 4,5-s-Grenze der Abbruchtests in `cmd/gomail-ceremony` (`stuckLimit`, `outputGrace` + 2,5 s, `cmd/gomail-ceremony/blocked15n_linux_test.go`). Sie scheiterte in zwei Volläufen: `TestPTYPromptBlocked` (`-race` ohne Tags) im Volllauf auf b2032d5 (20e) mit „no exit within 4.5s of share 1, prompt not shown“, die Wiederholung bestand (401,8 s); `TestPTYStopLoop/6` (`-race` mit Tags, Last 4 bis 5) im Volllauf auf dem Stand von 20h (302c6db, Code gleich 858b2f1) mit „share 1 neither cleared nor the program ended within 4.5s“ (19 Läufe im normalen Pfad gelöscht). Der Lauf ohne Tags bestand, die Wiederholung ebenfalls (ORCHESTRATION Abschnitt 6). Der Produktivcode der Zeremonie ist seit 20b unverändert, auch an b674ae3. 21c änderte danach `cmd/gomail-ceremony/main.go` und `internal/ceremony` (Abschnitt „Nachtrag 20o und Auftrag 21“); am Stand 9ad24a5 bestand `cmd/gomail-ceremony` im Abschluss-Volllauf in allen drei Schritten ohne Wiederholung (`orch/fr-final/`, kein `.fail`); 22 ändert in `cmd/gomail-ceremony` nur einen Kommentar. Zwei Fehlschläge in zwei Läufen behandelte der Orchestrator zunächst als echten Fund und ließ sie analysieren (D85 Nachtrag 20n; `docs/tasks/20-notes.md`, „Analyse der 4,5-s-Fehlschläge der Zeremonie“).
  - **Ergebnis:** Einen Fehler im Programm fand die Analyse nicht. Solange Programm und Test Rechenzeit bekommen, steht ein Anteil höchstens etwa 3,6 s nach Beginn der Ausgabe: `outputGrace` 2 s, dann `abortTotal` 1,5 s und wenige `abortFloor` (`cmd/gomail-ceremony/main.go`). Beide Fehlschläge setzen einen Stillstand des Programms oder des lesenden Testteils voraus, nach der Analyse von mindestens 2 s (aus den Schranken allein folgt ein Spielraum von etwa 0,9 s bis 4,5 s; D85 Nachtrag 20n); beobachtet oder nachgestellt wurde er nicht. Die Maschine war eine Firecracker-VM mit 4 geteilten vCPU, Last 2 bis 6, I/O-Druck bis 65 %, 90 % voller Platte und ohne Swap.
  - **Nicht nachgestellt:** 4 normale und rund 60 verfolgte Läufe waren alle grün. Die Protokolle liegen im Scratchpad `flake-promptblocked/`, `orch/fr-20e` und `orch/fr-20h`.
  - **Einordnung:** Die Zeitgrenzen des Abbruchpfads gelten in der Zeit des Programms; kein Benutzerprogramm kann sie garantieren, während es nicht läuft. Im Produktivcode gibt es keinen offenen Fund. `stuckLimit` bleibt bei 4,5 s.
  - **Auftrag 20m** (90e248b, nur Testcode, zusammengeführt; D85 Nachtrag 20m): `TestPTYNonblockClear`, `TestPTYPartialShare`, `TestPTYPromptBlocked`, `TestPTYStopLoop`, `TestPTYExitNotStopped` und `TestPTYUnblockBrief` messen bei einer abgelaufenen Wartezeit die Run-Queue-Wartezeit und die CPU-Zeit des Programms (`/proc/<pid>/task/*/schedstat`), die Zeit, die der Test es selbst angehalten hat (Zustand T nur bei eigenem Stopp des Tests), und die Lücken der Warteschleife und der Leser der Terminals. Liegt eine Größe über 500 ms (die Run-Queue nur, wenn das Programm höchstens 500 ms auf einer CPU lief), wird der Teiltest einmal wiederholt (`retryStalled`); steht er auch dann, wird er mit den Messwerten übersprungen. Ohne Stillstand scheitert er wie vorher, nach einer Diagnose der Threads. Die Prüfung fand 1 hoch und 1 mittel, beide nachgearbeitet; die Restgrenzen stehen in D85 Nachtrag 20m.
  - **Regel für die Abnahme:** Ein Stillstand ergibt jetzt einen SKIP, wo vorher ein FAIL an der 4,5-s-Grenze stand. Jeder SKIP dieser Tests wird im Abnahmelauf geprüft (`go test -v`, Messwerte und Zustand der Threads in der Ausgabe); ein Fehler, der auf einem Thread kreist und bei starker Überlast kaum CPU bekommt, kann als Stillstand erscheinen.
  - **SKIP-Nachweis zum Abschluss:** Die Volläufe `fr-final` und `fr-m1` liefen ohne `-v`; ein `t.Skipf` der Stillstandserkennung steht deshalb nicht in ihren Logs. Der Nachweis stammt aus einem eigenen Lauf, `orch/fr-m1-v/`: `go test -v -count=1` für `cmd/gomail-ceremony` unter `-race` ohne Tags (`race.log`), `-race` mit Tags (`racetag.log`) und 386 mit Tags (`386.log`). Quelle war 10b1783; ihr Code gleicht 1217496 bis auf `internal/client/platform23_test.go` (23b), `cmd/gomail-ceremony` ist gleich, und damit auch gleich fba4eb2. Alle drei Läufe endeten mit `ok` (435,0 s, 445,5 s, 304,9 s). `grep -n -- '--- SKIP'` findet in jedem Log genau zwei Stellen. Die erste ist `TestStallChild` (`race.log` Z. 759, `racetag.log` Z. 759, `386.log` Z. 759): der Hilfsprozess, der sich überspringt, wenn er nicht als Kind von `TestStallDetect` gestartet ist („a child of TestStallDetect only“). Die zweite ist `TestStallDetect/retry_stalled_twice/inner` (Z. 881, 882, 877): der Selbsttest der Stillstandserkennung, der den SKIP nach zwei Stillständen absichtlich herbeiführt. `grep -n 'did not run in both attempts'` trifft je einmal (Z. 849, 850, 845), und zwar in der Ausgabe dieses Selbsttests (der Test hält das Programm selbst an, in `race.log` „stopped by the test 2.001s“). Kein echter Teiltest wurde übersprungen. `TestPTYNonblockClear`, `TestPTYPartialShare`, `TestPTYPromptBlocked`, `TestPTYStopLoop`, `TestPTYExitNotStopped` und `TestPTYUnblockBrief` stehen in allen drei Logs als `--- PASS`, ohne Wiederholung: `grep -n 'repeated once'` trifft nur die Teiltests `retry` und `retry_stalled_twice` von `TestStallDetect`.
- `internal/client` `TestWordErrorsNameNoInput`: behoben (09g). Der Test prüft über `leakedWord` nur noch ganze Seed-Wörter, die nicht schon in der festen Meldung stehen (`internal/client/generations_test.go`, `TestLeakedWord`; `docs/tasks/20-triage.md` Nr. 197).
- Unter Last aufgefallen, seither nicht wieder als Fehler protokolliert: `TestPTYQuitInCommit` (einmal 61 s) und `TestTwoHostScript` (einmal gescheitert) (`docs/tasks/20-triage.md`, Nr. 138 und 152). In den Volläufen auf 7ffed5c, cb2344c und b2032d5 bestanden `cmd/gomail-ceremony` (auf b2032d5 nach einer Wiederholung) und `internal/e2e`, ebenso in den späteren Volläufen auf 302c6db (Code gleich 858b2f1; `cmd/gomail-ceremony` auch dort nach einer Wiederholung) und 1d49e6d (Code gleich b674ae3 ohne die Tests aus 20m), ebenso im Abschluss-Volllauf auf 9ad24a5 (`orch/fr-final/`, ohne Wiederholung). Auf dem Endstand bestanden beide ebenfalls (`orch/fr-m1/`), ohne Wiederholung wegen eines Fehlschlags; nur nach den Container-Neustarts lief der jeweils abgebrochene Schritt neu.

### Testvektoren

Testvektoren liegen unter `internal/<paket>/testdata/`, die Generatoren unter `internal/<paket>/testdata/gen/` (`go run ./testdata/gen` im Paketverzeichnis). Die Vektoren der Phase-0-Pakete (`rec`, `keys`, `shamir`, `envelope`) dürfen sich nicht ändern; jeder Auftrag prüft vor dem Commit, dass `git diff --stat 38626a9 -- internal/{rec,keys,shamir,envelope}/testdata` leer ist. Die `.gml`-Dateien aus Phase 0 (Rahmen ohne Typbytes) liegen unter `internal/envelope/testdata/phase0/` und müssen abgelehnt werden.

## rec

### API

```go
type Kind uint8            // U8, U32, I64, Bytes, String, List
type Field struct { Num uint8; Name string; Kind Kind; Required bool; Size, MaxLen int; Elem *Schema; MaxCount int }
type Schema struct { Type string; Fields []Field }
func NewSchema(typ string, fields ...Field) (*Schema, error)
func MustSchema(typ string, fields ...Field) *Schema          // panics on a bad schema (programming error)
func (s *Schema) Prefix() []byte                               // Typ || 0x00

type Record
func New(s *Schema) *Record
func (r *Record) SetU8/SetU32/SetI64/SetBytes/SetString/SetList(num, v) *Record   // verkettbar, erster Fehler bleibt
func (r *Record) Err() error
func (r *Record) Encode() ([]byte, error)
func Decode(s *Schema, data []byte) (*Record, error)
func (r *Record) Has(num) bool; U8/U32/I64/Bytes/String/List(num)   // Nullwert bei Abwesenheit, nie Panic
const MaxRecordSize, MaxValueLen = 1 << 20; MaxTypeLen = 64
var ErrBadType, ErrTruncated, ErrFieldOrder, ErrUnknownField, ErrBadLength, ErrTooLong, ErrTooMany,
    ErrMissingField, ErrBadString, ErrNotNormalized, ErrKind, ErrSchema
```

### Invarianten
- Ein Schema wird einmal gebaut und danach nicht verändert. Feldnummern 1..255, aufsteigend; `Bytes` hat genau eines von `Size` und `MaxLen`; `String` braucht `MaxLen`; `List` braucht `Elem` und `MaxCount`.
- `Decode` ist strikt: Was es annimmt, kodiert `Encode` byte-identisch zurück. Teilergebnisse gibt es nicht.
- Strings müssen gültiges UTF-8 in NFC sein und dürfen kein Nullbyte enthalten; `rec` normalisiert nie, es lehnt ab. Aufrufer, die Benutzereingaben annehmen, normalisieren vorher selbst mit `norm.NFC.String`.
- `Bytes` und `List` liefern Kopien; `SetBytes` kopiert die Eingabe. Listenelemente werden beim `Encode` erneut geprüft.
- `rec.Kind` ist die Feldart und hat nichts mit `envelope.Kind` (Dateiart) zu tun.

### Grenzen
- Keine Normalisierungsfunktion, nur die Prüfung über `golang.org/x/text/unicode/norm` (Unicode 15.0.0 in v0.43.0). Die UTF-8-Prüfung bleibt getrennt, weil `x/text` ungültige Bytes als normalisiert meldet. Beim Anheben von `x/text` die Unicode-Version beachten: Strings, die unter einer neueren Version anders normalisieren, würden von älteren Clients abgelehnt.
- Kein streamendes Dekodieren; Eingaben sind Byte-Slices bis `MaxRecordSize`.

## keys

### API

```go
type Seed [32]byte
func NewSeed(r io.Reader) (*Seed, error)                      // nil = crypto/rand
func (s *Seed) Words() ([]string, error)                      // 24 BIP-39-Wörter
func SeedFromWords(words []string) (*Seed, error)             // exakt 24, exakt wie in der Liste
func (s *Seed) Zero(); func Wipe(b []byte)
func Wordlist() []string; LookupWord(w string) (int, bool); Word(i int) (string, bool)
const WordlistSHA256

func DeriveUser(seed *Seed) *UserRoot
func (u *UserRoot) RootKey() (ed25519.PrivateKey, error)
func (u *UserRoot) IdentityKey(gen uint32) (ed25519.PrivateKey, error)
func (u *UserRoot) UnwrapKey(gen uint32) (*ecdh.PrivateKey, error)
func (u *UserRoot) Zero()
func DerivePlatform(seed *Seed) *PlatformRoot
func (p *PlatformRoot) IdentityKey/AdminKey/IngestKey(gen uint32) (ed25519.PrivateKey, error)
func (p *PlatformRoot) Zero()

func Sign(priv ed25519.PrivateKey, domain string, body []byte) ([]byte, error)   // "gomail/v1/sig/"+domain+0x00+body, domain aus der Tabelle in 3.7
func KnownDomain(d string) bool; RecordDomain(s *rec.Schema) (string, error)
const DomainPlatformCert, DomainPlatformSuccession, DomainUserGen, DomainEpoch, DomainAddress, DomainCheckpoint, DomainUser, DomainInvite, DomainWrapAccept, DomainMail, DomainMeta, DomainPending, DomainWrap, DomainIndex
func Verify(pub ed25519.PublicKey, domain string, body, sig []byte) bool

type GenerationCert struct { Gen uint32; IdentityPub ed25519.PublicKey; UnwrapPub *ecdh.PublicKey; Created int64; Revokes uint32; Signature []byte }
func NewGenerationCert(root ed25519.PrivateKey, gen uint32, identityPub ed25519.PublicKey, unwrapPub *ecdh.PublicKey, created int64) (*GenerationCert, error)
func (c *GenerationCert) Encode() ([]byte, error); DecodeGenerationCert([]byte) (*GenerationCert, error)
func (c *GenerationCert) Verify(rootPub ed25519.PublicKey) error
func VerifyGenerationChain(rootPub ed25519.PublicKey, certs []*GenerationCert) error

type PlatformCert struct { Role Role; Gen uint32; Pub ed25519.PublicKey; IdentityGen uint32; ValidFrom int64; Signature []byte }   // 2.3, Version 1.1
func NewPlatformCert(identity ed25519.PrivateKey, identityGen uint32, role Role, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformCert, error)
func DecodePlatformCert([]byte) (*PlatformCert, error); (c *PlatformCert) Encode(); Verify(identityPub) error
type PlatformSuccession struct { Gen uint32; Pub ed25519.PublicKey; ValidFrom int64; Signature []byte }   // gomail/v1/rec/platform-succ
func NewPlatformSuccession(prev ed25519.PrivateKey, gen uint32, pub ed25519.PublicKey, validFrom int64) (*PlatformSuccession, error)
func DecodePlatformSuccession([]byte); (s *PlatformSuccession) Encode(); Verify(prevPub, prevGen) error

type Keystore struct { Generation uint32; Identity ed25519.PrivateKey; Unwrap *ecdh.PrivateKey }
func (k *Keystore) Seal(passphrase []byte, r io.Reader) ([]byte, error)   // Argon2id 64 MiB/3/4, r: 16 Byte Salt, 12 Byte Nonce
func OpenKeystore(data, passphrase []byte) (*Keystore, error)
func (k *Keystore) Zero()
func WriteKeystoreFile(path string, data []byte) error; ReadKeystoreFile(path string) ([]byte, error)
var GenerationCertSchema, PlatformCertSchema, PlatformSuccessionSchema, KeystoreHeaderSchema, KeystoreContentSchema
var ErrWordlist, ErrWordCount, ErrUnknownWord, ErrChecksum, ErrGeneration, ErrZeroed, ErrDomain, ErrSignature,
    ErrCert, ErrKeystore, ErrPassphrase, ErrKDFParams
```

### Invarianten
- Generationen beginnen bei 1 und sind lückenlos; `VerifyGenerationChain` verlangt die vollständige Folge ab 1. Ob eine Signatur einer widerrufenen Generation vor dem Widerruf im Log stand (2.2 Punkt 4), prüfen Log und Client (`CheckRevokedSignature`, D88; Prüfvermerke für Dateien außerhalb des Logs, D84, D91).
- `RootKey` nur kurz im Speicher halten und mit `keys.Wipe` löschen; `UserRoot.Zero` nach der Ableitung aufrufen. Der Seed wird nie gespeichert.
- Signaturdomänen sind die Kurznamen aus 3.7 (Version 1.2) als Konstanten `Domain*`; `Sign` und `Verify` nehmen keine anderen an, `RecordDomain(schema)` liefert den Kurznamen eines Datensatztyps (DECISIONS D47). Ein neuer signierter Typ braucht eine neue Zeile in 3.7 und in `keys`.
- `Decode*` prüft Struktur, nicht Signatur; `Verify` immer aufrufen.
- Der Schlüsselspeicher enthält nur die aktuelle Generation. Beim Öffnen werden KDF-Parameter aus dem Kopf innerhalb fester Grenzen übernommen (64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads); schwächere als die Spezifikation nie.
- Die Passphrase ist `[]byte` (damit sie überschreibbar ist) und darf nicht leer sein.

### Grenzen
- `ecdh.PrivateKey` lässt sich nicht überschreiben; `Keystore.Zero` löscht den Ed25519-Schlüssel und gibt den X25519-Schlüssel nur frei.
- `user.rec` ist seit Auftrag 02 ein signierter Datensatz in `store` (Kurzname `user`, D68).
- `SeedFromWords` bleibt exakt; die Normalisierung der Eingabe (S11) macht `internal/words` (D85 (5)).

## shamir

### API

```go
const SecretSize = 32; ShareSize = 37; ShareWords = 30
type Share struct { ID uint16; Threshold uint8; Index uint8; Y [32]byte }
func Split(secret []byte, threshold, count int, r io.Reader) ([]*Share, error)   // r: 2 Byte ID, dann 32*(threshold-1) Koeffizienten
func Combine(shares []*Share) ([]byte, error)
func (s *Share) Bytes() []byte; ShareFromBytes([]byte) (*Share, error)
func (s *Share) Words() []string; ShareFromWords([]string) (*Share, error)
func (s *Share) Zero()
var ErrParams, ErrSecretSize, ErrShare, ErrDuplicate, ErrMismatch, ErrInsufficient, ErrWordCount, ErrUnknownWord, ErrChecksum
```

### Invarianten
- `Combine` liefert bei konsistenten Anteilen das Geheimnis, bei einem falschen oder manipulierten Anteil einen falschen Wert ohne Fehler. Das rekonstruierte Geheimnis muss anders geprüft werden (Probe-Rekonstruktion in der Zeremonie, Vergleich der abgeleiteten öffentlichen Schlüssel).
- Anteile sind so geheim wie das Geheimnis. Nach Gebrauch `Zero`.
- Die Kennung erkennt vermischte Aufteilungen, die Prüfsumme Tippfehler; beides ist kein Integritätsschutz gegen Angreifer.

### Grenzen
- Nur 32-Byte-Geheimnisse. Nicht SLIP-39-kompatibel.

## envelope

### API

```go
const Magic = "GOML"; FormatVersion = 1; Suite1 Suite = 1
const ChunkSize = 65536; MaxBlocks = 800; MaxContentSize = 800*65536; MaxRecipients = 4
const MaxHeaderSize = 4096; MaxRecipientsSize = 16384; MaxTrailerSize = 1024; MaxExtraSize = 4096; MaxFileSize
const ElemBlock = 0x01; ElemLastBlock = 0x02; ElemTrailer = 0x03   // Typbytes der Elemente nach dem Empfängerteil
type Kind uint8          // KindMail=1, KindMeta, KindPending, KindWrap, KindIndex; String() liefert den Domänennamen
type RecipientType uint8 // RecipientEpochContent=1, RecipientEpochMeta, RecipientUserUnwrap, RecipientRecovery
type SignerType uint8    // SignerIngest=1, SignerUser

type Header struct { Kind Kind; MailboxID [16]byte; Epoch uint32; FileID [16]byte; NoncePrefix [7]byte; ChunkSize uint32; Created int64 }
type Recipient struct { Type RecipientType; ID [16]byte; Gen uint32; PublicKey *ecdh.PublicKey }
type Signer struct { Type SignerType; ID [16]byte; Gen uint32; Key ed25519.PrivateKey; Extra []byte }
type SealOptions struct { Rand io.Reader; Signer *Signer }     // Rand: 7 Byte Nonce-Präfix, dann 32 Byte Dateischlüssel
func Seal(hdr Header, recipients []Recipient, plaintext []byte, opts *SealOptions) ([]byte, error)
func NewWriter(w io.Writer, hdr Header, recipients []Recipient, opts *SealOptions) (*Writer, error)
func (w *Writer) Write(p []byte) (int, error); Close() error

type File struct { Suite Suite; Header Header; Recipients []RecipientEntry; Trailer *Trailer }
func Parse(data []byte) (*File, error)                        // ohne Schlüssel, strukturell vollständig; nimmt genau ElemBlock* ElemLastBlock ElemTrailer? an
func (f *File) Bytes() []byte; FileHash() [32]byte
func (f *File) VerifySignature(pub ed25519.PublicKey, extra []byte) error
func (f *File) Decrypt(key RecipientKey) ([]byte, error)      // fail closed
type RecipientKey struct { Type RecipientType; ID [16]byte; Gen uint32; PrivateKey *ecdh.PrivateKey }
type OpenOptions struct { ExpectedSuite Suite; Key RecipientKey; ResolveSigner func(SignerRef) (ed25519.PublicKey, error); AllowUnsigned bool; Extra []byte }
func Open(data []byte, opts OpenOptions) (*File, []byte, error)
func CheckSuiteTransition(prev, next Suite) error
var HeaderSchema, RecipientSchema, RecipientsSchema, TrailerSchema, SignedSchema
var ErrMagic, ErrVersion, ErrSuite, ErrTruncated, ErrTooLarge, ErrHeader, ErrHeaderSize, ErrRecipients, ErrRecipientsSize,
    ErrBlockSize, ErrEmptyBlock, ErrElementType, ErrElement, ErrTrailer, ErrTrailerSize, ErrNoRecipient, ErrUnwrap, ErrDecrypt,
    ErrSignature, ErrSigner, ErrUnsigned, ErrSignaturePolicy, ErrWrap, ErrRandom, ErrClosed
```

Nachtrag seit Phase 1: Kopffeld 8 `version` (`Header.Version`, Version 1.4, D66), Pflicht und mindestens 1 für Art `meta`; `meta-signed` nur aus Kopf und Hashes (Auftrag 01).

### Invarianten für Aufrufer
- Jede Datei bekommt einen neuen Dateischlüssel und einen neuen Nonce-Präfix (beide zieht der Schreiber). Nie eine Datei durch Verändern einer bestehenden erzeugen; immer neu versiegeln (3.3 Regel 1).
- `FileID` im Kopf muss der ID im Dateinamen entsprechen; das prüft die Ablage, nicht `envelope`. Ebenso prüft die Ablage `MailboxID` und `Epoch` gegen den Ort der Datei und die Epochenkette (2.4).
- `OpenOptions.ExpectedSuite` kommt aus der signierten `epoch.rec` der Datei-Epoche; `CheckSuiteTransition` beim Prüfen der Epochenkette aufrufen.
- Signaturpolitik: Mail-Dateien mit `AllowUnsigned`, alle anderen mit `ResolveSigner`. `envelope` koppelt `AllowUnsigned` nicht an die Dateiart (Indexsegmente sind seit Version 1.4 signiert, D79 (1)); die Ablage muss die Politik je Dateiart setzen und darf `AllowUnsigned` nie pauschal verwenden. Der Resolver setzt Abschnitt 7 um: unbekannter Schlüssel, fehlendes Zertifikat, Widerruf, kompromittierte Generation führen zu einem Fehler. `Extra` muss beim Prüfen gleich dem beim Signieren sein; für Metadaten ist es `gomail/v1/rec/meta-signed` (`store.MetaSignedSchema`, Abschnitt 7, K6).
- Eine Mail-Datei (unsigniert) schützt ihren Empfängerteil nicht gegen Änderungen an fremden Einträgen. Der Client prüft deshalb den SHA-256 der Mail-Datei aus den signierten Metadaten. `FileHash` liefert den Hash aller Bytes vor dem Trailer-Element; bei einer unsignierten Datei ist das die ganze Datei.
- Dateiaufbau nach dem Empfängerteil (Version 1.1): Elemente `Typbyte || uint32 Länge || Inhalt`, genau in der Folge `0x01* 0x02 0x03?`. Eine unsignierte Datei endet mit dem `0x02`-Element. Das Typbyte eines Blocks muss zum Letzter-Block-Flag im Nonce passen; sonst scheitert die Authentifizierung.
- `RecipientRecovery` (Typ 4) gehört nach 2.4 nur in `epochs/<n>/members/recovery.wrap`, nie in Mail- oder Metadatendateien. `envelope` nimmt Typ 4 in jeder Datei an (3.1); die Ablage setzt die Regel aus 2.4 beim Schreiben und Lesen durch. Dateien sind unveränderlich: der Empfängerteil wird nie nachträglich ergänzt.
- `SealOptions.Rand` und der Reader von `Keystore.Seal` sind für Testvektoren gedacht. Im Betrieb immer `nil` übergeben (crypto/rand); ein fester Reader würde Nonce-Präfix und Dateischlüssel wiederverwenden.
- `Parse` braucht die ganze Datei; Dateien sind auf `MaxFileSize` begrenzt. Für Dateien aus dem Dateisystem die Größe vor dem Lesen prüfen.
- Streaming beim Schreiben: `NewWriter` schreibt sofort Präambel, Kopf und Empfängerteil; erst `Close` macht die Datei gültig. Bei Abbruch die Datei verwerfen (passt zum `spool/`-Verfahren in 5.2).
- Der Schreiber überschreibt `Header.NoncePrefix` und `Header.ChunkSize`.

### Grenzen
- Kein streamendes Lesen in Phase 0.1: `Parse` braucht die ganze Datei, obwohl der Elementrahmen seit Version 1.1 streamendes Parsen erlauben würde. Entschlüsselung puffert den gesamten Klartext (bis 50 MiB).
- Nur Suite 1. Suite 2 braucht andere Feldgrößen im Empfängerteil; vier Einträge passen in `MaxRecipientsSize` (S12).
- HPKE-Kapselungen sind nicht reproduzierbar; deterministische Vektoren decken Präambel, Kopf und Blöcke ab.

## store

Datenverzeichnis nach Abschnitt 4 (Version 1.4). Was seit Phase 1 dazukam, steht in D68 bis D70, D73, D78, D87 und D91; die API steht in `internal/store`.

### Invarianten
- Alles im Datenverzeichnis wird über `store` geschrieben: atomar, mit `fsync` von Datei und Verzeichnis; nie eine Datei an Ort und Stelle verändern. `epoch.rec`, Plattformdateien und `user.rec` werden nur exklusiv angelegt. Einzige Ausnahme: `ReplaceEpoch` ersetzt eine nie loggbare `epoch.rec` unter der Postfachsperre, und nur wenn der Aufrufer per `unloggable` belegt, dass das Log sie mit `ErrOrder` verweigert (D88 (4)).
- Jede Datei wird mit `ReadFileLimited` gelesen: Größe vor dem Lesen geprüft, geöffnet mit `O_NONBLOCK` und seit 20i unter Unix mit `O_NOCTTY` (`OpenRegular`, `openNoCTTY`), nur reguläre Dateien (D48, D87 Nachtrag 20a, D86 Nachtrag 20i). Andere Öffnungen ohne diesen Schutz: AUDIT R41.
- Seit 20l gibt es `WritePrivateFileAtomicIn` und `SyncRoot` (`fs.go`). Sie schreiben über ein `os.Root` in ein Verzeichnis, auch wenn dessen Pfad inzwischen ein anderes nennt. Genutzt werden sie von `createClientDir`; sie sind der Ausgangspunkt für die Abhilfe nach D92 (3). Seit Auftrag 26 (Paket 26B) kommen `OpenRegularIn`, `ReadDirIn`, `WriteFileAtomicIn`, `CreateFileAtomicIn`, `ReplaceFileIn`, `RemoveTempReportIn` und `SyncDirIn` dazu (`fsroot.go`, entfernt wird per `unlinkat` in `removenamein_unlinkat.go`, außerhalb von Linux und AIX mit Restfenster in `removenamein_other.go`); `publish` nutzt sie, ihre Fehler nennen den Pfad wie die Funktionen auf Pfaden. `Store.RemoveTempFiles` entfernt seitdem per Unlink und lässt Verzeichnisse stehen.
- Lesefunktionen prüfen Ort gegen Inhalt, nicht Signaturen. Signaturen, Kette (`store.Chain`, D64, D68) und Log prüft der Aufrufer.
- Sperren nach 9.1 in der Lesart D70: POSIX-Satzsperren (OFD unter Linux), Rollensperren `locks/server` (exklusiv) und `locks/client` (geteilt), Postfachsperren; mehrere Postfächer nur über `LockMailboxes`. Rechte 2770/0660, Gruppe `gomail` (D70, D81 (4)). Eine bestehende Sperrdatei wird seit 20l mit `O_NOCTTY|O_NONBLOCK` geöffnet und muss nach fstat regulär sein, sonst `ErrNotRegular` vor dem Sperren (`openExistingLock` in `lock_unix.go`).
- Nur `gomail-server init` legt ein Datenverzeichnis an (D87).
- Dekodierte Datensätze sind kanonisch; leere optionale Felder werden abgelehnt.
- `CleanText` ersetzt Steuerzeichen einschließlich C1 und Bidi (D86 (3)).

## translog, witness, loghttp

Verbindlicher Entwurf: `internal/translog/doc.go` (Abschnitte „Reference head“, „Validity rules“, „Who writes“, „Unlogged epoch.rec“, „Withheld entries“, „What write access to log/ gives an attacker“, „Witness quorum“, „Platform generations“). Umsetzung D78 (Log), D80 (Serverseite), D81 (Ingest und Server), D88 (Client), D74 (Zeuge).

- `translog.Log` ist die Schnittstelle für alle Prüfungen und Einträge; `translog.Open` liefert ein Client-Log (mit `Verifier`, Referenzkopf aus `state.json`) oder ein Operator-Log (Server, Zeremonie; Referenz ist `log/tree.rec`).
- Das Urteil über einen Eintrag ist eine Funktion von Logpräfix und Anker; jeder Client urteilt gleich. Köpfe gelten nur mit dem Quorum der Zeugen nach Schlüsseln; ein Kopf ist höchstens 24 Stunden alt (23 Stunden mit offenem eigenem Eintrag).
- Operator-Log fail closed: ein geschrumpftes oder beschädigtes `tree.rec` stoppt Annahme und Signatur bis `gomail-server log repair` und Neustart (D81 (3)); `RepairTree` meldet verwaiste Einträge und löscht nichts.
- `loghttp`: `GET /gomail/log/head`, `GET /gomail/log/consistency`, `POST /gomail/log/cosign`; Zeitlimits und Größengrenzen, keine Verbindungsobergrenze (AUDIT R8).
- `witness`: acht Regeln aus 2.7, Zustand vor der Gegensignatur dauerhaft, Fork beendet den Dienst (Exit 3).
- `translogtest.Unverified` nimmt alles an und dient nur Testcode und `testenv` (Serverseite der Testplattform); kein Programm nutzt es.

## smtpd

```go
type Backend interface { Accepting() error; Recipient(address string) error; Begin(Session, from string, rcpts []string) (Delivery, error) }
type Delivery interface { Write([]byte) (int, error); Commit() error; Abort() }
type Session struct{ ID, Helo, RemoteIP string }
type Config struct{ Hostname; MaxSize; MaxRecipients; CommandTimeout; DataTimeout; MaxConns; MaxConnsPerIP; MinRate; RateWindow; MaxMailsPerIP; RateMemory; Now; Logger }
func NewServer(Config, Backend) *Server; (s) Serve(net.Listener) error; Close() error
var ErrUnknownRecipient /*550*/, ErrDiskFull /*452*/, ErrTemporary /*451*/, ErrClosed
```

- `250` nach `DATA` erst, wenn `Commit` ohne Fehler zurückkam. Bei jedem Abbruch ruft die Sitzung `Abort`.
- Der Server schreibt den `Received`-Header als erstes in die Zustellung; Inhalte, Header und Adressen loggt er nie (nur Sitzungs-ID, Größen, Statuscodes).
- Grenzen und Antworten: DECISIONS D54. Zeitlimits und die Mindestrate laufen über `Config.Now` und Lese-Deadlines.
- Seit Auftrag 01 kündigt `EHLO` `SIZE` 26.214.400 an (25 MiB, 5.1); gezählt werden nur die Daten des Absenders (S62).

## ingest

`ingest.New` prüft Ingest-Schlüssel gegen sein Zertifikat, das Zertifikat im Log und `valid_from` gegen die Uhr des Servers ohne Toleranz (D90); dann nimmt es die Serversperre, auf Verlangen prüft es die Client-Sperre, zuletzt, dass die Generation nicht abgelöst ist (`internal/ingest/ingest.go`, `New`).

### Invarianten
- Ablauf je Mail: Epochenwahl bei jedem `DATA` unter der Sperre (K8, D71), Verschlüsselung je Postfach im Spool, Metadaten und Marker, Journal, Umbenennungen (D50, D52). Kein Klartext auf der Platte; die Warteschlange lagert nur verschlüsselt aus (`mlock`, sonst nicht).
- Gegen das Log geprüft werden `epoch.rec` und `user.rec` des Signierers, die Adresszuordnung (bei RCPT, in `Begin` und im Commit) und die eigene Ingest-Generation (in `New`, `Begin` und im Commit). Jeder Logfehler ist `451`; gegen eine ungeloggte oder zurückgesetzte Epoche wird nie verschlüsselt (D81 (1)).
- Jede eigene Signatur wird vor dem Commit ohne Schlüssel selbst geprüft (D73).
- `Recover` muss vor dem ersten `Begin` laufen. `BatchSize` höchstens `store.MaxBatch` (D81 (6)).
- Unbekannter freier Platz ist fail closed (`451`, S81); die 10-%-Grenze ist nur im Testbuild veränderbar.
- Absturzpunkte für Tests: Paketvariable `crashHook`, nur in Tests gesetzt.

## terms und words

- `internal/terms` hält die Regeln aus D55 einmal: Begriffe einer Mail (`List`), Anfragen (`Query`), Thread-Wurzel (`ThreadRoot`), Anhang (`HasAttachment`). `ingest.Terms` und `client.metaTerms` rufen sie auf (D91 (1)). Für Mails ohne Begriffsliste bildet der Client `thread:` aus der eigenen Message-ID (S23, Q12).
- `internal/words` normalisiert Seed- und Anteilswörter (NFKD, Kleinschreibung, beliebiger Leerraum) und prüft `MaxTokens` und `MaxInput` vor der Normalisierung (D85 (5)). `internal/client/words.go` ist nur noch eine Hülle darüber.

## client

Einstieg: `Keygen`, `Register`, `Restore`, `DeviceLost`, `Open`; am `Client`: `CreateMailbox`, `Share`, `Revoke`, `Sync`, `List`, `Read`, `Search`, `Index`, `SetFlags`, `SetFolders`, `Rename`, `Mailboxes`; dazu `Inspect`. `Config` trägt Datenverzeichnis, Client-Verzeichnis und Pin; das Log baut der Client selbst (D88 (1)).

### Prüfungen
- Jede Operation beginnt mit `ready()`: `Refresh` beim Öffnen, danach `CheckFresh` (24-Stunden-Regel); `Sync` und `DeviceLost` refreshen zusätzlich (D88 (1)).
- Vor jeder Verwendung: `CheckUser`, `CheckGeneration`, `CheckRevokedSignature`, `CheckEpoch` für jede Epoche, `CheckAddress` für jede Mail, `CheckPlatform` (D88 (2)). Danach die Lesepfade aus 2.4 und 7: Kette ab Epoche 1 (`store.Chain`, `checkSignerGen` als lokale Schranke, Q13), Verpackung, Metadaten mit Versionsregel und Merkzettel (Epoche, Empfangszeit, Mail-Hash, SHA-256 der Metadatei), Mail nur mit passendem Hash.
- Signaturen einer widerrufenen Generation außerhalb des Logs zählen nur mit Prüfvermerk vor dem Widerruf und werden dann neu signiert (D84, D91; AUDIT R27).
- Vermerke anderer Mitglieder (`checkpoints/`) werden in beide Richtungen verglichen; `Unconfirmed` bleibt bis zum Vermerk eines anderen Benutzer-Mitglieds (D88 (5), (6); Q20).

### Invarianten
- **Kein Pfad verkleinert den lokalen Zustand eines Postfachs** (D84 (2), S74). Einträge in `Checked` dürfen an Ort und Stelle in fester Größe geändert werden (D91 (6)).
- Wachstum von `state.json` ist begrenzt mit dokumentierter Rate; gelesen wird bis 64 MiB (`loadState`). Ohne Schlüssel bei Schreibzugriff: AUDIT R27 (a); im ehrlichen Betrieb: AUDIT R43.
- `List` zeigt nur Mails, die alle Prüfungen bestanden haben, und warnt für jede andere; `Read` gibt bei jedem Fehler nichts heraus. Warnungen nennen nur IDs, Nummern und feste Ursachen (`warnCause`).
- Erste Einträge nach „Who writes“: erst Log, dann Datei (`Register`, `CreateMailbox` über `new-mailboxes/`), Epochen und Generationen erst Datei, dann Log (D88 (3)).
- Schreibfolgen sind absturzsicher: was nach einem Absturz übrig bleibt, übernimmt oder räumt der nächste Lauf (Vormerkungen `Reissue`, `ErrPartial`). `keygen` (seit 20b) und `restore` (seit 20e) legen das Client-Verzeichnis in einem Temp-Verzeichnis `.<name>.keygen-*` bzw. `.<name>.restore-*` an und benennen es um (`createClientDir` in `internal/client/keygen.go`); Reste mit dem Marker `.incomplete` räumt der nächste erfolgreiche Lauf derselben Art (`removeLeftovers`, seit 20h nur mit Marker und nur bekannte Dateinamen). Seit 20l läuft alles im Temp-Verzeichnis über einen Deskriptor (`os.OpenRoot` in `openTempDir`, `store.WritePrivateFileAtomicIn`). `sameDir` prüft vor `lockOnlyDir`, vor und nach dem Umbenennen, dass der Pfad noch das eigene Verzeichnis nennt; sonst endet der Lauf mit `errTempReplaced`. Vor dem Umbenennen benennt er dann nichts um und entfernt nichts; nach dem Umbenennen steht an `--dir` möglicherweise ein fremdes Verzeichnis. Aufgeräumt wird nur bei gleicher Identität und nur durch den Deskriptor (`removeTempDir`). `ErrExists` meldet ein verlorenes Temp-Verzeichnis seit 20i nur bei belegtem Ziel (`dirTaken`). Restgrenzen: AUDIT R33.
- **Pfadbasiertes Schreiben eines offenen Clients** (D92, AUDIT R46): Nach dem Sperren schreibt der Client `state.json` (`saveState`), die Kopien neuer Postfächer unter `new-mailboxes/` (`prepareMailbox`, Entfernen mit `os.RemoveAll`), den Audit-Index `log-index.json` (über `translog.Options.IndexFile`) und bei `device lost` `user.rec` und den Schlüsselspeicher (`keys.WriteKeystoreFile`) über den Pfad des Client-Verzeichnisses, nicht über einen Deskriptor; einem Link als `--dir` folgt er dabei jedes Mal neu (`Open` macht den Pfad nur absolut). Betriebsvoraussetzung ist deshalb, dass das Elternverzeichnis nur für den eigenen Benutzer beschreibbar ist oder das Sticky-Bit trägt (Eigentümer der Benutzer oder `root`; RUNBOOK 0.3); bei einem Link als `--dir` gilt das für das Verzeichnis, das den Link enthält, und für das Elternverzeichnis des Linkziels. Der Umbau nach D92 (3), ein über `Open` gehaltenes `os.Root` für alle Schreibvorgänge, hebt die Voraussetzung für einen offenen Client auf (nach M1).
- Den Schlüsselspeicher lesen `Open` und `openForDeviceLost` seit 20l über `readKeystore` (`store.ReadFileLimited` mit `keys.MaxKeystoreSize`), nicht über `keys.ReadKeystoreFile` (AUDIT R41).
- Die Sperre des Client-Verzeichnisses nehmen `Open`, `openForDeviceLost`, `Register` und `lockOnlyDir` über `lockClientDir` (`internal/client/client.go`, seit 20h): Die Sperrdatei wird vor und nach `store.LockFile` über den Pfad verglichen (`os.SameFile`), bei Abweichung bis zu 8 Versuche (`lockAttempts`), dann `store.ErrLocked`. Restfall Wiederverwendung der Inode-Nummer: AUDIT R33; seit 20i nennt ihn der Kommentar an `lockClientDir` als bekannte Grenze.
- **`Client` ist nicht goroutinesicher, `Close` eingeschlossen.** `Client.mu` schützt nur das Merkmal `closed` (`open`, `Close` in `internal/client/client.go`) und die Caches der Epochen- und Ingest-Schlüssel, keine Methode als Ganzes; `open()` prüft und handelt danach ohne Sperre. Nach `Close` liefert jede Methode mit Fehlerergebnis `client.ErrClosed`, statt zu paniken (seit 20h, `TestNoPanicAfterClose`, `TestClosedCallsCoverMethods`); `UserID` und `Mailboxes` liefern weiter die IDs im Speicher. Gleichzeitige Aufrufe aus mehreren Goroutinen, auch `Close` gegen eine laufende Methode, sind Datenrennen (Angreiferprüfung von 20h, `docs/tasks/20-notes.md`). Ein Aufrufer, der einen `Client` teilt, serialisiert selbst. Seit 20i steht das im Paketkommentar (Abschnitt „Concurrency“) und am Typ `Client`. AUDIT R45.
- Der lokale Zustand ist Teil der Sicherheit. Ohne ihn beginnt ein Gerät bei Vertrauen beim ersten Kontakt (2.7; AUDIT R20, R22).

## ceremony und Programme

- `gomail-ceremony`: `init --shares k-of-n` (Standard 3 aus 5) mit Probe-Rekonstruktion, `ingest-rotate`, `reshare`, `succeed`, mit Auftrag 21c auch `succeed --compromised` mit Grenze, `revoke` und `admin-rotate` (D93; RUNBOOK 7.3), `publish` über das Log mit `--replace-witnesses` (D82, D85). Terminalregeln mit Abbruchpfad, `outputGrace`, `confirmDelay` (D85 Nachträge; RUNBOOK 2; AUDIT R1 bis R5). Schlüsselverzeichnis `--keys` über `os.Root`, 0700, kein Symlink im letzten Element.
- `gomail-server`: `init` (einziger Weg zum Datenverzeichnis, D87), `serve --pin --log-listen` (Startprüfungen RUNBOOK 1.6; Serversperre vor dem Laden des Ingest-Schlüssels, D88 (8)), `invite create`, `address add` (Logeintrag vor `addresses.json`, Admin-Schlüssel außerhalb des Datenverzeichnisses), `log repair`.
- `gomailctl`: Befehle nach 9.2 und `restore`, `flag` (D86, S92). Exit-Codes 0, 1, 2, 3 (`ErrPartial`), 130. Seed und Anteile nur am Terminal, Wörter ohne Echo; die Passphrase vom Terminal mit Echo (R31). Jeder Befehl außer `inspect` verlangt eine wirksame Serversperre.
- `gomail-witness`: `keygen`, `serve --log --log-key --origin --key --state` (S68).

## Datenverzeichnis

Auszug; maßgeblich sind Abschnitt 4, `internal/store` und `internal/translog/doc.go`.

```
data/
  platform/identity-<g>.pub, identity-<g>.succ (g ≥ 2), admin-<g>.pub/.cert, ingest-<g>.pub/.cert, witnesses.rec
  users/<user-id>/user.rec
  invites/<code>.json
  addresses.json, addresses.lock
  locks/server, locks/client
  log/lock, tree.rec, entries/<i>.rec, tree/tile/…, heads/<size>.sig, keys/…
  mailboxes/<postfach-id>/
    mailbox.rec, epoch-fallback.rec (nur nach einem Rückfall)
    epochs/<n>/epoch.rec, folders.gml, members/<user-id>.wrap, members/<user-id>.accept, members/recovery.wrap
    mail/<ordner-id>/<mail-id>.gml, <mail-id>.meta.gml
    pending/<n>/…                         Marker und Begriffslisten
    index/<n>/<device-id>-<lfd>.gml       Indexsegmente
    checkpoints/<user-id>-<device-id>.rec Vermerke der Clients
  spool/, work/                           nur während einer Annahme bzw. bei Last
```

Client-Verzeichnis (Standard `<UserConfigDir>/gomailctl` nach `os.UserConfigDir`, unter Linux meist `~/.config/gomailctl`, unter macOS `~/Library/Application Support/gomailctl`; nie im Datenverzeichnis): `keystore`, Kopie der eigenen `user.rec`, `state.json`, Audit-Index des Logs, `new-mailboxes/`, `lock` (AUDIT 3).

## Bekannte Grenzen

Vollständig in `docs/AUDIT.md` Abschnitt 5 (R1 bis R49), jeweils mit Beleg. Für die Übergabe besonders:

- **Widerruf von Plattformgenerationen** (R17, R18): mit Auftrag 21 gebaut (D93). Restgrenzen: Der Pin ist der einzige Träger (Clients mit altem Pin merken nichts); was ein Dieb vor der Grenze geloggt hat, bleibt gültig; eine weit in die Zukunft datierte Zuordnung friert eine Adresse ein; eine Metadaten-Version ab 2 nennt die Ingest-Generation von Version 1 nicht (Rest von F2, Formatänderung nach M1, unten Punkt 8).
- **`publish` heilt `data/platform/`, mit Restgrenzen** (Auftrag 22, afad8de; D93 Nachtrag 22, AUDIT R17): Ein Name gilt auch dann als frei, wenn sein gültiger Logeintrag genau die Datei des Exports ist. Eine Wiederholung derselben `publish`-Ausführung setzt so eine überschriebene geloggte Datei zurück, ebenso eine fremde `.pub` unter einem geloggten Admin- oder Ingest-Zertifikat (`freeName` in `internal/ceremony/publish.go`; `TestPublishHealsPlatform`, `TestPublishHealsOverwrittenCert`, `TestPublishHealsForeignPub`, `TestPublishValidEntryKept` in `heal22_test.go`). Durch anderen Inhalt wird ein gültiger Eintrag nie ersetzt. Nicht geheilt werden Dateien, die `checkDataPlatform` vorher ablehnt, und eine einzelne fremde `.pub` ohne geloggtes Zertifikat; diese entfernt der Betreiber von Hand (RUNBOOK 7.3, „Fremde Dateien in `platform/`“). Seit Auftrag 24 (Paket A; D93 Nachtrag 24) gilt ein symbolischer oder harter Link unter einem Namen des Exports nie als dessen Datei: Ist der Name frei, ersetzt `publish` den Link selbst, sonst verweigert es vor dem Schreiben mit einer eigenen Meldung (`linkErr`); F4 (gleiche Datei unter einem anders belegten Namen) verweigert es ebenfalls vor dem Schreiben. Seit Auftrag 25 (Paket 25A; D93 Nachtrag 25 A) gilt das auch für `witnesses.rec` (ohne `--replace-witnesses` abgelehnt, mit dem Schalter ersetzt und sofort gemeldet) und für eine Nachfolge, die `publish` nachloggen würde; ein Eintrag, der zwischen `Lstat` und Lesen wechselt, wird abgelehnt (F3); Reste `.tmp-*` entfernt `publish` unter der Serversperre und nennt sie, danach zählt jeder weitere Name; `platform/` als Link lehnt es ab (ein fehlendes `platform/` oder ein hängender Link dort scheitert über die CLI schon an `store.Open`: `store: not found: <datenverzeichnis> is not an initialized data directory`), einen fehlenden Namen mit anders belegtem gültigem Logeintrag vor dem Schreiben. Seit Auftrag 26 (Paket 26B; D93 Nachtrag 26 B) öffnet `publish` `platform/` einmal (`os.Root`) und arbeitet nur über diesen Deskriptor; ein Tausch von `platform/` vor oder gleich nach dem Öffnen wird abgelehnt, einer danach wirkt nicht mehr, und vor dem Loggen prüft `publish` noch einmal (neue Meldungen in RUNBOOK 7.3 und 8.6). Restgrenzen niedrig (fremdes Schreibrecht auf `data/` nötig): Ein Tausch von `platform/` zwischen dieser letzten Prüfung und den Logeinträgen und, wie bisher, ein Tausch eines Eintrags nach seiner letzten Prüfung fallen nicht auf, Links unter Namen, die `publish` nicht liest, fallen nicht auf, ein Bind-Mount ist nicht erkennbar; SIGKILL zwischen dem Umbenennen von `witnesses.rec` und der Ersatzzeile lässt die Zeile fehlen (AUDIT R17 (b); Liste nach M1 Nr. 85, 86). Die zwei überlebenden Mutanten der Spezifikationsprüfung von 22 töten seit Auftrag 24 die übernommenen Belegtests `TestV22PubUnderUnloggedSameCert` und `TestV22SymlinkOverLogged`.
- **Admin-Widerruf nur mit Untergrenze** (22, D93 Nachtrag 22): `checkRevocations` prüft „wäre nie gültig gewesen“ (`revoked_at_time` nicht nach `valid_from`) nur noch für Ingest-Elemente. Für ein Admin-Element begrenzt nur der 01.01.2025 (`minHeadTime`) die Zeit nach unten, weil für Admin `revoked_at_size` entscheidet. Die Obergrenze aus dem neuesten Kopf gilt für jedes Element (`TestRevocationTimes` in `rework21c_test.go`).
- **`resolveExisting` Stück für Stück** (22 und Auftrag 24, Paket B; D86 Nachträge 22 und 24 B, AUDIT R33): `resolveExisting` (`internal/client/client.go`) folgt Links wie das System, auch hängenden, und wendet `..` auf den schon aufgelösten Pfad an; ein Link ins Datenverzeichnis, auch über `sub/..`, ist `errInsideDataDir` (`TestClientDirDanglingLinkIntoDataDir`, `TestClientDirLinkDotDotIntoDataDir`). Fail closed: Kann der Client einen Teil des Pfads nicht prüfen (EACCES, ENAMETOOLONG, mehr als 40 Links, relativer Pfad), lehnt er ab (bis Auftrag 25 mit derselben Meldung). Seit Auftrag 25 (Paket 25B; D86 Nachtrag 25 B) nennt die Ablehnung dann die Ursache (`client: cannot check that the client directory is outside the data directory: <errno-Text>`), `… must not be inside the data directory` kommt nur noch für ein `--dir` im Datenverzeichnis (RUNBOOK 3.2). Restgrenze niedrig: Ein Bind-Mount des Datenverzeichnisses fällt nicht auf (rein pfadbasiert).
- **Ingest-Zertifikat einmal gelesen** (R48, mittel, behoben mit Auftrag 23 und 23b, fba4eb2; D93 Nachtrag 23): `Client.ingestKeyFor` (`internal/client/read.go`) und `ingest.New` lesen `ingest-<g>.cert` einmal (`store.ReadPlatformCertRaw`). Signaturprüfung, Schlüssel und Logabgleich arbeiten auf denselben Bytes. Vorher konnte ein Tausch zwischen zwei Lesevorgängen den Logabgleich umgehen. Belegt ist das mit zwei Tests, in denen der Testhaken `certReadHook` die Datei nach dem ersten Lesen tauscht: `TestPlatformIngestCertSwapped` (`internal/client`) und `TestPlatformCertReadOnce` (`internal/ingest`). Mit wiederhergestelltem zweitem Lesen scheitern sie: `TestPlatformIngestCertSwapped` tötet die Mutation „zweites Lesen“ in der Nachprüfung 23b je 5/5 unter amd64 und 386; für `TestPlatformCertReadOnce` gelten die Mutationen der Spezifikationsprüfung von 23 (M1 bis M9, alle getötet außer M4) und der Angriffstest `TestAttack23IngestFlipRace`, der auf der Mutante scheitert (`docs/tasks/20-notes.md`, „Läufe der Prüfungen von 23“). `TestReadPlatformCertRaw` (`internal/store`) tauscht nichts; er prüft nur, dass `ReadPlatformCertRaw` die gelesenen Bytes zurückgibt und dieselben Regeln anwendet wie `ReadPlatformCert`. 23b machte `TestPlatformIngestCertSwapped` unabhängig von der Reihenfolge der zufälligen Mail-IDs. Die damaligen Restgrenzen sind seit Auftrag 24 geschlossen: `address add` prüft `admin-<g>.cert` auf Signatur und gegen das Log (Paket C, `TestAddressAddForgedCert`), `TestReadPlatformCertRawReadsOnce` tötet die Mutante M4 (Paket E), und `TestPlatformIngestCertSwapped` deckt in jedem Lauf beide Prüfreihenfolgen ab (Paket B). Der Haken in `store` zählt nur Lesezugriffe über `ReadPlatformFile` (Mutante M4direct der Prüfung von E); seit Auftrag 26 (Paket 26D) zählt der Test unter Linux zusätzlich jedes Öffnen und Schließen der `.cert` per inotify, und M4direct scheitert. Niedrig bleibt: Ein zweites Lesen, das nebenläufig überlappt, einen nie geschlossenen Deskriptor nutzt oder ohne neues Öffnen über einen zwischengespeicherten Deskriptor läuft, bleibt verborgen, und auf anderen Systemen zählt nur der Haken (AUDIT R48; Liste nach M1 Nr. 84).
- **`loghttp`** (R8; Auftrag 24, Paket D mit Nacharbeit, D80 Nachtrag 24 D): Inhaltstyp und Länge von `/cosign` vor dem Körper, höchstens `MaxVerifying` (16) Signaturprüfungen zugleich, Platz erst nach dem Lesen des Körpers, 503 nach `SlotWait`, seit Auftrag 25 (Paket 25C; D80 Nachtrag 25 C) 5 s statt 1 s; ein wiederholt gesendeter veröffentlichter Kopf schreibt nicht neu, und seit Auftrag 25 ruft eine wiederholte Gegenzeichnung des Kandidaten `PublishHead` nicht mehr auf; `Tick` wiederholt eine gescheiterte Veröffentlichung vor `SignHead`. Eine Anfrage lebt bis etwa `ReadTimeout + SlotWait`; der Server spricht nur HTTP/1.1, hinter einem multiplexenden Proxy muss eine Grenze je Quelle Anfragen zählen. Seit Auftrag 26 (Paket 26F; D80 Nachtrag 26 F) veröffentlicht `PublishHead` keinen Kopf eines zurückgesetzten Baums (`refuse` wie in `SignHead`). Weiter fehlen eine Grenze für Verbindungen im Listener und eine Rate je Quelle (10.2, vor dem Betrieb). Paket 26A sollte sie bauen; nach drei Runden blieben zwei Funde über niedrig offen (F1 hoch, F2 mittel: die Zeugen ließen sich mit den Grenzen leichter aussperren als ohne sie), deshalb ist nichts davon zusammengeführt. Den Weg entscheidet der Auftraggeber (AUDIT R8, Liste nach M1 Nr. 7, ORCHESTRATION Abschnitt 10).
- **Referenzkopf aus `state.json` mit fremder Origin** (R49, niedrig; Auftrag 26, gefunden von `FuzzState`): Der Client übernimmt einen solchen Kopf, wenn der veröffentlichte Kopf älter ist, und schreibt danach Vermerke mit der fremden Origin, die andere Clients abweisen. `state.json` liegt in der Vertrauenszone (D57). Die Abhilfe (Origin in `openLog` prüfen) ist eine Prüfregel des Clients, also ein Haltepunkt; nicht gebaut (Liste nach M1 Nr. 92).
- **`address add` und die Uhr** (Auftrag 24, Paket C; D80 Nachtrag 24 C, RUNBOOK 4.2): `valid_from` = max(jetzt, letzter gültiger Wert der Adresse + 1 ms), solange das höchstens `translog.MaxClockSkew` (5 Minuten) voraus liegt; darüber verweigert das Log wie bisher (Exit 1). Eine weit vordatierte Zuordnung hält die Adresse fest, bis die Uhr auf 5 Minuten an sie heranreicht (Q9).
- **Zeuge auf einer anderen Maschine** (R47): `--log-listen` nur auf Loopback; ein Zeuge auf einer anderen Maschine braucht einen Tunnel (RUNBOOK 1.7, nicht getestet). Ein `log/` aus einer älteren Sicherung hält der Zeuge dauerhaft als Fork fest (R13, RUNBOOK 8.8 und 8.9).
- **Wachstum des Client-Zustands** (R27 (a), R43): ohne Schlüssel bei Schreibzugriff je nach Geräten und Größe der Epoche in Tagen bis Monaten bis 64 MiB; im ehrlichen Betrieb rund 70 000 Mails je Client-Verzeichnis. Abhilfe nach M1 (Q22 Variante B).
- **Verfügbarkeit bei Schreibzugriff:** Sperre durch frei signierten Vermerk (R23), nicht loggbare Epoche 1 (R24), dem Log widersprechende Epoche (R25), nicht reguläre Dateien (R26, R41), Lesegrenze der Segmente (R42), Neuausstellung, die nie gelingt (R44). 2.7 verspricht Erkennung, nicht Verfügbarkeit.
- **Zwei Maschinen nur bedingt** (R36): NFSv4-Sperren und Cache-Verhalten ungeprüft.
- **Zielplattformen** (R40): Terminalbehandlung auf BSD und Darwin nur per `go vet` geprüft, nie ausgeführt; PTY-Tests nur unter Linux. plan9 und js/wasm übersetzen die Terminalteile gewollt nicht; Windows lehnt die Zeremoniebefehle ab. `GOOS=solaris go vet ./...` und `GOOS=illumos go vet ./...` scheitern, mit und ohne Tags, nur an `undefined: syscall.Mkfifo` in sechs Testdateien mit Build-Tag `unix` (`cmd/gomail-ceremony/fifo20a_unix_test.go`, `cmd/gomail-server/rework15k_unix_test.go`, `internal/ceremony/fifo20b_unix_test.go`, `internal/client/keystore20l_unix_test.go`, `internal/store/fifo20b_unix_test.go`, `internal/translog/fifo20b_unix_test.go`); `go build ./...` gelingt (Auftrag 24, Paket E, am Stand vor den Paketen A und F, nur ausgeführt, nicht korrigiert; Liste nach M1 Nr. 52). Nacharbeit A2 und Paket F bringen fünf weitere Testdateien mit `//go:build unix` und `syscall.Mkfifo` (`internal/ceremony/publishlink24b_unix_test.go` und `fifo24f_unix_test.go` in `cmd/gomail-server`, `internal/client`, `internal/ingest` und `internal/store`); für sie ist der Lauf nicht wiederholt.
- **Terminal in `gomailctl`** (R6): Ein statisch per `mknod` angelegter Terminalknoten auf einem anderen Dateisystem (etwa in einem chroot) hat ein anderes `st_dev` und wird verweigert; das ist die sichere Richtung. Auf den BSDs ohne `/dev/tty` im Dateisystem entfällt die Unterscheidung der Sitzungen.
- **Ohne S-Punkt, offen mit `TODO(ask)`:** Passphrase mit Echo und Löschen des Seeds vor der Abfrage der Kontrollwörter (D86, R31); Gruppenname bei `gomail-server init` nur Warnung (D87 (4), R34). Neuer `init` statt Nachfolge bei kompromittiertem Root (Nachtrag zu Q19, R17) ist mit D93 (5) entschieden.
- **Aus Phase 1 weiter offen** (R38): Spool-Vervielfachung bei vielen Empfängerpostfächern, Mindestrate in festen 60-Sekunden-Fenstern, Doppelzustellung bei Verlust zwischen Commit und `250`.
- **`Client` nicht goroutinesicher** (R45): siehe „client“, Invarianten. `gomailctl` öffnet je Befehl einen `Client` (`client.Open` in `cmd/gomailctl/main.go` und `commands.go`) und teilt ihn nicht zwischen Goroutinen; die einzige Goroutine außerhalb der Tests ist der Signalwächter des Bildschirms (`screen.watch`, `cmd/gomailctl/screen.go`), der den `Client` nicht berührt; wer `internal/client` in eigene Werkzeuge einbaut, serialisiert die Aufrufe selbst.
- **Betriebsvoraussetzung für Client-Verzeichnisse** (D92, R46): Ein offener Client schreibt nach dem Sperren über den Pfad: `state.json`, die Kopien neuer Postfächer unter `new-mailboxes/`, den Audit-Index des Logs, bei `device lost` auch `user.rec` und den Schlüsselspeicher. Wer das Elternverzeichnis beschreiben kann, könnte das Client-Verzeichnis dazwischen tauschen und den Schlüsselspeicher eines anderen Client-Verzeichnisses desselben Kontos überschreiben. Das Elternverzeichnis muss deshalb nur für den eigenen Benutzer beschreibbar sein oder das Sticky-Bit tragen (Eigentümer der Benutzer oder `root`; bei einem Link als `--dir` auch das Verzeichnis, das den Link enthält); RUNBOOK 0.3 nennt den Prüfbefehl `stat -c '%U %a' <eltern>`. Unter dieser Voraussetzung gilt der Fund als niedrig. Abhilfe nach M1: ein über `Open` gehaltenes `os.Root`. Für `keygen` und `restore` ist dieselbe Klasse seit 20l geschlossen, bis auf einen Restwettlauf vor dem Umbenennen (R33).
- **Kein Klartext, aber Metadaten sichtbar** (R37): Root während des Empfangs liest neue Mails; Größen, Zeiten, Mitgliedschaften und Trefferzahlen bleiben sichtbar.

## Offene Fragen

Alle Fragen mit Stand stehen in `docs/QUESTIONS.md` und AUDIT 7.1. Die drei, die das Verhalten nach M1 am stärksten bestimmen, sind unten aufgeführt; Q18 und Q20 sind offen, Q19 ist mit D93 entschieden und mit Auftrag 21 gebaut (21a, 21b, 21c). Die Aufträge 20b bis 20l haben am gebauten Verhalten aller drei nichts geändert (Stand b674ae3). 20o und Auftrag 21 haben das Verhalten zu Q18 und Q20 nicht berührt: Die Marken `TODO(Q18)` und `TODO(Q20)` stehen unverändert (Abschnitt „TODO-Inventar“), und die geänderten Stellen in `client.go`, `devicelost.go` und `restore.go` betreffen das Client-Verzeichnis und Feld 7 (Stand 9ad24a5):

| Frage | Gegenstand | Stand | Gebaut bis zur Antwort |
|---|---|---|---|
| Q18 | alleiniges Mitglied nach einem Widerruf ohne geprüfte `folders.gml` | offen (Haltepunkt 1) | Ablehnung ohne Ausweg: `List`, `Rename`, `SetFolders` scheitern, `Read` geht; `sync` und `device lost` enden mit Exit 3 und fester Ursache (D84 (3), D88 (7), `TODO(Q18)` in `internal/client/devicelost.go`). Vorbeugung: Postfächer mit mindestens zwei Benutzer-Mitgliedern führen (RUNBOOK 8.4). AUDIT R21. |
| Q19 | Nachfolge nach Kompromittierung der Plattformidentität | entschieden (03.11.2026, D93: Option A, Widerruf über Pin-Feld 7; Haltepunkt 2 damit aufgelöst), gebaut mit Auftrag 21 (21a, 21b, 21c) | `succeed --compromised` mit Grenze (`revoked_at_time` = Kopfzeit + 1 ms), Kaskade auf die Admin- und Ingest-Generationen der kompromittierten Identität, Pflicht zur Neuausstellung (RUNBOOK 7.3.5); Pflichttest S9 ohne Skip. Neuer `init` mit neuem Origin bei kompromittiertem Root: D93 (5), RUNBOOK 7.3.6. AUDIT R17, S76. |
| Q20 | Markierung „noch kein bestätigter Zustand“ nach Wiederherstellung | offen (Haltepunkt 1) | strengste Lesart: `Unconfirmed` bleibt bis zum Vergleich mit dem Vermerk eines **anderen** Benutzer-Mitglieds; ein eigenes zweites Gerät zählt nicht; ein alleiniges Mitglied bleibt dauerhaft markiert (nur Warnung; D88 (6), `TODO(Q20)` in `internal/client`). AUDIT R22. |

Für den Betrieb mit echten Mails wichtig: Q8 (Widerruf von Ingest- und Admin-Generationen; entschieden mit D93, gebaut mit Auftrag 21, Restgrenzen AUDIT R18), weiter offen Q9 (zeitliche Bindung von Adresszuordnungen) und Q4 (Logschlüssel ist der Ingest-Schlüssel). Erledigt in dieser Phase: Q22 (Variante A, D91; mit 09g zusammengeführt, Wachstum bei Schreibzugriff als bekannte Grenze, AUDIT R27).

## Pflichttests aus 10.1

Vollständig in `docs/tasks/20-mandatory-tests.md` (Auftrag 20f, nachgeführt mit 20g und 20h): je Spiegelstrich aus 10.1 die Testfunktionen, Paket, Tags, Ergebnis eines gezielten Laufs und Stand, geprüft am Code des Tests. Gezählt sind 30 Pflichttests (T1 bis T3, K1, K2, G1 bis G9, S1 bis S9, F1 bis F3 je Fuzz-Ziel, Z1 bis Z4).

| Stand | Zahl | Pflichttests |
|---|---|---|
| vollständig | 28 | T1 bis T3, K1, K2, G1 bis G9, S1 bis S6, S8, S9, F1 bis F3, Z1, Z2, Z4 |
| teilweise | 1 | Z3: Suchmarken-Index vollständig (`TestDeviceChangeTakesOverSegments`, `TestDeviceChangeThenDeviceLost` in `internal/client/devicechange_test.go`, 20h); der Volltextindex (6.4) ist nicht Teil von M1 und nicht gebaut. |
| fehlt | 1 | S7 (Löschen von Epochen, 2.6): nicht Teil von M1 und nicht gebaut (Folgeauftrag F-3). |

S9 ist seit dem Abschluss-Volllauf vollständig. Bis Auftrag 21 war die Identität übersprungen (`TestVerifyCompromisedIdentityStillIssues`, Q19) und Ingest nur als Ablösung durch eine neue Generation geprüft (Q8). 21c entfernt das Skip: Pin 2 widerruft Identität 1 in Feld 7, und `publish` und das Operator-Log verweigern `ingest-3.cert` und `admin-2.cert` der Identität 1 mit `translog.ErrRevoked`. 21b prüft den Widerruf einer Ingest-Generation im Client und von Ende zu Ende (`TestLogIngestRevoked`, `TestRevokedIngestEndToEnd`): Eine Mail nach der Grenze wird mit der Ursache „Generation widerrufen“ abgelehnt, Mails davor bleiben lesbar. Diese drei Tests und die Regeln in `TestRevokedCompromise` (`internal/translog`) bestanden im Abschluss-Volllauf auf 9ad24a5; Paket und Logdatei stehen unter „Stand je M1-Kriterium“, E. Auf dem Endstand bestanden sie ebenfalls, in denselben Schritten (`orch/fr-m1/`). Alle zugeordneten Tests bestanden im gezielten Lauf; übersprungen war im gezielten Lauf (20f bis 20h) nur `TestVerifyCompromisedIdentityStillIssues`, seit 21c ohne Skip. Neu gebaut für die Zuordnung: `TestAllSchemasListed` und `TestAllSchemasRoundTrip` (`internal/rec/allschemas_test.go`, K1, alle 40 Datensatzschemata; 20f, `go/parser` und Build-Tags seit 20g) und die Tests zum Gerätewechsel (Z3, 20h). S7 und der Volltextteil von Z3 liegen außerhalb von M1.

## Testabdeckung

`go test -count=1 -cover -timeout 60m` je Paket unter `internal/`, ohne `-race`; „mit Tags“ heißt `-tags gomail_dev,gomail_test`. Soll nach M1-Kriterium E: 85 % je Paket, 90 % für `rec`, `keys`, `shamir`, `envelope`, `translog`.

Die Werte gelten für den Endstand fba4eb2. Gemessen wurde mit `nice -n 19`, parallel zum jeweiligen Volllauf. Die Last verlängert nur die Laufzeit, auf die Prozentwerte hat sie keinen Einfluss. Quellen im Scratchpad des Orchestrators:
- `orch/cov-m1/`: die vier Pakete, die 22 und 23 im Produktivcode ändern. `ceremony` ist auf 10b1783 gemessen (`rev`); 23b berührt `ceremony` nicht. `client`, `ingest` und `store` sind auf 1217496 gemessen (`rev-client-ingest-store`). Beide Quellen gleichen fba4eb2 in diesen Paketen (`git diff 10b1783 1217496 -- internal cmd` nennt nur `internal/client/platform23_test.go`, `git diff 1217496 fba4eb2 -- internal cmd ':!internal/bench'` ist leer). Gemessen am 04.11. zwischen 01:33 und 02:09 UTC, neben dem Volllauf `fr-m1`.
- `orch/cov-final/` (`tabelle.md` und je Paket `plain-` und `tags-<paket>.log`): alle übrigen Pakete, auf 9ad24a5, gemessen neben dem Abschluss-Volllauf `fr-final`. Diese Pakete sind zwischen 9ad24a5 und fba4eb2 im Produktivcode unverändert (`git diff --stat 9ad24a5 fba4eb2 -- internal`): In `translog` ändern sich nur Kommentare (`doc.go`, `verifier.go`), in `e2e` ein Kommentar im Test, in `bench` nur Testdateien aus 17.

Die früheren Werte und ihre Herleitung stehen in `docs/tasks/20-mandatory-tests.md` („Abdeckung je Paket“) und in der Fassung dieses Abschnitts vor 20r.

| Paket | Soll | mit Tags | ohne Tags | Code gemessen |
|---|---|---|---|---|
| `internal/bench` | 85 % | 92,8 % | 92,1 % | 9ad24a5 (`orch/cov-final/`). Der Produktivcode des Pakets (`hardware.go`, `mailgen.go`, `doc.go`) ist bis fba4eb2 unverändert. Die Testdateien aus 17 sind nicht mitgemessen. |
| `internal/ceremony` | 85 % | 88,9 % | 89,8 % | Endstand mit 22 und 23 (10b1783, `orch/cov-m1/`) |
| `internal/client` | 85 % | 88,3 % | 3,6 % | Endstand mit 22 und 23 (1217496, `orch/cov-m1/`) |
| `internal/e2e` | – | keine Anweisungen | – | nur Testcode und `doc.go` |
| `internal/envelope` | 90 % | 94,0 % | 94,0 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/ingest` | 85 % | 90,4 % | 5,1 % | Endstand mit 22 und 23 (1217496, `orch/cov-m1/`) |
| `internal/keys` | 90 % | 93,9 % | 93,9 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/loghttp` | 85 % | 93,9 % | 93,9 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/rec` | 90 % | 99,6 % | 99,6 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/shamir` | 90 % | 100,0 % | 100,0 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/smtpd` | 85 % | 91,9 % | 91,9 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/store` | 85 % | 89,6 % | 89,5 % | Endstand mit 22 und 23 (1217496, `orch/cov-m1/`) |
| `internal/terms` | 85 % | 100,0 % | 100,0 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/testenv` | 85 % | 96,3 % | 15,1 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/translog` | 90 % | 93,6 % | 93,6 % | 9ad24a5; bis fba4eb2 nur Kommentare (dcd14d9) |
| `internal/translog/translogtest` | 85 % | 100,0 % | 100,0 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/witness` | 85 % | 95,2 % | 95,2 % | 9ad24a5, bis fba4eb2 unverändert |
| `internal/words` | 85 % | 100,0 % | 100,0 % | 9ad24a5, bis fba4eb2 unverändert |

Kein Paket liegt unter dem Soll. Am knappsten liegen `client` mit 88,3 % und `ceremony` mit 88,9 % (Soll 85 %) sowie `translog` mit 93,6 % (Soll 90 %). Maßgeblich ist die Spalte „mit Tags“. Ohne Tags überspringen sich in `client`, `ingest` und `testenv` die Tests, die `testenv.New` oder `NewLogged` brauchen; daher 3,6 %, 5,1 % und 15,1 %. `internal/testenv` lag früher bei 0,0 % (Testhilfe ohne eigene Tests). Der Orchestrator hat entschieden, dass Kriterium E für jedes Paket unter `internal/` gilt, und 20g hat eigene Tests gebaut. Die Programme unter `cmd/` haben keinen Mindestwert. Die Werte aus Phase 1 stehen unter „Verlauf“.

## Fuzzing

Alle 25 Ziele liefen je 10 Minuten (`go test -run '^$' -fuzz '^FuzzX$' -fuzztime 10m -parallel 1`, ein Worker je Ziel, zwei Bahnen gleichzeitig) ohne Fund; kein neuer Fall unter `testdata/fuzz/` (zwischen bf427c2 und 9ad24a5 unverändert, `git diff --stat bf427c2 9ad24a5 -- 'internal/**/testdata/fuzz/**'` leer). Die Protokolle liegen im Scratchpad des Orchestrators (`orch/fz/`, `orch/fz2/`, `orch/fz3/`, `orch/fz4/`), nicht im Repository; die Zahlen stehen in `docs/tasks/20-notes.md` („Fuzzing für 10.2“, „Fuzzing, zweiter Teil“, „Fuzzing, dritter Teil“, „Fuzzing, vierter Teil“). Code je Teil:

- Erster Teil, 19 Ziele: auf bf427c2 (Code gleich 3e06f23). Die Pakete dieser Ziele (`envelope`, `ingest`, `keys`, `loghttp`, `rec`, `shamir`, `smtpd`, `witness`, `words`) sind bis 9ad24a5 im Produktivcode unverändert, bis auf `internal/ingest/ingest.go` (21b, Feld 7 bei der Annahme; 23, einmaliges Lesen des Ingest-Zertifikats in `New`). `FuzzTerms` prüft `ingest.Terms` in `terms.go`, und diese Datei ist bis fba4eb2 unverändert.
- Zweiter Teil, `store.FuzzDecodeRecords`: auf dem Worktree-Commit 84ca174 (WIP von 20b; `store` gleich cb2344c, dem Ergebnis von 20b, und damit gleich b155e1f im Arbeitsbranch). `store` hat sich danach in 20e nur in Kommentaren geändert, in 20i und 20l nur beim Öffnen und Schreiben von Dateien und bei den Sperrdateien (`fs.go`, `lock_unix.go`, `noctty_*.go`). 21a änderte `records.go` (Pin-Feld 7); deshalb lief das Ziel im vierten Teil noch einmal.
- Dritter Teil, 5 Ziele in `translog`: auf d85da00 (nach 20e, `translog/files.go` geändert); wiederholt, weil 20e `translog` änderte. Die Läufe des zweiten Teils auf 84ca174 für diese 5 Ziele waren ebenfalls ohne Fund. `translog` ist zwischen d85da00 und b674ae3 unverändert; 21a änderte es, deshalb der vierte Teil.
- Vierter Teil, 6 Ziele in `store` und `translog` (`FuzzDecodeRecords` und die 5 Ziele des dritten Teils): auf 56464da (nach 21a), je 10 Minuten in zwei Bahnen, ohne Fund. `store` und `translog` sind zwischen 56464da und 9ad24a5 unverändert (`git diff --stat 56464da 9ad24a5 -- internal/store internal/translog` leer; 21b und 21c ändern sie nicht). Danach ändert dcd14d9 in `translog` nur Kommentare. 23 ergänzt in `internal/store/store.go` die Lesefunktion `ReadPlatformCertRaw`; die Dekodierer der Datensätze, die `FuzzDecodeRecords` prüft, bleiben unverändert. 22 ändert nur `ceremony` und `resolveExisting` im Client, für die es kein Fuzz-Ziel gibt. Deshalb gab es nach 22 und 23 keinen weiteren Fuzzing-Lauf.

| Paket | Ziel | Ausführungen in 10 min | Code |
|---|---|---|---|
| `internal/envelope` | `FuzzParseAndOpen` | 829.752 | bf427c2 |
| `internal/ingest` | `FuzzTerms` | 1.465.639 | bf427c2 |
| `internal/keys` | `FuzzDecodeGenerationCert` | 9.322.292 | bf427c2 |
| `internal/keys` | `FuzzOpenKeystore` | 10.126.628 | bf427c2 |
| `internal/keys` | `FuzzParseWordlist` | 526.897 | bf427c2 |
| `internal/keys` | `FuzzSeedFromWords` | 8.829.700 | bf427c2 |
| `internal/loghttp` | `FuzzServer` | 3.093.479 | bf427c2 |
| `internal/rec` | `FuzzDecode` | 10.877.835 | bf427c2 |
| `internal/rec` | `FuzzIsNFC` | 9.876.698 | bf427c2 |
| `internal/shamir` | `FuzzCombine` | 4.165.047 | bf427c2 |
| `internal/shamir` | `FuzzShareFromBytes` | 12.377.691 | bf427c2 |
| `internal/shamir` | `FuzzShareFromWords` | 9.791.607 | bf427c2 |
| `internal/smtpd` | `FuzzCommands` | 3.568.702 | bf427c2 |
| `internal/smtpd` | `FuzzData` | 3.901.203 | bf427c2 |
| `internal/witness` | `FuzzCosign` | 3.365.961 | bf427c2 |
| `internal/witness` | `FuzzDecodeWitnesses` | 4.052.309 | bf427c2 |
| `internal/witness` | `FuzzParseProof` | 4.227.219 | bf427c2 |
| `internal/witness` | `FuzzPoll` | 1.327.905 | bf427c2 |
| `internal/words` | `FuzzNormalize` | 2.960.008 | bf427c2 |
| `internal/store` | `FuzzDecodeRecords` | 9.012.891 | 84ca174 (`store` wie cb2344c) |
| `internal/translog` | `FuzzAuditIndex` | 1.656.812 | d85da00 |
| `internal/translog` | `FuzzDecodeEntry` | 6.272.210 | d85da00 |
| `internal/translog` | `FuzzOpenHead` | 6.272.278 | d85da00 |
| `internal/translog` | `FuzzParseHeadText` | 6.436.659 | d85da00 |
| `internal/translog` | `FuzzProofs` | 4.849.422 | d85da00 |

Vierter Teil (Code 56464da, nach 21a; `docs/tasks/20-notes.md`, „Fuzzing, vierter Teil“):

| Paket | Ziel | Ausführungen in 10 min | Code |
|---|---|---|---|
| `internal/store` | `FuzzDecodeRecords` | 9.146.068 | 56464da |
| `internal/translog` | `FuzzAuditIndex` | 3.137.084 | 56464da |
| `internal/translog` | `FuzzDecodeEntry` | 6.929.298 | 56464da |
| `internal/translog` | `FuzzOpenHead` | 6.936.251 | 56464da |
| `internal/translog` | `FuzzParseHeadText` | 7.142.506 | 56464da |
| `internal/translog` | `FuzzProofs` | 4.665.887 | 56464da |

Fünfter Teil, sechs neue Ziele aus Auftrag 26 (Paket 26E mit den Nacharbeiten 26E2 und 26E3 und der Anpassung von `FuzzCheckDataPlatform` an 26B, 2e56813; Liste nach M1 Nr. 25; nur Testdateien). Sie decken die Prüfpfade des Clients, die Daten aus dem Datenverzeichnis und `state.json` lesen, und die Zeremonie. Jedes Ziel läuft ohne Netz unter `t.TempDir`, mit Seeds aus gültigen Testdaten (sie laufen als Tests mit), und prüft: kein Panic, keine Annahme ungültiger Daten, wo sich das ohne zweite Implementierung prüfen lässt (etwa: jede angenommene Epoche, jedes angenommene Zertifikat ist byte-gleich die echte Datei, weil der Fuzzer nicht signieren kann), und begrenzten Speicher (`runtime.MemStats.TotalAlloc` je Eingabe). Gelaufen je 5 Minuten mit `-parallel 2` (26E), nach den Nacharbeiten je 3 Minuten (26E2), die Zeremonie-Ziele nach der Anpassung an 26B je 2 Minuten:

| Paket | Ziel | Einstieg | Ausführungen in 5 min (422fcde) | letzter Lauf |
|---|---|---|---|---|
| `internal/store` | `FuzzChain` | `store.Chain.Add` über `DecodeEpoch` (Epochen oder Basisepochen mit Feldänderungen) | 1.996.747 | 3 min, 1.136.369, kein Fund (09f9e37) |
| `internal/client` | `FuzzVerifyChain` | `verifyChain` bzw. `loadChain` mit Übernahme, eine Datei der Kette ersetzt | 79.341 | 3 min, 65.240, kein Fund (09f9e37) |
| `internal/client` | `FuzzCheckpoint` | `checkCheckpoint` gegen den Referenzkopf | 2.930.200 | 3 min, 2.069.237, kein Fund (09f9e37) |
| `internal/client` | `FuzzState` | `client.OpenWithState` mit der Eingabe als `state.json`, danach die Kette | 618.894 | 3 min, 459.836, kein Fund (09f9e37); auf c44cc7e Fund nach etwa 30 s (AUDIT R49) |
| `internal/ceremony` | `FuzzReadExport` | `readExport`, danach `Publish` in ein leeres Datenverzeichnis | 184.875 | 2 min, 51.486, kein Fund (2e56813) |
| `internal/ceremony` | `FuzzCheckDataPlatform` | `checkDataPlatform` auf `platform/`, geöffnet mit `openPlatformDir` | 111.311 | 2 min, 28.524, kein Fund (2e56813) |

Die Ziele in `internal/client` brauchen die Tags (ohne sie werden sie übersprungen), etwa:

```
go test -tags gomail_dev,gomail_test -run '^$' -fuzz '^FuzzState$' -fuzztime 5m -parallel 2 -fuzzminimizetime 0s ./internal/client
```

`-fuzzminimizetime 0s` hält den Minimierer kurz, der sonst bei jeder neuen interessanten Eingabe mit Signaturen bis zu 60 s ohne gezählte Ausführungen stehen kann. Wer einen Mutanten gegen ein Ziel laufen lässt, gibt einen frischen Korpus-Cache mit (`-args -test.fuzzcachedir=<neues Verzeichnis>`), damit der Korpus früherer Läufe nicht mitentscheidet. Jeder Fuzz-Prozess baut eine eigene Plattform mit eigenen Schlüsseln; die Client-Ziele beschreiben ihre Eingaben deshalb relativ zu den echten Dateien (XOR, Feldänderungen, Platzhalter in einer Vorlage von `state.json`). **Grenze von `FuzzState`:** `state.json` liegt in der Vertrauenszone des Client-Verzeichnisses (D57). Das Ziel prüft, was ein beschädigter Zustand trotzdem nicht erreichen darf: Der angenommene Referenzkopf nennt Origin und einen Baum des Logs, jeder Pending-Eintrag, den dieser Kopf deckt, trägt das Blatt des Logs, keiner dahinter ist von ihm schon zurückgehalten (sonst muss das Öffnen mit `ErrWithheld` scheitern), und die Kette fällt nicht hinter die gemerkte Epoche zurück. Einen Pending-Eintrag, den der Client neu anhängt (`repairPending`), erreicht es nicht, weil das einen neuen signierten Datensatz braucht. Der Fall der fremden Origin (AUDIT R49) ist nicht behoben; längeres Fuzzing von `FuzzState` findet ihn wieder. Weitere Grenzen: Manche Regeln erreicht das Byte-Fuzzing über kanonische Datensätze nur über Seeds; einem Mutanten ohne Prüfung der Zertifikatssignatur entgehen die Seeds von `FuzzCheckDataPlatform`, der Fuzzer findet ihn nach 0,15 s (Liste nach M1 Nr. 90). Die Seeds brauchen in `internal/client` unter `-race` mit Tags etwa 30 s. `store` und `translog` haben sich mit Auftrag 26 nicht in den Dekodierern geändert (26B: Zugriff über `os.Root` und `RemoveTempFiles`; 26F: `refuse` in `PublishHead`); die Läufe ihrer bisherigen Ziele sind nicht wiederholt.

10.1 verlangt Fuzzing für den `.gml`-Parser, den SMTP-Parser und das Einlesen von Shamir-Anteilen (F1 bis F3); alle drei sind abgedeckt. Bis Auftrag 26 hatten die Prüfpfade des Clients (Kette, Vermerke, `state.json`) und die Zeremonie kein eigenes Ziel (seitdem der fünfte Teil oben); `internal/terms` deckt `ingest.FuzzTerms` über `ingest.Terms`.

## Unabhängige Prüfungen bis M1

Jedes Paket hatte nach `docs/ORCHESTRATION.md` Abschnitt 2 einen oder zwei Prüfer (Spezifikation und Angreifer für sicherheitskritische Pakete). Funde, Nacharbeitsrunden und Abweichungen von Regel 6 stehen je Paket in ORCHESTRATION Abschnitt 4 und in der Begründung des D-Eintrags. Funde niedrig, die nach der Zusammenführung offen blieben, sind in `docs/tasks/20-triage.md` eingeordnet. Zahlen für den Abschlussbericht (Prüfrunden, Funde nach Schwere): wird mit Auftrag 20 eingetragen.

## TODO-Inventar

Vorkommen in `cmd` und `internal` am Stand 9ad24a5, einschließlich Tests (`git grep -ohE 'TODO\([^)]*\)' 9ad24a5 -- 'cmd/*.go' 'internal/*.go' | sort | uniq -c`; neu gezählt mit 20q). Am Endstand fba4eb2 und bei HEAD fehlt nur das veraltete `TODO(Q19)`: 22 hat den Kommentar in `internal/e2e/succession_test.go` angeglichen (derselbe Befehl mit `HEAD`, nachgezählt mit 20r). Alle anderen Marken und Zahlen sind gleich. Gegenüber 858b2f1 (25 `TODO(ask)`, 8 `TODO(Q19)`) hat Auftrag 21 fünf `TODO(ask)` zu Q8 aufgelöst (Pin-Feld 7 in `internal/store/records.go`, `internal/translog/doc.go` zweimal, `translog.go`, `verifier.go`) und sieben `TODO(Q19)` entfernt (`git diff 858b2f1 9ad24a5 -- 'cmd/*.go' 'internal/*.go'`, nur entfernte Zeilen mit diesen Marken). Die Erwähnung `TODO(phase3-...)` in einem Kommentar von `internal/translog/doc.go` ist nicht gezählt. **Nach Auftrag 24** (gemeinsame Quelle `orch/n24`, derselbe Befehl): Die 11 Marken `TODO(phase3-translog)` sind entfallen (Paket E, ersetzt durch sachliche Kommentare); alle anderen Zahlen sind gleich:

| Marke | Zahl | Bedeutung |
|---|---|---|
| `TODO(ask)` | 20 | strengste Lesart, wo die Spezifikation schweigt; ohne eigene Frage, zwei Stellen mit Verweis auf Q11 (`internal/client/index.go`) |
| `TODO(phase3-translog)` | 11 an fba4eb2, 0 nach Auftrag 24 | standen nur im Testdouble `translogtest` (`unverified.go`) und waren veraltet; mit Auftrag 24 (Paket E) durch sachliche Kommentare ersetzt |
| `TODO(Q1)`, `TODO(Q15)` | je 8 | Wiederherstellungsempfänger, Neuausstellung für Leser vergangener Zeiträume |
| `TODO(Q20)` | 7 | Markierung `Unconfirmed` |
| `TODO(Q12)` | 5 | Thread-Wurzel ohne Begriffsliste |
| `TODO(Q9)`, `TODO(Q6)` | je 3 | Adresszuordnung, Vertretung |
| `TODO(Q13)`, `TODO(Q18)` | je 2 | `checkSignerGen`, alleiniges Mitglied |
| `TODO(Q3)`, `TODO(Q4)`, `TODO(Q7)` | je 1 | Serversuche, Logschlüssel, `mailbox rotate` |
| `TODO(Q19)` | 1 an 9ad24a5, 0 am Endstand | an 9ad24a5 veraltet: Kommentar im Kopf von `internal/e2e/succession_test.go` (Schritt 3 „is refused … stays locked“), obwohl der Code des Tests den gebauten Kompromissfall prüft (`ceremony.Succeed` mit `Compromised` und Grenze, 21b). Mit 22 angeglichen (afad8de). |

Außerhalb von Go: `scripts/two-host-test.sh` trug bis Auftrag 24 `TODO(task-15b)` (Pin und Zeuge einer echten Zeremonie). Mit Auftrag 24 (Paket E) ist die Marke entfallen; an ihrer Stelle verweist der Kommentar auf RUNBOOK 9.1 („Testbuild“) und RUNBOOK 1.

## Was die nächste Phase als Erstes wissen muss

1. **Widerruf nach D93 im Betrieb erproben, vor jedem Betrieb mit echten Mails.** Q19 und Q8 sind entschieden (03.11.2026, D93: Widerruf über Pin-Feld 7, `succeed --compromised`, `revoke`, `admin-rotate`) und mit Auftrag 21 gebaut (21a 02ee7b5, 21c 12d48cc, 21b 7cde738; Spezifikation und RUNBOOK 7.3 mit 21d und 21e). Seit 22 (afad8de) heilt eine Wiederholung von `publish` überschriebene Dateien in `data/platform/`, und seit 23 (fba4eb2) wird das Ingest-Zertifikat einmal gelesen (AUDIT R48). Seit Auftrag 24 ersetzt `publish` einen Link unter einem Namen des Exports oder verweigert ihn vor dem Schreiben (Paket A), und `address add` prüft das Admin-Zertifikat auf Signatur und gegen das Log (Paket C). Seit Auftrag 25 (Paket 25A) folgt `publish` auch an `witnesses.rec` und beim Nachloggen keinem Link, entfernt und nennt Reste `.tmp-*`, lehnt `platform/` als Link ab und einen fehlenden Namen mit anders belegtem gültigem Logeintrag vor dem Schreiben. Seit Auftrag 26 (Paket 26B) arbeitet `publish` über einen einmal geöffneten Deskriptor von `platform/` und lehnt einen Tausch von `platform/` ab; neue Meldungen stehen in RUNBOOK 7.3 und 8.6, die Ersatzzeile in 7.2. Die Restgrenzen stehen unter „Bekannte Grenzen“; was `publish` nicht heilt, entfernt der Betreiber von Hand (RUNBOOK 7.3). Die Abläufe 7.3.3 bis 7.3.5 als Ganzes mit den Programmen prüft kein Test (RUNBOOK „Nicht in `TestRunbook`“); ein Durchgang auf einer Testplattform gehört vor den Betrieb.
2. **Wachstum des Client-Zustands begrenzen** (Q22 Variante B oder Grenze je Epoche), bevor große Postfächer oder viele Geräte kommen (AUDIT R27 (a), R43). Dafür braucht D84 (2) eine Ausnahme.
3. **Zwei echte Maschinen mit NFSv4** fahren (`scripts/two-host-test.sh` ohne `--local`, RUNBOOK 9), erst dann ist M1-Kriterium E ohne Einschränkung erfüllt.
4. **Vor 10.2 Punkt 1:** TLS, Ratenbegrenzung, Missbrauchsschutz; mehrere Zeugen im Betrieb (R15). In `loghttp` hat Auftrag 24 (Paket D) den Inhaltstyp vor dem Körper und eine Grenze für gleichzeitige Signaturprüfungen gebracht, Auftrag 25 (Paket 25C) `SlotWait` 5 s und `PublishHead` nur bei neuer Gegenzeichnung, Auftrag 26 (Paket 26F) `refuse` in `PublishHead`; eine Grenze für Verbindungen im Listener und eine Rate je Quelle fehlen weiter (R8). **Haltepunkt 26A:** Die Grenzen aus Paket 26A sind nach drei Runden mit zwei offenen Funden über niedrig nicht zusammengeführt (F1 hoch, F2 mittel). Der Auftraggeber entscheidet zwischen drei Wegen (ORCHESTRATION Abschnitt 10, 12:05 UTC; Liste nach M1 Nr. 7): den Vorschlägen des Prüfers (beschäftigte Verbindungen mit vielen Anfragen verdrängen, Verbindungen von Zeugen schützen, Mindestverweildauer), einem Schalter für einen eigenen Listener der Zeugen, oder Nr. 7 so zu lassen wie vor 26A. Hinter einem Proxy mit HTTP/2 zum Client muss eine solche Grenze Anfragen zählen, nicht Verbindungen.
5. **Lokaler Zustand ist Sicherheit:** `state.json` schützt gegen Zurückspielen und trägt die Prüfvermerke. Eine Kopplung neuer Geräte (2.7, nicht in M1) muss ihn übertragen. Jede neue Schreibfolge im Client braucht dieselbe Überlegung, was nach einem Absturz übrig bleibt, und die Regel D84 (2). Bis zum Umbau auf ein über `Open` gehaltenes `os.Root` (D92 (3)) schreibt ein offener Client über den Pfad. Das Elternverzeichnis jedes Client-Verzeichnisses darf deshalb nur der eigene Benutzer beschreiben können, oder es trägt das Sticky-Bit (Eigentümer der Benutzer oder `root`; Betriebsvoraussetzung D92, AUDIT R46, RUNBOOK 0.3).
6. **Tests:** `internal/testenv` (`New`, `NewLogged`) baut Plattform, Log, Zeuge, Benutzer und Postfächer; `internal/client/tamper_test.go` zeigt gefälschte Mails, `takeover09*_test.go` die Angriffe auf die Übernahme, `cmd/gomail-ceremony/abort15m_*` und `blocked15n_*` die Terminalangriffe (AUDIT 6.5). Den Tausch einer Plattformdatei zwischen zwei Lesevorgängen stellt der Testhaken `certReadHook` nach (`platform23_test.go` in `client` und `ingest`, Auftrag 23). Fuzz-Ziele für die Prüfpfade des Clients und die Zeremonie gibt es seit Auftrag 26 („Fuzzing“, fünfter Teil); für die Client-Ziele die Tags `gomail_dev,gomail_test`.
7. **Nach M1 aus den letzten Prüfungen:** Die Punkte aus den Prüfungen von 22, 23 und 17e hat Auftrag 24 erledigt: Belegtests und überlebende Mutanten von 22 (Paket A), zweiter Aufruf von `IngestKeyFor(1)` (Paket B), Test gegen eine Doppel-Lese-Fassung in `store` (Paket E), Werte in Anführungszeichen beim Darstellen (Paket E). `-render` braucht weiter ein nicht gesetztes `TMPDIR` (MEASUREMENTS nennt `env -u TMPDIR`). Neue niedrige Reste aus den Prüfungen von Auftrag 24 stehen in der Liste nach M1 ab Nr. 64 (`docs/tasks/backlog-nach-m1.md`); Quelle: `docs/tasks/20-notes.md`, „Auftrag 24 … Prüfungen“. Auftrag 24 hat außerdem `resolveExisting` fail closed gemacht (Paket B): Ein `--dir`, dessen Pfad der Client nicht ganz prüfen kann, lehnt er ab, seit Auftrag 25 (Paket 25B) mit der Ursache (`client: cannot check that the client directory is outside the data directory: <errno-Text>`, RUNBOOK 3.2). Auftrag 25 hat Nr. 68 und 71 der Liste nach M1 erledigt und Nr. 64 und 65 zum Teil; die neuen niedrigen Reste aus seinen Prüfungen stehen dort als Nr. 72 bis 83 (Quelle: `docs/tasks/20-notes.md`, „Auftrag 25 … Prüfungen“). `scripts/bench.sh` behält seit Auftrag 25 (Paket 25D) die Rohdaten bei einem Abbruch unter `TMPDIR` und nennt den Pfad. Auftrag 26 hat Nr. 25, 66, 67, 69, 70, 72 bis 83 erledigt; Nr. 7 bleibt „Teil erledigt“ (Haltepunkt 26A, Punkt 4). Die neuen niedrigen Reste aus seinen Prüfungen stehen in der Liste als Nr. 84 bis 91, der Fund aus dem Fuzzing (Referenzkopf mit fremder Origin, AUDIT R49) als Nr. 92; er braucht eine Entscheidung des Auftraggebers, weil die Abhilfe eine Prüfregel des Clients ist (Quelle: `docs/tasks/20-notes.md`, „Auftrag 26 … Prüfungen“). `scripts/bench.sh` beendet seit Auftrag 26 (Paket 26C) bei einem Signal auch das laufende `go test`.
8. **Formatänderung für Metadaten ab Version 2 (nach M1):** Eine Version ab 2 (Flags, Übernahme) hält nur die Generationsnummer fest, nicht Schlüssel oder Zertifikats-Hash des Signierers von Version 1. Ein vor dem Pinwechsel geloggtes `ingest-<g>.cert` eines Diebs ist deshalb nicht von der ehrlichen Neuausstellung gleichen Namens zu unterscheiden, und eine solche Version kann eine Mail einer widerrufenen Generation „waschen“, wenn ihre Empfangszeit im Zeitraum einer gültigen Generation liegt. Der Client prüft heute nur den Zeitraum (`checkReceivedCovered`); schließen lässt es sich nur, wenn Version ab 2 Schlüssel oder Zertifikats-Hash von Version 1 festhält (Angreiferprüfung 21b, `docs/tasks/20-notes.md`; AUDIT R18 (e); D93 Nachtrag 21e).

## Verlauf

Die folgenden Abschnitte sind der Stand von Phase 0 und Phase 1 und bleiben zur Nachvollziehbarkeit erhalten.

### Testabdeckung in Phase 1

`go test -cover` (Phase 1):

| Paket | Abdeckung | Mindestwert |
|---|---|---|
| `store` | 90,2 % | 85 % |
| `ingest` | 88,9 % | 85 % |
| `client` | 87,5 % | 85 % |
| `smtpd` | 91,9 % | – |
| `translog` | 100 % | – |
| `ceremony` | 79,1 % | – |
| `rec`, `shamir`, `envelope`, `keys` | 99,6 %, 100 %, 93,5 %, 88,5 % | – |

Die nicht abgedeckten Zeilen in `store`, `ingest` und `client` fallen in vier Gruppen; keine gibt Daten heraus, alle brechen ab und reichen den Fehler weiter:

| Gruppe | Beispiele | Begründung |
|---|---|---|
| Fehler des Dateisystems | `store/fs.go` (`MkdirAll`, `writeTemp`, `WriteFileAtomic`, `RenameDurable`, `ReadFileLimited` nach `Stat`), `store/store.go` (Anlegen von Verzeichnissen in `WriteEpoch`, `WriteWrap`, `WriteMailbox`, `CreateUser`), `ingest/delivery.go` (`Mkdir`, `OpenFile`, `Sync`, `Close`, Schreiben von Metadaten und Marker, Journal, Löschen des Journals), `ingest/ingest.go` (`Recover`: `RemoveAll`, `SyncDir`), `ingest/queue.go` (Schreiben der Begriffsliste, Löschen der Marker), `client` (Schreiben von Verpackung, Ordnern, `mailbox.rec`, `state.json`) | Treten nur bei Ein-/Ausgabefehlern, vollem Datenträger oder fehlenden Rechten auf. Stellvertretend getestet sind: ENOSPC als `452` (`TestDiskSpaceAndErrors`), Fehler beim Verschieben mit Rücknahme (`TestMoveFailureIsUndone`), fehlende Verzeichnisse und Dateien in allen Lesepfaden, Absturz an jedem Schritt (`TestCrashDuringReceipt`). |
| Fehler von `crypto/rand` | `store.NewID`, `tempFile`, Nonces und Schlüssel in `ingest/queue.go`, Epochenschlüssel in `client/mailbox.go` | `crypto/rand` schlägt auf unterstützten Systemen nicht fehl; der Fehler wird trotzdem weitergegeben. |
| Kodierfehler geprüfter Strukturen | `rec.Encode` in `User.Encode`, `Epoch.Sign`, `AddressAssignment.Sign`, `sealPending`, `writeMeta`, `createEpoch` | Die Werte sind vorher geprüft (feste Längen, bereinigte Zeichenketten); `rec.Encode` kann dann nicht fehlschlagen. |
| Nicht erreichbare Prüfungen | `ecdh.X25519().NewPublicKey/NewPrivateKey` in `DecodeEpoch`, `DecodeEpochKeys` (32 Byte werden immer angenommen); `ParseID` nach erfolgreicher Zeichenprüfung; Kürzung in `CleanText`, wenn `cut > len(s)`; `hpke`-Fehlerpfade in `envelope`; Rückfall auf `time.Now` und `statfs` in `ingest.New` (Tests setzen beides) | Absicherungen gegen spätere Änderungen; die Bedingungen sind durch vorherige Prüfungen ausgeschlossen. |

Die Programme unter `cmd/` haben keinen Mindestwert; ihr Ablauf ist zusätzlich durch `TestRunbook` (gebaute Programme, alle Schritte des RUNBOOK) abgedeckt, der nicht in die Abdeckung der Pakete eingeht.

#### Nicht abgedeckte Zeilen der Pakete aus Phase 0 (Stand Phase 0.1)

Die Zeilennummern in `envelope/envelope.go` sind seit Phase 1 um eins verschoben (ein Import mehr).

`go test -cover` (Phase 0.1): `rec` 99,6 %, `shamir` 100 %, `envelope` 93,5 %, `keys` 88,3 % (für `keys` ist kein Mindestwert gefordert). Nicht abgedeckte Zeilen in den drei Paketen mit Mindestanforderung:

| Datei | Zeilen | Code | Begründung |
|---|---|---|---|
| rec/rec.go | 439-441 | `checkValue` in `Encode` für Listen schlägt fehl | Elemente werden bereits in `SetList` geprüft und die Slice kopiert; der zweite Aufruf ist eine Absicherung gegen spätere Änderung der Element-Records, die kein Test erzwingen kann, ohne die Prüfung in `SetList` zu umgehen. |
| envelope/envelope.go | 214-216, 278-280, 341-343 | `Encode`-Fehler in `Header.encode`, `encodeRecipients`, `Trailer.encode` | Die Werte stammen aus validierten Strukturen mit festen Größen; `rec.Encode` kann dann nicht fehlschlagen. Die Zweige geben den Fehler nur weiter (fail closed). |
| envelope/open.go | 71-73 | `hpke.NewDHKEMPrivateKey` schlägt fehl | Die Kurve wird vorher geprüft (`Curve() == ecdh.X25519()`); die Funktion schlägt nur bei anderen Kurven fehl. |
| envelope/open.go | 83-85 | entpackter Dateischlüssel hat nicht 32 Byte | `wrapped_key` hat per Schema 48 Byte, AES-GCM liefert daraus immer 32 Byte; Absicherung. |
| envelope/open.go | 90-92 | `contentAEAD` schlägt fehl | Siehe seal.go 221-232. |
| envelope/parse.go | 145-147 | mehr als 800 Blöcke | Durch `MaxFileSize` (am Anfang von `Parse`) ist ein 801. Block nicht erreichbar, weil Kopf, Empfängerteil und Trailer höchstens etwa 21,5 KiB Spielraum lassen, ein Blockelement aber 65.557 Byte braucht; die Prüfung bleibt als eigenständige Garantie. `TestParseTooManyBlocksAndTooLarge` prüft, dass 801 Blöcke abgelehnt werden (über die Dateigröße). |
| envelope/parse.go | 189-191, 193-195, 214-216 | `Encode`-Fehler in `Bytes` | `Bytes` wird nur auf Dateien aufgerufen, die `Parse` angenommen hat; deren Strukturen kodieren immer. |
| envelope/seal.go | 78-83 | `Write`/`Close` in `Seal` schlagen fehl | `Seal` schreibt in einen `bytes.Buffer` (schlägt nie fehl) und prüft die Größe vorher; die Fehlerpfade sind für den `Writer` getestet (`TestWriterOutputErrors`). |
| envelope/seal.go | 158-160 | `hdr.encode` schlägt fehl | Validierte Kopffelder mit festen Größen. |
| envelope/seal.go | 168-170, 177-179 | `hpke.NewDHKEMPublicKey`, `sender.Seal` schlagen fehl | Kurve vorher geprüft; `Seal` schlägt im Base-Modus mit gültigem Kontext nicht fehl. `NewSender` (Punkt kleiner Ordnung) ist getestet. |
| envelope/seal.go | 183-188 | `encodeRecipients` schlägt fehl; Empfängerteil über 16 KiB | Validierte Einträge; vier Einträge der Suite 1 belegen etwa 0,6 KiB. Die Grenze wird relevant für Suite 2 (S12). |
| envelope/seal.go | 192-194, 221-232 | `contentAEAD`: HKDF, `aes.NewCipher`, `cipher.NewGCM` schlagen fehl | Feste Schlüssellänge 32 und feste Parameter; diese Funktionen schlagen nur bei falschen Längen fehl. |
| envelope/seal.go | 238-240 | `emit` bei gesetztem `w.err` | `Write` und `Close` prüfen `w.err` vor dem Aufruf; Absicherung gegen neue Aufrufer. |
| envelope/seal.go | 290-293 | 801. Block im Schreiber | Die Größenprüfung in `Write` (`MaxContentSize`) macht einen 801. Block unerreichbar; die Prüfung bleibt als eigenständige Garantie. `TestWriterLimits` prüft die Grenze über die Größe. |
| envelope/seal.go | 346-360 | `signedStructure`, `keys.Sign`, `Trailer.encode` schlagen in `Close` fehl | Der Signer wird in `NewWriter` validiert (Typ, Generation, Schlüssellänge, `Extra` bis 4 KiB); danach können diese Aufrufe nicht fehlschlagen. |

Alle nicht abgedeckten Zeilen sind Fehlerzweige, die Fehler nur weiterreichen oder Grenzen ein zweites Mal prüfen. Keiner gibt Daten heraus.

### Unabhängige Prüfung in Phase 1

Zwei Subagenten prüften ohne Kenntnis von DECISIONS, HANDOFF, SPEC-ISSUES und der Commit-Historie.

**Spezifikation** (`store`, `ingest`, `client` gegen 2.4, 4, 5, 7). Behoben:
- A1: Fehlte die Epoche n+1 (entfernt oder ersetzt, `mailbox.rec` zurückgesetzt), prüfte der Client die Epochenregel für Mails der Epoche n nicht; eine nach Beginn von n+1 für n verschlüsselte Mail wurde geöffnet. Jetzt merkt sich der Client die Beginnzeiten und lehnt ab, wenn die Regel nicht entscheidbar ist (`TestStaleEpochWithNextEpochRemoved`, `TestBrokenChainWithoutMemory`).
- A2: Ein Absturz zwischen dem Anlegen neuer Epochen und dem Schreiben von `mailbox.rec` blockierte das Postfach dauerhaft und überschrieb dabei die Verpackung einer bestehenden Epoche. Jetzt übernimmt der Client gültige Epochen jenseits des Kopfs, räumt abgebrochene Epochenverzeichnisse auf und ersetzt nie eine vorhandene `epoch.rec` (`TestSupplyCrashRecovers`).
- B1: Der Server verschlüsselte für jede `epoch.rec` mit gültiger Benutzersignatur, auch von einem registrierten Nichtmitglied. Jetzt prüft er die Kette wie der Client und fragt das Log (`TestServerRejectsForeignEpoch`).
- B2: Eine monatliche Epoche, Sekunden vor Monatsbeginn angelegt, konnte eine korrekt angenommene Mail zur "veralteten" machen. Jetzt beginnt keine Epoche früher als fünf Minuten nach dem Anlegen (`TestSupplyAtMonthEnd`).
- B3: Schlug `mlock` fehl, wurde trotzdem nach `work/` ausgelagert. Jetzt nicht mehr (`TestNoSpillWithoutMlock`). Der erweiterte AES-Schlüssel im Speicher bleibt eine Grenze.
- B5: Begriffslisten wurden nicht gegen `valid_from` des Zertifikats geprüft und Ablehnungen nicht immer gemeldet (`TestPendingBeforeCertificate`).
- C3, C4, C8, C12: Begriffe aus dem Umschlag (Bcc), Aufräumen von `.tmp-*` beim Start, Sperre des Client-Verzeichnisses, offene Begriffslisten gegen die Speichergrenze.

Zur Kenntnis genommen: B4 (bleibt ein Rückgängigmachen hängen, liegen Teile bis zum nächsten Start im Postfach; nur bei Dateisystemfehlern), C1 und C2 (Auslegungen, S16 und D56), C5 (Leser können während der Umbenennungen kurz einen Marker oder Metadaten ohne Mail sehen; der Client listet nur Mails mit Datei), C6 (Doppelzustellung nach Commit ohne `250`), C7 (Generation des Unterzeichners wird nicht mit der Mitgliederliste abgeglichen, wichtig erst mit Generationswechseln in Phase 2), C9 (Dateirechte 0600/0700 passen nicht zu getrennten Betriebssystembenutzern mit gemeinsamem Verzeichnis), C10 (Abweichungen im Verzeichnisaufbau, S21), C11 (der Server kann das Ingest-Zertifikat mangels Plattformidentität nur gegen seinen Schlüssel abgleichen).

**Angreifer** (nur Datenverzeichnis nach dem Ende-zu-Ende-Lauf und Quellcode; Schreibzugriff auf das Datenverzeichnis ohne Schlüssel, entfernter SMTP-Client). Kein Klartext gefunden (sichtbar nur die Empfängeradresse in `addresses.json`, wie in Abschnitt 4 vorgesehen); kein Austausch einer Mail oder ihrer Metadaten, kein Unterschieben einer Epoche, kein Zurückspielen blieb unbemerkt; kein Absturz über SMTP. Behoben:
- B: Der unsignierte Zeiger auf den Posteingang in `mailbox.rec` ließ sich umbiegen, `list` zeigte dann ohne Warnung nichts. Jetzt kommt der Posteingang aus der signierten `folders.gml`, und der Client warnt bei Abweichung und bei unbekannten Ordnern (`TestInboxPointerRedirected`).
- C: Der Arbeiter der Vorverarbeitung hatte keinen Schutz gegen Panics; jetzt abgefangen. Antworten auf abgewiesene Verbindungen liefen in unbegrenzt vielen Goroutinen; jetzt höchstens 16, `Close` wartet auf sie (`TestRefusalsAreBounded`).
Zur Kenntnis genommen: Eine Mail mit 25 MB an 100 Postfächer schreibt 2,5 GB in den Spool und versiegelt 100-mal (begrenzt durch die Konstanten und den freien Platz, siehe Grenzen). Nur wegen des fehlenden Logs möglich (nicht als Fund gezählt): Zurückspielen gegenüber einem Client ohne Vorgeschichte, Umleiten von Adressen, widerrufene Generationen, unbemerktes Löschen von Mails.

#### Unabhängige Prüfung in Phase 0.1 (Verlauf)

Ein Subagent ohne Kenntnis von DECISIONS, SPEC-ISSUES und HANDOFF prüfte `envelope` und `rec` gegen 3.1 bis 3.6 der Version 1.1 und fand keine Abweichung von der Spezifikation. Behoben (Commit 3b8cb50): Der Schreiber überschrieb seinen Klartextpuffer nur im Erfolgsfall; `Kind.String` lieferte für unbekannte Dateiarten einen Kunstnamen, den `keys.Sign` als Domäne angenommen hätte. Zur Kenntnis genommen, nicht geändert: `SealOptions.Rand` erlaubt Aufrufern die Wiederverwendung von Zufall (siehe Invarianten); `Decrypt` leitet das Flag aus der Position in der Blockliste ab, die `Parse` als `0x01* 0x02` garantiert; `Parse` kopiert die ganze Datei (bis 50 MiB) und hält sie für `FileHash`.

### Fuzzing in Phase 1

Fuzz-Ziele aus Phase 0: `rec.FuzzDecode`, `rec.FuzzIsNFC`, `keys.FuzzParseWordlist`, `keys.FuzzSeedFromWords`, `keys.FuzzDecodeGenerationCert`, `keys.FuzzOpenKeystore`, `shamir.FuzzShareFromWords`, `shamir.FuzzShareFromBytes`, `shamir.FuzzCombine`, `envelope.FuzzParseAndOpen`. Neu in Phase 1:

- `store.FuzzDecodeRecords`: alle Datensätze von `store` (Benutzer, Postfach, Epoche, Epochenschlüssel, Metadaten, Begriffslisten, Vermerk, Journal, Plattformschlüssel und -identität, Adresszuordnung, Name, Ordner); angenommen wird nur, was byte-identisch zurückkodiert.
- `smtpd.FuzzCommands`: beliebige Eingaben auf Befehlsebene; jede Antwortzeile wohlgeformt, nichts über der Größengrenze zugestellt.
- `smtpd.FuzzData`: beliebige Daten nach `DATA`; zugestellt wird genau das Ergebnis einer Referenz für Dot-Unstuffing, ungültige Eingaben nie.
- `ingest.FuzzTerms`: beliebige Header; alle Begriffe und Metadatenfelder speicherbar (UTF-8, NFC, ohne Nullbyte, innerhalb der Grenzen), keine doppelten Begriffe.

Ergebnis Phase 1: alle 14 Ziele je 5 Minuten ohne Fund, kein neuer Fall unter `testdata/fuzz/`. Ausführungen:

| Ziel | Ausführungen | Ziel | Ausführungen |
|---|---|---|---|
| rec.FuzzDecode | 27,4 Mio. | shamir.FuzzShareFromBytes | 34,2 Mio. |
| rec.FuzzIsNFC | 29,1 Mio. | shamir.FuzzCombine | 25,4 Mio. |
| keys.FuzzParseWordlist | 14,5 Mio. | envelope.FuzzParseAndOpen | 12,1 Mio. |
| keys.FuzzSeedFromWords | 14,0 Mio. | store.FuzzDecodeRecords | 24,7 Mio. |
| keys.FuzzDecodeGenerationCert | 18,2 Mio. | smtpd.FuzzCommands | 3,6 Mio. |
| keys.FuzzOpenKeystore | 24,5 Mio. | smtpd.FuzzData | 8,5 Mio. |
| shamir.FuzzShareFromWords | 20,4 Mio. | ingest.FuzzTerms | 3,1 Mio. |

Die Ziele von `store`, `smtpd` und `ingest` liefen auf dem Stand nach den Korrekturen aus den Prüfungen. Bei `smtpd` und `ingest` zeigt der Fuzzer zeitweise 0 Ausführungen je Sekunde; das ist das Minimieren neuer Eingaben, keine einzelne Eingabe brauchte länger als eine halbe Sekunde (geprüft). Der Regressionsfall `revokes = 0` aus Phase 0 liegt zusätzlich mit dem neuen Typ-String `user-gen` vor.
