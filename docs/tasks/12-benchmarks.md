# Auftrag 12: Messumgebung (Meilenstein 7)

Welle 3. Nicht sicherheitskritisch, aber: keine Messung darf einen Klartextpfad in die Programme bringen. Feste Vorgaben: `docs/tasks/00-vorgaben.md`.

## Umfang
Paket `internal/bench` (nur `_test.go` und Benchmark-Helfer; nichts davon wird in die Programme gelinkt): reproduzierbare Benchmarks mit festem Zufall für die Mails (Größenklassen 4 KiB, 64 KiB, 1 MiB, 10 MiB; feste Header), je mit Angabe von Befehl, Umgebungsvariablen und Hardware-Erfassung (`runtime.GOARCH`, `NumCPU`, `/proc/cpuinfo` Modellname, Kernel aus `/proc/version`, Dateisystem des Datenverzeichnisses aus `/proc/mounts`; alles nur in die Ausgabe des Benchmarks, nie in ein Datenverzeichnis):
1. Durchsatz beim Empfang **mit** Verschlüsselung: `smtpd` + `ingest` über `net/smtp` gegen 127.0.0.1, Mails pro Sekunde und MiB/s, 1 und 4 gleichzeitige Verbindungen, Ergebnis je Größenklasse. **Ohne** Verschlüsselung: derselbe `smtpd` mit einem Benchmark-Backend im Testpaket, das den Datenstrom nur in eine Datei im Scratch-Verzeichnis des Benchmarks schreibt (kein Produktivcode; Datei wird sofort gelöscht; der Benchmark läuft nur in einem Temp-Verzeichnis).
2. Kosten der Indexierung im Client pro Mail (`client.Index` über `pending` mit Begriffslisten und mit `unprocessed`-Markern), µs/Mail und Allokationen.
3. Größe der Indexsegmente pro 1.000 Mails (Bytes auf der Platte je Segment und zusammengefasst) bei typischer Begriffsverteilung (10 Absender, 3 Empfänger, 30 Tage, 20 % Anhänge, Threads).
4. Dauer eines `Sync` bei 10.000 Mails in einem Postfach (ohne Indexierung und mit), Sekunden.
5. Speicherbedarf des Servers unter Last: `runtime.MemStats` (HeapInuse, Sys) und `/proc/self/status` VmRSS nach 1.000 Mails mit 20 Verbindungen; Spitze und Ruhewert.
`scripts/bench.sh` führt alles aus und schreibt eine Markdown-Tabelle (Vorlage für `docs/MEASUREMENTS.md`, Auftrag 17). Jede Zahl mit Befehl zum Nachmessen.

## Darf ändern
`internal/bench/**` (neu), `scripts/bench.sh` (neu), und falls nötig exportierte Test-Helfer in `internal/testenv/testenv.go`. Keine Änderungen an Produktivpaketen; brauchst du einen Haken (zum Beispiel ein injizierbares Backend), nenne ihn im Bericht statt ihn zu bauen.

## Fertig-Kriterien
`go vet ./...`, `go test -race ./internal/bench` (Kurzläufe mit `-short`), `go test -run '^$' -bench . ./internal/bench` läuft durch; eine erste Messtabelle im Bericht mit der Hardware dieser Maschine. Bericht nach `00-vorgaben.md`.
