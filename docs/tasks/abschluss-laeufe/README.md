# Zusammenfassungen der Abschlussläufe zu M1

Die vollständigen Protokolle lagen im Scratchpad des Orchestrators unter `orch/` und gehen mit dem Container verloren. Die Dateien hier fassen sie zusammen:

- `fr-final.txt`: Volllauf auf 9ad24a5.
- `fr-m1.txt`: Volllauf auf der gemeinsamen Quelle 1217496 mit 22, 23 und 23b; zum Code-Stand je Schritt siehe `fr-m1-NOTE.txt` und `docs/ORCHESTRATION.md`, Verlauf 04.11.
- `fr-head-bench.txt`: `internal/bench` mit den Testdateien aus 17.
- `ceremony-v.txt`: `cmd/gomail-ceremony` mit `-v`. SKIP-Zeilen belegen, dass die Stillstandserkennung keinen echten Teiltest übersprungen hat.
- `abdeckung.txt`: Abdeckung je Paket.

Skript der Volläufe: gofmt, vet mit und ohne Tags, je Paket `go test -race`, `-race -tags gomail_dev,gomail_test` und `GOARCH=386 -tags gomail_dev,gomail_test`; bei `internal/e2e` nur die beiden race-Läufe, mit `GOMAIL_TEST_MIN_FREE`; jeweils `-timeout 60m`.
