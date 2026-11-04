# Vorbereitete, nicht zusammengeführte Änderungen

- `backlog63-address-add.patch`: Punkt 63 aus `docs/tasks/backlog-nach-m1.md`. Der Commit 47d5342 basiert auf 39dbe93. `address add` prüft das Admin-Zertifikat auf Signatur (Identität des Pins oder geloggte Nachfolgen) und gegen das Log (`CheckPlatform` auf denselben Bytes); dazu kommt der Test `TestAddressAddForgedCert`. Lokal liefen gofmt, vet mit Tags und `go test -race -tags gomail_dev,gomail_test ./cmd/gomail-server`, mit Gegenbeleg.

  Zusammengeführt wird er erst nach M1, mit eigenem Volllauf und den Ergebnissen der Prüfungen (ORCHESTRATION, Abschnitt 7). Einspielen: `git am docs/tasks/vorbereitet/backlog63-address-add.patch`.
