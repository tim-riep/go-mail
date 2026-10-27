# Auftrag 08: `gomail-witness` (Zeuge nach 2.7)

Welle 2. Sicherheitskritisch (Gegensignaturen). Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Grundlage: `internal/witness/witness.go` (Paketkommentar mit Protokoll, Regeln 1 bis 8, Zustand, Schlüsseldatei, Befehlszeile), `protocol.go`, `witnesses.go`, und `internal/translog/doc.go` (Abschnitte „Heads“, „Witness quorum“, „Size limit“), `head.go`, `verifier.go` (`CheckTreeProof`, `NewWitnessVerifier`, `MaxTreeSize`, `MaxClockSkew`).

## Zu lesen
`docs/PLAN.md` 2.7, 3.7 (letzter Absatz), 9.2, 10.1; die genannten Dateien; `go doc golang.org/x/mod/sumdb/note`; `internal/store/fs.go` (atomares Schreiben, private Dateien).

## Umfang
1. `witness.New`, `Cosign` (alle acht Regeln: Herkunft, Logsignatur mit dem konfigurierten Log-Schlüssel, Größe ≤ `MaxTreeSize`, Konsistenzbeweis gegen den gespeicherten Kopf über `CheckTreeProof`, Zeit nicht älter als der gespeicherte Kopf und nicht mehr als `MaxClockSkew` in der Zukunft der eigenen Uhr (injizierbar), gleiche Größe nur mit gleichem Hash, Fork dauerhaft mit gespeichertem Beweis (`ErrFork`), Zustand dauerhaft geschrieben **bevor** die Gegensignatur den Prozess verlässt), `Poll` (Abruf `GET /gomail/log/head`, Beweis `GET …/consistency`, Gegensignatur `POST …/cosign` mit genau zwei Zeilen), `Serve` (Schleife mit `--interval`), `Keygen` (Schlüsseldatei 0600, exklusiv, `note.GenerateKey`; Ausgabe der Verifizierzeile), `Close`.
2. Zustandsverzeichnis (`--state`): je Origin eine Datei mit dem letzten Kopf (volle Note) und, bei Fork, der Beweis; atomar geschrieben (`store.WritePrivateFileAtomic`), beim Start gelesen; Verzeichnis gesperrt (ein Zeugenprozess je Zustand).
3. Programm `cmd/gomail-witness` mit `keygen --key <datei> --name <name>` und `serve --log <url> --log-key <verifier-zeile> --origin <origin> --key <datei> --state <dir> [--interval 10s]`; HTTP nur über die Standardbibliothek; Zeitlimits für jede Anfrage; Antwortgrößen begrenzt (`MaxHeadNote`, `MaxProofBody`). Log des Zeugen: nur Größe, Hash-Präfix, Statuscodes.
4. Tests (10.1 „Server zeigt zwei Clients unterschiedliche Logs“): ein Testserver (`httptest`) liefert Köpfe; zweiter Kopf gleicher Größe mit anderem Hash → verweigert, dauerhaft, auch nach Neustart des Zeugen; Kopf ohne gültige Logsignatur; falscher Konsistenzbeweis; Zeit in der Zukunft; Rückschritt der Größe; Absturz vor dem Schreiben des Zustands (Einspritzpunkt) → keine Gegensignatur geht hinaus; `/cosign`-Antworten 200/400/403/409 wie im Protokoll; Fuzz-Ziel für die vom Server gelieferten Körper (Kopf, Beweis) 3 Minuten; Abdeckung `witness` ≥ 85 %.

## Nicht Teil des Auftrags
Serverseite (`SignHead`, `PublishHead`, HTTP-Handler; Auftrag 11; für Tests baust du einen minimalen Testserver im Testpaket), Log-Umsetzung (07), Pin.

## Darf ändern
`internal/witness/**`, `cmd/gomail-witness/**` (neu). Nicht: `translog`, `store`, andere Pakete.

## Fertig-Kriterien
`gofmt -l .` leer, `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...`; Bericht nach `00-vorgaben.md`.
