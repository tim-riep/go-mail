# Auftrag 05: `ingest` nach Spezifikation 1.4 (Signaturprüfung ohne Schlüssel, Startsperren, Kettenspeicher)

Welle 2. Sicherheitskritisch (Signaturen, Epochenwahl). Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Die Epochenwahl nach 2.4 und K8 (verworfene und sofortige Epochen, Wahl unter der Sperre, erneute Prüfung im Commit) ist bereits umgesetzt (Auftrag 02b); baue darauf auf und ändere sie nur, wenn du einen Fehler findest (dann mit Test und Begründung im Bericht).

## Zu lesen
1. `docs/PLAN.md`: 3.1, 3.4, 5.1 bis 5.4, 7 („Was die Ingest-Signatur aussagt“), 9.1 (Testsperre), 2.4
2. `docs/PHASE2-KLAERUNGEN.md`: K8
3. Code: `internal/ingest/**` (besonders `delivery.go`: `verifyChain`, `chooseEpoch`, `stillValid`, `writeMeta`, `writeMarker`, `sealPending`; `queue.go`; `epochs_test.go`), `internal/store/records.go` (`MetaSignedExtra`, `MailMeta.SignedExtra`), `internal/store/store.go` (`HoldRoleLock`, `CheckPeerLock`, `ErrPeerLock`), `internal/envelope/envelope.go` (`Parse`, `VerifySignature`, `Header.Version`), `internal/testenv/testenv.go`

## Umfang
### A. Selbstprüfung der Signatur ohne Schlüssel (7)
Nach dem Schreiben jeder Metadatendatei und jeder Begriffsliste (Marker und Batch) prüft der Server die eigene Signatur **ohne Schlüssel**: `envelope.Parse` der geschriebenen Bytes, `extra` aus dem Kopf (`store.MetaSignedExtra(hdr, mailHash)` für Metadaten; für `pending` das `extra`, das `sealPending` verwendet, ebenfalls nur aus Kopffeldern), `VerifySignature` mit dem öffentlichen Ingest-Schlüssel der eigenen Generation. Schlägt die Prüfung fehl, bricht die Annahme vor dem Journal ab (fail closed, `smtpd.ErrTemporary`), eine Begriffsliste wird nicht geschrieben (Marker bleiben). Eine exportierte Funktion `ingest.VerifyMeta(data []byte, mailHash [32]byte, pub ed25519.PublicKey) error` (und `VerifyPending`) stellt die Prüfung für Tests und spätere Werkzeuge bereit; sie benutzt keinen privaten Schlüssel und entschlüsselt nichts.
### B. Startsperren (9.1)
`ingest.New` hält `HoldRoleLock(RoleServer)` für die Lebensdauer (Freigabe in `Close`); `Config.PeerCheck bool` (Standard false) lässt zusätzlich `CheckPeerLock(RoleClient)` laufen und bricht mit `ErrPeerLock` ab, wenn kein Client läuft. Dokumentiere, dass das Programm (Auftrag 15) entscheidet, ob der Server einen Client voraussetzt; Tests zeigen beide Fälle (zweiter Prozess oder zweiter Deskriptor wie in `store/lock_unix_test.go`).
### C. Kettenspeicher je Postfach
`verifyChain` prüft heute bei jedem `DATA` und im Commit die ganze Kette mit allen Signaturen. Ein Zwischenspeicher je Postfach, gebunden an die Bytes jeder `epoch.rec` (SHA-256 je Datei) und den Kopf aus `mailbox.rec`: stimmt alles, wird die geprüfte `store.Chain` wiederverwendet; sonst wird neu geprüft. Der Speicher darf nie eine Prüfung überspringen, die bei einer geänderten Datei nötig wäre; Test mit ersetzter `epoch.rec` bei gleichem Kopf (Hash ändert sich → neue Prüfung → Ablehnung) und Benchmark (`BenchmarkChooseEpoch` mit 40 Epochen, mit und ohne Speicher).
### D. Kleinigkeiten
`ImmediateLead` doppelt in `client` und `ingest`: nach `store` verschieben (`store.ImmediateLead`), beide Pakete verwenden die eine Konstante (erlaubte Änderung in `client/mailbox.go`: nur diese Konstante). `testenv.ImmediateEpoch` ist allgemein für jeden Grund brauchbar: Kommentar anpassen (Name bleibt). `FuzzTerms` 3 Minuten.

## Nicht Teil des Auftrags
Logprüfungen (Auftrag 15), `--insecure-no-log`, Programme (`cmd`), Vorverarbeitung über 5.3 hinaus.

## Darf ändern
`internal/ingest/**`, `internal/store/epoch.go` (nur die Konstante), `internal/client/mailbox.go` (nur die Konstante), `internal/testenv/testenv.go` (Kommentar).

## Tests und Fertig-Kriterien
Tabellentest für `VerifyMeta` (gültig; Trailer manipuliert; `extra` mit anderem Mail-Hash, anderer Version, anderer Empfangszeit; falscher Schlüssel; unsigniert); Abbruch der Annahme, wenn die Selbstprüfung scheitert (Einspritzpunkt oder manipulierter Signer); Startsperren; Kettenspeicher. `gofmt -l .` leer, `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...`; Abdeckung `ingest` ≥ 85 %. Bericht nach `00-vorgaben.md` mit Vorschlägen für DECISIONS.
