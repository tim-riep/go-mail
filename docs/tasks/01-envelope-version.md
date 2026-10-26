# Auftrag 01: `envelope` Kopffeld 8 `version`, `smtpd` SIZE 25 MiB, Abdeckung `keys`

Welle 1. Sicherheitskritisch (Dateiformat, Signaturen). Die festen Vorgaben stehen in `docs/tasks/00-vorgaben.md` und gelten wörtlich. Dieser Auftrag erlaubt ausdrücklich Änderungen an `internal/envelope` (Phase-0-Paket) und an den Tests von `internal/keys`.

## Zu lesen (vollständig)

1. `docs/PLAN.md`: Abschnitte 3.1 (Kopf, Feld 8), 3.4, 3.6, 5.1 (SIZE), 7 („Was die Ingest-Signatur aussagt“), 16 (Zeile K6, S22)
2. `docs/PHASE2-KLAERUNGEN.md`: K6
3. `docs/HANDOFF.md`: Abschnitte `envelope`, `keys`, `smtpd`, „Fuzzing“
4. `docs/DECISIONS.md`: D31, D44, D47, D51, D54; `docs/SPEC-ISSUES.md`: S15, S22
5. Code: `internal/envelope/*.go` (auch Tests und `testdata/gen/main.go`), `internal/keys/cert.go`, `internal/keys/*_test.go`, `internal/smtpd/smtpd.go`, `internal/smtpd/session.go`, `internal/smtpd/smtpd_test.go`

## Umfang

### A. `envelope`: Kopffeld 8 `version` (3.1, Version 1.4)

1. `Header` erhält `Version uint32`. `HeaderSchema` erhält Feld 8 `version` (uint32, optional im Schema).
2. Regel beim Kodieren und Dekodieren (fail closed, beides prüfen): Bei `Kind == KindMeta` ist das Feld Pflicht und mindestens 1; bei jeder anderen Art ist das Feld verboten (ein Kopf anderer Art mit Feld 8, auch mit Wert 0, wird abgelehnt). Beim Kodieren wird das Feld nur für `meta` geschrieben; ein `meta`-Kopf mit `Version == 0` wird vom Schreiber abgelehnt (`Seal`, `NewWriter`).
3. `Parse`, `Open` und alle Lesepfade lehnen einen Kopf ab, der die Regel verletzt. Fehler über `ErrHeader` (ein eigener, über `errors.Is` erkennbarer Fehler `ErrVersion` ist erlaubt, wenn er `ErrHeader` nicht ersetzt, sondern ergänzt).
4. `created` bei `meta` ist laut 3.1 „immer die Empfangszeit der Mail, unverändert über alle Versionen“. `envelope` prüft das nicht (es kennt die Mail nicht); dokumentiere im Paketkommentar, dass die Ablage und der Client es prüfen (D31 bleibt).
5. Die signierte Struktur (`SignedSchema`) bleibt unverändert. Dokumentiere im Kommentar zu `SignedSchema`, dass mit Feld 8 alle Werte von `meta-signed` (Postfach, Epoche, `file_id`, `created`, `version`, Hash der Mail-Datei) aus dem Kopf oder aus Hashes über Chiffrat stammen, sodass auch der Server die Signatur ohne Schlüssel prüfen kann (Abschnitt 7).
6. Aufrufer, die `meta`-Köpfe erzeugen, bekommen nur die Mindeständerung: `internal/ingest/delivery.go` (`writeMeta`: `Version: m.Version` bzw. die Version der Metadaten, heute 1), `internal/client/mailbox.go` (`sealMeta`: `Version: 1`), Tests in `internal/client`, `internal/store`, `internal/ingest`, `internal/e2e`, die `KindMeta`-Köpfe bauen. Ändere dort ausschließlich das Kopf-Literal (ein Feld). Keine anderen Änderungen in diesen Paketen.

### B. Vektoren

1. `go run ./testdata/gen` im Paketverzeichnis erzeugt die Vektoren neu. Die fünf signierten Vektoren (`*-signed.gml`, Art `meta`) ändern sich, weil der Kopf Feld 8 erhält. Die fünf unsignierten Vektoren (Art `mail`) müssen **byte-identisch** bleiben (16, Zeile K6). Weise das mit `git diff --stat internal/envelope/testdata` nach; ändert sich eine unsignierte Datei, ist das ein Fehler in deiner Änderung, nicht im Generator. Prüfe vor dem Commit außerdem, dass `internal/keys/testdata`, `internal/rec/testdata`, `internal/shamir/testdata` und `internal/envelope/testdata/phase0` unverändert sind.
2. `vectors.json`: die Einträge der signierten Vektoren (`HeaderBytes`, `BlockSHA256` usw.) entsprechend neu; ergänze je Vektor das Feld `version`.
3. Lege die bisherigen fünf signierten `.gml`-Dateien (Stand vor deiner Änderung, Version 1.2 ohne Feld 8) unter `internal/envelope/testdata/v12/` ab und prüfe in einem Test, dass `Parse` sie ablehnt (`meta` ohne Feld 8).
4. Fuzz-Korpus unter `testdata/fuzz/` bleibt gültig; passe Hilfsfunktionen an, falls sie `meta`-Köpfe erzeugen.

### C. `smtpd`: SIZE 25 MiB (5.1, Version 1.3)

`DefaultMaxSize = 26_214_400`; Ankündigung `SIZE 26214400`; Tests anpassen. Kommentar: 25 MiB nach 5.1; die 1.000.000 Byte für Header (5.2) und 1.000 Byte/s (D54) bleiben dezimal. Keine weiteren Änderungen in `smtpd`.

### D. `keys`: Abdeckung mindestens 90 %

M1 verlangt für `keys` mindestens 90 % (heute 88,5 %). Erhöhe die Abdeckung ausschließlich über Tests (`internal/keys/*_test.go`), ohne `keys`-Quellcode zu ändern. Jeder neue Test prüft ein Verhalten, kein Test ruft Code nur auf, um Zeilen zu decken. Nicht erreichbare Fehlerzweige begründest du im Bericht wie in HANDOFF („Nicht abgedeckte Zeilen“).

## Nicht Teil des Auftrags

* Keine Änderung an `internal/keys/*.go` außer Tests (die Kurznamen `user`, `invite`, `wrap-accept` setzt Auftrag 02).
* Keine Änderung an `store`, `client`, `ingest` über das Kopf-Literal hinaus; die Prüfung „Version und Empfangszeit im Inhalt gleich dem Kopf“ und die Signaturprüfung ohne Schlüssel bauen Auftrag 05 und 06.
* Kein `rec`, kein `shamir`.

## Darf ändern

`internal/envelope/**`, `internal/smtpd/**`, `internal/keys/*_test.go`, und ausschließlich Kopf-Literale mit `KindMeta` in `internal/ingest`, `internal/client`, `internal/store`, `internal/e2e`.

## Tests (Pflicht)

* Tabellentest der Kopfregel: `meta` ohne Feld 8, `meta` mit 0, `mail`/`pending`/`wrap`/`index` mit Feld 8 (auch 0), `meta` mit 1 und mit `MaxUint32`; jeweils Schreiben und Lesen.
* Vektoren: alle zehn Dateien gegen `vectors.json`; die alten signierten unter `v12/` werden abgelehnt; `phase0/` weiter abgelehnt.
* Die bestehenden Negativtests aus 10.1 bleiben grün; ein manipuliertes Feld 8 (Bit gekippt) führt zur Ablehnung über die AAD (Kopf ist Teil der AAD) und zusätzlich über die Signatur.
* `FuzzParseAndOpen` 5 Minuten (`go test -run '^$' -fuzz '^FuzzParseAndOpen$' -fuzztime 5m ./internal/envelope/`); Ausführungen und Ergebnis in den Bericht. `smtpd.FuzzCommands` 2 Minuten.

## Fertig-Kriterien

* `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...` fehlerfrei auf dem ganzen Modul.
* Abdeckung: `envelope` ≥ 90 %, `keys` ≥ 90 %, `smtpd` ≥ 85 %.
* Unsignierte Vektoren und alle Vektoren der anderen Phase-0-Pakete byte-identisch (Nachweis im Bericht).
* Bericht nach `00-vorgaben.md`, zusätzlich: Liste der geänderten Vektoren mit Begründung, Vorschlag für den DECISIONS-Eintrag zu Feld 8.
