# Abgleich nach 21c: vorläufige Stellen aus Auftrag 21d

Auftrag 21d hat Spezifikation und Betriebsdoku zu D93 geschrieben, bevor der Code aus 21a bis 21c fertig war. Jede Stelle, deren Wortlaut vom Code abhängt, trägt den Vermerk „vorläufig, Abgleich nach 21c“. Diese Liste nennt sie mit dem, was nach dem Zusammenführen von 21c am Code zu prüfen ist. Danach entfällt der Vermerk, und diese Datei wird nicht mehr gebraucht.

**Erledigt mit Auftrag 21e** (Code im Arbeitsbranch: 21a 02ee7b5, 21c 12d48cc, 21b 7cde738). Alle Vermerke sind entfernt; was am Code abgeglichen ist, steht hier knapp, die Belege in den Dokumenten:

- PLAN 2.3: Rollenwert der Identität 0 (`store.KeyRoleIdentity`); Regel 2 mit `revoked_at_time` = Kopfzeit + 1 ms, Regel 3 mit der Kaskade, Regel 8 (Server, `address add`, `log repair`, Ursache „Generation widerrufen“), neue Regel 9 (lückenlose Ingest-Nachfolge, nie neu zertifiziert). 9.2: Optionen und Schreibweise von `<t>` (Millisekunden wie `time <T>`).
- RUNBOOK 2: alle sechs Befehle (`shareCommands`). 7.3: Befehle, Anzeige, Meldungen und Prüfungen von `publish`; „Stand“-Absatz und Übergangsregel gestrichen. 7.3.2: `<T>` ist die Zeile `time <T>`, die Zeremonie addiert 1 ms; Server auch bei kompromittierter Identität anhalten (Kaskade); Grenze vor dem ersten Eintrag des Diebs (F3, fremde Zertifikate). 7.3.3: Reihenfolge `revoke`, `ingest-rotate --pin <neuer Pin> --valid-from <T+1 ms>`, `log repair`, `publish`, Verteilen, Zeugen, Start; Pin heißt wie der alte; Meldung des Servers mit altem Schlüssel. 7.3.4: `admin-rotate` nach `revoke` mit dem neuen Pin, Meldungen von `address add`, erneute Zuordnung. 7.3.5: Server angehalten und auf neue Ingest-Generation (Kaskade), Zertifikate des Diebs aus `platform/`, `ingest-rotate` genau mit dem Wert aus `succeed`, drei Exporte getrennt, Warnung von `publish`, Clients mit altem Pin, kein eigener `revoke` für Ingest nötig. 8.2, 8.6, 8.8, 8.9, 10 und „Abgleich mit `TestRunbook`“ nachgeführt.
- SPEC-ISSUES: „Stand Auftrag 21“, S24, S25, S28, S67, S76 mit dem Stand im Code.
- `TestRunbook` prüft zu 7.3 die Verweigerung ohne Grenze (21b); nach dem Zusammenführen von 21a bis 21c (9ad24a5) mit Auftrag 21e abgeglichen, auch mit den Nacharbeiten von 21b und 21c (Kaskade bei Server und `address add`, `checkReceivedCovered`, Untergrenze 2025, Ersetzen der Dateien des Diebs, Warnungen von `publish` und `ingest-rotate`).

## PLAN

| Stelle | am Code prüfen |
|---|---|
| 2.3 „Formate“, Absatz nach der Tabelle | fester Rollenwert der Identität in `platform-revoked` (Admin 1 und Ingest 2 wie im Zertifikat) |
| 2.3 „Widerruf von Plattformgenerationen“, Regel 8 | Server verweigert den Start mit widerrufener eigener Ingest-Generation (Exit 2); feste Ursache im Client für eine widerrufene Generation |
| 9.2, Absatz nach dem Block | Optionen von `admin-rotate`, `revoke`, `succeed --compromised` außer den im Auftrag genannten; Schreibweise von `--revoke-at-time` (Millisekunden oder RFC 3339) |

## RUNBOOK

| Stelle | am Code prüfen |
|---|---|
| 2, erster Satz | `admin-rotate` und `revoke` folgen den Terminalregeln (Anteile am Terminal) |
| 7.3, Absatz „Stand“ | Befehle im Usage-Text; Meldung von `succeed --compromised`; danach den Satz zur Übergangsregel kürzen oder streichen |
| 7.3.2 | Befehl zum Ablesen der Grenze: Kopfzeit in Millisekunden gegen die Schreibweise von `--revoke-at-time` |
| 7.3.3 Schritt 2 | `revoke --pin --out`; Ablage und Name des neuen Pins (heißt er wie der alte `identity-<g>.pin`?); Reihenfolge `ingest-rotate`/`revoke` |
| 7.3.3 Schritt 6 | Meldung und Exit-Code des Servers mit altem Schlüssel und neuem Pin |
| 7.3.3 Schritt 8, 7.3.4 Schritt 8, 7.3.5 Schritt 8 | Feldnamen von Feld 7 in `gomailctl inspect`; Ursache der Warnung in `list`/`read` |
| 7.3.4 Schritt 2 | Optionen von `admin-rotate` (`--pin`, `--gen`, `--out`, `--keys`, `--valid-from` wie `ingest-rotate`?) |
| 7.3.4 Schritt 7 | `address add` für eine Adresse, deren Zuordnung ab `<N>` ungültig ist; Umgang des Servers mit solchen Einträgen in `addresses.json` |
| 7.3.5 Schritt 3 | Verhalten eines Clients mit altem Pin nach `succeed --compromised` und nach dem Umschalten der Ingest-Generation |
| 7.3.5 Schritt 4 | `publish` nimmt `<g+1>` ohne `identity-<g+1>.succ` an; Reihenfolge der drei Exporte; ob die Zeremonie sie in einem Export zusammenfasst |
| 7.3.5 Schritt 6, Fall „Ingest auch verdächtig“ | `revoke` mit dem Pin aus `succeed --compromised`; Feld 7 mit zwei Elementen |
| 10, Zeile Zeremonierechner | Prüfung „nicht in der Vergangenheit“ bei `admin-rotate --valid-from` |
| „Abgleich mit TestRunbook“, Zeile 7.3 | was `TestRunbook` nach 21c zu 7.3 ausführt; die Liste „Nicht in TestRunbook“ um die Abläufe aus 7.3.3 bis 7.3.6 ergänzen, soweit sie kein Test ausführt |

Zusätzlich nach 21c: Zeilen für die neuen Meldungen in RUNBOOK 8.6 (Fehlerbilder) aufnehmen, sobald ihr Wortlaut feststeht.

## SPEC-ISSUES

| Stelle | am Code prüfen |
|---|---|
| „Stand Auftrag 21 (D93)“, S24, S25, S67, S76 | Stand im Code nachtragen (Commit im Arbeitsbranch), Vermerk entfernen |
