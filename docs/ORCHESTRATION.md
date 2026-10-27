# Orchestrierung bis M1 „PoC abgeschlossen“

Stand: 26.10.2026. Grundlage: `docs/PLAN.md` (Version 1.4), `docs/PHASE2-KLAERUNGEN.md`, `docs/HANDOFF.md` (Phase 1), `docs/DECISIONS.md`, `docs/SPEC-ISSUES.md`. Arbeitsbranch `claude/quirky-keller-hjsl5i`. Diese Datei ist der laufende Stand der Orchestrierung; Aufträge liegen unter `docs/tasks/`, offene Fragen an den Auftraggeber in `docs/QUESTIONS.md`.

## 1. Ausgangslage

Phase 1 ist abgeschlossen (Commit 41ba4cb, danach nur Dokumente): Postfächer mit genau einem Mitglied, Empfang, Lesen, Entwicklungszeremonie, `translog` nur als Schnittstelle mit `Unverified` hinter `--insecure-no-log`. **Phase 2 wurde nie begonnen**: der Code steht auf Spezifikation 1.2. Der Abstand zu 1.4 und zu M1 im Einzelnen:

| Bereich | Stand im Code | Soll (Abschnitt) |
|---|---|---|
| Kopffeld 8 `version`, `meta-signed` nur aus Kopf und Hashes | Feld fehlt; Version nur im Klartext (S22) | 3.1, 7 (K6) |
| Gründe und `discards` in `epoch.rec` | Gründe 1 initial … 6 sofort; kein `discards`; Beginn streng monoton | 2.4 (K1) |
| Vorlauf | fünf Minuten für alle Epochen (D50) | 2.4: sofortige Epochen ohne Vorlauf, ±5 Minuten (K8) |
| Name und Ordner | an Epoche 1, Name in `mailbox.rec` | `epochs/<n>/folders.gml` je Epoche (S20) |
| Kurznamen `user`, `invite`, `wrap-accept` | fehlen; `user.rec` unsigniert | 3.7, 2.2 (S13, S16) |
| Worteingabe | exakt (`TODO(S11)`) | 2.2 nachsichtig in der Kommandozeile |
| Sperren und Rechte | `flock`, 0600/0700 | 9.1: `fcntl`/OFD, Gruppe `gomail`, 0660/2770, Testsperre |
| SMTP `SIZE` | 25.000.000 | 26.214.400 (5.1) |
| Mehrere Mitglieder, `share`, `revoke`, `rotate`, `device lost` | nur Formate | 2.2, 2.4, 2.5, 9.2 (K2, K3) |
| Flags, Benutzersignaturen auf Metadaten | Client lehnt ab | 7 (K4) |
| Suche: `pending` verarbeiten, Indexsegmente, `search` | nur `OpenPending` | 6 (K5) |
| Transparenzlog, Zeuge, Vermerke, 24 h | 31 `TODO(phase3-translog)`, `Unverified` | 2.3, 2.7 |
| Zeremonie mit Shamir, `ingest-rotate`, `reshare` | nur `--dev` | 2.3 |
| Messung, AUDIT, RUNBOOK, zwei Maschinen | fehlt | 11 (7), 9.1, 10.2 |

Werkzeuge: Go 1.26.10 über `GOTOOLCHAIN`, 4 Kerne, 15 GiB. `golang.org/x/mod` ist erreichbar (v0.42.0, wird in `go.mod` festgeschrieben, sobald das erste Paket es braucht). Eine zweite Maschine mit NFSv4 steht in dieser Umgebung nicht zur Verfügung; der Test nach 9.1 wird als `scripts/two-host-test.sh` vorbereitet (M1 dann bedingt, siehe Auftrag).

## 2. Arbeitspakete und Wellen

Regeln: höchstens vier Umsetzer und sechs Subagenten gleichzeitig; jedes Paket nennt die Dateien, die es ändern darf; Pakete einer Welle werden in der angegebenen Reihenfolge zusammengeführt; nach jeder Zusammenführung laufen `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...`. Sicherheitskritische Pakete (Schlüssel, Signaturen, Formate, Epochen, Log, Prüfregeln im Client) bekommen zwei Verifizierer (Spezifikation und Angreifer, Modell `fable`), alle anderen einen (`opus`).

### Welle 1: Formate der Version 1.4 und Schnittstellen

| Nr. | Paket | Umfang | darf ändern | hängt ab von | sicherheitskritisch |
|---|---|---|---|---|---|
| 01 | `envelope`, `keys`, `smtpd`: Formate 1.4 | Kopffeld 8 `version`, fünf signierte `meta`-Vektoren neu, Kurznamen `user`, `invite`, `wrap-accept`, `SIZE` 25 MiB | `internal/envelope`, `internal/keys`, `internal/smtpd`; Kopf-Literale in `ingest`, `client`, `store` nur um `Version` ergänzen | – | ja |
| 02 | `store`: Datensätze und Ablage 1.4 | feste Gründe, `discards`, Kettenprüfer, `folders.gml` je Epoche mit Name, `user.rec` signiert (`user`), `wrap-accept`, Vermerk (`checkpoint`), Indexsegment, Pfade `checkpoints/`, `index/`, OFD-Sperren, Rechte 0660/2770, Testsperre | `internal/store`; mechanische Anpassungen der Aufrufer (`client`, `ingest`, `ceremony`, `testenv`, `e2e`, `cmd`) | – | ja |
| 03 | Schnittstellen Log, Zeuge, Zeremonie | `translog.Log` für M1 (Einträge, Beweise, Köpfe, Zeugen, Vermerke), Dateiformat `log/`, Note-Format der Köpfe, HTTP zwischen Server und Zeuge, `witnesses.rec`, API der Zeremonie; nur Typen, Signaturen, Fehlerwerte, Dokumentation | `internal/translog` (additiv), `internal/witness` (neu), `internal/ceremony` (nur neue Signaturen als Stubs), `docs/tasks/03-*` | – | ja (Entwurf) |

Reihenfolge beim Zusammenführen: 01, 02, 03. Integrationsprüfung der Welle danach.

### Welle 2: Annahme, Mitglieder, Log und Zeuge

| Nr. | Paket | Umfang | hängt ab von |
|---|---|---|---|
| 05 | `ingest`: Epochenwahl 1.4 | K8 (Epoche bei jedem `DATA` unter der Sperre neu lesen, sofortige Epochen bis fünf Minuten vor Beginn), `discards`, `version` im Kopf, `meta-signed` nach 7, Kettenprüfer aus `store` | 01, 02 |
| 06 | `client`: Epochen und Mitglieder | `share`, `revoke`, `rotate`, `device lost`, `generation-revoked`, `discards`, sofortige Epochen, `wrap-accept` und Übernahme (S13), `folders.gml` je Epoche, `user.rec` signiert, S11, Wiederherstellungsempfänger optional (K3, soweit entschieden) | 01, 02 |
| 07 | `translog`: Umsetzung mit `tlog` | Einträge, Baum, Beweise, signierte Köpfe, Vermerke, Aktualität; `Unverified` nach `translogtest` | 02, 03 |
| 08 | `gomail-witness` | Zeugendienst nach 2.7 mit `note`, Konsistenzprüfung, nie zwei Köpfe gleicher Größe | 03 |

Reihenfolge: 05, 06, 07, 08. Abweichung: 05 und 06 hängen nur von 01 und 02 ab und wurden nach deren Zusammenführung gestartet, noch während 03 in der letzten Nacharbeitsrunde war; die Integrationsprüfung der Welle 1 läuft nach der Zusammenführung von 03 und vor 07/08. 06b (`device lost`, `wrap-accept`, Übernahme, S11, `keygen --shares`, Wiederherstellung) folgt nach 06 in Welle 3.

### Welle 3: Suche, Zeremonie, Server-Seite des Logs, Messumgebung

| Nr. | Paket | Umfang | hängt ab von |
|---|---|---|---|
| 09 | `client`: Suche und Flags | `pending` verarbeiten, Indexsegmente (K5), Zusammenfassen ab 16, `search`, Flags mit Versionsregel (K4), Benutzersignaturen auf Metadaten | 06 |
| 10 | `gomail-ceremony` | `init --shares 3-of-5` mit Probe-Rekonstruktion, `ingest-rotate`, `reshare`; `--dev` nur mit Testkennzeichen | 03 |
| 11 | `gomail-server`: Log-Seite | Köpfe signieren, HTTP für Zeugen, Gegensignaturen ablegen, `witnesses.rec`, Adresszuordnungen ins Log | 07, 08 |
| 12 | Messumgebung | Benchmarks für Empfang mit und ohne Verschlüsselung, Indexierung, Segmentgröße, Sync, Speicher | 05, 09 |

### Welle 4: Log in Client und Server, Programme

| Nr. | Paket | Umfang | hängt ab von |
|---|---|---|---|
| 13 | `gomailctl`: Befehle | `share`, `revoke`, `rotate`, `device lost`, `search`, Flags, `recovery keygen`, `keygen --shares`, S11 | 06, 09 |
| 14 | `client`: Log-Prüfungen | alle `TODO(phase3-translog)` im Client, Vermerke in `checkpoints/`, 24-Stunden-Grenze, K2 Regel 3 über das Log, Entwicklungsidentität nur mit Testkennzeichen | 07, 09 |
| 15 | `ingest`, Server, Zeremonie: Log-Prüfungen | restliche `TODO(phase3-translog)`, `--insecure-no-log` entfernt, `Unverified` nur in Tests | 07, 10, 11 |
| 16 | Test auf zwei Maschinen | `scripts/two-host-test.sh` nach 9.1, Sperrtest über NFSv4 | 02, 15 |

### Welle 5: Abnahme und Übergabe

| Nr. | Paket | Umfang | hängt ab von |
|---|---|---|---|
| 17 | `docs/MEASUREMENTS.md` | Messungen mit Befehlen und Hardware | 12, 14, 15 |
| 18 | `docs/AUDIT.md` | Prüfpaket nach Abschnitt F | 14, 15 |
| 19 | `docs/RUNBOOK.md`, `TestRunbook` | Zeremonie, Zeuge, drei Benutzer | 13, 15 |
| 20 | Abnahme | `docs/HANDOFF.md`, Abdeckung, Fuzzing je 10 Minuten (führt der Orchestrator aus), Abschlussbericht | alle |

## 3. Haltepunkte und offene Fragen

Siehe `docs/QUESTIONS.md`. Pakete, die von einer offenen Frage abhängen, bauen die strengste Lesart und markieren die Stelle mit `TODO(Qn)`.

## 4. Verlauf

(Je zusammengeführtes Paket zwei bis drei Zeilen: Paket, Ergebnis der Verifikation, Commit.)

- **01 `envelope`, `keys`, `smtpd`** (Kopffeld 8, SIZE 25 MiB, Abdeckung `keys` 93,9 %). Verifikation: Angreifer ohne Funde (Feld 8 über AAD und Signatur gebunden, Dateiarten, Trailer- und Empfängertausch, SMTP-Größe und Smuggling abgewehrt); Spezifikation vier Funde (mittel: Client verglich die Version im Inhalt nicht mit dem Kopf; drei niedrig: stumpfe Tests, Fehlerumhüllung), behoben in Nacharbeit 01b, nachverifiziert ohne Funde. Commit 6dc201d.
- **03 Schnittstellen Log, Zeuge, Zeremonie**: Entwurf abgeliefert; Verifikation Spezifikation acht Funde (vier mittel: Zeugenquorum, zurückgehaltener Eintrag, Widerruf von Plattformgenerationen → Q8, ungeloggte Epoche blockiert Nummer), Angreifer (Bericht wurde vom Modellschutz abgebrochen, Funde aus seinen Testdateien rekonstruiert und selbst ausgeführt): hoch Zeugenquorum, hoch fremde Epochennummern belegbar, mittel `tlog`-Beweisfunktionen hängen bei Größen über 2^62, niedrig vergiftete Signaturzeile, Dekodierkosten. Nacharbeit 03b und 03c umgesetzt; die dritte Nachprüfung fand 3 mittlere Funde (Henne-Ei bei `Known` nach Ingest-Rotation, Nachfolgeregel gegen den Kompromissfall, `tree.rec`-Rollback irreversibel) und 7 niedrige; Nacharbeit 03d; vierte Prüfung: nur sechs niedrige Funde, als Pflicht in 07 und 11 übernommen (Q10). Zusammengeführt als Commit 1 nach 38626a9 (siehe `git log`), D72. Integrationsprüfung der Welle 1: 3 mittlere Funde (Kopf der Kette: Client übernimmt Epochen jenseits von `mailbox.rec` und sperrt sich danach mit `ErrRollback` → an 06; Testsperre 9.1 nicht verdrahtet → 05 (Server) und 15 (Programme); Fehlerwert für Generationslücken in der Zeremonie widersprüchlich → 10) und 8 niedrige (`folders.gml` ohne Versionszähler → 06; Vermerk-Prüfregeln, veraltete `doc.go`, Pin-Typ → 07; `wrap-accept` → 06b; Rest klarstellend für SPEC-ISSUES). Alle passenden Übergänge (Kopffeld 8, Epochenregel, `store.Chain`, translog↔store, Rechte, `pending`) bestätigt.
- **05 `ingest`** (Selbstprüfung ohne Schlüssel, Serversperre, Kettenspeicher 22× schneller, `store.ImmediateLead`). Verifikation: Angreifer ohne Funde; Spezifikation 1 mittel (Testsperre in den Programmen → Auftrag 15, `TODO(task-15)`), 2 niedrig (behoben in 05c). Commit nach 33999e4 (`git log`: „ingest: keyless self-check …“).
- Container-Neustart während der Welle 2: sechs Agenten verloren, Zwischenstände in den Worktrees erhalten; 06, 07, 10 und die 08-Verifizierer neu gestartet.
- **02 `store` nach 1.4** (Gründe, `discards`, `store.Chain`, `folders.gml` je Epoche, `user` signiert, `wrap-accept`, Vermerk, Indexsegmente, OFD-Sperren, Rechte, Rollensperren). Verifikation: Spezifikation 8 Funde (1 hoch: Client ignorierte Verwerfungen; 5 mittel: Vorlauf sofortiger Epochen, K8-Sperre, Mail-Rechte 0600, Testsperre nicht verdrahtet, `wrap-accept` ohne Schreiber), Angreifer 3 latente Funde (dieselben Lücken), sonst alle Angriffe abgewehrt. Nacharbeit 02b (Epochenregel D71, K8 im Commit, Rechte), nachverifiziert: nur niedrige Testlücken, in 02c geschlossen; Angreifer ohne hohe Funde (Restrisiko ohne Log: D71). Testsperre → Auftrag 15, `wrap-accept` → Auftrag 06 (planmäßig, nicht zurückgewiesen). Commit 38626a9.
- **08 `gomail-witness`** (acht Regeln aus 2.7, `Cosign` mit genau zwei Zeilen, Zustandsverzeichnis 0700 gesperrt, Fork-Nachweis dauerhaft, Exit 3 bei Fork). Verifikation: Spezifikation und Angreifer (fable) je ohne offene Funde nach 08b. Commit e1767dc.
- Stand Welle 2/3 (nach 08): 06 in Nacharbeit 06c (erledigt, d2fc311: untergeschobene ungültige `epoch.rec` bei Kopf+1 wird ersetzt) und 06d (Testpins, `Share` meldet verpackte Epochen; läuft); 07 verifiziert (Spezifikation 4 Funde, Angreifer 6 Funde, keiner hoch, drei mittel: OOM-Reservierung aus `tree.rec`, `Refresh` übernimmt Kopf und Index vor Erfolg von `saveIndex` und vor der Pending-Prüfung) → 07b läuft; 10 in Nacharbeit 10b (Echo aus, Bildschirm löschen, `os.Root`; läuft); 12 verifiziert (2 mittel: Speicherwerte bei `-count>1` verschleppt, `plain` misst das Ablageprotokoll statt der Verschlüsselung) → 12b läuft. Die Indexmessungen nach 09 heißen jetzt 12d (12c ist die zweite Nacharbeit).
- **06 `client` Mitglieder und Epochen** (sofortige Epochen, `Share`/`Revoke`/Vertretung, Wiederherstellungsempfänger, Ordnerliste, Ersetzen nie gültiger `epoch.rec` bei Kopf+1). Verifikation: Spezifikation erste Runde → 06c/06d; nach 06d Spezifikation (2 mittel, beide durch D63 bzw. Auftrag 06b gedeckt; 5 niedrig → 06b/DECISIONS) und Angreifer (keine Funde hoch/mittel, 2 niedrig). Volllauf race/386 grün, Abdeckung 89,6 %. Commit adf8431, D75.
- **12 Messumgebung** (`internal/bench`, `scripts/bench.sh`; Betriebsarten enc/proto/plain, Speicher im Kindprozess). Verifikation: drei Runden (opus); 12b behob 2 mittel/2 niedrig, 12c 1 mittel/4 niedrig; Abschluss ohne Funde über niedrig, 4 niedrige → 12d. Commit d4a8377, D77. Volllauf nach dem Merge läuft.
