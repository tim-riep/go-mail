# Runbook: go-mail lokal von Hand (Phase 1)

Dieses Dokument führt Schritt für Schritt durch den Ablauf von Phase 1: Plattform einrichten, Server starten, Benutzer anlegen und registrieren, Postfach anlegen, Adresse zuordnen, eine Mail per SMTP einliefern, sie auflisten und lesen. Alle Befehle laufen auf einem Rechner, im Verzeichnis des Repositorys. Der Test `TestRunbook` in `internal/e2e` führt genau diese Schritte automatisch aus.

**Nur für die Entwicklung.** Phase 1 hat kein Transparenzlog. Server, Client und Zeremonie starten deshalb nur mit `--insecure-no-log`, und der Client warnt bei jedem Start. Die Entwicklungszeremonie legt den Plattform-Root ungeteilt in eine Datei. Nie mit echten Mails verwenden.

## 0. Voraussetzungen

- Go 1.26 (getestet mit 1.26.10). Ist lokal eine ältere Version installiert, lädt `GOTOOLCHAIN` die richtige:

  ```
  export GOTOOLCHAIN=go1.26.10
  ```

- `curl` mit SMTP-Unterstützung (`curl --version` nennt `smtp` unter "Protocols") zum Einliefern einer Mail. Jeder andere SMTP-Client geht auch.

Ein Arbeitsverzeichnis anlegen und die drei Programme bauen:

```
mkdir -p /tmp/gomail-demo
go build -o /tmp/gomail-demo/bin/ ./cmd/...
cd /tmp/gomail-demo
export PATH="$PWD/bin:$PATH"
```

In `/tmp/gomail-demo` entstehen drei getrennte Verzeichnisse:

| Verzeichnis | Inhalt | gehört zu |
|---|---|---|
| `data/` | Datenverzeichnis nach Abschnitt 4, nur verschlüsselte Dateien, öffentliche Schlüssel und signierte Datensätze | Server und Client gemeinsam |
| `keys/` | private Plattformschlüssel aus der Zeremonie | Betreiber, nie ins Datenverzeichnis |
| `alice/` | Schlüsselspeicher und lokaler Zustand des Benutzers | Client |

## 1. Entwicklungszeremonie

```
gomail-ceremony init --dev --data ./data --keys ./keys --insecure-no-log
```

Das Programm erzeugt einen Plattform-Root, leitet Identität, Admin- und Ingest-Schlüssel der Generation 1 ab und schreibt:

- `data/platform/identity-1.pub`, `admin-1.pub`, `admin-1.cert`, `ingest-1.pub`, `ingest-1.cert`
- `keys/admin-1.key`, `keys/ingest-1.key` (private Schlüssel, Dateirechte 0600)
- `keys/identity-1.pin` (Plattformidentität für Clients, als Entwicklungsidentität markiert)
- `keys/platform-root.INSECURE-DEV-ONLY.txt` (der ungeteilte Root, deutlich markiert)

Liegt `keys/` im Datenverzeichnis oder umgekehrt, bricht die Zeremonie ab.

## 2. Server starten

In einem eigenen Terminal:

```
cd /tmp/gomail-demo
gomail-server serve --data ./data --listen 127.0.0.1:2525 --ingest-key ./keys/ingest-1.key --insecure-no-log
```

- Ohne `--insecure-no-log` verweigert der Server den Start.
- `--listen` muss eine Loopback-Adresse sein (5.1). Eine andere Adresse geht nur mit `--isolated-test-network`.
- Beim Start räumt der Server `spool/` und `work/` (5.2, 5.3).
- Das Log enthält nur IDs, Größen und Statuscodes. Beenden mit Strg+C.

### Server mit Transparenzlog (ab Auftrag 15)

Seit Auftrag 15 läuft `gomail-server serve` immer mit dem Transparenzlog; `--insecure-no-log` gibt es beim Server nicht mehr, dafür sind `--pin` (außerhalb des Datenverzeichnisses) und `--log-listen` Pflicht. Die Schritte oben beschreiben noch den Stand von Phase 1; Auftrag 19 stellt das RUNBOOK ganz um. Für den Betrieb des Servers gilt schon jetzt:

- **`--require-client-lock`** (Testsperre nach 9.1, Lesart D70): Der Server startet nur, wenn eine wirksame Client-Sperre `locks/client` besteht (gomailctl hält sie). Ohne den Schalter startet der Server auch ohne laufenden Client und meldet nur, dass keine Client-Sperre gehalten wird; ein dauerhaft laufender Server kann beim Start keinen Client voraussetzen. Der Test auf zwei Maschinen schaltet ihn ein. Die Testsperre zeigt nur, dass irgendein Prozess mit Zugriff auf das Datenverzeichnis die Sperre hält; sie garantiert keine Echtheit des Clients (keine Authentifizierung).
- **Inkonsistentes Log:** Erkennt der Server, dass `log/tree.rec` zurückgesetzt oder beschädigt wurde (ein Eintrag jenseits des nächsten Index, ein veröffentlichter Kopf jenseits der Größe, ein kleinerer oder anderer Baum als der zuletzt gesehene), verweigert er den Start mit `translog: log is inconsistent`. Läuft er bereits, lehnt er jede Einlieferung mit `451 4.3.0` ab und signiert keine Köpfe mehr (das Server-Log nennt `signing refused`), liefert aber den zuletzt veröffentlichten Kopf weiter an die Zeugen aus. Das bleibt so, bis der Server beendet, `log repair` ausgeführt und der Server neu gestartet ist: Ein laufender Server übernimmt einen reparierten Baum nie.
- **`log repair`:**

  ```
  gomail-server log repair --data ./data --pin ./keys/identity-1.pin
  ```

  *Wann:* wenn der Server wegen eines inkonsistenten Logs nicht startet oder mit 451 ablehnt, und nur bei beendetem Server (der Befehl hält die Serversperre `locks/server` und scheitert neben einem laufenden Server).

  *Was es tut:* Es baut `log/tree.rec`, die Kacheln und `log/keys/` aus den Einträgen und den signierten Köpfen neu. Die neue Größe m ist die Zahl der Einträge, die ab `entries/0.rec` lückenlos vorhanden und lesbar sind; jeder Kopf in `log/heads/` muss eine gültige Log-Signatur tragen, höchstens m groß sein und zum aus den Einträgen neu berechneten Baum passen. Es löscht nichts. Liegen Einträge jenseits von m (verwaiste Einträge `log/entries/<i>.rec` mit i ≥ m), meldet es deren Zahl und Bereich, schreibt nichts und endet mit Status 1; der Betreiber prüft und entfernt sie bewusst und führt `log repair` erneut aus. Bei Erfolg meldet es `0 verwaiste Einträge gemeldet, 0 verworfen`. Danach den Server neu starten.

  *Was es nicht heilt:* einen fehlenden oder geänderten Eintrag unterhalb eines signierten Kopfes (nur ein Backup von `log/`, das jeden je an einen Zeugen gegebenen Kandidaten umfasst, stellt die Bytes wieder her); ein `tree.rec`, das mehr Einträge nennt als vorhanden sind; eine Datei in `log/heads/`, die kein Kopf dieses Logs ist (der Betreiber entfernt sie und repariert erneut). Einen Rückschritt, bei dem auch `entries/<n+1>.rec` entfernt wurde und den kein veröffentlichter Kopf deckt (die Einträge seit dem letzten veröffentlichten Kopf), erkennt ein neu gestarteter Server gar nicht; nur der laufende Server und die Clients bemerken ihn (`internal/translog/doc.go`, „What write access to log/ gives an attacker“). Die Schreiber der verlorenen Einträge hängen sie erneut an.

## 3. Benutzer erzeugen

Zurück im ersten Terminal. Die Passphrase des Schlüsselspeichers kommt aus der Umgebungsvariable `GOMAILCTL_PASSPHRASE`, aus `--passphrase-file` oder wird abgefragt. Die Abfrage auf dem Terminal ist in Phase 1 sichtbar (keine Terminalsteuerung ohne Zusatzmodul); für echte Passphrasen die Datei oder die Variable verwenden.

Für die folgenden Befehle die gemeinsamen Optionen in eine Variable legen:

```
export GOMAILCTL_PASSPHRASE='correct horse battery staple'
C="--data ./data --dir ./alice --platform ./keys/identity-1.pin --insecure-no-log"
```

Schlüssel erzeugen:

```
gomailctl keygen $C
```

Der Client zeigt 24 Wörter und fragt danach drei davon ab ("Wort Nr. 7:"). Die Wörter genau so eingeben, wie sie angezeigt wurden, in Kleinbuchstaben und ohne Leerzeichen; eine tolerantere Eingabe ist noch nicht entschieden (SPEC-ISSUES S11). Erst nach der richtigen Antwort entstehen `alice/keystore`, `alice/user.rec` und `alice/state.json`. Der Seed wird danach gelöscht; er liegt nirgends auf der Platte.

## 4. Einladung und Registrierung

Der Admin erzeugt einen Einladungscode:

```
CODE=$(gomail-server invite create --data ./data)
echo "$CODE"
```

Der Benutzer registriert sich damit:

```
gomailctl register --invite "$CODE" $C
```

Danach liegt `data/users/<user-id>/user.rec`. Der Code ist verbraucht; ein zweiter Versuch mit demselben Code scheitert.

## 5. Postfach anlegen

```
MBX=$(gomailctl mailbox create "Büro" $C)
echo "$MBX"
```

Der Client erzeugt Epoche 1 (Beginn jetzt) und den Vorrat für die nächsten drei Monate (Epochen 2 bis 4, Beginn jeweils am Monatsersten 00:00 UTC), je mit zufälligen Schlüsseln und einer Verpackung für den Benutzer, dazu `folders.gml` mit dem Posteingang und zuletzt `mailbox.rec`.

## 6. Adresse zuordnen

```
gomail-server address add info@brownbear.example --mailbox "$MBX" --data ./data --admin-key ./keys/admin-1.key --insecure-no-log
```

Die Zuordnung wird mit dem Admin-Schlüssel signiert (für das spätere Log) und in `data/addresses.json` eingetragen. Das Postfach muss existieren.

## 7. Mail einliefern

```
printf 'From: Lieferant <rechnung@lieferant.example>\r\nTo: info@brownbear.example\r\nSubject: Rechnung 4711\r\n\r\nHallo.\r\n' > mail.txt
curl --silent --show-error --url smtp://127.0.0.1:2525 \
  --mail-from rechnung@lieferant.example --mail-rcpt info@brownbear.example \
  --upload-file mail.txt
```

Das Server-Log zeigt `status=250` mit Größe und IDs. Eine unbekannte Adresse wird mit `550 5.1.1` abgelehnt (curl meldet `RCPT failed: 550`):

```
curl --url smtp://127.0.0.1:2525 --mail-from x@example.net --mail-rcpt nobody@brownbear.example --upload-file mail.txt
```

## 8. Auflisten und lesen

```
gomailctl list "$MBX" $C
```

Jede Zeile: Mail-ID, Empfangszeit (UTC), Größe, Absender, Betreff. Vor der Ausgabe prüft der Client die Epochenkette, die Signatur der Metadaten durch den zertifizierten Ingest-Schlüssel, die Epoche zum Empfangszeitpunkt und den Versionszähler. Abgelehnte Dateien erscheinen nicht und erzeugen eine Warnung auf stderr.

```
MAIL=$(gomailctl list "$MBX" $C | awk 'NR==1 {print $1}')
gomailctl read "$MBX" "$MAIL" $C
```

`read` prüft zusätzlich den SHA-256 der Mail-Datei gegen die signierten Metadaten und die Kopffelder der Mail, erst dann wird entschlüsselt. Ausgegeben wird die Mail mit dem vom Server ergänzten `Received`-Header.

Nur den Posteingang über seinen Namen:

```
gomailctl list "$MBX" --folder INBOX $C
```

## 9. Dateien ansehen

`inspect` zeigt Datensätze und die lesbaren Teile von `.gml`-Dateien als JSON, ohne etwas zu entschlüsseln:

```
gomailctl inspect data/mailboxes/$MBX/epochs/1/epoch.rec
gomailctl inspect data/mailboxes/$MBX/mailbox.rec
gomailctl inspect "$(ls data/mailboxes/$MBX/mail/*/*.meta.gml | head -1)"
```

Prüfen, dass kein Klartext auf der Platte liegt:

```
grep -r "Rechnung 4711" data/ || echo "kein Klartext gefunden"
```

## 10. Epochenvorrat

```
gomailctl sync $C
```

`sync` prüft die Epochenkette und hält den Vorrat für drei Monate im Voraus. Hat der Server wegen eines leeren Vorrats die letzte Epoche über ihren Monat hinaus verwendet (Vermerk `data/mailboxes/<id>/epoch-fallback.rec`), erzeugt `sync` eine Epoche mit sofortigem Beginn (fünf Minuten Vorlauf) und entfernt den Vermerk.

## 11. Aufräumen

Server mit Strg+C beenden, dann:

```
rm -rf /tmp/gomail-demo
```

## Fehlerbilder

| Meldung | Ursache |
|---|---|
| `translog: no transparency log available; refusing to start` | `--insecure-no-log` fehlt |
| `--listen muss eine Loopback-Adresse sein` | Server auf `:2525` oder einer öffentlichen Adresse gestartet |
| `client: the seed words were not confirmed` | Wort bei `keygen` nicht exakt eingegeben; `keygen` neu starten |
| `store: unknown or used invitation code` | Code falsch oder schon verwendet |
| `keys: key store authentication failed (wrong passphrase or damaged file)` | falsche Passphrase |
| `WARNUNG: Mail ... wird nicht verarbeitet` | eine Prüfung aus Abschnitt 7 ist fehlgeschlagen; die Mail wird nicht angezeigt |
| `452 4.3.1` beim Einliefern | weniger als 10 % freier Platz im Datenverzeichnis |
