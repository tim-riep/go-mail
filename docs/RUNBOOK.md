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

## Erstinstallation

Der Produktionsweg ohne Entwicklungszeremonie (Auftrag 15h, SPEC-ISSUES S80): Programme ohne Build-Tag `gomail_dev` gebaut (`go build -o <bin>/ ./cmd/...`), Plattform-Root nur in Shamir-Anteilen. Die Abschnitte 1 und 2 oben beschreiben dagegen die Entwicklungszeremonie (`init --dev`, nur im Testbuild). `TestInitProduction` in `internal/e2e` führt diese Folge mit Programmen ohne `gomail_dev` aus (die Zeremonie über die Testseams, ohne Terminal). Platzhalter in spitzen Klammern; keine Beispielwerte übernehmen.

1. **Zeugenschlüssel** (auf dem Zeugenhost, vor der Zeremonie): je Zeuge

   ```
   gomail-witness keygen --name <zeuge> --key <zeugenschlüssel>
   ```

   Der private Schlüssel bleibt auf dem Zeugenhost (0600). Die ausgegebene Verifier-Zeile ist öffentlich und geht zur Zeremonie.

2. **Zeremonie offline** (Rechner ohne Netzwerk, Uhr vorher stellen, Standardein- und -ausgabe ein Terminal):

   ```
   gomail-ceremony init --shares 3-of-5 --out <export> --keys <schlüssel> --origin <origin> \
       --witness <zeuge>=<verifier-zeile> [--witness ...] --min-witnesses <k>
   ```

   Die Anteile erscheinen nur auf dem Bildschirm. Ergebnis: `<export>/platform/` (öffentliche Schlüssel, Zertifikate, `witnesses.rec`), `<export>/identity-1.pin` und in `<schlüssel>` die privaten Schlüssel `admin-1.key` und `ingest-1.key` (0600). Danach den Rechner ausschalten.

3. **Pin und Schlüssel verteilen:** `<export>` (nur öffentliche Dateien) und `identity-1.pin` auf den Server-Host, außerhalb des künftigen Datenverzeichnisses; `ingest-1.key` auf den Server-Host (0600, außerhalb des Datenverzeichnisses); `admin-1.key` zum Administrator; `identity-1.pin` auf getrenntem Weg zu jedem Client (`gomailctl --platform`). Die Zeugen behalten ihre privaten Schlüssel; sie bekommen Origin und, nach Schritt 5, den Prüfschlüssel des Logs.

4. **Datenverzeichnis anlegen** (Server-Host, als Benutzer der Gruppe `gomail`):

   ```
   gomail-server init --data <datenverzeichnis> --pin <pin> --witnesses <export>/platform/witnesses.rec
   ```

   `init` legt ein leeres Datenverzeichnis nach Abschnitt 4 an (`platform/`, `users/`, `invites/`, `mailboxes/`, `spool/`, `work/`, `locks/`, leeres `log/`; Rechte 2770) und schreibt nur `platform/witnesses.rec` (0660): ohne `--witnesses` aus dem Pin, mit `--witnesses` die Bytes aus `--witnesses` (die Datei muss genau Zeugen und Quorum des Pins enthalten; die Ausgabe nennt die Quelle). Es verweigert: ein vorhandenes, nicht leeres Verzeichnis, ein fehlendes Elternverzeichnis (nur die letzte Stufe wird angelegt), `--data` als symbolischen Link und ein Elternverzeichnis, dessen letzte Stufe ein symbolischer Link ist (den Pfad ohne Link angeben), einen nicht lesbaren oder ungültigen Pin, `--pin` oder `--witnesses`, die keine reguläre Datei sind (etwa eine FIFO), einen Entwicklungs-Pin (im Produktionsbuild) und Rechte oder eine Gruppe, die nicht passen (der Prozess muss der Gruppe des Verzeichnisses angehören; was es dann angelegt hat, entfernt es wieder, und nur das). Wird der Pfad während `init` ersetzt, bricht es ab, ohne Fremdes zu ändern. Die Gruppe wählt der Betreiber: ein leeres Verzeichnis mit der Gruppe `gomail` vorher anlegen, oder ein Elternverzeichnis mit setgid und Gruppe `gomail`.

5. **Veröffentlichen** (Server-Host, Server angehalten):

   ```
   gomail-ceremony publish --from <export> --data <datenverzeichnis> --pin <pin>
   ```

   `publish` schreibt Schlüssel und Zertifikate nach `platform/` und trägt die Zertifikate ins Log ein; es legt kein Datenverzeichnis an.

6. **Zeuge** (Zeugenhost): Prüfschlüssel des Logs aus `<datenverzeichnis>/platform/ingest-1.pub` bilden (note-Format `gomail-log+<hash>+<schlüssel>`, wie `scripts/two-host-test.sh` ihn bildet):

   ```
   pub=<datenverzeichnis>/platform/ingest-1.pub
   h=$({ printf 'gomail-log\n\001'; cat "$pub"; } | sha256sum | cut -c1-8)
   k=$({ printf '\001'; cat "$pub"; } | base64 | tr -d '\n')
   echo "gomail-log+$h+$k"
   gomail-witness serve --log http://<log-adresse> --log-key <prüfschlüssel> --origin <origin> \
       --key <zeugenschlüssel> --state <zustandsverzeichnis>
   ```

   Der Zeuge fragt das Log in Abständen ab und wartet, bis der Server erreichbar ist.

7. **Server:**

   ```
   gomail-server serve --data <datenverzeichnis> --listen 127.0.0.1:2525 --ingest-key <ingest-1.key> \
       --pin <pin> --log-listen <log-adresse> [--require-client-lock]
   ```

   Vor `publish` startet der Server nicht (keine Zertifikate). Mit einem anderen Pin als dem der Zeremonie verweigert er den Start. Einen Entwicklungs-Pin (`init --dev`) verweigern `serve`, `address add` und `log repair` im Produktionsbuild mit Exit-Status 2, bevor sie sperren oder das Log öffnen.

8. **Clients:** Einladung (`gomail-server invite create --data <datenverzeichnis>`), dann auf dem Client `gomailctl keygen` und `gomailctl register --invite <code>` mit `--platform <pin>`, weiter wie in den Abschnitten 3 bis 8.

## Zwei Maschinen

Der Test nach 9.1 (Abnahme, 10.2) läuft mit `scripts/two-host-test.sh`. Auftrag 19 ergänzt diesen Abschnitt; hier stehen nur Voraussetzungen und Aufrufe.

### Voraussetzungen

- Zwei Maschinen: der Server-Host exportiert ein Verzeichnis über **NFSv4**, der Client-Host hat es eingehängt, mit Sperrunterstützung (`vers=4.x`, `local_lock=none`; nie `nolock`, `local_lock=posix` oder `local_lock=all`, nie SSHFS). Das Skript prüft die Optionen in `/proc/mounts` des Client-Hosts; Leerzeichen und andere Sonderzeichen im Mountpfad (dort als `\040` usw. geschrieben) sind erlaubt.
- Zwei verschiedene Betriebssystembenutzer (Name und uid verschieden), einer je Host, beide in der Gruppe `gomail` mit derselben gid auf beiden Seiten. Empfohlene `umask` 0007; die Programme setzen 0660/2770 ohnehin selbst (D70).
- SSH mit Schlüssel ohne Rückfrage (`BatchMode`) zu beiden Benutzern, Login-Shell kompatibel zu `sh`. Das Skript selbst läuft auf einer dritten Maschine oder auf einem der beiden Hosts.
- Programme auf beiden Hosts im `PATH` oder unter `--bin` (gleicher Pfad auf beiden Hosts): auf dem Server-Host `gomail-server`, `gomail-ceremony`, `gomail-witness`, `curl` mit SMTP, `base64`, `sha256sum` oder `shasum`; auf dem Client-Host `gomailctl`, `gomail-server` (für die Gegenprobe „zweiter Server“) und der Log-Helfer.
- Log-Helfer bis Auftrag 14 (der Client trägt `user.rec` und `epoch.rec` noch nicht selbst ins Log ein): das Testprogramm von `internal/e2e`, gebaut mit

  ```
  go test -c -tags gomail_test -o e2e.test ./internal/e2e
  ```

  und auf den Client-Host kopiert (`--log-helper`).

### Aufrufe

```
scripts/two-host-test.sh --server-host gomail-srv@server --client-host gomail-cli@client \
    --export /srv/gomail --mount /mnt/gomail --log-helper /opt/gomail/e2e.test \
    [--bin /opt/gomail/bin] [--pin <datei>] [--witness <datei>] [--workdir <dir>] [--out <dir>] [--keep]
```

- **Eigenes Verzeichnis:** Das Skript legt auf jedem Host unter `--workdir` (Standard `/tmp`, lokal `$TMPDIR` oder `/tmp`) genau ein eigenes Verzeichnis `two-host.XXXXXX` an (`mktemp -d`) und arbeitet nur darin: Plattformschlüssel unter `…/keys` auf dem Server-Host, Passphrase-Datei, Pin (ohne `--pin`) und Schlüsselspeicher auf dem Client-Host, Server- und Zeugenprotokolle. Was sonst unter `--workdir` liegt, bleibt unberührt. Fehlt `--workdir`, legt das Skript es an (nur die letzte Stufe, das Elternverzeichnis muss existieren) und entfernt es am Ende wieder, wenn es leer ist.
- **`--pin` und `--witness` sind Ablageorte, die noch nicht existieren dürfen**; ihr Verzeichnis muss existieren (das Skript legt keine Elternverzeichnisse an). Eine vorhandene Datei ist ein Aufruffehler (Exit 2), das Skript überschreibt und löscht sie nicht. Es schreibt beide mit Rechten 0600 und löscht am Ende nur, was es selbst geschrieben hat. Ohne die Optionen liegen beide im eigenen Verzeichnis.
- Das Datenverzeichnis entsteht neu unter `<export>/gomail-<lauf>` (Entwicklungszeremonie). Am Ende löscht das Skript das Datenverzeichnis, die eigenen Verzeichnisse, die selbst geschriebenen Dateien unter `--pin`/`--witness` und ein selbst angelegtes `--workdir`; mit `--keep` bleibt das alles stehen (das Protokoll nennt die Pfade), nur die Passphrase-Datei nicht. Im Zwei-Maschinen-Modus müssen `--export` und `--mount` existieren; das Skript legt sie nicht an. Die Markierungsdatei `<export>/.two-host-<lauf>` (Prüfung „Export und Mount zeigen dasselbe Verzeichnis“) wird immer entfernt, auch wenn die Prüfung scheitert.
- **Keine Geheimnisse auf der Platte:** Die 24 Seed-Wörter von `gomailctl keygen` liest das Skript über eine FIFO in den Speicher der Shell und beantwortet daraus die drei Wortfragen; `list` und `read` prüft es in einer Pipe (`awk`), entschlüsselter Betreff und Text landen in keiner Datei, auch nicht mit `--keep`. Die Passphrase-Datei `…/passphrase` auf dem Client-Host löscht das Skript am Ende immer, **auch mit `--keep`**. Scheitert `keygen`, steht im Protokoll nur seine letzte Fehlerzeile, ohne die Wortfragen.
- **Keine Klartexte in Kommandozeilen:** Betreff, Text und Passphrase des Laufs stehen in keiner Kommandozeile (`/proc/*/cmdline` ist für alle Benutzer lesbar): Die Befehle bekommen sie über die Umgebung, auf den Hosts über die Standardeingabe der entfernten Shell. Die Adressen stehen als Argumente in `curl` und `gomail-server address add` (deren Schnittstelle).
- **Umgebung:** Das Skript liest nur `PATH`, `TMPDIR`, `GOMAIL_TEST_MIN_FREE` und was `ssh` braucht. Alle eigenen Variablen belegt es selbst vor; Werte aus der Umgebung (auch `GOMAILCTL_PASSPHRASE`, das sonst Vorrang vor der Passphrase-Datei hätte) wirken weder auf den Ablauf noch auf das Aufräumen. Gelöscht wird nur, was das Skript selbst angelegt hat und dessen Pfad es selbst abgeleitet hat. Prüfbar mit `env -i PATH="$PATH" sh scripts/two-host-test.sh …`.
- **Gegenprobe „zweiter Server“ ohne Kopie des Ingest-Schlüssels:** Auf dem Client-Host versucht `gomail-server log repair --data <mount>/gomail-<lauf> --pin <pin>` die Serversperre `locks/server` zu nehmen, dieselbe Sperre, die `serve` hält; das braucht keinen Ingest-Schlüssel, der Ingest-Schlüssel verlässt den Server-Host nicht (9.1). Erwartet wird die Verweigerung „Server-Sperre: store: in use by another process“. Wirkt die Sperre über NFS nicht, nähme `log repair` die Sperre und baute `tree.rec` des Testdatenverzeichnisses neu; der Lauf bricht dann ab.
- Wartet das Skript auf den Log-Kopf mit Zeugensignatur, prüft es, ob der Zeuge noch läuft, und bricht sonst sofort mit `witness.log` im Protokoll ab.
- Das Protokoll steht in `<out>/protokoll.md` (die Datei darf noch nicht existieren): jeder Befehl mit Ausgabe, nur IDs und Pfade; Adressen, Betreff, Text und Passphrase sind ersetzt.
- **Exit-Codes:** 0 bestanden; 1 abgebrochen (der Schritt steht im Protokoll), darunter im Zwei-Maschinen-Modus ein fehlendes `--export` (die Markierungsprüfung „Export und Mount zeigen dasselbe Verzeichnis“ scheitert); 2 Aufruffehler, auch solche, die das Skript erst auf einem Host erkennt (vorhandenes Ziel von `--pin`/`--witness`, fehlendes Elternverzeichnis von `--workdir`, `--pin`/`--witness` und im lokalen Modus von `--export`, fehlendes `go` im lokalen Modus ohne `--bin`); 130 Abbruch durch ein Signal (SIGINT, SIGTERM, SIGHUP). In jedem Fall beendet das Skript alle Prozesse, die es gestartet hat (Server, Zeuge, sperrender Client, `gomailctl keygen`, auch wenn dessen Shell auf dem Client-Host die Verbindung überlebt), und räumt wie oben beschrieben auf.

Ohne zweite Maschine:

```
scripts/two-host-test.sh --local [--bin <dir>] [--log-helper <datei>] [--workdir <dir>] [--out <dir>] [--keep]
```

Ohne `--bin` und `--log-helper` baut das Skript Programme und Log-Helfer mit `-tags gomail_test` in sein eigenes Verzeichnis; bei weniger als 10 % freiem Platz `GOMAIL_TEST_MIN_FREE=0.000001` setzen (wirkt nur in diesem Testbuild). Ohne `--export`/`--mount` liegen Export und „Mount“ (ein symbolischer Link) im eigenen Verzeichnis; sind sie angegeben und fehlen, legt das Skript `--export` (nur die letzte Stufe) und `--mount` als Link an und entfernt beide am Ende wieder, außer mit `--keep` (`--export` nur, wenn es leer ist). `go test -tags gomail_test -run TestTwoHostScript ./internal/e2e` führt den lokalen Modus aus (mit einer Umgebung nur aus `PATH`, `TMPDIR`, `GOMAIL_TEST_MIN_FREE` und einer Prüfung von `/proc/*/cmdline` auf Klartexte), den Zwei-Maschinen-Modus über einen `ssh`-Ersatz auf dieser Maschine (Leerzeichen im Export- und Mountpfad, eine NFSv4-Zeile statt `/proc/mounts`), dazu die Abbruchfälle (fremde Aufräumvariablen in der Umgebung, vorhandenes `--pin`/`--witness`, scheiterndes `keygen`, SIGINT während `keygen` lokal und auf einem entfernten Host, SIGTERM während der Client seine Sperre hält). **Der lokale Modus ist kein Nachweis nach 9.1:** ein Benutzer, ein Kernel, ein lokales Dateisystem, der „Mount“ ist ein symbolischer Link. Er zeigt Programme, Startprüfungen, Rechte, Abwesenheit von Schlüsseln und Klartext und den Ablauf; die Durchsetzung der Sperren durch NFSv4 zwischen zwei Maschinen und die Trennung der Benutzer zeigt nur der Lauf auf zwei Maschinen.

Noch nicht im Test: das Teilen eines Postfachs mit dem zweiten Benutzer (`gomailctl mailbox share` fehlt); geprüft wird nur, dass er das Postfach ohne Freigabe nicht lesen kann.
