# Runbook: go-mail mit Transparenzlog betreiben

Dieses Dokument beschreibt den Betrieb des PoC mit den tatsächlichen Befehlen der Programme `gomail-ceremony`, `gomail-server`, `gomail-witness` und `gomailctl`: Erstinstallation mit Zeremonie, Zeuge und Server, Benutzer und Postfächer, Geräteverlust, Ingest-Rotation, Nachfolge der Plattformidentität, Störungen, den Test auf zwei Maschinen und die Zeitquellen. Maßgeblich sind die Usage-Texte der Programme (Aufruf ohne Argumente); dieses Dokument folgt ihnen.

Der Test `TestRunbook` in `internal/e2e` geht die Abschnitte 1 bis 8 mit Programmen eines Produktionsbuilds Schritt für Schritt durch und nennt in seiner Ausgabe (`go test -v`) zu jedem Schritt den Abschnitt (`RUNBOOK 4.7: ...`). Die Zuordnung steht am Ende („Abgleich mit TestRunbook“).

**Schreibweise.** Platzhalter stehen in spitzen Klammern (`<datenverzeichnis>`, `<pin>`). Es gibt keine Beispielwerte für Seeds, Anteile, Passphrasen oder Einladungscodes; nie Werte aus einem Test oder einer Anleitung übernehmen.

**Grenzen des PoC.** Nicht mit echten Mails verwenden. Vor einem solchen Betrieb verlangt der Plan TLS, Ratenbegrenzung und Missbrauchsschutz beim Empfang, unabhängige Prüfungen (10.2), mindestens zwei von drei Zeugen und die Kopplung neuer Geräte (2.7). Der PoC hat einen Zeugen; offen sind unter anderem Q18 und Q19 (Abschnitte 7.3 und 8.4).

## 0. Überblick

### 0.1 Rollen und Rechner

| Rechner | Programme | was dort liegt |
|---|---|---|
| Zeremonierechner (offline, Live-System, ohne Netzwerk) | `gomail-ceremony` (`init`, `ingest-rotate`, `reshare`, `succeed`) | nur während der Zeremonie: Plattform-Root im Speicher; danach ausschalten |
| Server-Host | `gomail-server`, `gomail-ceremony publish` | Datenverzeichnis (Gruppe `gomail`, 2770/0660), Pin, Ingest-Schlüssel (0600, außerhalb des Datenverzeichnisses) |
| Zeugenhost (andere Maschine, anderer Betreiber oder zu Hause) | `gomail-witness` | Zeugenschlüssel (0600), Zustandsverzeichnis (0700) |
| Administrator | `gomail-server address add` | Admin-Schlüssel (0600), getrennt vom Server |
| Client-Rechner je Benutzer | `gomailctl` | Schlüsselspeicher und Client-Zustand (0600/0700), Pin |

Im PoC arbeiten Client und Server auf demselben Datenverzeichnis; für die Abnahme ist es über NFSv4 eingehängt (Abschnitt 9).

### 0.2 Programme bauen

Go 1.26 (getestet mit 1.26.10); ist lokal eine ältere Version installiert, lädt `export GOTOOLCHAIN=go1.26.10` die richtige.

```
go build -o <bin>/ ./cmd/...
```

Das ist der **Produktionsbuild**: ohne Build-Tags. Er enthält weder die Entwicklungszeremonie (`gomail-ceremony init --dev`) noch einen Testschalter (`GOMAIL_TEST_MIN_FREE`, `GOMAIL_TEST_HEAD_GAP`, `GOMAIL_TEST_DEV_IDENTITY`, `GOMAILCTL_TEST_KEYGEN_PIPE`); ein Entwicklungs-Pin wird von allen Serverbefehlen mit Exit 2 abgelehnt. Die Tags `gomail_dev` und `gomail_test` sind nur für Tests (Abschnitt 9, `docs/AUDIT.md` R35). Ausgeliefert werden nur Produktionsbuilds.

### 0.3 Verzeichnisse

| Pfad | Inhalt | Regel |
|---|---|---|
| `<datenverzeichnis>` | Abschnitt 4 des Plans: verschlüsselte Dateien, öffentliche Schlüssel, signierte Datensätze, `log/` | keine privaten Schlüssel, kein Klartext |
| `<export>` | Ergebnis einer Zeremonie: `platform/` (öffentliche Schlüssel, Zertifikate, `witnesses.rec`, Nachfolgen) und `identity-<gen>.pin` | nur öffentliche Dateien |
| `<schlüssel>` | private Plattformschlüssel `admin-<gen>.key`, `ingest-<gen>.key` | 0600, außerhalb des Datenverzeichnisses und des Exports |
| `<client>` | Schlüsselspeicher, `user.rec`-Kopie, `state.json`, Audit-Index des Logs | ein Verzeichnis je Benutzer und Gerät, Standard `~/.config/gomailctl` |

Pin, Ingest-Schlüssel und Admin-Schlüssel müssen außerhalb des Datenverzeichnisses liegen, auch über symbolische Links gesehen; sonst verweigern die Serverbefehle (Exit 2 für Pin und Admin-Schlüssel).

## 1. Erstinstallation

Reihenfolge: Zeugenschlüssel, Zeremonie, Verteilen, Datenverzeichnis, Veröffentlichen, Server, Zeuge. `TestInitProduction` und `TestRunbook` führen diese Folge mit Programmen ohne `gomail_dev` aus (die Zeremonie über die Testseams, ohne Terminal).

### 1.1 Zeugenschlüssel

Auf dem Zeugenhost, vor der Zeremonie, je Zeuge:

```
gomail-witness keygen --name <zeuge> --key <zeugenschlüssel>
```

Der Name ist druckbares ASCII ohne Leerzeichen und `+`. Die Schlüsseldatei entsteht mit 0600 und wird nie ersetzt. Die ausgegebene Verifier-Zeile `<zeuge>+<hash>+<schlüssel>` ist öffentlich und geht zur Zeremonie. Quorum: `2·<k> > <n>` (bei einem Zeugen 1 von 1).

### 1.2 Zeremonie offline

Auf dem Zeremonierechner, ohne Netzwerk. **Vorher die Uhr stellen** (Abschnitt 10): der Rechner hat kein NTP, seine Uhr gibt `valid_from` aller Zertifikate.

```
gomail-ceremony init --shares 3-of-5 --out <export> --keys <schlüssel> --origin <origin> \
    --witness <zeuge>=<verifier-zeile> [--witness ...] --min-witnesses <k>
```

- Standardeingabe und Standardausgabe müssen ein Terminal sein (Abschnitt 2). `init` zeigt zuerst die Uhr des Rechners; geht sie falsch, mit Strg-C abbrechen, die Uhr stellen und neu beginnen.
- Das Programm erzeugt den Plattform-Root, leitet Identität, Admin- und Ingest-Schlüssel der Generation 1 ab und teilt den Root in fünf Anteile zu je 30 Wörtern. Jeder Inhaber wird einzeln an den Bildschirm gerufen, sein Anteil erscheint, nach seiner Bestätigung wird der Bildschirm gelöscht. Danach geben drei zufällig gewählte Inhaber ihren Anteil ohne Anzeige ein (Probe-Rekonstruktion); erst wenn sie gelingt, werden die Dateien geschrieben.
- Ergebnis: `<export>/platform/` (öffentliche Schlüssel, Zertifikate, `witnesses.rec`), `<export>/identity-1.pin` und in `<schlüssel>` die privaten Schlüssel `admin-1.key` und `ingest-1.key` (0600). Anteile stehen in keiner Datei.
- Danach den Rechner ausschalten (2.3 Schritt 5).

### 1.3 Pin und Schlüssel verteilen

- `<export>` (nur öffentliche Dateien) und `identity-1.pin` auf den Server-Host, außerhalb des künftigen Datenverzeichnisses.
- `ingest-1.key` auf den Server-Host (0600, außerhalb des Datenverzeichnisses); `admin-1.key` zum Administrator.
- `identity-1.pin` auf getrenntem Weg zu jedem Client (`gomailctl --pin`). Der Pin ist der Vertrauensanker: Identität, Origin des Logs, Zeugen und Quorum. Er ist nicht signiert; wer ihn austauscht, bestimmt, wem Server und Clients trauen.
- Die Zeugen behalten ihre privaten Schlüssel. Sie bekommen den Origin und, nach 1.5, den Prüfschlüssel des Logs (1.7).

Im Datenverzeichnis liegt danach und zu jeder Zeit kein privater Schlüssel.

### 1.4 Datenverzeichnis anlegen

Auf dem Server-Host, als Benutzer der Gruppe `gomail`:

```
gomail-server init --data <datenverzeichnis> --pin <pin> [--witnesses <export>/platform/witnesses.rec]
```

`init` legt ein leeres Datenverzeichnis nach Abschnitt 4 an (`platform/`, `users/`, `invites/`, `mailboxes/`, `spool/`, `work/`, `locks/`, leeres `log/`; Rechte 2770) und schreibt nur `platform/witnesses.rec` (0660): ohne `--witnesses` aus dem Pin, mit `--witnesses` die Bytes der Datei, die genau Zeugen und Quorum des Pins enthalten muss (die Ausgabe nennt die Quelle). Die Gruppe wählt der Betreiber: ein leeres Verzeichnis mit der Gruppe `gomail` vorher anlegen oder ein Elternverzeichnis mit setgid und Gruppe `gomail`. Heißt die Gruppe anders, warnt `init` nur.

`init` verweigert: ein vorhandenes, nicht leeres Verzeichnis (Exit 2); ein fehlendes Elternverzeichnis (nur die letzte Stufe wird angelegt); `--data` als symbolischen Link und ein Elternverzeichnis, dessen letzte Stufe ein Link ist (den Pfad ohne Link angeben); einen nicht lesbaren oder ungültigen Pin; `--pin` oder `--witnesses`, die keine reguläre Datei sind (etwa eine FIFO); einen Entwicklungs-Pin (Exit 2); Rechte oder eine Gruppe, die nicht passen (der Prozess muss der Gruppe des Verzeichnisses angehören). Was es bis zu einem Fehler oder Signal angelegt hat, entfernt es wieder, und nur das. Wird der Pfad während `init` ersetzt, bricht es ab, ohne Fremdes zu ändern.

`init` ist der einzige Weg eines Produktionsbuilds, ein Datenverzeichnis anzulegen. Vor 1.5 startet der Server darauf nicht (keine Zertifikate).

### 1.5 Veröffentlichen

Auf dem Server-Host, solange kein Server läuft:

```
gomail-ceremony publish --from <export> --data <datenverzeichnis> --pin <pin>
```

`publish` hält die Serversperre `locks/server`, prüft `platform/` und `witnesses.rec` gegen den Pin, kopiert Schlüssel und Zertifikate nach `platform/` und trägt die Zertifikate ins Log ein. Es legt kein Datenverzeichnis an. Neben einem laufenden Server verweigert es („der Server läuft … erst anhalten“). Ein Abbruch dazwischen ist durch Wiederholen desselben Aufrufs heilbar.

### 1.6 Server starten

```
gomail-server serve --data <datenverzeichnis> --listen 127.0.0.1:2525 --ingest-key <ingest-1.key> \
    --pin <pin> --log-listen <log-adresse> [--head-interval 1h] [--hostname <name>] [--require-client-lock]
```

- `--pin` und `--log-listen` sind Pflicht; ohne Transparenzlog läuft der Server nicht (`--insecure-no-log` ist ein Aufruffehler).
- `--listen` und `--log-listen` müssen Loopback-Adressen sein; eine andere Adresse nur mit `--isolated-test-network` in einem isolierten Testnetz (5.1).
- Startprüfungen in dieser Reihenfolge (nach den Aufrufprüfungen, etwa der Loopback-Adressen), jede verweigert den Start:
  1. Pin lesen: lesbar und gültig; außerhalb des Datenverzeichnisses und kein Entwicklungs-Pin (beides sonst Exit 2).
  2. Rechte des Datenverzeichnisses und seiner obersten Einträge: nichts für andere offen; fehlendes setgid, fehlende Gruppenrechte und eine fremde Gruppe sind Warnungen.
  3. Serversperre `locks/server`: ein zweiter Server verweigert mit „Serversperre“, **bevor** er den Ingest-Schlüssel liest.
  4. Ingest-Schlüssel lesen: außerhalb des Datenverzeichnisses, Rolle Ingest.
  5. Log-Seite: Pin gegen `platform/` (keine Identitätsgeneration, die der Pin nicht kennt), `platform/witnesses.rec` (Abweichung vom Pin nur Warnung), das Log gegen Identitätsliste und Origin des Pins.
  6. Annahme (`ingest.New`): nimmt die Serversperre und hält sie bis zum Ende; prüft den Ingest-Schlüssel gegen sein Zertifikat, das Zertifikat im Log und nicht abgelöst (Abschnitt 6); mit `--require-client-lock` die Client-Sperre.
  7. Testsperre (9.1).
  8. Kopf: ein signierbarer Kopf des Logs.
- **`--require-client-lock`** (Testsperre nach 9.1, Lesart D70): Der Server startet nur, wenn eine wirksame Client-Sperre `locks/client` besteht (ein laufendes `gomailctl` hält sie). Ohne den Schalter startet er auch ohne Client und meldet nur, dass keine Client-Sperre gehalten wird; ein dauerhaft laufender Server kann beim Start keinen Client voraussetzen. Der Test auf zwei Maschinen schaltet ihn ein. Die Testsperre zeigt nur, dass irgendein Prozess mit Zugriff auf das Datenverzeichnis die Sperre hält; sie authentifiziert niemanden.
- Ein **zweiter Serverprozess** auf demselben Datenverzeichnis bräuchte eine Kopie des Ingest-Schlüssels; der verlässt den Server-Host nicht. Er verweigert ohnehin an der Serversperre. Wer die Sperre von einem anderen Host prüfen will, nimmt `gomail-server log repair` (Abschnitt 9).
- Beim Start räumt der Server `spool/` und `work/` (5.2, 5.3). Das Server-Log enthält nur IDs, Größen, Hash-Präfixe und Statuscodes, nie Adressen oder Inhalte. Beenden mit SIGINT oder SIGTERM.
- Kann die Plattform den freien Platz nicht ermitteln (NetBSD, Windows), startet der Server, nimmt aber keine Mail an (451). Unter 10 % freiem Platz antwortet er mit `452 4.3.1`.
- Köpfe: der Server signiert spätestens nach `--head-interval` (Standard 1 h) einen Kopf, während das Log wächst höchstens einen je Minute.

### 1.7 Zeuge starten

Der Zeuge braucht den Prüfschlüssel des Logs. Er wird aus `platform/ingest-<gen>.pub` des Datenverzeichnisses gebildet (note-Format `gomail-log+<hash>+<schlüssel>`; der Log-Schlüssel ist der Ingest-Schlüssel, Q4):

```
pub=<datenverzeichnis>/platform/ingest-1.pub
h=$({ printf 'gomail-log\n\001'; cat "$pub"; } | sha256sum | cut -c1-8)
k=$({ printf '\001'; cat "$pub"; } | base64 | tr -d '\n')
echo "gomail-log+$h+$k"
```

Die Zeile geht auf getrenntem Weg zum Zeugenhost. Dort:

```
gomail-witness serve --log http://<log-adresse> --log-key <prüfschlüssel> --origin <origin> \
    --key <zeugenschlüssel> --state <zustandsverzeichnis> [--interval 10s]
```

Der Zeuge fragt das Log in Abständen ab (Standard 10 s, mindestens 1 s), wartet, bis der Server erreichbar ist, signiert jeden Kopf mit, der den zuletzt mitsignierten konsistent fortsetzt, und schickt die Gegensignatur zurück; er öffnet keinen Port. Zeigt das Log zwei verschiedene Köpfe gleicher Größe, hört er für immer auf zu signieren und endet mit Exit 3 (der Beweis liegt im Zustandsverzeichnis). Das Zustandsverzeichnis bleibt über jeden Neustart erhalten; nie löschen.

Erst mit dem Quorum der Zeugen veröffentlicht der Server einen Kopf (`log/heads/<n>.sig`), und erst mit einem solchen Kopf arbeiten die Clients.

## 2. Terminalregeln der Zeremonie

`init`, `ingest-rotate`, `reshare` und `succeed` zeigen oder lesen Anteile. Für sie gilt:

- **Terminal:** Standardeingabe und Standardausgabe müssen ein Terminal sein, dessen Echo sich abschalten lässt; keine Umleitung, keine Pipe, keine Datei. Sonst verweigert das Programm, bevor es etwas anzeigt, liest oder schreibt. Einen Schalter darum gibt es nicht. Auf Systemen ohne Terminalsteuerung (nicht Linux, macOS oder BSD) verweigern alle vier Befehle.
- **stderr:** Die Aufforderungen stehen auf der Standardfehlerausgabe. Sie muss zum Schreiben geöffnet sein, sonst endet die Zeremonie mit Exit 2, bevor ein Anteil erscheint. Liegt sie auf einem anderen Terminal, wird auch dort gelöscht.
- **Anzeige:** Jeder Inhaber wird einzeln aufgerufen („Inhaber von Anteil i von n an den Bildschirm, dann Eingabetaste“); vorausgetippte Eingabe wird vorher verworfen. Nach „Anteil notiert?“ löscht die Eingabetaste den Bildschirm samt Verlauf. Die Software-Flusssteuerung (Strg-S/Strg-Q) ist während der ganzen Zeremonie aus.
- **Eingabe:** Anteile werden ohne Anzeige eingegeben, 30 Wörter, auch über mehrere Zeilen; die Eingabe wird normalisiert (Kleinschreibung, beliebiger Leerraum), Abkürzungen gelten nicht. Meldungen nennen Wortpositionen, nie Wörter. Ein Anteil wird bis zu dreimal abgefragt.
- **Abbruch:** Strg-C, Strg-\ oder Strg-Z, SIGTERM und SIGHUP stellen das Terminal wieder her, löschen den Bildschirm und beenden mit Exit 130. Während ein Anteil eingegeben wird, ist ISIG aus: Strg-C wirkt dann erst mit der Eingabetaste. Ein Abbruch endet nach höchstens etwa 2 s, auch wenn das Terminal keine Ausgabe mehr annimmt. Eine Zeremonie wird nie angehalten (Strg-Z bricht ab).
- **Commit:** Kommt ein Signal, während die Dateien geschrieben werden, aber vor dem Umbenennen des Exports, wird alles zurückgebaut (Exit 130, nichts geschrieben). Danach wird es ignoriert: die Zeremonie meldet ihr Ergebnis, den Hinweis auf das Signal und Exit 0. Exit 0 heißt immer „Export vollständig“, Exit 130 „nichts geschrieben“.
- **SIGKILL und SIGSTOP** lassen sich nicht abfangen: Echo und Flusssteuerung bleiben aus, ein gezeigter Anteil bleibt stehen. Das Terminal mit `stty sane` zurücksetzen und den Bildschirm samt Verlauf von Hand löschen.
- **Restgrenze:** Ein Terminal, das nie wieder liest (angehalten, voll, getrennt), zeigt das Löschen nicht; ein Anteil kann dann auf ihm stehen bleiben. Verlauf und Scrollback eines Terminal-Emulators liegen außerhalb des Programms: für die Zeremonie ein Terminal ohne Verlauf verwenden.

- **Bestätigungen:** Jede Bestätigung mit der Eingabetaste („Inhaber an den Bildschirm“, „Anteil notiert?“) zählt erst, wenn die Aufforderung mindestens eine Sekunde vollständig zu sehen ist. Eine frühere oder doppelte Eingabe wird verworfen, und die Zeremonie fragt mit „Eingabe zu früh, bitte erneut bestätigen“ noch einmal. Dann einmal ruhig warten und erneut die Eingabetaste drücken. Ein Doppel-Enter bestätigt nie für den nächsten Inhaber.
- **Angehaltene Ausgabe:** Ist die Bildschirmausgabe länger als 2 s angehalten oder voll, endet die Zeremonie mit Exit 130 und löscht den Bildschirm vorher. Ursachen sind Scroll Lock, Strg-S oder ein anderes Programm am Terminal. Terminal prüfen und die Zeremonie neu beginnen; es ist nichts geschrieben.

## 3. Benutzer anlegen

Alle Befehle von `gomailctl` außer `inspect` brauchen `--data <datenverzeichnis>` und `--pin <pin>` (älterer Name `--platform`), optional `--dir <client>` (Standard `~/.config/gomailctl`). Sie arbeiten nur neben einem laufenden Server, dessen Sperre `locks/server` auf diesem Rechner wirkt (Testsperre, 9.1); ohne ihn verweigern sie mit „Testsperre“. Jeder Befehl öffnet das Transparenzlog selbst mit dem Pin; ohne einen von den Zeugen bestätigten Kopf, der höchstens 24 Stunden alt ist, verarbeitet der Client nichts (Abschnitt 10).

Die Passphrase des Schlüsselspeichers kommt aus `GOMAILCTL_PASSPHRASE`, aus `--passphrase-file <datei>` oder wird auf der Standardeingabe gelesen (höchstens 4096 Byte). Vom Terminal gelesen, ist sie sichtbar (offen, R31); für echte Passphrasen die Datei verwenden.

Regeln für die **Passphrase-Datei** (das Programm prüft sie nicht, der Benutzer hält sie ein):

- Rechte 0600, nur für den Benutzer lesbar.
- Nicht im Datenverzeichnis und nicht auf NFS oder einem anderen gemeinsam genutzten Datenträger.
- Nicht neben dem Schlüsselspeicher, also nicht im Client-Verzeichnis `<client>` und nicht auf demselben Sicherungsmedium: Datei und Schlüsselspeicher zusammen öffnen den Schlüssel.
- Nach Gebrauch löschen.

### 3.1 Einladung

Der Betreiber erzeugt auf dem Server-Host einen Einladungscode und gibt ihn dem Benutzer auf getrenntem Weg:

```
gomail-server invite create --data <datenverzeichnis>
```

Ein Code gilt für eine Registrierung.

### 3.2 Schlüssel erzeugen, Seed sichern

Auf dem Client-Rechner, an einem Terminal:

```
gomailctl keygen --data <datenverzeichnis> --dir <client> --pin <pin>
```

- `keygen` läuft **nur am Terminal**: Standardausgabe und Standardeingabe müssen ein Terminal sein, dessen Echo sich abschalten lässt; ein Pseudoterminal-Master gilt nicht. Sonst bricht es ab, bevor es etwas anzeigt oder schreibt (Exit 1).
- Der Client fragt die Passphrase zweimal ab, löscht den Bildschirm samt Verlauf, zeigt die 24 Seed-Wörter und wartet auf die Eingabetaste, die erst nach dem Erscheinen der Wörter gilt („Seed notiert?“). Danach löscht er den Bildschirm und fragt drei der Wörter ohne Anzeige ab („Wort Nr. 7:“). Erst nach der richtigen Antwort und dem letzten Löschen entstehen Schlüsselspeicher, `user.rec` und `state.json` im Client-Verzeichnis.
- Strg-C oder ein anderes Abbruchsignal löscht den Bildschirm und beendet `keygen` mit Exit 130, ohne etwas zu schreiben.
- **Seed sichern:** Die 24 Wörter auf Papier, an einem sicheren Ort. Der Seed liegt danach nirgends auf der Platte. Gebraucht wird er nur für ein neues Gerät, einen Geräteverlust und die Wiederherstellung (Abschnitt 5).

Nur ein Testbuild (`-tags gomail_test`) beantwortet `keygen` ohne `--shares` mit `GOMAILCTL_TEST_KEYGEN_PIPE=1` über Pipes (Seed auf der Standardausgabe); das nutzen `TestRunbook` und das Zwei-Maschinen-Skript. Der Produktionsbuild kennt den Schalter nicht.

### 3.3 Seed zusätzlich in Anteile teilen

```
gomailctl keygen --shares <k>-of-<n> --data <datenverzeichnis> --dir <client> --pin <pin>
```

Zusätzlich zum Seed werden `<n>` Anteile zu je 30 Wörtern gezeigt, je einer für eine Vertrauensperson (2 ≤ k ≤ n ≤ 255; empfohlen für Geschäftspostfächer, etwa `2-of-3`). Jeder Inhaber wird einzeln aufgerufen, sein Anteil erscheint und wird nach seiner Bestätigung gelöscht. `<k>` Anteile stellen den Seed wieder her (5.3). Die Plattform bekommt keinen Anteil. Mit `--shares` gibt es auch im Testbuild keinen Pipe-Modus.

### 3.4 Registrieren

```
gomailctl register --invite <code> --data <datenverzeichnis> --dir <client> --pin <pin>
```

Ausgabe `Registriert: <benutzer-id>`. Der Client legt `users/<benutzer-id>/user.rec` an und trägt sie selbst ins Log ein. Der Code ist verbraucht; ein zweiter Versuch mit demselben Code scheitert.

**Warten auf den Kopf.** Jeder Befehl, der auf einen eigenen Logeintrag folgt (nach `register`, `mailbox create`, `share`, `revoke`, `device lost`), braucht einen von den Zeugen bestätigten Kopf, der diesen Eintrag deckt. Bis der Server ihn signiert hat (während das Log wächst höchstens einer je Minute) und der Zeuge ihn bestätigt hat, scheitert der nächste Befehl mit „not yet covered by a verified head“ (Exit 1); nach etwa einer Minute wiederholen.

## 4. Postfach

Für die Beispiele die gemeinsamen Optionen in einer Variable:

```
C="--data <datenverzeichnis> --dir <client> --pin <pin>"
```

### 4.1 Postfach anlegen

```
gomailctl mailbox create <name> $C
```

Ausgabe: die Postfach-ID. Der Client erzeugt Epoche 1 (Beginn jetzt) und den Vorrat für die nächsten drei Monate, je mit zufälligen Schlüsseln und einer Verpackung für den Benutzer, dazu `folders.gml` mit dem Posteingang `INBOX`, und trägt die Epochen ins Log ein.

### 4.2 Adresse zuordnen

Der Administrator:

```
gomail-server address add <adresse> --mailbox <postfach-id> --data <datenverzeichnis> --admin-key <admin-1.key> --pin <pin>
```

Die Zuordnung wird mit dem Admin-Schlüssel signiert, ins Log eingetragen und danach in `addresses.json` (Arbeitskopie) übernommen. Das Postfach muss existieren. Eine Adresse, die einem anderen Postfach zugeordnet ist, wird abgelehnt (Exit 2); Umordnen und Entfernen gibt es im PoC nicht (R39). Fehlermeldungen nennen die Adresse nie; die Adresse steht aber in der Kommandozeile und in der Erfolgsmeldung (R19).

### 4.3 Mail einliefern

Jeder SMTP-Client, etwa `curl` mit SMTP-Unterstützung (`curl --version` nennt `smtp`):

```
curl -q --url smtp://127.0.0.1:2525 --mail-from <absender> --mail-rcpt <adresse> --upload-file <mail-datei>
```

Das Server-Log zeigt `status=250` mit Größe und IDs. Eine unbekannte Adresse wird mit `550 5.1.1` abgelehnt; ein inkonsistentes Log, eine abgelöste Ingest-Generation oder eine nicht geloggte Epoche mit `451` (Abschnitt 8); zu wenig Platz mit `452 4.3.1`.

### 4.4 Auflisten und lesen

```
gomailctl list <postfach-id> [--folder <name>] $C
gomailctl read <postfach-id> <mail-id> $C
```

`list` gibt je Mail eine Zeile aus: Mail-ID, Empfangszeit (UTC), Größe, Betreff. Eine **Absenderspalte gibt es nicht** (D86: außer dem Betreff kein Klartext der Metadaten in der Ausgabe). Vor der Ausgabe prüft der Client Epochenkette, Log, Ingest-Zertifikat und Signatur der Metadaten, die Adresszuordnung zum Empfangszeitpunkt und den Versionszähler; abgelehnte Mails erscheinen nicht und erzeugen eine Warnung auf stderr (`WARNUNG: Mail <id> wird nicht verarbeitet: <ursache>`). `read` prüft zusätzlich den SHA-256 der Mail-Datei und gibt die Mail mit dem vom Server ergänzten `Received`-Header auf der Standardausgabe aus; entschlüsselte Inhalte nie in eine Datei auf gemeinsam genutzten Datenträgern umleiten.

### 4.5 Suchen

```
gomailctl search <postfach-id> <begriff> [--since JJJJ-MM] $C
```

Begriffe: `from:`, `fromdomain:`, `to:`, `day:`, `month:`, `thread:`, `has:attachment` (5.4). Ausgabe je Treffer: Mail-ID, Empfangszeit, Ordner, Betreff. Der Suchbegriff erscheint in keiner Meldung. `--since` erwartet `JJJJ-MM` (sonst Exit 2).

### 4.6 Flags

```
gomailctl flag <postfach-id> <mail-id> [--set a,b] [--clear c] $C
```

Namen: `seen`, `answered`, `flagged`, `deleted`, `draft`; ein anderer Name ist ein Fehler (Exit 1). Ausgabe: die gesetzten Flags und die neue Version der Metadaten.

### 4.7 Teilen und entziehen

```
gomailctl mailbox share <postfach-id> <benutzer-id> [--from <epoche>] [--to <epoche>] $C
gomailctl mailbox revoke <postfach-id> <benutzer-id> $C
```

- `share` ohne `--to` macht den Benutzer zum Mitglied ab einer neuen Epoche; mit `--from <n>` verpackt es zusätzlich die vorhandenen Epochen ab `<n>` für ihn (`--from 1`: alle). Mit `--to` verpackt es nur die Epochen eines vergangenen Zeitraums (Vertretung, kein Mitglied). Der andere Benutzer muss registriert sein.
- `revoke` löscht die Verpackungen des Benutzers und beginnt sofort eine neue Epoche ohne ihn. Danach liest er das Postfach nicht mehr (`list` endet mit Exit 1, „epoch keys not available“). Bereits gelesene oder gespeicherte Mails können bei ihm bleiben; `revoke` löscht keine Mails („Zugriff entziehen“ und „Daten löschen“ werden nie zusammengefasst, 2.5). Erst wenn die neue Epoche im Log steht, ist der Entzug wirksam.
- Prüfen mit `inspect` (4.9): Der Kopf einer Mail-Datei `mailboxes/<postfach-id>/mail/<ordner>/<mail-id>.gml`, die nach dem Entzug eingeht, nennt unter `header.epoch` die neue Epoche. Ihr `epochs/<n>/epoch.rec` hat `reason` 3 (Mitglied entfernt), `begin` zur Zeit des Entzugs und unter `members` den Benutzer nicht mehr. Ins Log trägt sie der Client, der `revoke` ausführt, selbst ein; sein nächster Befehl gelingt erst, wenn ein von den Zeugen bestätigter Kopf sie deckt (3.4).

### 4.8 Synchronisieren

```
gomailctl sync $C
```

`sync` prüft die Epochenketten, hält den Vorrat für drei Monate, verpackt nach einem Geräteverlust eines Mitglieds die Epochen für dessen neue Generation neu, setzt unterbrochene Neuausstellungen fort und indexiert. Hat der Server wegen eines leeren Vorrats die letzte Epoche über ihren Monat hinaus verwendet (Vermerk `epoch-fallback.rec`), erzeugt `sync` eine Epoche mit sofortigem Beginn. Jedes Mitglied sollte `sync` regelmäßig ausführen.

### 4.9 Dateien ansehen

```
gomailctl inspect <datei>
```

`inspect` zeigt Datensätze und die lesbaren Teile von `.gml`-Dateien als JSON, ohne etwas zu entschlüsseln; es braucht weder Server noch Pin.

### 4.10 Exit-Codes von `gomailctl`

| Code | Bedeutung |
|---|---|
| 0 | Erfolg |
| 1 | Fehler (auch Testsperre, Log, Prüfung, unbekannter Flag-Name) |
| 2 | Aufruffehler: unbekannter Befehl oder Schalter, falsche Zahl von Argumenten, ungültige ID, Epoche, Aufteilung oder ungültiger Monat |
| 3 | teilweiser Erfolg (`share`, `device lost`, auch `sync`): was erledigt ist, steht in der Ausgabe, die Meldung nennt die Abhilfe (meist: denselben Befehl später wiederholen) |
| 130 | Abbruch durch ein Signal, während Seed, Anteil oder getippte Wörter auf dem Bildschirm stehen konnten; der Bildschirm ist gelöscht |

## 5. Geräteverlust und Wiederherstellung

Seed- und Anteilswörter werden von einem Terminal ohne Anzeige gelesen und danach vom Bildschirm gelöscht; ist die Standardeingabe ein Terminal, muss die Standardausgabe dasselbe Terminal sein. Aus einer Datei oder Pipe werden sie ohne Rückfrage gelesen. Wörter nie in eine Datei schreiben.

### 5.1 Gerät verloren

Auf einem verbliebenen oder neu eingerichteten Gerät des Benutzers (mit Schlüsselspeicher und Passphrase):

```
gomailctl device lost $C
```

- Der Client fragt Passphrase und die 24 Seed-Wörter ab, leitet die nächste Generation ab, signiert `user.rec` neu (die bisherige Generation ist widerrufen) und trägt sie ins Log ein. Ausgabe: `Neue Generation <g>; die vorherige ist widerrufen.`
- **Jeder Aufruf erzeugt eine neue Generation** (D88 (7)). Postfächer, deren Neuausstellung ein früherer Aufruf nicht beendet hat, setzt er nebenbei fort.
- Eigene Dateien außerhalb des Logs (Verpackungen, `folders.gml`, Vermerke) stellt er mit der neuen Generation neu aus. Die anderen Mitglieder verpacken die gemeinsamen Postfächer beim nächsten `sync` für die neue Generation; bis dahin liest der Benutzer dort nur, was er selbst neu ausstellen konnte.
- Exit 3: nicht alle Postfächer sind fertig; die Meldung nennt sie. Später `device lost` oder `sync` wiederholen. Ein alleiniges Mitglied ohne geprüfte Ordnerliste bleibt dabei hängen (Abschnitt 8.4, Q18).

### 5.2 Wiederherstellen aus den Seed-Wörtern

Auf einem Gerät ohne Client-Zustand (leeres oder neues `--dir`):

```
gomailctl restore $C
```

Der Client fragt eine neue Passphrase (zweimal) und die 24 Wörter ab und richtet den Benutzer des Seeds auf diesem Gerät ein. Ausgabe: `Benutzer <id> auf diesem Gerät wiederhergestellt.` Ein so eingerichteter Client vertraut beim ersten Kontakt und warnt bei jedem Befehl „Noch kein bestätigter Zustand“, bis der Vermerk eines **anderen** Benutzer-Mitglieds mit seinem Kopf übereinstimmt; ein alleiniges Mitglied bleibt markiert (Q20, R22). Er übernimmt jedes Postfach, dessen Kopf den Benutzer nennt (R20).

`restore` erzeugt keine neue Generation. War das alte Gerät verloren, danach `device lost` ausführen (5.1).

### 5.3 Wiederherstellen aus Anteilen

```
gomailctl restore --shares <k> $C
```

Wie 5.2, aber mit `<k>` Anteilen aus `keygen --shares` (3.3), je 30 Wörter, einer nach dem anderen; nach jedem Anteil wird der Bildschirm gelöscht. Die Inhaber geben ihren Anteil selbst ein.

## 6. Ingest-Rotation

Ein neuer Ingest-Schlüssel (und damit ein neuer Log-Schlüssel, Q4) braucht drei Anteilsinhaber auf dem Zeremonierechner. Den Umschaltzeitpunkt `<valid-from>` so wählen, dass Veröffentlichen und Zeugen vorher erledigt sind; die Uhr des Zeremonierechners vorher stellen (Abschnitt 10).

1. **Zeremonie offline:**

   ```
   gomail-ceremony ingest-rotate --pin <pin> --gen <n> --out <export-n> --keys <schlüssel> --valid-from <RFC3339>
   ```

   `<n>` ist die höchste vorhandene Ingest-Generation + 1 (aus `platform/ingest-*.cert`). `--valid-from` darf nach der Uhr des Zeremonierechners nicht in der Vergangenheit liegen. Drei Inhaber geben ihren Anteil ein; der Root muss genau die Identität des Pins ergeben. Ergebnis: `<export-n>` mit `ingest-<n>.pub`/`.cert` und `<schlüssel>/ingest-<n>.key` (0600).
2. **Veröffentlichen vor dem Umschalten** (Server kurz anhalten): `gomail-ceremony publish --from <export-n> --data <datenverzeichnis> --pin <pin>`, dann den Server mit dem bisherigen Schlüssel wieder starten.
3. **Zeugen:** Prüfschlüssel der neuen Generation nach 1.7 aus `platform/ingest-<n>.pub` bilden und jeden Zeugen mit beiden Log-Schlüsseln neu starten (`--log-key <alt> --log-key <neu>`, gleiches Zustandsverzeichnis).
4. **Umschalten ab `<valid-from>`:** Ab diesem Zeitpunkt signiert die alte Generation nichts mehr gültig. Ein laufender Server mit dem alten Schlüssel lehnt Einlieferungen mit `451` ab; ein Neustart mit dem alten Schlüssel verweigert (`ingest: the ingest generation is superseded in the log`). Den Server **nach** `<valid-from>` mit `--ingest-key <ingest-<n>.key>` neu starten, nicht vorher (eine Mail mit Empfangszeit vor `valid_from` des neuen Zertifikats lehnen die Clients ab). Absender wiederholen nach `451`.
5. **Alten Schlüssel vernichten**, sobald der Server mit dem neuen läuft.

Clients beenden die alte Generation bei `valid_from` des neuen Zertifikats, sobald es im Log steht: Metadaten, die der alte Schlüssel für eine Empfangszeit ab `valid_from` signiert hat, lehnen sie ab (`WARNUNG: Mail <id> wird nicht verarbeitet: Plattformzertifikat oder Annahmeschlüssel nicht gültig.`); ältere Mails bleiben lesbar. Einen Widerruf einer kompromittierten Ingest- oder Admin-Generation und eine Admin-Rotation gibt es nicht (Q8, R18).

## 7. Nachfolge der Plattformidentität

### 7.1 Regulärer Wechsel

1. **Zeremonie offline** (drei Inhaber, Uhr gestellt; `succeed` zeigt die Uhr, sie gibt `valid_from` der Nachfolge):

   ```
   gomail-ceremony succeed --pin <identity-g.pin> --out <export-g+1>
   ```

   Origin, Zeugen und Quorum kommen aus dem Pin; `--origin` ist nur eine Kontrolle (der Origin ändert sich nie). Ergebnis: `<export-g+1>` mit `identity-<g+1>.succ` (signiert von Generation g) und der neue Pin `identity-<g+1>.pin`.
2. **Neuen Pin verteilen** an Server-Host und Clients (Client-Update, getrennter Weg). Clients mit dem alten Pin übernehmen die Nachfolge aus dem Log, sobald ein bestätigter Kopf sie deckt; der neue Pin ist trotzdem zu verteilen.
3. **Veröffentlichen** bei angehaltenem Server, mit dem **neuen** Pin: `gomail-ceremony publish --from <export-g+1> --data <datenverzeichnis> --pin <identity-g+1.pin>`. Neben einem laufenden Server oder mit dem alten Pin verweigert `publish`.
4. **Server mit dem neuen Pin starten** (`--pin <identity-g+1.pin>`). Mit dem alten Pin verweigert er den Start, weil `platform/` eine Generation nennt, die der Pin nicht kennt. Ingest- und Admin-Schlüssel bleiben gültig.
5. Zeugen weiterlaufen lassen (der Log-Schlüssel ändert sich nicht).

### 7.2 Zeugen wechseln

Zeugen und Quorum ändern sich nur ausdrücklich bei einer Nachfolge:

```
gomail-ceremony succeed --pin <identity-g.pin> --out <export-g+1> --witness <zeuge>=<verifier-zeile> [--witness ...] --min-witnesses <k>
gomail-ceremony publish --from <export-g+1> --data <datenverzeichnis> --pin <identity-g+1.pin> --replace-witnesses
```

Ohne `--replace-witnesses` verweigert `publish`, wenn `platform/witnesses.rec` vom Pin abweicht. Mit dem Schalter ersetzt es die Datei durch Zeugen und Quorum des Pins und nennt altes und neues Quorum. Der Pin ist nicht signiert: die Zeugen, denen der Server danach traut, hängen allein an seiner Echtheit. Die neuen Zeugen starten mit eigenem Zustandsverzeichnis; der Server startet danach ohne Warnung zu `witnesses.rec`.

### 7.3 Kompromittierte Identität

`gomail-ceremony succeed --compromised` ist **gesperrt** (Aufruffehler, Exit 2: „noch nicht verfügbar: Widerruf einer Plattformgeneration ist nicht festgelegt (Q19)“). **Bekannte Grenze:** Weder Pin noch Nachfolge noch Log können eine Identitätsgeneration als kompromittiert kennzeichnen; wer den Schlüssel einer kompromittierten Generation hat, könnte weiter Ingest- und Admin-Zertifikate ausstellen, die `publish`, Log und Clients annehmen. Ein Befehl dafür ist ohne neuen signierten Datensatz und neue Prüfregeln in Client und Log nicht zu bauen (Q19, R17).

**Betriebsregel bis zur Entscheidung von Q19:** Bei Verdacht auf Kompromittierung der Plattformidentität oder des Roots keine Nachfolge, sondern eine neue Plattform: neue Zeremonie (`init`) mit **neuem Origin**, neues Datenverzeichnis, neue Pins für alle Clients, Benutzer registrieren sich neu. Den alten Server anhalten und den alten Pin bei allen Clients entfernen.

### 7.4 Anteile neu verteilen

```
gomail-ceremony reshare --pin <pin> --shares <k-of-n>
```

Drei Inhaber stellen den Root her, die neuen Anteile werden einzeln gezeigt und geprüft. Die alten Anteile bleiben gültig und lassen sich nicht widerrufen: ihre Inhaber vernichten sie.

## 8. Störungen

### 8.1 Inkonsistentes Log

Erkennt der Server, dass `log/tree.rec` zurückgesetzt oder beschädigt wurde, gilt:

- **Beim Start** (ein Eintrag `log/entries/<n+1>.rec` jenseits des nächsten Index oder ein veröffentlichter Kopf jenseits der Größe von `tree.rec`) verweigert er den Start mit `translog: log is inconsistent`.
- **Läuft er bereits**, gilt zusätzlich: ein `tree.rec`, das kleiner ist als der größte Baum, den dieser Prozess angenommen hat, gleich groß mit anderer Wurzel oder ihn nicht fortsetzend. Dann lehnt er jede Einlieferung mit `451 4.3.0` ab und signiert keine Köpfe mehr (das Server-Log nennt `signing refused`), liefert aber den zuletzt veröffentlichten Kopf weiter an die Zeugen aus. Das bleibt so, bis der Server beendet, `log repair` ausgeführt und der Server neu gestartet ist; ein laufender Server übernimmt einen reparierten Baum nie. Einen solchen Rückschritt erkennt nur der laufende Prozess; ein neu gestarteter kennt die größere Größe nicht mehr und prüft nur die Fälle beim Start.

### 8.2 `log repair`

```
gomail-server log repair --data <datenverzeichnis> --pin <pin>
```

*Wann:* wenn der Server wegen eines inkonsistenten Logs nicht startet oder mit 451 ablehnt, und nur bei beendetem Server (der Befehl hält die Serversperre `locks/server` und scheitert neben einem laufenden Server mit „Server-Sperre“).

*Was es tut:* Es baut `log/tree.rec`, die Kacheln und `log/keys/` aus den Einträgen und den signierten Köpfen neu. Die neue Größe m ist die Zahl der Einträge, die ab `entries/0.rec` lückenlos vorhanden und lesbar sind; jeder Kopf in `log/heads/` muss eine gültige Log-Signatur tragen, höchstens m groß sein und zum neu berechneten Baum passen. Es löscht nichts. Liegen Einträge jenseits von m (verwaiste Einträge `log/entries/<i>.rec` mit i ≥ m), meldet es deren Zahl und Bereich, schreibt nichts und endet mit Exit 1; der Betreiber prüft und entfernt sie bewusst und führt `log repair` erneut aus. Bei Erfolg meldet es `0 verwaiste Einträge gemeldet, 0 verworfen`. Danach den Server neu starten.

*Was es nicht heilt:* einen fehlenden oder geänderten Eintrag unterhalb eines signierten Kopfes (nur ein Backup von `log/`, das jeden je an einen Zeugen gegebenen Kandidaten umfasst, stellt die Bytes wieder her; sonst bleibt nur eine neue Plattform mit neuem Origin); ein `tree.rec`, das mehr Einträge nennt als vorhanden sind; eine Datei in `log/heads/`, die kein Kopf dieses Logs ist (der Betreiber entfernt sie und repariert erneut). Einen Rückschritt, bei dem auch `entries/<n+1>.rec` entfernt wurde und den kein veröffentlichter Kopf deckt (die Einträge seit dem letzten veröffentlichten Kopf), erkennt ein neu gestarteter Server gar nicht (R12).

### 8.3 Clients, deren Einträge verloren gingen

Gingen bei einem Rückschritt oder einer Wiederherstellung von `log/` aus einem Backup Einträge verloren, die noch kein veröffentlichter Kopf deckte, bemerken das nur die Clients, die sie geschrieben haben: über ihre offenen Einträge in `state.json`. Findet ein Client seinen Eintrag ersetzt oder nicht mehr vor (`log is inconsistent`), hängt er ihn beim nächsten Befehl selbst erneut an; bis ein neuer bestätigter Kopf ihn deckt, scheitern seine Befehle wie in 3.4 und werden wiederholt (am einfachsten `gomailctl sync`). Meldet er, dass ein anderer Eintrag den Schlüssel belegt (`ErrDuplicate`), bleibt er gestoppt: der Betreiber prüft das Log. Wer nie etwas in den verlorenen Bereich geschrieben hat, merkt nichts. Ein Server, der einen eigenen Eintrag länger als `HeadInterval` nicht deckt, obwohl er neuere Köpfe signiert, hält ihn zurück: der Client stoppt dann mit `own log entry withheld`.

### 8.4 Alleiniges Mitglied ohne geprüfte Ordnerliste (Q18)

Nach `device lost` oder `restore` kann ein Postfach hängen bleiben, dessen einziges Benutzer-Mitglied keinen Prüfvermerk für `folders.gml` hat und dessen Ordnerliste von der widerrufenen Generation signiert ist. Der Client warnt („keine geprüfte Ordnerliste der Epoche … derzeit keine Abhilfe, siehe Q18“), `sync` und `device lost` enden mit Exit 3; `list` scheitert, `read` einzelner Mails geht. **Bekannte Grenze:** Bis Q18 entschieden ist, gibt es keinen Ausweg im Client; ein Befehl dafür bräuchte eine neue Prüfregel des Clients (Übernahme einer ungeprüften Ordnerliste). Vorbeugen: Postfächer, auf die es ankommt, mit mindestens zwei Benutzer-Mitgliedern führen; das andere Mitglied legt die Epoche dann an.

### 8.5 Prozesse beenden

Server, Zeuge und Clients enden mit SIGINT oder SIGTERM. Für Skripte, die Programme im Vordergrund starten (`scripts/two-host-test.sh`): Das Signal an die **Prozessgruppe** schicken (`kill -TERM -- -<pgid>`, oder Strg-C im Terminal, das die Vordergrundgruppe trifft). Ein Signal nur an die PID der Shell wirkt erst, wenn der laufende Vordergrundbefehl endet. Eine Zeremonie nie mit SIGKILL beenden (Abschnitt 2).

### 8.6 Fehlerbilder

| Meldung | Ursache, Abhilfe |
|---|---|
| `Testsperre (9.1): keine wirksame Sperre eines laufenden gomail-server` | Client ohne laufenden Server oder Sperren wirken nicht (kein NFSv4) |
| `Testsperre: --require-client-lock verlangt eine wirksame Client-Sperre` | Server mit `--require-client-lock` ohne laufenden Client |
| `ein anderer Server hält die Serversperre locks/server` | zweiter Server auf demselben Datenverzeichnis |
| `--pin und --log-listen sind erforderlich` | Server ohne Transparenzlog gestartet |
| `--listen und --log-listen müssen Loopback-Adressen sein` | öffentliche Adresse ohne `--isolated-test-network` |
| `kennt nur 1 bis <g>` beim Serverstart | Pin älter als `platform/` (nach einer Nachfolge den neuen Pin nehmen) |
| `ingest: the ingest generation is superseded in the log` | alter Ingest-Schlüssel nach `valid_from` der neuen Generation (Abschnitt 6) |
| `translog: log is inconsistent` | Abschnitt 8.1 und 8.2 |
| `not yet covered by a verified head` | eigener Logeintrag noch ohne bestätigten Kopf; nach etwa einer Minute wiederholen (3.4) |
| `translog: no fresh verified tree head` | seit 24 Stunden kein bestätigter Kopf: Server, Zeuge oder Uhr prüfen (Abschnitt 10) |
| `Anteile erscheinen und werden eingegeben nur auf einem Terminal` | Zeremonie mit Umleitung oder Pipe gestartet |
| `client: the seed words were not confirmed` | Wort bei `keygen` nicht exakt eingegeben; `keygen` neu starten |
| `store: unknown or used invitation code` | Code falsch oder schon verwendet |
| `keys: key store authentication failed (wrong passphrase or damaged file)` | falsche Passphrase |
| `WARNUNG: Mail <id> wird nicht verarbeitet: …` | eine Prüfung aus 4.4 ist fehlgeschlagen; die Mail wird nicht angezeigt |
| `452 4.3.1` beim Einliefern | weniger als 10 % freier Platz im Datenverzeichnis |
| `451` beim Einliefern | inkonsistentes Log (8.1), abgelöste Ingest-Generation (6), Logfehler einer Epoche oder unbekannter freier Platz |

## 9. Zwei Maschinen

Der Test nach 9.1 (Abnahme, 10.2) läuft mit `scripts/two-host-test.sh`.

### 9.1 Voraussetzungen

- Zwei Maschinen: der Server-Host exportiert ein Verzeichnis über **NFSv4**, der Client-Host hat es eingehängt, mit Sperrunterstützung: `vers=4.x` und `local_lock=none`; nie `nolock`, `local_lock=posix` oder `local_lock=all`, nie SSHFS (D83). Das Skript prüft die Optionen in `/proc/mounts` des Client-Hosts; Leerzeichen und andere Sonderzeichen im Mountpfad (dort als `\040` usw. geschrieben) sind erlaubt.
- Zwei verschiedene Betriebssystembenutzer (Name und uid verschieden), einer je Host, beide in der Gruppe `gomail` mit **derselben gid** auf beiden Seiten (sec=sys). Empfohlene `umask` 0007; die Programme setzen 0660/2770 ohnehin selbst (D70).
- SSH mit Schlüssel ohne Rückfrage (`BatchMode`) zu beiden Benutzern, Login-Shell kompatibel zu `sh`. Das Skript läuft auf einer dritten Maschine oder auf einem der beiden Hosts.
- Programme auf beiden Hosts im `PATH` oder unter `--bin` (gleicher Pfad auf beiden Hosts): auf dem Server-Host `gomail-server`, `gomail-ceremony`, `gomail-witness`, `curl` mit SMTP, `base64`, `sha256sum` oder `shasum`; auf dem Client-Host `gomailctl` und `gomail-server` (für die Gegenprobe „zweiter Server“).
- **Testbuild:** Die Programme unter `--bin` müssen mit `go build -tags gomail_dev,gomail_test -o <bin>/ ./cmd/...` gebaut sein. Das Skript nutzt die Entwicklungszeremonie (`init --dev`, Tag `gomail_dev`) und die Schalter des Tags `gomail_test`: `GOMAILCTL_TEST_KEYGEN_PIPE=1` (keygen über eine FIFO), `GOMAIL_TEST_DEV_IDENTITY=1` (Entwicklungs-Pin im Client), `GOMAIL_TEST_HEAD_GAP=1s` (Köpfe binnen Sekunden). Ein Produktionsbuild hat keinen dieser Schalter; den Produktionsweg zeigen `TestInitProduction` und `TestRunbook`.

### 9.2 Aufrufe

```
scripts/two-host-test.sh --server-host <ssh-ziel> --client-host <ssh-ziel> --export <dir> --mount <dir> \
    [--pin <datei>] [--witness <datei>] [--bin <dir>] [--workdir <dir>] [--out <dir>] [--group gomail] [--keep]
scripts/two-host-test.sh --local [--bin <dir>] [--workdir <dir>] [--out <dir>] [--keep]
```

Ablauf: a) Voraussetzungen, Mount, Export und Mount zeigen dasselbe Verzeichnis; b) Datenverzeichnis auf dem Server-Host, Rechte; c) Testsperre in beide Richtungen (Client ohne Server verweigert, `serve --require-client-lock` ohne Client verweigert, ein zweiter Server auf dem Client-Host verweigert, Server mit `--require-client-lock` neben einem Client startet); d) Zeuge, `keygen`, Einladung, Registrierung, Postfach, Adresse, Mail per SMTP, `sync`/`list`/`read` auf dem Client-Host, ein zweiter Benutzer, der das Postfach erst nach `mailbox share` liest, ein Log-Kopf mit Zeugensignatur; e) Nachweis im Export (keine privaten Schlüssel, kein Klartext, Rechte); f) Protokoll.

- **Eigenes Verzeichnis:** Das Skript legt auf jedem Host unter `--workdir` (Standard `/tmp`, lokal `$TMPDIR` oder `/tmp`) genau ein eigenes Verzeichnis `two-host.XXXXXX` an und arbeitet nur darin. Was sonst unter `--workdir` liegt, bleibt unberührt. Fehlt `--workdir`, legt das Skript es an (nur die letzte Stufe) und entfernt es am Ende wieder, wenn es leer ist.
- **`--pin` und `--witness` sind Ablageorte, die noch nicht existieren dürfen**; ihr Verzeichnis muss existieren. Eine vorhandene Datei ist ein Aufruffehler (Exit 2). Das Skript schreibt beide mit 0600 und löscht am Ende nur, was es selbst geschrieben hat.
- Das Datenverzeichnis entsteht neu unter `<export>/gomail-<lauf>`. Am Ende löscht das Skript Datenverzeichnis, eigene Verzeichnisse, selbst geschriebene Dateien und ein selbst angelegtes `--workdir`; mit `--keep` bleibt das alles stehen, **nur die Passphrase-Datei nicht** (sie wird immer gelöscht). Im Zwei-Maschinen-Modus müssen `--export` und `--mount` existieren. Im lokalen Modus legt das Skript sie bei Bedarf an (`--export` nur die letzte Stufe, `--mount` als Link; ein fehlendes Elternverzeichnis ist ein Aufruffehler) und entfernt sie am Ende, außer mit `--keep`.
- **Zeugenkopf abwarten:** Der Lauf wartet auf einen Kopf mit Zeugensignatur, solange der Zeuge läuft, und bricht sonst mit `witness.log` im Protokoll ab. Jeder Client-Befehl, der einen Kopf über die neuesten Einträge braucht, wird bis zu einer Minute wiederholt. Ohne `GOMAIL_TEST_HEAD_GAP` (Produktionsbuild) signiert der Server während des Wachstums höchstens einen Kopf je Minute; dann dauern diese Schritte entsprechend länger.
- **Gegenprobe „zweiter Server“ ohne Kopie des Ingest-Schlüssels:** Ein zweiter `serve` bräuchte den Ingest-Schlüssel, der den Server-Host nicht verlässt (9.1). Deshalb versucht auf dem Client-Host `gomail-server log repair --data <mount>/gomail-<lauf> --pin <pin>`, die Serversperre zu nehmen, dieselbe Sperre, die `serve` hält. Erwartet wird die Verweigerung „Server-Sperre: store: in use by another process“. Wirkt die Sperre über NFS nicht, nähme `log repair` sie und baute `tree.rec` des Testdatenverzeichnisses neu; der Lauf bricht dann ab.
- **Keine Geheimnisse auf der Platte:** Die Seed-Wörter liest das Skript über eine FIFO in den Speicher der Shell; `list` und `read` prüft es in einer Pipe (`awk`). Betreff, Text und Passphrase stehen in keiner Kommandozeile (`/proc/*/cmdline`), nur in der Umgebung und auf der Standardeingabe der entfernten Shell; die Adressen stehen als Argumente in `curl` und `address add`. Das Skript schaltet `xtrace` und `verbose` aus und ruft `curl -q` auf (keine `.curlrc`).
- **Umgebung:** Das Skript liest nur `PATH`, `TMPDIR`, `GOMAIL_TEST_MIN_FREE` und was `ssh` braucht. Prüfbar mit `env -i PATH="$PATH" sh scripts/two-host-test.sh …`.
- Das Protokoll steht in `<out>/protokoll.md` (darf noch nicht existieren): jeder Befehl mit Ausgabe, nur IDs und Pfade.
- **Exit-Codes:** 0 bestanden; 1 abgebrochen (der Schritt steht im Protokoll), auch ein fehlendes `--export` im Zwei-Maschinen-Modus; 2 Aufruffehler, auch solche, die das Skript erst auf einem Host erkennt; 130 Abbruch durch ein Signal (SIGINT, SIGTERM, SIGHUP). Abbrechen mit einem Signal an die Prozessgruppe (8.5). In jedem Fall beendet das Skript alle Prozesse, die es gestartet hat, und räumt auf.

Ohne `--bin` baut das Skript im lokalen Modus die Programme selbst mit den Testbuild-Tags; bei weniger als 10 % freiem Platz `GOMAIL_TEST_MIN_FREE=0.000001` setzen (wirkt nur im Testbuild). `go test -tags gomail_dev,gomail_test -run TestTwoHostScript ./internal/e2e` führt den lokalen Modus und den Zwei-Maschinen-Modus über einen `ssh`-Ersatz aus. **Der lokale Modus ist kein Nachweis nach 9.1:** ein Benutzer, ein Kernel, ein lokales Dateisystem, der „Mount“ ist ein symbolischer Link. Die Durchsetzung der Sperren durch NFSv4 zwischen zwei Maschinen und die Trennung der Benutzer zeigt nur der Lauf auf zwei Maschinen (R36).

## 10. Zeitquellen

| Uhr | wofür | Regel |
|---|---|---|
| Zeremonierechner (offline, ohne NTP) | `valid_from` der Zertifikate (`init`), der Nachfolge (`succeed`); Prüfung „nicht in der Vergangenheit“ von `ingest-rotate --valid-from` | vor jeder Zeremonie von Hand nach einer verlässlichen Quelle auf UTC stellen; `init` und `succeed` zeigen sie vor dem ersten Schritt, bei falscher Uhr mit Strg-C abbrechen |
| Server-Host | Empfangszeit jeder Mail, Zeit der Log-Köpfe, Umschalten der Ingest-Generation | NTP Pflicht |
| Client-Rechner | Prüfung der Kopfzeiten, Zeit offener Logeinträge, Beginn neuer Epochen | NTP Pflicht |
| Zeugenhost | Prüfung der Kopfzeiten | NTP Pflicht |

- **Abweichungen:** Köpfe mehr als fünf Minuten in der Zukunft lehnen Zeuge und Client ab. Weicht die Uhr des Servers mehr als fünf Minuten ab, können Mails abgelehnt werden (2.4 Regel 4: Verlust, kein Leck). Eine falsche Uhr des Zeremonierechners verschiebt den Umschaltzeitpunkt der Ingest-Generation.
- **24-Stunden-Regel (2.3):** Ist der neueste von den Zeugen bestätigte Kopf älter als 24 Stunden, verarbeitet der Client nichts, bis er einen aktuellen geprüft hat (`no fresh verified tree head`). Hat er einen eigenen, noch nicht gedeckten Logeintrag, gilt die Grenze schon nach 23 Stunden. Ein Ausfall von Server oder Zeugen stoppt also alle Clients nach spätestens einem Tag; der Server signiert spätestens jede Stunde einen Kopf (`--head-interval`).
- Die Uhren werden von den Programmen nicht geprüft; NTP ist Betreiberpflicht (R14).

## Abgleich mit TestRunbook

`TestRunbook` (`internal/e2e/runbook_test.go`) läuft mit Programmen, die nur mit dem Tag `gomail_test` gebaut sind (keine Entwicklungszeremonie); genutzt werden davon nur `GOMAIL_TEST_MIN_FREE`, `GOMAIL_TEST_HEAD_GAP` und `GOMAILCTL_TEST_KEYGEN_PIPE`. Er läuft auch in einem Testlauf ohne Tags.

| Abschnitt | Schritt in `TestRunbook` |
|---|---|
| 0.2 | `init --dev` im Produktionsbuild ist ein Aufruffehler |
| 1.1 | `gomail-witness keygen`, Schlüsseldatei 0600 |
| 1.2 | Zeremonie ohne Terminal verweigert, nichts geschrieben; `init` 3-of-5 mit Probe-Rekonstruktion über die Testseams (drei verschiedene der fünf Anteile abgefragt) |
| 1.3 | kein privater Schlüssel im Export; am Ende keiner im Datenverzeichnis; weder dort noch in den Server-Logs Betreff, Text, Geheimwort oder Absender einer Mail, in den Server-Logs auch keine Empfängeradresse |
| 1.4 | `gomail-server init` mit `--witnesses`; Server vor `publish` verweigert |
| 1.5 | `gomail-ceremony publish` |
| 1.6 | `--require-client-lock` ohne Client verweigert; Server startet; zweiter Server verweigert. Jeder Aufruf, der eine Verweigerung erwartet, hat eine Frist von 30 s; danach wird der Prozess beendet und der Schritt gemeldet |
| 1.7 | Prüfschlüssel mit den Shell-Zeilen aus 1.7 gebildet; Zeuge |
| 3.1–3.4 | drei Benutzer: Einladung, `keygen` (Pipe des Testbuilds; ohne Schalter verweigert), Registrierung, verbrauchter Code |
| 4.1–4.6, 4.9 | Postfach, Adresse, Mail, unbekannte Adresse 550, `list` ohne Absender, `read`, `--folder`, `search`, `flag`, `inspect` |
| 4.7 | `share --from 1` (bob), `share` ab neuer Epoche (carol), `revoke`: carol liest danach nicht; mit `inspect` eine neue Epoche mit `reason` 3, Beginn während des Entzugs, ohne carol, im Log und von einem Kopf gedeckt; die Mail nach dem Entzug liegt in ihr |
| 4.8, 4.10 | `sync`; Exit 2 und Exit 1 |
| 5.1 | `device lost` (bob), `sync` von alice, bob liest wieder |
| 5.2, 5.3 | `restore` aus Wörtern (bob) und aus 2 von 3 Anteilen (alice; die Anteile bildet der Test aus dem Seed wie `keygen --shares`, das nur am Terminal läuft) |
| 6 | `ingest-rotate`, Mails eines Servers mit altem Schlüssel vor und nach `valid_from`, `publish`, alter Schlüssel verweigert, Server und Zeuge mit beiden Log-Schlüsseln; `gomailctl` zeigt die Mail vor und lehnt die nach `valid_from` ab |
| 7.3 | `succeed --compromised` Exit 2 |
| 7.1 | `succeed`, `publish` neben dem Server verweigert, mit neuem Pin; Server mit altem Pin verweigert, mit neuem startet; Clients mit neuem und mit altem Pin |
| 8.2 | `log repair` neben dem Server verweigert, danach erfolgreich; Client ohne Server verweigert |

Nicht in `TestRunbook`: Exit 3 und 130 und die Terminalregeln (`cmd/gomailctl`, `cmd/gomail-ceremony`, Pseudoterminal-Tests), `--replace-witnesses` (`TestSuccessionEndToEnd`), Störungen 8.1 und 8.3 (`internal/translog`, `internal/client`), der Zwei-Maschinen-Test (`TestTwoHostScript`).
