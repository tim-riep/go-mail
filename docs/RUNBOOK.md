# Runbook: go-mail mit Transparenzlog betreiben

Dieses Dokument beschreibt den Betrieb des PoC mit den tatsächlichen Befehlen der Programme `gomail-ceremony`, `gomail-server`, `gomail-witness` und `gomailctl`: Erstinstallation mit Zeremonie, Zeuge und Server, Benutzer und Postfächer, Geräteverlust, Ingest-Rotation, Nachfolge der Plattformidentität, Widerruf kompromittierter Plattformschlüssel, Störungen, den Test auf zwei Maschinen und die Zeitquellen. Maßgeblich sind die Usage-Texte der Programme (Aufruf ohne Argumente); dieses Dokument folgt ihnen.

Der Test `TestRunbook` in `internal/e2e` geht die Hauptschritte der Abschnitte 1 bis 8 mit Programmen eines Produktionsbuilds durch und nennt in seiner Ausgabe (`go test -v`) zu jedem Schritt den Abschnitt (`RUNBOOK 4.7: ...`). Nicht jeder Schritt und nicht jede Verweigerung ist darin enthalten; die Zuordnung und die Liste dessen, was er nicht abdeckt, stehen am Ende („Abgleich mit TestRunbook“). Ohne jeden Test sind unter anderem der SSH-Tunnel zum Zeugen (1.7), Sicherung und Wiederherstellung (8.8) und das Vorgehen bei einem Fork des Zeugen (8.9).

**Schreibweise.** Platzhalter stehen in spitzen Klammern (`<datenverzeichnis>`, `<pin>`). Es gibt keine Beispielwerte für Seeds, Anteile, Passphrasen oder Einladungscodes; nie Werte aus einem Test oder einer Anleitung übernehmen.

**Grenzen des PoC.** Nicht mit echten Mails verwenden. Vor einem solchen Betrieb verlangt der Plan TLS, Ratenbegrenzung und Missbrauchsschutz beim Empfang, unabhängige Prüfungen (10.2), mindestens zwei von drei Zeugen und die Kopplung neuer Geräte (2.7). Der PoC hat einen Zeugen; offen ist unter anderem Q18 (Abschnitt 8.4). Q8 und Q19 sind entschieden (D93); den Ablauf bei kompromittierten oder verlorenen Plattformschlüsseln beschreibt 7.3.

## 0. Überblick

### 0.1 Rollen und Rechner

| Rechner | Programme | was dort liegt |
|---|---|---|
| Zeremonierechner (offline, Live-System, ohne Netzwerk) | `gomail-ceremony` (`init`, `ingest-rotate`, `admin-rotate`, `reshare`, `succeed`, `revoke`) | nur während der Zeremonie: Plattform-Root im Speicher; danach ausschalten |
| Server-Host | `gomail-server`, `gomail-ceremony publish` | Datenverzeichnis (Gruppe `gomail`, 2770/0660), Pin, Ingest-Schlüssel (0600, außerhalb des Datenverzeichnisses) |
| Zeugenhost (andere Maschine, anderer Betreiber oder zu Hause; erreicht das Log nur über einen Tunnel, 1.7) | `gomail-witness` | Zeugenschlüssel (0600), Zustandsverzeichnis (0700) |
| Administrator | `gomail-server address add` | Admin-Schlüssel (0600), getrennt vom Server |
| Client-Rechner je Benutzer | `gomailctl` | Schlüsselspeicher und Client-Zustand (0600/0700), Pin |

Im PoC arbeiten Client und Server auf demselben Datenverzeichnis; für die Abnahme ist es über NFSv4 eingehängt (Abschnitt 9).

### 0.2 Programme bauen

Go 1.26 (getestet mit 1.26.10); ist lokal eine ältere Version installiert, lädt `export GOTOOLCHAIN=go1.26.10` die richtige.

```
go build -o <bin>/ ./cmd/...
```

Das ist der **Produktionsbuild**: ohne Build-Tags. Er enthält weder die Entwicklungszeremonie (`gomail-ceremony init --dev`) noch einen Testschalter (`GOMAIL_TEST_MIN_FREE`, `GOMAIL_TEST_HEAD_GAP`, `GOMAIL_TEST_DEV_IDENTITY`, `GOMAILCTL_TEST_KEYGEN_PIPE`); ein Entwicklungs-Pin wird von `gomail-server init`, `serve`, `address add` und `log repair` mit Exit 2 abgelehnt, von `gomail-ceremony` mit Exit 1 (`invite create` liest keinen Pin). Die Tags `gomail_dev` und `gomail_test` sind nur für Tests (Abschnitt 9, `docs/AUDIT.md` R35). Ausgeliefert werden nur Produktionsbuilds.

**Eigene Werkzeuge:** Wer im Modul ein eigenes Programm auf `internal/client` baut, ruft die Methoden eines `client.Client` nie aus mehreren Goroutinen zugleich auf, `Close` eingeschlossen: das Paket ist nicht goroutinesicher (die Sperre im `Client` schützt nur das Merkmal `closed` und die Schlüssel-Caches (`ingest`, `epochKeys`), keine Methode als Ganzes; nach `Close` liefert jede Methode mit Fehlerergebnis `client.ErrClosed`).

### 0.3 Verzeichnisse

| Pfad | Inhalt | Regel |
|---|---|---|
| `<datenverzeichnis>` | Abschnitt 4 des Plans: verschlüsselte Dateien, öffentliche Schlüssel, signierte Datensätze, `log/` | keine privaten Schlüssel, kein Klartext |
| `<export>` | Ergebnis einer Zeremonie: `platform/` (öffentliche Schlüssel, Zertifikate, `witnesses.rec`, Nachfolgen) und `identity-<gen>.pin` | nur öffentliche Dateien |
| `<schlüssel>` | private Plattformschlüssel `admin-<gen>.key`, `ingest-<gen>.key` | 0600, außerhalb des Datenverzeichnisses und des Exports |
| `<client>` | Schlüsselspeicher, `user.rec`-Kopie, `state.json`, Audit-Index des Logs | ein Verzeichnis je Benutzer und Gerät, Standard `<UserConfigDir>/gomailctl` (unten); sein Elternverzeichnis nur für den eigenen Benutzer beschreibbar oder mit Sticky-Bit (Eigentümer der Benutzer oder `root`) (unten, D92) |

Pin, Ingest-Schlüssel und Admin-Schlüssel müssen außerhalb des Datenverzeichnisses liegen, auch über symbolische Links gesehen; sonst verweigern die Serverbefehle (Exit 2 für Pin und Admin-Schlüssel).

**Standard für `<client>`:** Ohne `--dir` nimmt `gomailctl` das Verzeichnis `gomailctl` im Konfigurationsverzeichnis des Benutzers (`os.UserConfigDir`, `cmd/gomailctl/main.go`): unter Linux und den BSDs `$XDG_CONFIG_HOME/gomailctl`, ist die Variable nicht gesetzt `~/.config/gomailctl`; unter macOS `~/Library/Application Support/gomailctl`. `<eltern>` ist dann entsprechend `$XDG_CONFIG_HOME`, `~/.config` oder `~/Library/Application Support`.

**Voraussetzung für `<client>` (D92):** Das Verzeichnis über dem Client-Verzeichnis (`<eltern>`, beim Standard das Konfigurationsverzeichnis von oben) darf nur der Benutzer selbst beschreiben können, oder es trägt das Sticky-Bit und gehört dem Benutzer selbst oder `root` wie `/tmp`. Ist `--dir` ein symbolischer Link, gilt das für das Verzeichnis, das den Link enthält, und für das Elternverzeichnis des Linkziels. Grund: Ein geöffneter Client schreibt nach dem Sperren über den Pfad in `<client>` und folgt dabei einem Link jedes Mal neu, etwa `state.json` nach jedem Befehl, die Kopien neuer Postfächer unter `new-mailboxes/`, den Audit-Index `log-index.json` und bei `device lost` `user.rec` und den Schlüsselspeicher. Wer `<eltern>` beschreiben kann, könnte `<client>` dazwischen gegen ein anderes Client-Verzeichnis tauschen und dessen Schlüsselspeicher überschreiben (AUDIT R46). `gomailctl` prüft das nicht (kein Test). Der Benutzer prüft es, bevor er `keygen` oder `restore` ausführt; die Voraussetzung gilt aber, solange ein Befehl das Client-Verzeichnis öffnet, besonders für `device lost` (5.1), das Schlüsselspeicher und `user.rec` neu schreibt:

```
stat -c '%U %a' <eltern>
```

Unter macOS und BSD heißt der Befehl `stat -f '%Su %Lp' <eltern>`; dort zeigt `%Lp` das Sticky-Bit nicht, also zusätzlich `ls -ld <eltern>` ansehen (`t` oder `T` an der letzten Stelle der Rechte ist das Sticky-Bit).

- In Ordnung ist die Ausgabe, wenn sie den eigenen Benutzer (oder `root`) nennt und weder Gruppe noch andere schreiben dürfen. Die letzten beiden Ziffern sind dann jeweils 0, 1, 4 oder 5, etwa `<benutzer> 700` oder `<benutzer> 755`.
- Ebenso in Ordnung ist eine vierstellige Zahl mit gesetztem Sticky-Bit (erste Ziffer 1, 3, 5 oder 7), wenn der Eigentümer der eigene Benutzer oder `root` ist, etwa `root 1777` bei `/tmp`. `<anderer> 1777` ist nicht in Ordnung: Der Eigentümer eines Verzeichnisses kann auch mit Sticky-Bit jeden Eintrag umbenennen und entfernen. In einem solchen Verzeichnis kann ein anderer Benutzer aber neue Namen anlegen. `ls -ld <client>` muss deshalb, falls es schon existiert, zeigen, dass `<client>` dem Benutzer gehört und kein symbolischer Link eines anderen ist, denn `keygen` und `restore` folgen einem Link als `--dir` (3.2).
- Nicht in Ordnung sind etwa `<benutzer> 775` mit einer Gruppe, der andere Benutzer angehören, oder `<anderer> 755`. Abhilfe: `chmod go-w <eltern>`, oder `<client>` an einen anderen Ort legen.
- `stat` zeigt keine Zugriffslisten. Ein `+` hinter den Rechten in `ls -ld <eltern>` zeigt, dass eine gesetzt ist; dann mit `getfacl <eltern>` prüfen, ob sie anderen Schreibrecht gibt.
- Dasselbe gilt für jede Stufe darüber, die ein anderer Benutzer umbenennen könnte. `namei -l <client>` zeigt Eigentümer und Rechte aller Stufen.

## 1. Erstinstallation

Reihenfolge: Zeugenschlüssel, Zeremonie, Verteilen, Datenverzeichnis, Veröffentlichen, Server, Zeuge. `TestInitProduction` und `TestRunbook` führen diese Folge mit Programmen ohne `gomail_dev` aus (die Zeremonie über die Testseams, ohne Terminal).

### 1.1 Zeugenschlüssel

Auf dem Zeugenhost, vor der Zeremonie, je Zeuge:

```
gomail-witness keygen --name <zeuge> --key <zeugenschlüssel>
```

Der Name ist druckbares ASCII ohne Leerzeichen, `+` und `=` und nicht `gomail-log` (der Name des Log-Schlüssels). Ein `=` verbietet `keygen` nicht, aber die Zeremonie trennt `--witness <zeuge>=<verifier-zeile>` am ersten `=`; ein solcher Name ist dort nicht verwendbar. Die Schlüsseldatei entsteht mit 0600 und wird nie ersetzt. Die ausgegebene Verifier-Zeile `<zeuge>+<hash>+<schlüssel>` ist öffentlich und geht zur Zeremonie. Quorum: `2·<k> > <n>` (bei einem Zeugen 1 von 1).

### 1.2 Zeremonie offline

Auf dem Zeremonierechner, ohne Netzwerk. **Vorher die Uhr stellen** (Abschnitt 10): der Rechner hat kein NTP, seine Uhr gibt `valid_from` aller Zertifikate.

```
gomail-ceremony init --shares 3-of-5 --out <export> --keys <schlüssel> --origin <origin> \
    --witness <zeuge>=<verifier-zeile> [--witness ...] --min-witnesses <k>
```

- Standardeingabe und Standardausgabe müssen ein Terminal sein (Abschnitt 2). `init` zeigt zuerst die Uhr des Rechners; geht sie falsch, mit Strg-C abbrechen, die Uhr stellen und neu beginnen.
- Das Programm erzeugt den Plattform-Root, leitet Identität, Admin- und Ingest-Schlüssel der Generation 1 ab und teilt den Root in fünf Anteile zu je 30 Wörtern. Jeder Inhaber wird einzeln an den Bildschirm gerufen, sein Anteil erscheint, nach seiner Bestätigung wird der Bildschirm gelöscht. Danach geben drei zufällig gewählte Inhaber ihren Anteil ohne Anzeige ein (Probe-Rekonstruktion); erst wenn sie gelingt, werden die Dateien geschrieben.
- Ergebnis: `<export>/platform/` (öffentliche Schlüssel, Zertifikate, `witnesses.rec`), `<export>/identity-1.pin` und in `<schlüssel>` die privaten Schlüssel `admin-1.key` und `ingest-1.key` (0600). Anteile stehen in keiner Datei.
- **`--out` und `--keys`:** `--out` muss fehlen oder ein leeres Verzeichnis sein (sonst `ceremony: unusable export directory: … is not empty`). `--keys` muss fehlen oder ein Verzeichnis mit Rechten 0700 sein, das dem ausführenden Benutzer gehört und kein symbolischer Link ist (sonst `ceremony: unusable key directory: …`, etwa `… has mode 0755, not 0700`); vorhandene Schlüsseldateien darin werden nie ersetzt. Beide sind getrennt, keins liegt im anderen. Geprüft wird das, bevor ein Anteil erscheint.
- **Schlüssel vom Live-System holen:** Da der Rechner ohne Netzwerk läuft, `--out` und `--keys` auf getrennte Wechselmedien legen, deren Dateisystem Unix-Rechte speichert (nicht FAT oder exFAT: dort zeigen Verzeichnisse 0755 oder 0777, und `--keys` wird verweigert), möglichst verschlüsselt. `--keys` dort vorher mit `mkdir -m 700 <schlüssel>` anlegen oder fehlen lassen.
- Danach den Rechner ausschalten (2.3 Schritt 5).

### 1.3 Pin und Schlüssel verteilen

- `<export>` (nur öffentliche Dateien) und `identity-1.pin` auf den Server-Host, außerhalb des künftigen Datenverzeichnisses.
- `ingest-1.key` auf den Server-Host (0600, außerhalb des Datenverzeichnisses); `admin-1.key` zum Administrator.
- `identity-1.pin` auf getrenntem Weg zu jedem Client (`gomailctl --pin`). Der Pin ist der Vertrauensanker: Identität, Origin des Logs, Zeugen und Quorum. Er ist nicht signiert; wer ihn austauscht, bestimmt, wem Server und Clients trauen.
- Die Zeugen behalten ihre privaten Schlüssel. Sie bekommen den Origin und, nach 1.5, den Prüfschlüssel des Logs (1.7).
- `gomail-server` prüft die Rechte der Schlüsseldateien nicht (`ceremony.ReadKey`): `ingest-1.key` und `admin-1.key` mit `chmod 600`, Eigentümer der Benutzer, der sie verwendet.
- Nach dem Verteilen und nach der Sicherung (8.8) die Schlüsseldateien auf dem Transportmedium sicher löschen; der Server-Host bekommt nur `ingest-<g>.key`, der Administrator nur `admin-<g>.key`.

Im Datenverzeichnis liegt danach und zu jeder Zeit kein privater Schlüssel.

### 1.4 Datenverzeichnis anlegen

Auf dem Server-Host, als Benutzer der Gruppe `gomail`.

**Voraussetzungen (Benutzer und Gruppe):** Server und Clients laufen unter verschiedenen Betriebssystembenutzern, die beide der Gruppe `gomail` angehören (9.1 des Plans, D70). Gruppe und Datenverzeichnis vorher anlegen, etwa:

```
getent group gomail || sudo groupadd gomail
sudo usermod -aG gomail <server-benutzer>     # danach neu anmelden; `id -nG` muss gomail zeigen
sudo install -d -o <server-benutzer> -g gomail -m 2770 <datenverzeichnis>
```

Jeder Client-Benutzer (Abschnitt 3) ist ebenfalls in `gomail` und erreicht das Datenverzeichnis; ebenso der Administrator, wenn er `address add` (4.2) auf seinem Rechner gegen das Datenverzeichnis ausführt.

```
gomail-server init --data <datenverzeichnis> --pin <pin> [--witnesses <export>/platform/witnesses.rec]
```

`init` legt ein leeres Datenverzeichnis nach Abschnitt 4 an (`platform/`, `users/`, `invites/`, `mailboxes/`, `spool/`, `work/`, `locks/`, leeres `log/`; Rechte 2770) und schreibt nur `platform/witnesses.rec` (0660): ohne `--witnesses` aus dem Pin, mit `--witnesses` die Bytes der Datei, die genau Zeugen und Quorum des Pins enthalten muss (die Ausgabe nennt die Quelle). Die Gruppe wählt der Betreiber: ein leeres Verzeichnis mit der Gruppe `gomail` vorher anlegen (oben) oder ein Elternverzeichnis mit setgid und Gruppe `gomail`. Heißt die Gruppe anders, warnt `init` nur („WARNUNG: Gruppe des Datenverzeichnisses ist …“) und endet trotzdem mit Exit 0; die Clients scheitern dann an den Rechten. In diesem Fall das eben angelegte Datenverzeichnis (nur `platform/witnesses.rec` und leere Verzeichnisse) entfernen und mit der Gruppe `gomail` neu anlegen.

`init` verweigert: ein vorhandenes, nicht leeres Verzeichnis (Exit 2); ein fehlendes Elternverzeichnis (nur die letzte Stufe wird angelegt); `--data` als symbolischen Link und ein Elternverzeichnis, dessen letzte Stufe ein Link ist (den Pfad ohne Link angeben); einen nicht lesbaren oder ungültigen Pin; `--pin` oder `--witnesses`, die keine reguläre Datei sind (etwa eine FIFO); einen Entwicklungs-Pin (Exit 2); Rechte oder eine Gruppe, die nicht passen (der Prozess muss der Gruppe des Verzeichnisses angehören). Was es bis zu einem Fehler oder Signal angelegt hat, entfernt es wieder, und nur das. Wird der Pfad während `init` ersetzt, bricht es ab, ohne Fremdes zu ändern.

`init` ist der einzige Weg eines Produktionsbuilds, ein Datenverzeichnis anzulegen. Vor 1.5 startet der Server darauf nicht (keine Zertifikate).

### 1.5 Veröffentlichen

Auf dem Server-Host, solange kein Server läuft:

```
gomail-ceremony publish --from <export> --data <datenverzeichnis> --pin <pin>
```

`publish` hält die Serversperre `locks/server`, prüft `platform/` und `witnesses.rec` gegen den Pin, kopiert Schlüssel und Zertifikate nach `platform/` und trägt die Zertifikate ins Log ein. Es legt kein Datenverzeichnis an. Neben einem laufenden Server verweigert es („der Server läuft … erst anhalten“). Ein Abbruch dazwischen ist durch Wiederholen desselben Aufrufs heilbar. Seit Auftrag 22 setzt dieselbe Wiederholung auch eine fremde Datei unter einem geloggten Namen in `platform/` auf den Logeintrag zurück; was sie nicht heilt, steht in 7.3 („Fremde Dateien in `platform/`“).

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
  6. Annahme (`ingest.New`), in dieser Reihenfolge: Ingest-Schlüssel gegen sein Zertifikat, Zertifikat im Log, Zertifikat schon gültig (`valid_from` nicht nach der Uhr des Servers, sonst Exit 2); dann nimmt sie die Serversperre und hält sie bis zum Ende; mit `--require-client-lock` die Client-Sperre; zuletzt, dass die Ingest-Generation nicht abgelöst ist (Abschnitt 6).
  7. Testsperre (9.1).
  8. Kopf: ein signierbarer Kopf des Logs.
- **`--require-client-lock`** (Testsperre nach 9.1, Lesart D70): Der Server startet nur, wenn eine wirksame Client-Sperre `locks/client` besteht (ein laufendes `gomailctl` hält sie). Ohne den Schalter startet er auch ohne Client und meldet nur, dass keine Client-Sperre gehalten wird; ein dauerhaft laufender Server kann beim Start keinen Client voraussetzen. Der Test auf zwei Maschinen schaltet ihn ein. Die Testsperre zeigt nur, dass irgendein Prozess mit Zugriff auf das Datenverzeichnis die Sperre hält; sie authentifiziert niemanden.
- Ein **zweiter Serverprozess** auf demselben Datenverzeichnis bräuchte eine Kopie des Ingest-Schlüssels; der verlässt den Server-Host nicht. Er verweigert ohnehin an der Serversperre. Wer die Sperre von einem anderen Host prüfen will, nimmt `gomail-server log repair` (Abschnitt 9).
- Beim Start räumt der Server `spool/` und `work/` (5.2, 5.3). Das Server-Log enthält nur IDs, Größen, Hash-Präfixe und Statuscodes, nie Adressen oder Inhalte. Beenden mit SIGINT oder SIGTERM.
- Kann die Plattform den freien Platz nicht ermitteln (NetBSD, Windows), startet der Server, nimmt aber keine Mail an (451). Unter 10 % freiem Platz antwortet er mit `452 4.3.1`.
- Köpfe: der Server signiert spätestens nach `--head-interval` (Standard 1 h) einen Kopf, während das Log wächst höchstens einen je Minute. `--head-interval` liegt zwischen 1 min und 1 h (Standard und Höchstwert 1 h); ein anderer Wert scheitert beim Start, nach dem Lesen des Schlüssels (`loghttp: invalid configuration: head interval at most 1h0m0s, at least the minimum gap`).

### 1.7 Zeuge starten

Der Zeuge braucht den Prüfschlüssel des Logs. Er wird aus `platform/ingest-<gen>.pub` des Exports der Zeremonie gebildet (note-Format `gomail-log+<hash>+<schlüssel>`; der Log-Schlüssel ist der Ingest-Schlüssel, Q4). Den Export nehmen, nicht das Datenverzeichnis: Dort darf jedes Mitglied der Gruppe `gomail` `platform/ingest-<gen>.pub` schreiben, und `publish` prüft diese Datei nicht; ein falscher Schlüssel hielte den Zeugen nur auf (die Clients prüfen Köpfe gegen das Zertifikat), wäre aber schwer zu finden.

```
pub=<export>/platform/ingest-1.pub
h=$({ printf 'gomail-log\n\001'; cat "$pub"; } | sha256sum | cut -c1-8)
k=$({ printf '\001'; cat "$pub"; } | base64 | tr -d '\n')
echo "gomail-log+$h+$k"
```

Die Zeile geht auf getrenntem Weg zum Zeugenhost.

**Erreichbarkeit (nicht getestet):** Der Log-Port lauscht nur auf Loopback (1.6), und der Zeuge holt Köpfe nur ab, er öffnet keinen Port. Ein Zeuge auf einer anderen Maschine (0.1) erreicht das Log deshalb nur über einen Tunnel, etwa einen SSH-Tunnel, den der Zeugenhost zum Server-Host aufbaut:

```
ssh -N -L 127.0.0.1:<lokaler-port>:<log-adresse> <server-host>
```

`<log-adresse>` ist die Adresse aus `--log-listen`, wie der Server-Host sie sieht (etwa `127.0.0.1:<port>`); `--log` des Zeugen ist dann `http://127.0.0.1:<lokaler-port>`. Köpfe und Gegensignaturen sind signiert; der Tunnel stellt nur die Erreichbarkeit her. Dieser Weg ist in keinem Test nachgefahren (AUDIT R47); `TestRunbook` und das Skript nach 9 starten den Zeugen auf dem Server-Host. Ein Zeuge auf dem Server-Host braucht keinen Tunnel, ist aber nicht unabhängig (0.1, AUDIT R15). `--isolated-test-network` öffnet auch SMTP und ist nur für ein isoliertes Testnetz.

Auf dem Zeugenhost:

```
gomail-witness serve --log http://<log-adresse> --log-key <prüfschlüssel> --origin <origin> \
    --key <zeugenschlüssel> --state <zustandsverzeichnis> [--interval 10s]
```

`--state` muss fehlen (es wird mit 0700 angelegt) oder darf Gruppe und anderen keine Rechte geben; `--key` muss nur für den Eigentümer lesbar sein (0600) und außerhalb von `--state` liegen. Sonst verweigert der Zeuge den Start.

Der Zeuge fragt das Log in Abständen ab (Standard 10 s, mindestens 1 s), wartet, bis der Server erreichbar ist, signiert jeden Kopf mit, der den zuletzt mitsignierten konsistent fortsetzt, und schickt die Gegensignatur zurück; er öffnet keinen Port. Zeigt das Log zwei verschiedene Köpfe gleicher Größe, hört er für immer auf zu signieren und endet mit Exit 3 (der Beweis liegt im Zustandsverzeichnis); Vorgehen dann: 8.9. Das Zustandsverzeichnis bleibt über jeden Neustart erhalten; nie löschen, nie durch ein leeres oder älteres ersetzen (8.8).

Erst mit dem Quorum der Zeugen veröffentlicht der Server einen Kopf (`log/heads/<n>.sig`), und erst mit einem solchen Kopf arbeiten die Clients.

## 2. Terminalregeln der Zeremonie

`init`, `ingest-rotate`, `reshare` und `succeed` zeigen oder lesen Anteile, ebenso `admin-rotate` und `revoke` (7.3). Für alle sechs gilt (Paketkommentar `cmd/gomail-ceremony/main.go`, `shareCommands`):

- **Terminal:** Standardeingabe und Standardausgabe müssen ein Terminal sein, dessen Echo sich abschalten lässt; keine Umleitung, keine Pipe, keine Datei. Sonst verweigert das Programm, bevor es etwas anzeigt, liest oder schreibt. Einen Schalter darum gibt es nicht. Auf Systemen ohne Terminalsteuerung (nicht Linux, macOS oder BSD) verweigern alle sechs Befehle.
- **stderr:** Die Aufforderungen stehen auf der Standardfehlerausgabe. Sie muss ein Terminal, eine Pipe oder eine reguläre Datei sein und zum Schreiben geöffnet, nicht `/dev/null`, kein Socket und kein anderes Gerät; sonst endet die Zeremonie mit Exit 2, bevor ein Anteil erscheint. Liegt sie auf einem anderen Terminal, wird auch dort gelöscht.
- **Anzeige:** Jeder Inhaber wird einzeln aufgerufen („Inhaber von Anteil i von n an den Bildschirm, dann Eingabetaste“); vorausgetippte Eingabe wird vorher verworfen. Nach „Anteil notiert?“ löscht die Eingabetaste den Bildschirm samt Verlauf. Die Software-Flusssteuerung (Strg-S/Strg-Q) ist während der ganzen Zeremonie aus.
- **Eingabe:** Anteile werden ohne Anzeige eingegeben, 30 Wörter, auch über mehrere Zeilen; die Eingabe wird normalisiert (Kleinschreibung, beliebiger Leerraum), Abkürzungen gelten nicht. Meldungen nennen Wortpositionen, nie Wörter. Ein Anteil wird bis zu dreimal abgefragt.
- **Abbruch:** Strg-C, Strg-\ oder Strg-Z, SIGTERM und SIGHUP stellen das Terminal wieder her, löschen den Bildschirm und beenden mit Exit 130. Während ein Anteil eingegeben wird, ist ISIG aus: Strg-C wirkt dann erst mit der Eingabetaste. Ein Abbruch endet nach höchstens etwa 2 s, auch wenn das Terminal keine Ausgabe mehr annimmt. Eine Zeremonie wird nie angehalten (Strg-Z bricht ab).
- **Geltung der Zeiten:** Die Zeiten in diesem Abschnitt gelten, solange das Programm Rechenzeit bekommt. Auf einer überlasteten oder angehaltenen Maschine (oder wenn der Prozess nicht eingeplant wird) steht ein Anteil entsprechend länger auf dem Bildschirm (D85 Nachtrag 20n).
- **Commit:** Kommt ein Signal, während die Dateien geschrieben werden, aber vor dem Umbenennen des Exports, wird alles zurückgebaut (Exit 130, nichts geschrieben). Danach wird es ignoriert: die Zeremonie meldet ihr Ergebnis, den Hinweis auf das Signal und Exit 0. Exit 0 heißt immer „Export vollständig“, Exit 130 „nichts geschrieben“.
- **SIGKILL und SIGSTOP** lassen sich nicht abfangen: Echo und Flusssteuerung bleiben aus, ein gezeigter Anteil bleibt stehen. Das Terminal mit `stty sane` zurücksetzen und den Bildschirm samt Verlauf von Hand löschen.
- **Restgrenze:** Ein Terminal, das nie wieder liest (angehalten, voll, getrennt), zeigt das Löschen nicht; ein Anteil kann dann auf ihm stehen bleiben. Verlauf und Scrollback eines Terminal-Emulators liegen außerhalb des Programms: für die Zeremonie ein Terminal ohne Verlauf verwenden.

- **Bestätigungen:** Jede Bestätigung mit der Eingabetaste („Inhaber an den Bildschirm“, „Anteil notiert?“) zählt erst, wenn die Aufforderung mindestens eine Sekunde vollständig zu sehen ist. Eine frühere oder doppelte Eingabe wird verworfen, und die Zeremonie fragt mit „Eingabe zu früh, bitte erneut bestätigen“ noch einmal. Dann einmal ruhig warten und erneut die Eingabetaste drücken. Ein Doppel-Enter bestätigt nie für den nächsten Inhaber.
- **Angehaltene Ausgabe:** Ist die Bildschirmausgabe länger als 2 s angehalten oder voll, endet die Zeremonie mit Exit 130 und löscht den Bildschirm vorher (Zeiten wie oben: in der Rechenzeit des Programms). Ursachen sind Scroll Lock, Strg-S oder ein anderes Programm am Terminal. Terminal prüfen und die Zeremonie neu beginnen; es ist nichts geschrieben.

## 3. Benutzer anlegen

Alle Befehle von `gomailctl` außer `inspect` brauchen `--data <datenverzeichnis>` und `--pin <pin>` (älterer Name `--platform`), optional `--dir <client>` (Standard `<UserConfigDir>/gomailctl`, 0.3). Der Benutzer ist Mitglied der Gruppe `gomail` und ein anderer Betriebssystembenutzer als der Server (1.4). Die Befehle arbeiten nur neben einem laufenden Server, dessen Sperre `locks/server` auf diesem Rechner wirkt (Testsperre, 9.1); ohne ihn verweigern sie mit „Testsperre“. Jeder Befehl öffnet das Transparenzlog selbst mit dem Pin; ohne einen von den Zeugen bestätigten Kopf, der höchstens 24 Stunden alt ist, verarbeitet der Client nichts (Abschnitt 10).

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
- Nach der Passphrase, bis die Wörter abgefragt sind (mit `--shares`: bis der letzte Anteil bestätigt ist), löscht Strg-C oder ein anderes Abbruchsignal den Bildschirm und beendet `keygen` mit Exit 130, ohne etwas zu schreiben; danach beendet ein Signal den Prozess sofort (Client-Verzeichnis unten).
- **Seed sichern:** Die 24 Wörter auf Papier, an einem sicheren Ort. Der Seed liegt danach nirgends auf der Platte. Gebraucht wird er nur für ein neues Gerät, einen Geräteverlust und die Wiederherstellung (Abschnitt 5).

**Client-Verzeichnis** (gilt für `keygen` und `restore`, 5.2):

- **Elternverzeichnis zuerst prüfen (D92):** `stat -c '%U %a' <eltern>` muss den eigenen Benutzer (oder `root`) zeigen und keine Schreibrechte für Gruppe und andere, oder bei diesem Eigentümer das Sticky-Bit (Abschnitt 0.3, „Voraussetzung für `<client>`“). `<eltern>` ist das Verzeichnis über `--dir`. Ist `--dir` ein symbolischer Link, gilt das für das Verzeichnis, das den Link enthält, und für das Elternverzeichnis des Linkziels; im Elternverzeichnis des Linkziels entsteht auch das Temp-Verzeichnis.
- **Ziel:** `--dir` darf fehlen, leer sein oder nur die Datei `lock` enthalten (die legt jeder Befehl an, der das Client-Verzeichnis öffnet, etwa `sync` oder `mailbox create`, auch wenn er mangels registriertem Benutzer abbricht). Ein Verzeichnis mit Schlüsselspeicher wird abgelehnt (`client: this client directory already has a user`; bei `restore` auch eines mit `user.rec` oder `state.json`), eines mit anderen Einträgen ebenso (`store: file exists: the client directory <client> is not empty or in use by another client`); beides endet mit Exit 1. Diese Meldung kommt auch, wenn gleichzeitig ein anderer Befehl dasselbe Verzeichnis belegt; dann einmal wiederholen. Ein symbolischer Link als `--dir` wird verfolgt; Temp-Verzeichnis und Reste liegen dann neben dem Ziel des Links.
- **Nicht im Datenverzeichnis:** `keygen`, `restore`, `register`, `device lost` und jeder Befehl, der das Client-Verzeichnis öffnet, verweigern ein `--dir` im Datenverzeichnis, auch über einen symbolischen Link an `--dir` oder an einem Elternverzeichnis, auch über einen hängenden Link (`client: the client directory must not be inside the data directory`; angelegt wird nichts). Seit Auftrag 24 (Paket B; `resolveExisting` und `insideDataDir` in `internal/client/client.go`; D86 Nachtrag 24 B) löst der Client den Pfad Stück für Stück auf wie das System. Mit derselben Meldung lehnt er auch ein `--dir` ab, dessen Pfad er nicht ganz prüfen kann: unter einem Verzeichnis ohne Suchrecht (EACCES), mit einem aufgelösten Pfad über `PATH_MAX` (ENAMETOOLONG), mit mehr als 40 symbolischen Links auf dem Weg oder einem Kreis von Links (`TestInsideDataDirUnexaminable`, `TestClientDirLongRealPath`, `TestClientDirChain41IntoDataDir`). Die Meldung heißt dann nicht, dass `--dir` im Datenverzeichnis liegt. Abhilfe: mit `namei -l <client>` Links und Suchrecht (`x`) jeder Stufe prüfen, Linkketten verkürzen oder ein kürzeres, direkt erreichbares `--dir` nehmen.
- **Temp-Verzeichnis verschwunden oder ausgetauscht:** Verschwindet das Temp-Verzeichnis während des Laufs, gibt es zwei Fälle. Ist `--dir` dann belegt, kommt die Meldung „not empty or in use by another client“ wie oben. Ist es nicht belegt, endet der Befehl mit dem Fehler des Schritts zum Temp-Verzeichnis, `no such file or directory`; jemand hat es verschoben oder gelöscht. Steht am Namen des Temp-Verzeichnisses (oder nach dem Umbenennen an `--dir`) ein anderes Verzeichnis als das, das der Lauf angelegt hat, endet er mit `client: the temporary directory of the client directory was replaced by another directory; its parent must not be writable by other users`. Vor dem Umbenennen benennt der Befehl dann nichts um und entfernt nichts; nach dem Umbenennen steht an `--dir` möglicherweise ein fremdes Verzeichnis. Die Dateien des Laufs liegen in dem Verzeichnis, das er angelegt hat, wohin auch immer es verschoben wurde. In allen drei Fällen ist Exit 1. Abhilfe bei dieser Meldung: das Elternverzeichnis prüfen (oben); das Verzeichnis am Temp-Namen und an `--dir` ansehen, nicht ungesehen löschen, denn es kann ein fremdes Client-Verzeichnis sein; erst danach wiederholen.
- **In einem Schritt:** Der Befehl schreibt zuerst in ein Temp-Verzeichnis neben dem Ziel, `.<name>.keygen-<ziffern>` bzw. `.<name>.restore-<ziffern>` (`<name>` ist der letzte Teil von `--dir`, ist `--dir` ein symbolischer Link: des Ziels des Links; Rechte 0700), legt darin als Erstes die leere Markierung `.incomplete` an, entfernt sie unmittelbar vor dem Umbenennen und benennt es dann in `--dir` um. `<client>` ist also entweder nicht da oder vollständig. Ein Fehler vor dem Umbenennen entfernt das Temp-Verzeichnis selbst; ein Abbruch während des Schreibens (ein Signal, nachdem die Wörter abgefragt sind, SIGKILL, Absturz, Stromausfall) lässt es liegen. Es enthält den versiegelten Schlüsselspeicher, das öffentliche `user.rec` und `state.json`, nie den Seed.
- **Aufräumen:** Der nächste erfolgreiche Lauf derselben Art für dasselbe `--dir` (`keygen` räumt nur `.<name>.keygen-*`, `restore` nur `.<name>.restore-*`) entfernt Reste, die die Markierung `.incomplete` enthalten, dem eigenen Benutzer gehören und zuletzt geändert wurden, bevor er in seinem eigenen Temp-Verzeichnis die Markierung anlegte (Zeit des Dateisystems), und darin nur die Dateien, die ein Lauf dort schreibt; ein Rest mit anderen Einträgen bleibt stehen. Einen Rest der anderen Art oder einen, der nicht mehr gebraucht wird, löscht der Benutzer von Hand.
- **Rest ohne Markierung:** Bricht der Lauf genau zwischen dem Entfernen von `.incomplete` und dem Umbenennen ab, bleibt ein Temp-Verzeichnis ohne Markierung, das kein Lauf entfernt. Es ist dann das vollständige Ergebnis dieses Laufs (versiegelter Schlüsselspeicher, `user.rec`, `state.json`). `<eltern>` ist das Verzeichnis über `--dir` (ist `--dir` ein symbolischer Link: über dem Ziel des Links); `ls -la <eltern>` zeigt den Rest. Vorgehen (kein Test):
  1. Erst ansehen: `ls -la <eltern>/.<name>.keygen-<ziffern>` (bzw. `.restore-`) muss dem eigenen Benutzer gehören und genau `keystore`, `user.rec` und `state.json` enthalten. Sonst nicht anfassen und das Elternverzeichnis prüfen (0.3): Es kann ein fremdes Verzeichnis sein.
  2. Ist `--dir` ein symbolischer Link, in diesem Schritt statt `<client>` das Ziel des Links nehmen. Fehlt `<client>` oder enthält es nichts außer der Datei `lock` (`ls -la <client>`), kann der Rest an seinen Platz: ein vorhandenes `<client>` mit `rm -f -- <client>/lock` leeren, dann `rmdir -- <client> && mv -T -- <eltern>/.<name>.keygen-<ziffern> <client>` (`rmdir` entfernt nur ein leeres Verzeichnis; `-T`: nie in ein vorhandenes Verzeichnis hinein; `-T` gibt es nur im GNU-`mv`, unter macOS/BSD nach dem `rmdir` prüfen, dass `<client>` fehlt, und dann `mv --` mit dem Zielnamen ausführen); fehlt `<client>`, nur `mv -T -- <eltern>/.<name>.keygen-<ziffern> <client>`. Für einen Rest von `restore` ebenso mit `.<name>.restore-<ziffern>`. Danach weiter wie nach einem erfolgreichen Lauf: nach `keygen` mit 3.4, nach `restore` mit `gomailctl sync` (4.8).
  3. Sonst, oder wenn der Lauf ohnehin wiederholt wurde: den Rest zuerst außerhalb von `<eltern>` aufbewahren (`mv -- <eltern>/.<name>.keygen-<ziffern> <aufbewahrung>/`) und erst löschen (`rm -r`), wenn ein Befehl mit `<client>` gelingt. Bei `keygen` gilt nur der Seed des Laufs, dessen Ergebnis in `<client>` steht.

  Nie das Verzeichnis `<client>` selbst löschen, wenn es einen Schlüsselspeicher enthält.
- **Einhängepunkt:** Ist `--dir` selbst ein Einhängepunkt, lässt es sich nicht ersetzen: das Umbenennen scheitert mit `device or resource busy` (EBUSY) oder `invalid cross-device link` (EXDEV), der Befehl endet mit Exit 1 und entfernt sein Temp-Verzeichnis. Abhilfe: ein Unterverzeichnis des Einhängepunkts als `--dir` nehmen.

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

Der Administrator. **Vorher** die Postfach-ID beim Eigentümer des Postfachs auf getrenntem Weg bestätigen lassen (Ausgabe von `gomailctl mailbox create`, 4.1): Eine Zuordnung lässt sich im PoC weder ändern noch entfernen (R39). Mails an diese Adresse gehen dauerhaft an die Mitglieder des genannten Postfachs, auch bei einem Tippfehler in `--mailbox`.

```
gomail-server address add <adresse> --mailbox <postfach-id> --data <datenverzeichnis> --admin-key <admin-1.key> --pin <pin>
```

Die Zuordnung wird mit dem Admin-Schlüssel signiert, ins Log eingetragen und danach in `addresses.json` (Arbeitskopie) übernommen. Das Postfach muss existieren. Eine Adresse, die einem anderen Postfach zugeordnet ist, wird abgelehnt (Exit 2); Umordnen und Entfernen gibt es im PoC nicht (R39). Fehlermeldungen nennen die Adresse nie; die Adresse steht aber in der Kommandozeile und in der Erfolgsmeldung (R19).

**Uhr (Auftrag 24, Paket C; `assignmentValidFrom` und `checkAddressFree` in `cmd/gomail-server/main.go`; D80 Nachtrag 24 C):** Der Beginn einer Zuordnung (`valid_from`) muss im Log für jede Adresse steigen. `address add` liest unter `addresses.lock` das größte `valid_from` der gültigen Zuordnungen dieser Adresse im Log und nimmt max(Uhr des Rechners, dieser Wert + 1 ms); ohne vorige Zuordnung ist es die Uhr (`TestAddressAddValidFromFirst`). Ist die Uhr seit der letzten Zuordnung derselben Adresse zurückgegangen, oder läuft `address add` auf einem anderen Rechner, dessen Uhr nachgeht, gelingt der Befehl deshalb (`TestAddressAddValidFromAfterLogged`). Zwei Aufrufe in derselben Millisekunde für dieselbe Adresse und dasselbe Postfach ergeben zwei Einträge mit aufeinanderfolgenden Werten (`TestAddressAddParallelUnderLock`). Das betrifft nur die erneute Zuordnung zum selben Postfach, denn eine andere wird schon vorher abgelehnt (Exit 2). **Schranke:** Liegt der letzte Wert + 1 ms mehr als `translog.MaxClockSkew` (5 Minuten) nach der Uhr, nimmt `address add` die Uhr, und das Log verweigert wie bisher (`translog: log entry violates a validity rule: valid_from does not increase`, Exit 1, nichts geschrieben; `TestAddressAddValidFromBeyondSkew`). Eine weit in die Zukunft datierte Zuordnung, etwa die eines Diebs des Admin-Schlüssels, wird so nicht still fortgeschrieben (Q9, F3 der Angreiferprüfung von 21a); sie hält die Adresse fest, bis die Uhr auf 5 Minuten an ihr `valid_from` heranreicht (AUDIT R18; bei Verdacht auf einen entwendeten Admin-Schlüssel 7.3.4). Abhilfe bei dieser Meldung: die Uhr prüfen und stellen (Abschnitt 10) und die geloggten Zuordnungen der Adresse ansehen. Lehnt das Log eine Zuordnung aus einem anderen Grund ab, bleibt der Fehler bestehen (fail closed). Steht die Uhr vor dem Beginn (`valid_from`) des Admin-Zertifikats, scheitert jede Zuordnung, auch die erste (`… assignment before the admin certificate`, Exit 1); Abhilfe: die Uhr prüfen und stellen (Abschnitt 10) oder den Befehl erst nach diesem Beginn wiederholen.

**Admin-Zertifikat (Auftrag 24, Paket C, Punkt 63 der Liste nach M1; D93 Nachtrag 24, AUDIT R48):** `address add` liest `admin-<gen>.cert` einmal (`store.ReadPlatformCertRaw`), prüft seine Signatur mit dem Schlüssel seiner `identity_gen` (aus der Identitätsliste des Pins, darüber aus den gültig geloggten Nachfolgen `identity-<g>.succ`; `identityKey`) und gleicht dieselben Bytes mit dem Log ab (`Log.CheckPlatform`), bevor es etwas loggt. Scheitert das, endet der Befehl mit Exit 1 und `admin-<gen>.cert ist nicht von der Plattformidentität seiner identity_gen signiert oder kein gültiger Eintrag des Logs: <ursache>` (`TestAddressAddForgedCert`, `TestAddressAddIdentitySuccession`). Abhilfe: `platform/admin-<gen>.cert` mit dem Export der Zeremonie vergleichen; eine fremde Datei unter dem geloggten Namen setzt eine Wiederholung desselben `publish` zurück (7.3, „Fremde Dateien in `platform/`“).

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
- Ein Leser vergangener Zeiträume (`share --to`) ist kein Mitglied. `revoke` löscht dann nur seine Verpackungen; eine Epoche mit sofortiger Wirkung entsteht nicht (wie bei `sync` ergänzt `revoke` höchstens den Vorrat geplanter Epochen). Grund 4 (`delegation-ended`) gibt es nur für Vertreter der Art 3, für die es keinen Befehl gibt (Q6).
- Prüfen mit `inspect` (4.9): Der Kopf einer Mail-Datei `mailboxes/<postfach-id>/mail/<ordner>/<mail-id>.gml`, die nach dem Entzug eingeht, nennt unter `header.epoch` die neue Epoche, bis die nächste geplante Epoche beginnt; auch deren Mitgliederliste nennt den Benutzer nicht. Die `epochs/<n>/epoch.rec` der neuen Epoche hat `reason` 3 (Mitglied entfernt), `begin` zur Zeit des Entzugs und unter `members` den Benutzer nicht mehr. Ins Log trägt sie der Client, der `revoke` ausführt, selbst ein; sein nächster Befehl gelingt erst, wenn ein von den Zeugen bestätigter Kopf sie deckt (3.4).

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
| 1 | Fehler (auch Testsperre, Log, Prüfung, unbekannter Flag-Name, fehlendes `--data` oder `--pin`, ungültige ID bei `list`, `read` und `register --invite`) |
| 2 | Aufruffehler: unbekannter Befehl oder Schalter, falsche Zahl von Argumenten, ungültige ID bei `mailbox share`, `mailbox revoke`, `search` und `flag`, ungültige Epoche, Aufteilung oder ungültiger Monat |
| 3 | teilweiser Erfolg (`share`, `device lost`, auch `sync`): was erledigt ist, steht in der Ausgabe, die Meldung nennt die Abhilfe (meist: denselben Befehl später wiederholen) |
| 130 | Abbruch durch ein Signal, während Seed, Anteil oder getippte Wörter auf dem Bildschirm stehen konnten; der Bildschirm ist gelöscht |

## 5. Geräteverlust und Wiederherstellung

Seed- und Anteilswörter werden von einem Terminal ohne Anzeige gelesen und danach vom Bildschirm gelöscht; ist die Standardeingabe ein Terminal, muss die Standardausgabe dasselbe Terminal sein. Aus einer Datei oder Pipe werden sie ohne Rückfrage gelesen. Wörter nie in eine Datei schreiben.

### 5.1 Gerät verloren

Auf einem verbliebenen oder neu eingerichteten Gerät des Benutzers (mit Schlüsselspeicher und Passphrase). Vorher das Elternverzeichnis des Client-Verzeichnisses prüfen (0.3, D92): `device lost` schreibt Schlüsselspeicher und `user.rec` neu, über den Pfad.

```
gomailctl device lost $C
```

- Der Client fragt Passphrase und die 24 Seed-Wörter ab, leitet die nächste Generation ab, signiert `user.rec` neu (die bisherige Generation ist widerrufen) und trägt sie ins Log ein. Ausgabe: `Neue Generation <g>; die vorherige ist widerrufen.`
- **Jeder Aufruf erzeugt eine neue Generation** (D88 (7)). Postfächer, deren Neuausstellung ein früherer Aufruf nicht beendet hat, setzt er nebenbei fort.
- Eigene Dateien außerhalb des Logs (Verpackungen, `folders.gml`, Vermerke) stellt er mit der neuen Generation neu aus. Die anderen Mitglieder verpacken die gemeinsamen Postfächer beim nächsten `sync` für die neue Generation; bis dahin liest der Benutzer dort nur, was er selbst neu ausstellen konnte.
- Exit 3: nicht alle Postfächer sind fertig; die Meldung nennt sie. Später `sync` wiederholen; es setzt die Neuausstellung fort. `device lost` nur erneut ausführen, wenn wieder ein Gerät verloren ist, denn jeder Aufruf erzeugt eine neue Generation. Ein alleiniges Mitglied ohne geprüfte Ordnerliste bleibt dabei hängen (Abschnitt 8.4, Q18); bleibt Exit 3 aus einem anderen Grund dauerhaft, siehe 8.10 (AUDIT R44).

### 5.2 Wiederherstellen aus den Seed-Wörtern

Auf einem Gerät ohne Client-Zustand (leeres oder neues `--dir`):

```
gomailctl restore $C
```

Der Client fragt eine neue Passphrase (zweimal) und die 24 Wörter ab und richtet den Benutzer des Seeds auf diesem Gerät ein. Ausgabe: `Benutzer <id> auf diesem Gerät wiederhergestellt.` Ein so eingerichteter Client vertraut beim ersten Kontakt und warnt bei jedem Befehl „Noch kein bestätigter Zustand“, bis der Vermerk eines **anderen** Benutzer-Mitglieds mit seinem Kopf übereinstimmt; ein alleiniges Mitglied bleibt markiert (Q20, R22). Er übernimmt jedes Postfach, dessen Kopf den Benutzer nennt (R20).

Für `--dir` gelten dieselben Regeln wie bei `keygen` (3.2, Client-Verzeichnis): fehlend, leer oder nur mit `lock`; das Temp-Verzeichnis heißt `.<name>.restore-<ziffern>`, und nur ein erfolgreiches `restore` räumt solche Reste auf. Falsche Wörter oder Anteile lassen `--dir` unverändert.

`restore` erzeugt keine neue Generation. War das alte Gerät verloren, danach `device lost` ausführen (5.1).

**Passphrase vergessen:** Ohne Passphrase öffnet sich der Schlüsselspeicher nicht (`keys: key store authentication failed …`). Dann mit `restore` aus den Seed-Wörtern in ein **neues** `--dir` wiederherstellen und das alte Client-Verzeichnis behalten, bis das neue arbeitet.

### 5.3 Wiederherstellen aus Anteilen

```
gomailctl restore --shares <k> $C
```

Wie 5.2, aber mit `<k>` Anteilen aus `keygen --shares` (3.3), je 30 Wörter, einer nach dem anderen; nach jedem Anteil wird der Bildschirm gelöscht. Die Inhaber geben ihren Anteil selbst ein.

## 6. Ingest-Rotation

Ein neuer Ingest-Schlüssel (und damit ein neuer Log-Schlüssel, Q4) braucht `<k>` Anteilsinhaber der aktuellen Aufteilung auf dem Zeremonierechner (bei 3-of-5 drei; nach `reshare` die neue Schwelle, 7.4). Den Umschaltzeitpunkt `<valid-from>` so wählen, dass Veröffentlichen und Zeugen vorher erledigt sind; die Uhr des Zeremonierechners vorher stellen (Abschnitt 10).

1. **Zeremonie offline:**

   ```
   gomail-ceremony ingest-rotate --pin <pin> --gen <n> --out <export-n> --keys <schlüssel> --valid-from <RFC3339>
   ```

   `<n>` ist die höchste vorhandene Ingest-Generation + 1 (aus `platform/ingest-*.cert`). `--valid-from` darf nach der Uhr des Zeremonierechners nicht in der Vergangenheit liegen. `<k>` Inhaber geben ihren Anteil ein; der Root muss genau die Identität des Pins ergeben. Ergebnis: `<export-n>` mit `ingest-<n>.pub`/`.cert` und `<schlüssel>/ingest-<n>.key` (0600).
2. **Veröffentlichen vor dem Umschalten** (Server kurz anhalten): `gomail-ceremony publish --from <export-n> --data <datenverzeichnis> --pin <pin>`, dann den Server mit dem bisherigen Schlüssel wieder starten.
3. **Zeugen:** Prüfschlüssel der neuen Generation nach 1.7 aus `platform/ingest-<n>.pub` bilden und jeden Zeugen mit beiden Log-Schlüsseln neu starten (`--log-key <alt> --log-key <neu>`, gleiches Zustandsverzeichnis).
4. **Umschalten ab `<valid-from>`:** Ab diesem Zeitpunkt signiert die alte Generation nichts mehr gültig. Ein laufender Server mit dem alten Schlüssel lehnt Einlieferungen mit `451` ab; ein Neustart mit dem alten Schlüssel verweigert (`ingest: the ingest generation is superseded in the log`). Den Server **nach** `<valid-from>` mit `--ingest-key <ingest-<n>.key>` neu starten; vorher verweigert der Server den Start mit dem neuen Schlüssel (Exit 2, `der Ingest-Schlüssel ist noch nicht gültig`), denn eine Mail mit Empfangszeit vor `valid_from` des neuen Zertifikats lehnen die Clients ab. Maßgeblich ist die Uhr des Servers (Abschnitt 10). Absender wiederholen nach `451`.
5. **Alten Schlüssel vernichten**, sobald der Server mit dem neuen läuft. Den alten `--log-key` kann der Zeuge danach weglassen, frühestens wenn er einen mit dem neuen Schlüssel signierten Kopf gegengezeichnet hat; sein gespeicherter Kopf bleibt auch ohne den alten Schlüssel lesbar (`internal/witness/witness.go`, Abschnitt „State“; kein Test).

Clients beenden die alte Generation bei `valid_from` des neuen Zertifikats, sobald es im Log steht: Metadaten, die der alte Schlüssel für eine Empfangszeit ab `valid_from` signiert hat, lehnen sie ab (`WARNUNG: Mail <id> wird nicht verarbeitet: Plattformzertifikat oder Annahmeschlüssel nicht gültig.`); ältere Mails bleiben lesbar. Bei Verdacht auf Kompromittierung des Ingest-Schlüssels genügt diese Rotation nicht: Sie beendet die alte Generation erst ab `valid_from` und verhindert keine rückdatierten Signaturen. Dann gilt 7.3.3 (Widerruf, D93). Die Admin-Rotation steht in 7.3.4.

## 7. Nachfolge der Plattformidentität

### 7.1 Regulärer Wechsel

1. **Zeremonie offline** (`<k>` Inhaber der aktuellen Aufteilung, Uhr gestellt; `succeed` zeigt die Uhr, sie gibt `valid_from` der Nachfolge):

   ```
   gomail-ceremony succeed --pin <identity-g.pin> --out <export-g+1>
   ```

   Origin, Zeugen und Quorum kommen aus dem Pin; `--origin` ist nur eine Kontrolle (der Origin ändert sich nie). Ergebnis: `<export-g+1>` mit `identity-<g+1>.succ` (signiert von Generation g) und der neue Pin `identity-<g+1>.pin`.
2. **Neuen Pin verteilen** an Server-Host, Administrator (`address add` und `log repair` nehmen `--pin`) und Clients (Client-Update, getrennter Weg). Clients mit dem alten Pin übernehmen die Nachfolge aus dem Log, sobald ein bestätigter Kopf sie deckt, aber nur, solange sich Zeugen und Quorum nicht ändern (7.2); der neue Pin ist trotzdem zu verteilen. Mit `--witness` (7.2) den neuen Pin nicht vor `publish` an die Clients verteilen, sondern wie in 7.2 beschrieben.
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

**Clients mit altem Pin (kein Test):** Ein Client nimmt Zeugen und Quorum nur aus seinem Pin (`internal/client/log.go`); eine Nachfolge ändert sie nicht, und der Server nimmt nach `--replace-witnesses` nur noch Gegensignaturen der Zeugen aus `witnesses.rec` an. Ein Client mit dem **neuen** Pin prüft Köpfe nur gegen die neuen Zeugen (`internal/translog/verifier.go`, Prüfung des Quorums) und arbeitet erst, wenn sie nach `publish --replace-witnesses` gegengezeichnet haben; ein Client mit dem alten Pin stoppt spätestens 24 Stunden nach dem letzten von den alten Zeugen gegengezeichneten Kopf (`translog: no fresh verified tree head`, Abschnitt 10). Deshalb entweder die neue Zeugenmenge so wählen, dass sie die Quoren beider Pins erfüllt (die alten Zeugen bleiben enthalten), bis alle Clients den neuen Pin haben, oder den neuen Pin unmittelbar nach dem ersten von den neuen Zeugen gegengezeichneten Kopf verteilen, innerhalb dieser 24 Stunden (kein Test).

### 7.3 Kompromittierte oder verlorene Plattformschlüssel

Ein Widerruf steht in Feld 7 eines **neuen Pins** (D93, Abschnitt 2.3 des Plans, „Widerruf von Plattformgenerationen“). Er nennt Rolle und Generation und eine Grenze aus Größe `<N>` und Zeit `<T>` eines Kopfes, den die Zeugen bestätigt haben. Im Pin steht `revoked_at_size` = `<N>` und `revoked_at_time` = `<T>` + 1 ms: Der bestätigte Kopf selbst bleibt gültig (D93 Nachtrag). Was die widerrufene Generation ab Logindex `<N>` ausstellt oder betrifft, gilt nicht mehr; was sie vorher ins Log gebracht hat, bleibt gültig. Köpfe und Metadaten einer widerrufenen Ingest-Generation gelten nur mit einer Zeit bis einschließlich `<T>`. Widerruft der Pin eine Identitätsgeneration, gilt dasselbe für jede Admin- und Ingest-Generation, deren Zertifikat sie ausgestellt hat, auch für die eigenen des Betreibers (Kaskade, D93 Nachtrag; `internal/translog/doc.go`, „Platform generations“). Der Pin ist der einzige Träger des Widerrufs. Wirksam ist er deshalb nur bei Server, Administrator und Clients, die den neuen Pin haben; ein Client mit dem alten Pin nimmt weiter an, was die widerrufene Generation signiert.

**Befehle** (Usage-Text von `gomail-ceremony`, Auftrag 21c, Commit 12d48cc):

```
gomail-ceremony revoke --pin <pin> --out <export> --role admin|ingest --generation <g> \
    --revoke-at-size <N> --revoke-at-time <T>
gomail-ceremony admin-rotate --pin <pin> --gen <n> --out <export> --keys <schlüssel> --valid-from <RFC3339>
gomail-ceremony succeed --pin <pin> --out <export> --compromised --revoke-at-size <N> --revoke-at-time <T>
```

- **Schreibweise der Grenze:** `<N>` und `<T>` so, wie der Kopf sie zeigt (7.3.2): dezimal, ohne Vorzeichen und ohne führende Nullen, `<T>` in Millisekunden seit 1970 UTC. Bei `revoke` und `succeed --compromised` sind beide Pflicht; ohne `--compromised` sind sie verboten. Sonst endet der Aufruf mit Exit 2, bevor etwas gezeigt, gelesen oder geschrieben wird, etwa `succeed --compromised: --revoke-at-size und --revoke-at-time sind nötig (Größe und Zeit eines von den Zeugen bestätigten Kopfes)` oder `--revoke-at-size und --revoke-at-time nur mit --compromised`. `--role` nimmt nur `admin` oder `ingest`; eine Identitätsgeneration widerruft `succeed --compromised`.
- **Anzeige vor dem ersten Anteil:** `Widerruf: <was> ab Logindex <N> und Zeit <T+1> (<RFC 3339>). Kopf: Größe <N>, "time <T>" (<RFC 3339>); der Kopf selbst bleibt gültig. Mit dem abgelesenen Kopf vergleichen; weicht etwas ab, jetzt mit Strg-C abbrechen.`, danach die Uhr des Zeremonierechners. Die Inhaber vergleichen das mit dem Papier aus 7.3.2.
- **Verweigerungen vor dem ersten Anteil** (Exit 1, nichts geschrieben): eine Kopfzeit nach der Uhr des Zeremonierechners plus fünf Minuten (`ceremony: invalid revocation: head time … lies after the clock of the ceremony …`), eine Kopfzeit vor dem 01.01.2025, meist eine Zeit in Sekunden statt Millisekunden (`… lies before 1735689600000 (2025-01-01T00:00:00Z), the earliest head time: the time of the head is in milliseconds since 1970, not in seconds`), eine Generation, die der Pin schon widerruft (`… the pin already revokes …`; eine Grenze lässt sich nie verschieben), und eine Rotation auf eine widerrufene Generation (`… the pin revokes … generation … its key is the stolen one …`): Ihr Schlüssel ist der gestohlene und wird nie neu zertifiziert.
- **`revoke`** schreibt nur den neuen Pin `<export>/identity-<g>.pin`: dieselbe Identitätsgeneration, derselbe Name wie der alte Pin, mit dem zusätzlichen Element in Feld 7. Er ersetzt den alten Pin überall; beide nie nebeneinander liegen lassen. Die Ausgabe nennt den nächsten Schritt: `Nachfolgerin (Pflicht, ohne Lücke): ingest-rotate --pin <neuer Pin> --gen <i+1> ... --valid-from <T+1 ms>` bzw. `Neue Admin-Generation: admin-rotate --pin <neuer Pin> --gen <a+1> ...`. Widerruft der Pin die Vorgängerin `<i>` und zusätzlich die Identitätsgeneration vor der aktuellen mit einer früheren Zeit, kennt die Zeremonie offline nicht, welche Grenze gilt: `ingest-rotate` verlangt dann `--valid-from` ausdrücklich mit einem der beiden Werte und nennt beide in der Verweigerung (den früheren, wenn jene Identität `ingest-<i>.cert` ausgestellt hat; `TestRotateBothRevoked`).
- **`admin-rotate`** nimmt dieselben Optionen wie `ingest-rotate` (Abschnitt 6) und schreibt `<export>/platform/admin-<n>.pub`, `admin-<n>.cert` und `<schlüssel>/admin-<n>.key` (0600). `--valid-from` darf nicht in der Vergangenheit liegen (Abschnitt 10). **`admin-rotate` allein beendet einen entwendeten Admin-Schlüssel nicht:** Die alte Generation ordnet mit einem `valid_from` vor dem der neuen weiter gültig zu, auch wenn die Zuordnung erst danach ins Log kommt (`TestAdminRotateDoesNotRevoke`). Dafür gibt es `revoke`.
- **`publish` mit Feld 7** prüft den Pin gegen das Log, bevor es etwas schreibt: Der neueste veröffentlichte Kopf muss sich öffnen lassen und das Zeugenquorum des Pins tragen, `<N>` darf nicht größer sein als seine Größe und `<T>` nicht später als seine Zeit und nicht vor dem 01.01.2025, und das Zertifikat jeder widerrufenen Admin- oder Ingest-Generation muss unterhalb von `<N>` gültig im Log stehen (sonst ist die Generation vertippt, und das Element sperrte die Rolle für immer); liegt bei einer Ingest-Generation `revoked_at_time` nicht nach dem `valid_from` ihres Zertifikats, obwohl die Generation am neuesten Kopf schon galt, wäre sie nie gültig gewesen (`… it would never have been valid …`; `TestRevocationTimes`). Diese Prüfung „nie gültig“ gilt seit Auftrag 22 nur für Ingest: Für eine Admin-Generation hat `revoked_at_time` keine Bedeutung, ihre Zuordnungen beurteilt das Log nach dem Logindex ab `<N>` (D93 (2) und Nachtrag 22). Nach unten begrenzt ist `<T>` bei ihr nur durch den 01.01.2025; eine Grenze aus einem Kopf, der älter ist als die Admin-Generation, nimmt `publish` an (`checkRevocations` in `internal/ceremony/publish.go`, `TestRevocationTimes`). Bei Erfolg meldet es `Widerrufe des Pins (<k>) geprüft gegen den neuesten bestätigten Kopf (Größe …, Zeit …).`, sonst `ceremony: invalid revocation: …` mit Exit 1. Es warnt auf der Standardfehlerausgabe und veröffentlicht trotzdem, wenn eine widerrufene Ingest-Generation noch keine lückenlose Nachfolgerin hat (`WARNUNG: Ingest-Generation <i> ist ab … widerrufen, ingest-<i+1>.cert gibt es noch nicht: …`) und wenn der neueste Kopf die Logsignatur einer Generation trägt, die der Pin für seine Zeit widerruft (`WARNUNG: der neueste Kopf (Größe …, Zeit …) trägt die Logsignatur von Ingest-Generation <i>, die der Pin ab … widerruft: Clients verwerfen ihn, gomail-server log repair verschiebt ihn nach log/heads-revoked/. …`; `TestPublishRevokedHead`). Was der Pin ab der Grenze ungültig macht (etwa ein Zertifikat der widerrufenen Identität), verweigert es mit `translog: log entry violates a validity rule: platform generation revoked by the pin: … which the pin revokes (field 7); nothing written`. Ein Zertifikat ohne Vorgängerin im Export oder als gültigen Logeintrag verweigert es, bevor es eine Datei schreibt (`translog: … needs <rolle>-<g-1>.cert, which is neither in the export nor a valid entry of the log …`).
- **Zertifikate des Diebs in `platform/`:** Hat der Dieb mit einer widerrufenen Identität ab `<N>` ein Zertifikat geloggt und in `platform/` gelegt, ist es ungültig, und sein Name ist frei. `publish` ersetzt die Datei samt `.pub` atomar durch die Neuausstellung gleichen Namens (`TestPublishReissueAfterThief`). Eine Datei, deren Name einen gültigen Logeintrag hat, ersetzt `publish` nie durch anderen Inhalt (`store: file exists: translog: duplicate log entry: … is a valid entry of the log under this pin with other content than the export's: a valid entry is never replaced`; `TestPublishValidEntryKept`). Das gilt auch für ein Zertifikat, das der Dieb vor `<N>` gültig geloggt hat: Es belegt seinen Namen, und die Neuausstellung braucht die Generation über ihm (7.3.2 „Welcher Kopf“, 7.3.5 Schritt 2). Liegt seine Datei in `platform/`, verweigert `publish` die Neuausstellung gleichen Namens mit dieser Meldung, bevor es etwas schreibt. Liegt dort ein symbolischer oder harter Link, verweigert es ebenso, bevor es schreibt, mit der Meldung zum Link und dem Hinweis `… publish the export that holds the logged <role>-<g>.cert, which replaces the link, or, if that entry is the thief's, reissue under the next generation (RUNBOOK 7.3)` (Auftrag 24, Paket A; `TestPublishLinkOverValidEntry`; „Fremde Dateien in `platform/`“, Fall 4). Liegt nur seine `<role>-<g>.pub` dort, verweigert `publish` ebenso, bevor es schreibt, mit der Meldung zur `.pub` (`store: file exists: …/<role>-<g>.pub with other content than … of the export, and <role>-<g>.cert is a valid entry of the log …: a valid entry is never replaced`, ohne `translog: duplicate log entry:`); die `.pub` bleibt liegen. Liegt keine der beiden Dateien dort, schlägt `publish` den Namen vor dem Schreiben nicht im Log nach: Es schreibt `<role>-<g>.cert` des Exports nach `platform/`, ebenso `<role>-<g>.pub`, wenn sie dort fehlt, und scheitert erst beim Loggen mit `ceremony: logging <role>-<g>.cert: translog: duplicate log entry: key taken by entry <k>` (Exit 1; Einträge, die `publish` vorher geloggt hat, etwa Nachfolgen, bleiben). Die geschriebenen Dateien bleiben in `platform/`. Eine Wiederholung verweigert seit Auftrag 24 (Paket A, F4 der Prüfung; `sameButLogged`, `TestPublishSameOverValidEntry`), bevor sie etwas schreibt: Eine Datei in `platform/`, die gleich der des Exports ist und deren Name einen gültigen Logeintrag mit anderem Inhalt hat, ergibt `store: file exists: translog: duplicate log entry: <datenverzeichnis>/platform/<role>-<g>.cert is the same as <export>/platform/<role>-<g>.cert of the export, and <role>-<g>.cert is a valid entry of the log under this pin with other content: a valid entry is never replaced` (Exit 1). Das gilt für Zertifikate und Nachfolgen, nicht für eine `.pub`. Abhilfe: diese `<role>-<g>.cert` und die mit ihr geschriebene `<role>-<g>.pub` aus `platform/` entfernen (sie sind gleich den Dateien des Exports und stehen nicht im Log; das Verbot im nächsten Satz gilt für sie nicht), dann mit der Generation über dem Zertifikat des Diebs neu ausstellen (7.3.5 Schritt 2). **Alte Plattformzertifikate nie von Hand aus `platform/` entfernen**, auch die widerrufener Generationen nicht: Die Clients brauchen sie weiter, etwa um Mails und geänderte Flags späterer Generationen zu prüfen (`checkReceivedCovered`, 7.3.2 „Folge für Mails“).
- **Fremde Dateien in `platform/`** (Auftrag 22, Commit 3cd9072, im Arbeitsbranch afad8de; `freeName` in `internal/ceremony/publish.go`; D93 Nachtrag 22): Liegt unter einem geloggten Namen eine fremde Datei, etwa weil jemand mit Schreibrecht auf `platform/` die Datei nach einem früheren `publish` überschrieben hat, setzt eine Wiederholung derselben `publish`-Ausführung (derselbe Export mit dem aktuellen Pin; nach einer Nachfolge lehnt der alte Pin ab, `… names identity generation <g>, the pin knows 1 to <n>; …` aus `checkDataPlatform` oder `checkDataLog`) sie atomar auf die Datei des Exports zurück, die der Logeintrag ist. Das gilt auch für eine fremde `.pub` unter einem geloggten Admin- oder Ingest-Zertifikat (`TestPublishHealsPlatform`, `TestPublishHealsOverwrittenCert`, `TestPublishHealsForeignPub` in `internal/ceremony/heal22_test.go`). Vier Fälle heilt `publish` nicht (Fall 4 nur, wenn `freeName` den Namen nicht freigibt); es verweigert mit Exit 1, bevor es etwas schreibt (nur bei einem Link, der erst während `publish` entsteht, nach anderen Dateien, Fall 4), oder bemerkt den Fall gar nicht (Angreiferprüfung von 22, N1 bis N3, `docs/tasks/20-notes.md`; Fall 4 seit Auftrag 24, Paket A):
  1. ein Zertifikat oder eine Nachfolge, die sich nicht dekodieren lässt (`platform/<name>: …` mit dem Fehler des Dekodierens);
  2. ein Zertifikat oder eine Nachfolge, die sich nicht mit dem Pin verifizieren lässt oder etwas anderes nennt als ihr Name (`translog: data directory contradicts the log: platform/<name> …`, für ein Zertifikat etwa `… does not verify with identity generation <g> of the pin (…); check where it came from and remove it`), ebenso eine fremde `identity-<g>.pub` (`… platform/identity-<g>.pub contradicts the identity list of the pin`; eine Identitäts-`.pub` ersetzt `publish` nie) und eine Datei, die eine Identitätsgeneration über der des Pins nennt (`… names identity generation <g>, the pin knows 1 to <n>; install the new pin (on the server as well) before publish (Q10 point 5)`; nach einer eigenen Nachfolge mit dem aktuellen Pin wiederholen, sonst ist die Datei fremd). Beide Fälle lehnt `checkDataPlatform` ab, bevor `publish` die Namen im Log nachschlägt;
  3. eine einzelne fremde `.pub`, deren Zertifikat nicht geloggt ist und im Datenverzeichnis fehlt oder gleich dem des Exports ist (`store: file exists: … is no valid entry of the log: a public key is replaced only together with its certificate or under its logged certificate`; `TestPublishHealsForeignPub`);
  4. ein Link unter einem Namen des Exports, seit Auftrag 24 (Paket A; `readEntry`, `linkErr` in `internal/ceremony/publish.go`; D93 Nachtrag 24). `publish` sieht jeden Namen des Exports zuerst mit `os.Lstat` an. Ein symbolischer Link, auch ein hängender, und eine reguläre Datei mit einem weiteren Namen (harter Link, `Nlink > 1`; ein Name `.tmp-*` in `platform/`, den ein Absturz von `store.CreateFileAtomic` hinterließ, zählt nicht) gelten nie als gleich der Datei des Exports, worauf sie auch zeigen. Gibt `freeName` den Namen frei, ersetzt `WriteFileAtomic` den Eintrag selbst per `rename`, nie das Linkziel und nie die Datei unter ihrem anderen Namen; so heilt eine Wiederholung auch einen Link auf den geloggten Inhalt (`TestPublishLinkToLoggedContent`, `TestPublishDanglingLink`, `TestPublishLinkedCertFreesPub`, `TestV22SymlinkOverLogged` in `publishlink24_test.go`; `TestPublishHardLinkUnderName`, `TestPublishCrashTempNotHardLink` in `publishlink24b_unix_test.go`). Sonst verweigert `publish` mit Exit 1, bevor es etwas schreibt, mit einer eigenen Meldung, die den Link nennt, nicht sein Ziel: `store: file exists: translog: duplicate log entry: <datenverzeichnis>/platform/<name> is a symbolic link, never taken for <export>/platform/<name> of the export<grund>; nothing written: <hinweis>`. Bei einem harten Link steht `a hard link` statt `a symbolic link`, bei einer `.pub` fehlt `translog: duplicate log entry:`, und `<grund>` ist der Zusatz von `freeName` wie in den Meldungen `… with other content than …` (8.6). Hat der Name einen gültigen Logeintrag mit anderem Inhalt, lautet `<hinweis>` `look at the link; publish the export that holds the logged <role>-<g>.cert, which replaces the link, or, if that entry is the thief's, reissue under the next generation (RUNBOOK 7.3)` (`TestPublishLinkOverValidEntry`), sonst `look at the link and remove it by hand`, etwa für einen Link als `identity-<g>.pub` (eine Identitäts-`.pub` ersetzt `publish` nie). Entsteht ein Link erst während `publish` unter einem Namen, der beim Vergleich fehlte, prüft auch der Zweig „written meanwhile“ den Eintrag mit `readEntry` und endet in der Schreibschleife mit `… of the export (written meanwhile); nothing logged: look at the link, remove it by hand and run the same publish again` (`TestPublishMeanwhileLink`); andere Dateien des Exports können dann schon geschrieben sein. Ein FIFO, ein Gerät oder ein Verzeichnis direkt unter einem Namen des Exports ersetzt `publish` nie (ein Verzeichnis lässt sich nicht per `rename` ersetzen); es verweigert, bevor es schreibt, mit `store: <name> is not a regular file` (`TestPublishNonRegularUnderName`). Anders geprüft werden `witnesses.rec` und eine Nachfolge, die weder im Export noch gültig im Log steht und die `publish` für die Kette braucht: Dort folgt `readData` einem Link weiter. Ein Link auf ein FIFO, ein Gerät oder ein Verzeichnis ergibt dort dieselbe Meldung (8.6), ein Link auf eine reguläre Datei fällt nicht auf. Links unter Namen, die `publish` nicht liest, bemerkt es nicht. Restgrenzen (Prüfungen von Auftrag 24, Paket A, niedrig): `os.Lstat` und das Lesen danach arbeiten über den Pfad, ohne `O_NOFOLLOW`; wer `platform/` während `publish` beschreiben kann, kann den Eintrag zwischen beiden tauschen (F3). Einen weiteren Namen `.tmp-*` in `platform/` zählt `publish` nie als fremden Namen, auch wenn ihn kein Absturz hinterlassen hat; anlegen kann ihn nur, wer `platform/` ohnehin beschreiben kann.

  Diese Dateien entfernt der Betreiber von Hand: ansehen, außerhalb des Datenverzeichnisses aufbewahren (wie in 8.2), nicht ungesehen löschen, dann denselben `publish` wiederholen. Nach jedem `publish` und bei jeder dieser Meldungen prüfen, dass es keine Links gibt: `find <datenverzeichnis>/platform \( -type l -o -type f -links +1 \)` muss leer bleiben; nur nach einem Absturz beim Schreiben in `platform/` darf ein Name `.tmp-*` zusammen mit der Datei erscheinen, deren zweiter Name er ist. Seit Auftrag 24 ersetzt `publish` einen Link unter einem Namen des Exports selbst, wenn der Name frei ist; `find` braucht es für Links, die `publish` nicht prüft (Fall 4). Das Verbot oben gilt weiter für alle echten, geloggten Plattformdateien.
- Jeder Folge-Pin übernimmt Feld 7, auch der eines späteren `succeed` (7.1); ein Widerruf geht nie verloren.

#### 7.3.1 Welcher Fall?

| Lage | Vorgehen |
|---|---|
| Der Ingest-Schlüssel (zugleich Log-Schlüssel, Q4) kann in fremden Händen sein: Server-Host übernommen, Kopie aufgetaucht, Sicherung abhandengekommen | Widerruf und neue Ingest-Generation (7.3.3) |
| Der Ingest-Schlüssel ist verloren und sicher nirgends sonst (Datenträger defekt oder vernichtet) | neue Ingest-Generation nach Abschnitt 6, ohne Widerruf |
| Der Admin-Schlüssel kann in fremden Händen sein | Widerruf und neue Admin-Generation (7.3.4) |
| Der Admin-Schlüssel ist verloren und sicher nirgends sonst | neue Admin-Generation (7.3.4 ohne Widerruf) |
| Eine Identitätsgeneration ist kompromittiert, Root und Anteile nicht | `succeed --compromised` mit Neuausstellung von Admin und Ingest (7.3.5) |
| Der Root ist kompromittiert, oder so viele Anteile sind in fremden Händen, wie die aktuelle Aufteilung zur Rekonstruktion braucht (bei 3-of-5 drei) | neue Plattform (7.3.6) |
| Ein Zeuge meldet einen Fork (Exit 3, 1.7) | Ein Widerruf hilft nicht: Der Zeuge signiert für diesen Origin nie wieder, ohne sein Quorum bekommt das Log keine Köpfe mehr. Neue Plattform (7.3.6, Abschnitt 8) |

Im Zweifel gilt ein Schlüssel als kompromittiert, nicht als verloren: Eine Rotation allein (`ingest-rotate`, `admin-rotate`) beendet die alte Generation erst ab `valid_from` der neuen und verhindert keine rückdatierten Signaturen. Der Identitätsschlüssel existiert nur während einer Zeremonie im Speicher. Wer ihn hat, hatte meist auch den Root; dann gilt 7.3.6.

Ohne Admin-Schlüssel gibt es bis zum `valid_from` der neuen Admin-Generation keine neue Adresszuordnung; die vorhandenen bleiben gültig. Ohne Ingest-Schlüssel nimmt der Server keine Mail an und signiert keine Köpfe; nach 24 Stunden ohne Kopf stoppen alle Clients, bis der neue Schlüssel läuft (Abschnitt 10).

#### 7.3.2 Grenze ablesen

Vor jeder Zeremonie mit Widerruf (7.3.3 bis 7.3.5). Ist der Ingest-Schlüssel oder die Identität betroffen, zuerst den Server anhalten (SIGTERM, 8.5) und **erst danach** die Grenze ablesen, sodass der Server am abgelesenen Kopf steht: Ein laufender Server signiert Köpfe gleicher Größe mit späterer Zeit neu und ersetzt damit `log/heads/<n>.sig`; `log repair` verschiebt einen solchen Kopf nach der Zeremonie, und dann bleibt kein bestätigter Kopf, aus dem die Grenze stammt (`publish` verweigert dann, weil `<N>` größer ist als der neueste Kopf). Außerdem: Was die Ingest-Generation nach `<T>` signiert, lehnen Clients mit dem neuen Pin ab, nach einer kompromittierten Identität auch bei der eigenen Ingest-Generation (Kaskade). Bei einem Admin-Schlüssel läuft der Server weiter.

Auf dem Zeugenhost den letzten Kopf lesen, den der Zeuge mitsigniert hat (1.7). Der Zeuge speichert nur Köpfe, die er bestätigt hat:

```
h=$(printf '%s' '<origin>' | sha256sum | cut -c1-64)
sed -n '2p;4p' <zustandsverzeichnis>/$h.head
```

Die erste Zeile der Ausgabe ist die Größe `<N>`, die zweite lautet `time <T>` (Millisekunden seit 1970 UTC). Genau diese beiden Zahlen gehören in `--revoke-at-size` und `--revoke-at-time`; die Millisekunde addiert die Zeremonie selbst. Beide Werte auf Papier notieren und zum Zeremonierechner bringen; er ist offline. Bei mehreren Zeugen von jedem den Kopf lesen und den mit der kleinsten Größe nehmen: Die Zeugen setzen ein und dasselbe Log fort, der kleinste Kopf ist also die früheste bestätigte Grenze.

Ohne Zugang zum Zeugenhost gibt der Server-Host denselben Wert: Der Server schreibt `log/heads/<n>.sig` erst mit dem Quorum der Zeugen, und die Datei mit dem größten `<n>` ist der neueste Kopf:

```
ls <datenverzeichnis>/log/heads | sort -n | tail -n 1
sed -n '2p;4p' <datenverzeichnis>/log/heads/<n>.sig
```

Ist der Server-Host selbst verdächtig, nur den Wert vom Zeugenhost nehmen.

**Welcher Kopf.** Alles, was die widerrufene Generation vor `<N>` ins Log gebracht hat, und Metadaten mit einer Empfangszeit bis `<T>` bleiben gültig, auch was ein Dieb bis dahin signiert hat (Restrisiko, 2.3 des Plans, Regel 4). Ist bekannt, seit wann der Schlüssel in fremden Händen sein kann, einen Kopf von vorher nehmen: eine ältere Datei aus `log/heads/` mit einer Zeit vor diesem Zeitpunkt. Ihre Zeugensignaturen prüft im PoC kein Befehl (wie 8.7 Schritt 2); deshalb nur aus einem Datenverzeichnis, das nicht verdächtig ist. `publish` nimmt eine solche ältere Grenze an (`<N>` und `<T>` höchstens Größe und Zeit des neuesten Kopfes). Sonst den neuesten bestätigten Kopf nehmen. Zwei Fälle verlangen eine Grenze vor dem ersten Eintrag des Diebs (`internal/translog/doc.go`, „Reading for the operator“; einen Befehl, der die Einträge einer Generation auflistet, gibt es nicht):

- Ein Dieb mit dem Admin-Schlüssel kann vor der Grenze eine Zuordnung mit weit in der Zukunft liegendem `valid_from` loggen. Sie bleibt gültig; der Nachfolger kann die Adresse nicht neu zuordnen, weil `valid_from` steigen muss, und ab jener Zeit gehört die Adresse dem Dieb (`TestRevokedFarFutureFreeze`). Abhilfe: `<N>` höchstens beim Index des ersten solchen Eintrags; ehrliche Zuordnungen ab dort ordnet der Administrator neu zu (7.3.4 Schritt 7).
- Ein Dieb mit der Identität kann vor der Grenze eigene Admin- und Ingest-Zertifikate loggen. Sie handeln ab der Grenze nicht mehr (Kaskade), belegen aber ihren Namen: Die Neuausstellung braucht dann die nächste Generation. Liegt die Grenze vor ihnen, sind sie ungültig, und die Neuausstellung nimmt ihren Namen; `publish` ersetzt die Datei des Diebs (7.3, „Zertifikate des Diebs“).

**Folge für Mails (Ingest, Identität):** Mails, die der Server nach `<T>` und vor dem Anhalten mit der widerrufenen Generation angenommen hat, lehnen Clients mit dem neuen Pin ab (`WARNUNG: Mail <id> wird nicht verarbeitet: Generation widerrufen.`, 4.4). Der Server signiert spätestens nach `--head-interval` (Standard 1 h) einen Kopf, der Zeitraum ist also meist kürzer. Diese Mails sind für die Benutzer verloren. Dasselbe gilt für spätere Versionen ihrer Metadaten (geänderte Flags, Übernahme nach einem Geräteverlust), die ein Gerät mit dem alten Pin signiert hat: Für eine Version ab 2 prüft der Client, dass die Empfangszeit im Zeitraum einer gültigen Ingest-Generation liegt, die der Pin dafür nicht widerruft (`checkReceivedCovered`; `TestLogFlagLaundering`, `TestLogFlagsAcrossGenerations`). Mails, die während des Stillstands eingeliefert werden sollen, wiederholen die Absender später.

#### 7.3.3 Ingest-Schlüssel kompromittiert

`<i>` ist die kompromittierte Ingest-Generation, `<i+1>` die nächste (die höchste Ingest-Generation in `platform/ingest-*.cert` + 1, wie in Abschnitt 6). `<pin>` ist der aktuelle Pin `identity-<g>.pin`.

1. **Server anhalten, Grenze ablesen** (7.3.2). Der Server bleibt bis Schritt 7 angehalten. Ist der Server-Host verdächtig, auch die Zeugen anhalten; sie starten erst in Schritt 6 mit nur dem neuen Log-Schlüssel. Ab `<T>` laufen die 24 Stunden aus Abschnitt 10: Dauern die Schritte länger, stoppen die Clients, bis der Server mit dem neuen Schlüssel läuft; Daten gehen dabei nicht verloren.
2. **Zeremonie offline** (`<k>` Anteilsinhaber der aktuellen Aufteilung, bei 3-of-5 drei; Uhr gestellt; Abschnitte 2 und 10), **zuerst `revoke`, dann `ingest-rotate` mit dem neuen Pin**:

   ```
   gomail-ceremony revoke --pin <pin> --out <export-widerruf> --role ingest --generation <i> \
       --revoke-at-size <N> --revoke-at-time <T>
   gomail-ceremony ingest-rotate --pin <export-widerruf>/identity-<g>.pin --gen <i+1> --out <export-i+1> \
       --keys <schlüssel> --valid-from <T+1 ms>
   ```

   `<T+1 ms>` ist genau die Zeit, die `revoke` in seiner letzten Zeile nennt (RFC 3339, Bruchteile ohne Nullen am Ende, etwa `2026-11-03T10:15:30.124Z`). `ingest-rotate` verlangt mit einem Pin, der die Vorgängerin widerruft, genau diesen Wert und verweigert jeden anderen vor dem ersten Anteil (`ceremony: invalid revocation: valid_from … must be revoked_at_time … of the revoked predecessor (D93)`): Ein späteres `valid_from` ließe eine Zeit ohne gültige Ingest-Generation, in der kein Kopf signiert werden kann; ein früheres machte Signaturen von `<i>` vor der Grenze ungültig. Das `valid_from` liegt damit in der Vergangenheit; das ist nur nach einem Widerruf erlaubt (hier und in 7.3.5). Ergebnis: in `<export-widerruf>` der neue Pin `identity-<g>.pin` (im Folgenden `<neuer-pin>`), in `<export-i+1>` `ingest-<i+1>.pub` und `.cert`, dazu `<schlüssel>/ingest-<i+1>.key` (0600).
3. **`log repair` mit dem neuen Pin** (8.2), bei weiter angehaltenem Server:

   ```
   gomail-server log repair --data <datenverzeichnis> --pin <neuer-pin>
   ```

   Köpfe, die `<i>` nach `<T>` signiert hat, gehören unter dem neuen Pin nicht zum Log. `log repair` verschiebt sie nach `log/heads-revoked/` und nennt jede Datei (`log/heads/<n>.sig von einer widerrufenen Generation signiert (Pin-Feld 7), verschoben nach log/heads-revoked/<n>-<hex>.sig`); die Schlussmeldung zählt sie (`…; <k> Köpfe einer widerrufenen Generation nach log/heads-revoked verschoben`). Die verschobenen Dateien sind Belege; nie löschen. Ohne diesen Schritt warnt `publish`, wenn der neueste Kopf ein solcher ist (7.3, „`publish` mit Feld 7“), und der Server stoppt später beim Signieren (`… head signed only by an ingest generation the pin revokes …`, 8.2).
4. **Veröffentlichen** mit dem neuen Pin, weiter bei angehaltenem Server, **bevor** der Pin verteilt wird; erst `publish` prüft Grenze und Generation gegen das Log (7.3, „`publish` mit Feld 7“):

   ```
   gomail-ceremony publish --from <export-i+1> --data <datenverzeichnis> --pin <neuer-pin>
   ```

5. **Pin verteilen** an Administrator und alle Clients (getrennter Weg, wie 1.3; auf dem Server-Host liegt er seit Schritt 3), dort den alten Pin ersetzen. Solange ein Client den alten Pin hat, nimmt er an, was der Dieb mit Generation `<i>` signiert.
6. **Zeugen:** Den Prüfschlüssel von `<i+1>` nach 1.7 bilden, aus `<export-i+1>/platform/ingest-<i+1>.pub`, und jeden Zeugen **nur** mit dem neuen Log-Schlüssel neu starten (`--log-key <neu>`, gleiches Zustandsverzeichnis). Anders als in Abschnitt 6 entfällt der alte Log-Schlüssel sofort; der Zeuge bestätigt dann keinen Kopf mehr, den der kompromittierte Schlüssel signiert. Sein gespeicherter Kopf bleibt ohne den alten Schlüssel verwendbar.
7. **Server starten** mit dem neuen Pin und dem neuen Schlüssel. `valid_from` von `ingest-<i+1>.cert` ist vorbei, er startet sofort:

   ```
   gomail-server serve --data <datenverzeichnis> --listen 127.0.0.1:2525 --ingest-key <ingest-<i+1>.key> \
       --pin <neuer-pin> --log-listen <log-adresse> [...]
   ```

   Mit dem alten Schlüssel und dem neuen Pin verweigert er mit Exit 2: `der Ingest-Schlüssel gehört zu einer Generation, die der Pin widerruft (Feld 7); den Server nur mit dem Schlüssel einer neu ausgestellten Ingest-Generation starten` (`TestServeRevoked`).
8. **Alten Schlüssel vernichten**, alle Kopien, auch in Sicherungen.
9. **Prüfen:**
   - `gomailctl inspect <neuer-pin>` zeigt in `revoked` ein Element mit `role` 2 (Ingest), `gen` `<i>`, `revoked_at_size` `<N>` und `revoked_at_time` `<T>` + 1.
   - Nach dem Start erscheint ein neuer Kopf `log/heads/<n>.sig` mit Zeugensignatur (1.7).
   - Eine Testmail an eine eigene Adresse (4.3) ergibt `status=250`. Ein Client mit dem neuen Pin zeigt sie nach `sync` mit `list` (4.4).
   - Mails aus dem Zeitraum nach `<T>` erscheinen als Warnung mit der Ursache `Generation widerrufen` (7.3.2, „Folge für Mails“); das ist erwartet (`TestRevokedIngestEndToEnd`).

#### 7.3.4 Admin-Schlüssel kompromittiert oder verloren

`<a>` ist die aktuelle Admin-Generation, `<a+1>` die neue. Generation `<a>` ordnet nur bis `valid_from` von `admin-<a+1>.cert` gültig zu, sobald dieses Zertifikat im Log steht (D93 (3)). Ist der Schlüssel nur verloren und sicher nirgends sonst, entfallen `revoke` und Schritt 1; `admin-rotate` läuft dann mit dem bisherigen Pin, und `publish` nimmt ihn. Ohne Widerruf entfallen auch Schritt 4 und der Pinwechsel in Schritt 5.

1. **Grenze ablesen** (7.3.2). Der Server läuft weiter.
2. **Zeremonie offline** (`<k>` Anteilsinhaber, Uhr gestellt), zuerst `revoke`, dann `admin-rotate` mit dem neuen Pin:

   ```
   gomail-ceremony revoke --pin <pin> --out <export-widerruf> --role admin --generation <a> \
       --revoke-at-size <N> --revoke-at-time <T>
   gomail-ceremony admin-rotate --pin <export-widerruf>/identity-<g>.pin --gen <a+1> --out <export-a+1> \
       --keys <schlüssel> --valid-from <RFC3339>
   ```

   `--valid-from` darf nicht in der Vergangenheit liegen; bis dahin gibt es keine neue Zuordnung. Ergebnis: `<neuer-pin>` wie in 7.3.3 Schritt 2, `<export-a+1>` mit `admin-<a+1>.pub` und `.cert`, `<schlüssel>/admin-<a+1>.key` (0600). Die Ausgabe von `admin-rotate` erinnert: `Die bisherige Admin-Generation ordnet nur bis <valid-from> gültig zu; ist ihr Schlüssel entwendet, sie mit revoke widerrufen.`
3. **Veröffentlichen** bei angehaltenem Server (SIGTERM), vor dem Verteilen: `gomail-ceremony publish --from <export-a+1> --data <datenverzeichnis> --pin <neuer-pin>` (ohne Widerruf mit dem bisherigen Pin). Ein Admin-Widerruf macht keinen Kopf ungültig; `log repair` ist nicht nötig.
4. **Pin verteilen** an Server-Host, Administrator und alle Clients, wie 7.3.3 Schritt 5.
5. **Server neu starten** mit dem neuen Pin und dem bisherigen Ingest-Schlüssel (1.6).
6. **Neuer Admin-Schlüssel:** `admin-<a+1>.key` zum Administrator (0600, nicht auf den Server-Host, 1.3), den alten vernichten. Ab `<valid-from>` ordnet er mit `address add … --admin-key <admin-<a+1>.key> --pin <neuer-pin>` zu (4.2). Vorher scheitert `address add` mit dem neuen Schlüssel (`… assignment before the admin certificate`, Exit 1, 4.2). Mit dem alten Schlüssel und dem neuen Pin verweigert es mit Exit 2, bevor etwas ins Log kommt: `der Admin-Schlüssel gehört zu einer Generation, die der Pin widerruft (Feld 7); Zuordnungen nur mit dem Schlüssel einer neu ausgestellten Admin-Generation` (`TestAddressAddRevoked`). Ohne Widerruf scheitert der alte Schlüssel ab `<valid-from>` am Log (`… dated after its successor's valid_from`, Exit 1).
7. **Zuordnungen nach der Grenze:** Zuordnungen, die Generation `<a>` ab Logindex `<N>` ins Log gebracht hat, gelten nicht mehr. Eine solche Zuordnung ist für Clients mit dem neuen Pin kein gültiger Logeintrag: Mails an die Adresse lehnen sie mit der Ursache `Adresse nicht zugeordnet` ab, oder es gilt die ältere gültige Zuordnung (4.4; `TestLogAdminRevoked`). Legitime Zuordnungen aus diesem Bereich ordnet der Administrator mit dem neuen Schlüssel neu zu. Das Log kennt nur gültige Einträge (`Lookup`), deshalb nimmt `address add` die erneute Zuordnung derselben Adresse zum selben Postfach an, sofern ihr `valid_from` nach dem der letzten gültigen Zuordnung liegt (4.2). Nennt `addresses.json` für die Adresse ein anderes Postfach, verweigert es mit Exit 2 (`Adresse bereits zugeordnet`, 4.2; kein Test für diesen Fall). Einen Befehl, der die Zuordnungen ab `<N>` auflistet, gibt es im PoC nicht (wie 8.7 Schritt 2).
8. **Prüfen:**
   - `gomailctl inspect <neuer-pin>` zeigt in `revoked` `role` 1 (Admin), `gen` `<a>`, `revoked_at_size` `<N>` und `revoked_at_time` `<T>` + 1.
   - Nach `<valid-from>` gelingt `address add` einer Testadresse mit dem neuen Schlüssel. Eine Testmail an sie erscheint bei einem Client mit dem neuen Pin.

#### 7.3.5 Identität kompromittiert

Nur wenn Root und Anteile sicher sind (7.3.1). `<g>` ist die kompromittierte Identitätsgeneration; `<a>` und `<i>` sind die aktuellen Admin- und Ingest-Generationen. Durch die Kaskade handeln beide ab der Grenze nicht mehr: `<a>` ordnet ab `<N>` nichts gültig zu, `<i>` signiert nach `<T>` keinen Kopf und keine Metadaten gültig. Ein eigener `revoke` für `<a>` oder `<i>` ist deshalb nicht nötig. Der Server wechselt auf eine neue Ingest-Generation.

1. **Server anhalten, Grenze ablesen** (7.3.2).
2. **Zertifikate des Diebs** in `platform/` (aus keiner eigenen Zeremonie, `gomailctl inspect` zeigt `identity_gen` `<g>`) nicht von Hand entfernen: Liegt die Grenze vor ihrem Logeintrag, ersetzt `publish` sie durch die Neuausstellung gleichen Namens (7.3, „Zertifikate des Diebs“). Stehen sie vor der Grenze gültig im Log, bleiben sie, und `<a+1>` bzw. `<i+1>` ist die Generation über ihnen. Ein Zertifikat des Diebs, das vor der Grenze gültig im Log steht, aber nicht in `platform/` liegt, zeigt sich erst bei `publish` in Schritt 5: Liegt seine `.pub` dort, mit `store: file exists: …/<role>-<g>.pub …, and <role>-<g>.cert is a valid entry …` (nichts geschrieben), sonst mit `ceremony: logging <name>: … key taken by entry <k>`; im zweiten Fall die geschriebenen Dateien nach 7.3, „Zertifikate des Diebs“, entfernen. In beiden Fällen die Rotation aus Schritt 3 mit der Generation darüber wiederholen.
3. **Zeremonie offline** (`<k>` Anteilsinhaber, Uhr gestellt), alle drei Befehle nacheinander:

   ```
   gomail-ceremony succeed --compromised --pin <identity-g.pin> --out <export-g+1> \
       --revoke-at-size <N> --revoke-at-time <T>
   gomail-ceremony admin-rotate --pin <export-g+1>/identity-<g+1>.pin --gen <a+1> --out <export-a+1> \
       --keys <schlüssel> --valid-from <RFC3339>
   gomail-ceremony ingest-rotate --pin <export-g+1>/identity-<g+1>.pin --gen <i+1> --out <export-i+1> \
       --keys <schlüssel> --valid-from <T+1 ms>
   ```

   `succeed --compromised` schreibt keine Nachfolge `identity-<g+1>.succ`, sondern `platform/identity-<g+1>.pub` und den neuen Pin `<export-g+1>/identity-<g+1>.pin`. Er nennt `<g+1>` in der Identitätsliste und `<g>` in Feld 7. Origin, Zeugen und Quorum kommen wie in 7.1 aus dem alten Pin. Die Ausgabe lautet `Identitätsgeneration <g+1> erzeugt, ohne Nachfolge; Generation <g> ist widerrufen.` und endet mit `Pflicht: Admin und Ingest unter Generation <g+1> neu ausstellen: admin-rotate und ingest-rotate mit --pin …; die neue Ingest-Generation mit --valid-from <T+1 ms> (nicht später).` **Die Neuausstellung ist Pflicht** (2.3 des Plans, Regel 6). Für `ingest-rotate` genau den Wert nehmen, den `succeed` nennt: Ein früheres `valid_from` verweigert `ingest-rotate` (`… is before revoked_at_time … of the compromised identity generation`), ein späteres nimmt es an und warnt vor dem ersten Anteil (`WARNUNG: --valid-from … liegt nach der Widerrufszeit … der kompromittierten Identitätsgeneration <g>. … dann --valid-from <T+1 ms>. Weicht das ab, jetzt mit Strg-C abbrechen.`), aber `publish` verweigert es dann (`ceremony: invalid revocation: ingest-<i+1>.cert is valid from …, after ingest generation <i> is revoked …; make it valid from <T+1 ms> (ingest-rotate --valid-from)`), und die Rotation muss wiederholt werden (`TestSucceedCompromised` in `cmd/gomail-ceremony`). Für `admin-rotate` gilt „nicht in der Vergangenheit“.
4. **`log repair` mit dem neuen Pin** wie 7.3.3 Schritt 3: Köpfe, die `<i>` nach `<T>` signiert hat, gehören wegen der Kaskade nicht mehr zum Log.
5. **Veröffentlichen** bei angehaltenem Server, mit dem neuen Pin, vor dem Verteilen, in dieser Reihenfolge:

   ```
   gomail-ceremony publish --from <export-g+1> --data <datenverzeichnis> --pin <identity-g+1.pin>
   gomail-ceremony publish --from <export-a+1> --data <datenverzeichnis> --pin <identity-g+1.pin>
   gomail-ceremony publish --from <export-i+1> --data <datenverzeichnis> --pin <identity-g+1.pin>
   ```

   `publish` nimmt `<g+1>` ohne `identity-<g+1>.succ` an, weil der Pin `<g>` widerruft; mit dem alten Pin verweigert es (`… install the new pin …`). Die ersten beiden Aufrufe warnen, dass Ingest-Generation `<i>` widerrufen ist und `ingest-<i+1>.cert` noch fehlt; das ist bis zum dritten Aufruf erwartet. Ein Zertifikat, das `<g>` ab der Grenze ausgestellt hat, verweigert `publish` (`… which the pin revokes (field 7); nothing written`).
6. **Pin verteilen** an Server-Host, Administrator und alle Clients, wie 7.3.3 Schritt 5. Clients mit dem alten Pin kennen `<g+1>` nicht, denn im Log steht keine Nachfolge. Sie nehmen weiter an, was der Dieb mit `<g>` ausstellt; `ingest-<i+1>.cert` können sie nicht prüfen und lehnen deshalb jede Mail und jeden Kopf der neuen Ingest-Generation ab (der Client nimmt Identitätsschlüssel nur aus seinem Pin oder aus geloggten Nachfolgen, `ingestKeyFor` in `internal/client/read.go`; kein Test). Spätestens 24 Stunden nach dem letzten Kopf von `<i>` stoppen sie (Abschnitt 10).
7. **Zeugen** nur mit dem neuen Log-Schlüssel, wie 7.3.3 Schritt 6.
8. **Server starten** mit dem neuen Pin und `ingest-<i+1>.key`, wie 7.3.3 Schritt 7; `valid_from` ist vorbei. Mit dem alten Schlüssel verweigert er mit Exit 2 wie in 7.3.3 Schritt 7 (`der Ingest-Schlüssel gehört zu einer Generation, die der Pin widerruft (Feld 7); …`): Die Identität, die `ingest-<i>.cert` ausgestellt hat, ist widerrufen (Kaskade; `TestServeRevoked`). Mit dem alten Pin verweigert er ebenso (`kennt nur 1 bis <g>`, 8.6).
9. **Admin:** `admin-<a+1>.key` zum Administrator, wie 7.3.4 Schritt 6. Zuordnungen, die `<a>` ab `<N>` geloggt hat, also zwischen dem Ablesen der Grenze und dem Wechsel auf den neuen Pin, gelten nicht mehr; der Administrator nimmt sie nach `<valid-from>` von `admin-<a+1>.cert` mit dem neuen Schlüssel neu vor, wie 7.3.4 Schritt 7. Mit dem Schlüssel von `<a>` und dem neuen Pin verweigert `address add` mit Exit 2, bevor etwas geloggt wird, mit derselben Meldung wie in 7.3.4 Schritt 6 (Kaskade; `TestAddressAddRevoked`).
10. **Alte Schlüssel vernichten:** `ingest-<i>.key` und `admin-<a>.key`, alle Kopien.
11. **Prüfen:**
    - `gomailctl inspect <identity-g+1.pin>` zeigt `<g+1>` in `identities` (Feld 8) und in `revoked` `role` 0 (Identität), `gen` `<g>`, `revoked_at_size` `<N>` und `revoked_at_time` `<T>` + 1.
    - Der Server startet mit dem neuen Pin, und ein neuer Kopf mit Zeugensignatur erscheint.
    - Eine Testmail erscheint bei einem Client mit dem neuen Pin.
    - Nach `<valid-from>` von `admin-<a+1>.cert` gelingt `address add` mit dem neuen Admin-Schlüssel.

Ein späteres `succeed` (7.1) und jeder weitere Widerruf übernehmen Feld 7 in den neuen Pin; ein Widerruf geht dabei nie verloren.

#### 7.3.6 Neue Plattform (kompromittierter Root)

Ist der Root kompromittiert, kann der Angreifer jede Generation selbst ableiten; dann hilft weder ein Widerruf noch eine Nachfolge (2.3 des Plans, Regel 7). Dasselbe gilt nach einem Fork (7.3.1). Die Plattform wird neu aufgesetzt:

1. Neue Zeremonie `init` mit **neuem Origin** (1.2), neue Anteile, neues Datenverzeichnis, `publish` und `serve` (1.3 bis 1.6).
2. Zeugen für den neuen Origin, je mit eigenem, neuem Zustandsverzeichnis (1.7). Das Zustandsverzeichnis des alten Zeugen nie löschen.
3. Neue Pins an alle Clients und den Administrator. Die Adressen neu zuordnen (4.2).
4. **Benutzer:** Jeder legt ein **neues** Client-Verzeichnis an (`--dir <neues-verzeichnis>`; dessen Elternverzeichnis prüfen, 0.3) und registriert sich mit einem neuen Einladungscode (3). `keygen` erzeugt dabei einen neuen Seed: die neuen 24 Wörter sichern, den alten Seed für die alte Plattform behalten. Das alte Client-Verzeichnis **nie löschen**. `keygen` verweigert ein `--dir`, das schon einen Benutzer hat (`client: this client directory already has a user`, 3.2). Wer deshalb das alte Verzeichnis löscht, etwa den Standard `~/.config/gomailctl`, vernichtet den einzigen Schlüsselspeicher für die alten Postfächer.
5. **Alte Mails:** Sie lassen sich nur lesen, solange der alte Server läuft (Testsperre, 3); einen Umzug von Postfächern gibt es nicht. Vor dem Anhalten des alten Servers festlegen, ob und wie lange er ohne Zustellung neuer Mails für das Lesen weiterläuft. Mails, die nach dem möglichen Zeitpunkt der Kompromittierung eingegangen sind, können gefälscht sein. Erst danach den alten Server anhalten und den alten Pin bei den Clients entfernen.

### 7.4 Anteile neu verteilen

```
gomail-ceremony reshare --pin <pin> --shares <k-of-n>
```

`<k>` Inhaber der bisherigen Aufteilung stellen den Root her, die neuen Anteile werden einzeln gezeigt und geprüft. Die alten Anteile bleiben gültig und lassen sich nicht widerrufen: ihre Inhaber vernichten sie, aber erst, wenn die neuen Inhaber ihren Anteil bestätigt haben.

Sind weniger als `<k>` Inhaber erreichbar, sind Ingest-Rotation, Nachfolge und `reshare` nicht mehr möglich. Deshalb `reshare` rechtzeitig ausführen, wenn Inhaber ausscheiden.

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

*Was es tut:* Es baut `log/tree.rec`, die Kacheln und `log/keys/` aus den Einträgen und den signierten Köpfen neu. Die neue Größe m ist die Zahl der Einträge, die ab `entries/0.rec` lückenlos vorhanden und lesbar sind; jeder Kopf in `log/heads/` muss eine gültige Log-Signatur tragen, höchstens m groß sein und zum neu berechneten Baum passen. Es löscht nichts. Liegen Einträge jenseits von m (verwaiste Einträge `log/entries/<i>.rec` mit i ≥ m), meldet es deren Zahl und Bereich, schreibt nichts und endet mit Exit 1 (`<n> verwaiste Einträge jenseits von <m> gemeldet, 0 verworfen; nichts geschrieben …`); der Betreiber prüft sie und nimmt sie bewusst aus `log/entries/` heraus und führt `log repair` erneut aus. Bei Erfolg meldet es `0 verwaiste Einträge gemeldet, 0 verworfen; <k> Köpfe einer widerrufenen Generation nach log/heads-revoked verschoben`. Danach den Server neu starten.

*Köpfe einer widerrufenen Generation (D93):* Ein Kopf in `log/heads/`, dessen Logsignatur nur mit einer Ingest-Generation prüft, die der Pin für die Zeit des Kopfes widerruft (direkt oder über die Identitätsgeneration, die ihr Zertifikat ausgestellt hat), gehört unter diesem Pin nicht zum Log. Signieren und Veröffentlichen stoppen an ihm (`translog: log is inconsistent: head signed only by an ingest generation the pin revokes: heads/<n>.sig (log repair moves it to log/heads-revoked)`). `log repair` mit dem neuen Pin verschiebt jeden solchen Kopf nach `log/heads-revoked/<n>-<hex SHA-256>.sig`, statt abzubrechen, und nennt ihn auf der Standardausgabe (`log/heads/<n>.sig von einer widerrufenen Generation signiert (Pin-Feld 7), verschoben nach …`; `TestLogRepairRevokedHeads`). Die Dateien dort sind Belege und werden nie gelesen; nicht löschen. Das gehört zu jeder Zeremonie, die eine Ingest-Generation oder eine Identität widerruft (7.3.3 Schritt 3, 7.3.5 Schritt 4).

*Verwaiste Einträge prüfen (kein Test):* Meist sind es gültige Einträge von Clients hinter einem einzigen fehlenden oder unlesbaren `log/entries/<m>.rec`, denn m ist die Länge der lückenlosen Folge ab `entries/0.rec`.
1. `ls -l <datenverzeichnis>/log/entries/<m>.rec` ansehen: fehlt die Datei oder ist sie nicht lesbar?
2. Enthält eine Sicherung (8.8) diesen Eintrag, nur ihn zurückspielen (Rechte 0660, Gruppe `gomail`) und `log repair` erneut ausführen; dann geht nichts verloren.
3. Sonst: Vorher in jedem Zustandsverzeichnis eines Zeugen die Größe in `<hex>.head` (zweite Zeile) ablesen; ist sie größer als m, nicht so vorgehen (8.8, 8.9). Andernfalls die gemeldeten Dateien nicht löschen, sondern außerhalb des Datenverzeichnisses aufbewahren (`mkdir -m 700 <aufbewahrung>`, dann `mv <datenverzeichnis>/log/entries/<i>.rec … <aufbewahrung>/`) und `log repair` erneut ausführen. Clients, deren Einträge darunter waren, hängen sie selbst neu an (8.3).

*Was es nicht heilt:* einen fehlenden oder geänderten Eintrag unterhalb eines signierten Kopfes (nur ein Backup von `log/`, das jeden je an einen Zeugen gegebenen Kandidaten umfasst, stellt die Bytes wieder her; sonst bleibt nur eine neue Plattform mit neuem Origin); ein `tree.rec`, das mehr Einträge nennt als vorhanden sind; eine Datei in `log/heads/`, die kein Kopf dieses Logs ist (der Betreiber entfernt sie und repariert erneut). Einen Rückschritt, bei dem auch `entries/<n+1>.rec` entfernt wurde und den kein veröffentlichter Kopf deckt (die Einträge seit dem letzten veröffentlichten Kopf), erkennt ein neu gestarteter Server gar nicht (R12).

### 8.3 Clients, deren Einträge verloren gingen

Gingen bei einem Rückschritt oder einer Wiederherstellung von `log/` aus einem Backup Einträge verloren, die noch kein veröffentlichter Kopf deckte, bemerken das nur die Clients, die sie geschrieben haben: über ihre offenen Einträge in `state.json`. Findet ein Client seinen Eintrag ersetzt oder nicht mehr vor (`log is inconsistent`), hängt er ihn beim nächsten Befehl selbst erneut an; bis ein neuer bestätigter Kopf ihn deckt, scheitern seine Befehle wie in 3.4 und werden wiederholt (am einfachsten `gomailctl sync`). Meldet er, dass ein anderer Eintrag den Schlüssel belegt (`translog: duplicate log entry`), bleibt er gestoppt, bis der Betreiber das Log geprüft und den Widerspruch behoben hat; ein Werkzeug dafür gibt es im PoC nicht (wie 8.7 Schritt 2). Wer nie etwas in den verlorenen Bereich geschrieben hat, merkt nichts. Ein Server, der einen eigenen Eintrag länger als `HeadInterval` nicht deckt, obwohl er neuere Köpfe signiert, hält ihn zurück: der Client stoppt dann mit `own log entry withheld`.

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
| `der Ingest-Schlüssel gehört zu einer Generation, die der Pin widerruft (Feld 7); …` | Server mit dem Schlüssel einer widerrufenen Ingest-Generation, auch über die Identität, die ihr Zertifikat ausgestellt hat (Exit 2): mit dem Schlüssel der neu ausgestellten Generation starten (7.3.3 Schritt 7, 7.3.5 Schritt 8) |
| `der Admin-Schlüssel gehört zu einer Generation, die der Pin widerruft (Feld 7); …` | `address add` mit dem Schlüssel einer widerrufenen Admin-Generation, auch über die Identität, die ihr Zertifikat ausgestellt hat (Exit 2, nichts geloggt): neuer Schlüssel nach 7.3.4 Schritt 6 bzw. 7.3.5 Schritt 9 |
| `… head signed only by an ingest generation the pin revokes: heads/<n>.sig (log repair moves it to log/heads-revoked)` | Kopf einer widerrufenen Ingest-Generation in `log/heads/`: Server beenden, `log repair` mit dem neuen Pin (8.2) |
| `ceremony: invalid revocation: …` bei `revoke`, `succeed --compromised`, `ingest-rotate`, `admin-rotate` oder `publish` | Grenze oder Generation passt nicht (Kopfzeit nach der Uhr der Zeremonie, Generation schon widerrufen, falsches `valid_from` der Nachfolgerin, Grenze nicht aus diesem Log, widerrufenes Zertifikat nicht im Log); 7.3 |
| `WARNUNG: der neueste Kopf … trägt die Logsignatur von Ingest-Generation <i>, die der Pin ab … widerruft …` bei `publish` | Kopf einer widerrufenen Generation in `log/heads/`: Server angehalten lassen, `log repair` mit dem neuen Pin (8.2; 7.3.3 Schritt 3) |
| `ceremony: incomplete options: valid_from … is before revoked_at_time … of the compromised identity generation` bei `ingest-rotate` | nach `succeed --compromised` ein `valid_from` vor der Widerrufszeit (Exit 1, vor dem ersten Anteil): genau den Wert nehmen, den `succeed` nennt (7.3.5 Schritt 3) |
| `WARNUNG: --valid-from … liegt nach der Widerrufszeit …` bei `ingest-rotate` | nach `succeed --compromised`: genau den Wert nehmen, den `succeed` nennt, sonst verweigert `publish` (7.3.5 Schritt 3) |
| `WARNUNG: Ingest-Generation <i> ist ab … widerrufen, ingest-<i+1>.cert …` bei `publish` | widerrufene Ingest-Generation ohne Nachfolgerin oder mit späterem `valid_from` (7.3, „`publish` mit Feld 7“; 7.3.5 Schritt 5) |
| `store: file exists: … with other content than … the export's: a valid entry is never replaced` (bei `.cert` und `.succ` mit `translog: duplicate log entry:`, bei einer `.pub` mit `…, and <role>-<g>.cert is a valid entry …`) bei `publish` | Der Export enthält unter diesem Namen eine andere Datei als den gültigen Logeintrag, etwa einen anderen Export oder eine zweite Ausstellung desselben Namens, oder der Logeintrag ist ein Zertifikat, das der Dieb vor der Grenze `<N>` gültig geloggt hat (Exit 1, nichts geschrieben). Mit dem Export veröffentlichen, aus dem der Logeintrag stammt; stammt er vom Dieb, gibt es diesen Export nicht: mit der Generation über seinem Zertifikat neu ausstellen (7.3.5 Schritt 2; 7.3, „Zertifikate des Diebs“). Liegt weder das Zertifikat des Diebs noch seine `.pub` in `platform/`, kommt statt dieser Meldung `ceremony: logging <name>: … key taken by entry <k>` (unten) |
| `store: file exists: … a public key is replaced only together with its certificate or under its logged certificate` bei `publish` | einzelne fremde `.pub` ohne geloggtes Zertifikat (Exit 1, nichts geschrieben): von Hand entfernen, dann `publish` wiederholen (7.3, „Fremde Dateien in `platform/`“, Fall 3) |
| `store: file exists: … with other content than … of the export (written meanwhile)` bei `publish` | ein anderer Prozess hat während `publish` unter einem Namen, der beim Vergleich fehlte, eine andere reguläre Datei geschrieben (Exit 1; andere Dateien des Exports können schon geschrieben sein): Herkunft klären, die Datei ansehen, von Hand entfernen, `publish` wiederholen. Einen hängenden Link meldet `publish` seit Auftrag 24 vor dem Schreiben mit der Meldung zum Link (unten) |
| `store: file exists: …/platform/<name> with other content than …/platform/<name> of the export` ohne weiteren Zusatz bei `publish` | unter dem Namen liegt eine fremde Datei, die `publish` nie ersetzt, eine Identitäts-`.pub` (Exit 1, nichts geschrieben; meist lehnt `checkDataPlatform` sie schon vorher ab, 7.3, „Fremde Dateien in `platform/`“, Fall 2): ansehen, von Hand entfernen, `publish` wiederholen. Einen Link meldet `publish` seit Auftrag 24 mit der Meldung zum Link (unten) |
| `store: file exists: <datenverzeichnis>/platform/<name> is a symbolic link, never taken for <export>/platform/<name> of the export…; nothing written: look at the link and remove it by hand` bei `publish` (`a hard link` statt `a symbolic link`) | unter dem Namen einer `.pub` des Exports liegt ein symbolischer Link (auch hängend) oder ein harter Link, und `freeName` gibt den Namen nicht frei (eine Identitäts-`.pub`, oder eine `.pub`, deren Zertifikat nicht geloggt ist und im Datenverzeichnis fehlt oder gleich dem des Exports ist). Einen Link unter einem Zertifikat oder einer Nachfolge ersetzt `publish` oder lehnt ihn mit dem Hinweis der nächsten Zeile ab (Exit 1, nichts geschrieben; Auftrag 24, Paket A): Link ansehen (`ls -l`, `find <datenverzeichnis>/platform \( -type l -o -type f -links +1 \)`), von Hand entfernen, `publish` wiederholen (7.3, „Fremde Dateien in `platform/`“, Fall 4) |
| `… is a symbolic link, never taken for … of the export, and <role>-<g>.cert is a valid entry of the log under this pin with other content than the export's: a valid entry is never replaced; nothing written: look at the link; publish the export that holds the logged <role>-<g>.cert, which replaces the link, or, if that entry is the thief's, reissue under the next generation (RUNBOOK 7.3)` bei `publish` | Link unter einem Namen, dessen gültiger Logeintrag nicht die Datei dieses Exports ist (Exit 1, nichts geschrieben): mit dem Export veröffentlichen, aus dem der Logeintrag stammt, das ersetzt den Link; stammt er vom Dieb, mit der Generation über seinem Zertifikat neu ausstellen (7.3.5 Schritt 2; 7.3, „Zertifikate des Diebs“) |
| `… is a symbolic link, never taken for … of the export (written meanwhile); nothing logged: look at the link, remove it by hand and run the same publish again` bei `publish` | ein Link ist während `publish` unter einem Namen entstanden, der beim Vergleich fehlte (Exit 1; andere Dateien des Exports können schon geschrieben sein, geloggt ist nichts): Link ansehen, von Hand entfernen, `publish` wiederholen (7.3, Fall 4) |
| `store: file exists: translog: duplicate log entry: …/platform/<name> is the same as …/platform/<name> of the export, and <name> is a valid entry of the log under this pin with other content: a valid entry is never replaced` bei `publish` | in `platform/` liegt das Zertifikat oder die Nachfolge des Exports, aber der Name ist im Log schon gültig mit anderem Inhalt belegt, meist nach einem früheren `publish`, das mit `ceremony: logging <name>: … key taken by entry <k>` endete (Exit 1, nichts geschrieben; Auftrag 24, Paket A, `sameButLogged`): wie dort beschrieben die Datei und ihre `.pub` entfernen und mit der Generation über dem Zertifikat des Diebs neu ausstellen (7.3, „Zertifikate des Diebs“) |
| `store: <name> is not a regular file` bei `publish` | ein FIFO, ein Gerät oder ein Verzeichnis direkt unter einem Namen des Exports, oder unter `witnesses.rec` bzw. einer Nachfolge, die weder im Export noch gültig im Log steht und die `publish` für die Kette braucht, eines davon oder ein symbolischer Link auf eines davon (Exit 1, nichts geschrieben; einen Link unter einem Namen des Exports meldet `publish` seit Auftrag 24 als Link, oben): ansehen, von Hand entfernen, `publish` wiederholen (7.3, „Fremde Dateien in `platform/`“, Fall 4) |
| `ceremony: logging <name>: translog: duplicate log entry: key taken by entry <k>` bei `publish` | `<name>` ist im Log schon gültig belegt, meist durch ein Zertifikat, das der Dieb vor der Grenze `<N>` gültig geloggt hat und das weder selbst noch mit seiner `.pub` in `platform/` liegt; `publish` hat `<name>` und eine fehlende `.pub` dazu schon nach `platform/` geschrieben (Exit 1; eine Wiederholung scheitert gleich): diese `<name>` und die mitgeschriebene `.pub` aus `platform/` entfernen und mit der Generation über dem Zertifikat des Diebs neu ausstellen (7.3.5 Schritt 2; 7.3, „Zertifikate des Diebs“) |
| `translog: data directory contradicts the log: platform/<name> does not verify with identity generation …; check where it came from and remove it`, `… platform/identity-<g>.pub contradicts the identity list of the pin`, `… names identity generation <g>, the pin knows 1 to <n>; …` oder `platform/<name>: …` bei `publish` | fremde Datei in `platform/`, die sich nicht verifizieren oder nicht dekodieren lässt, eine fremde `identity-<g>.pub` oder eine Datei mit einer Identitätsgeneration, die der Pin nicht kennt (Exit 1, nichts geschrieben): nach einer eigenen Nachfolge mit dem aktuellen Pin wiederholen; sonst Herkunft klären, von Hand entfernen, `publish` wiederholen (7.3, „Fremde Dateien in `platform/`“, Fälle 1 und 2) |
| `ingest: the ingest generation is superseded in the log` | alter Ingest-Schlüssel nach `valid_from` der neuen Generation (Abschnitt 6) |
| `der Ingest-Schlüssel ist noch nicht gültig` | neuer Ingest-Schlüssel vor `valid_from` seines Zertifikats gestartet: bis dahin mit dem bisherigen Schlüssel weiterlaufen lassen (Abschnitt 6); sonst die Uhr des Servers prüfen (Abschnitt 10) |
| `translog: log is inconsistent` | Abschnitt 8.1 und 8.2 |
| `not yet covered by a verified head` | eigener Logeintrag noch ohne bestätigten Kopf; nach etwa einer Minute wiederholen (3.4) |
| `translog: no fresh verified tree head` | seit 24 Stunden kein bestätigter Kopf: Server, Zeuge oder Uhr prüfen (Abschnitt 10) |
| `Anteile erscheinen und werden eingegeben nur auf einem Terminal` | Zeremonie mit Umleitung oder Pipe gestartet |
| `client: the seed words were not confirmed` | Wort bei `keygen` nicht exakt eingegeben; `keygen` neu starten |
| `store: unknown or used invitation code` | Code falsch oder schon verwendet |
| `keys: key store authentication failed (wrong passphrase or damaged file)` | falsche Passphrase |
| `WARNUNG: Mail <id> wird nicht verarbeitet: …` | eine Prüfung aus 4.4 ist fehlgeschlagen; die Mail wird nicht angezeigt |
| `WARNUNG: Mail <id> wird nicht verarbeitet: Generation widerrufen.` | Ingest-Signatur einer Generation, die der Pin für die Empfangszeit widerruft, auch über die Identität; bei einer späteren Version der Metadaten (Flags, Übernahme) eine Empfangszeit im Zeitraum einer solchen Generation (7.3.2, „Folge für Mails“). Eine Zuordnung einer widerrufenen Admin-Generation zeigt sich dagegen als `Adresse nicht zugeordnet` (7.3.4 Schritt 7) |
| `WARNUNG: Mail <id> wird nicht verarbeitet: Zuordnung einer abgelösten Admin-Generation.` | das Log lehnt die geltende Zuordnung nach seinen Regeln ab (`translog.ErrOrder`, `addressErr` in `internal/client/read.go`), meist weil ihre Admin-Generation bei ihrem `valid_from` schon abgelöst war (D93 (3), `TestLogAdminSuperseded`): mit der aktuellen Admin-Generation neu zuordnen (4.2) |
| `452 4.3.1` beim Einliefern | weniger als 10 % freier Platz im Datenverzeichnis |
| `451` beim Einliefern | inkonsistentes Log (8.1), abgelöste Ingest-Generation (6), Logfehler einer Epoche oder unbekannter freier Platz |
| `WARNUNG: Epoche <n> von <postfach-id> widerspricht dem Transparenzlog: …` | Abschnitt 8.7 |
| `store: file exists: the client directory … is not empty or in use by another client` | `keygen`/`restore` auf ein belegtes `--dir` (3.2, Client-Verzeichnis); endet sie auf `store: in use by another process`, hält gerade ein anderer Befehl die Sperre des Verzeichnisses: einmal wiederholen |
| `client: this is the temporary directory of an unfinished keygen or restore (it holds the marker .incomplete), not a client directory` | Befehl auf ein Temp-Verzeichnis von `keygen` oder `restore` statt auf das Client-Verzeichnis (Exit 1, nichts geschrieben, auch keine Sperrdatei); `--dir` prüfen (3.2, Aufräumen) |
| `client: the client directory is complete, but its durability is not confirmed: <client>: …` | `keygen`/`restore`: Umbenennen gelungen, aber das fsync des Elternverzeichnisses oder die Prüfung danach scheiterte (Exit 1). `<client>` ist vollständig; nicht wiederholen, sondern mit ihm weiterarbeiten (nach `keygen` 3.4, nach `restore` `sync`); nur ein Systemabsturz kurz danach könnte das Umbenennen verlieren |
| `client: the temporary directory of the client directory was replaced by another directory; its parent must not be writable by other users` | Bei `keygen`/`restore` hat jemand das Temp-Verzeichnis oder `--dir` ausgetauscht. Vor dem Umbenennen hat der Befehl dann nichts umbenannt und nichts entfernt; nach dem Umbenennen steht an `--dir` möglicherweise ein fremdes Verzeichnis (ansehen, nicht ungesehen löschen). Elternverzeichnis prüfen (0.3, D92; 3.2, Client-Verzeichnis) |
| `translog: log entry violates a validity rule: valid_from does not increase` bei `address add` | seit Auftrag 24 (Paket C) nur, wenn die letzte gültige Zuordnung der Adresse + 1 ms mehr als 5 Minuten (`translog.MaxClockSkew`) nach der Uhr dieses Rechners liegt: Uhr weit nachgehend oder eine weit vordatierte Zuordnung (Exit 1, nichts geschrieben; 4.2, Uhr) |
| `admin-<gen>.cert ist nicht von der Plattformidentität seiner identity_gen signiert oder kein gültiger Eintrag des Logs: <ursache>` bei `address add` | `platform/admin-<gen>.cert` ist nicht von der Identität signiert, die es nennt, nennt eine Identitätsgeneration ohne Schlüssel im Pin oder im Log, oder es ist nicht der gültige Logeintrag (Exit 1, nichts geloggt; Auftrag 24, Paket C): mit dem Export vergleichen, eine fremde Datei mit demselben `publish` zurücksetzen (4.2, Admin-Zertifikat; 7.3, „Fremde Dateien in `platform/`“) |
| `der Admin-Schlüssel passt nicht zu admin-<gen>.cert` (seit Auftrag 24 bei einem Lesefehler mit `: <ursache>` dahinter) bei `address add` | `--admin-key` gehört nicht zu dem Zertifikat seiner Generation in `platform/` (ohne Zusatz), oder `ReadPlatformCertRaw` scheitert, mit der Ursache nach dem Doppelpunkt: `admin-<gen>.cert` oder `admin-<gen>.pub` fehlt (`store: not found: admin-<gen>.cert`), ist keine reguläre Datei (`store: admin-<gen>.cert is not a regular file`) oder zu groß (`store: file too large: …`), bei der `.pub` mit deren Namen; `admin-<gen>.cert` lässt sich nicht dekodieren (der Fehler des Dekodierens) oder ist ein Zertifikat anderer Rolle oder Generation (`store: invalid record: admin-<gen>.cert certifies another key`); `admin-<gen>.pub` weicht vom Zertifikat ab (`store: invalid record: admin-<gen>.pub differs from its certificate`) (Exit 1): Schlüssel und Generation prüfen; fehlt die Datei, `publish` mit dem Export der Admin-Generation (7.3.4) |
| `Server-Sperre: store: in use by another process` | `log repair` neben einem laufenden Server (8.2); den Server vorher beenden |
| `client: the client directory must not be inside the data directory` | `--dir` liegt im Datenverzeichnis, auch über einen Link; seit Auftrag 24 auch, wenn der Client den Pfad nicht ganz prüfen kann (Verzeichnis ohne Suchrecht, Pfad über `PATH_MAX`, mehr als 40 Links): Links und Rechte mit `namei -l <client>` prüfen, ein anderes `--dir` nehmen (3.2, Nicht im Datenverzeichnis) |
| `der Pin darf nicht im Datenverzeichnis liegen` | Pin innerhalb des Datenverzeichnisses, auch über einen Link (Exit 2; 0.3) |
| `der Pin ist ein Entwicklungs-Pin …` | Pin aus `init --dev` an einem Produktionsbuild (Exit 2; 0.2) |
| `--data und --pin sind erforderlich` | `gomailctl` ohne `--data` oder `--pin` (Exit 1; 3) |
| `ceremony: unusable key directory: …` (etwa `… has mode 0755, not 0700`) | `--keys` nicht 0700, fremd, ein Link oder mit vorhandenem Schlüssel (1.2) |
| `ceremony: unusable export directory: … is not empty` | `--out` nicht leer (1.2) |
| `Seed und Anteile erscheinen nur auf einem Terminal …` | `gomailctl keygen` mit umgeleiteter Ausgabe (3.2) |
| `loghttp: invalid configuration: head interval at most 1h0m0s, at least the minimum gap` | `--head-interval` außerhalb von 1 min bis 1 h (1.6) |
| `gomail-witness: Das Log hat zwei verschiedene Köpfe gleicher Größe gezeigt. …` (Exit 3) | Fork: Abschnitt 8.9 |
| `… not a regular file …` bei jeder Änderung eines Postfachs | FIFO, Gerät oder Verzeichnis an Stelle einer Datei des Postfachs, etwa `epochs/<n>/epoch.rec` (8.10, AUDIT R26) |

### 8.7 Epoche widerspricht dem Log

Steht im Log unter der Nummer einer Epoche eine andere `epoch.rec` als im Datenverzeichnis, gilt der Logeintrag (K2 Regel 4). Kein Client ersetzt die Datei, auch nicht durch den geloggten Inhalt; Änderungen am Postfach scheitern, bis der Betreiber sie behebt. Der Client warnt:

```
WARNUNG: Epoche <n> von <postfach-id> widerspricht dem Transparenzlog: dort ist eine andere Epoche <n> eingetragen. Sie wird nie ersetzt; das Postfach bleibt blockiert. Abhilfe (Betreiber): <abhilfe>.
```

- **Nach dem Kopf** (jenseits der Epoche, die `mailbox.rec` nennt, und der neuesten geloggten; nur eine Änderung oder `sync` liest sie): Abhilfe „die Datei entfernen, nachdem der Logeintrag geprüft wurde“.
- **Am Kopf** (die Epoche, die `mailbox.rec` nennt, oder die neueste geloggte, je nachdem, welche höher ist): vorher die übliche Warnung, dass die Epochenkette bei Epoche `<n>` abbricht; Abhilfe „die Datei durch den Inhalt des Logeintrags ersetzen, nachdem er geprüft wurde“. Entfernen hilft hier nicht, die geloggte Epoche gehört an diese Stelle.
- **Unter dem Kopf** nennt der Client nur den Abbruch der Kette, keine Abhilfe.

Vorgehen des Betreibers:

1. Die Datei ansehen: `gomailctl inspect <datenverzeichnis>/mailboxes/<postfach-id>/epochs/<n>/epoch.rec` (`number`, `reason`, `begin`, `members`, `signer_gen`).
2. Den Logeintrag der Epoche finden und prüfen: Er liegt als `log/entries/<i>.rec` vor, das Feld `content` ist die geloggte `epoch.rec` Byte für Byte. Geprüft ist er, wenn er für dieses Postfach und diese Nummer steht und ein von den Zeugen bestätigter Kopf ihn deckt (i kleiner als dessen Größe und der Blatt-Hash des Eintrags per Inklusionsbeweis im Baum dieses Kopfes). **Einen Befehl dafür gibt es im PoC nicht:** Weder findet einer den Eintrag zu Postfach und Nummer, noch zeigt `inspect` Logeinträge (es kennt ihren Typ nicht), noch schreibt einer das Feld `content` heraus. Der Betreiber braucht dafür ein eigenes Werkzeug für das Datensatzformat (Abschnitt 3.6 des Plans).
3. Die alte Datei als Beleg außerhalb des Datenverzeichnisses aufbewahren. Nach dem Kopf: die Datei `epochs/<n>/epoch.rec` entfernen. Am Kopf: sie durch den geprüften Inhalt ersetzen (atomar, Rechte 0660, Gruppe `gomail`).
4. Prüfen: Ein Mitglied führt `gomailctl sync` aus; die Warnung darf nicht mehr erscheinen.

### 8.8 Sicherung und Wiederherstellung

Kein Programm sichert etwas, und kein Test fährt diese Regeln nach. Sie folgen aus den Regeln des Zeugen und der Clients (AUDIT R13).

- **Was sichern:**
  - `admin-<g>.key` und `ingest-<g>.key`: verschlüsselt, auf getrennten Medien, getrennt von den Anteilen. Einen verlorenen Ingest-Schlüssel ersetzt eine Ingest-Rotation (6). Einen verlorenen Admin-Schlüssel ersetzt eine Admin-Rotation (`admin-rotate`, 7.3.4); bis zum `valid_from` der neuen Generation gibt es keine neue Adresszuordnung. Ist ein Schlüssel womöglich in fremden Händen, genügt die Rotation nicht (7.3.1).
  - Pins und Exporte der Zeremonien (öffentlich; der Pin ist aber der Vertrauensanker, 1.3).
  - Zeugenschlüssel. Ohne ihn hilft nur ein Zeugenwechsel (7.2).
  - Das Datenverzeichnis, nur bei angehaltenem Server (`log/` und die übrigen Dateien müssen zusammenpassen), mit Rechten und Gruppe. Eine Sicherung von `log/` dient vor allem dazu, einzelne fehlende Einträge zurückzuholen (8.2).
  - Client-Verzeichnisse sichert jeder Benutzer selbst, nie zusammen mit der Passphrase-Datei (3); fehlt das Client-Verzeichnis, stellt der Seed den Benutzer wieder her (5.2).
- **`log/` nie als Ganzes aus einer Sicherung zurückspielen, die älter ist als der neueste gegengezeichnete Kopf.** Maßgeblich ist `<hex>.head` im Zustandsverzeichnis des Zeugen; `log/heads/` zeigt die veröffentlichten Köpfe. Der Zeuge verweigert dann jeden kleineren Kopf und jeden größeren, der den gespeicherten nicht konsistent fortsetzt, und hält einen Kopf gleicher Größe mit anderer Wurzel dauerhaft als Fork fest (Exit 3, 8.9; Regeln 5 bis 7 in `internal/witness/witness.go`). Ist nur eine solche Sicherung vorhanden, bleibt eine neue Plattform mit neuem Origin (7.3; AUDIT R13).
- **Übriges Datenverzeichnis:** Ein Client mit neuerem Zustand erkennt ältere `epoch.rec`, `mailbox.rec`, Metadaten oder `folders.gml` als Zurückspielen und lehnt sie ab (AUDIT Abschnitt 2); Mails seit der Sicherung fehlen. Ein erprobtes Verfahren, ein Datenverzeichnis aus einer Sicherung wieder in Betrieb zu nehmen, gibt es im PoC nicht.
- **Zustandsverzeichnis des Zeugen:** nie löschen und nie durch ein leeres oder ein älteres aus einer Sicherung ersetzen. Der Zeuge schreibt seinen Zustand, bevor die Gegensignatur ihn verlässt, damit er keinen gegengezeichneten Kopf vergisst (Regel 8 in `internal/witness/witness.go`); ein älterer Zustand macht genau das rückgängig, und ohne Zustand vertraut er dem nächsten Kopf beim ersten Kontakt. Eine Sicherung dient nur als Beleg (8.9).

### 8.9 Zeuge meldet einen Fork (Exit 3)

`gomail-witness` endet mit Exit 3 und „Das Log hat zwei verschiedene Köpfe gleicher Größe gezeigt“. Der Zeuge signiert für diesen Origin nie wieder, auch nicht nach einem Neustart (`<hex>.fork` im Zustandsverzeichnis). Mit einem Zeugen (1 von 1) veröffentlicht der Server keinen Kopf mehr, und nach spätestens 24 Stunden stoppen alle Clients (Abschnitt 10). Die Erkennung prüfen Tests in `internal/witness` und `cmd/gomail-witness`; das folgende Vorgehen ist nicht getestet.

1. Das Zustandsverzeichnis mit `<hex>.fork` und `<hex>.head` unverändert sichern (Beweis). Meldet der Zeuge, dass der Beweis **nicht** gespeichert werden konnte, seine Ausgabe und `log/heads/` sichern und den Zeugen erst nach Klärung der Ursache wieder starten.
2. Ursache klären: (a) Wurde `log/` zurückgesetzt oder aus einer Sicherung zurückgespielt (8.8), oder wurden Einträge entfernt und danach `log repair` ausgeführt? Dann ist es ein Betreiberfehler. (b) Sonst hat jemand mit dem Ingest-Schlüssel, der zugleich Log-Schlüssel ist (Q4, AUDIT R16), zwei Sichten signiert; der Ingest-Schlüssel gilt dann als kompromittiert. Ein Widerruf der Ingest-Generation (7.3.3) hilft dann nicht: Der Zeuge signiert für diesen Origin nie wieder (7.3.1, letzte Zeile); es bleibt eine neue Plattform (7.3.6).
3. Zustandsverzeichnis und Beweis nie löschen, um den Zeugen wieder in Gang zu bringen: Ein Zeuge ohne Zustand vertraut dem nächsten Kopf beim ersten Kontakt, und die Erkennung ist wertlos.
4. Ein geprüftes Verfahren, das Log danach mit einem anderen Zeugen fortzusetzen, gibt es nicht; ein Zeugenwechsel nach 7.2 hilft Clients mit altem Pin nicht. Solange es kein solches Verfahren gibt, bleibt eine neue Plattform mit neuem Origin (7.3.6).

### 8.10 Weitere Grenzen für den Betrieb

- **Nicht reguläre Datei an einer Prüfstelle** (AUDIT R26): Ein Verzeichnis oder eine FIFO an `mailboxes/<postfach-id>/epochs/<n>/epoch.rec` entfernt kein Client, denn sie ist nicht als ungültig beweisbar; jede Änderung am Postfach scheitert, bis der Betreiber sie nach Ansehen (`ls -l`) entfernt. Eine reguläre `epoch.rec` nie so entfernen (8.7).
- **Größe des Client-Zustands** (AUDIT R43): Im ehrlichen Betrieb reichen die 64 MiB von `state.json` für rund 70 000 Mails je Client-Verzeichnis; danach öffnet der Client nicht mehr. Eine Abhilfe gibt es im PoC nicht.
- **Exit 3 auf Dauer** (AUDIT R44, R42): `device lost` und `sync` können dauerhaft bei Exit 3 bleiben, wenn sich eine übernommene Datei nicht neu signieren lässt (etwa Metadaten mit der höchsten Version) oder mehr als 4096 ungültige Dateien unter `index/<n>/` liegen. Der Widerruf der alten Generation ist davon nicht betroffen; das Postfach bleibt vorgemerkt.

## 9. Zwei Maschinen

Der Test nach 9.1 (Abnahme, 10.2) läuft mit `scripts/two-host-test.sh`.

### 9.1 Voraussetzungen

- Zwei Maschinen: der Server-Host exportiert ein Verzeichnis über **NFSv4**, der Client-Host hat es eingehängt, mit Sperrunterstützung: `vers=4.x` und `local_lock=none`; nie `nolock`, `local_lock=posix` oder `local_lock=all`, nie SSHFS (D83). Das Skript prüft die Optionen in `/proc/mounts` des Client-Hosts; Leerzeichen und andere Sonderzeichen im Mountpfad (dort als `\040` usw. geschrieben) sind erlaubt.
- Zwei verschiedene Betriebssystembenutzer (Name und uid verschieden), einer je Host, beide in der Gruppe `gomail` mit **derselben gid** auf beiden Seiten (sec=sys). Empfohlene `umask` 0007; die Programme setzen 0660/2770 ohnehin selbst (D70).
- **Client-Verzeichnisse (D92):** Ihr Elternverzeichnis darf nur der Client-Benutzer beschreiben können, oder es trägt das Sticky-Bit (Eigentümer der Benutzer oder `root`; Abschnitt 0.3). Das Skript erfüllt das selbst, sofern `--workdir` nicht für andere Benutzer beschreibbar ist: Es legt die Client-Verzeichnisse in seinem eigenen Verzeichnis auf dem Client-Host an, das es mit `umask 077` anlegt (0700; `two-host.XXXXXX/client/` im lokalen Modus, sonst `two-host.XXXXXX/`). Wer Befehle von Hand nachfährt, prüft das Elternverzeichnis mit `stat -c '%U %a' <eltern>`. Ein Client-Verzeichnis gehört nie in das eingehängte Datenverzeichnis, das die Gruppe `gomail` beschreiben darf (2770; AUDIT Abschnitt 3).
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
| Zeremonierechner (offline, ohne NTP) | `valid_from` der Zertifikate (`init`), der Nachfolge (`succeed`); Prüfung „nicht in der Vergangenheit“ von `ingest-rotate --valid-from` und `admin-rotate --valid-from`; Ausnahmen nur für `ingest-rotate` mit einem Pin, der die Vorgängerin widerruft (genau `revoked_at_time`, 7.3.3) oder nach `succeed --compromised` die Identität (nicht vor `revoked_at_time`, 7.3.5); Prüfung „Kopfzeit nicht nach dieser Uhr plus fünf Minuten“ bei `revoke` und `succeed --compromised` (7.3) | vor jeder Zeremonie von Hand nach einer verlässlichen Quelle auf UTC stellen; `init` und `succeed` zeigen sie vor dem ersten Schritt, bei falscher Uhr mit Strg-C abbrechen |
| Server-Host | Empfangszeit jeder Mail, Zeit der Log-Köpfe (und damit `revoked_at_time` eines Widerrufs, 7.3.2), Umschalten der Ingest-Generation; Freigabe des Starts mit einem neuen Ingest-Schlüssel (vor dessen `valid_from` verweigert `serve`, ohne Toleranz) | NTP Pflicht |
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
| 1.7 | Prüfschlüssel mit den Shell-Zeilen aus 1.7 gebildet (aus `platform/ingest-1.pub` des Datenverzeichnisses, einer Kopie der Datei im Export); Zeuge auf demselben Rechner, ohne Tunnel |
| 3.1–3.4 | drei Benutzer: Einladung, `keygen` (Pipe des Testbuilds; ohne Schalter verweigert), Registrierung, verbrauchter Code |
| 4.1–4.6, 4.9 | Postfach, Adresse, Mail, unbekannte Adresse 550, `list` ohne Absender, `read`, `--folder`, `search`, `flag`, `inspect` |
| 4.7 | `share --from 1` (bob), `share` ab neuer Epoche (carol), `revoke`: carol liest danach nicht; mit `inspect` eine neue Epoche mit `reason` 3, Beginn während des Entzugs, ohne carol, im Log und von einem Kopf gedeckt; die Mail nach dem Entzug liegt in ihr |
| 4.8, 4.10 | `sync`; Exit 2 und Exit 1 |
| 5.1 | `device lost` (bob), `sync` von alice, bob liest wieder |
| 5.2, 5.3 | `restore` aus Wörtern (bob) und aus 2 von 3 Anteilen (alice; die Anteile bildet der Test aus dem Seed wie `keygen --shares`, das nur am Terminal läuft) |
| 6 | `ingest-rotate`, Mails eines Servers mit altem Schlüssel vor und nach `valid_from`, `publish`, alter Schlüssel verweigert, Server und Zeuge mit beiden Log-Schlüsseln; `gomailctl` zeigt die Mail vor und lehnt die nach `valid_from` ab |
| 7.3 | `succeed --compromised` ohne `--revoke-at-size` und `--revoke-at-time` verweigert (Exit 2, Meldung „sind nötig“), kein Export geschrieben (seit Auftrag 21b; den ganzen Ablauf prüfen die Tests unten) |
| 7.1 | `succeed`, `publish` neben dem Server verweigert, mit neuem Pin; Server mit altem Pin verweigert, mit neuem startet; Clients mit neuem und mit altem Pin |
| 8.2 | `log repair` neben dem Server verweigert, danach erfolgreich; Client ohne Server verweigert |

Nicht in `TestRunbook` (in Klammern, wo es sonst geprüft ist; „kein Test“, wo nirgends):

- 0.3 und 9.1: die Voraussetzung D92 für das Elternverzeichnis (kein Test, vom Programm nicht geprüft).
- 1.2: die Zeremonie am echten Terminal mit ihren Schaltern und der Anzeige der Uhr (Pseudoterminal-Tests in `cmd/gomail-ceremony`); die Verweigerungen von `--keys` und `--out` (Tests in `internal/ceremony`); der Weg der Schlüssel vom Live-System (kein Test).
- 1.4: die Verweigerungen von `init` (nicht leer, Link, FIFO, Entwicklungs-Pin, Gruppe, Rechte; `cmd/gomail-server/init15h_test.go`, `internal/e2e/init15h_test.go`, `TestInitProduction`); das Anlegen von Gruppe und Benutzern (kein Test).
- 1.6: Loopback-Prüfung und `--isolated-test-network` (`TestCheckListen`), Pin im Datenverzeichnis und Entwicklungs-Pin (Tests in `cmd/gomail-server`, etwa `TestDevPinRefusedInProduction`), Ingest-Schlüssel noch nicht gültig (`TestServeNotYetValid`), Rechte des Datenverzeichnisses (`TestStartDataDirRights`), zurückgesetzter Baum (`TestStartRolledBackTree`), `--head-interval` (`cmd/gomail-server/log_test.go`), `--hostname` (kein Test; geprüft ist nur `smtpd.Config.Hostname`), 452 und 451 (`TestDiskFull452`).
- 1.7: Fork und Exit 3 des Zeugen, `--interval` unter 1 s (`internal/witness`, `cmd/gomail-witness`); der SSH-Tunnel zu einem Zeugen auf einer anderen Maschine (kein Test, AUDIT R47); die Regeln für `--state` und `--key` (`internal/witness`).
- 2: alle Terminalregeln, Exit 130 (Pseudoterminal-, Signal-, stderr- und Stillstandstests in `cmd/gomail-ceremony`).
- 3.2: `keygen` am echten Terminal (Pseudoterminal-Tests in `cmd/gomailctl`); die Regeln für das Client-Verzeichnis (`TestKeygenAtomic`, `TestKeygenExistingDir`, `TestRestoreAtomic`, `TestClientDirLeftovers`, `TestLeftoverNeedsMarker`, `TestRunLosesTempDir`, `TestTempDirMovedAway`, `TestTempDirSwappedForClientDir`, `TestTempDirSwappedNotRemoved`, `TestTempDirSwappedBeforeRename`, `TestOpenTempDirRefuses`, seit 20o `TestIncompleteDirRefused`, `TestLeftoverAllOrNothing`, `TestClientDirLinkIntoDataDir`, `TestNotDurableAfterRename`, `TestHeldLockInUse`, seit Auftrag 24 `TestClientDirLinkDotDotIntoDataDir`, `TestInsideDataDirUnexaminable`, `TestClientDirLongRealPath`, `TestClientDirChain41IntoDataDir` in `internal/client`); das Vorgehen bei einem Rest ohne Markierung (kein Test).
- 3.3: `keygen --shares` (Pseudoterminal-Tests in `cmd/gomailctl`).
- 4.2: Umordnen einer Adresse mit Exit 2; die Uhr (`TestAddressAddValidFromFirst`, `TestAddressAddValidFromAfterLogged`, `TestAddressAddValidFromBeyondSkew`, `TestAddressAddParallelUnderLock` in `cmd/gomail-server`, Auftrag 24) und das Admin-Zertifikat (`TestAddressAddForgedCert`, `TestAddressAddIdentitySuccession`).
- 4.3: die Kommandozeile mit `curl` (kein Test); 451.
- 4.7: `share --to` (`cmd/gomailctl/cmds_test.go`, Tests in `internal/client`) und der Entzug eines solchen Lesers.
- 4.8: der Weg über `epoch-fallback.rec` (`TestSupplyEmptyAtMonthChange`).
- 4.10, 5.1: Exit 3 und 130; Q18 (`internal/client`).
- 5.2: die Warnung „Noch kein bestätigter Zustand“ (`cmd/gomailctl/cmds_test.go:597`, `internal/client/logrework_test.go:664`).
- 6: `ingest-rotate` über die Kommandozeile (die Zeremonie läuft über die Testseams); Schritt 2 (Neustart mit dem alten Schlüssel zwischen `publish` und `valid_from`); die Reihenfolge in Schritt 3; in Schritt 4 der laufende alte Server mit 451 nach `valid_from` (der Test nimmt einen Ingest im Prozess) und der neue Schlüssel vor `valid_from` (`TestServeNotYetValid`); Schritt 5.
- 7.1: `succeed` über die Kommandozeile mit Anzeige der Uhr; `publish` mit altem Pin (`TestSuccessionEndToEnd`); Schritt 5 (der Test startet den Zeugen neu).
- 7.2: `--replace-witnesses` (`TestSuccessionEndToEnd`); Clients mit altem oder neuem Pin nach einem Zeugenwechsel und die Reihenfolge der Verteilung (kein Test).
- 7.3: der Ablauf mit Widerruf. Die Teile prüfen: Zeremonie über die Kommandozeile und am Pseudoterminal (`TestSucceedCompromised`, `TestRevokeCommand`, `TestPTYRevocation` in `cmd/gomail-ceremony`), Grenze, Feld 7, Rotation nach einem Widerruf und `publish` mit Feld 7 (`TestSucceedCompromised`, `TestRevoke`, `TestAdminRotate`, `TestPublishRevocations`, `TestCompromiseChain`, `TestAddRevoked`, `TestRotateAfterRevocation`, `TestPublishReissueAfterThief`, `TestPublishRevokedHead`, `TestRevocationTimes`, `TestRotateBothRevoked`, `TestVerifyCompromisedIdentityStillIssues` in `internal/ceremony`, seit Auftrag 22 auch `TestPublishHealsPlatform`, `TestPublishHealsOverwrittenCert`, `TestPublishHealsForeignPub`, `TestPublishValidEntryKept`), Server und `address add` mit widerrufener Generation und `log repair` (`TestServeRevoked`, `TestAddressAddRevoked`, `TestLogRepairRevokedHeads` in `cmd/gomail-server`), Client (`TestLogIngestRevoked`, `TestLogAdminRevoked`, `TestLogAdminSuperseded`, `TestLogIngestCascadeRefused`, `TestLogFlagLaundering`, `TestLogFlagsAcrossGenerations`, `TestLogAddressRefreshAfterOrder`, `TestIngestRevocation` in `internal/client`), Annahme (`TestRevokedGeneration` in `internal/ingest`), SMTP-Server, Annahme und Client mit einem von Hand gebauten Pin (`TestRevokedIngestEndToEnd` in `internal/e2e`) und die Regeln des Logs (`internal/translog`, `revoke21a_test.go`, `rework21a_test.go`). Ohne Test: die Abläufe 7.3.3 bis 7.3.5 als Ganzes mit den Programmen (Reihenfolge `log repair`, `publish`, Verteilen, Start), das Ablesen der Grenze (7.3.2), Zeugen mit nur dem neuen Log-Schlüssel, das Ersetzen von Zertifikaten des Diebs und das Zurücksetzen fremder Dateien über die Kommandozeile (nur `TestPublishReissueAfterThief` und die Tests aus Auftrag 22 in `internal/ceremony`), symbolische und harte Links unter `platform/` (nur die Tests aus Auftrag 24, Paket A, in `internal/ceremony`: `publishlink24_test.go`, `publishlink24b_unix_test.go`), Clients mit altem Pin nach `succeed --compromised` und die erneute Zuordnung nach 7.3.4 Schritt 7; 7.3.6 (kein Test).
- 7.4: `reshare` (`cmd/gomail-ceremony`, `internal/ceremony/api_test.go`).
- 8.1 und 8.3 (`internal/translog`, `internal/client`); 8.2 mit verwaisten Einträgen (`TestLogRepairOrphans`) und das Vorgehen dazu (kein Test), mit Köpfen einer widerrufenen Generation (`TestLogRepairRevokedHeads`); 8.4 (Q18, `internal/client`); 8.5 (kein Test); von 8.6 die meisten Zeilen (geprüft sind nur die Meldungen, die die Schritte oben auslösen); die Warnungen aus 8.7 (`TestLogDuplicateNeverReplaced`, `TestLogContradictsAtHead`); 8.8, 8.9 und 8.10 (kein Test für das Vorgehen).
- 9: der Zwei-Maschinen-Test (`TestTwoHostScript`).
- 10: 24-Stunden-Regel, 23-Stunden-Regel für offene Einträge, fünf Minuten Abweichung (Tests in `internal/translog`, `internal/witness` und `internal/client`, etwa `TestLogStaleStops`).
