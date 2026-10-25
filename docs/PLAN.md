# go-mail: Proof of Concept

Stand: 25.10.2026

go-mail ist der erste Baustein der Go-Business-Cloud. Der PoC nimmt Mails per SMTP an und legt sie als einzelne, immer verschlüsselte Dateien in einem Dateisystem ab. Der Server kann Mails empfangen, ablegen und für die Suche vorbereiten, hält aber zu keinem Zeitpunkt einen Schlüssel, mit dem er gespeicherte Daten lesen könnte.

---

## 1. Ziele und Abgrenzung

### Ziele des PoC

1. Mails per SMTP annehmen (ohne TLS) und verschlüsselt ablegen
2. Schlüsselhierarchie für Benutzer, Postfächer und Plattform umsetzen
3. Persönliche und geteilte Postfächer mit Zeitabschnitten (Epochen)
4. Suche über verschlüsselte Suchmarken, ohne Schlüssel auf dem Server
5. Messen, was die Verschlüsselung an Durchsatz kostet

### Nicht Teil des PoC

- TLS, STARTTLS und SMTP-Anmeldung (Submission)
- Versand an fremde Server
- IMAP, Webmail, HTTP-API
- SPF, DKIM, DMARC
- echte Spam- und Virenprüfung (nur als Schnittstelle mit Platzhalter)
- Sortierregeln
- Kalender, Kontakte, Dateien

### Grundsätze

- Jede Datei im Datenverzeichnis ist verschlüsselt. Ausnahmen sind ausschließlich öffentliche Schlüssel, Signaturen und die Zuordnung von Adressen zu Postfächern.
- Klartext einer Mail existiert nur im Arbeitsspeicher, nur während des Empfangs und auf dem Gerät des Benutzers.
- Kein Wurzelschlüssel wird im Betrieb verwendet. Verwendet werden immer nur abgeleitete oder zertifizierte Teilschlüssel.
- Keine externen Abhängigkeiten außer `golang.org/x/crypto` und `golang.org/x/mod`. Alles andere wird mit der Go-Standardbibliothek umgesetzt. Mindestversion ist **Go 1.26**, weil erst diese HPKE mitbringt. Beide werden vom Go-Team gepflegt und nur dort genutzt, wo die Standardbibliothek nichts Gleichwertiges bietet: Argon2id aus `x/crypto` und das Transparenzlog aus `x/mod/sumdb/tlog`.

---

## 2. Schlüsselhierarchie

### 2.1 Überblick

```
Plattform-Root (offline, Shamir 3 von 5)
├── platform/identity/<gen>      signiert alle öffentlichen Plattformschlüssel
├── platform/admin/<gen>         signiert Adresszuordnungen und Einladungen
└── platform/ingest/<gen>        signiert Metadaten beim Empfang

Benutzer-Seed (nur auf Papier, nie dauerhaft auf einem Gerät)
├── user/root                    zertifiziert die Generationen, nur bei Bedarf aus dem Seed berechnet
├── user/identity/<gen>          signiert Flags, Mitgliedschaften, Epochen
└── user/unwrap/<gen>            entpackt Postfachschlüssel

Postfach-Epoche (zufällig erzeugt, für jedes Mitglied verpackt)
├── content                      X25519, für Mails
├── meta                         X25519, für Metadaten und Begriffslisten
└── index                        symmetrisch, für Suchmarken

Datei (zufällig erzeugt, pro Datei)
└── Dateischlüssel               AES-256, verpackt für einen Postfach-Epochenschlüssel
```

Der Baum zeigt die Zuordnung, nicht die Ableitung. Abgeleitet wird nur innerhalb von Plattform-Root und Benutzer-Seed. Epochenschlüssel und Dateischlüssel sind immer zufällig erzeugt und hängen mit den Ebenen darüber nur über Verpackungen zusammen.

### 2.2 Benutzerschlüssel

**Erzeugung vor dem Anlegen.** Bevor ein Benutzer im System existiert, erzeugt er auf seinem Gerät einen Seed mit 256 Bit Zufall aus `crypto/rand`. Der Server sieht ihn nie.

**Seed-Format.** Der Seed wird nach BIP-39 mit der englischen Wortliste als 24 Wörter kodiert, inklusive der 8 Bit Prüfsumme. Die BIP-39-eigene Passphrase-Ableitung (PBKDF2 zum Wallet-Seed) wird **nicht** verwendet. Die 24 Wörter stehen nur für die 32 Byte Entropie. Eine spätere Änderung des Ableitungsverfahrens erhält einen neuen Versions-String (`v2`), der Seed bleibt gültig.

**Ableitung.** Einmalig `prk = HKDF-Extract(salt = "gomail/v1/user-seed", ikm = seed)`, danach pro Schlüssel `HKDF-Expand(prk, info, 32)`. Kodierung von `info`:

```
info = label (ASCII) || 0x00 || uint32 Big Endian (Generation)    für Schlüssel mit Generation
info = label (ASCII)                                              für Schlüssel ohne Generation
```

Das Nullbyte trennt Label und Generation eindeutig. Labels enthalten selbst nie ein Nullbyte.

| Teilschlüssel | Label | Generation | Algorithmus | liegt wo |
|---|---|---|---|---|
| Root | `gomail/v1/user/root` | nein | Ed25519 | nirgends dauerhaft, nur kurz im Speicher, wenn der Seed eingegeben wird |
| Identität | `gomail/v1/user/identity` | ja | Ed25519 | Schlüsselspeicher des Geräts |
| Entpacken | `gomail/v1/user/unwrap` | ja | X25519 | Schlüsselspeicher des Geräts |

**Umwandlung in Schlüssel.** Für Ed25519 werden die 32 Byte als Seed an `ed25519.NewKeyFromSeed` übergeben, für X25519 an `ecdh.X25519().NewPrivateKey`, das die Bits intern nach RFC 7748 anpasst. Für jede Zeile der Tabelle werden Testvektoren aus festen Seeds festgeschrieben. Dieselben Regeln gelten mit dem Salt `gomail/v1/platform-root` für den Plattform-Root.

**Was auf dem Gerät liegt.** Nur Identität und Entpackschlüssel der **aktuellen** Generation, nie der Seed und nie der Root. Geht ein Gerät verloren, hat der Finder höchstens diese Generation und kann keine neue erzeugen.

**Generationen.**

1. Die erste Generation ist 1. Jede neue Generation ist genau um 1 höher. Lücken oder Sprünge werden abgelehnt.
2. Eine neue Generation entsteht nur mit dem Seed: Der Client berechnet daraus kurzzeitig den Root, leitet Identität und Entpackschlüssel der neuen Generation ab und erstellt ein Generationszertifikat, signiert mit dem Root. Das Zertifikat erklärt im selben Schritt die vorherige Generation für widerrufen.
3. Das Zertifikat wird in `user.rec` übernommen und in das Transparenzlog eingetragen (siehe 2.7). Erst ab diesem Logeintrag gilt die neue Generation.
4. Signaturen einer widerrufenen Generation werden nur akzeptiert, wenn sie nachweislich vor dem Widerruf im Log standen.
5. Beim nächsten Sync verpacken die Clients der anderen Mitglieder alle Epochen für die neue Generation neu und löschen die Verpackungen für die widerrufene.

Weil alle Generationen aus dem Seed ableitbar sind, gefährdet eine Rotation die Wiederherstellung nicht: Wer den Seed hat, kann jede Generation neu berechnen.

**Lokale Ablage im Client.** Der Schlüsselspeicher liegt unter `~/.config/gomailctl/keystore`:

- verschlüsselt mit AES-256-GCM, Schlüssel per Argon2id aus der Passphrase (64 MiB, 3 Durchläufe, 4 Threads)
- zufälliger Salt von 16 Byte pro Schlüsselspeicher
- Version und alle KDF-Parameter stehen im Kopf der Datei und sind über die AAD mitauthentifiziert
- Dateirechte 0600, Schreiben atomar über temporäre Datei, `fsync` und Umbenennen
- private Schlüssel werden nach Gebrauch im Speicher überschrieben, soweit Go das zulässt

Gegen ein kompromittiertes, entsperrtes Gerät schützt das nicht. Wer dort Code ausführen kann, liest alles, worauf der Benutzer Zugriff hat. Hardware-Schlüssel (FIDO2, YubiKey, TPM) und eigene Schlüssel pro Gerät sind nicht Teil des PoC und für später vorgesehen.

**Sicherung des Seeds.** `gomailctl keygen` gibt die 24 Wörter aus und fragt danach drei zufällig gewählte Wörter ab. Erst wenn das gelingt, ist die Registrierung möglich. Danach wird der Seed auf dem Gerät gelöscht.

**Wiederherstellung.** `gomailctl keygen --shares 2-of-3` teilt den Seed zusätzlich per Shamir auf Vertrauenspersonen auf. Die Plattform bekommt keinen Anteil. Für Geschäftspostfächer wird diese Option empfohlen, siehe offene Entscheidung 1.

**Was der Benutzer selbst tun muss.** Den Seed sicher verwahren und die Passphrase kennen. Den Seed braucht er nur bei drei Gelegenheiten: Einrichtung eines neuen Geräts, Verlust eines Geräts (`gomailctl device lost`, erzeugt eine neue Generation) und Wiederherstellung. Epochenvorrat, Neuverpacken und Indexierung erledigt `gomailctl sync` automatisch.

**Registrierung.** Der Client legt `users/<user-id>/user.rec` an, hier zur Lesbarkeit als JSON dargestellt. Gespeichert und signiert wird die kanonische Kodierung nach 3.6.

```json
{
  "user_id": "u_7f3c...",
  "root_pub": "<ed25519, base64>",
  "generations": [
    {
      "gen": 1,
      "identity_pub": "<ed25519, base64>",
      "unwrap_pub": "<x25519, base64>",
      "created": "2026-10-25T21:46:00Z",
      "revokes": null,
      "sig": "<ed25519 des Root>"
    }
  ]
}
```

Eine Registrierung ist nur mit einem Einladungscode möglich, den der Admin vorher erzeugt. Der Admin kann damit keinen Benutzer anlegen, dessen Schlüssel er kennt.

### 2.3 Plattformschlüssel

**Root.** Der Plattform-Root ist ein 256-Bit-Seed, erzeugt offline in einer Zeremonie. Er wird per Shamir über GF(256) in fünf Anteile zerlegt, drei davon reichen zur Rekonstruktion. Jeder Anteil wird als Wortliste mit Prüfsumme ausgegeben, nach dem Vorbild von SLIP-39.

**Abgeleitete Teilschlüssel:**

| Teilschlüssel | Info-String | Algorithmus | liegt wo |
|---|---|---|---|
| Identität | `gomail/v1/platform/identity` + Generation | Ed25519 | nur in der Zeremonie, öffentlicher Teil im Client hinterlegt |
| Admin | `gomail/v1/platform/admin` + Generation | Ed25519 | beim Administrator, getrennt vom Server |
| Ingest | `gomail/v1/platform/ingest` + Generation | Ed25519 | privater Teil beim SMTP-Server |

Kodierung der Labels mit Generation wie in 2.2. Admin- und Ingest-Schlüssel werden mit dem Identitätsschlüssel zertifiziert (`platform/admin-<gen>.cert`, `platform/ingest-<gen>.cert`). Clients akzeptieren nur Signaturen, die auf ein solches Zertifikat zurückgehen.

**Adresszuordnungen.** Jede Zuordnung einer Adresse zu einem Postfach wird vom Admin-Schlüssel signiert und ins Transparenzlog eingetragen. `addresses.json` ist nur eine Arbeitskopie für den Server. Der Client prüft für jede Mail, dass die Empfängeradresse laut Log zum Zeitpunkt des Empfangs seinem Postfach zugeordnet war. Leitet ein Server eine Adresse still auf ein anderes Postfach um, fällt das spätestens beim Abgleich des Logs auf.

**Widerrufe und Aktualität.** Widerrufe von Generationen, egal ob Plattform oder Benutzer, werden über das Transparenzlog verteilt. Ein Client, der einen Widerruf noch nicht kennt, kann ihn durch lokale Signaturprüfung nicht erkennen. Deshalb gilt eine Aktualitätsgrenze: Ist der zuletzt geprüfte Baumkopf älter als 24 Stunden, verarbeitet der Client keine neuen Signaturen, bis er einen aktuellen Kopf mit Zeugenbestätigung (siehe 2.7) geprüft hat.

**Wechsel der Identität.** Die Identität hat ebenfalls Generationen. Für einen regulären Wechsel signiert die alte Generation die neue (`platform/identity-<gen>.succ`). Ein Client, der Generation 1 kennt, akzeptiert so Generation 2 und merkt sie sich. Ist eine Identität kompromittiert, taugt diese Kette nicht, weil der Angreifer selbst eine Nachfolgerin signieren könnte. Dann wird aus dem Root eine neue Generation abgeleitet und über ein Update des Clients verteilt, also außerhalb der Plattform. Clients lehnen ab diesem Update jede Signatur der kompromittierten Generation ab.

**Zeremonie** (Werkzeug `gomail-ceremony`, Rechner ohne Netzwerk, Live-System):

1. Root erzeugen
2. Identitätsschlüssel und Ingest-Schlüssel ableiten, Zertifikat erstellen, öffentliche Teile exportieren
3. Root in fünf Anteile aufteilen und ausgeben
4. Probe-Rekonstruktion aus drei zufällig gewählten Anteilen
5. Rechner ausschalten

Für einen neuen Ingest-Schlüssel oder eine Neuverteilung der Anteile kommen drei Anteilsinhaber in einer neuen Zeremonie zusammen.

### 2.4 Postfach-Epochen

Jedes Postfach besteht aus einer Folge von **Epochen**. Eine Epoche hat drei Schlüssel, die **zufällig** erzeugt werden und nicht abgeleitet sind:

- `content`: X25519-Schlüsselpaar für Mails
- `meta`: X25519-Schlüsselpaar für Metadaten und Begriffslisten
- `index`: 32 Byte für die Suchmarken

Zufällig statt abgeleitet, damit gelöschte Epochen wirklich unlesbar werden.

**Epochenwechsel:**

- regulär monatlich
- sofort beim Entfernen eines Mitglieds
- auf Wunsch zu Beginn und Ende einer Vertretung

Epochen werden fortlaufend nummeriert. `epoch.rec` hält Nummer, Beginn, Grund, die erlaubte Algorithmen-Suite, die öffentlichen Schlüssel, die Liste der Mitglieder mit ihrer Generation und den SHA-256 der vorherigen `epoch.rec`. Das Mitglied, das die Epoche erzeugt, signiert sie mit seiner Identität.

**Schutz gegen Zurückspielen.** Die Epochen bilden so eine signierte Kette. Der Client merkt sich lokal die höchste Epoche, die er je gesehen hat, und prüft bei jedem Start die Kette ab dort. Erkannt werden damit:

- eine entfernte oder ersetzte Epoche
- eine zurückgesetzte `mailbox.rec`, die wieder auf eine alte Epoche zeigt
- Mails, die nach Beginn einer neuen Epoche noch für eine ältere verschlüsselt wurden

In allen drei Fällen zeigt der Client eine Warnung und verarbeitet die betroffenen Dateien nicht weiter.

**Vorrat.** Neue Epochen erzeugt immer der Client eines Mitglieds, weil nur Mitglieder die Schlüssel verpacken können. Bei jedem Login legt der Client deshalb Epochen für die nächsten drei Monate an. Fehlt beim Monatswechsel trotzdem eine Epoche, verwendet der Server die zuletzt vorhandene weiter und vermerkt das. Der nächste Client erzeugt dann eine Epoche mit sofortigem Beginn.

**Verpackung für Mitglieder.** `epochs/<n>/members/<user-id>.wrap` enthält alle drei privaten Epochenschlüssel, verpackt für den aktuellen Entpackschlüssel des Mitglieds, signiert mit der Identität des Mitglieds, das die Verpackung erstellt hat.

### 2.5 Geteilte Postfächer

Ein geteiltes Postfach unterscheidet sich technisch nicht von einem persönlichen. Es hat mehrere Verpackungen pro Epoche.

**Mitglied hinzufügen.** Ein bestehendes Mitglied entpackt die Epochenschlüssel und verpackt sie für das neue Mitglied. Welche Epochen, entscheidet es: alle, nur ab jetzt oder einen Zeitraum.

**Mitglied entfernen.** Seine Verpackungen werden gelöscht, und es beginnt sofort eine neue Epoche ohne dieses Mitglied. Was das Mitglied vorher schon lesen konnte, kann es behalten haben. Das lässt sich grundsätzlich nicht verhindern.

Die Oberfläche trennt deshalb zwei Aktionen, die nie zusammengefasst werden:

| Aktion | Wirkung | Wirkung nicht |
|---|---|---|
| **Zugriff entziehen** | keine Verpackungen mehr für neue Epochen, neue Epoche beginnt sofort | bereits gelesene oder gespeicherte Mails bleiben beim Mitglied |
| **Daten löschen** | Crypto-Shredding ganzer Epochen nach 2.6 | betrifft alle Mitglieder, nicht nur eines |

Bis die neue Epoche im Transparenzlog steht, ist der Entzug nicht wirksam. Der Client des entziehenden Mitglieds zeigt erst danach "entzogen" an. Clients der verbleibenden Mitglieder prüfen beim Sync, dass für Mails nach dem Entzug ausschließlich die neue Epoche verwendet wurde (siehe 2.4).

**Vertretung.** Die Vertretung bekommt nur die Verpackungen der Epochen ihres Zeitraums. Sie liest genau die Mails, die in diesem Zeitraum angekommen sind.

### 2.6 Löschen und Aufbewahrung

Werden alle Verpackungen einer Epoche gelöscht, sind sämtliche Mails dieser Epoche für jeden unlesbar, der die Epochenschlüssel nie besessen hat (Crypto-Shredding).

Das gilt ausdrücklich **nicht** für Kopien außerhalb der Plattform:

- Epochenschlüssel, die ein Client zwischengespeichert hat
- entschlüsselte Mails, Anhänge und Volltextindizes auf Geräten
- Exporte, weitergeleitete Mails, Ausdrucke
- Sicherungen des Datenverzeichnisses, die noch die Verpackungen enthalten
- Verpackungen für einen Wiederherstellungsempfänger

Für eine Löschung im Sinne von go-mail gilt deshalb:

1. Die Löschung wird als signierter Eintrag in der Epochenkette vermerkt (`epoch.rec` mit Grund `deleted`).
2. Jeder Client, der diesen Eintrag sieht, löscht seine zwischengespeicherten Schlüssel, Mails und Indexteile dieser Epoche und bestätigt das mit einem signierten Vermerk.
3. Sicherungen des Datenverzeichnisses werden so aufbewahrt, dass sie nach Ablauf derselben Frist ebenfalls gelöscht werden, sonst stellt eine Rücksicherung die Verpackungen wieder her.
4. Verpackungen für einen Wiederherstellungsempfänger werden mitgelöscht.

Was ein Mitglied bewusst exportiert oder auf einem nicht mehr verbundenen Gerät behalten hat, bleibt lesbar. Das lässt sich technisch nicht verhindern, nur organisatorisch regeln. Für Geschäftspostfächer gelten die Aufbewahrungsfristen nach HGB und AO von sechs bzw. zehn Jahren. Crypto-Shredding ist dort das Werkzeug für das sichere Löschen nach Ablauf der Frist, nicht davor.

### 2.7 Konsistenz der Zustände

Signierte Epochenkette und lokale Versionsstände schützen nur einen Client, der seinen bisherigen Zustand kennt. Ein Server könnte einem neuen Gerät oder zwei Mitgliedern unterschiedliche, jeweils gültig signierte Ketten zeigen, etwa einem Mitglied eine Kette, in der ein anderes nie entfernt wurde. Dagegen gibt es drei Maßnahmen.

**Transparenzlog.** Jede `user.rec`, jede `epoch.rec`, jede Adresszuordnung, jedes Zertifikat und jede Nachfolge der Plattformidentität wird in ein Append-only-Log eingetragen, aufgebaut als Merkle-Baum wie bei der Checksum-Datenbank von Go. Verwendet wird dafür direkt das Paket `golang.org/x/mod/sumdb/tlog`. Der Server signiert regelmäßig den Baumkopf. Clients prüfen bei jedem Sync:

- dass ihre Einträge im Log enthalten sind (Inklusionsbeweis)
- dass der neue Baumkopf eine Fortsetzung des zuletzt gesehenen ist (Konsistenzbeweis)

Damit kann der Server Einträge nicht still entfernen oder umschreiben. Er kann aber weiterhin zwei Clients zwei verschiedene Logs zeigen.

**Abgleich zwischen Clients.** Gegen dieses Aufspalten hilft nur, dass Clients ihre gesehenen Baumköpfe untereinander vergleichen:

- Jeder Client legt seinen zuletzt gesehenen Baumkopf signiert im Postfach ab. Andere Mitglieder prüfen beim Sync, dass dieser Kopf in ihrem eigenen Log enthalten ist. Der Server kann diese Vermerke aber verzögern, einzelnen Clients vorenthalten oder Clients voneinander isolieren. Die Vermerke allein garantieren deshalb keine Erkennung.

**Zeugen (verbindlich).** Den Ausschlag geben unabhängige Zeugen nach dem Verfahren des Go-Checksum-Ökosystems (Witness Cosigning im Format `golang.org/x/mod/sumdb/note`):

- Ein Zeuge ist ein eigener kleiner Dienst auf einer anderen Maschine, bei einem anderen Betreiber oder zu Hause. Er speichert den letzten Baumkopf, den er gesehen hat, prüft jeden neuen auf Konsistenz und signiert ihn nur dann mit.
- Ein Zeuge signiert für ein Log nie zwei Köpfe gleicher Größe mit verschiedenem Inhalt. Damit kann es pro Zeuge nur eine Sicht geben.
- Clients akzeptieren einen Baumkopf nur mit der Signatur von mindestens einem Zeugen, im Betrieb mit echten Mails von mindestens zwei aus drei. Die öffentlichen Schlüssel der Zeugen sind im Client hinterlegt wie die Plattformidentität.

**Garantien.** Unter der Annahme, dass nicht alle geforderten Zeugen mit dem Server zusammenarbeiten, wird **garantiert erkannt**:

| Manipulation | Erkennung |
|---|---|
| Entfernen oder Ändern eines Logeintrags | Konsistenzbeweis schlägt fehl |
| verschiedene Sichten für verschiedene Clients | Zeuge verweigert den zweiten Kopf, Client erhält keinen gültigen Kopf |
| Zurückhalten eines Widerrufs über 24 Stunden | Aktualitätsgrenze in 2.3, Client stellt die Verarbeitung ein |
| stilles Umleiten einer Adresse | Adresszuordnung fehlt im Log oder widerspricht ihm |

**Nicht garantiert** ist die Erkennung, wenn der Server zusammen mit allen geforderten Zeugen manipuliert, oder wenn er einen Client vollständig vom Netz der Zeugen abschneidet. Im zweiten Fall bemerkt der Client das aber durch die Aktualitätsgrenze, er wird also nicht getäuscht, sondern blockiert.

**Neue Geräte und Wiederherstellung.** Ein Gerät ohne Vorgeschichte hat keinen vertrauenswürdigen Zustand. Es übernimmt ihn deshalb, wo möglich, von einem bestehenden Gerät:

| Fall | Herkunft des Vertrauenszustands |
|---|---|
| zweites Gerät | Kopplung mit dem ersten Gerät per QR-Code, überträgt den zuletzt gesehenen Baumkopf |
| Wiederherstellung aus Seed, anderes Gerät noch vorhanden | wie zweites Gerät |
| Wiederherstellung aus Seed, kein Gerät mehr vorhanden | Vertrauen beim ersten Kontakt, danach Abgleich mit den Vermerken anderer Mitglieder und mit Zeugen. Der Client zeigt deutlich an, dass er noch keinen bestätigten Zustand hat. |
| Erstregistrierung | Vertrauen beim ersten Kontakt, abgesichert durch die fest hinterlegte Plattformidentität |
| mehrere eigene Geräte parallel | jedes Gerät legt seinen Baumkopf ab, die Geräte prüfen sich gegenseitig |

Im PoC werden umgesetzt: Transparenzlog mit Inklusions- und Konsistenzbeweisen, Vermerke der Clients und **ein Zeuge** als eigener Prozess auf einer zweiten Maschine. Mehrere Zeugen und die Kopplung per QR-Code folgen vor dem Betrieb mit echten Mails.

---

## 3. Dateiformat `.gml`

### 3.1 Aufbau

Alle Teile sind binär und kanonisch kodiert (siehe 3.6). Es gibt kein JSON in `.gml`-Dateien, damit Sender und Empfänger garantiert dieselben Bytes authentifizieren.

```
Präambel         6 Byte    "GOML" || Formatversion (0x01) || Suite (0x01)
Länge Kopf       4 Byte    uint32 Big Endian, höchstens 4 KiB
Kopf             n Byte    kanonisch kodiert
Länge Empfänger  4 Byte    uint32 Big Endian, höchstens 16 KiB
Empfängerteil    m Byte    kanonisch kodiert
Blöcke           je Block: uint32 Big Endian Länge || Chiffrat
Länge Trailer    4 Byte    uint32 Big Endian, 0 wenn ohne Signatur
Trailer          t Byte    kanonisch kodiert
```

**Kopf** (Felder in genau dieser Reihenfolge):

| Nr. | Feld | Typ |
|---|---|---|
| 1 | `kind` | uint8: 1 mail, 2 meta, 3 pending, 4 wrap, 5 index |
| 2 | `mailbox_id` | 16 Byte |
| 3 | `epoch` | uint32 |
| 4 | `file_id` | 16 Byte, gleich der ID im Dateinamen |
| 5 | `nonce_prefix` | 7 Byte, zufällig |
| 6 | `chunk_size` | uint32, im PoC fest 65536 |
| 7 | `created` | int64, Millisekunden seit 1970 UTC |

`file_id` bindet den Inhalt an genau eine Datei. Vertauscht jemand zwei Mails desselben Postfachs, schlägt die Entschlüsselung fehl.

**Empfängerteil:** Liste von 1 bis 32 Einträgen mit `type` (uint8: 1 epoch-content, 2 epoch-meta, 3 user-unwrap), `id` (16 Byte), `gen` (uint32), `enc` (HPKE-Kapselung) und `wrapped_key`. Er ist bewusst nicht Teil der AAD der Blöcke, damit spätere Empfängertypen (etwa ein Wiederherstellungsschlüssel) ohne Neuverschlüsselung des Inhalts ergänzt werden können. Jeder Eintrag ist über HPKE einzeln an den Kopf gebunden, und bei signierten Dateien deckt die Signatur den gesamten Empfängerteil ab.

### 3.2 Verpacken des Dateischlüssels

Für das Verpacken wird keine eigene Konstruktion verwendet, sondern **HPKE nach RFC 9180** im Base-Modus mit der Suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 und AES-256-GCM. HPKE ist genau für diesen Zweck spezifiziert und analysiert.

1. Zufälligen Dateischlüssel (32 Byte) aus `crypto/rand` erzeugen
2. `info = "gomail/v1/wrap" || 0x00 || type || id || gen`, kanonisch kodiert
3. `enc, sender = hpke.NewSender(empfänger_pub, HKDFSHA256, AES256GCM, info)`
4. `wrapped_key = sender.Seal(aad = SHA-256("gomail/v1/aad/wrap" || 0x00 || Präambel || Kopf), dateischlüssel)`
5. `enc` und `wrapped_key` kommen in den Empfängereintrag

Beim Entpacken müssen `type`, `id` und `gen` des Eintrags zum eigenen Schlüssel passen. Andernfalls wird der Eintrag übersprungen, ohne einen Entschlüsselungsversuch. Schlägt `hpke.NewRecipient` oder `Open` fehl, etwa wegen eines falschen Empfängers, eines anderen `info`, eines ungültigen öffentlichen Schlüssels oder einer manipulierten Verpackung, wird die Datei abgelehnt.

Jeder Aufruf von `hpke.NewSender` erzeugt einen neuen flüchtigen Schlüssel und damit einen neuen Kontext. Eine Wiederverwendung ist konstruktiv ausgeschlossen.

**Keine eigene Implementierung.** HPKE kommt ausschließlich aus `crypto/hpke` der Standardbibliothek (ab Go 1.26, `hpke.NewSender` und `hpke.NewRecipient`). Das Paket `envelope` setzt nur das Dateiformat darum herum um. Die Testvektoren aus RFC 9180 dienen als Regressionstest, nicht als Ersatz für eine Prüfung.

**Was HPKE nicht leistet.** HPKE schützt weder gegen Wiedereinspielen noch bietet es Vorwärtssicherheit, wenn der Empfängerschlüssel später kompromittiert wird. Im Dateiformat ist beides auch nicht die Aufgabe von HPKE: Gegen Wiedereinspielen schützen Signaturen, Epochenkette und Versionszähler (siehe 2.4 und 7). Vorwärtssicherheit gibt es nur grob über Epochen: Wird ein Epochenschlüssel später kompromittiert, sind genau die Mails dieser Epoche betroffen, nicht ältere oder neuere.

**Ungültige öffentliche Schlüssel.** `crypto/ecdh` liefert bei X25519 einen Fehler, wenn das gemeinsame Geheimnis null ist (Punkte kleiner Ordnung). Dieser Fehler führt immer zum Abbruch und darf nie übergangen werden.

### 3.3 Inhalt

Der Inhalt folgt der STREAM-Konstruktion (Hoang, Reyhanitabar, Rogaway, Vizár 2015), wie sie auch age und Tink verwenden:

- Inhaltsschlüssel: `HKDF-SHA256(ikm = dateischlüssel, salt = nonce_prefix, info = "gomail/v1/content")`, 32 Byte
- Blöcke zu `chunk_size`, jeder mit AES-256-GCM verschlüsselt
- Nonce pro Block: `nonce_prefix (7) || Blockzähler uint32 Big Endian (4) || Letzter-Block-Flag (1)`
- AAD pro Block: `SHA-256("gomail/v1/aad/block" || 0x00 || Präambel || Kopf)`

Blockindex und Dateiende sind damit kryptografisch gebunden: Der Index steckt im Nonce, das Ende im Flag, und ein Block entschlüsselt nur an genau seiner Position mit genau seinem Flag. Authentifiziert wird so die gesamte Datei als Folge, nicht nur einzelne Blöcke.

Verbindliche Regeln:

1. Jeder Dateischlüssel verschlüsselt genau eine Datei. Ein Dateischlüssel wird nie wiederverwendet, auch nicht beim Neuschreiben derselben Mail. Jede Änderung erzeugt eine neue Datei mit neuem Dateischlüssel und neuem `nonce_prefix`.
2. Der Blockzähler beginnt bei 0, steigt um genau 1 und darf nicht überlaufen. Dateien sind auf 50 MB begrenzt, also höchstens 800 Blöcke.
3. Alle Blöcke außer dem letzten sind genau `chunk_size` groß. Der letzte Block trägt das Flag 0x01, alle anderen 0x00.
4. **Leerer Inhalt:** genau ein Block mit 0 Byte Klartext und Flag 0x01.
5. **Inhalt genau ein Vielfaches von `chunk_size`:** Der letzte volle Block trägt das Flag 0x01. Es folgt kein zusätzlicher leerer Block. Der Schreiber hält dafür beim Streaming immer einen Block zurück, bis er weiß, ob noch Daten folgen.
6. Ein leerer letzter Block ist nur bei leerem Inhalt zulässig.
7. Fehlt der Block mit dem Flag, ist die Datei abgeschnitten und ungültig. Folgen nach ihm noch Bytes außer der Trailer-Länge und dem Trailer, ist sie ebenfalls ungültig.
8. **Fail closed:** Schlägt die Authentifizierung eines beliebigen Blocks fehl, ist die gesamte Datei ungültig. Der Client entschlüsselt in einen temporären Puffer und gibt Inhalt erst frei, wenn der letzte Block erfolgreich geprüft ist. Bereits entschlüsselte Teile werden bei einem Fehler verworfen.

Damit lässt sich keine Datei unbemerkt in ein anderes Postfach oder an eine andere Stelle verschieben, und Blöcke können weder vertauscht, verdoppelt noch abgeschnitten werden.

**Grenzen für den Parser.** Alle Längenfelder werden vor jeder Speicherreservierung gegen die Höchstwerte geprüft. Unbekannte Formatversionen, Suiten, Feldnummern oder Typen, doppelte Felder und falsche Reihenfolge führen zum Abbruch.

### 3.4 Signatur

Metadaten, Verpackungen und Begriffslisten tragen einen Trailer mit `signer_type` (uint8: 1 Plattform-Ingest, 2 Benutzer), `signer_id` (16 Byte), `signer_gen` (uint32) und `sig` (64 Byte).

```
sig = Ed25519( "gomail/v1/sig/" || kind || 0x00 || kanonische Struktur )
```

Die kanonische Struktur enthält immer den SHA-256 über Präambel, Kopf, Empfängerteil und alle Blöcke, je nach Dateiart weitere Felder (siehe 7). Signiert wird also stets das Chiffrat, sodass auch der Server Signaturen ohne Schlüssel prüfen kann. Das Präfix mit `kind` verhindert, dass eine Signatur für eine Dateiart als Signatur für eine andere ausgegeben werden kann.

### 3.5 Algorithmen-Suite

| Suite | Schlüsseleinigung | Ableitung | Verschlüsselung | Signatur |
|---|---|---|---|---|
| 1 | HPKE, DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-256-GCM | Ed25519 |
| 2 (später) | HPKE mit `MLKEM768X25519` (hybrid) | HKDF-SHA256 | AES-256-GCM | Ed25519 |

Alle Primitive stehen in der Standardbibliothek bereit (geprüft mit Go 1.26.0): `crypto/hpke` (inklusive des hybriden KEM für Suite 2), `crypto/ecdh`, `crypto/mlkem`, `crypto/hkdf`, `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/ed25519`. Einzige Ausnahme ist Argon2id aus `golang.org/x/crypto` für den Schlüsselspeicher des Clients.

**Schutz gegen Herabstufung.** Eine Suite ist kein frei wählbarer Wert:

1. Der PoC kennt genau eine Suite, die Nummer 1. Jede andere Nummer wird abgelehnt.
2. Jede Epoche legt in ihrer signierten `epoch.rec` fest, welche Suite für sie gilt. Eine Datei mit einer anderen Suite als der ihrer Epoche wird abgelehnt.
3. Eine Epoche darf nur eine gleiche oder neuere Suite haben als ihre Vorgängerin. Ein Wechsel zurück wird abgelehnt.
4. Es gibt keinen Rückfall: Kann ein Client eine Suite nicht, verarbeitet er die Datei nicht, statt eine andere zu versuchen.

### 3.6 Kanonische Kodierung

Alles, was signiert oder als AAD verwendet wird, ist binär und eindeutig kodiert. Das gilt für den Kopf, den Empfängerteil, den Trailer und für alle Datensätze (`.rec`) wie `user.rec` oder `epoch.rec`.

1. Ein Datensatz ist eine Folge von Feldern: Feldnummer (uint8), Länge (uint32 Big Endian), Wert.
2. Felder stehen in aufsteigender Nummer, jede Nummer höchstens einmal. Pflichtfelder fehlen nie.
3. Ganzzahlen haben feste Breite und Big Endian. Zeichenketten sind UTF-8 in Unicode-Normalform NFC und dürfen kein Nullbyte enthalten.
4. Listen sind ein Feld, dessen Wert eine Anzahl (uint32) und danach die Elemente als eingebettete Datensätze enthält.
5. Jeder Datensatz beginnt mit seinem Typ-String und einem Nullbyte, etwa `gomail/v1/rec/epoch` || 0x00. Dadurch ist eine Struktur nie mit einer anderen verwechselbar.
6. Der Decoder lehnt alles ab, was nicht exakt diesen Regeln entspricht. Kodieren und erneutes Dekodieren muss byte-identisch dieselbe Folge ergeben.

JSON-Darstellungen in diesem Dokument dienen nur der Lesbarkeit. `gomailctl inspect` gibt Datensätze als JSON aus, geprüft und signiert wird aber immer die Binärform.

---

## 4. Ablage im Dateisystem

Das Datenverzeichnis enthält keinerlei private Schlüssel von Benutzern. Private Schlüssel der Plattform liegen dort ebenfalls nicht, der Ingest-Schlüssel wird dem Server beim Start getrennt übergeben.

```
data/
  platform/
    identity-1.pub               öffentlicher Identitätsschlüssel der Plattform
    identity-2.succ              Nachfolge, signiert von Generation 1
    admin-1.pub
    admin-1.cert                 Zertifikat, signiert mit der Identität
    ingest-1.pub
    ingest-1.cert                Zertifikat, signiert mit der Identität
    witnesses.rec                öffentliche Schlüssel der Zeugen
  users/
    <user-id>/user.rec          öffentliche Schlüssel, signiert
  invites/
    <code>.json                  Einladungscodes
  addresses.json                 Adresse oder Alias zu Postfach-ID
  log/
    entries/                     Einträge des Transparenzlogs
    tree/                        Hashes des Merkle-Baums
    heads/<n>.sig                signierte Baumköpfe
  mailboxes/
    <postfach-id>/
      mailbox.rec               Name (verschlüsselt), aktuelle Epoche
      folders.gml                Ordnernamen, verschlüsselt mit meta
      epochs/
        <n>/
          epoch.rec             Nummer, Beginn, Grund
          content.pub
          meta.pub
          members/<user-id>.wrap
      mail/
        <ordner-id>/
          <mail-id>.gml          Mail, für content der Epoche
          <mail-id>.meta.gml     Metadaten, für meta der Epoche, signiert
      pending/
        <n>/<batch-id>.gml       Begriffslisten, für meta der Epoche, signiert
      checkpoints/
        <user-id>-<device-id>.rec   zuletzt gesehener Baumkopf, signiert vom Client
      index/
        <n>/postings.gml         Suchmarken und Mail-IDs
        <n>/fulltext.gml         Volltextindex des Clients, für meta der Epoche
  spool/                         laufende Annahmen, bereits für das Postfach verschlüsselt
  work/                          ausgelagerte Vorverarbeitung, flüchtiger Schlüssel
```

Alle IDs sind zufällig (128 Bit, base32). Ordnernamen stehen nur verschlüsselt in `folders.gml`.

**Was im Dateisystem sichtbar bleibt:** Anzahl und Größe der Dateien, Zeitstempel, Mitgliedschaften, Zuordnung von Adressen zu Postfächern, Anzahl der Mail-IDs pro Suchmarke.

---

## 5. SMTP und Empfang

### 5.1 SMTP im PoC

- Port 2525, ohne TLS, ohne Anmeldung
- **ausschließlich an `127.0.0.1` oder ein isoliertes Testnetz gebunden.** Ein öffentlich erreichbarer Betrieb ist im PoC ausgeschlossen, weil Inhalte auf dem Transportweg ungeschützt sind und jeder Mails einspeisen könnte.
- Befehle: `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`
- maximale Größe 25 MB (`SIZE` in `EHLO`), maximal 100 Empfänger
- unbekannte Empfänger: `550 5.1.1`
- Zeilenenden CRLF, Zeilen höchstens 1.000 Zeichen, Dot-Unstuffing beim Lesen
- Zeitlimits nach RFC 5321: 5 Minuten pro Befehl, 10 Minuten für `DATA`
- höchstens 20 gleichzeitige Verbindungen, höchstens 5 pro IP-Adresse
- Mindestrate bei `DATA` von 1 KB/s gemittelt über 60 Sekunden, darunter wird die Verbindung getrennt (gegen absichtlich langsame Verbindungen)
- höchstens 1.000 Mails pro Stunde und IP-Adresse, darüber `451 4.7.1`
- Sinkt der freie Platz im Datenverzeichnis unter 10 %, nimmt der Server keine Mails mehr an und antwortet mit `452 4.3.1`. Absender stellen dann später erneut zu, nichts geht verloren.
- Die Vorverarbeitung hat eine feste Obergrenze für RAM und `work/`. Ist sie erreicht, wird nicht weiter ausgelagert, sondern die Mail nur mit dem Marker `unprocessed` abgelegt (siehe 5.3).

Diese Grenzen machen den PoC robuster, schützen aber nicht gegen einen verteilten Angriff aus vielen Quellen. Das gehört zum Schutz gegen Missbrauch vor dem Betrieb mit echten Mails.

TLS, Ratenbegrenzung und Schutz gegen Missbrauch sind Voraussetzung für jeden Betrieb mit echten Mails und folgen nach dem PoC.

### 5.2 Ablauf

1. **RCPT TO:** Adresse gegen `addresses.json` prüfen und Postfach-ID merken. Zeigen mehrere Empfängeradressen auf dasselbe Postfach (etwa Adresse und Alias), wird dieses Postfach nur einmal vermerkt.
2. **DATA:** Der Server ergänzt einen `Received`-Header und verschlüsselt den Datenstrom beim Lesen direkt pro Empfängerpostfach für den `content`-Schlüssel der aktuellen Epoche nach `spool/<postfach-id>/<mail-id>.gml`. Klartext landet nie auf der Platte.
3. **Metadaten und Marker:** Noch vor dem Abschluss schreibt der Server pro Postfach `<mail-id>.meta.gml` (für `meta`, signiert mit dem Ingest-Schlüssel) und einen Marker `unprocessed` für `pending/`, beides ebenfalls nach `spool/`.
4. **Abschluss:** Nach dem Punkt werden Mail, Metadaten und Marker atomar in das jeweilige Postfach verschoben. Erst dann antwortet der Server mit `250`.
5. **Vorverarbeitung:** Header und Größe kommen in die Verarbeitungswarteschlange (siehe 5.3). Ist die Begriffsliste geschrieben, ersetzt sie den Marker.

**Mehrere Empfänger.** Jedes Empfängerpostfach bekommt eine eigene Kopie mit eigenem Dateischlüssel und eigener Mail-ID, abgelegt in seinem eigenen Verzeichnis `mailboxes/<postfach-id>/mail/`. Bei fünf Empfängerpostfächern liegen also fünf unabhängige Dateien in fünf Verzeichnissen. Untereinander sind die Kopien nicht verknüpft.

**Absturz während des Empfangs.** Alles in `spool/` ist bereits für das Postfach verschlüsselt, aber unvollständig. Da noch kein `250` gesendet wurde, gilt die Mail für den Absender als nicht zugestellt, und er versucht es nach SMTP-Regeln erneut. Beim Start löscht der Server deshalb den gesamten Inhalt von `spool/`. Mails, die bereits verschoben wurden, haben durch den Marker aus Schritt 3 immer einen Eintrag in `pending/` und werden dort von der Ausweichvariante erfasst.

**Klartext im Arbeitsspeicher.** Der Inhalt läuft nur blockweise (64 KiB) durch den Speicher. Vollständig gepuffert werden lediglich die Header, begrenzt auf 1 MB, weil die Vorverarbeitung sie braucht. Ein Angreifer mit Root-Zugriff während des Empfangs kann den Datenstrom trotzdem vollständig mitlesen.

### 5.3 Vorverarbeitung mit flüchtigem Schlüssel

Die Vorverarbeitung arbeitet auf dem Klartext, solange er ohnehin im Arbeitsspeicher liegt:

- Spam- und Virenprüfung (im PoC Platzhalter)
- Zerlegen in Suchbegriffe

Im PoC werden nur die Header gelesen (`net/mail`, höchstens 1 MB, höchstens 500 Header-Felder). MIME-Teile und Anhänge werden nicht ausgewertet. Sobald echte Inhaltsprüfung dazukommt, läuft sie in einem eigenen Prozess mit eigenem Betriebssystembenutzer, ohne Zugriff auf das Datenverzeichnis, weil Parser für fremde Inhalte das wahrscheinlichste Einfallstor sind.

**Flüchtiger Schlüssel.** Bei jedem Start erzeugt der Server einen zufälligen AES-256-Schlüssel, nur im Arbeitsspeicher, gesperrt gegen Auslagerung (`mlock`). Muss die Warteschlange bei Last auf die Platte ausweichen, wird sie mit diesem Schlüssel nach `work/` verschlüsselt.

Startet der Server neu, ist der Schlüssel weg und alles in `work/` unlesbar. Der Server löscht `work/` beim Start. Verloren geht dabei nur Vorverarbeitung, die Mails selbst liegen bereits dauerhaft im Postfach, und ihr Marker `unprocessed` in `pending/` bleibt stehen, bis ein Client die Mail selbst verarbeitet.

### 5.4 Begriffslisten

Pro Mail zerlegt der Server die Hüllmetadaten in normalisierte Begriffe (Kleinschreibung, Unicode NFC):

| Feld | Beispiel |
|---|---|
| `from` | `from:rechnung@lieferant.de` |
| `from_domain` | `fromdomain:lieferant.de` |
| `to` | `to:info@brownbear.de` |
| `day` | `day:2026-10-25` |
| `month` | `month:2026-10` |
| `attachment` | `has:attachment` |
| `thread` | `thread:<message-id der Wurzel>` |

Begriffslisten werden gesammelt (bis 100 Mails oder 60 Sekunden) und als ein `pending/<n>/<batch-id>.gml` für den `meta`-Schlüssel der Epoche geschrieben und mit dem Ingest-Schlüssel signiert.

---

## 6. Suche

### 6.1 Suchmarken

```
marke = HMAC-SHA256(index_schlüssel_der_epoche, begriff)
```

Der Server kennt keinen Indexschlüssel und kann deshalb weder Marken erzeugen noch Begriffe durchprobieren.

### 6.2 Indexierung durch den Client

Beim Login verarbeitet der Client für jedes seiner Postfächer `pending/`:

1. Begriffslisten entschlüsseln und Signatur prüfen
2. Für Einträge `unprocessed`: Metadaten der Mail laden und Begriffe selbst erzeugen
3. Marken berechnen und in `index/<n>/postings.gml` einfügen
4. Verarbeitete Dateien in `pending/` löschen

**Wenn sich kein Client anmeldet,** wächst `pending/` weiter, etwa um einige hundert Byte pro Mail. Das ist für Monate unkritisch. Der Server überwacht pro Postfach Alter und Größe von `pending/` und meldet Postfächer, in denen seit 30 Tagen kein Mitglied aktiv war. Löschen darf er dort nichts, weil er nicht weiß, was die Dateien enthalten.

`postings.gml` ist eine Zuordnung `marke → [mail-id]`. Die Datei ist zusätzlich für den `meta`-Schlüssel verschlüsselt, damit die Struktur nicht offen auf der Platte liegt. Im PoC liest der Client sie direkt, in einer späteren Ausbaustufe wird sie durch eine Server-API ersetzt, die nur Marken entgegennimmt.

### 6.3 Suchen

1. Client bestimmt die Epochen des gewünschten Zeitraums.
2. Pro Epoche berechnet er die Marke des Suchbegriffs.
3. Treffer pro Epoche werden zusammengeführt, die Mails geladen und entschlüsselt.
4. Noch nicht verarbeitete Einträge in `pending/` durchsucht der Client direkt mit.

Dieselbe Adresse ergibt in jeder Epoche eine andere Marke. Suchen lassen sich deshalb nicht über Epochen hinweg verknüpfen.

### 6.4 Volltext

Volltext über Betreff und Inhalt läuft ausschließlich im Client. Der Index wird als `index/<n>/fulltext.gml` für den `meta`-Schlüssel abgelegt, damit neue Geräte ihn übernehmen können.

---

## 7. Integrität

| Datei | signiert von | geprüft durch |
|---|---|---|
| `user.rec` | Identität des Benutzers | Server, andere Clients |
| `identity-<gen>.succ` | vorherige Generation der Plattformidentität | Client |
| `ingest-<gen>.cert` | Identität der Plattform | Client |
| `<mail-id>.meta.gml` beim Empfang | Ingest-Schlüssel | Client |
| `<mail-id>.meta.gml` nach Flag-Änderung | Identität des Benutzers | Client |
| `members/<user>.wrap` | Identität des verpackenden Mitglieds | Client |
| `pending/*.gml` | Ingest-Schlüssel | Client |

Ändert ein Benutzer Flags, verschlüsselt sein Client die Metadaten neu für den `meta`-Schlüssel der Epoche und signiert sie.

### Was die Ingest-Signatur aussagt

Signiert wird eine kanonische Struktur aus Postfach-ID, Epoche, Mail-ID, Empfangszeit, Generation des Ingest-Schlüssels, SHA-256 der verschlüsselten Mail-Datei und SHA-256 der verschlüsselten Metadaten. Hashes von Klartext werden bewusst nicht aufgenommen, weil sie offen im Trailer stünden und der Server damit vermutete Inhalte bestätigen könnte. Eine gültige Signatur belegt damit:

- dass ein Inhaber des zertifizierten Ingest-Schlüssels genau diese Mail zu diesem Zeitpunkt für dieses Postfach angenommen hat
- dass Mail und Metadaten seitdem nicht verändert oder vertauscht wurden

Sie belegt **nicht**, dass der angegebene Absender echt ist, dass der Inhalt unverändert vom ursprünglichen Absender stammt oder dass ein kompromittierter Server keine falschen Metadaten erzeugt hat. Absenderprüfung ist Aufgabe von SPF, DKIM und DMARC und folgt nach dem PoC.

### Gegen Wiedereinspielen

Metadaten tragen einen Versionszähler, der bei jeder Änderung steigt und mitsigniert wird. Der Client merkt sich pro Mail die höchste gesehene Version und lehnt ältere ab. So lassen sich etwa zurückgesetzte Flags nicht unbemerkt einspielen.

### Verhalten des Clients bei Fehlern

| Fall | Verhalten |
|---|---|
| Signatur fehlt | Datei wird nicht verarbeitet und nicht indexiert, Warnung |
| Signatur ungültig | ebenso |
| unbekannter Signaturschlüssel | ebenso |
| Ingest-Generation nicht durch gültiges Zertifikat gedeckt | ebenso |
| Signatur einer als kompromittiert markierten Generation | ebenso, zusätzlich deutliche Warnung |
| ältere Version als bereits gesehen | ältere Version wird verworfen |

Es gibt keinen Modus, in dem unsignierte Dateien still akzeptiert werden.

---

## 8. Was wer sehen kann

| Angreifer | Mailinhalte | Metadaten | Suchbegriffe |
|---|---|---|---|
| Zugriff auf die Platte | nein | nein | nein |
| Root auf dem Server, gespeicherte Daten | nein | nein | nein |
| Root auf dem Server während des Empfangs | ja, für diese Mail | ja, für diese Mail | ja, für diese Mail |
| Root auf dem Server, Suchverhalten | nein | nein | Anzahl Treffer, Wiederholungen innerhalb einer Epoche |
| Mitglied eines Postfachs | ja, für seine Epochen | ja | ja |
| entferntes Mitglied | was es vorher entschlüsselt hat | ebenso | ebenso |

Der Moment des Empfangs ist die einzige Stelle, an der der Server Klartext sieht. Das lässt sich ohne Verschlüsselung durch den Absender grundsätzlich nicht vermeiden.

### Sicherheitsversprechen

> Gespeicherte Mails, Metadaten und Suchbegriffe sind ohne die privaten Schlüssel eines Postfachmitglieds nicht lesbar. Der SMTP-Empfangsprozess ist eine Vertrauensgrenze: Er sieht jede eingehende Mail im Klartext. Wer ihn kontrolliert, kann neu eingehende Mails lesen und kopieren. Schutz davor gibt es nur, wenn bereits der Absender Ende-zu-Ende verschlüsselt.

### Bedrohungsmodell

| Angreifer | im Modell | Schutz |
|---|---|---|
| Diebstahl oder Abbild der Platte | ja | vollständig |
| Root auf dem Server, nur gespeicherte Daten | ja | vollständig für Inhalte, teilweise für Zugriffsmuster |
| Root auf dem Server während des Empfangs | ja, als bekannte Grenze | keiner für neue Mails |
| Server spielt alte Zustände zurück | ja | Erkennung über Epochenkette und Versionszähler |
| Angreifer im Netz zwischen Absender und Server | nein im PoC | erst mit TLS |
| kompromittiertes Gerät eines Mitglieds | nein | Schaden begrenzt auf dessen Postfächer und Epochen |
| Seitenkanäle, Analyse von Zeitpunkten und Größen | nein | bewusst nicht abgedeckt, siehe unten |

**Größen und Zeitpunkte.** Dateigrößen verraten die ungefähre Länge einer Mail, Zeitstempel den Eingang, Zugriffszeiten das Verhalten der Clients. Gegen gezielte Verkehrsanalyse schützt go-mail nicht. Als spätere Ausbaustufe ist das Auffüllen der Inhalte auf Größenstufen vorgesehen (Padmé, höchstens etwa 12 % Mehrbedarf). Zeitpunkte lassen sich bei einem Mailserver grundsätzlich kaum verbergen.

### Was die Suche preisgibt

Ohne Indexschlüssel kann der Server keine Marken erzeugen. Was er trotzdem erfährt, ist als Leakage-Profil festgeschrieben und wird im PoC gemessen:

| Stufe | Was sichtbar ist | Wann |
|---|---|---|
| L1 | Anzahl Marken pro Epoche, Länge jeder Trefferliste | dauerhaft, sobald der Index existiert |
| L2 | welche Mail-IDs zu derselben Marke gehören | dauerhaft |
| L3 | welche Marke gesucht wird, wie oft, zusammen mit welchen anderen | bei jeder Suche |
| L4 | Zeitpunkte von Suchen und Indexierung | bei jeder Aktion |

**Was der Server daraus ableiten kann.** Aus L1 und L2 lassen sich Häufigkeiten erkennen: Die längste Trefferliste vom Typ `month:` ist sehr wahrscheinlich der aktuelle Monat, eine Marke mit hunderten Treffern ist eher ein Newsletter als ein Geschäftspartner. Hat der Server Wissen von außen, etwa dass ein bestimmter Lieferant jeden Montag eine Rechnung schickt, kann er Marken über Muster in Anzahl und Zeitpunkt einzelnen Begriffen zuordnen. Die Annahme "der Server kann keine Begriffe erraten" gilt also nur ohne solches Zusatzwissen.

Dass Suchen über Epochen hinweg nicht verknüpfbar sind, gilt nur, solange die Indexschlüssel der Epochen unabhängig sind und der Server nicht über Zeitpunkte oder Trefferzahlen Zusammenhänge herstellt.

**Postfächer mit hochsensiblen Begriffen.** Pro Postfach lässt sich die Suche über den Server abschalten (`gomailctl mailbox set <postfach-id> --server-search off`). Dann entfallen L1 bis L3 vollständig, gesucht wird nur noch im Client über den Volltextindex. Für Postfächer etwa der Personalabteilung oder mit Gesundheitsdaten ist das die empfohlene Einstellung.

---

## 9. Bestandteile

### 9.1 Programme

| Programm | Aufgabe |
|---|---|
| `gomail-server` | SMTP-Annahme, Ablage, Vorverarbeitung, Verwaltung von Einladungen und Adressen |
| `gomailctl` | Client des Benutzers: Schlüssel, Postfächer, Lesen, Suchen |
| `gomail-ceremony` | Offline-Werkzeug für den Plattform-Root |

Im PoC arbeiten `gomailctl` und `gomail-server` auf demselben Datenverzeichnis. Der Client schreibt dorthin ausschließlich verschlüsselte Dateien und öffentliche Schlüssel. Seine privaten Schlüssel liegen getrennt im lokalen Schlüsselspeicher (siehe 2.2), auf den der Serverprozess keinen Zugriff hat.

Für die Entwicklung reicht dafür ein getrennter Betriebssystembenutzer. Als **Nachweis** der Trennung taugt das nicht, weil Root auf derselben Maschine auch den Client angreifen kann. Für die Abnahme des PoC laufen Client und Server deshalb auf getrennten Maschinen, und das Datenverzeichnis wird dem Client nur über das Netz bereitgestellt (etwa per SSHFS oder NFS). Eine API zwischen Client und Server folgt später.

### 9.2 Befehle

```
gomail-server serve --data ./data --listen :2525
gomail-server invite create
gomail-server address add info@brownbear.de --mailbox <postfach-id>

gomailctl keygen [--shares 2-of-3]
gomailctl register --invite <code>
gomailctl mailbox create <name>
gomailctl mailbox share <postfach-id> <user-id> [--from <epoche>] [--to <epoche>]
gomailctl mailbox revoke <postfach-id> <user-id>
gomailctl mailbox rotate <postfach-id>
gomailctl sync                         Epochenvorrat, pending verarbeiten
gomailctl device lost                  neue Generation, Postfächer neu verpacken lassen
gomailctl list <postfach-id> [--folder <name>]
gomailctl read <postfach-id> <mail-id>
gomailctl search <postfach-id> from:rechnung@lieferant.de [--since 2026-01]
gomailctl mailbox set <postfach-id> --server-search on|off
gomailctl inspect <datei>               Datensatz oder Kopf als JSON anzeigen

gomail-witness serve --log <url> --key <schlüsseldatei>

gomail-ceremony init --shares 3-of-5
gomail-ceremony ingest-rotate
gomail-ceremony reshare
```

### 9.3 Pakete

| Paket | Inhalt |
|---|---|
| `rec` | kanonische Kodierung nach 3.6, strikter Decoder |
| `keys` | Seed, Wortliste, HKDF-Ableitung, Generationen, Schlüsselspeicher |
| `shamir` | Aufteilung über GF(256), Anteile mit Prüfsumme, umgesetzt in Anlehnung an das geprüfte Shamir-Paket aus OpenBao, inklusive dessen Tests |
| `envelope` | Dateiformat, Verpacken, blockweise Verschlüsselung, Signatur |
| `store` | Ablage, atomares Schreiben, Postfächer, Epochen, Mitglieder |
| `smtpd` | SMTP-Zustandsmaschine |
| `ingest` | Annahme, Vorverarbeitung, flüchtiger Schlüssel, Begriffslisten |
| `search` | Suchmarken, Postings, Zusammenführen über Epochen |
| `translog` | Transparenzlog auf Basis von `x/mod/sumdb/tlog`, Baumköpfe, Vermerke der Clients |
| `witness` | Zeugendienst, eigenes Programm `gomail-witness` |

---

## 10. Tests und Abnahme

### 10.1 Pflichttests

**Testvektoren**
- HKDF-Ableitung zu Ed25519 und X25519 aus festen Seeds
- `crypto/hpke` mit der gewählten Suite gegen die Testvektoren aus RFC 9180 (Regressionstest der Einbindung)
- Shamir: Aufteilen und Rekonstruieren für alle Kombinationen von 3 aus 5, eigene Vektoren für das Wortformat

**Kanonische Kodierung**
- Kodieren und Dekodieren ist für alle Datensätze byte-identisch
- abgelehnt werden: doppelte Felder, falsche Reihenfolge, unbekannte Feldnummern, falsche Längen, nicht normalisierte Zeichenketten, Nullbytes in Zeichenketten

**Negativtests für `.gml`**
- veränderter Kopf, veränderter Empfängereintrag, vertauschte Postfach-ID, Epoche oder `file_id`
- zwei Mails desselben Postfachs vertauscht
- abgeschnittene Datei, fehlender letzter Block, angehängte Daten nach dem letzten Block
- vertauschte, doppelte oder fehlende Blöcke, Flag am falschen Block
- leerer Inhalt, Inhalt genau ein und genau zwei Blöcke groß, leerer letzter Block bei nicht leerem Inhalt
- übergroße Längenfelder, übergroßer Kopf, zu viele Empfänger
- öffentlicher Schlüssel kleiner Ordnung, falscher Empfänger, abweichendes `info`, manipulierte Verpackung
- unbekannte Suite, Suite abweichend von der Epoche, ältere Suite als die Vorgänger-Epoche
- fehlende, ungültige oder fremde Signatur, Signatur einer anderen Dateiart

**Negativtests für Schlüssel und Zustände**
- zurückgespielte `epoch.rec`, entfernte Epoche, Mail für veraltete Epoche
- Server zeigt zwei Clients unterschiedliche Logs: Zeuge verweigert den zweiten Kopf, Clients ohne gültigen Kopf verarbeiten nichts
- Baumkopf ohne Zeugensignatur, Baumkopf älter als 24 Stunden
- Generationen: Sprung um mehr als 1, Generation ohne Root-Signatur, Signatur einer widerrufenen Generation nach dem Widerruf
- Adresse ohne oder mit widersprüchlicher Zuordnung im Log
- Baumkopf, der keine Fortsetzung des zuletzt gesehenen ist
- Löschung einer Epoche: Clients entfernen zwischengespeicherte Schlüssel, Mails und Indexteile
- zurückgespielte Metadaten mit älterer Version
- Signatur einer kompromittierten Ingest- oder Identitätsgeneration

**Fuzzing** mit `go test -fuzz` für den `.gml`-Parser, den SMTP-Parser und das Einlesen von Shamir-Anteilen.

**Szenarien**
- Wiederherstellung eines Benutzer-Seeds aus Shamir-Anteilen
- Mitglied hinzufügen, entfernen, Vertretung für einen Zeitraum
- Gerätewechsel mit Übernahme des Volltextindex
- Absturz des Servers in jeder Phase des Empfangs

### 10.2 Freigabekriterien

Der PoC gilt als abgeschlossen, wenn alle Pflichttests grün sind und die Trennung von Client und Server auf getrennten Maschinen nachgewiesen ist. Vor einem Betrieb mit echten Mails kommen hinzu:

1. TLS, Ratenbegrenzung und Schutz gegen Missbrauch beim SMTP-Empfang
2. unabhängige Prüfung von `keys`, `shamir` und `envelope` sowie des SMTP-Empfangs
3. Prüfung von Betriebssystemrechten, Logging und Deployment, insbesondere dass kein Klartext in Logs oder Absturzberichte gelangt

---

## 11. Meilensteine

1. **Kryptografie:** `keys`, `shamir`, `envelope` mit Testvektoren, Negativtests und Fuzzing
2. **Ablage und Benutzer:** `store`, `keygen`, `register`, `mailbox create`
3. **Empfang:** `smtpd`, `ingest`, `list`, `read`
4. **Geteilte Postfächer:** Epochen, `share`, `revoke`, `rotate`, Vorrat
5. **Suche:** Begriffslisten, `pending`, Suchmarken, `search`
6. **Plattform:** `gomail-ceremony`, Zertifikate, Signaturprüfung im Client, Transparenzlog und Vermerke der Clients
7. **Messung:** Durchsatz beim Empfang mit und ohne Verschlüsselung, Kosten der Indexierung im Client, Größe der Postings

---

## 12. Offene Entscheidungen

1. **Wiederherstellung:** Reicht die optionale Shamir-Aufteilung des Benutzer-Seeds, oder braucht ein Unternehmenspostfach zusätzlich einen Wiederherstellungsempfänger in den Verpackungen?
2. **IMAP später:** Entschlüsselt nur ein eigener Client, oder übergibt der Benutzer beim IMAP-Login einen Sitzungsschlüssel an den Server?
3. **Betreff als Suchbegriff:** Wörter aus dem Betreff als Suchmarken wären praktisch, die Trefferzahlen verraten dann aber mehr. Im PoC bleibt der Betreff nur im Volltextindex des Clients.
4. **Sortierregeln:** Regeln wie "Mails von X in Ordner Y" müsste der Server lesen können. Bewusste Ausnahme oder Sortierung nur im Client?
5. **Aufbewahrung:** Den gesetzlichen Rahmen nennt 2.6. Offen ist die Umsetzung: welche Postfächer als geschäftlich gelten, wer das Löschen einer Epoche auslösen darf und ob dafür mehrere Mitglieder zustimmen müssen.
