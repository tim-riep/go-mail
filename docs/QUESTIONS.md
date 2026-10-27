# Fragen an den Auftraggeber (Haltepunkte)

Jede Frage nennt den Haltepunkt nach Abschnitt 4 des Orchestrierungsauftrags, die Stelle, das Problem und einen Vorschlag. Bis zur Antwort wird an allem weitergearbeitet, was nicht davon abhängt; wo ein Paket die Stelle berührt, baut es die strengste Lesart und markiert sie mit `TODO(Qn)`.

## Q1 Wiederherstellungsempfänger: Ableitung, Kennung, Wiederaufnahme (K3)

- Haltepunkt 1 (Dateiformat, signierter Datensatz, Prüfregel im Client).
- Stelle: K3 (Mechanismus entschieden), 2.4 „Wiederherstellungsempfänger“, 3.1 Empfängertyp 4, K2 Regel 1.
- Problem: Festgelegt ist, dass der Wiederherstellungsschlüssel ein eigener Seed ist (`gomailctl recovery keygen --shares 3-of-5`), als Mitglied der Art 2 in `epoch.rec` steht und je Epoche `members/recovery.wrap` (Empfängertyp 4) bekommt. Nicht festgelegt sind: (a) die HKDF-Labels für den Entpackschlüssel des Wiederherstellungsempfängers (2.2 nennt nur Benutzer- und Plattformlabels), (b) welche `id` und `gen` der Mitgliedseintrag und der Empfängereintrag tragen, (c) wie der öffentliche Schlüssel zum eintragenden Mitglied kommt, (d) wie „sich selbst neu als Mitglied aufnehmen“ (K3 Punkt 4) ohne das Anlegen einer Epoche (K2 Regel 1) möglich sein soll.
- Vorschlag: (a) Der Seed wird wie ein Benutzer-Seed abgeleitet (`gomail/v1/user/identity` und `gomail/v1/user/unwrap`, Generation 1); ein eigenes Label ist nicht nötig, weil der Seed nie als Benutzer registriert wird. (b) `id` ist eine zufällige 16-Byte-Kennung, die `recovery keygen` erzeugt, `gen` ist 1. (c) `recovery keygen` schreibt eine Datei `recovery.pub` (Datensatz `gomail/v1/rec/recovery-pub`: Kennung, öffentlicher Entpack- und Identitätsschlüssel, keine Signatur), die ein Mitglied mit `gomailctl mailbox set <id> --recovery recovery.pub` einträgt (neue Epoche `recovery-changed`, Fingerabdruck wird angezeigt und bestätigt). (d) Für M1 kann der Wiederherstellungsempfänger nur lesen (`gomailctl mailbox recover <id> --shares` rekonstruiert den Seed, entpackt und liest); die Wiederaufnahme als Mitglied erledigt ein verbleibendes Mitglied mit `share`. Der Fall „kein Mitglied mehr vorhanden“ bleibt bis nach M1 offen, weil er K2 Regel 1 widerspricht.
- Bis zur Antwort: Welle 2 baut Mitgliedereinträge der Art 2 und `recovery.wrap` nach (a) und (b) hinter einer internen API; kein Befehl wird ausgeliefert, bevor die Frage entschieden ist (`TODO(Q1)`).

## Q2 Einladungen: signierter Datensatz oder JSON

- Haltepunkt 1 (Dateiformat).
- Stelle: 3.7 Kurzname `invite` („Einladungscode mit Ablaufzeit, Admin-Schlüssel“); 4 `invites/<code>.json`; 2.1 „signiert Adresszuordnungen und Einladungen“.
- Problem: Seit 1.3 verlangt 3.7 eine Signatur und eine Ablaufzeit, Abschnitt 4 nennt weiter eine JSON-Datei. Ein signierter Datensatz nach 3.6 ist kein JSON. Phase 1 schreibt unsigniertes JSON ohne Ablauf (D53, S17).
- Vorschlag: `invites/<code>.rec` mit `gomail/v1/rec/invite` (Code, erstellt, gültig bis, Generation des Admin-Schlüssels, Signatur unter `invite`); `register` prüft Signatur und Ablauf gegen `admin-<gen>.cert`; Standardablauf 7 Tage; Abschnitt 4 nennt dann `.rec`.
- Bis zur Antwort: unverändert (JSON, unsigniert). `gomail-server invite create` braucht nach dem Vorschlag den Admin-Schlüssel wie `address add`.

## Q3 `gomailctl mailbox set --server-search off` ohne Volltextindex

- Haltepunkt 1 (Dateiformat) und 4 (Umfang).
- Stelle: 8 „Postfächer mit hochsensiblen Begriffen“, 9.2.
- Problem: Der Schalter soll die Begriffslisten des Servers abschalten; dann sucht der Client „nur noch über den Volltextindex“, der nicht Teil von M1 ist. Der Server müsste den Schalter lesen können, also stünde er unverschlüsselt in `mailbox.rec` (unsigniert) oder in der signierten `epoch.rec`.
- Vorschlag: Nicht Teil von M1 (der Schalter hätte ohne Volltext nur die Wirkung „keine Suche“); Eintrag in `SPEC-ISSUES.md` als offen. Soll er trotzdem kommen: Feld `server_search` in `epoch.rec` (signiert, Mitglied legt es fest), der Server schreibt bei `off` nur den Marker `unprocessed` und keine Begriffslisten.

## Q4 Schlüssel und Zeitstempel des Baumkopfs

- Haltepunkt 1 (signierter Datensatz, Prüfregel im Client).
- Stelle: 2.7 „Der Server signiert regelmäßig den Baumkopf“, 3.7 letzter Absatz (Format `note`), 2.3 Aktualitätsgrenze 24 Stunden, 2.1 (die Plattform hat nur Identität, Admin und Ingest).
- Problem: Nicht festgelegt ist, mit welchem Schlüssel der Server den Kopf signiert und woher der Client das Alter des Kopfs kennt (eine `note` hat keinen Zeitstempel).
- Vorschlag: Der Server signiert mit dem Ingest-Schlüssel (der einzige, den er hat) als `note`-Signer mit Namen `gomail-log`; der Kopf ist ein Checkpoint im Format `origin\n<größe>\n<hash base64>\n` mit einer Erweiterungszeile `time <ms seit 1970 UTC>` (Uhr des Servers), die Zeugen bei der Gegensignatur mitprüfen (nicht in der Zukunft, nicht älter als ihr letzter Kopf). Der Client prüft das Alter über diese Zeile gegen seine Uhr. Zeugen signieren als `note`-Signer mit ihrem eigenen Schlüssel; ihre öffentlichen Schlüssel stehen in `platform/witnesses.rec`, signiert von der Plattformidentität, und werden dem Client wie die Identität hinterlegt (`identity-<gen>.pin` erhält die Zeugenliste).
- Bis zur Antwort: Das Log bekommt den Signierschlüssel als Parameter; Welle 2 baut mit dem Vorschlag, der Schlüssel ist an einer Stelle austauschbar.

## Q5 Grund der Epoche 1 und der Epoche nach erschöpftem Vorrat

- Kein Haltepunkt im engen Sinn (klarstellend), hier nur zur Kenntnis; Entscheidung in `DECISIONS.md`.
- 2.4 nennt sechs Gründe; keiner heißt „erste Epoche“ oder „sofortiger Beginn nach leerem Vorrat“. Umgesetzt wird: Epoche 1 und die Epoche nach erschöpftem Vorrat tragen `regular` (geplant, mit fünf Minuten Vorlauf wie bisher); `member-added` gilt in M1 immer als sofort (K-Anhang: „geplant oder sofort“, es wird nur die sofortige Form gebaut).

## Q6 Vertretung als eigene Mitgliedsart

- Haltepunkt 1 (signierter Datensatz, Prüfregel im Client).
- Stelle: 2.5 „Vertretung“, 2.4 Grund `delegation-ended`, K2 Regel 1 („Ein Wiederherstellungsempfänger und eine Vertretung dürfen keine Epochen anlegen“), D49 (Mitgliedsarten 1 Benutzer, 2 Wiederherstellung).
- Problem: Die Regel, dass eine Vertretung keine Epochen anlegen darf, ist nur prüfbar, wenn die Mitgliederliste der `epoch.rec` eine Vertretung von einem Mitglied unterscheidet. Heute gibt es dafür keine Art.
- Vorschlag: Mitgliedsart 3 `delegate` in `gomail/v1/rec/epoch-member`. Eine Vertretung bekommt wie ein Mitglied eine Verpackung je Epoche ihres Zeitraums, darf aber weder Epochen signieren noch `folders.gml` oder Metadaten neu ausstellen; `share --from --to` trägt sie als Art 3 ein, `delegation-ended` entfernt sie.
- Bis zur Antwort: Auftrag 02 baut die Art 3 als strengste Lesart (`TODO(Q6)`), kein Befehl verwendet sie, bevor die Frage entschieden ist.

## Q7 Grund für `gomailctl mailbox rotate`

- Haltepunkt 1 (signierter Datensatz).
- Stelle: 9.2 `gomailctl mailbox rotate <postfach-id>`; 2.4 Tabelle der Gründe.
- Problem: `rotate` legt eine neue Epoche ohne Änderung der Mitglieder an. Keiner der sechs Gründe passt (`regular` ist der monatliche Vorrat mit Vorlauf).
- Vorschlag: `rotate` erzeugt eine Epoche mit Grund `regular` und sofortigem Beginn? Das widerspricht "geplant, mit Vorlauf". Besser: eigener Grund `rotated` (sofort, `discards` wie bei jeder sofortigen Epoche) in die Tabelle aufnehmen. Bis zur Antwort wird `rotate` nicht gebaut (`TODO(Q7)`), weil es nur einen neuen Grund braucht und nichts anderes davon abhängt.

## Q8 Widerruf von Plattformgenerationen und die Prüfbarkeit der Historie

- Haltepunkt 1 (signierter Datensatz, Prüfregel im Client) und 2 (Sicherheitsfund der Verifikation des Log-Entwurfs, Fund 3).
- Stelle: 2.3 „Wechsel der Identität“ („Clients lehnen ab diesem Update jede Signatur der kompromittierten Generation ab“), 2.2 Generationen Punkt 4 (für Benutzer: Logeinträge vor dem Widerruf bleiben gültig), 10.1 „Signatur einer kompromittierten Ingest- oder Identitätsgeneration“, 9.2 (`ingest-rotate`, keine Admin-Rotation).
- Problem: (a) Es gibt keinen Datensatz, der eine kompromittierte Ingest- oder Admin-Generation widerruft; 2.3 kennt nur den Wechsel der Identität per Client-Update. (b) Wörtlich genommen macht ein Widerruf der Identitätsgeneration g alle von ihr ausgestellten Zertifikate ungültig, damit jede bisher geloggte Adresszuordnung (vom Admin-Schlüssel signiert) und jede Ingest-Signatur alter Mails. Die Historie wäre nicht mehr prüfbar, und eine Reparatur durch neue Zuordnungen scheitert an der Regel „`valid_from` steigt streng“ für alte Empfangszeiten. (c) Nach `ingest-rotate` bleibt der alte Ingest-Schlüssel unbegrenzt gültig; ein gestohlener alter Schlüssel kann Metadaten mit späterer Empfangszeit signieren. (d) 2.3 nennt Admin-Generationen, aber keine Admin-Rotation in 9.2.
- Vorschlag: (a) Die Liste der kompromittierten Plattformgenerationen steht in `identity-<gen>.pin` (Feld 7: Rolle, Generation, Logstand `revoked_at_size`), verteilt wie die Identität per Client-Update. (b) Für Plattformgenerationen gilt dieselbe Regel wie für Benutzer (2.2 Punkt 4): Logeinträge und Signaturen, die vor dem Logstand des Widerrufs im Log standen (Zertifikate, Adresszuordnungen) oder deren Empfangszeit vor der Kopfzeit dieses Logstands liegt (Metadaten), bleiben gültig; neue Signaturen werden abgelehnt. (c) Ein Ingest-Schlüssel der Generation g signiert gültig nur Metadaten mit Empfangszeit vor `valid_from` von `ingest-<g+1>.cert`. (d) `gomail-ceremony admin-rotate` analog zu `ingest-rotate`.
- Bis zur Antwort: Der Entwurf lässt Feld 7 offen (`TODO(ask)`); Welle 2 baut (c) als strengste Lesart, die (a), (b) und (d) nicht berühren.
- Nachtrag (Verifikation 07, Angreifer): Für Admin-Generationen gibt es anders als für Ingest-Generationen kein Ende der Gültigkeit beim Wechsel; eine Admin-Generation g signiert nach dem Loggen von `admin-<g+1>.cert` und nach dessen `valid_from` weiter gültige Adresszuordnungen (`doc.go` verlangt nur `cert.valid_from ≤ valid_from`). 2.3 schweigt. Vorschlag: dieselbe Regel wie bei Ingest (Generation g gilt nur bis `valid_from` von `admin-<g+1>.cert`), sobald Q8 entschieden ist; bis dahin bleibt die gebundene Lesart.

## Q9 Zeitliche Bindung von Adresszuordnungen

- Haltepunkt 1 (signierter Datensatz, Prüfregel im Client) und 2 (Fund der Verifikation des Log-Entwurfs).
- Stelle: 2.3 „Der Client prüft für jede Mail, dass die Empfängeradresse laut Log zum Zeitpunkt des Empfangs seinem Postfach zugeordnet war“; Datensatz `gomail/v1/rec/address` mit `valid_from` (D53).
- Problem: `valid_from` wählt der Admin frei. Eine nach dem Empfang geloggte Zuordnung mit rückdatiertem `valid_from` kann Mails nachträglich einem Postfach zuschreiben (und mit einer früheren, nie geloggten Zuordnung lässt sich das nicht erkennen). Eine Obergrenze über die Kopfzeit des ersten deckenden Kopfs ist von Client zu Client verschieden und deshalb keine brauchbare Prüfregel.
- Vorschlag: Der Datensatz erhält ein signiertes Feld `issued` (Zeitpunkt der Ausstellung, Uhr des Admins). Regeln: `valid_from ≥ issued`; der Logeintrag muss in einem Kopf stehen, dessen Zeit höchstens `issued + 24 h` ist (sonst ist die Zuordnung ungültig); der Client nimmt eine Mail nur an, wenn `valid_from ≤ Empfangszeit` und die Zuordnung zur Empfangszeit die jüngste gültige war. Damit kann eine Zuordnung Mails höchstens aus den 24 Stunden vor ihrer Ausstellung nachträglich zuschreiben, und jeder Client urteilt gleich.
- Bis zur Antwort: Lesart „größtes `valid_from` ≤ Empfangszeit“ ohne Obergrenze (`TODO(Q9)`); der Entwurf nennt die Lücke.

## Q10 Entwurf 03 nach drei Nacharbeitsrunden mit sechs niedrigen Funden

- Haltepunkt 3 (Paket nach drei Nacharbeitsrunden mit offenen Funden).
- Stand: Der Entwurf für Log, Zeuge und Zeremonie (Auftrag 03, Nacharbeiten 03b, 03c, 03d) hat nach der vierten Prüfung keine Funde der Schwere hoch oder mittel mehr; offen sind sechs niedrige: (1) Pin-Feld 7 (nur falls Q8) kann 64 KiB sprengen → Konstante `MaxRevoked`; (2) `SignHead` darf `tree.rec` erst nach eigenem `fsync` des Verzeichnisses signieren (Sichtbarkeit vor Dauerhaftigkeit); (3) `CreateUser`/`WriteEpoch` müssen bei der Wiederaufnahme eine byte-gleiche vorhandene Datei als erledigt werten, die lokale Kopie wird direkt nach `mailbox.rec` entfernt; (4) Sicherung des Logs muss jeden je ausgelieferten Kandidaten decken, Ausweg bei Verlust: neuer Origin; (5) Betriebsregel: neuer Pin auf dem Server vor `Publish`/Neustart nach einer Nachfolge; (6) Wortlaut von `Refresh` (`Logged` aus dem Audit-Index bis zum neuen Kopf).
- Entscheidung des Orchestrators (vorbehaltlich deines Einspruchs): Der Entwurf wird zusammengeführt; die sechs Punkte sind als Pflichtpunkte in Auftrag 07 (Log-Umsetzung) und 11 (Serverseite) aufgenommen, weil sie Umsetzungsdetails ohne Formatänderung sind. Ein vierter Entwurfsdurchlauf würde 07 und 08 nur verzögern.

## Q11 Bindung der Laufnummer eines Indexsegments

- Haltepunkt 1 (Dateiformat und Prüfregel des Clients, von der Spezifikation nicht festgelegt); Fund niedrig des Angreifer-Verifizierers von Auftrag 09.
- Stelle: 3.1 Feld 4 („`file_id` gleich der ID im Dateinamen“), 4 (`index/<n>/<device-id>-<lfd>.gml`), 6.2, K5.
- Problem: Der Dateiname eines Segments besteht aus Gerätekennung und Laufnummer; `file_id` im signierten Kopf trägt nach der strengsten Lesart von 3.1 nur die Gerätekennung. Ein gültiges Segment, das der Server auf eine andere Laufnummer desselben Geräts kopiert, wird still angenommen. Folge: keine Falschtreffer und kein Leck (Treffer werden je Marke vereinigt), aber der Server kann die Segmentzahl aufblähen und das Zusammenfassen ab 16 früher auslösen; eine Kopie auf ein anderes Gerät wird erkannt.
- Vorschlag: `file_id` eines Segments ist der vollständige Basisname `<device-id>-<lfd>` (so bindet der Kopf genau eine Datei, wie 3.1 für Mails); der Client lehnt Segmente ab, deren `file_id` nicht dem Dateinamen gleicht. Keine Änderung an `rec`, `envelope` oder dem Datensatz `index-segment`; nur die Belegung eines bestehenden Kopffelds und die Prüfregel ändern sich. Alternativ die heutige Lesart in 3.1/6.2 festschreiben.
- Bis zur Antwort: heutige Lesart (`file_id` = Gerätekennung, `TODO(ask)` in `index.go`); Auftrag 09b ergänzt nur die Warnung bei doppelten Laufnummern.

## Q12 Thread-Wurzel in den Metadaten für Mails ohne Begriffsliste

- Haltepunkt 1 (signierter Datensatz `gomail/v1/rec/mail-meta`, Prüf- und Indexregel des Clients); Fund mittel des Spezifikations-Verifizierers von Auftrag 09; SPEC-ISSUES S23.
- Stelle: 5.4 (`thread:<message-id der Wurzel>` aus `References`, sonst `In-Reply-To`, sonst `Message-ID`), 6.2 Schritt 2 (Client bildet für Marker `unprocessed` die Begriffe aus den entschlüsselten Kopffeldern), 3.1 (Metadaten).
- Problem: Die Metadaten halten `Message-ID`, aber weder `References` noch `In-Reply-To`. Für eine Mail, deren Begriffsliste der Server nie nachliefert (Neustart, 5.3), bildet der Client `thread:` aus der eigenen `Message-ID` statt aus der Wurzel; `thread:<wurzel>` findet die Antwort dann nie. Keine Sicherheitsfolge, aber eine Abweichung von 5.4.
- Vorschlag: Die Metadaten erhalten ein Feld `thread` (Message-ID der Wurzel nach der Serverregel aus 5.4, höchstens 998 Byte, leer, wenn die Mail keine hat); der Server füllt es beim Empfang, der Client bildet `thread:` daraus. Das ändert den signierten Datensatz (neues Feld hinter den bestehenden, Version-1-Dateien ohne das Feld bleiben lesbar; `meta-signed` ändert sich nicht, weil es nur Kopf und Mail-Hash bindet) und berührt keine Phase-0-Vektoren. Alternative: 6.2 einschränken („`thread:` aus Metadaten ist die eigene Message-ID“).
- Bis zur Antwort: heutiges Verhalten (eigene Message-ID), in S23 vermerkt.

## Q13 Prüfregel „Generation darf in der Kette nicht sinken“ (`checkSignerGen`)

- Haltepunkt 1 (Prüfregel des Clients, von Spezifikation und Auftrag nicht festgelegt); `TODO(ask)` aus Auftrag 06b.
- Stelle: 2.2 Generationen Punkt 4 („Signaturen einer widerrufenen Generation sind nach dem Widerruf ungültig“, Logreihenfolge entscheidet), K2 Regel 1, 2.7; ohne Log (Phase 2, `translogtest.Unverified`) gibt es keine Logreihenfolge.
- Problem: Ohne Log kann ein Dieb mit dem alten Schlüsselspeicher nach `device lost` weiter Epochen anlegen, weil `CheckRevokedSignature` nichts prüft; die vom Auftrag verlangte Ablehnung (`ErrChain`) wäre nicht erreichbar.
- Gebaut (strengste Lesart): Der Client lehnt eine Epoche ab, die mit einer niedrigeren Generation eines Benutzers signiert ist, als eine frühere Epoche derselben Kette für ihn nennt (als Mitglied oder Unterzeichner, sofern `user.rec` diese Generation kennt). Folge: `ErrChain` beim Lesen; jenseits des Kopfs gilt die Epoche als nie gültig und wird ersetzt. Der Server (`ingest` mit `Unverified`) setzt die Regel nicht durch und verschlüsselt für eine solche Epoche; die Clients lehnen sie ab.
- Vorschlag: Die Regel als Regel 8 in `store.Chain.Add` aufnehmen, damit Client und Server sie gleich durchsetzen (Auftrag 15 oder 14); mit dem Log bleibt sie als zusätzliche, lokal prüfbare Schranke erhalten (sie ist eine Folge von 2.2 Punkt 4, sobald die Kette selbst als Zeitlinie gelesen wird). Alternativ nach Auftrag 14 wieder entfernen und nur `CheckRevokedSignature` gegen das Log verwenden.
- Bis zur Antwort: Regel bleibt im Client (`TODO(ask)`), nicht im Server.
