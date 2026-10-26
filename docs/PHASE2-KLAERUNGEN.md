# go-mail: Klärungen vor Phase 2

Stand: 26.10.2026, Grundlage Spezifikation 1.3 und Abschlussbericht Phase 1

Jeder Punkt hat einen Vorschlag. Punkte mit **Status: entschieden** gelten für Phase 2 verbindlich, solange du sie nicht änderst. Punkte mit **Status: offen** muss das Modell vorlegen, bevor es baut, was davon abhängt.

## K1. Vorrat an Epochen beim Entfernen eines Mitglieds

**Status: entschieden**

**Problem.** Spezifikation 2.4 sieht einen Vorrat von Epochen für drei Monate vor. Wird ein Mitglied entfernt, beginnt laut 2.5 sofort eine neue Epoche. Die bereits angelegten künftigen Epochen enthalten aber noch die Verpackung des entfernten Mitglieds, und es kennt ihre Schlüssel, vielleicht hat es sie sogar selbst erzeugt. Ohne Regel würde der Server nach dem nächsten Monatswechsel wieder für eine Epoche verschlüsseln, die das entfernte Mitglied lesen kann.

**Entscheidung.**

1. Beim Entfernen eines Mitglieds werden alle Epochen verworfen, deren Beginn in der Zukunft liegt. Umgesetzt über das signierte Feld `discards` der neuen, sofortigen Epoche nach Spezifikation 1.4, Abschnitt 2.4. Es gibt keinen eigenen Vermerk.
2. Die neue Epoche beginnt sofort, und der Vorrat wird ohne das entfernte Mitglied neu angelegt.
3. Eine verworfene Epoche darf nie wieder gültig werden. Der Client lehnt jede Mail ab, die für sie verschlüsselt ist.
4. Dasselbe gilt beim Ende einer Vertretung und bei `device lost`, falls die Vertretung bzw. die widerrufene Generation in künftigen Epochen steht.

## K2. Wer eine Epoche anlegen darf

**Status: entschieden**

**Problem.** Mit mehreren Mitgliedern muss feststehen, wer die nächste Epoche signieren darf und was bei zwei gleichzeitig angelegten Epochen mit derselben Nummer passiert. Ohne Transparenzlog gibt es dafür keine Instanz.

**Entscheidung.**

1. Epoche n+1 darf nur ein Mitglied von Epoche n signieren, dessen Generation zum Zeitpunkt des Signierens gültig ist. Ein Wiederherstellungsempfänger und eine Vertretung dürfen keine Epochen anlegen.
2. Ein entferntes Mitglied darf die Epoche, die es entfernt, nicht signieren. Die Epoche mit Grund `member-removed` muss von einem verbleibenden Mitglied stammen.
3. Bei zwei Epochen mit derselben Nummer gilt die zuerst unter der Postfachsperre geschriebene. Die zweite wird vom `store` abgelehnt. Der Client des Verlierers legt seine Änderung auf der Grundlage der Siegerin neu an.
4. Phase 3 ersetzt Regel 3 durch die Reihenfolge im Transparenzlog. Bis dahin `TODO(phase3-translog)`.

## K3. Wiederherstellungsempfänger: wer setzt ihn, wer verwahrt ihn

**Status: entschieden für den Mechanismus, offen für die Pflicht**

**Problem.** Würde der Admin den öffentlichen Wiederherstellungsschlüssel festlegen, könnte ein kompromittierter Admin ihn durch einen eigenen ersetzen und so jedes Postfach lesen, das ihn annimmt. Das wäre eine Hintertür.

**Entscheidung zum Mechanismus.**

1. Der Wiederherstellungsschlüssel ist ein eigener Seed, erzeugt mit `gomailctl recovery keygen --shares 3-of-5` und per Shamir auf Vertrauenspersonen der Organisation verteilt. Er gehört nicht der Plattform.
2. Er wird nur von einem Mitglied des Postfachs eingetragen, als Eintrag in der Mitgliederliste der `epoch.rec`, signiert wie jede Epoche. Der Admin kann ihn weder setzen noch ändern.
3. Ein Wechsel des Wiederherstellungsschlüssels ist eine neue Epoche mit Grund `recovery-changed`. Der Client zeigt den Fingerabdruck des neuen Schlüssels an und verlangt eine Bestätigung.
4. Mit dem Wiederherstellungsschlüssel kann man Epochen entpacken und sich selbst neu als Mitglied aufnehmen. Er kann keine Epochen anlegen (K2).

**Offen.** Ob ein Wiederherstellungsempfänger für Geschäftspostfächer Pflicht ist. Für Phase 2 genügt: Er ist optional und pro Postfach einstellbar.

## K4. Gleichzeitige Änderungen an Metadaten

**Status: entschieden**

**Problem.** In geteilten Postfächern können zwei Mitglieder gleichzeitig Flags derselben Mail ändern. Beide erhöhen den Versionszähler auf denselben Wert.

**Entscheidung.**

1. Eine neue Metadatenversion wird nur geschrieben, wenn ihr Versionszähler genau um 1 über dem aktuell gespeicherten liegt. Die Prüfung erfolgt unter der Postfachsperre.
2. Scheitert sie, liest der Client die aktuelle Version, wendet seine Änderung erneut an und versucht es wieder.
3. Flags werden als Menge gespeichert. Das erneute Anwenden setzt oder entfernt nur die Flags, die der Benutzer geändert hat.

## K5. Suchindex bei mehreren Mitgliedern

**Status: entschieden**

**Problem.** Spezifikation 6.2 sieht eine Datei `postings.gml` pro Epoche vor. Bei mehreren Mitgliedern verarbeiten mehrere Clients gleichzeitig `pending/` und müssten dieselbe Datei umschreiben.

**Entscheidung.**

1. Statt einer Datei gibt es unveränderliche Segmente `index/<n>/<device-id>-<laufnummer>.gml`, je für den `meta`-Schlüssel der Epoche verschlüsselt und vom Client signiert.
2. Ein Client, der `pending/` verarbeitet, schreibt erst sein Segment atomar und löscht danach die verarbeiteten Einträge in `pending/`.
3. Verarbeiten zwei Clients denselben Eintrag, entstehen doppelte Treffer. Beim Lesen werden Treffer pro Marke zusammengeführt und doppelte Mail-IDs entfernt.
4. Ab 16 Segmenten pro Epoche fasst der nächste Client sie zu einem zusammen und löscht die alten. Das Zusammenfassen läuft unter der Postfachsperre.

## K6. Prüfbarkeit der Ingest-Signatur ohne Schlüssel

**Status: entschieden.** Vorschlag aus Phase 2 übernommen, Kopffeld 8 `version`, siehe Spezifikation 1.4, Abschnitte 3.1 und 7. Der folgende Text ist die ursprüngliche Fragestellung.

**Problem.** Laut `SPEC-ISSUES.md` aus Phase 1 ist die Ingest-Signatur ohne Schlüssel nicht prüfbar. Spezifikation 3.4 verspricht das Gegenteil. Vermutlich liegen Felder der signierten Struktur nur im verschlüsselten Teil der Metadaten.

**Vorschlag.** Alle Felder der signierten Struktur stammen entweder aus dem Klartextkopf der Datei oder sind Hashes über Chiffrat. Fehlt dafür ein Feld im Kopf, etwa der Versionszähler, wird der Kopf um ein Feld erweitert. Das ändert das Format aus Phase 0 und braucht neue Vektoren.

**Vorgehen.** Das Modell legt den Eintrag aus `SPEC-ISSUES.md` und seinen Vorschlag vor und hält an, bevor es das Format ändert.

## K7. Haltepunkte

**Status: entschieden**

In Phase 1 hat das Modell an einem vorgegebenen Haltepunkt weitergebaut, mit nachvollziehbarer Begründung. Für Phase 2 gilt deshalb eine eindeutige Regel:

- Anhalten ist Pflicht, wenn eine offene Entscheidung ein Dateiformat, einen signierten Datensatz, eine Signaturdomäne oder eine Prüfregel im Client betrifft.
- Weiterbauen mit der strengsten Lesart ist erlaubt, wenn nichts davon betroffen ist. Die Stelle wird mit `TODO(Kn)` markiert und im Abschlussbericht aufgeführt.
- Im Zweifel gilt Anhalten.

## K8. Entfernen eines Mitglieds während laufender Annahme

**Status: entschieden**

Zwischen dem Anlegen der neuen Epoche und dem Moment, in dem der Server sie bemerkt, können Mails noch für die alte Epoche verschlüsselt werden. Spezifikation 2.4 lässt der Client solche Mails ablehnen. Das ist für ein entferntes Mitglied richtig, für die verbleibenden aber ein Verlust.

**Ergänzung.** Die Regeln zu Vorlauf und Uhren stehen jetzt in Spezifikation 1.4, Abschnitt 2.4, und ersetzen den Vorlauf aus D50 für sofortige Epochen.

**Entscheidung.** Der Server liest die aktuelle Epoche bei jedem `DATA` unter der Postfachsperre neu. Damit gibt es kein Zeitfenster, solange Server und Client dasselbe Datenverzeichnis sehen. Über NFS kann ein Zeitfenster durch zwischengespeicherte Daten entstehen. Deshalb wird `mailbox.rec` immer erst nach Erwerb der `fcntl`-Sperre geöffnet und gelesen. Der Linux-NFS-Client prüft beim Sperren seinen Cache für diese Datei neu. Ein Test auf getrennten Maschinen muss das bestätigen. Mails, die trotzdem für eine bereits ersetzte Epoche verschlüsselt wurden, lehnt der Client wie bisher ab und zeigt sie als "nicht zustellbar, erneut anfordern" an.

## Bewusst nicht in Phase 2

- Löschen von Epochen (Crypto-Shredding nach 2.6). Offen ist, wer es auslösen darf (offene Entscheidung 5 der Spezifikation). Folgt in Phase 3.
- Volltextindex im Client (6.4)
- Kopplung neuer Geräte per QR-Code und Übertragung von `state.json`
- Transparenzlog, Zeugen, echte Zeremonie
