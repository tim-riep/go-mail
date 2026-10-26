# Offene Punkte der Spezifikation

Festgestellt bei der Umsetzung von Phase 0 (`rec`, `keys`, `shamir`, `envelope`) gegen `docs/PLAN.md`. Jeder Punkt nennt die Stelle, das Problem, wie Phase 0 damit umgeht, und einen Vorschlag. Die zugehörigen Umsetzungsentscheidungen stehen in `docs/DECISIONS.md`.

Keiner der Punkte ist ein Sicherheitsproblem, das den Bau hätte anhalten müssen. S01 und S06 betreffen die Robustheit des Formats, S09 ein Spannungsfeld im Entwurf, die übrigen sind Lücken oder Mehrdeutigkeiten.

Stand Phase 0.1 (Version 1.1 in `docs/PLAN.md`, Abschnitt 13): Erledigt sind S01, S02, S04, S06 (Lesepfad ab Phase 1), S07, S08, S09 und S12, jeweils unten mit Commit oder Verweis markiert.

Stand Phase 1 (Version 1.2, Abschnitt 14): S03, S05, S10 und S14 sind erledigt (Schritt 0, Commit d8d7afa). S11 und S13 tragen unten einen Vorschlag und warten auf die Entscheidung des Auftraggebers; bis dahin ist jeweils die strengste Lesart umgesetzt (DECISIONS D60). Neu aus Phase 1 sind S15 bis S23.

## S01 `.gml`: Ende der Blockfolge ist ohne Schlüssel nicht bestimmbar
- Erledigt in Phase 0.1 (Commit 53b92a0): Version 1.1 gibt jedem Element nach dem Empfängerteil ein Typbyte (`0x01` Block, `0x02` letzter Block, `0x03` Trailer). D29 ist aufgehoben, siehe D42.
- Stelle: 3.1 Aufbau, 3.3 Regel 7.
- Problem: Blöcke und Trailer sind beide `uint32 Länge || Bytes`. Das Ende der Blockfolge ist nur über das Letzter-Block-Flag im Nonce definiert, das ein Parser ohne Schlüssel nicht sieht. Nach einem vollen Block ist nicht entscheidbar, ob das nächste Längenfeld einen Block oder den Trailer einleitet, solange nur der Datenstrom und nicht die Dateilänge bekannt ist. Auch der Server, der laut 3.4 Signaturen ohne Schlüssel prüfen soll, braucht diese Grenze.
- Phase 0: Die Trailer-Länge ist das Längenfeld, dessen Wert genau den verbleibenden Bytes entspricht (DECISIONS D29). Das setzt die vollständige Datei voraus und schließt streamendes Parsen aus.
- Vorschlag: Die Grenze explizit machen, etwa durch die Zahl der Blöcke oder die Inhaltslänge im Kopf, oder durch einen Trailer, dessen Länge am Dateiende steht (Parsen vom Ende), oder durch ein Endmarker-Längenfeld (`0xFFFFFFFF`) vor dem Trailer. Bis dahin die Regel aus D29 in 3.1 aufnehmen.

## S02 NFC-Prüfung und Abhängigkeitsregel
- Erledigt in Phase 0.1 (Commit 4ee0b90): Version 1.1 lässt `golang.org/x/text` zu; die eigenen Tabellen sind entfernt, `x/text` ist auf v0.43.0 festgelegt. D09 und D10 sind aufgehoben.
- Stelle: 3.6 Regel 3 und 6; 1 Grundsätze (nur `x/crypto` und `x/mod`).
- Problem: Die Standardbibliothek kann keine Unicode-Normalisierung. Die Ablehnung nicht normalisierter Zeichenketten erfordert entweder `golang.org/x/text/unicode/norm` oder eigene Tabellen aus der Unicode-Datenbank.
- Phase 0: Eigene Tabellen und eine exakte Prüfung (DECISIONS D09, D10), knapp 1.500 Zeilen generierter Code, der bei jedem Unicode-Wechsel der Werkzeugkette neu erzeugt werden muss.
- Vorschlag: Entweder `golang.org/x/text` (vom Go-Team gepflegt, wie `x/crypto`) ausdrücklich zulassen, oder festlegen, dass die eigenen Tabellen gewollt sind und wer sie pflegt.

## S03 Kodierung von `info` beim Verpacken
- Erledigt in Version 1.2 (3.2 Schritt 2 und 4): `info` ist die Verkettung fester Breiten von genau 36 Byte, `Kopf` in der AAD ist der Kopfdatensatz ohne Längenfeld. Vollständig abgedeckt, entspricht D33; ein Test pinnt die 36 Byte (`TestWrapInfoLayout`).
- Stelle: 3.2 Schritt 2, "`info = "gomail/v1/wrap" || 0x00 || type || id || gen`, kanonisch kodiert".
- Problem: "Kanonisch kodiert" kann die Verkettung fester Breiten oder einen Datensatz nach 3.6 meinen. Beides ist eindeutig, aber inkompatibel zueinander.
- Phase 0: Verkettung fester Breiten (DECISIONS D33).
- Vorschlag: Die Bytefolge in 3.2 ausschreiben (`uint8 type || 16 Byte id || uint32 BE gen`), ebenso für die AAD-Eingabe festhalten, dass "Kopf" den Datensatz ohne sein Längenfeld meint.

## S04 Bedeutung von `kind` in der Signaturdomäne
- Erledigt in Version 1.1: 3.4 nennt den ASCII-Namen der Dateiart; entspricht D36, keine Codeänderung.
- Stelle: 3.4, `"gomail/v1/sig/" || kind || 0x00`.
- Problem: `kind` ist im Kopf ein `uint8`, in der Domäne könnte die Zahl oder der Name gemeint sein.
- Phase 0: Der Name (`gomail/v1/sig/meta`), DECISIONS D36.
- Vorschlag: In 3.4 die Namen nennen oder die Zahl festlegen.

## S05 Abgrenzung von Listenelementen
- Erledigt in Version 1.2 (3.6 Regel 4): Anzahl als uint32 Big Endian, jedes Element `Länge || eingebetteter Datensatz` mit Typ-String und Nullbyte, die Elementlängen füllen das Feld exakt. Vollständig abgedeckt, entspricht D05 und D06; der Decoder lehnt Restbytes nach dem letzten Element ab (`rec_test.go`, "list trailing bytes after elements").
- Stelle: 3.6 Regel 4.
- Problem: Datensätze sind nicht selbstbegrenzend; ohne Längenpräfix je Element ist die Kodierung einer Liste mehrdeutig.
- Phase 0: `Anzahl || (Länge || Element)*` (DECISIONS D06).
- Vorschlag: Regel 4 entsprechend ergänzen, inklusive der Aussage, dass jedes Element mit seinem Typ-String beginnt.

## S06 Empfängerteil unsignierter Dateien ist nicht geschützt
- Erledigt in Version 1.1 (3.1, 7): Der Client öffnet eine Mail nur, wenn der SHA-256 der gesamten Mail-Datei mit den signierten Metadaten übereinstimmt. Keine Änderung in Phase 0.1; betrifft die Lesepfade ab Phase 1. `File.FileHash` liefert für unsignierte Dateien genau diesen Hash.
- Stelle: 3.1, "bewusst nicht Teil der AAD der Blöcke"; 7, Mails selbst tragen keine Signatur.
- Problem: In einer Mail-Datei (`kind` 1, unsigniert) kann, wer die Datei schreiben darf, Einträge anderer Empfänger entfernen, verändern oder hinzufügen, ohne dass ein Empfänger es an seiner eigenen Entschlüsselung bemerkt. Ein Angreifer gewinnt damit keinen Schlüssel (ein neuer Eintrag ließe sich nur mit dem Dateischlüssel erzeugen), kann aber einzelne Mitglieder vom Lesen ausschließen (Verfügbarkeit) und das Entfernen eines Wiederherstellungsempfängers verschleiern.
- Phase 0: Verhalten dokumentiert und getestet (DECISIONS D39, `TestBitFlipForeignRecipient`).
- Vorschlag: Festhalten, dass die Integrität des Empfängerteils einer Mail über die signierten Metadaten gewährleistet wird (Abschnitt 7 nimmt den SHA-256 der verschlüsselten Mail-Datei in die Ingest-Signatur auf; dieser Hash deckt den Empfängerteil mit ab) und dass ein Client beim Lesen einer Mail diesen Hash prüft.

## S07 Keine Grenzen für KDF-Parameter aus dem Schlüsselspeicher
- Erledigt in Version 1.1 (2.2): Speicher 64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads, Prüfung vor Argon2id. Entspricht genau D22; keine Codeänderung, Tests für Unter- und Obergrenzen vorhanden.
- Stelle: 2.2 Lokale Ablage, "alle KDF-Parameter stehen im Kopf der Datei".
- Problem: Werden die Parameter aus der Datei übernommen, kann eine manipulierte Datei den Client zu beliebig großen Argon2-Reservierungen zwingen, bevor die Authentifizierung fehlschlägt (die AAD-Prüfung braucht den abgeleiteten Schlüssel).
- Phase 0: Unter- und Obergrenzen, Prüfung vor Argon2 (DECISIONS D22).
- Vorschlag: In 2.2 festlegen, welche Parameter beim Öffnen akzeptiert werden (mindestens die festen Werte, höchstens definierte Obergrenzen) oder nur exakt die festen Werte zulassen.

## S08 Formate der Plattformzertifikate und der Identitätsnachfolge fehlen
- Erledigt in Phase 0.1 (Commit 5863796): 2.3 legt `gomail/v1/rec/platform-cert` und `gomail/v1/rec/platform-succ` fest; `keys` ist angeglichen (D20, D46).
- Stelle: 2.3, `admin-<gen>.cert`, `ingest-<gen>.cert`, `identity-<gen>.succ`; 4 Ablage.
- Problem: Nur die Dateinamen und die Signierenden sind genannt, nicht die Felder.
- Phase 0: Minimale Datensätze (DECISIONS D20).
- Vorschlag: Die Felder in 2.3 aufnehmen; insbesondere, dass ein Zertifikat die Generation der signierenden Identität nennt, damit der Client den richtigen Schlüssel wählt.

## S09 Nachträgliche Empfänger und signierte Dateien
- Erledigt in Phase 0.1 (Commit 53b92a0): Version 1.1 führt den Empfängertyp 4 (`recovery`) ein, sodass der Wiederherstellungsempfänger beim Schreiben eingetragen wird (Vorschlag c). Die Signatur deckt den Empfängerteil weiterhin vollständig ab; nachträgliche Einträge bleiben damit ausgeschlossen.
- Stelle: 3.1, "damit spätere Empfängertypen (etwa ein Wiederherstellungsschlüssel) ohne Neuverschlüsselung des Inhalts ergänzt werden können" und "bei signierten Dateien deckt die Signatur den gesamten Empfängerteil ab".
- Problem: Beide Aussagen zusammen bedeuten, dass ein nachträglich ergänzter Empfänger die Signatur einer Metadaten-, Verpackungs- oder Begriffslisten-Datei ungültig macht. Für Ingest-signierte Dateien kann kein Mitglied neu signieren, ohne dass die Aussage der Ingest-Signatur verloren geht (Abschnitt 7 erlaubt die Benutzersignatur nur nach einer Flag-Änderung an Metadaten).
- Phase 0: Keine Vorkehrung; die Signatur deckt den gesamten Empfängerteil ab, wie gefordert.
- Vorschlag: Entscheiden, ob (a) der Empfängerteil aus dem signierten Hash herausgenommen wird und stattdessen jeder Eintrag durch HPKE an Kopf und Dateischlüssel gebunden bleibt, oder (b) das Ergänzen von Empfängern bei signierten Dateien ein Neusignieren durch ein Mitglied verlangt und Abschnitt 7 das vorsieht, oder (c) Wiederherstellungsempfänger immer beim Schreiben eingetragen werden (siehe offene Entscheidung 1 in Abschnitt 12).

## S10 50 MB gegenüber 800 Blöcken
- Erledigt in Version 1.2 (3.3 Regel 2): "50 MiB (52.428.800 Byte), also höchstens 800 Blöcke". Vollständig abgedeckt, entspricht D35. Die 25 MB in 5.1 (SMTP `SIZE`) und das 1 MB für Header in 5.2 sind davon unabhängig, siehe S15.
- Stelle: 3.3 Regel 2.
- Problem: 800 Blöcke zu 65.536 Byte sind 52.428.800 Byte (50 MiB, 52,4 MB), nicht 50 MB.
- Phase 0: 800 Blöcke (DECISIONS D35).
- Vorschlag: "50 MiB (800 Blöcke)" schreiben.

## S11 Normalisierung der Seed-Wörter bei der Eingabe
- Stelle: 2.2 Seed-Format, 9.2 `gomailctl keygen`, Wiederherstellung.
- Problem: Nicht festgelegt, ob Eingaben mit Großbuchstaben, zusätzlichem Leerraum oder Unicode-Varianten angenommen werden. BIP-39 empfiehlt NFKD-Normalisierung der Eingabe.
- Phase 0: `keys.SeedFromWords` verlangt die Wörter exakt wie in der Liste (DECISIONS D14).
- Vorschlag: In 2.2 die Eingabenormalisierung der Kommandozeile festlegen (Trimmen, Kleinschreibung, Trennung an Leerraum).
- Phase 1: Offen, zur Entscheidung vorgelegt. `gomailctl keygen` vergleicht die drei abgefragten Wörter exakt, entfernt wird nur das Zeilenende (`TODO(S11)`, DECISIONS D60). Betroffen sind in Phase 1 nur diese Abfrage, später die Eingabe des Seeds (neues Gerät, Wiederherstellung, `device lost`) und der Shamir-Anteile.
- Vorschlag Phase 1: Eine Regel für jede Eingabe von Wörtern (Seed und Shamir-Anteile), nur in der Kommandozeile, `keys` und `shamir` bleiben strikt:
  1. Die Eingabe wird nach Unicode NFKD normalisiert (wie BIP-39 es für Eingaben empfiehlt), dann werden Groß- in Kleinbuchstaben umgewandelt.
  2. Getrennt wird an jedem Leerraum (Leerzeichen, Tabulator, Zeilenumbruch, auch mehrfach); führender und folgender Leerraum fällt weg. Bei der Abfrage einzelner Wörter muss genau ein Wort übrig bleiben.
  3. Jedes Wort muss danach exakt in der Liste stehen. Abkürzungen auf die ersten vier Buchstaben (in BIP-39 eindeutig) werden **nicht** angenommen: eine Abkürzung wäre ein zweiter Weg zum selben Seed und eine weitere Fehlerquelle, und die Wörter werden ohnehin selten getippt.
  4. Ein unbekanntes Wort wird mit seiner Position gemeldet, ohne es auszugeben; die Prüfsumme deckt vertauschte oder falsche, aber gültige Wörter.
  Damit akzeptiert `keygen` etwa " Abandon " für "abandon", aber nie ein anderes Wort. Kein Format ändert sich.

## S12 Suite 2 ändert die Größen im Empfängerteil
- Erledigt in Phase 0.1 (Commit 53b92a0): Version 1.1 senkt die Höchstzahl der Empfänger auf 4; vier Einträge der Suite 2 (je etwa 1,2 KiB) passen in die 16 KiB. Die Feldgrößen je Suite sind erst beim Einführen von Suite 2 festzulegen.
- Stelle: 3.5, Suite 2 mit `MLKEM768X25519`.
- Problem: Die Kapselung dieses KEM ist 1.120 Byte groß statt 32. Der Höchstwert von 16 KiB für den Empfängerteil reicht für 32 Einträge (etwa 40 KiB) dann nicht mehr; außerdem müssen Schemas je Suite verschiedene feste Längen haben.
- Phase 0: Schema und Grenzen gelten für Suite 1.
- Vorschlag: Beim Einführen von Suite 2 die Höchstwerte in 3.1 und die Feldgrößen je Suite festlegen.

## S13 Widerrufsprüfung braucht das Log
- Stelle: 2.2 Generationen Punkt 4, 2.3 Widerrufe.
- Problem: Ob eine Signatur einer widerrufenen Generation "nachweislich vor dem Widerruf im Log stand", lässt sich erst mit dem Transparenzlog (Phase 6) prüfen. Phase 0 kann nur die Kette der Generationszertifikate prüfen.
- Phase 0: `VerifyGenerationChain` prüft Lückenlosigkeit und Signaturen; die zeitliche Einordnung bleibt offen.
- Vorschlag: Kein Änderungsbedarf an der Spezifikation; Hinweis für Phase 2 und 6 (siehe HANDOFF).
- Phase 1: Offen, zur Entscheidung vorgelegt. Bei der Umsetzung zeigt sich eine Lücke in 2.2 Punkt 4: "nur akzeptiert, wenn sie nachweislich vor dem Widerruf im Log standen" lässt sich nur für Datensätze prüfen, die ins Log kommen (`user.rec`, `epoch.rec`, Zertifikate, Nachfolgen, Adresszuordnungen, Vermerke). Verpackungen (`members/<user>.wrap`), Metadaten nach einer Flag-Änderung, `folders.gml` und der Name in `mailbox.rec` sind ebenfalls mit der Identität eines Benutzers signiert, kommen aber nie ins Log. Wörtlich genommen wären sie nach einem Widerruf für immer ungültig, auch die, die ein Mitglied vor dem Verlust seines Geräts für andere Mitglieder erstellt hat. Umgesetzt ist vorläufig genau das, also die strengste Lesart (`TODO(S13)`, DECISIONS D60); in Phase 1 gibt es nur Generation 1, die Regel greift also noch nicht.
- Vorschlag Phase 1:
  1. **Datensätze im Log:** Eine Signatur einer widerrufenen Generation gilt genau dann, wenn der signierte Datensatz im Log vor dem Eintrag steht, der die Generation widerruft (Vergleich der Log-Indizes, Inklusionsbeweis für beide). Umgesetzt über `translog.CheckRevokedSignature`, das heute schon aufgerufen wird.
  2. **Dateien außerhalb des Logs:** Signaturen einer widerrufenen Generation gelten nie. Stattdessen erneuert der Client bei `gomailctl device lost` mit der neuen Generation alles, was die alte signiert hat: neue Verpackungen für alle Mitglieder, die er verpackt hat (nicht nur für sich selbst, das verlangt 2.2 Punkt 5 schon), neue Versionen geänderter Metadaten, neue `folders.gml` und einen neu versiegelten Namen. Bis das geschehen ist, kann ein anderes Mitglied dieselben Dateien mit seiner Identität neu ausstellen.
  3. Damit ein kompromittiertes Gerät in der Zeit bis zum Widerruf nichts Dauerhaftes anrichten kann, nehmen Clients beim Abgleich nur Verpackungen an, deren Mitglied in der signierten `epoch.rec` steht (umgesetzt), und verlangen nach einem Widerruf die neue Verpackung, bevor sie weitere Mails dieser Epoche anzeigen.
  4. In 2.2 Punkt 4 und in Abschnitt 7 sollte diese Trennung ausdrücklich stehen.
  Kein Format ändert sich; Phase 2 baut damit `device lost`, Phase 3 die Log-Prüfung.

## S14 Signaturdomäne der Plattformdatensätze verdoppelt das Präfix
- Erledigt in Phase 1, Schritt 0 (Commit d8d7afa): Version 1.2 legt in 3.7 Kurznamen für alle Signaturen fest; `keys` ist umgestellt, Vektoren neu erzeugt (DECISIONS D47).
- Stelle: 2.3 (Version 1.1), "mit dem Präfix `"gomail/v1/sig/" || Datensatztyp || 0x00`".
- Problem: Der Datensatztyp ist laut Tabelle der volle Typ-String, die signierte Nachricht beginnt also mit `gomail/v1/sig/gomail/v1/rec/platform-cert`. Das ist eindeutig, aber vermutlich nicht beabsichtigt; für das Generationszertifikat in 2.2 ist keine Domäne genannt (Phase 0 nutzt `generation`).
- Phase 0.1: Wörtlich umgesetzt (DECISIONS D46).
- Vorschlag: Entweder bestätigen oder in 2.3 einen Kurznamen (`platform-cert`, `platform-succ`) nennen und in 2.2 die Domäne des Generationszertifikats festlegen.


## S15 Einheiten in 5.1 bis 5.3
- Stelle: 5.1 "maximale Größe 25 MB", "1 KB/s gemittelt über 60 Sekunden"; 5.2 und 5.3 "Header, begrenzt auf 1 MB".
- Problem: Seit Version 1.2 nennt 3.3 die Größe in MiB; in 5.1 bis 5.3 bleibt offen, ob MB und KB dezimal oder binär gemeint sind.
- Phase 1: Dezimal, wie bei SMTP üblich (`SIZE 25000000`, 1.000.000 Byte Header, 1.000 Byte je Sekunde), DECISIONS D54.
- Vorschlag: In 5.1 "25.000.000 Byte (SIZE)", "1.000 Byte/s" und in 5.2 "1.000.000 Byte" schreiben.

## S16 `user.rec` ist laut Abschnitt 7 signiert, 3.7 hat dafür keinen Kurznamen
- Stelle: 7 Tabelle "`user.rec` signiert von Identität des Benutzers"; 3.7 Tabelle der Kurznamen; 2.2 JSON-Beispiel ohne Signatur auf oberster Ebene.
- Problem: Die Tabelle in 3.7 soll alle Signaturen erfassen, enthält aber keinen Kurznamen für `user.rec`. Das JSON-Beispiel in 2.2 hat nur die Signaturen der Generationen durch den Root. Ohne eine Signatur über `user_id` und `root_pub` bindet nur das Log die Benutzer-ID an den Root.
- Phase 1: `user.rec` ohne eigene Signatur; die Generationen sind durch den Root geschützt, die Bindung an die ID übernimmt später das Log (DECISIONS D59).
- Vorschlag: Entweder in 7 "signiert von der Identität" streichen (die Generationszertifikate sind die Signaturen) oder in 3.7 einen Kurznamen `user` ergänzen und festlegen, welche Generation signiert.

## S17 Einladungen: signiert oder nicht?
- Stelle: 2.1 "platform/admin/<gen> signiert Adresszuordnungen und Einladungen"; 4 `invites/<code>.json`; 3.7 ohne Kurzname für Einladungen.
- Problem: Eine signierte Einladung bräuchte einen Kurznamen; als JSON-Datei ist sie keine kanonische Struktur.
- Phase 1: Unsignierte JSON-Datei mit Erstellzeit; der Code ist eine zufällige ID und wird beim Registrieren atomar verbraucht (DECISIONS D53).
- Vorschlag: In 2.1 "und Einladungen" streichen oder einen Datensatz `gomail/v1/rec/invite` mit Kurzname `invite` festlegen.

## S18 `epoch.rec` nennt weder Postfach noch Unterzeichner
- Stelle: 2.4 Inhalt von `epoch.rec`.
- Problem: Ohne Postfach-ID lässt sich eine `epoch.rec` (vor allem Epoche 1, die keinen Vorgänger nennt) in ein anderes Postfach desselben Mitglieds verschieben. Ohne Angabe des Unterzeichners muss der Prüfer alle Mitglieder durchprobieren.
- Phase 1: Postfach-ID und Unterzeichner (ID, Generation) sind Felder des Datensatzes (DECISIONS D49).
- Vorschlag: Beide Felder in 2.4 aufnehmen.

## S19 "Sofortiger Beginn" einer Epoche und Uhrzeiten
- Stelle: 2.4 Vorrat, "Der nächste Client erzeugt dann eine Epoche mit sofortigem Beginn"; Schutz gegen Zurückspielen, dritter Punkt.
- Problem: Der Beginn kommt von der Uhr des Clients, die Empfangszeit von der Uhr des Servers, und zwischen dem Erzeugen und dem Sichtbarwerden der neuen `epoch.rec` vergeht Zeit. Eine Mail, die der Server in dieser Lücke annimmt, wird für die alte Epoche verschlüsselt, obwohl die neue laut ihrem Beginn schon gilt; der Client meldet sie dann als Zurückspielen.
- Phase 1: Die Epoche beginnt fünf Minuten nach dem Erzeugen (DECISIONS D50). Die Empfangszeit ist der Beginn von `DATA`.
- Vorschlag: In 2.4 "mit Beginn wenige Minuten nach dem Erzeugen" schreiben und die zulässige Uhrabweichung zwischen Client und Server nennen.

## S20 Name und Ordner hängen an Epoche 1
- Stelle: 4 `mailbox.rec` "Name (verschlüsselt)", `folders.gml` "verschlüsselt mit meta"; 2.5, 2.6.
- Problem: Nicht festgelegt ist, für welche Epoche Name und Ordnerliste verschlüsselt werden. Phase 1 nimmt Epoche 1. Ein Mitglied, das nur spätere Epochen bekommt (Vertretung, "nur ab jetzt"), kann den Namen dann nicht lesen; wird Epoche 1 gelöscht (2.6), ist er für alle verloren. Außerdem muss der Server den Posteingang kennen, ohne `folders.gml` lesen zu können.
- Phase 1: Name und `folders.gml` für Epoche 1, signiert vom anlegenden Mitglied; die ID des Posteingangs steht offen in `mailbox.rec` (DECISIONS D56).
- Vorschlag: Name und Ordnerliste bei jedem Epochenwechsel für die neue Epoche neu versiegeln (sie sind klein) oder einen eigenen, dauerhaften Postfachschlüssel dafür einführen; die Posteingangs-ID in 4 als offenes Feld von `mailbox.rec` nennen.

## S21 Mehrere Dateien und Postfächer atomar verschieben
- Stelle: 5.2 Schritt 4 "werden Mail, Metadaten und Marker atomar in das jeweilige Postfach verschoben", `spool/<postfach-id>/<mail-id>.gml`.
- Problem: Drei Dateien in zwei Verzeichnissen, bei mehreren Empfängern in mehreren Postfächern, lassen sich nicht mit einer Umbenennung verschieben. Bricht der Server mittendrin ab, liegt ein Teil im Postfach. Die Regel "beim Start den gesamten Inhalt von spool/ löschen" räumt das nicht auf.
- Phase 1: Transaktion je Annahme unter `spool/<txn-id>/<postfach-id>/` mit Journal; das Löschen des Journals ist der Commit, `Recover` macht nicht abgeschlossene Umbenennungen rückgängig, bevor `spool/` geleert wird (DECISIONS D52).
- Vorschlag: In 5.2 das Journal und den Commit-Punkt beschreiben und den Spool-Pfad anpassen.

## S22 Signierte Felder der Metadaten sind ohne Schlüssel nicht prüfbar
- Stelle: 3.4 "sodass auch der Server Signaturen ohne Schlüssel prüfen kann"; 7 signierte Felder einschließlich Empfangszeit, "Metadaten tragen einen Versionszähler, der ... mitsigniert wird".
- Problem: Postfach, Epoche, Mail-ID stehen im Kopf, der Hash der Metadaten ist der Datei-Hash, der Hash der Mail-Datei lässt sich ohne Schlüssel berechnen. Versionszähler (und bei Benutzersignaturen die ursprüngliche Empfangszeit) stehen aber nur im verschlüsselten Inhalt. Wer sie für die signierte Struktur braucht, muss entschlüsseln; der Server kann die Signatur also nicht prüfen.
- Phase 1: Nur der Client prüft; er entschlüsselt, baut die Felder und prüft die Signatur, bevor er einen Wert verwendet (DECISIONS D51).
- Vorschlag: Entweder festhalten, dass nur Clients Metadaten-Signaturen prüfen, oder Version und Empfangszeit lesbar machen (etwa im Dateinamen `<mail-id>.<version>.meta.gml` oder in einem offenen Feld des Trailers).

## S23 Begriffe aus 5.4 im Einzelnen
- Stelle: 5.4 Tabelle.
- Problem: Offen ist, ob `to` auch `Cc` umfasst, ob `day` und `month` aus dem `Date`-Header oder der Empfangszeit kommen, wann eine Mail einen Anhang hat und wie die Wurzel eines Threads bestimmt wird.
- Phase 1: `to` aus `To` und `Cc`; `day` und `month` aus der signierten Empfangszeit in UTC; Anhang bei `multipart/mixed` auf oberster Ebene; Wurzel ist der erste Eintrag von `References`, sonst `In-Reply-To`, sonst die eigene `Message-ID` (DECISIONS D55).
- Vorschlag: Diese Regeln in 5.4 aufnehmen; sie bestimmen, welche Marken ein Client in Phase 5 sucht.
