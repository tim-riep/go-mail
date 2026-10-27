# Offene Punkte der Spezifikation

Festgestellt bei der Umsetzung von Phase 0 (`rec`, `keys`, `shamir`, `envelope`) gegen `docs/PLAN.md`. Jeder Punkt nennt die Stelle, das Problem, wie Phase 0 damit umgeht, und einen Vorschlag. Die zugehörigen Umsetzungsentscheidungen stehen in `docs/DECISIONS.md`.

Keiner der Punkte ist ein Sicherheitsproblem, das den Bau hätte anhalten müssen. S01 und S06 betreffen die Robustheit des Formats, S09 ein Spannungsfeld im Entwurf, die übrigen sind Lücken oder Mehrdeutigkeiten.

Stand Phase 0.1 (Version 1.1 in `docs/PLAN.md`, Abschnitt 13): Erledigt sind S01, S02, S04, S06 (Lesepfad ab Phase 1), S07, S08, S09 und S12, jeweils unten mit Commit oder Verweis markiert.

Stand Phase 1 (Version 1.2, Abschnitt 14): S03, S05, S10 und S14 sind erledigt (Schritt 0, Commit d8d7afa). S11 und S13 tragen unten einen Vorschlag und warten auf die Entscheidung des Auftraggebers; bis dahin ist jeweils die strengste Lesart umgesetzt (DECISIONS D60). Neu aus Phase 1 sind S15 bis S23.

## Stand M1
- Grundlage: Version 1.4 (`docs/PLAN.md`, Abschnitt 16) und `docs/PHASE2-KLAERUNGEN.md`. Neu sind S24 bis S69 aus den Prüfberichten der Aufträge bis M1.
- Jeder neue Punkt trägt eine Art. **Klarstellend:** Die Spezifikation schweigt oder ist mehrdeutig, der Code hat eine Lesart gewählt, die Spezifikation sollte sie übernehmen. **Offen:** Eine Entscheidung des Auftraggebers ist nötig, die Frage steht in `docs/QUESTIONS.md`, soweit eine Nummer genannt ist.
- Zahl: 46 neue Punkte, davon 36 klarstellend und 10 offen.
- Offen: S24 (Q8), S25 (Q8), S27 (Q9), S28 (Q4, Q8), S35 (ohne Frage), S43 (Q1), S44 (Q1), S48 (Q4), S52 (ohne Frage, `TODO(ask)`), S69 (ohne Frage, `TODO(ask)`). Dazu bleibt S23 offen (Q12).
- Bestehende Punkte: S11 und S13 sind im Client umgesetzt (Auftrag 06b), S23 hängt an Q12; der Stand steht jeweils unten. S22 ist mit Version 1.4 erledigt (Kopffeld 8 `version`, K6); der Server prüft jede eigene Signatur ohne Schlüssel nach dem Schreiben (`ingest.VerifyMeta`, D73). S15 ist teilweise erledigt: 5.1 nennt seit Version 1.3 25 MiB; Header (1.000.000 Byte) und Mindestrate (1.000 Byte/s) bleiben dezimal (D67).
- Der Stand im Code bezieht sich auf den Arbeitszweig. Wo ein Punkt Auftrag 06b, 09 oder 10 nennt, liegt der Code noch in dessen Worktree und ist nicht zusammengeführt.
- Zu prüfen: S34 (Quellen und Code widersprechen sich).

## Stand Welle 4
- Grundlage: weiter Version 1.4. Neu sind S70 bis S87 aus den Aufträgen 06b bis 06h, 10 und 15b, 15c und 15d, 16 bis 16c, aus Auftrag 14 (Nachtrag und Pflichtpunkte) sowie aus Q13, Q15, Q18 und Q19.
- Zahl: 18 neue Punkte, davon 9 klarstellend und 9 offen.
- Offen: S71 (Q13), S72 (Q15), S73 (Q18), S75 (ohne Frage), S76 (Q19), S77 (ohne Frage, `TODO(ask)`), S80 (ohne Frage), S83 (ohne Frage), S87 (ohne Frage).
- Q16 und Q17 sind Haltepunkte zum Ablauf, keine Fragen an die Spezifikation; ihr fachlicher Inhalt steht in S70, S74 und S78.
- Der Code zu S76, S77, S78 und S86 (Auftrag 15b) liegt noch in dessen Worktree (Commit 11259ef) und ist nicht zusammengeführt.
- Präzisiert werden S24 (durch S76), S32 (S78), S56 (S79), S65 (S82 bis S84) und S67 (S86); dort steht jeweils ein Verweis.

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
- Stand M1: Version 1.3 übernimmt den Vorschlag (2.2 „Eingabe von Wörtern“). Im Client umgesetzt in Auftrag 06b (`client.normalizeWords`, `oneWord`, `normalizeList`, verwendet in `keygen`, `DeviceLost` und `Restore`); `keys` und `shamir` bleiben strikt. Auftrag 10 bringt dieselbe Regel als Paket `internal/words`, das die Funktionen des Clients ersetzen soll.

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
- Stand M1: Version 1.3 übernimmt den Vorschlag (2.2 Punkt 4). Umgesetzt in Auftrag 06b: Gegensignatur der eigenen Verpackung (`client.writeAccept`, `checkAccept`, Datensatz `wrap-accept`) und Neuausstellung bei `device lost` (`client.DeviceLost`). Für Metadaten mit Benutzersignatur und für Indexsegmente gilt noch die strengste Lesart (`TODO(S13)` in `client/read.go` und `client/index.go`, Auftrag 09); Auftrag 09b überträgt die Regel aus 06b, sonst fallen nach `device lost` Mails aus `List`.

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
- Stand M1: Offen bleibt die Thread-Wurzel für Mails mit Marker `unprocessed`. Die Metadaten halten weder `References` noch `In-Reply-To`; der Client bildet `thread:` aus der eigenen `Message-ID` (`client/terms.go`, Auftrag 09), eine Antwort ist unter der Wurzel dann nicht auffindbar. Ob die Metadaten ein Feld `thread` erhalten, entscheidet Q12.

## S24 Widerruf kompromittierter Ingest- und Admin-Generationen
- Art: offen (Q8).
- Stelle: 2.3 „Wechsel der Identität“ und „Widerrufe und Aktualität“; 10.1 „Signatur einer kompromittierten Ingest- oder Identitätsgeneration“.
- Problem: 2.3 kennt nur den Wechsel der Identität per Client-Update. Für eine kompromittierte Ingest- oder Admin-Generation gibt es keinen Datensatz, der sie widerruft.
- Stand M1: Der Pin hat kein Feld 7 (`store.PlatformPinSchema`), `translog.Verifier.Revoked` bleibt leer, die Stellen tragen `TODO(ask)`.
- Ergänzung aus der Prüfung von 03b: Feld 7 braucht neben `revoked_at_size` auch `revoked_at_time`, weil Köpfe einer Größe mit späteren Zeiten neu signiert werden und die Kopfzeit zu `revoked_at_size` sonst nicht eindeutig ist (`internal/translog/doc.go`, „Platform generations“).
- Vorschlag: Wie Q8 (a) und (b), mit `revoked_at_time` als viertem Bestandteil von Feld 7.
- Siehe S76 (Q19) für die Kompromittierung der Plattformidentität selbst.

## S25 Gültigkeitsende einer Plattformgeneration nach dem Wechsel
- Art: offen (Q8).
- Stelle: 2.3 „Für einen neuen Ingest-Schlüssel …“, 9.2 (`ingest-rotate`, keine Admin-Rotation).
- Problem: Nach `ingest-rotate` bleibt der alte Ingest-Schlüssel nach 2.3 unbegrenzt gültig; ein gestohlener alter Schlüssel könnte Metadaten mit späterer Empfangszeit signieren. Für Admin-Generationen gilt dasselbe für Adresszuordnungen.
- Stand M1: Strengste Lesart für Ingest: Generation g signiert gültig nur bis `valid_from` von `ingest-<g+1>.cert` (`translog.LogKey.Covers` für Köpfe, D72 (9)). Für Admin-Generationen gibt es kein Ende (Q8, Nachtrag).
- Vorschlag: Wie Q8 (c), dieselbe Regel für Admin-Generationen, und Q8 (d) `admin-rotate`.

## S26 Umschaltzeitpunkt bei `ingest-rotate`
- Art: klarstellend.
- Stelle: 2.3 „Für einen neuen Ingest-Schlüssel … neue Zeremonie“; 2.4 „Vorlauf und Uhren“ Regel 4.
- Problem: Gilt die neue Generation ab der Zeremonie, gehen Mails verloren, die der Server zwischen Zeremonie und Umschalten noch mit dem alten Schlüssel signiert (die Clients lehnen sie nach S25 ab).
- Stand M1: `gomail-ceremony ingest-rotate --valid-from` setzt den geplanten Umschaltzeitpunkt; ein Zeitpunkt in der Vergangenheit wird abgelehnt (`ceremony.checkValidFrom`, Auftrag 10). Auf dem Arbeitszweig steht dazu noch `TODO(ask)` an `ceremony.IngestRotate`.
- Vorschlag: In 2.3 festhalten, dass `valid_from` des neuen Zertifikats der geplante Umschaltzeitpunkt ist und nie in der Vergangenheit liegt.

## S27 Zeitliche Bindung von Adresszuordnungen
- Art: offen (Q9).
- Stelle: 2.3 „Adresszuordnungen“.
- Problem: `valid_from` wählt der Admin frei. Eine später geloggte Zuordnung mit rückdatiertem `valid_from` schreibt Mails nachträglich einem Postfach zu.
- Stand M1: Der Datensatz hat kein Feld `issued` (`store.AddressSchema`); es gilt die jüngste Zuordnung mit `valid_from ≤ Empfangszeit` ohne Obergrenze (`translog.Log.CheckAddress`, `TODO(Q9)`).
- Vorschlag: Wie Q9.

## S28 Format des Pins `identity-<gen>.pin`
- Art: offen (Q4, Q8).
- Stelle: 2.3 „öffentlicher Teil im Client hinterlegt“, „Wechsel der Identität“; 2.7 „Die öffentlichen Schlüssel der Zeugen sind im Client hinterlegt wie die Plattformidentität“.
- Problem: 2.3 nennt den Pin, legt aber seine Felder nicht fest.
- Stand M1: `store.PlatformPinSchema` mit Generation, Schlüssel, Entwicklungskennzeichen, Feld 4 `origin`, Feld 5 `witnesses`, Feld 6 `min_witnesses` und Feld 8 `identities` (alle Identitätsgenerationen), höchstens 64 KiB (D72 (7)); Feld 7 fehlt bis Q8 (S24). Der Server bekommt denselben Pin.
- Vorschlag: Die Felder in 2.3 aufnehmen, sobald Q4 und Q8 entschieden sind.

## S29 Probe-Rekonstruktion und Grenzen der Aufteilung
- Art: klarstellend.
- Stelle: 2.3 „Zeremonie“ Schritt 4 („aus drei zufällig gewählten Anteilen“).
- Problem: „drei“ passt nur zu 3-of-5; `--shares` lässt andere Aufteilungen zu.
- Stand M1: Die Probe nimmt k (die Schwelle) zufällig gewählte Anteile; zulässig ist 2 ≤ k ≤ n ≤ 16 (`ceremony.splitAndProbe`, `pick`, `Shares.check` mit `MaxShareCount`, Auftrag 10).
- Vorschlag: „aus k zufällig gewählten Anteilen“ schreiben und die Grenzen nennen.

## S30 Export erst nach der Probe
- Art: klarstellend.
- Stelle: 2.3 „Zeremonie“ Schritte 2 und 4.
- Problem: Nach 2.3 werden die öffentlichen Teile in Schritt 2 exportiert, die Probe folgt in Schritt 4.
- Stand M1: Vor der Probe wird nichts geschrieben; Export und Schlüssel folgen erst nach bestandener Probe (`ceremony.Init`: `splitAndProbe` vor `commit`, D72 (11), Auftrag 10).
- Vorschlag: Den Export in 2.3 hinter die Probe setzen.

## S31 Neuverteilung macht alte Anteile nicht ungültig
- Art: klarstellend.
- Stelle: 2.3 „Für … eine Neuverteilung der Anteile kommen drei Anteilsinhaber … zusammen“.
- Problem: 2.3 sagt nicht, was eine Neuverteilung bewirkt. Alte Anteile rekonstruieren weiter denselben Root.
- Stand M1: `ceremony.Reshare` teilt denselben Root neu mit neuer Kennung der Aufteilung; die Kennung warnt nur beim Mischen alter und neuer Anteile (Auftrag 10).
- Vorschlag: In 2.3 festhalten, dass eine Neuverteilung nur gegen verlorene Anteile und Wechsel der Inhaber hilft; sind genug alte Anteile in falschen Händen, ist der Root zu ersetzen (Kompromissfall nach „Wechsel der Identität“).

## S32 Terminalregeln der Zeremonie
- Art: klarstellend.
- Stelle: 2.3 „Zeremonie“; 9.2 `gomail-ceremony`.
- Problem: 2.3 nennt keine Regeln für Anzeige und Eingabe der Anteile.
- Stand M1: Anteile erscheinen und werden eingegeben nur, wenn stdin und stdout ein Terminal mit abschaltbarem Echo sind; keine Eingabe aus Datei oder Pipe; nach jedem Schritt wird der Bildschirm samt Scrollback gelöscht; stderr muss kein Terminal sein, weil dort keine Geheimnisse erscheinen (`cmd/gomail-ceremony`: `isTerminal`, `errNoTerminal`, `clearScreen`, Auftrag 10). Betriebsregel im RUNBOOK: nur an der Linux-Konsole, kein tmux, screen, script oder Emulator mit eigenem Verlauf.
- Vorschlag: Diese Regeln in 2.3 aufnehmen.
- Siehe S78 (getrennte Terminals, Signale nach dem Commit).

## S33 Eingetippte Anteile bleiben im Speicher
- Art: klarstellend (bekannte Grenze).
- Stelle: 2.2 „private Schlüssel werden nach Gebrauch im Speicher überschrieben, soweit Go das zulässt“; 2.3 „Zeremonie“.
- Problem: Die Grenze ist nur für den Schlüsselspeicher genannt. Getippte Anteilswörter liegen im Puffer von `bufio` und in Go-Zeichenketten, die sich nicht überschreiben lassen.
- Stand M1: `cmd/gomail-ceremony` löscht die eigenen Zeilenpuffer, die Kopien in Zeichenketten bleiben bis zur Speicherbereinigung (Auftrag 10).
- Vorschlag: Die Grenze in 2.3 nennen; die Zeremonie läuft ohnehin auf einem Rechner, der danach ausgeschaltet wird (Schritt 5).

## S34 Schlüsselverzeichnis als symbolischer Link
- Art: klarstellend, **zu prüfen**.
- Stelle: 2.3 „Zeremonie“; 9.2 `gomail-ceremony` (die Option `--keys` nennt die Spezifikation nicht).
- Problem: Nicht festgelegt ist, wie die Zeremonie das Verzeichnis für private Schlüssel prüft.
- Stand M1: Laut Prüfung von 10b wird `--keys` als Link aufgelöst und das Ziel geprüft (0700, eigener Benutzer, `O_NOFOLLOW` beim Öffnen); Q14 nennt dasselbe Verhalten als offenen Hinweis. Der Code in Auftrag 10 (Stand 10d) lehnt dagegen einen Link im letzten Element ab (`ceremony.checkKeyFiles` mit `Lstat`, `openKeyDir` mit `O_NOFOLLOW`). Welche Aussage gilt, ist zu prüfen.
- Vorschlag: In 9.2 festhalten: `--keys` ist ein eigenes Verzeichnis mit 0700 des ausführenden Benutzers, kein symbolischer Link.

## S35 Verwerfen bereits begonnener Epochen
- Art: offen (keine Frage in `QUESTIONS.md`).
- Stelle: 2.4 „Verwerfen des Vorrats“ Regel 1 und 4; K1.
- Problem: `discards` richtet sich nach dem Beginn der neuen Epoche, den ihr Unterzeichner wählt. Legt ein Mitglied den Beginn einer sofortigen Epoche früh, verwirft sie auch Epochen, die schon begonnen haben; deren Mails lehnt der Client danach ab (Regel 3).
- Stand M1: `store.Chain.Add` prüft die Vollständigkeit von `discards` und den Beginn gegen die letzte nicht verworfene Vorgängerin, aber gegen keine Uhr; verworfene Nummern zählen dabei nicht mit.
- Vorschlag: Der Beginn einer sofortigen Epoche liegt nicht vor dem Beginn der laufenden, nicht verworfenen Epoche und höchstens fünf Minuten nach dem Anlegen.

## S36 Grund der Ausweich-Epoche bei erschöpftem Vorrat
- Art: klarstellend (Q5, D63).
- Stelle: 2.4 „Vorrat“ („eine Epoche mit sofortigem Beginn“), Tabelle der Gründe.
- Problem: Keiner der sechs Gründe passt; „sofort“ hätte nach der Tabelle Regel 2 und Vorlauf Regel 2 zur Folge.
- Stand M1: Die Ausweich-Epoche trägt `regular` und beginnt wie jede geplante Epoche fünf Minuten nach dem Anlegen (`client.ImmediateDelay` in `syncMailbox`). Zum Beginn siehe S19.
- Vorschlag: In 2.4 „eine geplante Epoche mit Grund `regular`, Beginn fünf Minuten nach dem Anlegen“ schreiben.

## S37 Beginn von Epoche 1
- Art: klarstellend.
- Stelle: 2.4 „Vorlauf und Uhren“ Regel 1, Tabelle der Gründe.
- Problem: Epoche 1 hat keinen Grund in der Tabelle; als `regular` müsste sie nach Regel 1 fünf Minuten Vorlauf haben, und der Server nähme so lange nichts an.
- Stand M1: Epoche 1 trägt `regular` und beginnt beim Anlegen (`client.CreateMailbox`, D75 (9)). Ohne Vorgängerin gibt es nichts, wofür zu spät verschlüsselt werden könnte.
- Vorschlag: In 2.4 festhalten, dass die erste Epoche `regular` trägt und ohne Vorlauf beginnt.

## S38 `member-added` nur sofort
- Art: klarstellend (D63).
- Stelle: 2.4 Tabelle der Gründe („geplant oder sofort“), „Verwerfen des Vorrats“ Regel 2.
- Problem: Aus `epoch.rec` ist nicht ablesbar, welche Form gemeint ist; Regel 2 (bei geplanter Wirkung ist `discards` leer) ist für `member-added` damit nicht prüfbar.
- Stand M1: `member-added` gilt immer als sofort (`store.Reason.Immediate`); gebaut wird nur diese Form.
- Vorschlag: In der Tabelle „sofort“ schreiben.

## S39 Vorlauf geplanter Epochen ist nicht prüfbar
- Art: klarstellend.
- Stelle: 2.4 „Vorlauf und Uhren“ Regel 1.
- Problem: `epoch.rec` hat keine Erstellzeit; ob eine geplante Epoche fünf Minuten nach dem Anlegen beginnt, kann kein Prüfer feststellen.
- Stand M1: Regel 1 ist Pflicht des Schreibers: der Client legt geplante Epochen frühestens fünf Minuten in der Zukunft an (`client.supply`, `ImmediateDelay`); `store.Chain` prüft sie nicht.
- Vorschlag: Regel 1 in 2.4 als Pflicht des anlegenden Clients kennzeichnen; mit dem Log ließe sie sich gegen die Logzeit prüfen.

## S40 Gleicher Beginn gilt nicht als später
- Art: klarstellend.
- Stelle: 2.4 „Verwerfen des Vorrats“ Regel 1 („mit späterem Beginn“) und Regel 4 („Beginn sinkt nie“).
- Problem: Offen ist, wie zwei Epochen mit gleichem Beginn zu behandeln sind.
- Stand M1: Gleicher Beginn ist nicht später: eine solche Epoche wird nicht verworfen, und gleicher Beginn verletzt Regel 4 nicht (`store.Chain.Add`, D68).
- Vorschlag: In Regel 1 „mit echt späterem Beginn“ schreiben.

## S41 Kopf der Kette für Leser
- Art: klarstellend.
- Stelle: 2.4 „Schutz gegen Zurückspielen“; 4 (`mailbox.rec` „aktuelle Epoche“).
- Problem: Offen ist, ob eine gültige `epoch.rec` jenseits von `mailbox.rec` für Leser zählt und wer `mailbox.rec` fortschreibt.
- Stand M1: Für Leser endet die Kette bei `mailbox.rec`; Epochen jenseits davon übernimmt nur ein Schreiber unter der Postfachsperre nach vollständiger Prüfung (`client.loadChain` mit `adopt`, `mutate`, `syncMailbox`; D75 (2)).
- Vorschlag: In 4 festhalten, dass `mailbox.rec` den Kopf bestimmt und jeder Client sie unter der Postfachsperre auf die letzte geprüfte Epoche vorrücken darf.

## S42 Nicht reguläre `epoch.rec` hinter dem Kopf
- Art: klarstellend (bekannte Grenze).
- Stelle: 2.4 „Schutz gegen Zurückspielen“; 7 „Verhalten des Clients bei Fehlern“.
- Problem: Die Spezifikation sagt nicht, was mit einer Datei bei Kopf+1 geschieht, die sich weder lesen noch als nie gültig beweisen lässt.
- Stand M1: Der Client ersetzt nur beweisbar ungültige Dateien (`client.readBeyond`, `createEpoch` mit `store.ClearInvalidEpoch` und `ReplaceInvalidEpoch`, D75 (3)). Ein Verzeichnis oder FIFO an dieser Stelle bleibt liegen, und jede Änderung am Postfach scheitert dauerhaft (fail closed). Ein FIFO blockiert `store.ReadFileLimited`, weil `os.Open` vor der Prüfung auf eine reguläre Datei wartet.
- Vorschlag: Als bekannte Grenze festhalten (Schreibzugriff auf das Datenverzeichnis erlaubt nach 2.7 ohnehin Vorenthalten); mit dem Log entscheidet `ErrOrder` über das Ersetzen (Auftrag 14).

## S43 Ablage des öffentlichen Wiederherstellungsschlüssels
- Art: offen (Q1 (c)).
- Stelle: 2.4 „Wiederherstellungsempfänger“; 4.
- Problem: Abschnitt 4 nennt keinen Ort, über den der öffentliche Schlüssel zum eintragenden Mitglied kommt.
- Stand M1: `mailboxes/<id>/recovery/<recovery-id>.pub`, unsigniert, per Fingerabdruck je Gerät bestätigt (`store.RecoveryPubFile`, D75 (7), `TODO(Q1)`).
- Vorschlag: Wie Q1 (c).

## S44 Wiederaufnahme durch den Wiederherstellungsempfänger
- Art: offen (Q1 (d)).
- Stelle: 2.4 „Wiederherstellungsempfänger“; K3 Punkt 4 und K2 Regel 1.
- Problem: K3 Punkt 4 erlaubt dem Wiederherstellungsempfänger, sich selbst neu als Mitglied aufzunehmen; K2 Regel 1 verbietet ihm, Epochen anzulegen, und ohne neue Epoche ist keine Aufnahme möglich.
- Stand M1: Der Wiederherstellungsschlüssel liest nur (`client.RecoverRead`, `ErrReadOnly`).
- Vorschlag: Wie Q1 (d).

## S45 Vertretung mit geplantem Ende
- Art: klarstellend.
- Stelle: 2.5 „Vertretung“; 9.2 `mailbox share … [--to <epoche>]`.
- Problem: Offen ist, ob eine Vertretung mit einem Ende in der Zukunft angelegt werden kann.
- Stand M1: `client.Share` nimmt `To` nur vor der laufenden Epoche an (`ErrRange`); eine laufende Vertretung endet über `Revoke` mit `delegation-ended`.
- Vorschlag: In 2.5 festhalten, dass `--to` nur vergangene Zeiträume begrenzt und eine laufende Vertretung durch Entzug endet.

## S46 Entzug löscht Verpackungen aller nicht verworfenen Epochen
- Art: klarstellend (strenger als die Spezifikation).
- Stelle: 2.5 Tabelle, „Zugriff entziehen“ („keine Verpackungen mehr für neue Epochen“).
- Problem: 2.5 spricht nur von neuen Epochen; ob die Verpackungen bestehender Epochen bleiben, ist offen.
- Stand M1: `client.Revoke` löscht die Verpackungen des Entzogenen für alle nicht verworfenen Epochen und legt sofort `member-removed` bzw. `delegation-ended` an (D75 (6)).
- Vorschlag: In 2.5 „seine Verpackungen aller Epochen werden gelöscht“ schreiben; was er schon gelesen hat, bleibt nach 2.5 ohnehin bei ihm.

## S47 Prüfung nach dem Entzug beim Lesen statt beim Sync
- Art: klarstellend.
- Stelle: 2.5 „Clients der verbleibenden Mitglieder prüfen beim Sync …“.
- Problem: `sync` öffnet keine Mails; geprüft werden kann die verwendete Epoche erst an den Metadaten.
- Stand M1: Die Epochenregel gilt beim Lesen der Metadaten und Begriffslisten (`client.checkEpochRule`, aufgerufen aus `checkMeta` für `List` und `Read` und aus `OpenPending`), nicht in `Sync`.
- Vorschlag: „prüfen beim Lesen“ schreiben.

## S48 Kopfformat: Origin und Zeitzeile
- Art: offen (Q4).
- Stelle: 2.7 „Der Server signiert regelmäßig den Baumkopf“; 2.3 Aktualitätsgrenze; 3.7 letzter Absatz.
- Problem: Nicht festgelegt sind Schlüssel, Origin und Zeit des Kopfs; eine `note` hat keinen Zeitstempel.
- Stand M1: Kopf als `note` mit `origin`, Größe, Hash und Zeile `time <ms>`, signiert mit dem Ingest-Schlüssel als `gomail-log` (`translog` `head.go`, D72 (2), `TODO(Q4)`).
- Vorschlag: Wie Q4.

## S49 `witnesses.rec` ist eine unsignierte Arbeitskopie
- Art: klarstellend.
- Stelle: 4 (`witnesses.rec` „öffentliche Schlüssel der Zeugen“); 2.7 „im Client hinterlegt wie die Plattformidentität“.
- Problem: Offen ist, ob `witnesses.rec` signiert ist und wen sie bindet.
- Stand M1: Unsigniert, bindet nur den Server (welche Gegensignaturen er annimmt, wie viele ein Kopf braucht); verbindlich für Clients ist die Liste im Pin (`witness.WitnessesSchema`, D72 (8)).
- Vorschlag: In 4 „Arbeitskopie des Servers, verbindlich ist der Pin“ schreiben, wie bei `addresses.json`.

## S50 Zeugenquorum und die Garantie bei „zwei aus drei“
- Art: klarstellend.
- Stelle: 2.7 „Zeugen“ („mindestens zwei aus drei“) und „Garantien“ („Unter der Annahme, dass nicht alle geforderten Zeugen mit dem Server zusammenarbeiten“).
- Problem: Bei min aus n Zeugen ist eine geteilte Sicht nur ausgeschlossen, wenn weniger als 2·min − n Zeugen mit dem Server zusammenarbeiten. Bei zwei aus drei ist das kein einziger: ein kolludierender Zeuge genügt für zwei Sichten mit je einem ehrlichen Zeugen.
- Stand M1: Pin und `witnesses.rec` verlangen 2·min > n (`translog.CheckQuorum`, D72 (5)).
- Vorschlag: Die Regel 2·min > n in 2.7 aufnehmen und die Garantie mit der Schranke 2·min − n formulieren.

## S51 Vermerk ohne Postfach-ID
- Art: klarstellend.
- Stelle: 2.7 „Abgleich zwischen Clients“; 4 `checkpoints/<user-id>-<device-id>.rec`; 3.7 `checkpoint`.
- Problem: Der Vermerk nennt kein Postfach und lässt sich in ein anderes Postfach kopieren.
- Stand M1: `store.CheckpointSchema` (Benutzer, Gerät, Origin, Größe, Wurzelhash, Kopfzeit, Generation); der Client schreibt denselben Vermerk in jedes seiner Postfächer. Eine Kopie sagt nur, welchen Kopf das Gerät gesehen hat, und ist deshalb harmlos.
- Vorschlag: In 2.7 festhalten, dass ein Vermerk das Gerät und nicht das Postfach betrifft.

## S52 Kopfzeit eines kleineren Vermerks
- Art: offen (keine Frage in `QUESTIONS.md`, `TODO(ask)`).
- Stelle: 2.7 „Abgleich zwischen Clients“.
- Problem: Die Spezifikation legt nicht fest, welche Rolle die Kopfzeit eines Vermerks bei der Prüfung spielt.
- Stand M1: Strengste Lesart: Ein Vermerk kleiner als der eigene Kopf mit späterer Kopfzeit zeigt, dass der Server für ein anderes Gerät eine alte Größe weiter signiert hat (`ErrConsistency`); bei gleicher Größe sind beide Richtungen erlaubt, ein größerer Vermerk ist `ErrPending` (`translog.Verifier.CheckCheckpoint`).
- Vorschlag: Diese Lesart bestätigen oder die Kopfzeit nur zur Anzeige verwenden.

## S53 Signierte Struktur führt den Unterzeichner
- Art: klarstellend.
- Stelle: 3.4 („Die kanonische Struktur enthält immer den SHA-256 …“); 7 (`meta-signed` nennt nur die Generation des Unterzeichners).
- Problem: 3.4 nennt als festen Inhalt nur den Hash der Datei; ob Art, ID und Generation des Unterzeichners mitsigniert werden, sagt allein 7, und dort nur die Generation.
- Stand M1: `envelope.SignedSchema` signiert für jede Dateiart `file_hash`, `signer_type`, `signer_id`, `signer_gen` und die art-spezifischen Felder als eingebetteten Datensatz `extra`.
- Vorschlag: Die Felder der signierten Struktur in 3.4 aufzählen.

## S54 Höchstgröße des Trailers
- Art: klarstellend.
- Stelle: 3.1 (Höchstwerte nur für Kopf und Empfängerteil); 3.3 „Grenzen für den Parser“.
- Problem: Für das Element `0x03` nennt die Spezifikation keine Obergrenze.
- Stand M1: `envelope.MaxTrailerSize` ist 1.024 Byte und wird vor jeder Reservierung geprüft.
- Vorschlag: In 3.1 „Trailer höchstens 1 KiB“ ergänzen.

## S55 `signer_id` der Ingest-Signatur
- Art: klarstellend.
- Stelle: 3.4 (`signer_id` 16 Byte).
- Problem: Für `signer_type` 1 (Plattform-Ingest) gibt es keine Benutzer-ID.
- Stand M1: `signer_id` besteht aus 16 Nullbytes, die Generation wählt den Schlüssel (D49); die Selbstprüfung des Servers lehnt eine andere ID ab (`ingest.parseIngestSigned`).
- Vorschlag: In 3.4 festhalten.

## S56 `pending` signiert keine Zusatzfelder
- Art: klarstellend.
- Stelle: 3.4 („Je nach Dateiart kommen weitere Felder hinzu (siehe 7)“); 7.
- Problem: 7 legt Zusatzfelder nur für `meta` fest; für `pending` schweigt die Spezifikation.
- Stand M1: `extra` bleibt leer (`ingest.pendingSignedExtra`); Postfach, Epoche, Datei-ID und `created` sind über den Kopf im Hash der Datei gebunden.
- Vorschlag: In 7 festhalten, dass `pending` nur Hash und Unterzeichner signiert.
- Siehe S79 (Bedeutung von `created` bei `pending`).

## S57 Inhalt von `folders.gml`
- Art: klarstellend.
- Stelle: 4 (`folders.gml` „Name des Postfachs und Ordnerliste, für meta dieser Epoche, signiert“).
- Problem: Abschnitt 4 nennt weder Dateiart noch Datensatz noch die Belegung des Kopfs.
- Stand M1: Datei der Art `meta` mit `file_id` gleich dem Posteingang und Versionszähler im Kopf; Inhalt `gomail/v1/rec/folders` mit Postfach-ID, Epoche, Name und Ordnerliste (`store.FoldersSchema`, D69).
- Vorschlag: In 4 aufnehmen.

## S58 Schutz von `folders.gml` gegen Zurückspielen
- Art: klarstellend.
- Stelle: 7 „Gegen Wiedereinspielen“ (nur Metadaten); 3.1 Feld 8.
- Problem: Eine ältere, gültig signierte `folders.gml` derselben Epoche lässt sich zurückspielen; den Versionszähler verlangt 7 nur für Metadaten.
- Stand M1: Jede Neuschrift erhöht `version`; der Client merkt sich je Epoche die höchste gesehene Version (`Folders` in `state.json`) und lehnt ältere ab (`client`, D75 (8)).
- Vorschlag: 7 auf `folders.gml` ausdehnen.

## S59 Auswahl der Ordnerliste bei nicht öffnender Verpackung
- Art: klarstellend.
- Stelle: 4 „Ein Client liest die Liste der neuesten Epoche, auf die er Zugriff hat“.
- Problem: „Zugriff“ ist nicht bestimmt. Eine untergeschobene Verpackung in einer späteren Epoche, die sich nicht öffnen lässt, kann die Auswahl auf diese Epoche lenken.
- Stand M1: `client.folderList` wählt die neueste nicht verworfene Epoche, in der der Client gelistet ist oder eine eigene Verpackung vorliegt (`ownWrapExists`, nur `Lstat`); lässt sie sich nicht öffnen, scheitert `List` ohne Rückfall (fail closed, Schutz gegen Zurückspielen, D75 (8)). Wer schreiben kann, kann nach 2.7 ohnehin vorenthalten.
- Vorschlag: Die Lesart in 4 festhalten; alternativ festlegen, dass eine nicht öffnende Verpackung übersprungen wird.

## S60 Verzeichnis `locks/`
- Art: klarstellend.
- Stelle: 4; 9.1 „Testsperre“.
- Problem: Abschnitt 4 nennt keine Sperrdateien.
- Stand M1: `locks/server` (exklusiv) und `locks/client` (geteilt) im Datenverzeichnis (`store.Store.HoldRoleLock`, `CheckPeerLock`, D70).
- Vorschlag: `locks/` in 4 aufnehmen.

## S61 `identity-<gen>.pub` neben der Nachfolge
- Art: klarstellend.
- Stelle: 4 (`identity-1.pub`, `identity-2.succ`).
- Problem: Für Generationen ab 2 nennt Abschnitt 4 nur `.succ`.
- Stand M1: `gomail-ceremony succeed` schreibt für jede neue Generation auch `identity-<gen>.pub` (`ceremony.runSucceed`, Auftrag 10).
- Vorschlag: In 4 `identity-<gen>.pub` für jede Generation nennen.

## S62 `SIZE` zählt nur die Daten des Absenders
- Art: klarstellend.
- Stelle: 5.1 („maximale Größe 25 MiB … `SIZE` in `EHLO`“); 5.2 Schritt 2 (`Received`-Header).
- Problem: Offen ist, ob der vom Server ergänzte `Received`-Header zur Grenze zählt.
- Stand M1: Gezählt werden nur die Zeilen des Absenders nach dem Dot-Unstuffing mit CRLF; der `Received`-Header zählt nicht (Lesart von RFC 1870, `smtpd` `session.data`).
- Vorschlag: In 5.1 „gezählt werden die Daten des Absenders“ ergänzen.

## S63 Namen und Bits der Flags
- Art: klarstellend.
- Stelle: 7 („Ändert ein Benutzer Flags …“); K4 Punkt 3.
- Problem: Die Spezifikation nennt keine Flags.
- Stand M1: Bits 0 bis 4 des signierten Felds `flags`: `seen`, `answered`, `flagged`, `deleted`, `draft`; unbekannte Bits bleiben unverändert (`client.flagBits`, Auftrag 09). Keine Formatänderung.
- Vorschlag: Die Liste in 7 aufnehmen.

## S64 Nur Benutzer-Mitglieder ändern Flags
- Art: klarstellend.
- Stelle: 7 Tabelle („`<mail-id>.meta.gml` nach Flag-Änderung, Identität des Benutzers“).
- Problem: Offen ist, welcher Benutzer Metadaten neu signieren darf.
- Stand M1: Nur ein Benutzer-Mitglied (Art 1) der Epoche der Mail, mit seiner aktuellen Generation; Vertretung und Wiederherstellungsempfänger nicht (`client.setFlags`, `checkMeta`, Auftrag 09).
- Vorschlag: In 7 „Identität eines Benutzer-Mitglieds der Epoche“ schreiben.

## S65 Testsperre: der Server setzt keinen Client voraus
- Art: klarstellend (Bestätigung erbeten).
- Stelle: 9.1 „Beim Start prüfen Server und Client, dass eine Testsperre von der jeweils anderen Seite wirksam ist“.
- Problem: Läuft noch kein Client, kann der Server dessen Sperre nicht prüfen und dürfte nach dem Wortlaut nicht starten.
- Stand M1: Der Client prüft die Sperre des laufenden Servers; der Server hält nur seine eigene Sperre und startet ohne Client (`store.Store.CheckPeerLock`, `ingest.Config.PeerCheck` standardmäßig aus; D70, D73). Das Verdrahten in den Programmen ist Auftrag 15.
- Vorschlag: In 9.1 „Der Client prüft beim Start die Sperre des Servers“ schreiben.
- Siehe S82 (`--require-client-lock`), S83 (kein Befehl hält die Client-Sperre) und S84 (keine Echtheit).

## S66 Mehrere Clients gleichzeitig
- Art: klarstellend.
- Stelle: 9.1.
- Problem: Eine exklusive Client-Sperre ließe nur einen Client je Datenverzeichnis zu.
- Stand M1: Die Rollensperre des Clients ist geteilt; mehrere Clients laufen gleichzeitig (`store.RoleClient`, D70).
- Vorschlag: In 9.1 festhalten.

## S67 Befehle und Optionen der Zeremonie
- Art: klarstellend.
- Stelle: 2.3 „Zeremonie“ (offline, ohne Netzwerk); 9.2 (`init`, `ingest-rotate`, `reshare`).
- Problem: Die Zeremonie läuft offline und kann das Log nicht schreiben; ein Wechsel der Identität (2.3) hat keinen Befehl.
- Stand M1: Zusätzlich `succeed` (Nachfolge, `--compromised` für den Kompromissfall, bis zur Aufhebung von `TODO(task-07)` gesperrt) und `publish` (bringt den Export ins Datenverzeichnis und ins Log); Optionen `--out`, `--keys`, `--origin`, `--witness`, `--min-witnesses`, `--pin`, `--gen`, `--valid-from`, bei `publish` `--from`, `--data`, `--pin` (`cmd/gomail-ceremony`, D72 (11), Auftrag 10). Gedeckt durch M1-Kriterium C.
- Vorschlag: Die Befehle und Optionen in 9.2 aufnehmen.
- Siehe S86 (Form von `--witness`) und S77 (Zeugenwechsel über `succeed`).

## S68 Optionen des Zeugen
- Art: klarstellend.
- Stelle: 9.2 `gomail-witness serve --log <url> --key <schlüsseldatei>`.
- Problem: Ohne Log-Schlüssel, Origin und Zustandsverzeichnis kann der Zeuge die Regeln aus 2.7 nicht prüfen.
- Stand M1: Zusätzlich `--log-key` (bei einer Ingest-Rotation zweimal), `--origin`, `--state`, `--interval` und der Befehl `keygen` (`cmd/gomail-witness`, D74).
- Vorschlag: In 9.2 aufnehmen.

## S69 Entwicklungszeremonie und Zeuge
- Art: offen (keine Frage in `QUESTIONS.md`, `TODO(ask)`).
- Stelle: 9.2 `gomail-ceremony init`; 2.7 (mindestens ein Zeuge).
- Problem: 9.2 nennt keine Option für den Zeugen einer Entwicklungszeremonie (`init --dev`).
- Stand M1: Ohne angegebene Zeugen erzeugt `ceremony.InitDev` einen Entwicklungszeugen (`gomail-dev-witness`, Schlüssel 0600 im Schlüsselverzeichnis) und pinnt ihn mit Quorum 1 aus 1.
- Vorschlag: Entscheiden, ob die Entwicklungszeremonie einen eigenen Zeugen erzeugt oder Zeugen wie `init` verlangt.

## S70 `device lost` erzeugt immer eine neue Generation
- Art: klarstellend (Q16, D84).
- Stelle: 2.2 „Generationen“ Punkt 2; 2.2 „Was der Benutzer selbst tun muss“ (`gomailctl device lost`, „erzeugt eine neue Generation“); 9.2.
- Problem: Offen ist, was ein zweiter Aufruf bewirkt, wenn der erste die Neuausstellung nicht in allen Postfächern abgeschlossen hat. Auftrag 06b hat dafür einen Modus „nur fortsetzen“ gebaut: keine neue Generation, solange ein Postfach vorgemerkt ist, mit `ForceNewGeneration` als Ausweg. Die Angreifer-Prüfung von 06h zeigt, dass ein gepflanztes Postfach (Strohmann mit `member-added` ohne Verpackung) oder eine gebrochene fremde Kette den Befehl so dauerhaft festhält; die verlorene Generation wird dann nie widerrufen.
- Stand Welle 4: Auf dem Arbeitszweig gilt noch der Fortsetzungsmodus (`client.DeviceLost`, `DeviceLostOptions.ForceNewGeneration` mit `TODO(ask)`). Auftrag 14 (Pflichtpunkt 1) baut die Lesart von 2.2: Jeder Aufruf erzeugt die nächste Generation; vorgemerkte Postfächer werden im selben Lauf fortgesetzt; scheitern sie weiter, bleibt die Marke und der Befehl endet mit `ErrPartial`; eine Marke in einem Postfach, in dem der Benutzer laut Kopf kein Benutzer-Mitglied ist, blockiert nichts.
- Vorschlag: In 2.2 Punkt 2 festhalten: „Jeder Aufruf von `device lost` erzeugt eine neue Generation. Nicht abgeschlossene Neuausstellungen früherer Aufrufe setzt der Client im selben Lauf und bei jedem `sync` mit der neuen Generation fort.“

## S71 Generation eines Unterzeichners sinkt in der Kette nicht
- Art: offen (Q13).
- Stelle: 2.2 „Generationen“ Punkt 4; K2 Regel 1.
- Problem: Ohne Log lässt sich nicht prüfen, ob eine `epoch.rec` vor dem Widerruf der signierenden Generation entstand. Der Client ergänzt deshalb eine Schranke, die die Spezifikation nicht kennt: Eine Epoche, die mit einer niedrigeren Generation eines Benutzers signiert ist, als eine frühere Epoche derselben Kette für ihn nennt, ist ungültig. Der Server setzt die Regel nicht durch und verschlüsselt auch für eine solche Epoche.
- Stand Welle 4: `client.checkSignerGen` (`internal/client/mailbox.go`, `TODO(ask)`), mit 06b zusammengeführt (D84 (1)). Auftrag 14 behält sie neben `CheckRevokedSignature` als lokale Schranke (`TODO(Q13)`).
- Vorschlag: Wie Q13: entweder als Kettenregel in 2.4 aufnehmen (dann auch in `store.Chain.Add` und damit im Server) oder nach Auftrag 14 entfernen und nur die Logreihenfolge nach 2.2 Punkt 4 gelten lassen.

## S72 Neuausstellung für Leser vergangener Zeiträume
- Art: offen (Q15).
- Stelle: 2.2 „Generationen“ Punkt 4 („Übernahme durch andere Mitglieder“) und Punkt 5; 2.5 (`mailbox share … --to`); K2 Regel 2.
- Problem: Nach Punkt 5 verpacken die Clients „alle Epochen“ für die neue Generation neu. Für Mitglieder ist die signierte `epoch.rec` die Quelle; Leser vergangener Zeiträume stehen in keiner Mitgliederliste, ihre alte Verpackung ist der einzige Beleg. Die Angreifer-Prüfung von 06e zeigt, dass ein Dieb mit einem kolludierenden Strohmann diesen Beleg selbst herstellen kann, wenn eine Vorlage einer widerrufenen Mitgliedsgeneration genügt.
- Stand Welle 4: Strengste Lesart (06f, D84 (1)): Neuausstellung für solche Leser nur, wenn die Vorlage von einer gültigen Generation eines Benutzer-Mitglieds signiert ist; sonst Warnung, der Teilende teilt erneut (`client.reissueTarget`, `TODO(Q15)`).
- Vorschlag: Wie Q15: In 2.2 Punkt 5 die automatische Neuausstellung auf Empfänger aus der signierten Mitgliederliste beschränken; Leser vergangener Zeiträume erhalten nach einem Widerruf der Generation des Teilenden ein erneutes `share`.

## S73 Alleiniges Mitglied ohne geprüfte Ordnerliste
- Art: offen (Q18).
- Stelle: 2.2 „Generationen“ Punkt 4 (nicht geprüfte Dateien werden nicht übernommen); 2.4 Grund `generation-revoked`; 4 (`folders.gml` je Epoche); K2 Regel 1.
- Problem: Ist `folders.gml` der neuesten zugänglichen Epoche von der eigenen, inzwischen widerrufenen Generation signiert und fehlt der lokale Prüfvermerk (neues Gerät per `restore`, oder `mailbox.rec` fehlte während `device lost`), darf ein alleiniges Benutzer-Mitglied die Liste nicht übernehmen. Ohne Ordnerliste kann es die Epoche `generation-revoked` nicht anlegen, und kein anderes Mitglied kann helfen; `List`, `Rename` und `SetFolders` scheitern dauerhaft.
- Stand Welle 4: Ablehnung ohne Ausweg (`ErrPartial`, D84 (3)). Auftrag 14 (Pflichtpunkt 3) korrigiert nur die gemeldete Ursache („keine geprüfte Ordnerliste; derzeit keine Abhilfe“); der Ausweg bleibt `TODO(Q18)`.
- Vorschlag: Wie Q18: In 2.2 Punkt 4 eine Ausnahme für die Ordnerliste eines alleinigen Mitglieds festlegen (nach ausdrücklicher Bestätigung die ungeprüfte Liste übernehmen oder eine leere Liste schreiben; Standard bleibt die Ablehnung). Zur Auswahl der Ordnerliste siehe S59.

## S74 Der lokale Zustand eines Postfachs wird nie kleiner
- Art: klarstellend (Q16, D84 (2)).
- Stelle: 2.4 „Schutz gegen Zurückspielen“; 2.7 erster Absatz („schützen nur einen Client, der seinen bisherigen Zustand kennt“); 2.2 Punkt 4 (Prüfvermerke in `state.json`); K1 Punkt 3.
- Problem: Der Schutz gegen Zurückspielen stützt sich auf den lokalen Zustand, die Spezifikation sagt aber nicht, dass er nie verkleinert werden darf. In 06g löschte `device lost` den Zustand eines Postfachs, dessen `mailbox.rec` gerade fehlte (Fund hoch, Q16). Danach wurde eine ältere, echt signierte `mailbox.rec` ohne die Warnung aus 2.4 übernommen, und die Prüfvermerke für `folders.gml` waren verloren.
- Stand Welle 4: Unveränderliche Regel seit 06h: Kein Pfad im Client verkleinert oder löscht `Epoch`/`EpochHash`, `Epochs`, `Checked`, `Recovery`, `Versions`, `Folders` oder `Mails` eines Postfachs; fehlt `mailbox.rec`, bleibt der Eintrag; `adoptMemberships` ersetzt nie einen vorhandenen Eintrag (D84 (2)). Einzige Ausnahme: `null`-Einträge in `state.json` werden entfernt (Auftrag 14, Pflichtpunkt 4).
- Vorschlag: In 2.4 festhalten: „Der lokale Zustand eines Postfachs (höchste gesehene Epoche mit Hash, verworfene Epochen, Prüfvermerke, gesehene Versionen) wird nie verkleinert, auch nicht durch `device lost` oder eine fehlende `mailbox.rec`.“

## S75 Erster Kontakt mit einem nie geöffneten Postfach
- Art: offen (keine Frage in `QUESTIONS.md`; in D84 als offene Frage zur Spezifikation für AUDIT vermerkt).
- Stelle: 2.7 erster Absatz; 2.2 „Generationen“ Punkt 4; 2.4.
- Problem: Nach `restore` oder `device lost` übernimmt der Client Postfächer, die den Benutzer als Mitglied nennen und deren Kette gültig ist, ohne lokales Vorwissen (`adoptMemberships`). Das gilt auch für ein Postfach, das ein Dieb mit der gestohlenen Generation vor deren Widerruf angelegt hat; seine `epoch.rec` ist nach 2.2 Punkt 4 gültig, wenn sie vor dem Widerruf im Log stand. Die Spezifikation sagt nicht, ob der Client solche Postfächer kennzeichnet oder erst nach Bestätigung übernimmt.
- Stand Welle 4: Übernahme beim ersten Kontakt ohne Rückfrage; in D84 als Grenze von Phase 2 vermerkt, die das Log (Auftrag 14) eingrenzen soll.
- Vorschlag: Entscheiden, ob der Client neu gefundene Postfächer, deren Epochen von einer inzwischen widerrufenen eigenen Generation signiert sind, nur mit Warnung und nach Bestätigung übernimmt; andernfalls die Grenze in 2.7 festhalten.

## S76 Nachfolge nach Kompromittierung der Plattformidentität
- Art: offen (Q19).
- Stelle: 2.3 „Wechsel der Identität“ (im Kompromissfall gilt der Vorgänger ab dem Logeintrag der Nachfolge als ungültig); 2.7; K8; Q8.
- Problem: Kein Datensatz und kein Feld macht eine Generation der Plattformidentität ab einem Logeintrag ungültig: `platform-succ` hat kein Kennzeichen „kompromittiert“, der Pin hat kein Feld 7 (S24), `translog` kennt keine solche Regel. Wirksam ist nur die Zeitgrenze; ein Dieb mit dem alten Schlüssel kann bis dahin rückdatierte Zertifikate loggen lassen. Außerdem sagt 2.3 nicht, dass Admin- und Ingest-Zertifikate der kompromittierten Generation unter der neuen neu ausgestellt werden müssen, was neue Admin- und Ingest-Generationen verlangt (eine Admin-Rotation gibt es nicht, Q8 (d)).
- Stand Welle 4: `gomail-ceremony succeed --compromised` schreibt den neuen Pin mit verlängerter Identitätsliste und `identity-<g>.pub`, aber keine Nachfolge-Signatur des Vorgängers; zwei `TODO(ask)` an `ceremony.Succeed` (Auftrag 15b, Worktree, Commit 11259ef, nicht zusammengeführt). Bis zur Antwort gilt die Betriebsregel aus Q19: nach `succeed --compromised` sofort `ingest-rotate` unter der neuen Identität.
- Vorschlag: Wie Q19: ein Logeintrag `revocation-<g>.rec`, von der neuen Identität signiert, der alle danach geloggten Einträge der Generation g ungültig macht; dazu in 2.3 die Neuausstellung der Admin- und Ingest-Zertifikate festlegen.

## S77 Geänderte Zeugen erreichen `witnesses.rec` nicht
- Art: offen (keine Frage in `QUESTIONS.md`, `TODO(ask)`).
- Stelle: 2.7 „Zeugen“; 4 (`witnesses.rec`); 9.2 (`gomail-ceremony succeed`, `publish`).
- Problem: `succeed --witness` und `--min-witnesses` ändern Zeugen und Quorum im neuen Pin. `publish` vergleicht `witnesses.rec` des Datenverzeichnisses mit dem Pin und verweigert bei einer Abweichung, damit die Arbeitskopie nie still ersetzt wird (S49). Ein gewollter Wechsel der Zeugen hat damit keinen Weg in ein bestehendes Datenverzeichnis.
- Stand Welle 4: Strengste Lesart: `publish` verweigert mit `ErrMismatch`, der Betreiber entscheidet (`ceremony.checkWitnessFile`, `TODO(ask)`; Auftrag 15b, Worktree, nicht zusammengeführt).
- Vorschlag: Ein Schalter von `publish`, der `witnesses.rec` nach Bestätigung durch die Liste des Pins ersetzt (oder ein eigener Befehl des Servers); in 9.2 aufnehmen.

## S78 Terminalregeln: getrennte Terminals, Signale nach dem Commit
- Art: klarstellend (Q17, D82); präzisiert S32.
- Stelle: 2.3 „Zeremonie“; 9.2 `gomail-ceremony`.
- Problem: S32 verlangt Terminals für stdin und stdout, sagt aber nicht, ob es dasselbe sein muss und was ein Signal nach dem Schreiben der Ergebnisse bedeutet. Die letzte Prüfung von 10e (Q17) zeigte: Bei getrennten Terminals hält ein XOFF auf stdout Ausgabe und Signalhandler an; ein Signal zwischen Commit und Programmende beendet den Prozess mit Exit 130, obwohl Export und Schlüssel vollständig vorliegen.
- Stand Welle 4: stdin und stdout dürfen verschiedene Terminals sein; die Software-Flusssteuerung (`IXON`/`IXOFF`/`IXANY`) ist auf beiden aus und wird danach wiederhergestellt; nach dem Commit werden Abbruchsignale bis zum Ende angenommen und verworfen. Exit 0 heißt vollständiger Export, Exit 130 heißt nichts geschrieben, nie ein Teilzustand (`CommitGuard`, D82 (2) und (3); Pflichtpunkte 0a–0c von Auftrag 15b, Worktree, nicht zusammengeführt).
- Vorschlag: Bei den Terminalregeln in 2.3 (S32) ergänzen: Flusssteuerung auf allen beteiligten Terminals aus; Exit 0 nur bei vollständigem Ergebnis, Exit 130 nur ohne geschriebene Dateien; ein Signal nach dem Commit ändert das Ergebnis nicht.

## S79 `created` bei Dateiart `pending`
- Art: klarstellend.
- Stelle: 3.1 Kopffeld 7 `created` („Bei Art `meta` immer die Empfangszeit der Mail“); 2.4 „Schutz gegen Zurückspielen“; 5.4.
- Problem: Für Begriffslisten und Marker (`pending`) legt 3.1 nicht fest, welche Zeit `created` trägt. Davon hängt ab, gegen welche Zeit der Client die Epochenregel prüft: Eine Begriffsliste, die nach dem Beginn einer neueren Epoche geschrieben wird, enthält noch Mails, die vorher empfangen wurden.
- Stand Welle 4: `created` ist die Empfangszeit der frühesten Mail, die die Datei erfasst; der Client wendet die Epochenregel darauf an (`ingest.sealPending`, `TODO(ask)`; gemeldet von der Prüfung von 15c).
- Vorschlag: In 3.1 Feld 7 ergänzen: „Bei Art `pending` die früheste Empfangszeit der erfassten Mails.“

## S80 Anlegen des Datenverzeichnisses
- Art: offen (keine Frage in `QUESTIONS.md`).
- Stelle: 4 (Aufbau des Datenverzeichnisses); 9.1 (Rechte 2770/0660); 9.2.
- Problem: Kein Befehl in 9.2 legt das Datenverzeichnis an. Gebaut legt nur die Entwicklungszeremonie `gomail-ceremony init --dev` die Struktur nach Abschnitt 4 an (`store.Init`); `gomail-ceremony publish` und alle Befehle von `gomail-server` verlangen ein schon angelegtes Verzeichnis (`store.Open`). Auftrag 16 ging von einem `gomail-server init` aus, das es nicht gibt; der Zwei-Maschinen-Test nutzt deshalb die Entwicklungszeremonie.
- Stand Welle 4: Mit Auftrag 15b wird `init --dev` nur noch mit dem Build-Tag `gomail_dev` übersetzt (Worktree, nicht zusammengeführt); ein Produktionsbuild hätte dann keinen Weg, ein Datenverzeichnis anzulegen.
- Vorschlag: Einen Befehl festlegen, etwa `gomail-server init --data <verzeichnis>` (Struktur nach 4 einschließlich `locks/`, Rechte 2770, die Gruppe wählt der Betreiber), oder `publish` legt ein fehlendes Verzeichnis an; in 9.2 aufnehmen.

## S81 Unbekannter freier Platz
- Art: klarstellend.
- Stelle: 5.1 („Sinkt der freie Platz im Datenverzeichnis unter 10 % … `452 4.3.1`“).
- Problem: 5.1 nennt die Antwort nur für den gemessenen Fall. Auf Plattformen, auf denen das Paket `syscall` den freien Platz nicht liefert (NetBSD, Windows), lässt sich die Grenze nicht prüfen.
- Stand Welle 4: Fail closed: Ist der freie Platz unbekannt, antwortet der Server mit `451 4.3.0` und nimmt nichts an, bis `Config.DiskSpace` gesetzt ist; `gomail-server` meldet das beim Start (`ingest.Accepting`, `disk_other.go`, D81 (5)). Die 10-%-Grenze ist nur in Testbuilds veränderbar (Build-Tag `gomail_test`, `GOMAIL_TEST_MIN_FREE`).
- Vorschlag: In 5.1 ergänzen: „Lässt sich der freie Platz nicht bestimmen, antwortet der Server mit `451 4.3.0`.“

## S82 Der Server prüft die Client-Sperre nur auf Verlangen
- Art: klarstellend (D70, D81 (4)); präzisiert S65.
- Stelle: 9.1 „Beim Start prüfen Server und Client, dass eine Testsperre von der jeweils anderen Seite wirksam ist, und verweigern andernfalls den Betrieb.“
- Problem: Der Wortlaut verlangt die Prüfung in beide Richtungen bei jedem Start. Ein dauerhaft laufender Server kann beim Start keinen laufenden Client voraussetzen (S65); ohne jede Prüfung auf der Serverseite fehlt aber der Nachweis, dass die Sperre des Clients beim Server wirkt.
- Stand Welle 4: `gomailctl` verlangt eine wirksame Serversperre (`CheckPeerLock(RoleServer)`, nur `inspect` ausgenommen). `gomail-server serve --require-client-lock` verlangt zusätzlich beim Start eine wirksame Client-Sperre (`ingest.Config.PeerCheck`, Auftrag 15c); Standard ist aus, dann meldet der Server nur, dass keine Client-Sperre gehalten wird. Der Zwei-Maschinen-Test schaltet ihn ein (D83).
- Vorschlag: In 9.1 schreiben: „Der Client prüft bei jedem Start die Sperre des Servers. Der Server prüft die Sperre des Clients auf Verlangen (`--require-client-lock`); der Test auf zwei Maschinen weist damit beide Richtungen nach.“

## S83 Kein Befehl hält die Client-Sperre
- Art: offen (keine Frage in `QUESTIONS.md`).
- Stelle: 9.1 (Testsperre); 9.2 (`gomailctl`).
- Problem: `gomailctl` hält `locks/client` nur für die Dauer eines Befehls. Für `--require-client-lock` (S82) muss die Sperre beim Start des Servers bestehen, aber 9.2 nennt keinen Befehl, der sie hält. Der Zwei-Maschinen-Test behilft sich mit `gomailctl sync`, das an der Abfrage der Passphrase wartet (Eingabe über eine FIFO), während der Server startet.
- Stand Welle 4: `scripts/two-host-test.sh` Schritt c (`holder.in`, D83); kein eigener Befehl.
- Vorschlag: Entweder einen Befehl `gomailctl lock` aufnehmen (hält die Client-Sperre ohne Passphrase bis zum Ende der Eingabe oder bis zu einem Signal), oder in 9.1 festhalten, dass `--require-client-lock` nur dem Nachweis im Test dient und der Test die Sperre über einen wartenden Befehl hält.

## S84 Die Testsperre weist keine Echtheit nach
- Art: klarstellend (bekannte Grenze).
- Stelle: 9.1 (Testsperre); 8 „Bedrohungsmodell“.
- Problem: 9.1 sagt nicht, was die Testsperre nachweist. Eine wirksame Sperre zeigt nur, dass POSIX-Satzsperren über das Dateisystem wirken und irgendein Prozess mit Schreibzugriff auf `locks/` sie hält; sie authentifiziert weder Server noch Client.
- Stand Welle 4: Für AUDIT vermerkt (D81 (4), Angreifer-Prüfung von 15c); das RUNBOOK sagt es seit Auftrag 15d ausdrücklich.
- Vorschlag: In 9.1 ergänzen: „Die Testsperre weist die Wirksamkeit der Sperren nach, nicht die Echtheit der Gegenseite.“

## S85 Befehle und Optionen von `gomail-server`
- Art: klarstellend.
- Stelle: 9.2 (`gomail-server serve --data ./data --listen :2525`, `invite create`, `address add <adresse> --mailbox <postfach-id>`).
- Problem: Mit Log und Rollensperren braucht der Server Angaben, die 9.2 nicht nennt: Pin, Ingest- und Admin-Schlüssel außerhalb des Datenverzeichnisses, Adresse des Zeugenprotokolls. Für die Reparatur des Operator-Logs gibt es keinen Befehl.
- Stand Welle 4: `serve` mit `--data`, `--listen` (Standard `127.0.0.1:2525`), `--ingest-key`, `--hostname`, `--isolated-test-network`, `--pin` und `--log-listen` (beide Pflicht), `--head-interval`, `--require-client-lock`; `invite create --data`; `address add <adresse> --data --mailbox --admin-key --pin`; `log repair --data --pin` (baut `tree.rec` nach einem Rückschritt neu, meldet verwaiste Einträge, löscht nichts); `--insecure-no-log` ist entfernt (`cmd/gomail-server`, D80, D81, `internal/translog/doc.go` „Additions to 9.2“).
- Vorschlag: Die Befehle und Optionen in 9.2 aufnehmen, wie S67 und S68 für Zeremonie und Zeugen.

## S86 Form der Zeugenangabe `--witness`
- Art: klarstellend; präzisiert S67.
- Stelle: 9.2 `gomail-ceremony` (die Option fehlt dort, siehe S67); 2.7 „Zeugen“ (Format `note`).
- Problem: Offen ist, in welcher Form ein Zeuge bei `init` und `succeed` angegeben wird. Auftrag 15b sah `name=<öffentlicher Schlüssel hex>` vor; ein bloßer Schlüssel hat keine Prüfsumme gegen Tippfehler und keine Bindung an den Namen.
- Stand Welle 4: `--witness <name>=<verifier-zeile>`, wiederholbar, mit der Zeile, die `gomail-witness keygen` ausgibt (`<name>+<hash>+<base64>` nach `note`); der Name muss dem der Zeile gleichen, der Hash wird nachgerechnet, höchstens 256 Byte (`parseWitness` in `cmd/gomail-ceremony`; Auftrag 15b, Worktree, nicht zusammengeführt).
- Vorschlag: In 9.2 die Form `--witness <name>=<verifier-zeile>` festlegen.

## S87 Adressen in Kommandozeilen
- Art: offen (keine Frage in `QUESTIONS.md`).
- Stelle: 9.2 (`gomail-server address add info@brownbear.de --mailbox <postfach-id>`); 8.
- Problem: 9.2 legt die Adresse als Argument fest. Argumente sind auf der Server-Maschine für jeden lokalen Benutzer über `/proc/<pid>/cmdline` lesbar, auch für Benutzer außerhalb der Gruppe `gomail`, die `addresses.json` nicht lesen dürfen. Dasselbe gilt für Absender und Empfänger in der Kommandozeile von `curl` im Zwei-Maschinen-Test.
- Stand Welle 4: Argumentform wie in 9.2; Hinweis für AUDIT (D83). Auftrag 14 (Nachtrag) stellt `address add` nur dann auf stdin um, wenn 9.2 die Argumentform nicht festlegt, sonst `TODO(ask)`.
- Vorschlag: Entscheiden, ob `address add` die Adresse von stdin liest, oder die Grenze in 8 festhalten (Adressen sind für Benutzer der Server-Maschine sichtbar).
