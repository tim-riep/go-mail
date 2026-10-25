# Offene Punkte der Spezifikation

Festgestellt bei der Umsetzung von Phase 0 (`rec`, `keys`, `shamir`, `envelope`) gegen `docs/PLAN.md`. Jeder Punkt nennt die Stelle, das Problem, wie Phase 0 damit umgeht, und einen Vorschlag. Die zugehörigen Umsetzungsentscheidungen stehen in `docs/DECISIONS.md`.

Keiner der Punkte ist ein Sicherheitsproblem, das den Bau hätte anhalten müssen. S01 und S06 betreffen die Robustheit des Formats, S09 ein Spannungsfeld im Entwurf, die übrigen sind Lücken oder Mehrdeutigkeiten.

## S01 `.gml`: Ende der Blockfolge ist ohne Schlüssel nicht bestimmbar
- Stelle: 3.1 Aufbau, 3.3 Regel 7.
- Problem: Blöcke und Trailer sind beide `uint32 Länge || Bytes`. Das Ende der Blockfolge ist nur über das Letzter-Block-Flag im Nonce definiert, das ein Parser ohne Schlüssel nicht sieht. Nach einem vollen Block ist nicht entscheidbar, ob das nächste Längenfeld einen Block oder den Trailer einleitet, solange nur der Datenstrom und nicht die Dateilänge bekannt ist. Auch der Server, der laut 3.4 Signaturen ohne Schlüssel prüfen soll, braucht diese Grenze.
- Phase 0: Die Trailer-Länge ist das Längenfeld, dessen Wert genau den verbleibenden Bytes entspricht (DECISIONS D29). Das setzt die vollständige Datei voraus und schließt streamendes Parsen aus.
- Vorschlag: Die Grenze explizit machen, etwa durch die Zahl der Blöcke oder die Inhaltslänge im Kopf, oder durch einen Trailer, dessen Länge am Dateiende steht (Parsen vom Ende), oder durch ein Endmarker-Längenfeld (`0xFFFFFFFF`) vor dem Trailer. Bis dahin die Regel aus D29 in 3.1 aufnehmen.

## S02 NFC-Prüfung und Abhängigkeitsregel
- Stelle: 3.6 Regel 3 und 6; 1 Grundsätze (nur `x/crypto` und `x/mod`).
- Problem: Die Standardbibliothek kann keine Unicode-Normalisierung. Die Ablehnung nicht normalisierter Zeichenketten erfordert entweder `golang.org/x/text/unicode/norm` oder eigene Tabellen aus der Unicode-Datenbank.
- Phase 0: Eigene Tabellen und eine exakte Prüfung (DECISIONS D09, D10), knapp 1.500 Zeilen generierter Code, der bei jedem Unicode-Wechsel der Werkzeugkette neu erzeugt werden muss.
- Vorschlag: Entweder `golang.org/x/text` (vom Go-Team gepflegt, wie `x/crypto`) ausdrücklich zulassen, oder festlegen, dass die eigenen Tabellen gewollt sind und wer sie pflegt.

## S03 Kodierung von `info` beim Verpacken
- Stelle: 3.2 Schritt 2, "`info = "gomail/v1/wrap" || 0x00 || type || id || gen`, kanonisch kodiert".
- Problem: "Kanonisch kodiert" kann die Verkettung fester Breiten oder einen Datensatz nach 3.6 meinen. Beides ist eindeutig, aber inkompatibel zueinander.
- Phase 0: Verkettung fester Breiten (DECISIONS D33).
- Vorschlag: Die Bytefolge in 3.2 ausschreiben (`uint8 type || 16 Byte id || uint32 BE gen`), ebenso für die AAD-Eingabe festhalten, dass "Kopf" den Datensatz ohne sein Längenfeld meint.

## S04 Bedeutung von `kind` in der Signaturdomäne
- Stelle: 3.4, `"gomail/v1/sig/" || kind || 0x00`.
- Problem: `kind` ist im Kopf ein `uint8`, in der Domäne könnte die Zahl oder der Name gemeint sein.
- Phase 0: Der Name (`gomail/v1/sig/meta`), DECISIONS D36.
- Vorschlag: In 3.4 die Namen nennen oder die Zahl festlegen.

## S05 Abgrenzung von Listenelementen
- Stelle: 3.6 Regel 4.
- Problem: Datensätze sind nicht selbstbegrenzend; ohne Längenpräfix je Element ist die Kodierung einer Liste mehrdeutig.
- Phase 0: `Anzahl || (Länge || Element)*` (DECISIONS D06).
- Vorschlag: Regel 4 entsprechend ergänzen, inklusive der Aussage, dass jedes Element mit seinem Typ-String beginnt.

## S06 Empfängerteil unsignierter Dateien ist nicht geschützt
- Stelle: 3.1, "bewusst nicht Teil der AAD der Blöcke"; 7, Mails selbst tragen keine Signatur.
- Problem: In einer Mail-Datei (`kind` 1, unsigniert) kann, wer die Datei schreiben darf, Einträge anderer Empfänger entfernen, verändern oder hinzufügen, ohne dass ein Empfänger es an seiner eigenen Entschlüsselung bemerkt. Ein Angreifer gewinnt damit keinen Schlüssel (ein neuer Eintrag ließe sich nur mit dem Dateischlüssel erzeugen), kann aber einzelne Mitglieder vom Lesen ausschließen (Verfügbarkeit) und das Entfernen eines Wiederherstellungsempfängers verschleiern.
- Phase 0: Verhalten dokumentiert und getestet (DECISIONS D39, `TestBitFlipForeignRecipient`).
- Vorschlag: Festhalten, dass die Integrität des Empfängerteils einer Mail über die signierten Metadaten gewährleistet wird (Abschnitt 7 nimmt den SHA-256 der verschlüsselten Mail-Datei in die Ingest-Signatur auf; dieser Hash deckt den Empfängerteil mit ab) und dass ein Client beim Lesen einer Mail diesen Hash prüft.

## S07 Keine Grenzen für KDF-Parameter aus dem Schlüsselspeicher
- Stelle: 2.2 Lokale Ablage, "alle KDF-Parameter stehen im Kopf der Datei".
- Problem: Werden die Parameter aus der Datei übernommen, kann eine manipulierte Datei den Client zu beliebig großen Argon2-Reservierungen zwingen, bevor die Authentifizierung fehlschlägt (die AAD-Prüfung braucht den abgeleiteten Schlüssel).
- Phase 0: Unter- und Obergrenzen, Prüfung vor Argon2 (DECISIONS D22).
- Vorschlag: In 2.2 festlegen, welche Parameter beim Öffnen akzeptiert werden (mindestens die festen Werte, höchstens definierte Obergrenzen) oder nur exakt die festen Werte zulassen.

## S08 Formate der Plattformzertifikate und der Identitätsnachfolge fehlen
- Stelle: 2.3, `admin-<gen>.cert`, `ingest-<gen>.cert`, `identity-<gen>.succ`; 4 Ablage.
- Problem: Nur die Dateinamen und die Signierenden sind genannt, nicht die Felder.
- Phase 0: Minimale Datensätze (DECISIONS D20).
- Vorschlag: Die Felder in 2.3 aufnehmen; insbesondere, dass ein Zertifikat die Generation der signierenden Identität nennt, damit der Client den richtigen Schlüssel wählt.

## S09 Nachträgliche Empfänger und signierte Dateien
- Stelle: 3.1, "damit spätere Empfängertypen (etwa ein Wiederherstellungsschlüssel) ohne Neuverschlüsselung des Inhalts ergänzt werden können" und "bei signierten Dateien deckt die Signatur den gesamten Empfängerteil ab".
- Problem: Beide Aussagen zusammen bedeuten, dass ein nachträglich ergänzter Empfänger die Signatur einer Metadaten-, Verpackungs- oder Begriffslisten-Datei ungültig macht. Für Ingest-signierte Dateien kann kein Mitglied neu signieren, ohne dass die Aussage der Ingest-Signatur verloren geht (Abschnitt 7 erlaubt die Benutzersignatur nur nach einer Flag-Änderung an Metadaten).
- Phase 0: Keine Vorkehrung; die Signatur deckt den gesamten Empfängerteil ab, wie gefordert.
- Vorschlag: Entscheiden, ob (a) der Empfängerteil aus dem signierten Hash herausgenommen wird und stattdessen jeder Eintrag durch HPKE an Kopf und Dateischlüssel gebunden bleibt, oder (b) das Ergänzen von Empfängern bei signierten Dateien ein Neusignieren durch ein Mitglied verlangt und Abschnitt 7 das vorsieht, oder (c) Wiederherstellungsempfänger immer beim Schreiben eingetragen werden (siehe offene Entscheidung 1 in Abschnitt 12).

## S10 50 MB gegenüber 800 Blöcken
- Stelle: 3.3 Regel 2.
- Problem: 800 Blöcke zu 65.536 Byte sind 52.428.800 Byte (50 MiB, 52,4 MB), nicht 50 MB.
- Phase 0: 800 Blöcke (DECISIONS D35).
- Vorschlag: "50 MiB (800 Blöcke)" schreiben.

## S11 Normalisierung der Seed-Wörter bei der Eingabe
- Stelle: 2.2 Seed-Format, 9.2 `gomailctl keygen`, Wiederherstellung.
- Problem: Nicht festgelegt, ob Eingaben mit Großbuchstaben, zusätzlichem Leerraum oder Unicode-Varianten angenommen werden. BIP-39 empfiehlt NFKD-Normalisierung der Eingabe.
- Phase 0: `keys.SeedFromWords` verlangt die Wörter exakt wie in der Liste (DECISIONS D14).
- Vorschlag: In 2.2 die Eingabenormalisierung der Kommandozeile festlegen (Trimmen, Kleinschreibung, Trennung an Leerraum).

## S12 Suite 2 ändert die Größen im Empfängerteil
- Stelle: 3.5, Suite 2 mit `MLKEM768X25519`.
- Problem: Die Kapselung dieses KEM ist 1.120 Byte groß statt 32. Der Höchstwert von 16 KiB für den Empfängerteil reicht für 32 Einträge (etwa 40 KiB) dann nicht mehr; außerdem müssen Schemas je Suite verschiedene feste Längen haben.
- Phase 0: Schema und Grenzen gelten für Suite 1.
- Vorschlag: Beim Einführen von Suite 2 die Höchstwerte in 3.1 und die Feldgrößen je Suite festlegen.

## S13 Widerrufsprüfung braucht das Log
- Stelle: 2.2 Generationen Punkt 4, 2.3 Widerrufe.
- Problem: Ob eine Signatur einer widerrufenen Generation "nachweislich vor dem Widerruf im Log stand", lässt sich erst mit dem Transparenzlog (Phase 6) prüfen. Phase 0 kann nur die Kette der Generationszertifikate prüfen.
- Phase 0: `VerifyGenerationChain` prüft Lückenlosigkeit und Signaturen; die zeitliche Einordnung bleibt offen.
- Vorschlag: Kein Änderungsbedarf an der Spezifikation; Hinweis für Phase 2 und 6 (siehe HANDOFF).
