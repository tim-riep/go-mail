# Entscheidungen in Phase 0, 0.1, 1 und bis M1

Die Spezifikation liegt in `docs/PLAN.md` (Version 1.0). Dieses Dokument hält jede Stelle fest, an der sie mehrdeutig ist oder etwas offen lässt, und welche Entscheidung die Umsetzung getroffen hat. Grundsatz: im Zweifel die konservativere Lesart, keine erfundenen Anforderungen. Widersprüche und Lücken, die eine Änderung der Spezifikation nahelegen, stehen zusätzlich in `docs/SPEC-ISSUES.md`.

Die Arbeit bis Meilenstein M1 (Orchestrierung, `docs/ORCHESTRATION.md`) arbeitet gegen Version 1.4 und `docs/PHASE2-KLAERUNGEN.md`; ihre Entscheidungen stehen ab D63. Fragen, die nach K7 angehalten wurden, stehen in `docs/QUESTIONS.md`.

Phase 1 arbeitet gegen Version 1.2 (`docs/PLAN.md`, Abschnitt 14 listet die Änderungen gegenüber 1.1); ihre Entscheidungen stehen ab D47.

Phase 0.1 setzt die Änderungen der Version 1.1 um. Die Version 1.1 liegt als `docs/PLAN.md` vor (Abschnitt 13 listet die Änderungen); die Umsetzung von `envelope` und `rec` begann nach dem Auftragstext, bevor die Datei im Repository lag, und wurde danach gegen den Text geprüft (D42, D43). Aufgehobene Entscheidungen bleiben als Verlauf stehen und sind mit "Aufgehoben in Phase 0.1" und dem Commit markiert.

Format je Eintrag: Stelle in der Spezifikation, Frage, Entscheidung, Begründung.

## Allgemein

### D01 Ablage der Spezifikation
- Stelle: Vorbereitung der Phase 0 (Auftrag), erwartet `docs/spec.md`.
- Frage: Die Spezifikation wurde als `docs/PLAN.md` abgelegt. Umbenennen oder kopieren?
- Entscheidung: Die Datei bleibt unverändert unter `docs/PLAN.md` und wird überall so referenziert.
- Begründung: Eine Kopie wäre eine zweite Quelle, ein Umbenennen eine Änderung an einer Datei, die nicht Teil des Auftrags ist.

### D02 Go-Version und Werkzeugkette
- Stelle: 1 Grundsätze, Mindestversion Go 1.26.
- Frage: Welche konkrete Version?
- Entscheidung: `go.mod` nennt `go 1.26.0`; entwickelt und getestet wurde mit Go 1.26.10 (über `GOTOOLCHAIN`, da im Container nur Go 1.24 installiert war). Modul `github.com/tim-riep/go-mail`, einzige Abhängigkeit `golang.org/x/crypto v0.58.0` für Argon2id.
- Begründung: Vorgabe des Auftrags. `golang.org/x/mod` aus den Grundsätzen wird erst vom Transparenzlog (spätere Phase) gebraucht und ist deshalb noch nicht im Modul.

### D03 Injizierbarer Zufall
- Stelle: Auftrag, "injizierbarer io.Reader, nie ein veränderter globaler Zufall"; 3.2, HPKE aus `crypto/hpke`.
- Frage: `hpke.NewSender` zieht den flüchtigen Schlüssel intern aus `crypto/rand` und bietet keinen Reader an. Wie werden `.gml`-Testvektoren reproduzierbar?
- Entscheidung: Alle anderen Zufallswerte (Nonce-Präfix, Dateischlüssel, Seeds, Salts, Shamir-Koeffizienten) kommen aus einem injizierbaren Reader mit dokumentierter Reihenfolge. Die HPKE-Kapselung bleibt nicht reproduzierbar. Die Vektoren enthalten vollständige Dateien; die Tests prüfen Präambel, Kopf und alle Blöcke byteweise gegen eine erneute Erzeugung und entschlüsseln den Rest mit dem festen Empfängerschlüssel. `testing/cryptotest.SetGlobalRandom` wird nicht verwendet.
- Begründung: Ein globaler Eingriff in den Zufall ist ausdrücklich untersagt; HPKE selbst zu implementieren ebenso.

### D04 Überschreiben von Geheimnissen
- Stelle: 2.2, "nach Gebrauch im Speicher überschrieben, soweit Go das zulässt".
- Frage: Was wird überschrieben und was nicht?
- Entscheidung: Überschrieben werden Seeds (`Seed.Zero`), der HKDF-PRK (`UserRoot.Zero`, `PlatformRoot.Zero`), abgeleitete Rohbytes vor der Umwandlung in Schlüssel, Dateischlüssel und Inhaltsschlüssel nach dem Aufbau des AEAD, Schlüsselspeicher-Inhalte nach dem Dekodieren, Ed25519-Schlüssel über `keys.Wipe`, Shamir-Koeffizienten und Zwischenwerte. Nicht überschreibbar sind die Bytes in `ecdh.PrivateKey` (keine API dafür), der expandierte AES-Schlüssel im `cipher.AEAD`, Argon2-Arbeitsspeicher in `x/crypto`, sowie Kopien, die der Garbage Collector oder Stack-Spills anlegen. Das ist in den Paketkommentaren vermerkt.
- Begründung: Go gibt keine Garantie; die Umsetzung verkürzt die Lebensdauer von Geheimnissen, mehr ist nicht möglich.

## rec (Spezifikation 3.6)

### D05 Typ-String auch in eingebetteten Datensätzen
- Stelle: 3.6 Regel 4 und 5.
- Frage: Beginnt ein Listenelement ebenfalls mit seinem Typ-String?
- Entscheidung: Ja. Jeder Datensatz, auch ein eingebetteter, beginnt mit `Typ || 0x00`.
- Begründung: Regel 5 sagt "jeder Datensatz". Damit sind auch Listenelemente nie mit anderen Strukturen verwechselbar.

### D06 Längenpräfix für Listenelemente
- Stelle: 3.6 Regel 4.
- Frage: Ein Datensatz hat kein Ende-Zeichen; nach einem Feld könnte ein weiteres Feld oder das nächste Element folgen. Wie werden Elemente abgegrenzt?
- Entscheidung: Jedes Element trägt ein eigenes `uint32`-Längenpräfix: `Anzahl (uint32) || (Länge (uint32) || Datensatz)*`. Der Decoder verlangt, dass jedes Element genau seine Länge verbraucht.
- Begründung: Ohne Präfix wäre die Kodierung mehrdeutig. Das Präfix macht sie eindeutig und erlaubt Längenprüfungen vor jeder Reservierung. Siehe SPEC-ISSUES S05.

### D07 Schema-getriebener Decoder
- Stelle: 3.6 Regel 2 und 6, "unbekannte Feldnummern ... führen zum Abbruch".
- Frage: Woher kennt der Decoder Pflichtfelder, Typen und Längen?
- Entscheidung: Jeder Datensatztyp hat ein `rec.Schema` mit Feldnummer, Art, Pflicht, fester Größe oder Höchstlänge, Elementschema und Höchstzahl. Der Decoder akzeptiert genau die Felder des Schemas in aufsteigender Reihenfolge, lehnt unbekannte, doppelte, falsch lange und fehlende Pflichtfelder ab. Optionale Felder sind erlaubt (etwa `revokes` in 2.2).
- Begründung: Nur so lassen sich alle Regeln aus 3.6 und 10.1 mechanisch prüfen.

### D08 Arten von Werten
- Stelle: 3.6 Regel 3 und 4.
- Frage: Welche Feldarten gibt es?
- Entscheidung: `U8`, `U32`, `I64` (Zweierkomplement, Big Endian), `Bytes` (feste Größe oder Höchstlänge), `String` (UTF-8, NFC, ohne Nullbyte, Höchstlänge), `List`. Weitere Breiten werden erst eingeführt, wenn ein Datensatz sie braucht.
- Begründung: Phase 0 braucht genau diese; nichts erfinden.

### D09 NFC-Prüfung ohne `golang.org/x/text`
- Aufgehoben in Phase 0.1 (Commit 4ee0b90): Version 1.1 lässt `golang.org/x/text` zu (S02). Die eigenen Tabellen und der Generator sind entfernt; `isNFC` ist `utf8.ValidString` gefolgt von `norm.NFC.IsNormalString`. Die UTF-8-Prüfung bleibt getrennt, weil `x/text` ungültige Bytes als normalisiert meldet. `x/text` ist in `go.mod` auf v0.43.0 festgelegt (Unicode 15.0.0, dieselbe Version wie die entfernten Tabellen). Alle NFC-Testfälle aus Phase 0 bleiben bestehen.
- Stelle: 3.6 Regel 3 und 6; Auftrag erlaubt nur Standardbibliothek und `x/crypto`.
- Frage: Die Standardbibliothek hat keine Unicode-Normalisierung. Wie wird NFC geprüft?
- Entscheidung: Exakte Prüfung mit eigenen Tabellen aus der Unicode Character Database 15.0.0 (dieselbe Version wie `unicode.Version` von Go 1.26): vollständige kanonische Dekomposition, kanonische Umordnung, kanonische Komposition nach UAX #15, dann Vergleich mit der Eingabe. `NFC_Quick_Check` dient nur als Abkürzung. Der Generator `internal/rec/nfc_tables_gen.go` erzeugt die Tabellen; die SHA-256 der Eingabedateien stehen in `nfc_tables.go`. Die Umsetzung wurde gegen Pythons `unicodedata` mit 200.000 Zufallsstrings abgeglichen (keine Abweichung). Ein Test schlägt fehl, wenn die Unicode-Version der Werkzeugkette von der der Tabellen abweicht.
- Begründung: Die Spezifikation verlangt die Ablehnung nicht normalisierter Zeichenketten; eine Näherung (nur Quick Check) würde gültige Strings ablehnen oder ungültige durchlassen. Siehe SPEC-ISSUES S02.

### D10 Quelle der Unicode-Daten
- Aufgehoben in Phase 0.1 (Commit 4ee0b90) zusammen mit D09; die Unicode-Daten kommen jetzt aus `golang.org/x/text`.
- Stelle: wie D09.
- Frage: `unicode.org` war aus der Umgebung nicht erreichbar.
- Entscheidung: Die Dateien `UnicodeData.txt` und `DerivedNormalizationProps.txt` der Version 15.0.0 stammen aus dem ICU-Repository auf GitHub (`unicode-org/icu`, Tag `release-73-2`, Verzeichnis `icu4c/source/data/unidata`), das die offiziellen Dateien unverändert enthält. Ihre Hashes sind im generierten Code vermerkt, damit ein Prüfer sie gegen `unicode.org` vergleichen kann.
- Begründung: Nachvollziehbarkeit bei fehlendem Direktzugang.

### D11 Höchstgrößen
- Stelle: 3.3 "Alle Längenfelder werden vor jeder Speicherreservierung gegen die Höchstwerte geprüft".
- Frage: Welche Höchstwerte gelten für Datensätze?
- Entscheidung: `MaxRecordSize` und `MaxValueLen` sind 1 MiB, `MaxTypeLen` 64. Jedes Schema setzt zusätzlich Höchstlängen und Höchstzahlen je Feld. Vor der Reservierung einer Liste wird geprüft, dass `Anzahl × Mindestgröße eines Elements` in die verbleibenden Bytes passt.
- Begründung: Die Container (`.gml`-Kopf 4 KiB, Empfängerteil 16 KiB) begrenzen ohnehin; 1 MiB lässt Platz für spätere `.rec`-Dateien wie `epoch.rec` mit Mitgliederlisten.

### D12 Getter auf fehlende Felder
- Stelle: Auftrag, kein `panic`.
- Frage: Was liefert ein Getter für ein fehlendes Feld oder bei falscher Art?
- Entscheidung: Den Nullwert, nie ein Panic; `Has` sagt, ob das Feld vorhanden ist. `Bytes` und `List` liefern Kopien.
- Begründung: Robustheit gegenüber Programmierfehlern in Aufrufern; Panics gibt es nur in `MustSchema` bei einem fehlerhaften Schema (Programmfehler, keine Eingabe).

### D13 Typ-Strings der Phase-0-Datensätze
- Stelle: 3.6 Regel 5 nennt nur ein Beispiel (`gomail/v1/rec/epoch`).
- Frage: Wie heißen die Typ-Strings der Strukturen aus Phase 0?
- Entscheidung: `gomail/v1/rec/header`, `.../recipient`, `.../recipients`, `.../trailer`, `.../signed` (envelope); `gomail/v1/rec/generation`, `.../platform-cert`, `.../identity-succ`, `.../keystore`, `.../keystore-content` (keys). Die Kodierung jedes Typs ist in `internal/rec/testdata/records.json` festgeschrieben.
- Begründung: Muster des Beispiels; eindeutig und nicht verwechselbar.

## keys (Spezifikation 2.2, 2.3)

### D14 Seed und Wortliste
- Stelle: 2.2 Seed-Format.
- Frage: Welche Eingaben werden beim Dekodieren der Wörter akzeptiert?
- Entscheidung: Genau 24 Wörter, jedes exakt wie in der Liste (Kleinschreibung, keine umgebenden Leerzeichen). Prüfsumme sind die ersten 8 Bit von SHA-256 über die 32 Byte Entropie. Andere Wortzahlen (12, 15, 18, 21) werden abgelehnt. Die Normalisierung von Benutzereingaben (Groß-/Kleinschreibung, Leerraum) ist Aufgabe der Kommandozeile in einer späteren Phase. Die Zuordnung zwischen Wort und Index (`keys.Word`, `keys.LookupWord`) durchläuft die ganze Liste mit konstantzeitigen Auswahloperationen, weil der Index 11 Bit des Seeds ist; ein Slice-Index oder eine Map wären geheimnisabhängige Speicherzugriffe (Hinweis der unabhängigen Prüfung).
- Begründung: 2.2 legt 24 Wörter fest; eine tolerante Eingabe würde zusätzliche Fehlerquellen schaffen.

### D15 Prüfung der Wortliste beim Start
- Stelle: Auftrag, "SHA-256 im Code festschreiben und beim Start prüfen".
- Frage: Was passiert, wenn die Prüfung fehlschlägt?
- Entscheidung: `init()` prüft den Hash und parst die Liste; bei Abweichung bricht das Programm mit Panic ab. Der Parser selbst (`parseWordlist`) ist eine Funktion über Bytes und wird gefuzzt.
- Begründung: Eine veränderte eingebettete Liste ist ein Integritätsfehler des Programms, keine fremde Eingabe; Fail closed ist hier richtig.

### D16 HKDF-Kodierung
- Stelle: 2.2 Ableitung, 2.3 Plattformschlüssel.
- Frage: Keine; die Kodierung ist festgelegt. Festzuhalten ist die Umsetzung.
- Entscheidung: `prk = hkdf.Extract(SHA-256, ikm=seed, salt="gomail/v1/user-seed")` bzw. `"gomail/v1/platform-root"`; je Schlüssel `hkdf.Expand(prk, info, 32)` mit `info = label || 0x00 || uint32 BE gen` für Schlüssel mit Generation und `info = label` für den Root. Generation 0 wird abgelehnt. Ed25519 über `ed25519.NewKeyFromSeed`, X25519 über `ecdh.X25519().NewPrivateKey`. Ein Test rechnet die Formel unabhängig vom Paketcode nach.
- Begründung: Direkte Umsetzung.

### D17 Plattform: kein abgeleiteter Root-Signaturschlüssel
- Stelle: 2.3, Tabelle der Teilschlüssel.
- Frage: Hat die Plattform wie der Benutzer einen Root-Signaturschlüssel?
- Entscheidung: Nein. Abgeleitet werden nur Identität, Admin und Ingest (je mit Generation). Zertifikate signiert die Identität.
- Begründung: Die Tabelle nennt nur diese drei; nichts erfinden.

### D18 Generationszertifikat
- Geändert in Phase 1 (Schritt 0, S14): Typ-String `gomail/v1/rec/user-gen` statt `gomail/v1/rec/generation`, Signaturdomäne `user-gen` statt `generation` (3.7, Version 1.2), siehe D47.
- Stelle: 2.2 Generationen und Registrierung (JSON-Beispiel).
- Frage: Welche Felder, was genau wird signiert, welche Regeln?
- Entscheidung: Datensatz `gomail/v1/rec/generation` mit `gen`, `identity_pub`, `unwrap_pub`, `created` (int64 ms), optional `revokes`, `sig`. Signiert wird mit dem Root über `"gomail/v1/sig/generation" || 0x00 || kanonischer Datensatz ohne sig`. Regeln: `gen >= 1`; Generation 1 hat kein `revokes`; Generation n > 1 hat `revokes = n-1` und nichts anderes. Ein ausdrücklich kodiertes `revokes = 0` wird abgelehnt, weil es dieselbe Bedeutung wie das fehlende Feld hätte und die Kodierung sonst nicht eindeutig wäre (Fund des Fuzzers, Regressionsfall unter `internal/keys/testdata/fuzz/`). `VerifyGenerationChain` verlangt die lückenlose Folge 1..n, alle vom Root signiert. `created` wird nicht geprüft (keine Vorgabe).
- Begründung: Die Domänen-Trennung folgt 3.4; das Nullbyte nach dem Label entspricht 2.2. `user_id` und `root_pub` sind nicht Teil des Zertifikats, weil es ohnehin nur unter dem Root-Schlüssel der `user.rec` gültig ist.

### D19 `user.rec` nicht in Phase 0
- Stelle: 2.2 Registrierung, 9.3 Paket `store`.
- Frage: Gehört `user.rec` zu `keys`?
- Entscheidung: Nein. `keys` liefert Zertifikate und Kettenprüfung; der Datensatz `user.rec` (mit `user_id`, `root_pub`, Liste der Generationen, Signatur der Identität) gehört zur Ablage in Phase 2.
- Begründung: Abgrenzung des Auftrags; die Bausteine dafür liegen bereit.

### D20 Plattformzertifikate und Identitätsnachfolge
- Geändert in Phase 0.1 (Commit 5863796): Version 1.1 legt die Datensätze in 2.3 fest. `gomail/v1/rec/platform-cert`: `role`, `gen`, `pub`, `identity_gen`, `valid_from`, `sig` (Felder 4 und 5 gegenüber Phase 0 vertauscht). `gomail/v1/rec/platform-succ` (statt `identity-succ`): `gen`, `pub`, `valid_from`, `sig`. Signaturdomäne ist der Datensatztyp, siehe D46. Go-Namen: `ValidFrom`, `PlatformSuccession`.
- Stelle: 2.3, `platform/admin-<gen>.cert`, `platform/ingest-<gen>.cert`, `identity-<gen>.succ`.
- Frage: Die Spezifikation legt keine Felder fest.
- Entscheidung: `gomail/v1/rec/platform-cert` mit `role` (1 admin, 2 ingest), `gen`, `pub`, `created`, `identity_gen` (Generation der signierenden Identität), `sig`; Domäne `platform-cert`. `gomail/v1/rec/identity-succ` mit `gen` (>= 2), `pub`, `created`, `sig` der Generation `gen-1`; Domäne `identity-succ`. Beides minimal, Signatur jeweils über den Datensatz ohne `sig`.
- Begründung: 2.3 verlangt die Zertifikate; das kleinste Format, das die Prüfung erlaubt. Siehe SPEC-ISSUES S08.

### D21 Schlüsselspeicher: Dateiformat
- Stelle: 2.2 Lokale Ablage im Client.
- Frage: Die Spezifikation nennt Verfahren und Parameter, aber kein Format.
- Entscheidung: `"GMKS" || uint32 Kopflänge || Kopf || Chiffrat`. Kopf ist der Datensatz `gomail/v1/rec/keystore` mit Version, KDF-Kennung, Speicher (KiB), Durchläufen, Threads, Salt (16) und Nonce (12). AAD ist `"gomail/v1/aad/keystore" || 0x00 || "GMKS" || Kopflänge || Kopf`. Inhalt ist der Datensatz `gomail/v1/rec/keystore-content` mit Generation, Ed25519-Seed und X25519-Skalar. Kein `user_id` im Speicher (nicht gefordert).
- Begründung: Alle Parameter sind authentifiziert, wie gefordert; das Format folgt dem Muster der `.gml`-Datei.

### D22 Schlüsselspeicher: Grenzen der KDF-Parameter
- Bestätigt in Phase 0.1: Version 1.1 schreibt in 2.2 genau diese Bereiche fest (64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads, Prüfung vor Argon2id). Keine Codeänderung; die Tests decken Unter- und Obergrenzen ab.
- Stelle: 2.2, "Version und alle KDF-Parameter stehen im Kopf der Datei".
- Frage: Parameter aus einer fremden Datei können den Client zu Gigabyte-Reservierungen zwingen. Welche Werte werden beim Öffnen akzeptiert?
- Entscheidung: Speicher 64 MiB bis 256 MiB, Durchläufe 3 bis 10, Threads 1 bis 16. Untergrenzen sind die Werte der Spezifikation, Obergrenzen schützen vor einer feindlichen Datei (nach der unabhängigen Prüfung von 1 GiB/32/64 gesenkt). Die Prüfung erfolgt vor dem Aufruf von Argon2. Zum Schreiben werden immer die Werte der Spezifikation benutzt. Version und KDF-Kennung müssen 1 sein.
- Begründung: Fail closed vor jeder Reservierung; schwächere Parameter als in der Spezifikation werden nie akzeptiert. Siehe SPEC-ISSUES S07.

### D23 Schlüsselspeicher: Dateioperationen
- Stelle: 2.2, "Dateirechte 0600, Schreiben atomar über temporäre Datei, fsync und Umbenennen".
- Entscheidung: `WriteKeystoreFile` schreibt eine temporäre Datei im selben Verzeichnis mit 0600, `fsync`, schließt, benennt um und synchronisiert das Verzeichnis nach Möglichkeit. `ReadKeystoreFile` liest nur reguläre Dateien bis 64 KiB; Dateirechte werden beim Lesen nicht geprüft. Die Passphrase wird als `[]byte` übergeben und darf nicht leer sein.
- Begründung: Direkte Umsetzung; eine Rechteprüfung beim Lesen ist nicht gefordert und auf manchen Dateisystemen irreführend.

## shamir (Spezifikation 2.3)

### D24 Nur 32-Byte-Geheimnisse
- Stelle: 2.3 Root (256 Bit), 2.2 Wiederherstellung (Seed).
- Entscheidung: `Split` nimmt genau 32 Byte an. Schwellwert 2 bis 255, Anzahl Schwellwert bis 255.
- Begründung: Beide Anwendungen teilen Seeds; ein festes Format vereinfacht Anteile und Prüfung.

### D25 Feldarithmetik ohne Tabellen
- Stelle: Auftrag.
- Entscheidung: GF(2^8) mit dem AES-Polynom 0x11b. Multiplikation bitseriell mit Masken, Inverse über eine feste Kette a^254, Division als Multiplikation mit der Inversen, Horner-Auswertung, Lagrange-Interpolation bei 0. Keine Verzweigung und kein Speicherzugriff hängt von geheimen Werten ab. Die Begründung steht in `field.go`. Ein Test vergleicht die Multiplikation erschöpfend mit einer tabellenbasierten Referenz.
- Begründung: Vorgabe; OpenBao verfährt inzwischen genauso.

### D26 Indizes 1..n statt zufälliger Indizes
- Stelle: OpenBao als Vorbild wählt zufällige, verschiedene x-Koordinaten.
- Entscheidung: Anteil i erhält Index i (1..n). Index 0 ist ausgeschlossen, weil das Polynom dort den Geheimnisbyte liefert.
- Begründung: Zufällige Indizes bringen keinen Sicherheitsgewinn; feste Indizes machen Anteile und Vektoren einfacher nachzuvollziehen.

### D27 Rekonstruktion mit mehr Anteilen als dem Schwellwert
- Entscheidung: Alle übergebenen Anteile gehen in die Interpolation ein. Weniger Anteile als der Schwellwert werden abgelehnt (`ErrInsufficient`), gemischte Mengen (`ErrMismatch`), doppelte Indizes (`ErrDuplicate`).
- Begründung: Mit konsistenten Anteilen ergibt sich dasselbe Ergebnis; ein inkonsistenter Anteil verfälscht es so oder so. Shamir bietet keine Integritätsprüfung; die Spezifikation verlangt dafür die Probe-Rekonstruktion in der Zeremonie. Ein Hash des Geheimnisses wurde bewusst nicht aufgenommen, weil er nicht gefordert ist.

### D28 Anteilsformat und Wortkodierung
- Stelle: 2.3, "Wortliste mit Prüfsumme, nach dem Vorbild von SLIP-39".
- Entscheidung: Binär 37 Byte: Version 1, zufällige 16-Bit-Kennung der Aufteilung, Schwellwert, Index, 32 Byte y. Wortform: Binärform plus 4 Byte Prüfsumme (SHA-256 über `"gomail/v1/share" || 0x00 || Binärform`), 328 Bit, als 30 Wörter der BIP-39-Liste zu 11 Bit, 2 Füllbits gleich 0. Nicht SLIP-39-kompatibel (eigene Wortliste und Prüfsumme dort).
- Begründung: "nach dem Vorbild" verlangt keine Kompatibilität; die BIP-39-Liste ist bereits eingebettet, die SHA-256-Prüfsumme ist einfach nachrechenbar und erkennt Übertragungsfehler mit Wahrscheinlichkeit 1 - 2^-32. Die Kennung lässt vermischte Anteile erkennen.

## envelope (Spezifikation 3)

### D29 Erkennung des Trailers
- Aufgehoben in Phase 0.1 (Commit 53b92a0): Version 1.1 gibt jedem Element nach dem Empfängerteil ein Typbyte (S01); siehe D42. Die Regel "Längenfeld gleich Restlänge" ist vollständig entfernt.
- Stelle: 3.1 Aufbau, Blöcke `Länge || Chiffrat`, dann `Länge Trailer || Trailer`.
- Frage: Ohne Schlüssel kann ein Parser nicht wissen, welcher Block der letzte ist (das Flag steckt im Nonce). Nach einem vollen Block könnte das nächste Längenfeld ein Block oder der Trailer sein.
- Entscheidung: Ein Längenfeld, dessen Wert genau der Zahl der verbleibenden Bytes entspricht, ist die Trailer-Länge. Ein Block kann diese Bedingung nie erfüllen, weil nach ihm mindestens die 4 Byte der Trailer-Länge folgen. Dafür muss die gesamte Datei vorliegen; `Parse` arbeitet auf einem Byte-Slice. Zusätzlich gilt strukturell: nur der letzte Block darf kürzer als `chunk_size + 16` sein, ein leerer Block (nur Tag) ist nur als einziger Block zulässig, mindestens ein Block ist Pflicht.
- Begründung: Eindeutig und ohne Schlüssel prüfbar; jede Fehldeutung scheitert spätestens an der Authentifizierung der Blöcke oder der Signatur. Siehe SPEC-ISSUES S01.

### D30 `chunk_size` nur 65536
- Stelle: 3.1 Kopf, "im PoC fest 65536".
- Entscheidung: Der Parser lehnt jeden anderen Wert ab; der Schreiber setzt ihn immer.
- Begründung: Ein frei wählbarer Wert aus einer fremden Datei würde die Größenprüfungen aushebeln.

### D31 Keine Prüfung von `created`
- Stelle: 3.1 Kopf.
- Entscheidung: `created` wird kodiert und dekodiert, aber nicht bewertet (auch negative Werte passieren).
- Begründung: Keine Vorgabe; die Bewertung gehört zur Ablage und zur Epochenkette.

### D32 Empfängerteil: Anzahl und Eindeutigkeit
- Geändert in Phase 0.1 (Commit 53b92a0): 1 bis 4 Einträge, Typ 1 bis 4 (4 = `recovery`, Wiederherstellungsempfänger), nach Version 1.1 (S09, S12). Die Schemagrenze `MaxCount` und die Prüfung in `NewWriter` sind auf 4 gesetzt; ein fünfter Eintrag wird beim Schreiben und beim Lesen abgelehnt. `MaxRecipientsSize` bleibt 16 KiB (vier Einträge der Suite 2 mit 1.120 Byte Kapselung passen hinein).
- Stelle: 3.1, "Liste von 1 bis 32 Einträgen".
- Entscheidung (Phase 0): 1 bis 32 Einträge, Typ 1 bis 3, Generation >= 1, kein doppeltes Tripel (Typ, ID, Generation). Beim Öffnen wird genau der Eintrag benutzt, der zum eigenen Tripel passt; fehlt er, `ErrNoRecipient` ohne Entschlüsselungsversuch; schlägt sein Entpacken fehl, wird die Datei abgelehnt.
- Begründung: 3.2 verlangt das Überspringen fremder Einträge ohne Versuch; ein doppeltes Tripel hätte keine sinnvolle Bedeutung.

### D33 Kodierung von `info` und AAD beim Verpacken
- Stelle: 3.2, "`info = "gomail/v1/wrap" || 0x00 || type || id || gen`, kanonisch kodiert" und "aad = SHA-256(... || Präambel || Kopf)".
- Frage: Ist `info` ein Datensatz nach 3.6 oder eine Verkettung fester Breiten? Enthält "Kopf" das Längenfeld?
- Entscheidung: `info` ist die Verkettung `Label || 0x00 || uint8 Typ || 16 Byte ID || uint32 BE Generation` (23 + 21 Byte). Der AAD-Hash läuft über `"gomail/v1/aad/wrap" || 0x00 || Präambel (6 Byte) || Kopfdatensatz` ohne das Längenfeld des Kopfes. Entsprechend für Blöcke mit `"gomail/v1/aad/block"`.
- Begründung: Alle Felder haben feste Breite, die Verkettung ist deshalb eindeutig ("kanonisch" im Sinne von 3.6 Regel 3). Das Längenfeld ist durch den Datensatz impliziert. Siehe SPEC-ISSUES S03.

### D34 Inhaltsschlüssel und Blöcke
- Stelle: 3.3.
- Entscheidung: `Inhaltsschlüssel = HKDF-SHA256(ikm = Dateischlüssel, salt = nonce_prefix, info = "gomail/v1/content")` über `hkdf.Key`. Nonce `nonce_prefix || uint32 BE Zähler || Flag`. Der Schreiber hält immer einen Block zurück; der letzte Block (auch ein leerer bei leerem Inhalt, auch ein voller bei Vielfachen von `chunk_size`) trägt Flag 1. Der Leser entschlüsselt in einen Puffer und gibt ihn erst nach dem letzten Block frei; bei einem Fehler wird der Puffer überschrieben und nichts zurückgegeben.
- Begründung: Direkte Umsetzung der Regeln 1 bis 8.

### D35 Größen
- Stelle: 3.3 Regel 2, "50 MB, also höchstens 800 Blöcke".
- Entscheidung: Höchstens 800 Blöcke, also 52.428.800 Byte (50 MiB) Inhalt. `MaxFileSize` ergibt sich aus den Höchstwerten aller Teile (Phase 0: 52.466.322 Byte; seit Phase 0.1 mit Typbyte je Element 52.467.123 Byte). Der Trailer ist auf 1 KiB begrenzt (der Trailer der Suite 1 hat 127 Byte).
- Begründung: 800 Blöcke sind die präzise Zahl; siehe SPEC-ISSUES S10.

### D36 Signatur: Domäne und signierte Struktur
- Stelle: 3.4, `sig = Ed25519("gomail/v1/sig/" || kind || 0x00 || kanonische Struktur)`; "enthält immer den SHA-256 über Präambel, Kopf, Empfängerteil und alle Blöcke, je nach Dateiart weitere Felder (siehe 7)".
- Frage: Ist `kind` die Zahl oder der Name? Welche Bytes gehen in den Hash? Wie kommen die Felder aus Abschnitt 7 hinein?
- Entscheidung: `kind` ist der Name (`mail`, `meta`, `pending`, `wrap`, `index`), also etwa `"gomail/v1/sig/meta" || 0x00`. Der Hash läuft über die Dateibytes von Offset 0 bis vor das Trailer-Element (Phase 0: bis vor das Trailer-Längenfeld), also inklusive der Längenfelder von Kopf und Empfängerteil und der Typbytes und Längenfelder aller Blöcke (3.4, Version 1.1; Commit 53b92a0). Bei einer unsignierten Datei liefert `FileHash` damit den Hash der ganzen Datei. Die signierte Struktur ist der Datensatz `gomail/v1/rec/signed` mit `file_hash`, `signer_type`, `signer_id`, `signer_gen` und optional `extra`: ein vom Aufrufer kanonisch kodierter Datensatz mit den dateiartspezifischen Feldern aus Abschnitt 7 (Phase 3 legt ihn für Metadaten fest). Der Prüfer muss dasselbe `extra` übergeben.
- Begründung: Der Name liest sich wie die anderen Labels; beides wäre eindeutig. Die Signer-Felder in der Struktur binden den Trailer an den Schlüssel. `extra` hält die Schnittstelle offen, ohne Felder zu erfinden. Siehe SPEC-ISSUES S04.

### D37 Signaturpolitik beim Öffnen
- Stelle: 7, "Es gibt keinen Modus, in dem unsignierte Dateien still akzeptiert werden"; Mails selbst sind nicht signiert (ihr Hash steht in den Metadaten).
- Entscheidung: `Open` verlangt eine ausdrückliche Politik: eine signierte Datei braucht `ResolveSigner`, das den Schlüssel zum Trailer liefert oder ablehnt (unbekannt, widerrufen, ohne Zertifikat); eine unsignierte Datei wird nur mit `AllowUnsigned` angenommen. Fehlt der Resolver bei einer signierten Datei, lehnt `Open` ab (`ErrSignaturePolicy`). Der Nullwert der Optionen akzeptiert nichts.
- Begründung: Fail closed als Standard; die Entscheidung, wer signieren darf, liegt bei der Ablage (Zertifikate, Log) und nicht im Dateiformat.

### D38 Suite-Prüfung
- Stelle: 3.5.
- Entscheidung: Der Parser lehnt jede Suite außer 1 ab. `Open` verlangt `ExpectedSuite` (aus der `epoch.rec` des Aufrufers) und lehnt Abweichungen ab; 0 ist kein gültiger Wert. `CheckSuiteTransition(prev, next)` lehnt einen Rückschritt ab und steht für die Epochenkette bereit.
- Begründung: Regeln 1 bis 4 aus 3.5; die Epochenkette selbst kommt in Phase 4.

### D39 Verhalten gegenüber Änderungen in fremden Empfängereinträgen
- Stelle: 3.1, "bewusst nicht Teil der AAD der Blöcke".
- Entscheidung: In einer unsignierten Datei kann der Eintrag eines anderen Empfängers (Typ, ID, Generation, `enc`, `wrapped_key`) verändert werden, ohne dass der Öffner es bemerkt, solange die Struktur gültig bleibt und der Eintrag nicht mit dem eigenen Tripel zusammenfällt. Das Klartext-Ergebnis ist dann unverändert. Jede andere Änderung wird erkannt. In signierten Dateien wird jede Änderung erkannt. `TestBitFlipForeignRecipient` prüft genau das.
- Begründung: Vorgabe der Spezifikation; die Folge ist dokumentiert (siehe SPEC-ISSUES S06).

### D40 Eingaben des Schreibers
- Entscheidung: `NoncePrefix` und `ChunkSize` im übergebenen Kopf werden vom Schreiber gesetzt und überschrieben. `Parse` kopiert die Eingabe, damit spätere Änderungen am Slice die Datei nicht beeinflussen.
- Begründung: Der Nonce-Präfix muss zufällig aus dem Reader kommen; eine Kopie verhindert Zeitfenster zwischen Prüfung und Verwendung.

### D41 HPKE-Testvektoren
- Stelle: Auftrag, "Testvektoren aus RFC 9180 für genau die verwendete Suite".
- Frage: Anhang A des RFC enthält für X25519 nur AES-128-GCM und ChaCha20-Poly1305.
- Entscheidung: Verwendet wird der Vektor für DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, Base-Modus aus der vom RFC referenzierten vollständigen Sammlung (`cfrg/draft-irtf-cfrg-hpke`, `test-vectors.json`), beschränkt auf die ersten zehn Verschlüsselungen und alle Exporte. Quelle steht in der Datei und im Test. Geprüft werden die Ableitung des Empfängerschlüssels, das Öffnen der Kapselung und der Verschlüsselungen, die Exporte, der Pfad über `crypto/ecdh` und die Ablehnung von Punkten kleiner Ordnung auf beiden Seiten.
- Begründung: Einziger offizieller Vektor für genau diese Suite.

## Phase 0.1 (Version 1.1)

### D42 Elementrahmen nach dem Empfängerteil
- Stelle: 3.1 (Version 1.1), Elemente mit Typbyte; Auftrag Phase 0.1 Punkt 1.
- Frage: Der Auftrag nennt die Typbytes (`0x01` Block, `0x02` letzter Block, `0x03` Trailer) und die zulässige Folge `0x01*, 0x02, 0x03?`, nicht aber die Bytefolge innerhalb eines Elements; der Text der Version 1.1 lag zu diesem Zeitpunkt noch nicht im Repository (er kam als `docs/PLAN.md` hinzu).
- Entscheidung: Ein Element ist `Typbyte (1) || Länge uint32 Big Endian (4) || Inhalt`. Der Parser nimmt genau die Folge `ElemBlock* ElemLastBlock ElemTrailer?` und danach das Dateiende an. Jeder `ElemBlock` ist ein voller Block (`chunk_size + 16`), der `ElemLastBlock` ist 16 bis `chunk_size + 16` Byte groß und nur als einziger Block leer. Abgelehnt werden: fehlender `0x02` (Dateiende oder Trailer nach `0x01`-Blöcken: `ErrTruncated` bzw. `ErrElement`), zwei `0x02`, `0x01` nach `0x02`, zwei Trailer, jedes andere Typbyte (`ErrElementType`), jedes Byte nach dem Trailer (`ErrElement`, vor dem Lesen des Längenfelds). Eine unsignierte Datei endet mit dem `0x02`-Element; es gibt kein Trailer-Längenfeld 0 mehr. Die Übereinstimmung von Typbyte und Letzter-Block-Flag im Nonce prüft die Authentifizierung: Der Entschlüsseler setzt das Flag aus dem Typbyte, ein Block mit dem jeweils anderen Flag authentifiziert nicht (`TestElementTypeMatchesNonceFlag`). `MaxFileSize` enthält 5 Byte Rahmen je Element.
- Begründung: Typbyte vor der Länge entspricht dem Aufbau der übrigen Teile (Kennung, dann Länge). Die Folge ist ohne Schlüssel und streamend prüfbar; jede Abweichung wird vor jeder Entschlüsselung abgelehnt.
- Bestätigt gegen den Text: 3.1 der Version 1.1 legt `Typ (1 Byte) || Länge (uint32 Big Endian) || Wert`, die Typen `0x01`/`0x02`/`0x03`, die Folge "beliebig viele `0x01`, genau ein `0x02`, danach höchstens ein `0x03`, danach Dateiende" und die Ablehnung jedes Bytes danach fest; 3.4 den Hash über alle Bytes vor dem Trailer-Element einschließlich Typbyte und Länge. Die Umsetzung entspricht dem.

### D43 Empfängertyp 4 und Höchstzahl 4
- Stelle: 3.1 (Version 1.1); Auftrag Phase 0.1 Punkt 2.
- Entscheidung: `RecipientRecovery = 4`; Typen 1 bis 4 gültig, höchstens vier Einträge (siehe D32). Für Typ 4 gelten dieselben Regeln wie für die anderen (HPKE-`info` mit Typ, ID, Generation; eindeutiges Tripel). `envelope` erzwingt nicht, dass Typ 4 nur in `recovery.wrap` vorkommt: 2.4 (Version 1.1) legt fest, dass der Wiederherstellungsempfänger nie in Mail- oder Metadatendateien eingetragen wird, aber 3.1 lässt die Typen 1 bis 4 in jeder Datei zu; die Regel aus 2.4 setzt die Ablage um (siehe HANDOFF).
- Begründung: Vorgabe von 3.1; keine erfundene Prüfung im Format.

### D44 Testvektoren nach dem Formatwechsel
- Stelle: Auftrag Phase 0.1, "Vektoren, die sich nicht ändern dürften, müssen unverändert bleiben".
- Entscheidung: Die zehn `.gml`-Dateien sind neu erzeugt (Rahmen geändert, Signaturen decken den neuen Rahmen ab). Alle in `vectors.json` festgehaltenen Werte sind byte-identisch geblieben: Kopfkodierung, Nonce-Präfix, SHA-256 der Blockchiffrate, SHA-256 des Klartexts; das wurde vor dem Commit mit der alten Datei verglichen. Die Dateien aus Phase 0 liegen unter `internal/envelope/testdata/phase0/` und laufen als Ablehnungsfälle (`TestPhase0FilesRejected`) und als Fuzz-Saat weiter.
- Begründung: Kopf, Schlüsselableitung, Nonces und Block-AAD sind unverändert; nur der Rahmen und damit die Signatur ändern sich. Ein Unterschied in den festgehaltenen Werten hätte auf einen Fehler in der Umsetzung gedeutet.

### D45 Argon2-Bereiche und Datensatztypen aus 2.2 und 2.3
- Stelle: Auftrag Phase 0.1 Punkt 4 (S07, S08); 2.2 und 2.3 der Version 1.1.
- Entscheidung: Die Argon2id-Bereiche in 2.2 entsprechen genau D22; keine Änderung. Die Datensatztypen in 2.3 weichen von D20 ab und sind angeglichen (Commit 5863796), siehe D20 und D46.
- Begründung: Vorgabe des Textes.

### D46 Signaturdomäne der Plattformdatensätze
- Aufgehoben in Phase 1 (Schritt 0, S14): Version 1.2 legt in 3.7 Kurznamen fest (`platform-cert`, `platform-succ`). Siehe D47.
- Stelle: 2.3 (Version 1.1): "Signiert wird jeweils der Datensatz ohne das Signaturfeld, mit dem Präfix `"gomail/v1/sig/" || Datensatztyp || 0x00`."
- Frage: "Datensatztyp" ist in der Tabelle davor der volle Typ-String (`gomail/v1/rec/platform-cert`). Gemeint sein könnte auch ein Kurzname.
- Entscheidung: Wörtlich: Domäne ist der volle Typ-String, die signierte Nachricht beginnt mit `gomail/v1/sig/gomail/v1/rec/platform-cert\x00`. `DomainPlatformCert` und `DomainPlatformSuccession` sind gleich `PlatformCertSchema.Type` und `PlatformSuccessionSchema.Type`; ein Test pinnt das. Das Generationszertifikat der Benutzer (2.2, D18) ist nicht betroffen und behält die Domäne `generation`.
- Begründung: Die konservative Lesart ist der Text; die Verdopplung des Präfixes ist eindeutig und kollidiert mit keiner anderen Domäne. Siehe SPEC-ISSUES S14.

## Phase 1 (Version 1.2)

### D47 Signaturdomänen nach 3.7
- Stelle: 3.7 (Version 1.2), Abschnitt 14 Punkt S14; Auftrag Phase 1 Schritt 0 Punkt 1.
- Frage: 3.7 leitet den Kurznamen eines Datensatzes aus seinem Typ ab ("Datensatztyp ohne das Präfix `gomail/v1/rec/`"), die Tabelle nennt für das Generationszertifikat aber `user-gen`, während dessen Typ seit Phase 0 `gomail/v1/rec/generation` heißt.
- Entscheidung: Beide Regeln gelten wörtlich; deshalb heißt der Typ jetzt `gomail/v1/rec/user-gen`. `keys` führt die Tabelle aus 3.7 als einzige Liste (`DomainPlatformCert`, `DomainPlatformSuccession`, `DomainUserGen`, `DomainEpoch`, `DomainAddress`, `DomainCheckpoint`, `DomainMail`, `DomainMeta`, `DomainPending`, `DomainWrap`, `DomainIndex`). `keys.Sign` und `keys.Verify` nehmen nur diese elf Namen an (`ErrDomain` sonst), damit kein Aufrufer eine eigene Domäne erfindet und Kurznamen eindeutig bleiben. `keys.RecordDomain(schema)` liefert den Kurznamen eines Datensatztyps und lehnt Typen ab, die nicht in der Tabelle stehen. `envelope.Kind.String` liefert die Konstanten aus `keys`. Die Datensätze `epoch`, `address` und `checkpoint` heißen `gomail/v1/rec/epoch`, `gomail/v1/rec/address` und `gomail/v1/rec/checkpoint`.
- Vektoren: In `keys/testdata/cert_vectors.json` ändern sich die drei Generationszertifikate (Typ-String und Signatur) sowie Admin-, Ingest-Zertifikat und Nachfolge (Signatur); öffentliche Schlüssel, Ableitung und Schlüsselspeicher sind byte-identisch. In `rec/testdata/records.json` ändern sich nur die zwei Generationszertifikate (Typ-String). `envelope` ist unverändert, die Dateiartnamen waren bereits die Kurznamen; die `.gml`-Dateien wurden deshalb nicht neu erzeugt. Der Fuzz-Regressionsfall `revokes = 0` liegt zusätzlich mit dem neuen Typ-String vor (`user-gen-revokes-zero`), der alte bleibt als Ablehnungsfall.
- Begründung: Text der Version 1.2; die feste Liste setzt "Kurznamen sind eindeutig, ein neuer signierter Typ braucht einen neuen Kurznamen" mechanisch durch.

### D48 Grenzen der neuen Datensätze und Dateien
- Stelle: 3.3 "Alle Längenfelder werden vor jeder Speicherreservierung gegen die Höchstwerte geprüft"; Auftrag Phase 1, kein `panic`, fail closed.
- Frage: Welche Höchstwerte gelten für die Datensätze und Dateien von Phase 1?
- Entscheidung: Je Datensatz feste Höchstzahlen (`store`: 1.024 Generationen, 64 Mitglieder je Epoche, 100 Empfänger in den Metadaten, 4.096 Byte je Headerfeld, 100 Einträge je Begriffsliste, 256 Begriffe je Mail zu höchstens 1.024 Byte, 1.024 Ordner). Jede Datei wird vor dem Lesen über ihre Größe geprüft (`ReadFileLimited`): `user.rec` 512 KiB, Datensätze 64 KiB, Verpackungen 16 KiB, Metadaten 512 KiB, Begriffslisten 2 MiB, Mails `envelope.MaxFileSize`, `addresses.json` 16 MiB, Journale 256 KiB. Eine Begriffsliste wird geteilt, bevor sie kodiert 512 KiB überschreitet, damit sie unter `rec.MaxRecordSize` bleibt.
- Begründung: Die Spezifikation nennt nur die Grenzen von `.gml`; die gewählten Werte liegen weit über dem Bedarf des PoC und begrenzen jede Reservierung.

### D49 Inhalt von `epoch.rec` und Kennungen der Empfänger
- Stelle: 2.4 "`epoch.rec` hält Nummer, Beginn, Grund, die erlaubte Algorithmen-Suite, die öffentlichen Schlüssel, die Liste der Mitglieder mit ihrer Generation und den SHA-256 der vorherigen `epoch.rec`"; 3.1 Empfängereinträge mit `id` und `gen`.
- Frage: Fehlen Felder, um eine Epoche zu prüfen? Welche `id` und `gen` tragen Empfängereinträge für Epochenschlüssel?
- Entscheidung: `gomail/v1/rec/epoch` enthält zusätzlich die Postfach-ID (Feld 1) und den Unterzeichner (`signer_id`, `signer_gen`), signiert unter dem Kurznamen `epoch`. `prev_hash` fehlt genau bei Epoche 1. Gründe: 1 initial (nur Epoche 1), 2 monatlich, 3 Mitglied entfernt, 4 Vertretung, 5 gelöscht, 6 sofortiger Beginn nach leerem Vorrat. Mitglieder sind Einträge `gomail/v1/rec/epoch-member` mit Art (1 Benutzer, 2 Wiederherstellung), ID und Generation; höchstens ein Wiederherstellungsempfänger. Kettenregeln (`store.CheckLink`): gleiche Postfach-ID, Nummer +1, `prev_hash` gleich SHA-256 der Kodierung der Vorgängerin, Beginn nicht früher, Suite nicht älter, Unterzeichner ist Benutzer-Mitglied der Vorgängerin; Epoche 1 ist von einem ihrer eigenen Mitglieder signiert. Empfängereinträge für `content` und `meta` tragen als `id` die Postfach-ID und als `gen` die Epochennummer; für `user-unwrap` die Benutzer-ID und die Generation. Der Ingest-Unterzeichner hat die ID 16 Nullbytes und als Generation die des Ingest-Schlüssels.
- Begründung: Ohne Postfach-ID ließe sich Epoche 1 eines Postfachs in ein anderes Postfach desselben Benutzers verschieben; ohne Unterzeichner wüsste der Prüfer nicht, welchen Schlüssel er nehmen soll. Siehe SPEC-ISSUES S18.

### D50 Empfangszeit, Wahl der Epoche und Vorrat
- Stelle: 2.4 Epochenwechsel, Vorrat, "Mails, die nach Beginn einer neuen Epoche noch für eine ältere verschlüsselt wurden"; 7 "Empfangszeit".
- Frage: Was ist die Empfangszeit, wenn die Annahme über einen Epochenwechsel hinweg dauert? Wann beginnt eine "monatliche" und eine "sofortige" Epoche? Wie stellt der Client die Regel fest?
- Entscheidung: Die Empfangszeit ist der Zeitpunkt von `DATA`, an dem der Server die Epoche wählt und die Verschlüsselung beginnt; sie steht als `created` im Kopf der Metadaten und als `received` in den signierten Feldern. Der Server wählt die höchste Epoche, deren Beginn nicht nach der Empfangszeit liegt, und prüft ihre Signatur. Monatliche Epochen beginnen am Monatsersten 00:00 UTC, aber nie früher als fünf Minuten nach ihrem Erzeugen (Fund der Prüfung); der Vorrat reicht drei Monate über den laufenden hinaus (bei `mailbox create` und `sync`). Liegt der Beginn der gewählten Epoche in einem früheren Monat, ist der Vorrat erschöpft: der Server verwendet sie weiter und vermerkt das in `mailboxes/<id>/epoch-fallback.rec` (Epoche, erste und letzte Empfangszeit, Anzahl, unverschlüsselt, ohne Inhalt) und im Log. Der nächste `sync` erzeugt eine Epoche mit Grund 6 und Beginn fünf Minuten nach dem Erzeugen (`client.ImmediateDelay`) und entfernt den Vermerk. Der Client nimmt eine Mail der Epoche n nur an, wenn Beginn(n) ≤ Empfangszeit < Beginn(n+1) gilt. Beginn(n+1) kommt aus der geprüften Kette oder, wenn die Kette inzwischen vor n+1 endet, aus dem lokal gemerkten Beginn; ist beides unbekannt und die Kette gebrochen, wird die Mail abgelehnt (Fund der Prüfung). Der Server prüft die Kette von Epoche 1 bis zum Kopf (Verknüpfung, Unterzeichner Mitglied der Vorgängerin, Signatur, Log), bevor er für eine Epoche verschlüsselt (Fund der Prüfung).
- Begründung: Ein Beginn genau "jetzt" würde eine Mail, die der Server zwischen dem Zeitstempel des Clients und dem Sichtbarwerden der neuen `epoch.rec` annimmt, als "für eine veraltete Epoche verschlüsselt" erscheinen lassen; der Vorlauf deckt das und eine mäßige Uhrabweichung ab, ohne die Prüfung abzuschwächen. Siehe SPEC-ISSUES S19.

### D51 Metadaten und Ingest-Signatur
- Stelle: 5.2 Schritt 3; 7 "Was die Ingest-Signatur aussagt", "Prüfung beim Öffnen einer Mail", "Gegen Wiedereinspielen"; Übergabe Phase 0.1 Punkte 2 und 3.
- Frage: Was steht in den Metadaten, wie sieht `extra` der Signatur aus, welcher Hash der Mail-Datei?
- Entscheidung: Klartext `gomail/v1/rec/mail-meta`: Version, Mail-ID, Empfangszeit, SHA-256 der **ganzen** Mail-Datei, Größe, Ordner, Flags, Umschlagabsender, Umschlagempfänger dieses Postfachs, `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID` (RFC 2047 dekodiert, mit `store.CleanText` bereinigt: ungültiges UTF-8 wird U+FFFD, Steuerzeichen werden Leerzeichen, NFC, höchstens 4.096 Byte), Anhang-Kennzeichen und ob der Header ausgewertet wurde. `extra` ist `gomail/v1/rec/meta-signed` mit Postfach-ID, Epoche, Mail-ID, Empfangszeit, Hash der Mail-Datei und Version; Hash der Metadaten-Datei und Ingest-Generation stehen bereits in der signierten Struktur von `envelope` (`file_hash`, `signer_gen`). Der Server schreibt Version 1. Der Client entschlüsselt die Metadaten, baut daraus `extra`, prüft die Signatur und verwendet erst danach irgendeinen Wert; anschließend prüft er Mail-ID, Ordner und `received = created`, die Gültigkeit des Ingest-Zertifikats zur Empfangszeit, die Epochenregel aus D50, die Adresszuordnung (über das Log) und die Version. Beim Lesen vergleicht er den SHA-256 der ganzen Mail-Datei mit den Metadaten und Postfach-ID, Epoche und `file_id` des Mail-Kopfs. Metadaten mit Benutzersignatur (Flag-Änderungen) lehnt der Client in Phase 1 ab, weil es sie noch nicht gibt.
- Begründung: Der Hash der ganzen Datei deckt auch den Empfängerteil (S06). Die Felder aus Abschnitt 7 sind vollständig signiert; ohne Schlüssel lässt sich die Signatur aber nicht prüfen, weil Version und Empfangszeit nur im Klartext stehen, siehe SPEC-ISSUES S22.

### D52 Spool-Transaktion und Absturzsicherheit
- Stelle: 5.2 Schritte 2 bis 4, "Absturz während des Empfangs"; Auftrag Phase 1 "Entweder ... kein 250 und nichts im Postfach, oder die Mail liegt vollständig im Postfach".
- Frage: Mail, Metadaten und Marker liegen in verschiedenen Verzeichnissen (`mail/<ordner>/`, `pending/<n>/`), bei mehreren Empfängern in mehreren Postfächern. Mehrere Umbenennungen sind nicht atomar.
- Entscheidung: Eine Annahme ist eine Transaktion unter `spool/<txn-id>/<postfach-id>/` (statt `spool/<postfach-id>/<mail-id>.gml`) mit `mail.gml`, `meta.gml` und `marker.gml`. Nach dem Schreiben aller Dateien wird unter den Sperren aller Empfängerpostfächer ein Journal `spool/<txn-id>/journal.rec` mit allen Umbenennungen atomar angelegt, danach werden Marker, Metadaten und Mail umbenannt (jeweils mit `fsync` der Verzeichnisse), dann wird das Journal gelöscht. Das Löschen ist der Commit; erst danach antwortet der Server `250`. Beim Start macht `Recover` die Umbenennungen jeder Transaktion mit Journal rückgängig und löscht `spool/` und `work/` vollständig. Ein Absturz nach dem Commit und vor `250` lässt eine vollständige Mail ohne `250` zurück; der Absender stellt erneut zu (Doppelzustellung, wie bei SMTP üblich). Der Marker ist eine `pending`-Datei mit der Mail-ID als Datei-ID und einem Eintrag `unprocessed`, verschlüsselt für `meta` und mit dem Ingest-Schlüssel signiert. Für Tests gibt es Einspritzpunkte (`data`, `spooled`, `journal`, `moved-1` bis `moved-6`, `committed`, `batch-written`, `marker-removed`) über eine Paketvariable, die nur Tests setzen.
- Begründung: Nur so gilt "alles oder nichts" über mehrere Dateien und Postfächer. Siehe SPEC-ISSUES S21.

### D53 Adressen und Einladungen
- Stelle: 2.2 Registrierung mit Einladungscode; 2.3 Adresszuordnungen; 4 `invites/<code>.json`, `addresses.json`; 5.2 Schritt 1.
- Entscheidung: Adressen werden kanonisch als ASCII in Kleinbuchstaben verglichen (`local@domain`, höchstens 254 Byte, ohne Leerzeichen, Klammern und Anführungszeichen); internationalisierte Adressen sind im PoC nicht vorgesehen. `addresses.json` ist `{"addresses": {"<adresse>": "<postfach-id>"}}`, geschrieben atomar unter `addresses.lock`; eine Adresse wird nie still einem anderen Postfach zugeordnet. `address add` verlangt den Admin-Schlüssel, ein bestehendes Postfach und signiert die Zuordnung (`gomail/v1/rec/address`, Kurzname `address`) für das Log. Einladungen sind `invites/<code>.json` mit dem Erstellzeitpunkt, der Code ist eine zufällige ID; ein Code wird durch atomares Umbenennen verbraucht, bevor `user.rec` geschrieben wird, sodass er nie zwei Benutzer registriert. Einladungen sind nicht signiert (SPEC-ISSUES S17).
- Begründung: Groß- und Kleinschreibung im lokalen Teil werden in der Praxis nicht unterschieden; konservativ und einfach.

### D54 Einheiten und Antworten bei SMTP
- Stelle: 5.1, 5.2.
- Entscheidung: 25 MB sind 25.000.000 Byte (so in `SIZE` angekündigt, gezählt nach Dot-Unstuffing mit CRLF), 1 MB Header 1.000.000 Byte, 1 KB/s sind 1.000 Byte je Sekunde, gemessen in festen Fenstern von 60 Sekunden ab `DATA`; wer in einem Fenster weniger schickt, wird mit `421 4.4.2` getrennt, ein Stillstand am Fensterende ebenso. Zeilen haben höchstens 1.000 Oktette einschließlich CRLF. Ein nacktes LF oder CR beendet nie die Daten und führt nach dem echten Ende zu `554 5.6.0` (Schutz gegen SMTP-Smuggling); eine zu lange Datenzeile ebenso. Antworten: `550 5.1.1` unbekannter Empfänger, `452 4.5.3` ab dem 101. Empfänger, `552 5.3.4` zu groß, `452 4.3.1` bei weniger als 10 % freiem Platz (bei `MAIL FROM`, `DATA` und ENOSPC beim Schreiben), `451 4.7.1` ab der 1.001. Mail je IP-Adresse und Stunde, `421 4.7.0` über 20 Verbindungen insgesamt oder 5 je IP-Adresse, `503 5.5.1` bei falscher Reihenfolge. Die Stundenzählung merkt sich höchstens 65.536 IP-Adressen; ist die Tabelle voll, wird eine neue Adresse vorübergehend abgewiesen. Angekündigt werden `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`, nicht `PIPELINING`. IP-Adressen stehen nur im `Received`-Header der verschlüsselten Mail, nie im Log.
- Begründung: SMTP rechnet dezimal; die Fensterregel ist die direkte Umsetzung von "gemittelt über 60 Sekunden". Siehe SPEC-ISSUES S15.

### D55 Vorverarbeitung und Begriffe
- Stelle: 5.1 letzte Grenze, 5.2 Schritt 5, 5.3, 5.4.
- Entscheidung: Die Warteschlange hält Header im Speicher bis 32 MiB, lagert darüber mit AES-256-GCM unter dem flüchtigen Schlüssel nach `work/` aus (AAD bindet Postfach, Epoche und Mail-ID) bis 256 MiB und lässt darüber die Mail mit Marker liegen. Der flüchtige Schlüssel entsteht bei jedem Start aus `crypto/rand`, wird mit `mlock` gesperrt und bei `Close` überschrieben; schlägt `mlock` fehl, wird nie nach `work/` ausgelagert (Mails behalten dann ihren Marker, Fund der Prüfung). Der von `crypto/aes` erweiterte Schlüssel liegt in nicht gesperrtem Speicher und lässt sich nicht überschreiben (wie D04). Offene Begriffslisten zählen gegen die Speichergrenze; wird sie überschritten, werden alle geschrieben. Ein Fehler im Arbeiter (Panic) wird abgefangen, die betroffenen Mails behalten ihren Marker. Begriffe: `from:` und `fromdomain:` aus der Adresse in `From` (ohne lesbare Adresse aus dem Umschlagabsender), `to:` aus den Umschlagempfängern dieses Postfachs (damit eine Bcc-Kopie unter ihrer Adresse zu finden ist), `To` und `Cc`, `day:` und `month:` aus der Empfangszeit in UTC, `has:attachment` bei `multipart/mixed` auf oberster Ebene, `thread:` aus dem ersten Eintrag von `References`, sonst `In-Reply-To`, sonst `Message-ID`, jeweils mit spitzen Klammern; alles klein geschrieben, bereinigt und in NFC, höchstens 256 Begriffe, Empfänger zuletzt. Eine Begriffsliste gilt je Postfach und Epoche und wird nach 100 Mails, 60 Sekunden oder 512 KiB geschrieben; danach werden die ersetzten Marker gelöscht. Header über 1 MB, mit mehr als 500 Feldern, ohne Leerzeile oder für `net/mail` unlesbar werden nicht ausgewertet: die Metadaten tragen dann nur Umschlagdaten, der Marker bleibt.
- Begründung: 5.4 nennt die Felder, lässt aber offen, ob `to` auch `Cc` umfasst und ob `day` aus `Date` oder der Empfangszeit kommt; der `Date`-Header ist vom Absender frei wählbar, die Empfangszeit ist signiert. Siehe SPEC-ISSUES S23.

### D56 Postfachname, Ordner und Posteingang
- Stelle: 4 `mailbox.rec` "Name (verschlüsselt), aktuelle Epoche", `folders.gml`, `mail/<ordner-id>/`.
- Entscheidung: `mailbox.rec` (`gomail/v1/rec/mailbox`, nicht signiert) enthält Postfach-ID, die höchste Epochennummer (Kopf der Kette), die ID des Posteingangs und den Namen als `.gml`-Datei der Art `meta` für den `meta`-Schlüssel von Epoche 1, `file_id` gleich der Postfach-ID, signiert vom anlegenden Mitglied. `folders.gml` ist ebenso aufgebaut mit `file_id` gleich der Posteingangs-ID und enthält die Liste `gomail/v1/rec/folders` (in Phase 1 nur `INBOX`). Der Server liefert immer in den Posteingang aus `mailbox.rec`; er kann die Ordnernamen nicht lesen. Der Klartext trägt jeweils einen eigenen Typ-String, sodass Name, Ordnerliste und Mail-Metadaten nie verwechselt werden.
- Begründung: Der Server muss den Zielordner kennen, ohne `folders.gml` lesen zu können. Siehe SPEC-ISSUES S20.

### D57 Lokaler Zustand des Clients
- Stelle: 2.4 "Der Client merkt sich lokal die höchste Epoche"; 7 "merkt sich pro Mail die höchste gesehene Version".
- Entscheidung: Das Client-Verzeichnis (Standard `~/.config/gomailctl`, nie im Datenverzeichnis) enthält `keystore`, eine Kopie der eigenen `user.rec` und `state.json` (Benutzer-ID, registriert, je Postfach die höchste gesehene Epoche mit dem SHA-256 ihrer `epoch.rec` und je Mail die höchste Version; nur IDs und Zahlen). Beim Öffnen muss `user.rec` im Datenverzeichnis byte-gleich mit der lokalen Kopie sein, und der Schlüsselspeicher muss die aktuelle Generation halten. Bei jedem Lesen prüft der Client die ganze Kette ab Epoche 1; zeigt `mailbox.rec` unter die gemerkte Epoche, warnt er und prüft trotzdem bis zur gemerkten; weicht der Hash der gemerkten Epoche ab, gilt die Kette ab dort als ungültig. `sync` verlängert nie eine Kette, die nicht vollständig geprüft ist.
- Nach der Prüfung ergänzt: `state.json` merkt sich den Beginn jeder geprüften Epoche (für D50). Epochen jenseits des Kopfs von `mailbox.rec` werden übernommen, wenn sie sich wie jede andere prüfen lassen (Absturz zwischen dem Anlegen der Epochen und dem Schreiben von `mailbox.rec`); `sync` schreibt dann den neuen Kopf. Ein Epochenverzeichnis ohne `epoch.rec` (abgebrochenes Anlegen) wird vor dem erneuten Anlegen gelöscht, eine vorhandene `epoch.rec` nie. Ein Client-Prozess hält eine Dateisperre auf `<client-dir>/lock`; ein zweiter Prozess auf demselben Verzeichnis bricht ab (`store.ErrLocked`). Der Posteingang kommt aus der signierten `folders.gml`; nennt `mailbox.rec` einen anderen, warnt der Client, ebenso für Ordnerverzeichnisse, die `folders.gml` nicht kennt.
- Begründung: Direkte Umsetzung; JSON genügt für lokale, nicht geheime Zahlen.

### D58 Plattformidentität und Entwicklungszeremonie
- Stelle: 2.3 "öffentlicher Teil im Client hinterlegt", Auftrag Phase 1 "Entwicklungszeremonie".
- Entscheidung: Der Client erhält die Plattformidentität als Datei (`gomail/v1/rec/platform-pin`: Generation, öffentlicher Schlüssel, Entwicklungskennzeichen). `gomail-ceremony init --dev` schreibt sie nach `keys/identity-1.pin` mit Kennzeichen; ein Client lehnt eine Entwicklungsidentität ab, wenn sein Log prüft (also ohne `--insecure-no-log`). Ingest-Zertifikate werden nur angenommen, wenn sie von der hinterlegten Identitätsgeneration ausgestellt sind (Nachfolgen der Identität folgen später) und die Empfangszeit nicht vor `valid_from` liegt. Private Plattformschlüssel liegen als `gomail/v1/rec/platform-key` (Rolle, Generation, 32 Byte Seed) unverschlüsselt mit Rechten 0600 im Schlüsselverzeichnis, das weder im Datenverzeichnis liegen noch es enthalten darf; der Root steht als Textdatei `platform-root.INSECURE-DEV-ONLY.txt` daneben. `inspect` zeigt den Seed einer Schlüsseldatei nie an.
- Begründung: Vorgabe des Auftrags; unverschlüsselte Schlüsseldateien sind nur in der Entwicklung vertretbar.

### D59 `user.rec`
- Stelle: 2.2 Registrierung (JSON-Beispiel), 7 Tabelle ("`user.rec` signiert von Identität des Benutzers"), 3.7.
- Entscheidung: `gomail/v1/rec/user` mit Benutzer-ID, öffentlichem Root und der Liste der Generationszertifikate (`gomail/v1/rec/user-gen`, je vom Root signiert); beim Dekodieren wird die Kette 1..n gegen den Root geprüft. Der Datensatz selbst trägt keine Signatur, weil 3.7 keinen Kurznamen dafür hat (SPEC-ISSUES S16). `keygen` legt den Benutzer nur lokal an (Seed, drei Wörter abgefragt, dann Root, Generation 1, Zertifikat, Schlüsselspeicher; Seed und Root werden überschrieben); `register` veröffentlicht ihn.
- Begründung: Die Generationen sind durch den Root geschützt; neue Domänen erfinden verbietet 3.7.

### D60 Signaturen widerrufener Generationen und Eingabe der Seed-Wörter (vorläufig)
- Stelle: 2.2 Generationen Punkt 4; 2.2 Seed-Format; Auftrag Phase 1 Schritt 0 Punkt 3 (S11, S13 vorlegen und anhalten).
- Entscheidung (vorläufig, bis zur Entscheidung des Auftraggebers): Wörter werden bei `keygen` exakt verglichen, nur das Zeilenende wird entfernt (`TODO(S11)`). Signaturen einer nicht mehr aktuellen Generation gelten für Datensätze, die ins Log kommen (`epoch.rec`), nur über `translog.CheckRevokedSignature`; für Dateien, die nie ins Log kommen (Verpackungen, Name, Ordner), gar nicht (`TODO(S13)`). In Phase 1 gibt es nur Generation 1; beide Stellen sind die strengste Lesart und ändern kein Format. Vorschläge in SPEC-ISSUES S11 und S13.
- Begründung: Der Auftrag verlangt, vor abhängigen Arbeiten anzuhalten; die strengste Lesart lässt jede spätere Entscheidung offen, ohne etwas zurückbauen zu müssen.

### D61 Verpackungen der Epochenschlüssel
- Stelle: 2.4 "Verpackung für Mitglieder".
- Entscheidung: `epochs/<n>/members/<user-id>.wrap` ist eine `.gml`-Datei der Art `wrap` mit `file_id` gleich der Benutzer-ID, einem Empfänger `user-unwrap` (Benutzer-ID, Generation) und dem Klartext `gomail/v1/rec/epoch-keys` (Postfach-ID, Epoche, die privaten Schlüssel `content` und `meta`, der Indexschlüssel). Der Client nimmt sie nur an, wenn sie von einem Benutzer-Mitglied dieser Epoche signiert ist, der Kopf zu Ort und Epoche passt und die abgeleiteten öffentlichen Schlüssel gleich denen der signierten `epoch.rec` sind. Neue Epochen werden mit zufälligen Schlüsseln aus `crypto/rand` erzeugt; die Verpackung wird vor der `epoch.rec` geschrieben, `mailbox.rec` zuletzt.
- Begründung: Der Vergleich der öffentlichen Schlüssel verhindert, dass eine Verpackung mit fremden Schlüsseln (die jeder für den öffentlichen Entpackschlüssel erzeugen kann) Mails für einen Angreifer lesbar macht.

### D62 IDs, Sperren und Pfade
- Stelle: 4 "Alle IDs sind zufällig (128 Bit, base32)"; Auftrag Phase 1 "Sperren pro Postfach mit Dateisperren, keine globale Sperre".
- Entscheidung: IDs sind 16 Byte aus `crypto/rand`, Textform base32 in Kleinbuchstaben ohne Auffüllung (26 Zeichen); `ParseID` nimmt nur die kanonische Form an, sodass eine ID nie einen Pfad außerhalb ihres Verzeichnisses bezeichnet. Sperren sind `flock` auf `mailboxes/<id>/lock`; mehrere Postfächer werden in fester Reihenfolge gesperrt. Gehalten werden sie beim Commit einer Annahme, beim Schreiben einer Begriffsliste und beim Anlegen von Epochen und `mailbox.rec`. Atomare Schreibvorgänge: temporäre Datei `.tmp-*` im Zielverzeichnis, `fsync`, Umbenennen (oder harter Link für exklusives Anlegen), `fsync` des Verzeichnisses; neue Verzeichnisse werden mit `fsync` des Elternverzeichnisses angelegt.
- Begründung: `flock` gibt es auf allen Zielsystemen; über NFS ist es nicht verlässlich (siehe HANDOFF, Grenzen).

## Bis M1 (Version 1.4, Orchestrierung)

### D63 Gründe der Epochen und sofortige Wirkung
- Stelle: 2.4 Tabelle der Gründe (Version 1.4); Vorrat ("Der nächste Client erzeugt dann eine Epoche mit sofortigem Beginn"); 2.6 Grund `deleted`; K1, K8; `docs/QUESTIONS.md` Q5.
- Frage: Die Tabelle nennt sechs Gründe. Keiner passt auf die erste Epoche eines Postfachs oder auf die Epoche nach erschöpftem Vorrat; `deleted` aus 2.6 fehlt in der Tabelle; `member-added` ist "geplant oder sofort", und aus der `epoch.rec` ist nicht ablesbar, welche Form gemeint ist.
- Entscheidung: `store.Reason` kennt genau die sechs Werte der Tabelle in ihrer Reihenfolge (1 `regular` bis 6 `generation-revoked`); die Gründe aus D49 entfallen (D49 insoweit aufgehoben). Epoche 1 und die Epoche nach erschöpftem Vorrat tragen `regular` und beginnen wie jede geplante Epoche frühestens fünf Minuten nach dem Anlegen (2.4 Vorlauf Regel 1; D50 bleibt für geplante Epochen). `member-added` gilt in M1 immer als sofort (`Reason.Immediate()` ist wahr für 2 bis 6): es wird nur die sofortige Form gebaut, und für eine neuere Epoche zu früh zu verschlüsseln "schadet nie" (2.4). `deleted` wird nicht gebaut (Löschen ist nicht Teil von M1).
- Begründung: Keine erfundenen Gründe; die Lesart ist aus der Tabelle und den Vorlaufregeln ableitbar und ändert sich nicht, falls die Spezifikation später einen eigenen Grund für die erste Epoche einführt (dann nur ein neuer Wert).

### D64 Kettenprüfer `store.Chain` und Unterzeichnerregeln
- Stelle: 2.4 "Verwerfen des Vorrats" Regeln 1 bis 5; K2 Regeln 1 und 2; HANDOFF Phase 1 Punkt C7.
- Entscheidung: Die Regeln der Kette liegen in einem einzigen Prüfer ohne Ein-/Ausgabe (`store.Chain`), den Client und Server gleich verwenden: Verknüpfung über `prev_hash`, Nummer +1, Suite nicht älter, `discards` genau gleich der Menge der bisher nicht verworfenen Epochen mit späterem Beginn (bei `regular` leer und keine solche Epoche vorhanden), Beginn nicht vor der letzten nicht verworfenen Vorgängerin, verworfene Nummern nie wieder gültig. Der Unterzeichner muss Benutzer-Mitglied der Vorgängerin und der neuen Epoche sein, und sein Mitgliedseintrag in der neuen Epoche trägt genau `signer_gen`. Damit kann ein entferntes Mitglied die Epoche `member-removed` nicht signieren (K2 Regel 2), eine Vertretung oder ein Wiederherstellungsempfänger keine Epoche anlegen (K2 Regel 1, siehe Q6), und ein Unterzeichner keine fremde Generation vortäuschen (C7). Ob die Generation des Unterzeichners zum Zeitpunkt gültig war, prüft der Aufrufer über `user.rec` und das Log.
- Begründung: Eine einzige Umsetzung der Regeln verhindert, dass Server und Client auseinanderlaufen (K8 verlangt, dass der Server dieselbe Epoche wählt, die der Client akzeptiert).

### D65 Haltepunkte in `docs/QUESTIONS.md`
- Stelle: K7; Orchestrierungsauftrag Abschnitt 4.
- Entscheidung: Jede Frage, die nach K7 anzuhalten ist, steht mit Vorschlag in `docs/QUESTIONS.md` (Q1 Wiederherstellungsempfänger, Q2 Einladungen, Q3 `--server-search`, Q4 Schlüssel und Zeit des Baumkopfs, Q6 Vertretung als Mitgliedsart). Pakete, die eine solche Stelle berühren, bauen die strengste Lesart und markieren sie mit `TODO(Qn)`; kein Befehl, der davon abhängt, wird vor der Antwort ausgeliefert.

### D66 Kopffeld 8 `version`
- Stelle: 3.1 (Version 1.4), 7, 16 Zeile K6; SPEC-ISSUES S22.
- Entscheidung: `envelope.Header.Version` (uint32), im Schema optional. Regel beim Kodieren und Dekodieren: `meta` verlangt Feld 8 mit Wert ≥ 1, alle anderen Arten verbieten Feld 8 auch mit Wert 0; der Schreiber lehnt einen Kopf anderer Art mit Version ab, statt sie wegzulassen. Fehler: `ErrHeader` zusammen mit `ErrHeaderVersion` (`ErrVersion` bleibt die Formatversion der Präambel). `SignedSchema` ist unverändert; mit Feld 8 stammen alle Werte von `meta-signed` aus dem Kopf oder aus Hashes über Chiffrat, sodass die Ingest-Signatur ohne Schlüssel prüfbar ist (Abschnitt 7). `envelope` prüft `created` nicht (D31); der Client vergleicht nach dem Entschlüsseln Version und Empfangszeit des Inhalts mit dem Kopf (`client.checkMeta`, `ErrMismatch`). Vektoren: die fünf signierten `meta`-Dateien neu (Kopf +9 Byte), die fünf unsignierten byte-identisch, die alten signierten unter `testdata/v12/` als Ablehnungsfälle. Der Generator behält Dateien, deren deterministische Teile unverändert sind, weil HPKE nicht reproduzierbar ist (D44).
- Begründung: Wörtliche Umsetzung von 3.1; die strengste Lesart beim Schreiber verhindert, dass ein Aufrufer unbemerkt eine Version verliert.

### D67 Fehler von `envelope` und SMTP-Größe
- Stelle: `envelope` Paketkommentar („jeder Fehler umhüllt einen exportierten Fehler“); 5.1 (25 MiB seit Version 1.3).
- Entscheidung: `ErrArgument` (Aufruffehler wie ein `nil`-Writer), `ErrInternal` (mit 32-Byte-Schlüssel unerreichbare Fehler der Schlüsselableitung, nie `ErrDecrypt`), `ErrWrite` (umhüllt zusätzlich den Fehler des `io.Writer`). `smtpd.DefaultMaxSize` ist 26.214.400 Byte (D54 insoweit geändert; Header 1.000.000 Byte und 1.000 Byte/s bleiben dezimal).
- Begründung: Fund der Verifikation von Auftrag 01; `errors.Is` muss für jeden Fehler des Pakets funktionieren.

### D68 `epoch.rec` in Version 1.4: `discards`, Mitgliedsarten, Kettenprüfer
- Stelle: 2.4 (Gründe, `discards` Regeln 1 bis 5), K1, K2, Q6; D49 und D64.
- Entscheidung: `gomail/v1/rec/epoch` mit den Feldern 1 `mailbox_id`, 2 `number`, 3 `begin`, 4 `reason`, 5 `suite`, 6 `content_pub`, 7 `meta_pub`, 8 `members`, 9 `discards` (Liste von `gomail/v1/rec/epoch-discard` mit `number`; streng aufsteigend, jede kleiner als die eigene Nummer, höchstens 1.024, nur bei sofortiger Wirkung, leer heißt abwesend), 10 `prev_hash`, 11 `signer_id`, 12 `signer_gen`, 13 `sig`. Mitgliedsarten 1 Benutzer, 2 Wiederherstellung, 3 Vertretung (`TODO(Q6)`); eine ID kommt in der Liste nur einmal vor; der Unterzeichner steht als Benutzer-Mitglied mit Generation `signer_gen` in der eigenen Liste. `store.Chain` (`NewChain`, `Add`, `Head`, `Epoch`, `Discarded`, `Begin`) prüft in fester Reihenfolge nach D64; eine abgelehnte Epoche lässt die Kette unverändert; `Add` verlangt, dass die übergebenen Bytes gleich der Kodierung sind; Regel 7 (Beginn sinkt nie) folgt aus der Vollständigkeit der `discards` und bleibt als zweite Sicherung. Gleicher Beginn gilt nicht als „später“. `CheckLink` entfällt.
- Begründung: Wörtliche Umsetzung von 2.4 mit den Klärungen; eine einzige Prüfung für Client und Server.

### D69 Ablage in Version 1.4: Ordnerliste, Signaturen, Vermerk, Indexsegment
- Stelle: 4 („Name und Ordnerliste pro Epoche“, `checkpoints/`, `index/`), 2.2 Punkt 4, 3.7 (`user`, `wrap-accept`, `checkpoint`), 6.2, 7, K5; D56, D59, D61.
- Entscheidung: `epochs/<n>/folders.gml` ist eine `meta`-Datei (Version 1, `file_id` gleich dem Posteingang) mit Klartext `gomail/v1/rec/folders` (Postfach-ID, Epoche, Name, Ordnerliste), für `meta` dieser Epoche, vom anlegenden Mitglied signiert, vor `epoch.rec` geschrieben; `mailbox.rec` enthält nur ID, Kopf und Posteingang; der Client liest die neueste nicht verworfene Epoche, in der er Mitglied ist (D56 insoweit aufgehoben). `user.rec` trägt Feld 4 `sig`: Signatur des Roots unter `user` über den Datensatz ohne `sig`; `DecodeUser` prüft sie gegen `root_pub` (S16 erledigt, D59 insoweit aufgehoben). `gomail/v1/rec/wrap-accept` (Postfach, Epoche, Benutzer, SHA-256 der ganzen `.wrap`-Datei, Generation, Signatur unter `wrap-accept`) in `epochs/<n>/members/<user-id>.accept`. `gomail/v1/rec/checkpoint` (Benutzer, Gerät, Origin ≤ 128 Byte, Größe, Wurzelhash, Kopfzeit, Generation, Signatur unter `checkpoint`) in `mailboxes/<id>/checkpoints/<user-id>-<device-id>.rec`, je Gerät ersetzt. `gomail/v1/rec/index-segment` (Postfach, Epoche, Einträge `posting` mit Marke und IDs; Marken und IDs streng aufsteigend, höchstens 16.384 Einträge zu je 4.096 IDs, kodiert höchstens 1 MiB, Datei höchstens 4 MiB) in `index/<n>/<device-id>-<lfd>.gml`, exklusiv angelegt, `lfd` dezimal ab 0. `MetaSignedExtra(Header, mailHash)` baut `meta-signed` nur aus dem Kopf (mit `Version`) und dem Hash der Mail-Datei.
- Begründung: Abschnitt 4 und 3.7 in Version 1.3/1.4; Grenzen nach dem Muster von D48.

### D70 Sperren und Rechte nach 9.1
- Stelle: 9.1; D62.
- Entscheidung: POSIX-Satzsperren über die ganze Datei statt `flock` (D62 insoweit aufgehoben): unter Linux OFD-Sperren (`F_OFD_SETLK` 37, `F_OFD_SETLKW` 38 über `syscall.FcntlFlock`), sonst Prozess-Sperren; ein prozessweites Register hält je Sperrpfad genau einen Deskriptor, weil Prozess-Sperren beim Schließen irgendeines Deskriptors verfallen. Dateien im Datenverzeichnis 0660, Verzeichnisse 2770, jeweils per `Chmod` nach dem Anlegen (`umask` kann Gruppenbits entfernen); `Init` setzt die Wurzel; die Gruppe `gomail` setzt der Administrator. Private Dateien außerhalb des Datenverzeichnisses (Schlüsselspeicher, Client-Zustand, Plattformschlüssel) über `WritePrivateFileAtomic`/`CreatePrivateFileAtomic` mit 0600. Rollensperren `locks/server` (exklusiv) und `locks/client` (geteilt, mehrere Clients laufen gleichzeitig); `CheckPeerLock` versucht nicht blockierend eine exklusive Sperre auf der Datei des Gegenübers und meldet `ErrPeerLock`, wenn sie gelingt; der Client prüft so den laufenden Server, der Server hält nur seine Sperre (ein Server kann keinen laufenden Client voraussetzen). Das Verdrahten in den Programmen ist Auftrag 15.
- Begründung: Nur Satzsperren werden von NFSv4 über Maschinen hinweg durchgesetzt; die geteilte Client-Sperre ist die einzige Lesart, die mehrere Benutzer zulässt.

### D71 Epochenregel 1.4 in Client und Server, K8
- Stelle: 2.4 „Verwerfen des Vorrats“ und „Vorlauf und Uhren“, K1, K8; D50, D57.
- Entscheidung (ersetzt die Epochenregel aus D50): Eine Mail der Epoche n wird nur angenommen, wenn (a) n nicht verworfen ist (`ErrDiscardedEpoch`), (b) `Beginn(n) ≤ Empfangszeit`, bei sofortiger Epoche `Beginn(n) − 5 min ≤ Empfangszeit` (`ImmediateLead`), und (c) keine nicht verworfene Epoche k > n mit `Beginn(k) ≤ Empfangszeit` existiert; dieselbe Regel gilt für `OpenPending` (über `created`), Verpackungen und `folders.gml` (nie aus verworfenen Epochen). `state.json` merkt sich je Epoche Beginn, Wirkung und Verwerfung (`epochs`, das alte `begins` wird übernommen); gemerkte Verwerfungen bleiben dauerhaft, auch wenn die Kette sie nicht mehr zeigt; für gebrochene Ketten gilt weiter D50 mit gemerkten Beginnzeiten. Der Server wählt unter den nicht verworfenen Epochen die höchste, die zur Empfangszeit verwendbar ist (sofortig ab `Beginn − 5 min`, geplant ab `Beginn`); eine sofortige Epoche, deren Beginn weiter in der Zukunft liegt, wird nicht verwendet und im Log (nur IDs) vermerkt. K8: `mailbox.rec` und die Kette werden erst nach Erwerb der Postfachsperre gelesen; der Commit prüft unter der Sperre erneut Kopfnummer und Kopf-Hash, die Kette, die Verwerfung und die Überholung und bricht sonst mit `451` ab (Spool verworfen, nichts im Postfach); jede Kopfänderung während `DATA` führt zur Wiederholung durch den Absender (strenge Lesart, kein Leck). Warnung des Clients bei veralteter oder verworfener Epoche: „nicht zustellbar, erneut anfordern“ (K8). `created` der `pending`-Dateien ist die Empfangszeit (Marker) bzw. die früheste Empfangszeit der Begriffsliste, damit die Epochenregel des Clients passt (3.1 schweigt dazu, SPEC-ISSUES). Mail-Dateien und Spool-Verzeichnisse erhalten die Rechte aus D70.
- Begründung: Funde der Verifikation von Auftrag 02 (zwei unabhängige Prüfer); vor den Mitgliederfunktionen der Welle 2 muss die Regel stehen. Restrisiko (Angreifer-Bericht): Ein Server ohne Gedächtnis und ohne Log verschlüsselt nach einem Zurücksetzen von `epoch.rec` und `mailbox.rec` wieder für die alte Epoche; das schließt erst die Logprüfung des Servers (Auftrag 15).

### D72 Entwurf des Transparenzlogs, der Zeugen und der Zeremonie (Auftrag 03)
- Stelle: 2.3, 2.7, 3.7 (letzter Absatz), 4 (`log/`, `checkpoints/`, `witnesses.rec`), 9.1, 9.2; K2 Regel 3 und 4; Q4, Q8, Q9, Q10. Verbindlich ist `internal/translog/doc.go`; hier die Kernentscheidungen.
- Entscheidung: (1) `log/` mit `lock`, `tree.rec` (Größe und Wurzelhash als Commit-Punkt), `entries/<index>.rec` (`gomail/v1/rec/log-entry`: Art, Subjekt, Laufnummer, unveränderte Kodierung des Datensatzes), Kacheln der Höhe 8 nach `tlog`, `heads/<größe>.sig`, `keys/` als abgeleiteter Doppelungsindex; Blatt-Hash `tlog.RecordHash`. (2) Kopf als `note` mit Text `origin\n<größe>\n<hash>\ntime <ms>\n`, Logsignatur mit dem Ingest-Schlüssel (Q4, Signer `gomail-log`; Domänentrennung zu 3.7 über das Nullbyte), Zeugen als normale `note`-Signer; Größen über `MaxTreeSize = 2^40` werden abgelehnt (Fund: `tlog` hängt ab 2^62). (3) Doppelungsschlüssel `user` (ID, Zahl der Generationen), `epoch` (Postfach, Nummer), `address` (Adresse, `valid_from`), `platform` (Dateiname); der erste gültige Eintrag gewinnt (K2 Regel 4), ungültige belegen keinen Schlüssel; Gültigkeitsregeln prüfen Signaturen aller Arten mit Schlüsseln aus dem Log und dem Pin, Epochen gegen die Vorgängerin über `store.Chain`; `ErrPrerequisite` (vorübergehend) gegenüber `ErrOrder` (nie loggbar). (4) Wer schreibt: der Erzeuger des Datensatzes unter `log/lock`; für erste Einträge (`user` Generation 1, `epoch` 1) erst lokale Kopie, dann Logeintrag, dann Datei im Datenverzeichnis (Wettlauf um die ID); nur der Server signiert Köpfe. (5) Zeugenquorum `2·min > n` ist Pflicht; geteilte Sicht ist genau dann ausgeschlossen, wenn weniger als `2·min − n` Zeugen kolludieren. (6) Zurückgehaltene eigene Einträge: `Pending{Index, Leaf, At}` im Client; `ErrWithheld`, wenn ein neuerer Kopf nach `At + HeadInterval` den Eintrag nicht deckt; `MaxPendingHeadAge = 23 h`, damit die Erkennung spätestens 24 h nach dem Anfügen erfolgt. (7) Pin: Felder 4 `origin`, 5 `witnesses`, 6 `min_witnesses`, 8 `identities` (alle Identitätsgenerationen), Feld 7 (Widerrufe) nur falls Q8; `MaxPinFile = 64 KiB`; der Server bekommt denselben Pin (`--pin`). (8) `witnesses.rec` ist unsignierte Arbeitskopie des Servers; verbindlich ist der Pin. (9) Ingest-Generation g gilt für Köpfe und Metadaten nur bis `valid_from` von `ingest-<g+1>.cert`; Log-Schlüssel zum Öffnen stammen aus `platform/`, geprüft gegen die Identitätsliste. (10) `CheckAddress`: jüngste Zuordnung mit `valid_from ≤ Empfangszeit` (Lesart, Lücke in Q9). (11) Zeremonie: `Init` mit Shamir, Probe-Rekonstruktion mit zufälligen Indizes, nichts wird vor der Probe geschrieben, Anteile nur zur Anzeige; `IngestRotate`, `Reshare`, `Succeed`, `Publish` (Ergänzung zu 9.2, weil die Zeremonie offline läuft); `--dev` nur mit `Config.AllowDevIdentity` aus Tests. (12) Zeuge: Pull über HTTP, acht Regeln, Zustand vor der Gegensignatur dauerhaft, Fork dauerhaft, `/cosign`-Körper mit genau zwei Zeilen.
- Begründung: Vier Prüfrunden (Spezifikation und Angreifer); jede Regel verweist in `doc.go` auf ihren Fund oder Abschnitt. Die sechs verbleibenden niedrigen Funde sind Pflichtpunkte der Aufträge 07 und 11 (Q10).

### D73 Annahme nach 1.4: Selbstprüfung ohne Schlüssel, Serversperre, Kettenspeicher (Auftrag 05)
- Stelle: 3.1, 3.7, 9.1, K8; D70, D71.
- Entscheidung: Nach dem Schreiben prüft `ingest` jede eigene Signatur erneut ohne Zugriff auf den privaten Schlüssel (`VerifyMeta(data, mailHash, gen, pub)`, `VerifyPending(data, gen, pub)`); schlägt das fehl, bricht die Zustellung mit `ErrSelfCheck` ab, das `smtpd.ErrTemporary` wrappt (451, nichts im Postfach). `ingest.New` hält die Rolle `locks/server` exklusiv (D70) und prüft über `Config.PeerCheck` nichts weiter (ein Server setzt keinen Client voraus). Der Kettenspeicher je Postfach ist an den Kopf aus `mailbox.rec`, den Hash jeder `epoch.rec` und den Hash der `user.rec` jedes Signierers gebunden; ändert sich einer, wird die Kette neu geprüft (22-fach schneller bei unveränderter Kette, keine Prüfung entfällt). `created` der `pending`-Dateien nach D71.
- Begründung: Fund der Verifikation von 02 (Signatur mit falschem Schlüssel bliebe unbemerkt bis zum Client); K8 verlangt die Kettenprüfung bei jedem `DATA`, ohne Speicher wäre sie der Engpass. Die Testsperre in den Programmen ist `TODO(task-15)`.

### D74 Zeuge nach 2.7 (Auftrag 08)
- Stelle: 2.7, 9.2; D72 (12).
- Entscheidung: `gomail-witness` holt Köpfe per HTTP (`serve --log --log-key --origin --key --state --interval`), prüft die acht Regeln aus `internal/translog/doc.go` (Origin, Logsignatur der gültigen Generation, Größe nie kleiner, gleiche Größe nur mit gleichem Hash, Konsistenzbeweis, Zeit nie rückwärts, nie zwei Köpfe gleicher Größe mit verschiedenem Hash, Zustand vor der Gegensignatur dauerhaft), sendet an `/cosign` genau zwei Zeilen (Kopftext-Hash und Signatur), hält sein Zustandsverzeichnis 0700 und gesperrt, schreibt einen Fork-Nachweis `.fork` dauerhaft und beendet sich mit Exit 3; Weiterleitungen werden abgelehnt, `Config.Timeout` begrenzt jede Verbindung; `keygen` erzeugt den `note`-Schlüssel 0600.
- Begründung: Spezifikation 2.7 und die Funde der Verifikation von 03 (Fork dauerhaft, Zustand vor der Signatur).

### D75 Mitglieder und Epochen im Client (Auftrag 06, 06c, 06d)
- Stelle: 2.2, 2.4, 2.5, 3.1, 4, K2, K3, Q1, Q5, Q6; D61, D63, D71.
- Entscheidung: (1) Schreibfolge einer Epoche: Verpackungen → `folders.gml` → `content.pub`/`meta.pub` → `epoch.rec` → Vorrat → `mailbox.rec` zuletzt; Reste ohne `epoch.rec` entfernt der nächste Lauf; keine Verpackung einer bestehenden Epoche wird je ersetzt. (2) Kopf der Kette für Leser ist `mailbox.rec`; gültige Epochen jenseits des Kopfs übernimmt nur `mutate` unter der Postfachsperre (`syncMailbox` rückt den Kopf auch für Nichtmitglieder vor, weil `mailbox.rec` unsigniert ist und nur vollständig geprüfte Epochen übernommen werden; die Spezifikation nennt keinen Schreiber, SPEC-ISSUES). (3) Eine `epoch.rec` bei Kopf+1, die nie gültig werden kann (nicht dekodierbar, auch größer als `MaxRecordFile`; anderes Postfach oder andere Nummer; `store.Chain.Add` gegenüber dem Kopf verletzt; Generation fehlt in lesbarer `user.rec`; Signatur falsch), ersetzt ein Benutzer-Mitglied des Kopfs unter der Sperre nur bei byte-gleicher Datei (`ClearInvalidEpoch`, dann `ReplaceInvalidEpoch` mit `epoch.rec` zuletzt); dasselbe für gestapelte Dateien hinter einer gerade geschriebenen Epoche. Was sich nicht als ungültig beweisen lässt (Lesefehler, nicht-reguläre Datei, unlesbare `user.rec`, Logfehler), bleibt liegen, und die Änderung scheitert nach drei Versuchen mit dieser Ursache (fail closed; `TODO(phase3-translog)`: mit Log entscheidet `ErrOrder`). Ein dekodierbarer Kandidat, der den Kopf als Vorgängerin nennt, ist ein Wettlauf nach K2 Regel 3 (Neuanlage auf der Siegerin, höchstens drei Versuche). (4) Zugriffsregel: Eine Verpackung gilt nur, wenn sie für den eigenen Schlüssel bestimmt ist, ihr Kopf Postfach, Epoche und Datei-ID des Orts nennt, ein Benutzer-Mitglied (Art 1) der Epoche sie mit seiner gültigen (aktuellen) Generation signiert hat und die Schlüssel zur `epoch.rec` passen; Art 1 ist nur Voraussetzung für Anlegen von Epochen und `folders.gml`. (5) `Share(mbx, user, ShareOptions{From, To, Delegate}) ([]uint32, error)`: verpackt begonnene, nicht verworfene Epochen des Bereichs, in denen der Teilende Benutzer-Mitglied ist, für die aktuelle Generation des Ziels; `To` nur vor der laufenden Epoche (`ErrRange`); ohne `To` zusätzlich eine sofortige Epoche `member-added` (Art 1 oder 3); konnten angeforderte, nicht verworfene Epochen nicht verpackt werden, wird die Freigabe abgeschlossen und `ErrPartial` (nur Nummern) zurückgegeben; `SetRecovery` meldet Übersprungenes noch nicht (→ 06b). (6) `Revoke` löscht die Verpackungen des Entzogenen für alle nicht verworfenen Epochen (strenger als 2.5 „neue Epochen“, SPEC-ISSUES klarstellend), legt `member-removed` bzw. `delegation-ended` sofort an und verweigert den Selbstentzug des letzten Benutzer-Mitglieds (`ErrSelfRevoke`). (7) Wiederherstellungsempfänger (Q1, `TODO(Q1)`): Art 2, `recovery.wrap` mit Empfängertyp 4 und Generation 1 aus `store.RecoveryPub` (`mailboxes/<id>/recovery/<recovery-id>.pub`, unsigniert, per Fingerabdruck je Gerät in `state.json` bestätigt); `RecoverRead` nur lesend (`ErrReadOnly`). (8) `folders.gml` wird für die laufende und alle künftigen nicht verworfenen Epochen neu geschrieben, nur durch ein Benutzer-Mitglied aller; Versionszähler je Epoche in `state.json` gegen Rückspielen; der Leser nimmt die neueste zugängliche Epoche und fällt nicht zurück (eine untergeschobene, nicht öffnende Verpackung lässt `List` fail closed scheitern; mit Schreibzugriff ist Vorenthalten nach 2.7 ohnehin möglich, SPEC-ISSUES). (9) Epoche 1 eines neuen Postfachs beginnt sofort (ohne Vorlauf; es gibt keine Vorgängerin, und der Server nähme sonst fünf Minuten nichts an), die Ausweich-Epoche nach einem Server-Vermerk ist `regular` mit Vorlauf (D63/Q5).
- Begründung: Spezifikation 2.4/2.5 und die Funde von drei Prüfrunden (Spezifikation und Angreifer, 21 Mutationen, Abdeckung `client` 89,6 %). Zurückgestellt mit Begründung: `wrap-accept`/Neuverpacken nach `device lost` (2.2 Regel 4/5) ist Auftrag 06b; der Test für „nicht bewiesen ungültige Epoche bleibt“ und `ErrPartial` für `SetRecovery` gehen in 06b; `CheckAddress`-Fehlertexte dürfen die Adresse nicht enthalten (Auftrag 14).

### D76 Audit-Index des Clients liegt in der Vertrauenszone des Client-Verzeichnisses
- Stelle: 2.7, 8, `internal/translog/doc.go` „Audit“; D57; Fund „hoch“ des Angreifer-Verifizierers von 07b (manipulierter Audit-Index mit passendem Anker, Größe und Wurzel hebt einen ungültigen Logeintrag auf „gültig“, `CheckEpoch` liefert `nil`).
- Entscheidung: Der Fund wird nicht als Sicherheitsfund gewertet, sondern als Präzisierung der Dokumentation (Auftrag 07c Punkt 5). Begründung: Die Angreiferrolle „Schreibzugriff auf das Client-Verzeichnis außer `state.json`“ stammte aus dem Prüfauftrag des Orchestrators, nicht aus der Spezifikation; `state.json` ist unsigniert (D57), wer den Index schreiben kann, kann ebenso den verifizierten Kopf `Verifier.Last`, die Pending-Liste und die Pin-Bestätigungen in `state.json` schreiben. Der Index (`Options.IndexFile`, 0600, außerhalb des Datenverzeichnisses) ist deshalb Teil derselben Vertrauenszone; seine Strukturprüfungen und der Nachweis von Inklusion, Blatt und Schlüssel je Treffer sind Schutz gegen Beschädigung und gegen Verwechslung mit einem anderen Log, nicht gegen einen Angreifer im Client-Verzeichnis. Ein Nachrechnen des Gültigkeitsurteils bei jedem Laden würde den Index überflüssig machen (vollständiges Re-Audit); ein Integritätsschutz über `state.json` brächte nichts, weil beide Dateien gleich erreichbar sind. Kein Haltepunkt: keine Prüfregel des Clients ändert sich, das Bedrohungsmodell aus 8 und D57 bleibt.
- Folge für AUDIT.md: Client-Verzeichnis (Schlüsselspeicher, `state.json`, Audit-Index) als eine Vertrauenszone nennen.

### D77 Messumgebung (Auftrag 12, 12b, 12c)
- Stelle: 1 Punkt 5, 5.1 bis 5.3, 11; M1-Kriterium D.
- Entscheidung: `internal/bench` ist ein reines Testpaket (kein Programm importiert es, `TestNotLinked`); Testmails und Korpus kommen aus `math/rand/v2` (ChaCha8) mit festem Seed, nur für Testdaten (Schlüssel, Nonces und IDs weiter aus `crypto/rand`). Drei Betriebsarten für den Empfang: `enc` (Ingest vollständig), `proto` (dasselbe Datei- und fsync-Protokoll einschließlich Worker, Begriffslisten je 100 Mails, Markerlöschung und Platzprüfung, ohne Kryptografie; Systemaufrufe im Messfenster mit `enc` identisch, 0 % Abweichung), `plain` (Minimal-Senke mit einem fsync); Verschlüsselungskosten = `enc − proto` (enthält auch Signaturen, Selbstprüfung, Kopfzeilen, Adressauflösung, Kettenprüfung über den Cache, Termzerlegung), Protokollkosten = `proto − plain`. Speichermessung je Iteration in einem Kindprozess (keine Verschleppung von `Sys`/VmRSS zwischen `-count`-Läufen), Grund- und Ruhewert gleich vorbereitet. Gelockerte Grenzen nur im Testpaket: `MinFree` 1 % statt 10 %, `MaxConns` 64 statt 20, `MaxConnsPerIP` 64 statt 5, kein Mail-Limit je IP; Uhr eingefroren, Logausgabe verworfen. Die Tabelle nennt Hardware, Befehl und alle Lockerungen.
- Begründung: Drei Prüfrunden; zurückgestellt nach 12d (Indexmessungen nach Auftrag 09) mit Begründung: `MaxMailsPerIP` in `TestBenchScriptLimits`; VmRSS-Verschleppung nur über `Sys` erkennbar (ehrlicher Kommentar oder engere Schwelle); eingefrorene Uhr und verworfenes Log im Tabellenkopf; Kettenprüfung über Cache genauer beschreiben. Auftrag 17 misst auf ruhiger Maschine mit `scripts/bench.sh -count 5`.

### D78 Umsetzung des Transparenzlogs (Auftrag 07, 07b, 07c, 07d)
- Stelle: 2.3, 2.7, 3.7, 4, 9.1, 10.1; K2; D72; verbindlich bleibt `internal/translog/doc.go`.
- Entscheidung (Ergänzungen zu D72 aus drei Prüfrunden): (1) `sync` prüft die Kacheln gegen `tree.rec` vor jeder Reservierung und liest Blatthashes kachelweise (höchstens 256 je Lesevorgang); Größen aus `tree.rec` bestimmen nie eine Reservierung (ein gefälschter Baum mit `Size = MaxTreeSize` und passender Spitzen-Kachel liefert `ErrConsistency`, Test im Kindprozess unter `RLIMIT_AS`). (2) `Refresh` übernimmt erst, wenn alles gelungen ist: Audit auf einem Klon → `CheckHead` auf einer Kopie des Verifiers → Prüfung aller vom Kopf gedeckten Pending-Einträge gegen ihr Blatt → `saveIndex` → Übernahme von `Last`, `LogKeys`, `ref`, `Pending`; bei jedem Fehler bleibt alles alt. Ein ersetzter eigener Eintrag setzt einen klebrigen Fehler (`ownErr`, nur aus einem Kopf, der `CheckHead` bestanden hat); `CheckFresh` und `Refresh` liefern dann `ErrConsistency`, bis eine Pending-Prüfung gegen einen verifizierten Baum mindestens der Größe `ownSize` besteht (der Aufrufer entfernt den Eintrag und hängt ihn neu an). `Fresh` meldet einen gedeckten, noch in `Pending` stehenden Eintrag als `ErrConsistency`. (3) Fehlertaxonomie: jeder Fehler wrappt genau einen dokumentierten `Err*`; neu `ErrIO` für die Indexdatei (auch Lage im Datenverzeichnis, über Symlinks aufgelöst). (4) Audit-Index: `find`/`included` prüfen Inklusion, Blatt und Schlüssel gegen den Referenzkopf; `checkKeys` beim Laden; Neuaufbau bis zum Erfolg wiederholt. Der Index liegt in der Vertrauenszone des Client-Verzeichnisses (D76). (5) Zeugen-Verifier stammen aus `NewWitnessVerifier`; `checkConfig` lehnt denselben Schlüssel unter zwei Namen ab; das Quorum zählt Schlüssel. (6) `Options.Now` hat Vorrang und wird in `Verifier.Now` kopiert. (7) `Entry` meldet eine fehlende Datei unterhalb der Referenzgröße als `ErrConsistency`; `newestHeadSize` bestimmt nur das Maximum; der Laufzeittest prüft lineare Skalierung statt einer Wanduhr-Grenze. (8) `store.ReplaceEpoch` nimmt die Postfachsperre selbst und ersetzt nur bei byte-gleichem `old` und `unloggable(old)` (Funktion aus Auftrag 14: `Append` → `errors.Is(err, ErrOrder)`).
- Begründung: Funde der Verifizierer (Spezifikation 4+2+3, Angreifer 6+1+1, keine offenen Funde über niedrig). Zurückgestellt nach Auftrag 11 mit Begründung (gleicher Code, nächster Auftrag): Übernahme eines bestandenen Kopfs bei fortbestehendem `ownErr` festlegen; einmaliges `ErrConsistency` des ersten Client-`Append` nach einem Rollback durch stillen Neuaufbau des Caches ersetzen; `doc.go` „Withheld entries“ präzisieren; Schleifengrenze in `candidates`; Kommentar in `client.go`.
