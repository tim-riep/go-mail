# Entscheidungen in Phase 0 und 0.1

Die Spezifikation liegt in `docs/PLAN.md` (Version 1.0). Dieses Dokument hält jede Stelle fest, an der sie mehrdeutig ist oder etwas offen lässt, und welche Entscheidung die Umsetzung getroffen hat. Grundsatz: im Zweifel die konservativere Lesart, keine erfundenen Anforderungen. Widersprüche und Lücken, die eine Änderung der Spezifikation nahelegen, stehen zusätzlich in `docs/SPEC-ISSUES.md`.

Phase 0.1 setzt die Änderungen der Version 1.1 um, soweit der Auftrag sie benennt (Elementrahmen, Empfängertyp 4, höchstens vier Empfänger, NFC über `golang.org/x/text`). Der Text der Version 1.1 (`docs/spec.md`) lag bei der Umsetzung nicht vor; Einträge, die davon abhängen, sind als Annahme gekennzeichnet (D42 bis D44) und gegen den Text zu prüfen, sobald er im Repository liegt. Aufgehobene Entscheidungen bleiben als Verlauf stehen und sind mit "Aufgehoben in Phase 0.1" und dem Commit markiert.

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
- Frage: Der Auftrag nennt die Typbytes (`0x01` Block, `0x02` letzter Block, `0x03` Trailer) und die zulässige Folge `0x01*, 0x02, 0x03?`, nicht aber die Bytefolge innerhalb eines Elements; `docs/spec.md` lag nicht vor.
- Entscheidung: Ein Element ist `Typbyte (1) || Länge uint32 Big Endian (4) || Inhalt`. Der Parser nimmt genau die Folge `ElemBlock* ElemLastBlock ElemTrailer?` und danach das Dateiende an. Jeder `ElemBlock` ist ein voller Block (`chunk_size + 16`), der `ElemLastBlock` ist 16 bis `chunk_size + 16` Byte groß und nur als einziger Block leer. Abgelehnt werden: fehlender `0x02` (Dateiende oder Trailer nach `0x01`-Blöcken: `ErrTruncated` bzw. `ErrElement`), zwei `0x02`, `0x01` nach `0x02`, zwei Trailer, jedes andere Typbyte (`ErrElementType`), jedes Byte nach dem Trailer (`ErrElement`, vor dem Lesen des Längenfelds). Eine unsignierte Datei endet mit dem `0x02`-Element; es gibt kein Trailer-Längenfeld 0 mehr. Die Übereinstimmung von Typbyte und Letzter-Block-Flag im Nonce prüft die Authentifizierung: Der Entschlüsseler setzt das Flag aus dem Typbyte, ein Block mit dem jeweils anderen Flag authentifiziert nicht (`TestElementTypeMatchesNonceFlag`). `MaxFileSize` enthält 5 Byte Rahmen je Element.
- Begründung: Typbyte vor der Länge entspricht dem Aufbau der übrigen Teile (Kennung, dann Länge). Die Folge ist ohne Schlüssel und streamend prüfbar; jede Abweichung wird vor jeder Entschlüsselung abgelehnt. Annahme, gegen 3.1 der Version 1.1 zu prüfen.

### D43 Empfängertyp 4 und Höchstzahl 4
- Stelle: 3.1 (Version 1.1); Auftrag Phase 0.1 Punkt 2.
- Entscheidung: `RecipientRecovery = 4`; Typen 1 bis 4 gültig, höchstens vier Einträge (siehe D32). Für Typ 4 gelten dieselben Regeln wie für die anderen (HPKE-`info` mit Typ, ID, Generation; eindeutiges Tripel). Ob Version 1.1 dem Wiederherstellungsempfänger weitere Regeln gibt (etwa Pflicht beim Schreiben), ist aus dem Auftrag nicht ersichtlich und gegen 3.1 zu prüfen.
- Begründung: Vorgabe des Auftrags.

### D44 Testvektoren nach dem Formatwechsel
- Stelle: Auftrag Phase 0.1, "Vektoren, die sich nicht ändern dürften, müssen unverändert bleiben".
- Entscheidung: Die zehn `.gml`-Dateien sind neu erzeugt (Rahmen geändert, Signaturen decken den neuen Rahmen ab). Alle in `vectors.json` festgehaltenen Werte sind byte-identisch geblieben: Kopfkodierung, Nonce-Präfix, SHA-256 der Blockchiffrate, SHA-256 des Klartexts; das wurde vor dem Commit mit der alten Datei verglichen. Die Dateien aus Phase 0 liegen unter `internal/envelope/testdata/phase0/` und laufen als Ablehnungsfälle (`TestPhase0FilesRejected`) und als Fuzz-Saat weiter.
- Begründung: Kopf, Schlüsselableitung, Nonces und Block-AAD sind unverändert; nur der Rahmen und damit die Signatur ändern sich. Ein Unterschied in den festgehaltenen Werten hätte auf einen Fehler in der Umsetzung gedeutet.

### D45 Nicht umgesetzt: Argon2-Bereiche und Datensatztypen aus 2.2 und 2.3
- Stelle: Auftrag Phase 0.1 Punkt 4 (S07, S08).
- Entscheidung: Nicht geändert. Die Bereiche für Argon2id in 2.2 und die Datensatztypen der Plattformzertifikate und Nachfolgen in 2.3 der Version 1.1 stehen nur im Text der Spezifikation, der nicht vorlag. `keys` prüft weiterhin die Grenzen aus D22 (64 bis 256 MiB, 3 bis 10 Durchläufe, 1 bis 16 Threads, Untergrenzen vorhanden) und verwendet die Formate aus D20.
- Begründung: Raten würde die Vorgabe "keine erfundenen Anforderungen" verletzen. Sobald `docs/spec.md` vorliegt, sind D22 und D20 gegen 2.2 und 2.3 abzugleichen.

