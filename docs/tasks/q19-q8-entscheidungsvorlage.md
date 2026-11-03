# Entscheidungsvorlage: Q19 und Q8 – Widerruf kompromittierter Plattformgenerationen

Stand 03.11.2026, Branch `claude/quirky-keller-hjsl5i`. Für den Auftraggeber.

**Worum es geht.** Der Pflichttest S9 aus PLAN 10.1 („Signatur einer kompromittierten Ingest- oder Identitätsgeneration“) ist nur teilweise erfüllt. `TestVerifyCompromisedIdentityStillIssues` (`internal/ceremony/succession15f_test.go`) wird übersprungen, für den Ingest-Teil fehlt der Test. Damit bleibt M1-Kriterium E in diesem Punkt offen (HANDOFF, `docs/tasks/20-mandatory-tests.md` Zeile S9 und Folgeauftrag F-2). Jede Lösung ändert ein Dateiformat oder eine Prüfregel im Client. Nach K7 (PHASE2-KLAERUNGEN) müssen wir deshalb anhalten, bis Sie entscheiden.

---

## 1. Was ist offen?

**Q19: Kompromittierte Plattformidentität.** PLAN 2.3 sieht für diesen Fall vor, dass eine neue Identitätsgeneration aus dem Root abgeleitet und per Client-Update verteilt wird. Ab dem Update lehnen Clients „jede Signatur der kompromittierten Generation“ ab. Der neue Pin muss die alte Generation aber weiter führen (Feld 8). Sonst lassen sich die alten Admin- und Ingest-Zertifikate nicht mehr prüfen, und mit ihnen die gesamte Historie: alle Adresszuordnungen und Ingest-Signaturen alter Mails.

Nichts kennzeichnet die alte Generation als „ab hier ungültig“: kein Feld im Pin, keines in der Nachfolge und keine Regel in `translog`. Wer den alten Schlüssel hat, stellt deshalb weiter `ingest-<n>.cert` und `admin-<n>.cert` aus. `publish`, das Operator-Log und Clients mit dem neuen Pin nehmen sie an. Damit übernimmt er Ingest (Metadaten, Log-Köpfe) und Admin (Adresszuordnungen). Die Prüfung hat das reproduziert, als Fund hoch und Haltepunkt 2. Deshalb ist `succeed --compromised` gesperrt (D85 (6), AUDIT R17).

Offen ist:
- wo die Kennzeichnung steht (im Pin oder im Log),
- wo die Grenze liegt (an einer Logposition oder an einem Zeitpunkt),
- was davor gültig bleibt.

Nebenfrage: Wann ist statt einer Nachfolge ein neuer `init` mit neuem Origin nötig, weil der Root selbst kompromittiert ist?

**Q8: Kompromittierte Ingest- oder Admin-Generation.** Es gibt überhaupt keinen Widerruf. Gebaut ist nur die strengste Lesart: Ingest-Generation g gilt bis `valid_from` von `ingest-<g+1>.cert`. Ein gestohlener alter Ingest-Schlüssel kann aber unbegrenzt Metadaten mit einer zurückdatierten Empfangszeit signieren, die dann gültig bleiben. Eine Admin-Generation endet nie, auch nicht nach einem Wechsel, und eine Admin-Rotation gibt es nicht (9.2).

Offen sind vier Punkte:
- (a) der Träger des Widerrufs, vorgeschlagen ist Pin-Feld 7,
- (b) welche Historie gültig bleibt,
- (c) das Ende der Admin-Gültigkeit,
- (d) der Befehl `admin-rotate`.

**Kopplung.** Nach einer Kompromittierung der Identität müssen Admin und Ingest unter der neuen Identität neu ausgestellt werden. Dafür braucht es die Admin-Rotation aus Q8 (d). Der Q19-Vorschlag verweist den Ingest- und Admin-Widerruf ausdrücklich an Q8. Am sinnvollsten werden deshalb beide Fragen zusammen entschieden.

---

## 2. Optionen

**K7-Haltepunkte:** F = Dateiformat/Datensatz, D = Signaturdomäne, P = Prüfregel im Client. Jede Option berührt mindestens eine davon. Die Aufwandsangaben sind Schätzungen. Jede Option ist sicherheitskritisch, Verifikation also mit 2–3 Prüfrunden.

### Q19 (Identität)

| | **A: Pin-Feld 7** (Q8-Vorschlag, Rolle „Identität“) | **B: Widerrufseintrag im Log** (Q19-Vorschlag) | **C: kein Widerruf, neuer `init`** |
|---|---|---|---|
| Was sich ändert | Der neue Pin aus `succeed --compromised` listet `(Rolle, Generation, revoked_at_size, revoked_at_time)`. Zertifikate der Generation g, die ab Logindex `revoked_at_size` geloggt sind, sind ungültig. Ältere bleiben gültig (wie 2.2 Regel 4). | Neuer Datensatz `revocation-<g>.rec`, signiert von der neuen Identität und als `KindPlatform` geloggt. Alles, was g nach diesem Eintrag signiert, ist ungültig. | Eine kompromittierte Identität bedeutet: neue Zeremonie, neuer Origin, neues Log und neue Pins. `succeed --compromised` entfällt. 10.1 wird angepasst: Der Test prüft, dass ein Pin mit neuem Origin nichts der alten Identität annimmt. |
| Haltepunkte | F (Pin-Schema `platform-pin` Feld 7, neues Element `platform-revoked`), P | F (neuer signierter Datensatz), D (neuer Kurzname in 3.7), P (neue Logregel) | Spezifikationsänderung 2.3 und 10.1, P nur geringfügig |
| Aufwand | etwa 7–8 Pakete: `store`, `translog`, `client`, `ceremony`, `cmd/gomail-ceremony`, `cmd/gomail-server`, `ingest`, dazu Testvektoren. Neue Tests etwa 15–25. Vorarbeit vorhanden: `translog.Revoked`, `MaxRevoked`, `Verifier.IsRevoked`, Form in `doc.go` und `records.go`. | etwa 9–10 Pakete: wie A, zusätzlich `rec`/`keys` (Domäne, Vektoren), Logart und Doppelungsschlüssel, `publish`-Pfad. Für Q8 ist trotzdem ein zweiter Mechanismus nötig, oder B wird auf alle Rollen erweitert. | 2–3 Pakete: `ceremony`, `cmd/gomail-ceremony`, RUNBOOK, Test umschreiben. Ein Migrationswerkzeug für Benutzer und Postfächer ins neue Log fehlt dabei. |
| Sicherheit | Schließt den Fund. Die Grenze kommt aus einem zeugenbestätigten Kopf vor der Zeremonie und ist damit mindestens so früh wie bei B. Einträge, die der Dieb vor der Grenze geloggt hat, bleiben gültig. Abhilfe: Neuausstellung unter g+1 (siehe 4.) und gezielter Widerruf erkannter fremder Generationen in Feld 7. | Schließt den Fund ebenso. Die Grenze liegt erst beim `publish`, also nach der Zeremonie. Clients mit altem Pin können den Eintrag nicht prüfen (sie kennen g+1 nicht), also kein Vorteil gegenüber A. | Am saubersten. Weil der Identitätsschlüssel nur in der Zeremonie existiert, heißt seine Kompromittierung praktisch fast immer auch Root-Kompromittierung. Betrieblich teuer: faktisch eine neue Plattform. |
| S9 / E | Test ohne Skip mit `Compromised: true` grün, dazu der Client-Test aus F-2. E erfüllbar. | wie A | Nur wenn Sie 10.1 ändern. Sonst bleibt E offen. |

### Q8 (Ingest und Admin)

| | **A: Pin-Feld 7, wie in Q8 vorgeschlagen** | **B: Widerrufseintrag im Log für alle Rollen** | **C: nur Ablösung, kein Widerruf** |
|---|---|---|---|
| Was sich ändert | Wie Q19-A, Rollen Admin und Ingest. Q8 (b): Logeinträge vor `revoked_at_size` und Metadaten mit einer Empfangszeit vor `revoked_at_time` bleiben gültig. Q8 (c): Admin-Generation g gilt nur bis `valid_from` von `admin-<g+1>.cert`. Q8 (d): `admin-rotate`. | Wie Q19-B, signiert von der aktuellen Identität. Dazu (c) und (d) wie in A. | Nur (c) und (d). Ingest bleibt wie gebaut. Ein „kompromittiert“ gibt es nicht, nur „abgelöst“. |
| Haltepunkte | F, P | F, D, P | P (Ende der Admin-Gültigkeit), dazu eine Lesart von 10.1 |
| Aufwand | im Q19-A-Aufwand enthalten, zusätzlich `admin-rotate` (Zeremonie, PTY-Tests, RUNBOOK) | im Q19-B-Aufwand enthalten, zusätzlich `admin-rotate` | 3–4 Pakete (`translog`, `client`, `ceremony`, `cmd/gomail-ceremony`), etwa 8–10 Tests |
| Sicherheit | Ein Dieb kann nach dem Widerruf nichts Neues mehr signieren. Rest: Metadaten, die mit dem gestohlenen Schlüssel auf eine Zeit vor `revoked_at_time` zurückdatiert werden, bleiben gültig. Das ist unvermeidbar, weil Metadaten nicht geloggt werden. | wie A | Bekannte Lücke bleibt: Ein gestohlener Ingest-Schlüssel signiert unbegrenzt zurückdatierte Metadaten, solange die Empfangszeit vor dem Wechsel liegt. |
| S9 / E | F-2-Ingest-Test (Widerruf von Generation 1, zurückdatierte Mail wird abgelehnt) grün. E erfüllbar. | wie A | Nur wenn Sie „abgelöst“ ausdrücklich als Erfüllung von 10.1 annehmen. |

---

## 3. Empfehlung: Option A für beide Fragen, ein einziger Mechanismus

1. **Er passt zur Spezifikation.** 2.3 verteilt den Kompromissfall ohnehin per Client-Update. Ohne gültige Nachfolge braucht es dafür einen neuen Pin. Feld 7 ist also kein zusätzlicher Verteilweg.
2. **Kleinste Formatänderung.** Es gibt keinen neuen signierten Datensatz und keine neue Signaturdomäne. Der Pin ist unsigniert und wird außerhalb der Plattform verteilt.
3. **Ein Mechanismus für drei Rollen.** Er schließt Q8 und Q19 zusammen, ebenso S24, S25, S28 (Q8-Anteil) und S76. Code, Doku und Größengrenze sind seit Entwurf 03 vorbereitet.
4. **Die Historie bleibt prüfbar,** nach derselben Regel wie für Benutzer (2.2 Regel 4).
5. **Die Grenze liegt früher als bei B.** Sie stammt aus einem zeugenbestätigten Kopf, und alle Clients mit demselben Pin urteilen gleich.

Ergänzend empfehlen wir drei Festlegungen in 2.3:
- **Neuausstellung ist Pflicht.** Nach `succeed --compromised` werden Ingest und Admin unter der neuen Identität neu ausgestellt. Durch die Ablösungsregel enden damit auch fremde Zertifikate, die der Dieb vor der Grenze geloggt hat.
- **Nebenfrage aus Q19:** Ist der Root selbst oder sind k Anteile in falschen Händen, ist eine Nachfolge wertlos. Dann gilt Option C (neuer `init`, neuer Origin).
- **Feld 7 bekommt `revoked_at_time`** als vierten Bestandteil. Die Kopfzeit zu einer Größe ist nicht eindeutig (`TODO(ask)` in `doc.go`).

---

## 4. Was gebaut würde (Option A)

- **`store`:** `PlatformPinSchema` erhält Feld 7 (optional) als Liste von `gomail/v1/rec/platform-revoked` mit 1 Rolle u8, 2 Generation u32, 3 `revoked_at_size` i64 und 4 `revoked_at_time` i64. Höchstens `MaxRevoked` Elemente, der Pin bleibt unter 64 KiB. Dazu Testvektoren und `internal/rec/allschemas_test.go` (K1).
- **`translog`:**
  - `Verifier.Revoked` bzw. `Options.Revoked` aus dem Pin füllen.
  - Gültigkeitsregel `platform`: Ein Zertifikat oder eine Nachfolge, die eine widerrufene Identitäts- oder Rollengeneration ausstellt oder betrifft, ist ab Index `revoked_at_size` ungültig (`ErrOrder`). Das gilt in `Append`, im Audit und in `SignHead`.
  - Adresszuordnungen einer widerrufenen Admin-Generation ab `revoked_at_size` sind ungültig. Ebenso Köpfe einer widerrufenen Ingest-Generation ab `revoked_at_time`.
  - Q8 (c): Ablösungsregel für Admin wie für Ingest.
  - `doc.go` sowie die `TODO(ask)` in `verifier.go` und `translog.go` auflösen.
- **`client`:**
  - `ingestKeyFor`: Empfangszeit < `revoked_at_time` für widerrufene Ingest-Generationen.
  - `CheckAddress` mit dem Ende der Admin-Gültigkeit.
  - Feste Fehlerursache „Generation widerrufen“ in `list` und `read`.
- **`ceremony` / `cmd/gomail-ceremony`:**
  - Sperre `ErrCompromised` aufheben. `succeed --compromised --revoke-at-size N --revoke-at-time T` schreibt Feld 7 für die Identität g. Größe und Zeit stammen aus einem zeugenbestätigten Kopf, den der Betreiber vorher abliest.
  - Neuer Befehl `revoke` (neuer Pin gleicher Identitätsgeneration mit Feld 7 für Ingest oder Admin).
  - Neuer Befehl `admin-rotate`.
  - `publish` nimmt eine Generation aus der Identitätsliste des Pins ohne `identity-<g>.succ` an. Heute verweigert es das nach der Regel aus 15g.
  - Feld 7 wird in Folge-Pins übernommen.
- **`cmd/gomail-server` / `ingest`:** Der Server liest Feld 7 aus `--pin` und startet nicht mit einer widerrufenen eigenen Ingest-Generation (Exit 2).
- **Tests:**
  - `t.Skip` in `TestVerifyCompromisedIdentityStillIssues` entfernen.
  - Beide F-2-Tests im Client.
  - Grenztests in `translog` (Index N−1 gültig, N ungültig; Kopf nach `revoked_at_time`).
  - Pin-Kodierung mit Größengrenze.
  - Für `admin-rotate`, `revoke` und `succeed --compromised`: `TestSucceedCompromised`, `TestUsage` und PTY-Tests anpassen.
  - `TestRunbook`, Zeile 7.3.
- **Doku:**
  - PLAN 2.3 und 9.2.
  - RUNBOOK 7.3, neu mit Ablauf: Kopf ablesen, Zeremonie, Neuausstellung, Pin verteilen, Server neu starten.
  - SPEC-ISSUES S24, S25, S28 und S76 schließen; AUDIT R17 und R18; HANDOFF S9.

**Was Ihre Antwort freigibt:**
- Q19 (Haltepunkt 1 und 2) einschließlich Nachtrag (a)–(d),
- Q8 (a)–(d) mit Nachtrag zur Admin-Gültigkeit,
- K7-Haltepunkte „Dateiformat“ (Pin-Feld 7) und „Prüfregel im Client“ (Widerrufs- und Ablösungsregeln),
- Q10 Punkt 1 (`MaxRevoked`),
- die Markierungen `TODO(Q19)` in `ceremony/api.go`, `ceremony/init.go` und `cmd/gomail-ceremony/main.go`,
- die Markierungen `TODO(ask)` zu Q8 in `translog` und `store/records.go`.

Danach ist S9 vollständig baubar (F-2), und Kriterium E hängt in diesem Punkt nur noch an der Umsetzung. Q9 (Rückdatierung von Adresszuordnungen) bleibt davon unberührt.

**Bitte beantworten Sie:**
1. Option A für beide Fragen (ja/nein)?
2. Feld 7 mit `revoked_at_time` (ja/nein)?
3. Admin-Ablösungsregel und `admin-rotate` (ja/nein)?
4. Ist ein kompromittierter Root ein Fall für neuen `init` und neuen Origin (ja/nein)?
