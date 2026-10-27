# Auftrag 09c: Nacharbeit 09b (Funde der Spezifikations- und Angreifer-Prüfung)

Welle 4, sicherheitskritisch. Das ist die erste Nacharbeitsrunde von 09b. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md`.
Worktree: `/home/user/go-mail/.claude/worktrees/agent-a4b5ac897ba87ee5f`, Branch `worktree-agent-a4b5ac897ba87ee5f`, Stand e5b9dc8. Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i` ausführen; seitdem sind 13e, 18, 19 und 19b dazugekommen.
Auftrag 09b und sein Nachtrag bleiben gültig. Ändern darfst du dieselben Pfade wie in 09b.
Angriffstests des Prüfers liegen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify09b-attack/kept/`: `attack09b_growth_test.go`, `attack09b_devicelost_test.go`, `attack09b_misc_test.go`, `attack09b_tree_test.go`. Die Mutationsprotokolle der Spezifikationsprüfung liegen unter `.../verify09b-spec/mut/`.

## Fund hoch: `state.json` wächst ohne Grenze durch Segmentkopien

**Ablauf.** Ein Angreifer mit Schreibzugriff auf das Datenverzeichnis kopiert ein gültiges Segment unter immer neue Laufnummern. Einen Schlüssel braucht er dafür nicht. Jede Kopie bekommt in `readSegment` einen eigenen Prüfvermerk `index/<n>/<dev>-<seq>`.
- Vermerke werden nie gelöscht (D84 (2)).
- Ab 64 MiB öffnet `client.Open` nicht mehr. Dann scheitern auch `DeviceLost` und `Restore`.

**Umsetzen.**
- Ein Angreifer ohne Schlüssel darf `state.json` nicht vergrößern können. Deshalb bindet ein Segment-Vermerk an den Inhalt und nicht an die Laufnummer: Epoche, Gerät (`file_id`) und SHA-256 der Datei.
- Byte-gleiche Kopien unter anderer Laufnummer teilen sich einen Vermerk und erzeugen keinen neuen. Die Q11-Warnung bleibt.
- Die Übernahme einer Datei mit Vermerk verlangt weiter Hash, Unterzeichner und Generation.
- D84 (2) bleibt: Kein Pfad verkleinert `Checked`. Vermerke werden nicht gelöscht.
- Das Wachstum durch legitime Schreibvorgänge ist bekannt und niedrig. Miss es und nenne im Bericht die Zahl in Byte je Mail und je Zusammenfassung.
- `readSegments` hält alle Segmente einer Epoche im Speicher. Ihre Zahl ist nicht begrenzt, jedes kann bis zu 4 MiB groß sein.
  - Begrenze die Zahl der Segmente, die ein Lauf je Postfach und Epoche liest. Vorschlag: 4096 Segmente oder 256 MiB.
  - Bei Überschreitung gibt es eine Warnung mit fester Ursache, und Suche und Indexierung melden `ErrPartial` bzw. die Warnung. Sie dürfen nicht stillschweigend unvollständig sein.
  - Begründe den gewählten Wert.
- **Tests:**
  - Vorlage `TestAttack09bStateGrowthSegmentCopies`: 3 × 1000 Kopien. Danach darf `state.json` um höchstens einen festen Betrag wachsen, der von der Zahl der Kopien unabhängig ist.
  - Ein Test für die Grenze in `readSegments`.

## Fund mittel: Schritt 2 von `device lost` lässt sich über das Dateisystem blockieren

**Ablauf.** `checkOwnFiles` gibt Fehler von `ListIndexSegments`, `readSegments`, `mailFolders`, `ListFolders` und `ListMails` zurück. `DeviceLost` bricht dann vor Schritt 3 ab. Eine normale Datei an der Stelle von `mailboxes/<mbx>/index/<n>` oder `mailboxes/<mbx>/mail` (ENOTDIR) hält den Befehl so dauerhaft fest, und g wird nie widerrufen. Das widerspricht D84 (b).

**Umsetzen.**
- Fehler in Schritt 2 erzeugen je Postfach eine Warnung mit fester Ursache und setzen die Vormerkung `Reissue`. Der Widerruf (Schritt 3) läuft trotzdem.
- Dateien, die in Schritt 2 nicht geprüft wurden, haben keinen Vermerk und werden nicht übernommen. Das ist fail closed.
- Der Befehl endet mit `ErrPartial`.
- Ebenso für den vorbestehenden Weg: `members/<me>.accept` ist ein Verzeichnis, und `writeAccept` scheitert mit „file exists“. Auch das hält `DeviceLost` nicht mehr vor dem Widerruf fest; es wird gewarnt und vorgemerkt. Der Prüfer hat das mit `TestAttack09bDeviceLostBlockedByAccept` gezeigt.
- Prüfe, ob in `prepareDeviceLost` oder Schritt 2 weitere Fehlerpfade auf Dateien des Datenverzeichnisses den Widerruf verhindern. Behandle sie ebenso. Ausgenommen sind Fehler an eigenen lokalen Dateien und an `user.rec` bzw. am Log selbst.
- **Tests:** `TestAttack09bDeviceLostBlockedByIndexDir` (index, mail) und `...ByAccept`. Erwartet wird jeweils: Widerruf geloggt, Generation g+1, `ErrPartial`, Warnung.

## Funde niedrig

1. **Search scheitert bei einem Schreibfehler der Neusignatur.** Scheitert `resignSegment` in `Search` (oder `List`/`Read`), wird gewarnt und das geprüfte Segment unverändert verwendet. Die Neusignatur holt ein späterer Lauf nach. Gilt sinngemäß auch für `resignMeta`. Test: `TestAttack09bSearchFailsOnResignWrite`, erwartet sind Treffer und eine Warnung.
2. **`ErrMetaChanged` kann der betroffene Client nicht selbst auflösen.** Das bleibt die strengste Lesart von 09b Punkt 5. Dokumentiere den Zustand und den Ausweg (ein anderes Mitglied schreibt n+2) im Paketkommentar. Keine Codeänderung, außer es gibt eine Lösung, die K4 und Punkt 5 nicht lockert; dann begründen.
3. **Testlücken:**
   - (a) Grenzfall des Vergleichs: Ein Vermerk mit `Tree` = R+1 (R = Index des Widerrufs) wird abgelehnt, einer mit `Tree` = R übernommen. Die Mutation `e.Index+1 >= tree` muss brechen.
   - (b) `resignSegment`: Die Postfachsperre muss gehalten werden. Erst kommt das neue Segment, dann wird das alte gelöscht. Der Byte-Vergleich vor dem Ersetzen muss greifen. Jede dieser drei Mutationen muss einen Test brechen.
   - (c) Die Absturzpunkte `segment-resigned` und `meta-resigned` kommen in `TestDeviceLostCrash`.
4. **`internal/terms`:** Der Paketkommentar nennt die Wahl der Thread-Wurzel (References → In-Reply-To → Message-ID) und die Erkennung von `multipart/mixed` als Regeln des Pakets. Umgesetzt sind sie in `ingest/terms.go`. Ziehe beide nach `terms`, mit Test, oder berichtige den Kommentar. Bevorzugt ist der Umzug, damit 9.3 „genau einmal“ gilt.

## Fertig

- `gofmt -l .` leer.
- `go vet ./...` und `go vet -tags gomail_dev,gomail_test ./...` ohne Befund.
- `go test -race -tags gomail_dev,gomail_test -timeout 40m` für `./internal/client`, `./internal/ingest`, `./internal/terms`, `./internal/e2e` und `./cmd/gomailctl`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/client ./internal/terms`.
- Abdeckung: `client` ≥ 85 %, `terms` ≥ 85 %.
- Vektoren byte-gleich.
- Mutationsnachweise für den Fund hoch (Kopien ohne Wachstum), den Fund mittel und die Punkte 3(a)–(b).
- Ein Commit `client, terms: segment notes bound to content, device lost not blocked by the data directory, tests (task 09c)` mit `Task: docs/tasks/09c-client-takeover-rework.md`. Kein Modellname, keine Co-Authored-By-Zeile.
