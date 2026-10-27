# Auftrag 09d: Nacharbeit 09c (zweite Runde): Neusignatur und Zusammenfassen ohne Wachstum, Schritt 4 meldet Fehler

Welle 4, sicherheitskritisch. Zweite Nacharbeitsrunde von 09b; bleiben danach Funde über niedrig, folgt eine letzte Runde, dann greift Haltepunkt 3. Feste Vorgaben: `docs/tasks/00-vorgaben.md`.
Worktree `/home/user/go-mail/.claude/worktrees/agent-a4b5ac897ba87ee5f` (Branch `worktree-agent-a4b5ac897ba87ee5f`, Stand 2e5a17a). Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i` (seitdem dazugekommen: Zeremonie 15i–15n, 19/19b).
Die Aufträge 09b und 09c bleiben gültig. Erlaubte Pfade wie in 09b.
Angriffstests des Prüfers: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify09c-attack/kept/`
- `attack09c_resign_growth_test.go`
- `attack09c_step4_silent_test.go`
- `attack09c_merge_growth_test.go`
- `old_attack09b_*.go`

Leitregel aus 09c gilt weiter: Ein Angreifer ohne Schlüssel darf `state.json` nicht vergrößern können. D84 (2) bleibt: Kein Pfad verkleinert `Checked`, Vermerke werden nicht gelöscht. Vermerke dürfen aber **geändert** werden, solange sie dabei nicht wachsen.

## Fund hoch: Kopien desselben Inhalts werden je Datei neu signiert

**Ablauf:**
1. Bob verliert ein Gerät.
2. Alice hatte vorher sein Segment B geprüft und vermerkt.
3. Ein Angreifer ohne Schlüssel legt Kopien von B unter neuen Laufnummern ab.
4. Alle Kopien teilen sich den Vermerk von B. `readSegments` ruft aber für jede Datei `resignSegment` auf.
5. Jedes neu signierte Segment hat neue Bytes und bekommt einen eigenen Vermerk. Das sind 301 Byte je Kopie, Stillstand nach etwa 54 Suchen.

**Umsetzen:**
- Byte-gleiche Dateien desselben Geräts und derselben Epoche werden in einem Lauf nur einmal verarbeitet. Die übrigen werden unter der Postfachsperre entfernt oder ignoriert, mit der Q11-Warnung. Wähle eines davon und begründe die Wahl.
- Nach der Neusignatur wird im Vermerk des Originalinhalts dauerhaft festgehalten, dass dieser Inhalt neu ausgestellt ist, zum Beispiel als Feld in `checkMemo` mit dem Hash des Nachfolgers. Taucht später eine Kopie des Originalinhalts auf, wird sie nicht erneut neu signiert. Sie wird ignoriert oder entfernt, denn ihre Einträge stehen im Nachfolger.
- Gilt sinngemäß für Metadaten: Eine zurückgespielte Version ist schon durch `Versions`/`ErrReplay` gedeckt. Prüfe es und belege es mit einem Test.
- **Test:** `TestAttack09cStateGrowthResignCopies` mit 3 × 1000 Kopien. Danach wächst `state.json` um höchstens einen festen Betrag, unabhängig von der Zahl der Kopien. Die Suche findet die Mail weiter genau einmal.

## Fund mittel 1: Schritt 4 von `device lost` meldet eine gescheiterte Neusignatur nicht

Beide Prüfer haben das unabhängig gefunden.
- Die Toleranz aus 09c („Neusignatur scheitert → Warnung“) greift über `readSegments` und `resignMeta` auch in `reissueMetaAndSegments`. Dort darf sie nicht greifen.
- **Umsetzen:**
  - In Schritt 4 und in der Fortsetzung (`Sync`, erneuter `device lost`) zählt eine gescheiterte Neusignatur eines Segments oder einer Metadatendatei als Fehler des Postfachs. Folge: Vormerkung `Reissue`, `ErrPartial`, und die Warnung nennt „nicht neu ausgestellt“, nicht „Prüfung fehlgeschlagen“.
  - Dasselbe gilt für `checkMeta`-Fehler in Schritt 4. Diese Lücke bestand schon vor 09c.
  - Search, List und Read behalten die Toleranz.
- **Test:** `attack09c_step4_silent_test.go`. Erwartet sind `ErrPartial`, Vormerkung, Warnung, und nach Beseitigen des Hindernisses schließt `Sync` die Neuausstellung ab.

## Fund mittel 2: Erzwungenes Zusammenfassen vergrößert `state.json` ohne Schlüssel

**Ablauf:**
1. Der Angreifer legt 14 Dateien mit gültigem Namen und Müll als Inhalt ab. Sie halten die Schwelle `MergeThreshold` erreicht.
2. Vor jedem Sync kopiert er ein gültiges Segment.
3. `Index` fasst zusammen und schreibt ein neues Segment, das einen neuen Vermerk bekommt. Das sind 300 Byte je Sync und Epoche.

Variante: alte, verschiedene Segmente wiedereinspielen, die früher zusammengefasst und gelöscht wurden. Ebenso alte `pending`-Dateien.

**Umsetzen:**
- Für die Schwelle zählen nur verschiedene, gültige Segmente. Ungültige Dateien und byte-gleiche Kopien zählen nicht.
- Beim Zusammenfassen wird im Vermerk jedes verbrauchten Segments festgehalten, dass es zusammengefasst ist, mit dem Hash des Ergebnisses. Der Vermerk wird geändert, er wächst nicht. Ein wiedereingespieltes Segment mit diesem Kennzeichen wird ignoriert oder entfernt und löst kein Zusammenfassen aus; seine Einträge stehen im Ergebnis.
- Ein wiedereingespielter `pending`-Eintrag für eine Mail, die der Client schon indexiert hat, erzeugt kein neues Segment. Belege mit dem vorhandenen Zustand (`Mails`, `Versions` o. Ä.), dass das ohne neuen Zustand je Mail geht. Wenn nicht, melde es als offenen Punkt und nenne die Rate.
- Wenn ein Weg ohne Spezifikationsänderung oder ohne Lockerung von D84 (2) nicht auskommt, halte an diesem Punkt an und melde ihn. Baue die strengste Lesart und miss die verbleibende Rate.
- **Test:** `TestAttack09cStateGrowthForcedMerge` und eine Variante mit wiedereingespielten alten Segmenten und `pending`-Dateien. Nach 100 Syncs wächst `state.json` um höchstens einen festen Betrag.

## Funde niedrig

1. **Testlücke Inhaltsschlüssel:** Bob schreibt zwei verschiedene Segmente, Alice prüft beide, Bob rotiert. Beide müssen übernommen werden. Die Mutation `segmentMemo` mit konstantem Hash muss brechen.
2. **Testlücken in Schritt 4 und bei der Auflistung:**
   - früher Abbruch bei einem Lesefehler von `index/` in `reissueMetaAndSegments`;
   - `first` verworfen;
   - `steps.unlisted` nicht gesetzt: `ErrPartial` allein wegen „Postfächer nicht auflistbar“;
   - `ErrNotFound` in `resignMeta` geschluckt.
   Jede dieser Mutationen muss einen Test brechen.
3. **Vermerke im alten Format:** Sie enthalten den Hash. Wenn es ohne Wachstum geht, nutzt der Lesepfad sie verlustfrei, also als Vermerk für genau diesen Inhalt. Sonst bleibt es bei „zählen nicht“, mit Begründung.
4. **`TestResignSegmentHoldsLock`:** Das 500-ms-Fenster durch eine Synchronisation über den Hook ersetzen.

## Fertig

- `gofmt -l .` leer.
- `go vet ./...` sauber, mit und ohne `-tags gomail_dev,gomail_test`.
- `go test -race -tags gomail_dev,gomail_test -timeout 40m` grün für `./internal/client`, `./internal/ingest`, `./internal/terms`, `./internal/e2e` und `./cmd/gomailctl`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/client ./internal/terms` grün.
- Abdeckung: `client` mindestens 85 %, `terms` mindestens 85 %.
- Vektoren byte-gleich.
- Mutationsnachweise für alle Funde.
- Die alten Angriffstests aus 09b und 09c laufen grün als Regression im Repository, unter neuen Namen.
- Ein Commit `client: resign and merge without state growth, step 4 reports failed reissue (task 09d)` mit `Task: docs/tasks/09d-client-state-growth.md`. Kein Modellname, keine Co-Authored-By-Zeile.
