# Auftrag 09f: Regel `merged` an das eigene Ergebnis binden, Originale nur nach angenommenem Nachfolger löschen, Testlücken (offene Punkte aus Q22)

Vorbereitet für Q22. Gestartet wird der Auftrag erst nach der Entscheidung des Auftraggebers: entweder als Folgeauftrag nach dem Merge von 09e oder als vierte Runde davor.
- Feste Vorgaben: `docs/tasks/00-vorgaben.md`.
- Basis: Worktree `/home/user/go-mail/.claude/worktrees/agent-a4b5ac897ba87ee5f` (Stand 4acdc45), oder der Arbeitsbranch nach dem Merge von 09e.
- Es gelten die Aufträge 09b bis 09e.
- Angriffs- und Belegtests liegen im Scratchpad:
  - `verify09e-attack/kept/`: `v_attack09e_merged_block_test.go`, `v_attack09e_step4_hide_test.go`, `v_attack09e_replay_mark_test.go`, `v_attack09e_rollback_test.go` und `v_attack09e_honest_order_test.go`;
  - `verify09e-spec/evidence/zz_verify_honest_test.go`.
  Übernimm sie ins Repository, mit neuen Namen, und passe sie an.

## Fund mittel (Angreifer 09e): `merged` blockiert das Zusammenfassen nach einem Löschen dauerhaft

Dasselbe tritt im ehrlichen Betrieb auf (Spezifikationsprüfung 09e, niedrig): Nach dem Widerruf eines Mitglieds, dessen zusammengefasstes Ergebnis der Client nicht geprüft hatte, fasst er nicht mehr zusammen.

Umsetzen:
- Die Grenze `merged` gilt nur, solange das eigene letzte Zusammenfassungsergebnis der Epoche unter den angenommenen Segmenten liegt. Erkennbar ist es am Hash des Ergebnisses oder an `next` der verbrauchten Vermerke.
- Fehlt das Ergebnis oder wird es abgelehnt, fasst der Client wieder normal zusammen, also ab 16 zählenden Segmenten. `merged` wird dann auf das neue Ergebnis gesetzt; D84 (2) gilt, der Wert sinkt nie.
- Belege, dass die Begrenzung erzwungener Zusammenfassungen aus 09e erhalten bleibt (`TestForeignMergesPutBack` grün), oder nenne die neue Schranke mit Rate.
- Tests:
  - `TestAttack09eMergedBlock` mit den Varianten Löschen und Kolludieren: Danach wird wieder zusammengefasst, und es gibt kein `ErrPartial` durch angehäufte Segmente.
  - Der Ablauf aus `zz_verify_honest_test.go`: höchstens 16 Segmente.

## Funde niedrig

1. **Rücksetzen auf den Stand vor dem Zusammenfassen.** Originale werden nur dann als verbraucht gelöscht, wenn ihr Nachfolger (`next`) unter den angenommenen Segmenten liegt. Andernfalls werden sie als gültig verwendet. Ein Zurückspielen darf dabei nicht wachsen. Test: `TestV09eRollbackOriginals`.
2. **Datei während `device lost` versteckt, stiller Erfolg.** Prüfe, ob Schritt 4 die in Schritt 2 vermerkten eigenen Segmente und Metadaten gegen das Vorgefundene abgleichen kann: Was vermerkt war und jetzt fehlt, ergibt Vormerkung und `ErrPartial`. Das darf die Vormerkung nicht dauerhaft blockieren (Ausweg: `Sync` nach dem Zurücklegen schließt ab; endgültig verschwundene Dateien gelten nach einer festen Zahl von Versuchen als gelöscht). Geht das nicht einfach und begrenzt, begründe es im Bericht; es wird dann bekannte Grenze im AUDIT.
3. **Zurückgespielte ältere Metadatenversion hält die Vormerkung.** Einheitlich mit Segmenten behandeln: Eine ältere Version, die `Versions` ohnehin ablehnt, zählt in Schritt 4 nicht als „nicht neu ausgestellt“.
4. **Testlücken:**
   - `merged` je Epoche: Test mit Zusammenfassen in zwei Epochen. Die Mutation „globaler Zähler“ muss brechen.
   - Toleranz von Search, List und Read bei `errStale`.
   - `ownGenValid`, Zweig „eigene Generation widerrufen“: Es wird nicht neu signiert.
   - Die Reihenfolge „Marken speichern vor Entfernen“ bei Zusammenfassen, Neusignatur und Index (Mutationen V13, V14 und V18 aus der Spezifikationsprüfung 09d).
   - `reissuing` wird nach `Sync` zurückgesetzt (V8).

## Volllauf: `internal/bench` scheitert auf 4acdc45

Betroffen sind `TestIndex/terms`, `TestIndex/unprocessed`, `TestSync` (keine Segmente nach `Sync`) und `TestIndexSegments` (kein Zusammenfassen bei 1000 Mails), jeweils mit Tags, unter race und unter 386.
- Ursache klären: Unterdrücken die neuen Regeln (keine enthaltenen Einträge, `Indexed`, `merged`) wiederholte Messrunden mit denselben Mails, oder liegt ein Fehler vor, der auch echte Nutzer trifft?
- Liegt ein Fehler im Code vor, wird er behoben.
- Ist es nur die Messweise, wird die Messumgebung angepasst (nur Testcode in `internal/bench`), ohne die gemessene Größe zu verfälschen.
- `go test -race -tags gomail_dev,gomail_test ./internal/bench` kommt in die Fertig-Läufe.

## Fertig

- `gofmt -l .` ist leer.
- `go vet ./...` ohne Befund, mit und ohne Tags.
- `go test -race -tags gomail_dev,gomail_test -timeout 40m ./internal/client` grün.
- Ohne race grün: `./internal/e2e`, `./cmd/gomailctl`, `./internal/terms`; mit race grün: `./internal/bench`. Dazu der Volllauf aller Pakete nach `00-vorgaben.md`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/client` grün.
- Abdeckung `client` mindestens 85 %.
- Mutationsnachweise.
- Ein Commit `client: merge limit bound to the own result, originals kept until the successor is accepted, tests (task 09f)` mit `Task: docs/tasks/09f-client-merge-rule.md`. Kein Modellname, keine Co-Authored-By-Zeile.
