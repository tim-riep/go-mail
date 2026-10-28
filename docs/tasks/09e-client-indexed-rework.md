# Auftrag 09e: Nacharbeit 09d (dritte und letzte Runde): Merkmal `Indexed` nur für Begriffslisten, Schritt 4 ohne stille Ausgänge

Welle 4, sicherheitskritisch. **Dritte und letzte Nacharbeitsrunde der Linie 09b. Bleiben danach Funde über niedrig offen, greift Haltepunkt 3.**
- Feste Vorgaben: `docs/tasks/00-vorgaben.md`.
- Worktree: `/home/user/go-mail/.claude/worktrees/agent-a4b5ac897ba87ee5f`, Branch `worktree-agent-a4b5ac897ba87ee5f`, Stand f982400.
- Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`.
- Die Aufträge 09b, 09c und 09d gelten weiter. Erlaubt sind dieselben Pfade wie in 09b.
- Angriffstests des Prüfers liegen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify09d-attack/kept/`.

## Fund mittel: `Indexed` verwirft die Begriffsliste, wenn vorher der Marker indexiert wurde

Der Fehler kommt aus 09d und tritt im ehrlichen Betrieb auf. Test: `TestAttack09dIndexedMarkerFirst`.

**Ablauf:**
1. Der Ingest legt zuerst den Marker `unprocessed` an (5.2 Schritt 3).
2. Später ersetzt ihn die Begriffsliste (Schritt 5).
3. Indexiert der Client dazwischen, setzt er `Indexed=n` mit Begriffen aus den Metadaten. `thread:` ist dabei die eigene Message-ID.
4. Den Eintrag der späteren Begriffsliste überspringt er dann und löscht die Datei.

**Folge:** `thread:<root>` ist für alle Leser dauerhaft verloren. Dasselbe gilt sinngemäß für gekürzte `from:`/`to:`.

**Umsetzen:**
- Marker-Einträge (`unprocessed`) und Begriffslisten getrennt vermerken. Je Mail und Epoche wird höchstens ein Eintrag je Art indexiert. Eine Begriffsliste wird nach einem Marker immer noch indexiert, ein zurückgespielter Eintrag derselben Art nicht.
- Begründe, dass das Wachstum je legitimer Mail begrenzt bleibt: höchstens ein zusätzliches Merkmal.
- Die Deduplizierung gegen vorhandene Segmente deckt den Rest.
- **Tests:**
  - `TestAttack09dIndexedMarkerFirst`: `thread:<root>` wird gefunden.
  - `TestPendingReplayAfterDeletion`: weiterhin +0 Byte, für Marker und für Begriffsliste.
  - Je eine Mutation, die bricht.

## Funde niedrig (in dieser letzten Runde mitnehmen)

1. **Schritt 4: stille Ausgänge unter `c.reissuing`.**
   - Drei frühe `return nil` sind betroffen:
     - `resignSegment` bei geänderter Datei zwischen Lesen und Sperre (Austausch, Test `attack09d_step4_toctou_test.go`);
     - `resignSegment`/`resignMeta`, wenn `userGen` scheitert;
     - `resignMeta` bei `Version == MaxUint32`.
   - Unter `c.reissuing` werten alle drei als `errNotReissued`, mit Vormerkung und `ErrPartial`.
   - Search, List und Read bleiben tolerant.
   - Tests für den Austausch und für `userGen`. `MaxUint32` nur, wenn es ohne großen Aufwand geht.
2. **Vermerke im alten Format lassen sich durch eine Kopie ausschalten.** Test: `attack09d_oldmemo_shadow_test.go`.
   - Eine Kopie gilt nur dann als erledigt, wenn die erste Datei mit demselben Inhalt angenommen wurde.
   - Wurde sie abgelehnt, wird die nächste Datei mit demselben Inhalt geprüft.
   - Das Wachstum bleibt +0.
3. **Wiedereinspielen fremd zusammengefasster Segmente.** Segmente, die ein anderer Client zusammengefasst hat, sind im eigenen Zustand nicht markiert. Rechnerisch ist das ab 16 Geräten unbegrenzt.
   - Prüfe, ob eine einfache, begrenzte Regel das schließt.
   - Beispiel: Ein Segment, dessen Einträge vollständig in einem gültigen Segment desselben Laufs enthalten sind, wird ignoriert und zählt nicht für die Schwelle.
   - Wenn ja, umsetzen und testen. Wenn nein, im Bericht mit Rate begründen; das geht dann als bekannte Grenze ins AUDIT.

## Fertig

- `gofmt -l .` leer.
- `go vet ./...` mit und ohne `-tags gomail_dev,gomail_test`.
- `go test -race -tags gomail_dev,gomail_test -timeout 40m ./internal/client` grün.
- Ohne `-race` grün: `./internal/e2e`, `./cmd/gomailctl`, `./internal/terms`.
- `GOARCH=386 go test -tags gomail_dev,gomail_test ./internal/client` grün.
- Abdeckung `client` ≥ 85 %.
- Vektoren byte-gleich.
- Mutationsnachweise für den Fund mittel und die Punkte 1–2.
- Ein Commit auf dem Merge-Stand: `client: indexed marker per entry kind, step 4 without silent exits (task 09e)` mit `Task: docs/tasks/09e-client-indexed-rework.md`. Kein Modellname, keine Co-Authored-By-Zeile.
