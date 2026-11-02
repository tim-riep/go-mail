# Auftrag 18c: `docs/AUDIT.md` auf den Stand nach 13e, 15i–15n, 19 und 20a bringen

Nur Dokumentation. Feste Vorgaben: `docs/tasks/00-vorgaben.md`. Eigener Worktree auf dem Arbeitsbranch (Stand dieses Auftrags). Auftrag 18 und 18b gelten weiter. Jede neue Aussage wird am Code des Branchs belegt.

1. **Kopf und Stand:** Der Code-Stand ist der aktuelle Branch. „In Arbeit“ bleibt nur noch die Linie 09b (S13 für Metadaten und Segmente, `internal/terms`, Auftrag 09g läuft, Q22). Für alle anderen Punkte, die als „in Arbeit (15i/15l/15m/15n, 13e)“ markiert sind, beschreibst du den gebauten Zustand:
   - **R1–R6** nach D85-Nachträgen (15i–15n, 20a) und D86-Nachträgen (13e, 20a).
   - **Restgrenzen** jeweils mit Beleg:
     - Ein Terminal, das nie wieder annimmt, zeigt das Löschen nicht.
     - Eine blockierte Anteilszeile kann das letzte TCOON nach dem Löschen durchlassen. Nur mit Mutante nachgestellt.
     - O_NONBLOCK auf einer gemeinsamen Beschreibung macht auch stdin nicht blockierend.
     - BSD und Darwin sind nur per `vet` geprüft.
     - `confirmDelay` gilt nicht für eine unvollständige Zeile.
     - Auf BSD gibt es ohne `/dev/tty` kein `sameControlling`.
     - Ein statischer mknod-Knoten auf einem anderen Dateisystem wird verweigert.
2. **D90:** Ingest-Schlüssel vor `valid_from` ohne Toleranz. Folge für die Verfügbarkeit: Eine nachgehende Server-Uhr verweigert den Start.
3. **D87-Nachtrag:** Reguläre Dateien werden mit `O_NONBLOCK` gelesen. **Neue Restgrenze:** Weitere `os.Open`-Aufrufe ohne diese Prüfung, ein FIFO hängt dort:
   - `ceremony/files.go`, `ceremony/publish.go` `readExport`;
   - `translog/operator.go`: Verzeichnisse und `syncFile`.
4. **Prüfpfade (6.x):**
   - Neue Tests aus 13e, 15i–15n, 19b und 20a in die Tabelle Regel → Test → Datei aufnehmen. Jeder Testname wird per grep geprüft.
   - Die Vorlagen der nachbaubaren Angriffe für die Zeremonie stehen jetzt im Repository: `abort15m_*`, `blocked15n_*`, `confirm15n_test.go`, `exit20a_*`.
   - Den Hinweis „kommen erst mit diesen Aufträgen“ entfernen.
5. **Niedrige Punkte aus der Prüfung von 18b**, siehe `docs/tasks/20-notes.md`, Abschnitt „Aus 18b-Nachprüfung“:
   - R35: `TestProductionBuild` gehört nicht in den Nachsatz.
   - 7.2: Einleitung zur DragonFly-Grenze anpassen.
   - 6.5: Die CLI lehnt `--compromised` ebenfalls ab.
   - 6.1: `cmd/gomail-server` überspringt Tests über den Fehler von `ceremony.InitDev`.
6. **AUDIT-Hinweise aus `docs/tasks/20-notes.md`:** Alle als „AUDIT“ markierten Punkte prüfen und aufnehmen, die nicht die Linie 09b betreffen. Die Punkte zur Linie 09b (Wachstum, Vermerke, R27) bleiben, wie sie sind; der Orchestrator ergänzt sie nach dem Merge von 09g.
7. **Q22:** In 7.1 aufnehmen, mit Stand „entschieden (A), Auftrag 09g läuft“.

Fertig: Ein Commit `docs: AUDIT on the state after 13e, 15i-15n, 19, 20a (task 18c)` mit `Task: docs/tasks/18c-audit-update.md`, ohne Modellnamen und ohne Co-Authored-By-Zeile. Bericht: geänderte Abschnitte, Restrisiken neu, geändert und entfallen, Widersprüche zwischen Dokumenten.
