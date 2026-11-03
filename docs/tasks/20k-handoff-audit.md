# Auftrag 20k: HANDOFF und AUDIT auf den Stand vor der Abnahme (nur Dokumentation)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree. Der Code von 20h liegt im Branch `worktree-agent-a7b23152bafa90687` (Commit b14d798), wird parallel zusammengeführt und gilt für diesen Auftrag als Stand des Codes.
- Darf ändern: nur `docs/HANDOFF.md` und `docs/AUDIT.md`. Kein Code, keine Tests.
- Parallel ändert Auftrag 20j `RUNBOOK`, `DECISIONS`, `SPEC-ISSUES`; verweise auf deren Abschnitte, ohne sie zu ändern.
- Quelle: `docs/tasks/20-notes.md` (ganz, besonders ab „Aus 18c“), `docs/tasks/20-triage.md`, `docs/tasks/20-mandatory-tests.md`, `docs/ORCHESTRATION.md` §1 und Verlauf ab 20b, DECISIONS D84–D91 mit Nachträgen.

## Umfang

1. **HANDOFF:**
   - Platzhalter füllen, soweit die Daten vorliegen: Fuzzing (alle 25 Ziele mit Ausführungen aus `20-notes.md`, Stand des Codes je Teil), Abdeckung je Paket (`20-mandatory-tests.md`, für `client` 88,3 % nach 20h), Zuordnung der Pflichttests (27 von 30 vollständig; S7 und Volltext außerhalb M1; S9 wartet auf Q19/Q8), Laufzeiten (`internal/client` unter race bis etwa 57 Minuten bei Last, `-timeout 60m` knapp; Abschlussläufe ohne parallele Last), bekannte Flakes (`TestPTYPromptBlocked` unter race, einmal; `TestWordErrorsNameNoInput` behoben).
   - Kriterium D (MEASUREMENTS) und der Abschluss-Volllauf von E bleiben Platzhalter „wird mit Auftrag 17 bzw. 20 eingetragen“.
   - Stand je Kriterium A–F ehrlich, mit dem, was fehlt; offene Fragen Q18, Q19, Q20 mit Stand; Q22 erledigt.
   - `Client` nicht goroutinesicher; Testkommandos mit `-timeout 60m`.
2. **AUDIT:**
   - Kopf auf den Stand nach 20h; R33 (geschlossen, Restgrenzen: Rest ohne Marker, Inode-Wiederverwendung bei der Sperrprüfung), R41 (`keys.ReadKeystoreFile`, `emptyDir` offen), R27/D91 (Nachtrag 20e `noteWritten`), 6.2 (neue Regel→Test-Zeilen: `TestAllSchemasListed`, `TestAllSchemasRoundTrip`, `TestDeviceChange*`, `TestNoPanicAfterClose`, `TestLeftoverNeedsMarker`, `TestOpenLockFileReplaced`, FIFO-Tests), 6.4 (Fuzzing vollständig), neue Restgrenze „`Client` nicht goroutinesicher“.
   - Jede Aussage mit Datei und Funktion oder Testname belegt; geprüft am Code (b14d798).

## Fertig

- Nur die zwei Dateien geändert. Ein Commit mit `Task: docs/tasks/20k-handoff-audit.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20k/notes.md`.
- Keine Läufe ganzer Pakete (die CPUs sind belegt); einzelne `go test -run` nur, wenn für einen Beleg nötig.
