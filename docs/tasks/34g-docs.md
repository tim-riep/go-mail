# Auftrag 34g: Doku-Nachzug zu Auftrag 34 (Paket 34A) und Hinweise aus 33g2

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 33g.

- **Basis:** Arbeitsbranch, aktueller Stand, eigener Worktree. Ein Commit mit `Task: docs/tasks/34g-docs.md`, ohne Co-Authored-By, ohne Claude-Session-Zeile, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle außer `go env`.
- **Code:** 34A, Patch `docs/tasks/patches/34a-656b2c3.patch` (656b2c3 auf 526cb21). Lies ihn, indem du ihn in einer Kopie anwendest (`git worktree add --detach <ordner> 526cb21` und `git -C <ordner> am <patch>`) oder den Patch direkt liest. Schreibe „Auftrag 34, Paket 34A“; Merge-Hash und Volllauf trägt der Orchestrator ein (Platzhalter „die Commits und den Volllauf trägt der Orchestrator ein“).
- **Quellen:** `docs/tasks/33-nach-m1-nacht4.md` (Abschnitte „Auftrag 34“, „Nacharbeit 34A2“, „Neuauflage 34A“), `docs/tasks/20-notes.md` (Einträge „34A“ und „34A neu“, „33g2“), ORCHESTRATION Abschnitt 14.
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`, `docs/DECISIONS.md` (nur Nachträge).

## Umfang

1. **RUNBOOK 7.2, 7.3 und 8.6:** die neuen Meldungen von `publish` wörtlich (`… is not the file publish wrote and nothing is logged …`, `ceremony: writing <…>: store: … another process changed the directory meanwhile; nothing is logged …`, die Fassungen mit `… and stays: another process changed the directory meanwhile; … was not replaced …` bzw. `… is missing …`) mit Bedeutung und Abhilfe („another process writes platform/ during publish: stop it, look at platform/ and run the same publish again“); dass dann kein Rückruf „replaced“ kommt und nichts geloggt ist; EMFILE „dup … too many open files“.
2. **D93 Nachtrag 34 A:** Prüfung des Namens nach rename/link mit `Root.Lstat` und `SameFile` gegen `fstat`; `held` als Duplikat des Deskriptors gegen die Wiedervergabe von Inode-Nummern; der Temp-Name wird nur entfernt, wenn er noch die geschriebene Datei ist; Restfenster 1 und 2; `SetTempInHook` nur mit Tag `gomail_test` (Entscheidung des Orchestrators); Windows ohne `held`.
3. **AUDIT R17 (b) und Testtabelle 6.2:** die neuen Tests (`TestFilesInTempSwapped`, `TestFilesInTempRemoved`, `TestCreateFileAtomicInTempGoneAfterLink`, `TestFilesInNameChangedAfter`, `TestFilesInInodeReused`, `TestFilesInTempGoneOnError`, `TestPublishWitnessesTempDirMissingName`, `TestPublishWitnessesReplacedMeanwhile`, `TestPublishExportFileReplacedMeanwhile`, `TestReplaceFailedErrMeanwhile`) und die Wettlaufzahlen der Prüfer (20-notes).
4. **Liste:** Nr. 124 erledigt mit Auftrag 34; Nr. 108 Restfenster-Teil weitgehend erledigt (was offen bleibt, genau); neue Zeile mit den niedrigen Resten aus beiden Prüfungen (Testlücken S13/S11 mit beiliegender Probe, ENOENT-Zweig, EISDIR-Meldung nach link, Fenster 2 und der Vorschlag, den Temp-Namen vor dem Entfernen auf einen eigenen Namen umzubenennen, `TestFilesInInodeReused` nur auf ext4 wirksam, `removeTemp` verschluckt Fehler, Kommentar „a directory never“); eine Zeile für dieselbe Klasse in `WriteFileAtomic`, `CreateFileAtomic` und `WritePrivateFileAtomicIn` (Pfad-Varianten; die letzte erst nach 29B).
5. **HANDOFF:** Kopf-Nachtrag 34g; „Bekannte Grenzen“ zu `publish` (Grenze bis Auftrag 34 aufheben, Restfenster nennen); Punkt 7.
6. **Hinweise aus 33g2** (20-notes „33g2“): H1 RUNBOOK 0.2 „Die Meldungen des Durchlaufs über das Modul (seit Auftrag 29) nennen den Pfad“; H2 Stil in Nr. 95 und D93 Nachtrag 33 A; H3 Nr. 125 `vendor` wie F4.

## Fertig

Ein Commit; jeder Meldungstext wörtlich wie im Code; Bericht mit geänderten Stellen. Notizen: `scratchpad/impl34g/notes.md`; Patch `scratchpad/patches/34g.patch`.
