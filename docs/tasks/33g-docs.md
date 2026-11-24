# Auftrag 33g: Doku-Nachzug zu Auftrag 33 (33A, 33B, 33C, 33D) und 35A

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme wie bei 29g: Nachträge an bestehende D-Einträge in DECISIONS und der Nachtrag in HANDOFF sind erlaubt.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, aktueller Stand, eigener Worktree. Ein Commit mit `Task: docs/tasks/33g-docs.md`, ohne Co-Authored-By, ohne Claude-Session-Zeile, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle.
- **Code der Pakete** (je ein Commit auf c6b2ea2; mit `git show` lesen): 33A 8d557b0, 33B b167652 (Runden 48e8378, b167652), 33C 369860f, 35A 3a688c4. Schreibe „Auftrag 33, Paket 33X“ bzw. „Auftrag 35, Paket 35A“. Die Hashes nach dem Merge und den Volllauf trägt der Orchestrator ein (Platzhalter wie bei 29g).
- **Quellen:** `docs/tasks/33-nach-m1-nacht4.md`; `docs/tasks/20-notes.md`, Abschnitt „Auftrag 33 (Nacht 24./25.11.): Prüfungen“; ORCHESTRATION Abschnitt 14; Notizen `scratchpad/impl33a/`, `rev33a-spec/`, `rev33a-robust/`, `impl33b/`, `rev33b/`, `impl33b2/`, `rev33b2/`, `impl33c/`, `rev33c/`, `impl33d/`, `impl35a/`, `rev35a/` (je `notes.md`).
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`, `docs/DECISIONS.md` (nur Nachträge).

## Umfang, je Paket am Code prüfen

- **33A:** RUNBOOK 7.2 und 8.6 (`was not replaced` bei jedem gescheiterten Umbenennen, `is unchanged` nur bei Fehlern der temporären Datei, wörtlich; die neue Fassung mit entfernten `.tmp-*`; Grenze NFS/FUSE). D93 Nachtrag 33 A. AUDIT R17 (b) und Testtabelle (`TestReplaceFailedErrState`, `TestPublishPlatformGoneBeforeLog`, `TestNofileOnlyThroughSetNofile`, `keepNofile`). HANDOFF Testkonventionen (Limits in `internal/ceremony` nur über `setNofile` mit `keepNofile`, nie `t.Parallel`; Grenzen der statischen Prüfung). Liste: Nr. 118 erledigt; Nr. 95 die zwei Hinweise erledigt; Nr. 108 Wortlaut-Teil; neue Reste aus den Prüfungen (Testlücke ohne `TempRemoved`, 324 weitere Matrix-Duplikate, fremdes Verzeichnis `.tmp-*` bleibt liegen, hartes Limit, H1 von Prüfer 2 als „in Auftrag 34“).
- **33B:** RUNBOOK 0.2 und AUDIT R35 (Status von `grep` und `sort`; `skippedTagged` mit Meldung wörtlich; neu abgelehnte Links; Fund D; verschwundene Einträge werden übersprungen; zweite Runde nach 3 s; `.git` und `.claude/worktrees` werden durchsucht). Liste: Nr. 110 und Nr. 119 erledigt; neue Reste (N1 aus 33B2 mit Vorschlag FIXB, vendor nicht durchsucht, Ref `*.go` unter `.git`, R01/R04).
- **33C:** Liste: Nr. 121 Teile `TestSeedTypo`, `TestSwapWords`, dreifaches `swapWords` erledigt; neue Reste (Abstände, i ∈ {0,3}, Laufzeit).
- **33D:** HANDOFF „Laufzeiten“ mit den gemessenen Zahlen, Ursachen und dem race-Exit-Schlaf; Liste Nr. 27 aktualisieren (Zahlen, Ursachen, Vorschläge V1–V8; V2 als **Entscheidung des Auftraggebers**, weil `internal/keys` Phase 0 ist).
- **35A:** HANDOFF „Bekannte Flakes“/Testkonventionen: unter `go test -json` ist `os.Stderr` im Test Deskriptor 1; wer Deskriptor 2 prüft, nimmt `os.Stderr` vor `m.Run`. Liste: neue Zeile, erledigt mit 35A.
- **Köpfe:** Nachtrag 33g in HANDOFF, AUDIT und Liste, im Stil von 32g; Code-Stand „Arbeitsbranch nach Auftrag 33 und 35“; Platzhalter für Commits und Volllauf „die Commits und den Volllauf trägt der Orchestrator ein“. 29B weiter ungemergt (Entscheidung offen); neu offen: V2 (Erlaubnis für `internal/keys`).
- **Hinweise aus 32g:** AUDIT Kopf 32g „verweist nur noch auf H3“ genauer; „brach die übrigen Fälle ab“ → Panik beendet den Testlauf des Pakets.

## Fertig

Ein Commit; jeder Meldungstext wörtlich wie im Code; Bericht mit geänderten Stellen, neuen Nummern, offenen Punkten. Notizen: `scratchpad/impl33g/notes.md`.
