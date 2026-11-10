# Auftrag 26g: Doku-Nachzug zu Auftrag 26 (Pakete 26B bis 26F; 26A angehalten)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme: Dieser Auftrag erlaubt Nachträge an bestehende D-Einträge in DECISIONS und den Nachtrag in HANDOFF (wie 24g und 25g).

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, eigener Worktree, nur Dokumentation, keine `go`-Befehle.
- **Code der Pakete:** Lies ihn in der gemeinsamen Quelle `orch/n26` (lokaler Branch, beff425) mit `git show beff425:<pfad>`.
- **Endstände je Paket:**
  - 26B: 76fc484
  - 26C: e060e09
  - 26D: aa44137
  - 26E: c44cc7e, dazu die Anpassung an 26B 2e56813
  - 26F: c16ee34

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe „Auftrag 26, Paket 26X“.
- **Quellen:**
  - `docs/tasks/26-nach-m1-nacht2.md`;
  - `docs/tasks/20-notes.md`, Abschnitt „Auftrag 26 … Prüfungen“;
  - `docs/ORCHESTRATION.md`, Abschnitt 10;
  - die Notizen der Implementierer unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/`: `impl26b/`, `impl26b2/`, `impl26c/`, `impl26c2/`, `impl26d/`, `impl26d2/`, `impl26e/`, `impl26e2/`, `impl26e3/`, `impl26e-adapt/`, `impl26f/` (je `notes.md`).
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/MEASUREMENTS.md` (nur „Messcode“), `docs/tasks/backlog-nach-m1.md`, `docs/DECISIONS.md` (nur Nachträge).

## Umfang, je Paket am Code prüfen

- **26B (`publish` über einen Deskriptor von `platform/`):**
  - RUNBOOK 7.3 „Fremde Dateien“ und Restfenster: `platform/` wird einmal geöffnet (`os.Root`), nach dem Öffnen und vor dem Log noch einmal geprüft; ein Tausch wirkt nicht mehr. Die neuen Meldungen stehen wörtlich in 8.6:
    - „was replaced during publish … looked at …“;
    - „… opened and wrote to; nothing logged …“;
    - „listing platform/“.
  - RUNBOOK 7.2: Die Ersatzzeile kommt auch bei einem fsync-Fehler nach dem `rename`.
  - D93: Nachtrag 26 B.
  - AUDIT R17: Restgrenzen nach 26B.
  - Nr. 73: `Store.RemoveTempFiles` entfernt mit Unlink, Verzeichnisse bleiben stehen (Serverstart).
- **26C (`bench.sh`):**
  - D94: Nachtrag 26 C mit Prozessgruppe, Trap, Wächter, QUIT/TTIN, Probe von `-o`/`-raw`, `samefile`, `-benchtime` und AST-Test der Namen.
  - MEASUREMENTS „Messcode“: Messcode unverändert, belegt durch die Prüfungen.
- **26D (Testlücken):**
  - AUDIT R48: M4direct ist unter Linux per inotify abgedeckt, mit Restgrenze.
  - Liste: Nr. 66, 69, 79 erledigt.
- **26E (Fuzz-Ziele):**
  - HANDOFF „Fuzzing“ und AUDIT 6.4: sechs neue Ziele mit Paket, Einstieg, Laufzeit und Ausführungen.
  - Befehl für die Client-Ziele mit Tags, Hinweis auf `-fuzzminimizetime 0s` und einen frischen `-test.fuzzcachedir` für Mutanten.
  - Grenze von `FuzzState`, D57.
  - Liste: Nr. 25 erledigt.
  - **Fund aus dem Fuzzing:** Der Client übernimmt einen Referenzkopf aus `state.json` mit fremder Origin (20-notes, Eintrag 26E3).
    - In AUDIT als offener Befund niedrig, mit dem Hinweis, dass die Abhilfe eine Prüfregel des Clients ist und damit einen Haltepunkt bildet.
    - In der Liste als neue Nummer mit der Abhängigkeit „Entscheidung des Auftraggebers“.
- **26F (aus 26A, ohne Grenzen am Listener):**
  - Nr. 74: `PublishHead` lehnt wie `SignHead` mit `ErrConsistency` ab. Dazu AUDIT R8 bzw. die Stelle zu `refuse` und der D80-Nachtrag.
  - Nr. 75, 67 und 70 (ohne `bench.sh`) als erledigt.
- **26A (Grenzen am Listener, angehalten):**
  - In AUDIT R8 und der Liste (Nr. 7): Nach drei Runden sind zwei Funde über niedrig offen (F1 hoch, F2 mittel; 20-notes, Einträge 26A bis 26A3). Die Grenzen sind deshalb nicht zusammengeführt. Nr. 7 bleibt „Teil erledigt“ mit dem Stand nach 24/25.
  - Die drei möglichen Wege stehen in ORCHESTRATION Abschnitt 10 (Haltepunkt 26A); sie gehören als „Entscheidung des Auftraggebers“ in die Liste.
  - Keine Beschreibung von Code, der nicht zusammengeführt wird.
- **`SlotWait`:** ist seit 25C 5 s. Berichtige die veralteten Angaben „1 s“ in DECISIONS (um Z. 472), AUDIT (um Z. 173) und HANDOFF (um Z. 490), am Code geprüft.
- **Liste nach M1:**
  - Erledigt: Nr. 25, 66, 67, 69, 70, 72, 73, 74, 75, 76 bis 83 (prüfe jede am Code und an 20-notes).
  - Neue Nummern für alle in 20-notes, Abschnitt „Auftrag 26 … Prüfungen“, als niedrig genannten und nicht behobenen Reste, kurz.
  - Dazu der Fund zur Origin und der Haltepunkt 26A.
- **HANDOFF:** Nachtrag 26g im Kopf, im Stil von 25g, mit dem Code-Stand „Arbeitsbranch nach Auftrag 26“. Dazu kurz in „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“.

## Fertig

- Ein Commit mit `Task: docs/tasks/26g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt.
- Bericht: geänderte Stellen und offene Punkte.
