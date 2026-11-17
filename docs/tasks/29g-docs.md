# Auftrag 29g: Doku-Nachzug zu Auftrag 29 (Pakete 29A bis 29D)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme wie bei 27g und 28g: Dieser Auftrag erlaubt Nachträge an bestehende D-Einträge in DECISIONS und den Nachtrag in HANDOFF.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, eigener Worktree, nur Dokumentation, keine `go`-Befehle.
- **Code der Pakete:** Lies ihn mit `git show <commit>:<pfad>`. Die Endstände, je ein Commit auf 0854dab (dem Code nach Auftrag 28):
  - 29A: 78fa2ac (Runden babcb9f, 78fa2ac)
  - 29B: @29B@ (Runden 188d765, @29B@)
  - 29C: e8bf056
  - 29D: df5a202 (Runden 38562b1, df5a202)

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe „Auftrag 29, Paket 29X“.
- **Quellen:**
  - `docs/tasks/29-nach-m1-nacht3.md`;
  - `docs/tasks/20-notes.md`, Abschnitt „Auftrag 29 (Nacht 17./18.11.): Prüfungen“;
  - `docs/ORCHESTRATION.md`, Abschnitt 12;
  - die Notizen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/`, je `notes.md` in `impl29a/`, `impl29a2/`, `impl29b/`, `impl29b2/`, `impl29c/`, `impl29d/`, `impl29d2/` und `rev29*/`.
- **Darf ändern:**
  - `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`;
  - `docs/DECISIONS.md`, nur Nachträge;
  - `docs/MEASUREMENTS.md`, nur falls dort schon eine Messung zu `indexEpoch` oder Nr. 112 steht: 1000 Mails × 100 Marker, Öffnungen 100 000 → 1000, Zeit nur wenig kürzer (189 → 166 s, gemessen unter Last mit 188d765; die pending-Dateien beherrschen den Aufruf).

## Umfang, je Paket am Code prüfen

- **29A (`store.ReadFileLimited`):**
  - **D48:** Nachtrag 29 A. Erster Read bei Stat-Größe 0 mindestens `min(512, Grenze)`; Kopie eines kurzen Ergebnisses nur unter der Regel aus dem Code (gesamt + Länge ≤ 2 × Grenze, dazu die Schwellen aus dem Code); `ErrTooLarge` mit der Meldung „the buffer is full at N bytes before the limit“, wörtlich wie im Code. Allokation höchstens etwa 2 × die Grenze (angeforderte Bytes), Rückhalt eines kurzen, nicht kopierten Ergebnisses unter 3 × seiner Länge.
  - **AUDIT 6.2:** die neuen Tests aus `fs29a_test.go`; die Allokationstests laufen nicht parallel.
  - **HANDOFF:** die Zeile zu `ReadFileLimited` angleichen.
  - **Liste:** Nr. 115 erledigt bis auf `max = math.MaxInt64` (bleibt offen, Verhaltensänderung). Neue Hinweise aus 29A/29A2 nur, wenn sie nicht schon erledigt sind.
- **29B (Client):**
  - **RUNBOOK 4.5 und 8.6:** die neue Warnung zur unlesbaren Datei in `pending/` wörtlich (beide Ursachen, wie im Code). Der Eintrag bleibt liegen; Ablauf unverändert.
  - **D91:** Nachtrag 29 B. `Index` öffnet eine Mail je Aufruf nur einmal; zwischengespeichert werden nur gelungene Lesungen, gekürzt wie im Code, und Lesefehler, die den Marker liegen lassen. Urteile werden nicht zwischengespeichert, jeder Eintrag bekommt sein eigenes Urteil wie vorher (Entscheidung des Orchestrators, ORCHESTRATION Abschnitt 12, mit Grund: Speichergrenze bei Absendern von außen, kein Verlust von Begriffen bei einer Änderung der Mail zwischen zwei Markern).
  - **AUDIT R27 (b) und R32:** R32 am Code prüfen und berichtigen (was `unprocessedTerms` bzw. der Zwischenspeicher hält und wie lange). R27 (b): die Härtungen am fanotify-Test und der Test zu P8.
  - **Liste:** Nr. 112 erledigt. Nr. 114 erledigt bis auf das, was der Code nicht umsetzt (am Code prüfen, etwa SKIP ohne `CAP_SYS_ADMIN`). Bei Nr. 111 den Teil `openPending` als erledigt vermerken; `checkMeta` bleibt offen. Neu: keine Sammelwarnung für unlesbare pending-Dateien (Hinweis), dazu die niedrigen Reste aus den Prüfungen von 29B2 (20-notes).
- **29C (`publish`):**
  - **RUNBOOK 7.2 und 8.6:** Die Meldung nach einem gescheiterten Ersetzen von `witnesses.rec` hat zwei Fassungen, wörtlich: „was not replaced“ (fremdes Verzeichnis, `EEXIST`/`EISDIR`) und „is unchanged“ (sonst). Erkläre, dass „is unchanged“ bedeutet „von publish nicht verändert“; ein fremder Prozess kann den Namen trotzdem geändert haben (Hinweis H1 aus 29C).
  - **D93:** Nachtrag 29 C.
  - **AUDIT R17 (b):** die Kommentare zum Restfenster (`protected_hardlinks`, Rücktausch vor dem zweiten `Lstat`), soweit AUDIT davon spricht.
  - **Liste:** Nr. 108 teilweise erledigt (die Meldung bei `EEXIST`); offen bleiben die Restfenster und NFS/FUSE. Nr. 109 erledigt, soweit der Code es zeigt. Neu: H1 aus 29C und der Doc-Kommentar von `store.ReplaceFileIn`.
- **29D (`TestReleaseSwitches`):**
  - **AUDIT R35 und RUNBOOK 0.2, wo der Test beschrieben ist:** Ein symbolischer Link, dem go build folgen würde, lässt den Test scheitern; Dateien mit `_` oder `.` vorn werden wie bei go/build übersprungen; ein Unterordner zählt nur dann als eigenes Modul, wenn dort eine Datei `go.mod` liegt, die kein Verzeichnis ist.
  - **Liste:** Nr. 110 erledigt bis auf den Status von `grep` und `sort` im Skript (bleibt offen). Neu: die niedrigen Reste aus 29D2 (FIFO-Schutz nur gegen ein einziges Öffnen, Abhilfe Unix-Socket; ohne `mkfifo` fällt der Fall still weg; Prüfung der Wurzel ohne automatischen Test).
- **HANDOFF:**
  - Nachtrag 29g im Kopf, im Stil von 28g. Code-Stand „Arbeitsbranch nach Auftrag 29“; die Commits trägt der Orchestrator ein.
  - Kurz in „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“: Die offenen Haltepunkte und Entscheidungen bleiben die aus 27g; neu ist nur die Entscheidung des Orchestrators zu 29B.
- **Liste nach M1:** Nachtrag 29g im Kopf; neue Zeilen ab Nr. 116; die Zeile „Zeilen: …“ am Ende fortschreiben.

## Fertig

- Ein Commit mit `Task: docs/tasks/29g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt.
- Bericht: geänderte Stellen, offene Punkte, Abweichungen zwischen Code und Notizen.
