# Auftrag 28g: Doku-Nachzug zu Auftrag 28 (Pakete 28A bis 28D)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme wie bei 27g: Dieser Auftrag erlaubt Nachträge an bestehende D-Einträge in DECISIONS und den Nachtrag in HANDOFF.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, eigener Worktree, nur Dokumentation, keine `go`-Befehle.
- **Code der Pakete:** Lies ihn mit `git show <commit>:<pfad>`. Die Endstände je Paket:
  - 28A: 8f15bbf (Runden 96cb2ea, 8f15bbf), auf f8fe095
  - 28B: 40fa7ab (Runden 077f5cc, 40fa7ab), auf f8fe095
  - 28D: 3a9b333 (Runden aaa9504, 3a9b333), auf f8fe095
  - 28C: 23d5f55 (Runden 838c2d5, 23d5f55), auf 3a9b333

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe „Auftrag 28, Paket 28X“.
- **Quellen:**
  - `docs/tasks/28-nach-m1-nacht2c.md`;
  - `docs/tasks/20-notes.md`, Abschnitt „Auftrag 28 … Prüfungen“;
  - `docs/ORCHESTRATION.md`, Abschnitt 10, Einträge ab 17:00 UTC am 10.11.;
  - die Notizen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/`, je `notes.md` in `impl28a/`, `impl28a2/`, `impl28b/`, `impl28b2/`, `impl28c/`, `impl28c2/`, `impl28d/`, `impl28d2/` und `rev28*/`.
- **Darf ändern:**
  - `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`;
  - `docs/MEASUREMENTS.md`, nur „Messcode“, falls nötig;
  - `docs/DECISIONS.md`, nur Nachträge.

## Umfang, je Paket am Code prüfen

- **28A (`publish`):**
  - **RUNBOOK 7.2:**
    - die Ankündigungszeile vor dem Ersetzen von `witnesses.rec`, wörtlich, für Datei, symbolischen und harten Link;
    - die neue Meldung, wenn das Ersetzen danach scheitert. Die Datei ist unverändert, nichts geloggt; Abhilfe: denselben publish mit `--replace-witnesses` wiederholen;
    - nach SIGKILL ohne zweite Zeile: `witnesses.rec` ansehen, dann denselben publish wiederholen.
    - Der veraltete Satz zu Nr. 85 entfällt.
  - **RUNBOOK 7.3 und 8.6:**
    - Tausch einer regulären Datei nach `Lstat` gegen FIFO, Verzeichnis, Gerät oder Socket ergibt `errChanged`, auch bei wiederverwendeter Inode-Nummer. Ein Rücktausch vor dem zweiten `Lstat` liefert den rohen Fehler (Restfenster).
    - „is gone“ auch nach einem gescheiterten Öffnen.
    - Die Zeile `store: <name> is not a regular file` ersetzen durch die beiden langen Meldungen aus Nr. 94, wörtlich; die Variante „written meanwhile“ eingeschlossen.
    - Restfenster beim Gerät: Ein vorhandener Gerätknoten lässt sich ohne `CAP_MKNOD` hinlegen.
    - Grenze: NFS/FUSE.
  - **D93:** Nachtrag 28 A.
  - **AUDIT R17 (b):** Restgrenzen nach 28.
  - **Liste:** Nr. 85, 93, 94 erledigt. Nr. 95: Testteile erledigt, Hinweise offen. Neue niedrige Reste aus 20-notes (28A, 28A2), kurz.
- **28B (`check-release.sh`):**
  - **RUNBOOK 0.2:**
    - neue Meldungen wörtlich: `testing.tRunner` und `testing.MainStart`. Ein Testprogramm zeigt meist beide;
    - `GOFLAGS=-json=false` wird gesetzt;
    - „go version gescheitert“ ohne GOFLAGS als Ursache;
    - Grenzen genauer (`tr`, das Teile verliert).
  - **AUDIT R35 und die Belegtabelle:** dasselbe, dazu `TestReleaseSwitches` mit der strengen Regel (jeder Selektor Environ/Getenv/LookupEnv/ExpandEnv, jeder Punkt-Import, `os` nach Importpfad).
  - **Liste:** Nr. 96, 97 erledigt. Neu: Symlink auf eine Go-Datei wird nicht geprüft; ignorierte Dateien (`_`/`.`) werden geparst.
- **28C (`unprocessed`, Warnungen):**
  - **RUNBOOK 4.5 und 8:**
    - Sammelwarnung ab zehn Mails je Aufruf, wörtlich, am Ende des Aufrufs, auch wenn Search mit Fehler endet;
    - Weg zu den übrigen Mails (etwa `find … ! -type f -o ! -perm -u=r`);
    - Urteile wiederholt Search bei jedem Aufruf bis zum nächsten Index-Lauf;
    - die Ursache „Datei nicht lesbar“ jetzt auch für Nicht-Dateien an anderen Stellen. Dazu die geänderten Warnungen wörtlich: „Epochenkette … bricht … ab“, auch bei `Read`, sowie „folders.gml … ist ungültig“;
    - „Prüfung fehlgeschlagen“ kann auch ein Lesefehler des Systems sein.
  - **D91:** Nachtrag 28 C (`unreadableCause` ersetzt `fileUnreadable`; `warnCause` kennt `ErrNotRegular`).
  - **AUDIT R27 (b):** Testlücken geschlossen. Der Test für „grew beyond“ braucht CAP_SYS_ADMIN (fanotify) und überspringt sich sonst. Im Abnahmelauf als root prüfen, dass er nicht übersprungen wird.
  - **Liste:** Nr. 102, 103, 104, 106 erledigt; Nr. 107 Testteile erledigt, Rest offen. Neu:
    - `checkMeta` macht Lesefehler still;
    - Zwischenspeicher je Aufruf in `indexEpoch` (100 000 Einträge: 13,7 GiB);
    - eigener Sentinel für Lesefehler;
    - stille unlesbare pending-Datei;
    - Härtungen am fanotify-Test;
    - Sammelwarnung je Aufruf ungetestet (P8).
- **28D (`store.ReadFileLimited`):**
  - **D48:** Nachtrag 28 D. Vorbelegung mit Größe + 1, Verdoppelung bis zum Limit, Kopie bei kurzem Ergebnis. Allokation an der Grenze 1,0 ×, im Wachstumsfall höchstens etwa 2 ×, im konstruierten schlimmsten Fall mit Kopie 2,5 ×.
  - **HANDOFF:** Zeile zu `ReadFileLimited`.
  - **AUDIT 6.2:** die neuen Tests.
  - **Liste:** Nr. 105 erledigt. Bei Nr. 99 vermerken, dass der Aufwand je Eintrag etwa halbiert ist. Neu:
    - erster Read bei Stat 0 nur 1 Byte (Sonderdateien über einen Link: EINVAL statt `ErrTooLarge`);
    - 2,5 × im schlimmsten Fall;
    - kein Test gegen leeren Lesepuffer;
    - 386-Grenze ab 2 GiB;
    - `max = MaxInt64` liefert leer ohne Fehler.
- **HANDOFF:**
  - Nachtrag 28g im Kopf, im Stil von 27g. Code-Stand „Arbeitsbranch nach Auftrag 28“; die Commits trägt der Orchestrator ein.
  - Kurz in „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“: Die offenen Haltepunkte und Entscheidungen bleiben die aus 27g.
- **Liste nach M1:** Nachtrag 28g im Kopf.

## Fertig

- Ein Commit mit `Task: docs/tasks/28g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt.
- Bericht: geänderte Stellen, offene Punkte, Abweichungen zwischen Code und Notizen.
