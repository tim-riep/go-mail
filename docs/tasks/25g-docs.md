# Auftrag 25g: Doku-Nachzug zu Auftrag 25 (Pakete 25A bis 25D)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i` (mit Auftrag 24 zusammengeführt), eigener Worktree. Nur Dokumentation, keine `go`-Befehle.
- **Den Code liest du** im Arbeitsbranch für alles vor Auftrag 25 und für die Pakete mit `git show <commit>:<pfad>`:
  - 25A: Endstand 9fd2156 (25A f6420a6, 25A2 4b37e6d, 25A3 9fd2156). Kommt nach der Nachprüfung von 25A3 eine weitere Nacharbeit, nennt der Orchestrator den neuen Endstand.
  - 25B: 23fc312 (25B 704ff09, 25B2 23fc312)
  - 25C: 4f4535f (25C aaf2bd8, 25C2 4f4535f)
  - 25D: 79bd462 (25D 8270349, 25D2 3beee11, 25D3 79bd462)

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe „Auftrag 25, Paket 25X“ statt eines Hashes.
- **Quellen:**
  - `docs/tasks/25-nach-m1-nacht1-runde2.md`;
  - `docs/tasks/20-notes.md`, Abschnitte „Auftrag 24 … Prüfungen“ (Eintrag 24g) und „Auftrag 25 … Prüfungen“;
  - die Notizen der Implementierer unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/`: `impl25a/`, `impl25a2/`, `impl25a3/`, `impl25b/`, `impl25b2/`, `impl25c/`, `impl25c2/`, `impl25d/`, `impl25d2/`, `impl25d3/` (je `notes.md`);
  - die Diffs gegen den Arbeitsbranch vor Auftrag 25 (8a58052).
- **Darf ändern:**
  - `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/MEASUREMENTS.md` (nur den Absatz „Messcode“), `docs/tasks/backlog-nach-m1.md`;
  - `docs/DECISIONS.md`, nur als Nachträge an bestehende D-Einträge.

## Umfang, je Paket am Code prüfen

- **25A (`publish`):**
  - **RUNBOOK 7.3, „Zertifikate des Diebs“:** Der Absatz „Liegt keine der beiden Dateien dort … scheitert erst beim Loggen …“ ist überholt. Ein fehlender Name, dessen gültiger Logeintrag anderen Inhalt hat, wird jetzt vor dem Schreiben abgelehnt. Abhilfe bei `.succ`: RUNBOOK 7.3.1.
  - **RUNBOOK 7.3, „Fremde Dateien in `platform/`“, Fall 4 und folgende:**
    - Ein Link oder harter Link wird nie gelesen oder geloggt. Das gilt unter einem Namen des Exports, unter `witnesses.rec` und unter einer Nachfolge, die `publish` nachloggen würde.
    - Eintrag zwischen `Lstat` und Lesen gewechselt: Meldung `errChanged`.
    - `.tmp-*` werden unter der Serversperre entfernt und einzeln gemeldet, auch wenn `publish` danach ablehnt.
    - `platform/` als Link wird abgelehnt (mit Ziel), ebenso ein fehlendes `platform/`.
    - Restfenster nennen: Ein Tausch von `platform/` oder eines Eintrags nach der letzten Prüfung ist nur mit fremdem Schreibrecht auf `data/` möglich. Ein Bind-Mount ist nicht erkennbar. Ein `cp -al`-Schnappschuss macht jede Datei zu einem harten Link.
    - Den Prüfbefehl nach `publish` nennen: `find … \( -type l -o -type f -links +1 \)`.
  - **RUNBOOK 7.2:** Ein Link als `witnesses.rec` wird ohne `--replace-witnesses` abgelehnt und mit dem Schalter ersetzt, ohne gelesen zu werden. Die Ersatzzeile erscheint sofort, auch wenn `publish` danach scheitert.
  - **RUNBOOK 8.6:**
    - Neue Zeilen für jede neue Meldung aus 25A, 25A2 und 25A3, wörtlich aus dem Code, mit Exit-Code und Abhilfe.
    - Die Zeile „written meanwhile“ auf den heutigen Stand bringen.
    - In der Zeile zu „a valid entry is never replaced“ die Abhilfe für eine `.succ` ergänzen.
  - **D93:** Nachtrag 25 A.
  - **AUDIT R17:** Restgrenzen nach 25. Geschlossen sind F3, N1 (`.tmp`), N3, `witnesses.rec`, Nachloggen durch Links, L1 und L2. Offen bleibt der Tausch von `platform/` während des Laufs (Abhilfe `os.Root`).
- **25B (Client-Verzeichnis):**
  - **RUNBOOK 3.2 und 8.6:** Die beiden Meldungen wörtlich, mit `<errno-Text>` als Platzhalter:
    - `client: cannot check that the client directory is outside the data directory: <errno-Text>`
    - `client: the client directory must not be inside the data directory`
    - Wann welche kommt; unter einer Datei kommt „not a directory“.
  - **D86:** Nachtrag 25 B.
  - **AUDIT R33:** Die Restgrenze „Meldung bei ‚Prüfung nicht möglich‘“ ist geschlossen.
- **25C (`loghttp`):**
  - **AUDIT R8:**
    - `publish()` wird nur bei neuer Zeile aufgerufen.
    - `SlotWait` 5 s, mit Begründung und Messwerten aus `impl25c/notes.md`.
    - Eine Anfrage lebt bis etwa `ReadTimeout + SlotWait`.
    - Der Server spricht nur HTTP/1.1; hinter einem multiplexenden Proxy muss eine Grenze je Quelle Anfragen zählen, nicht Verbindungen.
    - `Tick` wiederholt die Veröffentlichung vor einem neuen Kandidaten.
    - Rest: keine Verbindungsgrenze, keine Rate je Quelle. Der Kopf mit Quorum geht nur verloren, wenn `PublishHead` zweimal scheitert und der Kandidat wechselt.
  - **D80:** Nachtrag 25 C, nur wenn D80 Nachtrag 24 D den alten Stand beschreibt.
- **25D (`bench.sh`):**
  - **MEASUREMENTS „Messcode“:** 25D ändert nur Darstellung und Prüfungen. Messlogik und Tabellen der vier Läufe bleiben gleich.
  - **D94:** Nachtrag 25 D:
    - Quoting, Soll-Liste `wantnames` (von Hand gepflegt), gawk/onetrue awk/busybox;
    - Rohdaten bleiben bei Abbruch erhalten (Pfad auf stderr);
    - Prüfungen vor der Messung mit Exit 2;
    - relatives `TMPDIR` ab dem Aufrufverzeichnis.
  - **RUNBOOK:** Gibt es einen Abschnitt zu `bench.sh`, dort dasselbe kurz.
- **24g-Reste** (20-notes, Eintrag 24g):
  - RUNBOOK 8.6 `adminKeyMismatch`: Ursache „oder lässt sich aus einem anderen Grund nicht öffnen oder lesen“.
  - RUNBOOK 7.3 Fall 3 und 8.6: „nicht geloggt“ → „keinen gültigen Logeintrag“.
- **Liste nach M1 (`docs/tasks/backlog-nach-m1.md`):**
  - Nr. 64, 65, 68 und 71 als erledigt mit „Auftrag 25, Paket 25X“ markieren, wenn der Code das trägt; sonst Teil erledigt mit Rest.
  - Neue niedrige Reste aus den Prüfungen von 25 als neue Nummern, kurz:
    - `platform/` über `os.Root`/`unlinkat` gegen Tausch während des Laufs;
    - `Store.RemoveTempFiles` mit Unlink;
    - `translog.operatorLog.PublishHead` ohne `refuse(tree)`;
    - `loghttp`-Paketkommentar „…, once SignHead yields one“;
    - `bench.sh`: TERM nur an bash lässt `go test` weiterlaufen;
    - Test für `wantnames` gegen `internal/bench`;
    - `TestClientDirLeftovers` ohne Rechte;
    - weitere, wenn in 20-notes als niedrig genannt und nicht behoben.
- **HANDOFF:**
  - In „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“ die Änderungen aus Auftrag 25 kurz nennen.
  - Nachtrag 25g im Kopf, im Stil von Nachtrag 24g. Code-Stand „Arbeitsbranch nach Auftrag 25“; die Commits trägt der Orchestrator ein.

## Fertig

- Ein Commit mit `Task: docs/tasks/25g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt. Platzhalter in spitzen Klammern sind erlaubt.
- Bericht: geänderte Stellen und offene Punkte.
