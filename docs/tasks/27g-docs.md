# Auftrag 27g: Doku-Nachzug zu Auftrag 27 (Pakete 27A bis 27D; Nr. 88 angehalten)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich. Ausnahme: Dieser Auftrag erlaubt Nachträge an bestehende D-Einträge in DECISIONS und den Nachtrag in HANDOFF (wie 25g und 26g).

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, eigener Worktree, nur Dokumentation, keine `go`-Befehle.
- **Code der Pakete** liest du mit `git show <commit>:<pfad>`. Endstände je Paket, jeweils ein Commit auf beff425:
  - 27A: 092e61b (Runden 24db78e, 092e61b)
  - 27B: d37e722 (Runden e6f5954, 12a91fa, d37e722)
  - 27C: c3614ec (Runden 81705e1, 26ab41f, c3614ec)
  - 27D: 588a20c. Das ist 0ca55c5 ohne die Änderung an Nr. 88; `internal/bench/script_test.go` bleibt auf dem Stand von beff425.

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe „Auftrag 27, Paket 27X“.
- **Quellen:**
  - `docs/tasks/27-nach-m1-nacht2b.md`;
  - `docs/tasks/20-notes.md`, Abschnitt „Auftrag 27 … Prüfungen“;
  - `docs/ORCHESTRATION.md`, Abschnitt 10 (Einträge ab 12:53 UTC am 10.11.);
  - die Notizen unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/` in den Ordnern `impl27a/`, `impl27a2/`, `impl27b/`, `impl27b2/`, `impl27b3/`, `impl27c/`, `impl27c2/`, `impl27c3/`, `impl27d/`, `impl27d2/`, `impl27d3/` und `rev27*/` (je `notes.md`).
- **Darf ändern:**
  - `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`;
  - `docs/MEASUREMENTS.md`, nur „Messcode“;
  - `docs/tasks/backlog-nach-m1.md`;
  - `docs/DECISIONS.md`, nur Nachträge an bestehende D-Einträge.

## Umfang, je Paket am Code prüfen

- **27A (`publish`):**
  - **RUNBOOK 7.3 „Fremde Dateien in `platform/`“ und 8.6:**
    - Die Generation einer `identity-<g>.pub/.succ` zählt nach dem Namen, egal welcher Typ der Eintrag ist.
    - Ein Eintrag, der weder reguläre Datei noch symbolischer Link ist (FIFO, Gerät, Verzeichnis, Socket), wird unter jedem Namen aus Abschnitt 4 nach dem Typ aus `Lstat` abgelehnt, vor jedem Öffnen. Das gilt auch außerhalb des Exports und unter `admin-/ingest-<g>.pub`. Ein solcher Eintrag sperrt jedes `publish`, bis er von Hand entfernt ist.
    - Die neuen Meldungen gehören wörtlich nach 8.6: die lange Meldung „… is not a regular file (a FIFO, a device, a directory or a socket) under a name of section 4 …“ und die Variante für `identity-<g>` über dem Pin (Abhilfe: entfernen, kein neuer Pin).
    - Ebenso beide Varianten von `errPlatformReplaced`: „opened and wrote to; nothing logged“ und „opened; nothing written or logged“.
    - Die Zeile `store: <name> is not a regular file` passt du an. Sie gilt jetzt für `witnesses.rec`, für Wettläufe und für „written meanwhile“; im letzten Fall kann schon etwas geschrieben sein.
  - **Restfenster in RUNBOOK 7.3 und AUDIT R17:** Ein Gerät, das zwischen `Lstat` und Öffnen eingetauscht wird, wird geöffnet. Ein Tausch nach dem Listing bleibt ungesehen, wie bisher.
  - **D85:** Nachtrag 27 A. Teil 1 gilt seit 21c. Teil 2 gilt je Zustand seit 21c/22, 24A und 25A. Teil 3 kommt mit 27A. Offen bleiben der fremde Pin bei leerem `platform/` ohne Kopf und die bloße Warnung des Servers (Entscheidung).
  - **D93:** Nachtrag 27 A.
  - **Liste:**
    - Nr. 40 „teilweise erledigt (27A)“, mit den offenen Teilen.
    - Nr. 86, 87 und 90 erledigt.
    - Neue niedrige Reste aus 20-notes (27A, 27A2).
- **27B (`scripts/check-release.sh`):**
  - **RUNBOOK, Produktionsbuild:**
    - Das Skript ist ein Pflichtschritt vor der Auslieferung, mit Aufruf, Exit-Codes und Meldungen wörtlich.
    - Es braucht go, awk, tr, grep und sort im PATH.
    - Grenze: Es schützt vor versehentlicher Auslieferung, nicht vor gezielter Manipulation.
  - **AUDIT R35 und 6.2:**
    - Beleg ist `TestCheckRelease`.
    - Unter `gomail_dev` erkennt nur die Prüfung von `-tags` den Server und `gomailctl`.
  - **Liste:**
    - Nr. 19 erledigt.
    - Neu: F10 (Abgleich der Schalterliste per AST-Test) und die Hinweise aus 27B3 (`go test -c` ohne Tags, tr mit leerer Ausgabe, `GOFLAGS=-json`).
    - Die offene Frage aus `TODO(ask)` in `cmd/gomailctl/keygen_pipe_tagged.go` (Terminalregel im Testbuild) als Frage an den Auftraggeber.
- **27C (`from:`/`to:` für `unprocessed`):**
  - **AUDIT R27 (b):**
    - Der Client nimmt `from:` und `to:` aus dem Kopf der Mail, wenn ein Wert in den Metadaten länger als 4092 Byte ist oder U+FFFD enthält.
    - `Search` öffnet die Mail nur bei `from:`, `fromdomain:` und `to:`.
    - Urteil oder kein Urteil:
      - Hash, Umschlag, Kopf, Suite, Entschlüsselung und eine Datei über `MaxMailFile` sind ein Urteil. Der Marker wird gelöscht, mit Warnung, und es gelten die Begriffe aus den Metadaten.
      - Lesefehler der Umgebung sind kein Urteil. Der Marker bleibt, mit Warnung „Datei nicht lesbar“.
    - Die Warnungen stehen wörtlich im Text.
    - Restgrenzen:
      - kodierte Wörter mit Komma in ungekürzten Werten;
      - Tausch oder Vergrößern zwischen Liste und Lesen;
      - Leseaufwand bis `MaxMailFile` vor dem Hash (Prüfer 2 F2).
  - **R32:** Die Kopien von `net/mail` bleiben bis zur Speicherbereinigung.
  - **DECISIONS, Nachtrag an D91:**
    - Auswertung des Kopfs und Adressregeln stehen einmal in `internal/terms` (`HeaderOf`, `ParseHeader`, `Addresses`).
    - Dazu die Einteilung Urteil/kein Urteil.
    - Dazu die Einordnung von F2 aus 27C2 als niedrig, mit den Gründen aus 20-notes. Die Abhilfe, eine Größenprüfung vorab gegen `Meta.Size`, ist eine Prüfregel des Clients und damit eine Entscheidung des Auftraggebers.
  - **HANDOFF (`internal/terms`):** die drei Funktionen.
  - **Liste:**
    - Nr. 47 erledigt, mit Restgrenze.
    - Neu:
      - F2-Abhilfe (Entscheidung);
      - „bei jeder `unprocessed`-Mail den Kopf lesen“ (Entscheidung, aus impl27c);
      - Variante für `thread:` aus References/In-Reply-To als Hinweis zu Q12;
      - EACCES-Test;
      - Sammelwarnung;
      - `warnCause` für `ErrNotRegular`;
      - Allokation in `ReadFileLimited`;
      - Trailer-Prüfung in `openMail` ungetestet;
      - weitere niedrige Reste aus 20-notes.
- **27D:**
  - **AUDIT R48:** die Prüfung über `/proc/self/fd` (Nr. 84) mit ihrer Grenze.
  - **D94:** Nachtrag 27 D. Die FIFO wird direkt nach `mktemp` angelegt; bei einem TMPDIR ohne FIFO endet der Lauf mit Exit 2 und „nothing run“; `-render` braucht keine FIFO.
  - **MEASUREMENTS „Messcode“:** Messcode unverändert. Dazu, falls vorhanden, im RUNBOOK zu `bench.sh -dir`: Das Verzeichnis muss eine FIFO halten können.
  - **D80:** Nachtrag 27 D zum Kommentar über die Wiederholung durch `http.Transport` (Nr. 91).
  - **Liste:**
    - Nr. 84, 89 und 91 erledigt.
    - **Nr. 88 angehalten:** nach drei Runden offen (F1 hoch, F2/F3 mittel; 20-notes 27D3). Der Code bleibt beim Stand von beff425. Die drei Wege aus ORCHESTRATION Abschnitt 10 kommen als „Entscheidung des Auftraggebers“ in die Liste.
    - Beschreibe keinen Code, der nicht zusammengeführt wird.
- **HANDOFF:**
  - Nachtrag 27g im Kopf, im Stil von 26g, mit dem Code-Stand „Arbeitsbranch nach Auftrag 27“; die Commits trägt der Orchestrator ein.
  - Kurz in „Bekannte Grenzen“ und in „Was die nächste Phase als Erstes wissen muss“: alle offenen Haltepunkte und Entscheidungen:
    - 26A Listener-Grenzen;
    - Origin-Fund Nr. 92;
    - Nr. 88;
    - 27C F2;
    - die Frage aus `TODO(ask)`.
- **Liste nach M1:** Nachtrag 27g im Kopf, im Stil von 26g.

## Fertig

- Ein Commit mit `Task: docs/tasks/27g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt.
- Bericht: geänderte Stellen und offene Punkte.
