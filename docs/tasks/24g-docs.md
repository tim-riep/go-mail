# Auftrag 24g: Doku-Nachzug zu Auftrag 24 (Pakete A bis F)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.

- **Basis:** Arbeitsbranch `claude/quirky-keller-hjsl5i`, eigener Worktree. Nur Dokumentation, keine `go`-Befehle.
- **Den Code liest du** in der gemeinsamen Quelle `orch/n24` (lokaler Branch: Arbeitsbranch mit A, B, C, E, F) mit `git show orch/n24:<pfad>`, dazu für D `git show 7e054c9:<pfad>` (Paket D mit Nacharbeit; wird nach seiner Nachprüfung ergänzt).
- **Die Commits je Paket:**
  - A: cdd01fd und 4bef43b
  - B: caac1df und bc0f73b
  - C: 6464b71, f427f65, e6abee7, 9414fcd
  - D: 8c924de und 7e054c9
  - E: e597ccf
  - F: fa41def und cde26fe

  Die Hashes nach dem Merge trägt der Orchestrator ein. Schreibe deshalb „Auftrag 24, Paket X“ statt eines Hashes.
- **Quellen:**
  - `docs/tasks/24-nach-m1-nacht1.md`
  - `docs/tasks/20-notes.md`, Abschnitt „Auftrag 24 … Prüfungen“
  - die Notizen der Implementierer unter `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl24a/notes.md` bis `impl24f/notes.md`, außerdem `impl24b/` (B2), `impl24d2/` (D2), `impl24c/notes.md`
  - die Diffs gegen 8ec3da5
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/DECISIONS.md` (nur Nachträge an bestehende D-Einträge), `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`, `docs/SPEC-ISSUES.md` (nur „Stand“-Zeilen von S88 und S89).

## Umfang, je Paket am Code prüfen

- **A (`publish`):**
  - RUNBOOK 7.3, „Fremde Dateien in `platform/`“, Fall 4: Symlinks und harte Links (`Nlink > 1`; `.tmp-*` zählt nicht) unter einem Namen des Exports gelten nie als gleich. Ist der Name frei, ersetzt `publish` den Eintrag, sonst erscheint `linkErr` mit Hinweis. FIFO, Gerät und Verzeichnis werden abgelehnt (`is not a regular file`). „written meanwhile“ prüft mit `readEntry`. F4 (`sameButLogged`) gilt auch für Dateien.
  - `witnesses.rec` und nachgeloggte Nachfolgen folgen Links weiter.
  - `find … \( -type l -o -links +1 \)`.
  - RUNBOOK 7.3, „Zertifikate des Diebs“: F4 und die neuen Meldungen.
  - RUNBOOK 8.6: neue und geänderte Zeilen, Meldungstexte wörtlich aus dem Code.
  - D93: Nachtrag 24 A.
  - AUDIT R17 (b): Restgrenzen F3 (ohne `O_NOFOLLOW`) und `.tmp`-Name.
- **B (`resolveExisting`):**
  - D86: Nachtrag 24 B. Auflösung Stück für Stück, fail closed bei Fehlern außer ENOENT und ENOTDIR, bei mehr als 40 Sprüngen und bei relativen Pfaden. Hingenommene Folge: Pfade über PATH_MAX und Elternverzeichnisse ohne Suchrecht werden abgelehnt.
  - Die „Bekannte Lücke“ aus Nachtrag 22 ist geschlossen.
  - AUDIT R33: Restgrenze (e) wird ersetzt. Neue Restgrenzen: Meldung `ErrInsideDataDir` bei „Prüfung nicht möglich“; Bind-Mount nicht erkannt (rein pfadbasiert).
  - RUNBOOK 3.2 / 8.6: die Meldung bei EACCES.
  - SPEC-ISSUES S88 und S89: „Stand“ mit den neuen Tests.
- **C (`address add`):**
  - RUNBOOK 4.2, „Uhr“: `valid_from` = max(jetzt, letzter gültiger Wert + 1 ms) bis `MaxClockSkew`, sonst Exit 1. Zwei Aufrufe in derselben Millisekunde ergeben zwei Einträge.
  - RUNBOOK 8.6: `adminCertInvalid`, Ursache bei `adminKeyMismatch`, `valid_from does not increase` erst ab 5 min.
  - D80: Nachtrag 24 C. Dabei ist der Satz zu `errSame` aus 20j überholt.
  - D93 Nachtrag 23 und AUDIT R48: Die Restgrenze zu `address add` ist geschlossen; Beleg sind die Tests.
- **D (`loghttp`):**
  - AUDIT R8: Typprüfung vor dem Körper; `MaxVerifying` gilt nur für die Prüfung, mit `SlotWait`. Der wiederholt gesendete veröffentlichte Kopf schreibt nicht mehr neu. `Connection: close` bei 400, 404, 405, 413, 503 und bei GET mit Körper.
  - Rest: keine Verbindungsgrenze und keine Rate je Quelle.
  - Protokollkommentar `witness` nur als Vorschlag im Bericht, denn Code ändert dieser Auftrag nicht.
  - Ein D-Eintrag nur, wenn ein passender bestehender D-Eintrag vorhanden ist (prüfen, z. B. zu `loghttp`/Zeugen); sonst AUDIT.
- **E:**
  - HANDOFF Kriterium B und das TODO-Inventar: Die 11 Marken sind ersetzt, `TODO(task-15b)` ist entfallen.
  - AUDIT R48: Die Restgrenze M4 ist geschlossen (`TestReadPlatformCertRawReadsOnce`).
  - D94: Nachtrag 24 E (`-render` mit entquoteten Werten und den neuen Ablehnungen); Restgrenzen N1 und N2 aus der Prüfung von E.
  - MEASUREMENTS „Messcode“: E ändert nur `render`.
  - Notiz zu `GOOS=solaris`/`illumos go vet`.
- **F:**
  - AUDIT R41: `store.ReadDir` an 16 Stellen und `emptyDir`. Dazu der Befund, dass `os.ReadDir` schon `O_DIRECTORY` nutzt. Die Restgrenze `emptyDir` ist geschlossen; als Rest bleibt `keys.ReadKeystoreFile` (nur testenv).
  - AUDIT 6.2: Tabellenzeile zu FIFO.
- **Liste nach M1 (`docs/tasks/backlog-nach-m1.md`):**
  - Nr. 7 (Teil), 37, 41, 52 (Testteil und Vet-Teil als Notiz), 53, 54 bis 63 als erledigt mit „Auftrag 24, Paket X“ markieren.
  - Neue niedrige Reste aus den Prüfungen als neue Nummern aufnehmen. Die Liste steht in 20-notes; kurz halten.
- **HANDOFF:** In „Bekannte Grenzen“ und „Was die nächste Phase als Erstes wissen muss“ die Änderungen aus Auftrag 24 kurz nennen. Einstieg: Code-Stand „Arbeitsbranch nach Auftrag 24“; den Commit trägt der Orchestrator ein.

## Fertig

- Ein Commit mit `Task: docs/tasks/24g-docs.md`, ohne Co-Authored-By und ohne Modellnamen. Nicht pushen.
- Jeder Meldungstext steht wörtlich so, wie ihn der Code ausgibt; Platzhalter in spitzen Klammern sind erlaubt.
- Bericht: die geänderten Stellen und offene Punkte.
