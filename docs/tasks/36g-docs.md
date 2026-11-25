# Auftrag 36g: Doku-Nachzug zu Auftrag 36 (36A, 36B) und Hinweise aus 34g

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, mit derselben Ausnahme wie bei 34g.

- **Basis:** Arbeitsbranch, aktueller Stand, eigener Worktree. Ein Commit mit `Task: docs/tasks/36g-docs.md`, ohne Co-Authored-By, ohne Claude-Session-Zeile, ohne Modellnamen; nicht pushen. Nur Dokumentation, keine `go`-Befehle außer `go env`. Patch danach nach `scratchpad/patches/36g.patch`.
- **Code:** 36B ist zusammengeführt (8024b51). 36A liegt als Patch `docs/tasks/patches/36a-558ce2b.patch` (auf c8cda58) vor und ist in Prüfung; Merge-Hash und Volllauf trägt der Orchestrator ein (Platzhalter „die Commits und den Volllauf trägt der Orchestrator ein“). Zum Lesen den Patch in einer eigenen Kopie anwenden.
- **Quellen:** `docs/tasks/36-nach-m1-nacht4b.md`; `docs/tasks/20-notes.md`, Einträge „34g“, „36A“, „36B“; ORCHESTRATION Abschnitt 14; Notizen `scratchpad/impl36a/notes.md` (Tabelle zu Nr. 128), `scratchpad/impl36b/notes.md`, `scratchpad/rev36b/notes.md`.
- **Darf ändern:** `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/backlog-nach-m1.md`, `docs/DECISIONS.md` (nur Nachträge).

## Umfang

1. **36A:** RUNBOOK 7.2/7.3/8.6 die geänderten Meldungen wörtlich („…, moved to <aside>, is X, not the file written, and stays there: …“ u. a.); D93 Nachtrag 36 A (Temp-Name vor dem Entfernen beiseite, Fenster 2 geschlossen, neues Fenster 2', Verhalten bei scheiterndem rename); AUDIT R17 (b) und 6.2 (neue Tests, Wettlaufzahlen aus 20-notes); Liste Nr. 127 entsprechend.
2. **Nr. 128:** Liste und HANDOFF: Ergebnis der Untersuchung kurz (Sperren je Aufrufer, rmdir-Rückfall der Pfad-Varianten) und der **neue Haltepunkt** `WriteAccept` ohne Postfachsperre als **Entscheidung des Auftraggebers** (Wege: Annahme unter die Postfachsperre legen oder nur den Typ prüfen), auch in HANDOFF Punkt 9 und „Bekannte Grenzen“.
3. **36B:** AUDIT R35 und RUNBOOK 0.2 (Verzeichnis direkt an `skippedTagged`, `os.Stat` nur für Links, Dauertausch-Beleg); Liste Nr. 125 N1 und R01/R04 erledigt; Hinweis H1 der Prüfung (Link mit scheiterndem `os.Stat` still nicht durchsucht) als neuer niedriger Rest.
4. **Hinweise aus 34g** (20-notes „34g“): F1 RUNBOOK 8.6 Zeile der Ankündigung; F2 Nr. 108 und Köpfe; F3 Ursachen von `was not replaced` und Zeile `is unchanged`; F4 HANDOFF Punkt 1 dritter Zustand; F5 Stil.
5. **Köpfe:** Nachtrag 36g in HANDOFF, AUDIT, Liste.

## Fertig

Ein Commit; Meldungen wörtlich wie im Code; Bericht mit geänderten Stellen und neuen Nummern. Notizen `scratchpad/impl36g/notes.md`.

## Nacharbeit 36g2

Ausgangspunkt ist der Patch `docs/tasks/patches/36g-171436a.patch` (auf fc49c68). Ergebnis ist genau ein Commit, der 36g insgesamt enthält, auf dem aktuellen Arbeitsbranch. 36A ist inzwischen als Nacharbeit 36A2 neu gefasst (Patch `docs/tasks/patches/36a2-24c35c6.patch` auf c8cda58): Scheitert das Umbenennen auf `aside`, fällt `store` auf das geprüfte Entfernen wie vor 36A zurück; damit entfällt die neue Ablehnung bei `ENOSPC` nach dem Link (F1 der Prüfung 36g), die Temp-Datei bleibt bei `ENOSPC` nicht mehr liegen, und die Meldung bei `chattr +a` nach dem Link ist wieder `unlink <tmp>: operation not permitted`. Alle Aussagen zu 36A am Code von 24c35c6 prüfen und anpassen (auch die Prüfstatus: 36A erste Runde von beiden Prüfern abnahmefähig, Nacharbeit 36A2 in Prüfung). Dazu aus der Prüfung 36g (20-notes „36g“, `scratchpad/rev36g/notes.md`): F2 (Verweis auf `docs/tasks/36a-untersuchung-128.md` statt Scratchpad) und H1–H5 mit den Textvorschlägen; H2 Entscheidungshilfe zu `WriteAccept` aufnehmen. Fenster 2' und die Gründe gegen einen Unterordner 0700 (Notizen `scratchpad/impl36a2/notes.md`, Kommentar an `dropTemp`) kurz nennen.

## Nacharbeit 36g3

Ausgangspunkt: aktueller Arbeitsbranch, darauf der Patch `docs/tasks/patches/36g2-28924d8.patch` (36g insgesamt). Ergebnis: **ein weiterer Commit** darauf (nicht zusammengefasst), mit `Task: docs/tasks/36g-docs.md`. Umzusetzen: die niedrigen Funde (1) und (2) und die Hinweise 3–6 der Prüfung von 36g2 (20-notes „36g2“, Textvorschläge in `scratchpad/rev36g2/notes.md`); bei (2) die Köpfe auf „(20-notes „36A“ und „36A2 Bericht“; ORCHESTRATION Abschnitt 14)“ umstellen; dazu die Hinweise H1 und H4 der Prüfung von 36A2 (20-notes „36A2“) nur als Textstellen in der Liste (Nr. 127), falls dort nicht schon genannt.

## Nacharbeit 36g4 (25.11.2026, nach dem Merge von 36A)

Ausgangspunkt: aktueller Arbeitsbranch (053e9cc oder später). Ergebnis: ein Commit, nur Dokumentation, mit `Task: docs/tasks/36g-docs.md (Nacharbeit 36g4)`. Notizen `scratchpad/impl36g4/notes.md`. Code von 36A ist zusammengeführt als bde271b (gleich 836f28c auf c8cda58; Nacharbeit 36A3 ändert gegenüber 24c35c6 nur `internal/store/fsroot36a_linux_test.go`).

1. **Köpfe und Nr. 127 glätten:** Der Orchestrator hat beim Merge den Platzhalter in HANDOFF (Nachtrag 36g), AUDIT (Nachtrag 36g), Liste (Kopf und Nr. 127) und DECISIONS (D93 Nachtrag 36 A) mit einem langen Einschub gefüllt. In Nr. 127 und in den Köpfen stehen danach widersprüchliche Angaben („Endstand 24c35c6“ neben „Endstand 836f28c“, „36A2 in Prüfung“ o. ä.). Fasse sie je Stelle zu einer stimmigen Aussage: 36A mit 36A2 und 36A3, Endstand 836f28c auf c8cda58, zusammengeführt als bde271b; Doku 36g2/36g3 als b7822a2/95c688d; Volllauf 67/67 am 25.11. bis 03:48 UTC (`fr-n36a` 63, PTY-Schritt einmal wiederholt, drei Store-Schritte in `fr-n36a3`); alle Prüfer abnahmefähig (36A, 36A2, 36A3 je zwei). Kein Inhalt geht verloren.
2. **36A3:** AUDIT 6.2: `TestWriteTempInErrorSwapped` läuft je Fall in einem Kindprozess (nur dieser senkt `RLIMIT_FSIZE`), mit Grund. In Nr. 127 den Hinweis „`RLIMIT_FSIZE` im Test gilt für den ganzen Prozess“ als erledigt mit 36A3 vermerken. **Neue Zeile Nr. 130** (Test, niedrig): die niedrigen Funde und Hinweise der Prüfungen von 36A3 (20-notes „36A3“): Wächter in `limitFileSize` scheitert erst nach 60 s; Frist des Kinds gleich der des Elternprozesses (Ausgabe verloren, Kind läuft bis zu 60 s weiter); kein Beleg, dass der Rumpf im Kind lief; PASS/SKIP-Suche nicht am Zeilenanfang; keine Abdeckung aus dem Kind; `-cpu`/`-short`/`-timeout` nicht weitergegeben; von außen gesetzte Variable `GOMAIL_STORE_TEST_FSIZE_CHILD` schaltet den alten Weg ein. Vorschläge aus 20-notes.
3. **Reste aus 36g3:** der niedrige Fund der Prüfung von 36g3 (H2 der Spezifikationsprüfung von 36A2 fehlt in Nr. 127; 20-notes „36g3“); HANDOFF: „Fenster 2 geschlossen“ nur mit „solange das Umbenennen auf den neuen Namen gelingt“ (sonst Rückfall wie auf c8cda58).
4. **Zählzeile** der Liste fortschreiben (Nr. 130 mit 36g4 aus den Prüfungen von 36A3).

Keine Änderung an Code, Skripten, Tests oder Vektoren; keine neuen D-Einträge (Nachträge an D93 erlaubt).
