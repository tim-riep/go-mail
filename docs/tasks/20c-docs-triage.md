# Auftrag 20c: Einordnung der Hinweise, AUDIT nach D91, HANDOFF-Entwurf (Teil der Abnahme, nur Dokumentation)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei bf427c2 oder später, in einem eigenen Worktree.
- Darf ändern: nur `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/tasks/20-notes.md` und neu `docs/tasks/20-triage.md`. Kein Code, keine Tests, keine anderen Dokumente. Wo DECISIONS, SPEC-ISSUES oder RUNBOOK etwas brauchen, steht es als Vorschlag in `20-triage.md`; der Orchestrator übernimmt es.
- Parallel läuft Auftrag 20b (`docs/tasks/20b-small-fixes.md`, Produktivcode). Seine Punkte gelten in der Einordnung als „in 20b“.
- Lies: `docs/PLAN.md` 10.1, 10.2, 12; `docs/ORCHESTRATION.md` Abschnitt 1 (M1-Kriterien A–F) und Verlauf; `docs/DECISIONS.md` ab D79, besonders D84 bis D91; `docs/AUDIT.md`; `docs/HANDOFF.md`; `docs/tasks/20-notes.md`; `docs/tasks/20-acceptance.md`.

## Umfang

1. **Einordnung** (`docs/tasks/20-triage.md`): eine Tabelle über jeden Punkt in `docs/tasks/20-notes.md`, mit Abschnitt, Kurzbeschreibung und genau einer Klasse:
   - erledigt (mit Beleg: Commit, Testname, D-Eintrag oder Datei und Zeile);
   - in 20b;
   - in 20 (nur Testcode oder Dokumentation, mit Ort);
   - Produktivcode, nicht in 20b (Vorschlag an den Orchestrator);
   - bekannte Grenze (wohin: AUDIT-Rnn, HANDOFF, SPEC-ISSUES).
   Prüfe „erledigt“ am Code (`grep`, Test vorhanden), nicht am Wortlaut der Notizen. Am Ende eine Liste der Vorschläge für DECISIONS, SPEC-ISSUES und RUNBOOK mit genauem Text.
2. **AUDIT auf den Stand nach D91:** Kopf (Stand, Commit 3e06f23 für den Code), R27 (der Text unter „Der folgende Text beschreibt den Stand vor 09b“ wird durch den gebauten Zustand ersetzt), 6.5 (Dieb mit altem Schlüsselspeicher, Zeile mit `Checked`), 8.1 Punkt 3 und jede andere Stelle, die noch `TODO(S13)`, „strengste Lesart für Metadaten und Segmente“ oder die doppelten Begriffsregeln beschreibt. Belege mit Datei und Funktion aus `internal/client/accept.go`, `devicelost.go`, `index.go`, `internal/terms`. Die Wachstumsgrenze aus D91 mit Formel und Messwerten. Die Punkte aus `20-notes.md`, die dort als „AUDIT in 20“ stehen und erledigt werden können, ebenfalls.
3. **HANDOFF-Entwurf:** `docs/HANDOFF.md` auf den heutigen Stand bringen, nach dem Aufbau, den die Datei schon hat. Inhalt mindestens: Stand je M1-Kriterium A–F mit dem, was fehlt (ehrlich, nichts als erfüllt ausgeben, was nicht belegt ist; Messungen, Fuzzing, Abdeckung und Abnahme laufen noch und bekommen Platzhalter „wird mit Auftrag 20 eingetragen“); wie man baut und testet (Tags `gomail_dev,gomail_test`, Laufzeiten, `GOMAIL_TEST_MIN_FREE`); bekannte Grenzen mit Verweis auf AUDIT; offene Fragen Q18, Q19, Q20 mit Stand; die Punkte aus `20-notes.md`, die dort als „HANDOFF“ stehen.

## Fertig

- Nur die vier genannten Dateien geändert. Jede Aussage über den Code mit Datei und Funktion oder Testname belegt; jede Aussage über eine Entscheidung mit D-, Q- oder S-Nummer.
- Ein Commit mit `Task: docs/tasks/20c-docs-triage.md`, ohne Co-Authored-By. Nicht pushen.
- Der Container startet etwa stündlich neu. Committe nach jedem der drei Punkte einen WIP-Stand im Worktree und halte in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20c/notes.md` fest, was fertig ist. Am Ende die WIP-Commits zu einem zusammenfassen.
- Bericht: Zahl der Punkte je Klasse; Liste „Produktivcode, nicht in 20b“; Vorschläge für DECISIONS, SPEC-ISSUES, RUNBOOK; was in AUDIT und HANDOFF geändert wurde.
