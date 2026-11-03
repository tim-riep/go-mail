# Auftrag 21d: Widerruf über Pin-Feld 7 – Spezifikation und Betriebsdoku (D93, nur Dokumentation)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 92e43ad oder später, eigener Worktree.
- Darf ändern: `docs/PLAN.md` (nur 2.3, 9.2 und 10.1 S9, mit Vermerk „Änderung nach D93“), `docs/SPEC-ISSUES.md`, `docs/RUNBOOK.md` (7.3 neu und Verweise), `docs/tasks/21-runbook-draft.md` (neu, falls Teile erst nach dem Code passen).
- Grundlage: D93; Entscheidungsvorlage `docs/tasks/q19-q8-entscheidungsvorlage.md`; Q8, Q19; SPEC-ISSUES S24, S25, S28, S76.
- Code entsteht parallel in 21a–21c; Befehlsnamen und Optionen: `gomail-ceremony succeed --compromised --revoke-at-size N --revoke-at-time T`, `gomail-ceremony revoke --role admin|ingest --generation g --revoke-at-size N --revoke-at-time T`, `gomail-ceremony admin-rotate`. Wo das Verhalten vom Code abhängt, als „vorläufig, Abgleich nach 21c“ markieren.

## Umfang

1. PLAN 2.3: Widerruf über Pin-Feld 7 (Rolle, Generation, Logposition, Zeitpunkt), was davor gültig bleibt, Pflicht zur Neuausstellung nach `succeed --compromised`, kompromittierter Root → neuer `init` mit neuem Origin; Admin-Ablösung. 9.2: neue Befehle. 10.1 S9 unverändert im Wortlaut, Verweis auf D93.
2. RUNBOOK 7.3 neu: Ablauf bei Verdacht auf Kompromittierung (Kopf mit Zeugenbestätigung ablesen und `size`/Zeit notieren; Zeremonie; Neuausstellung; Pin verteilen; Server neu starten; Prüfen). Für Ingest und Admin getrennt.
3. Aus dem RUNBOOK-Durchgang (`/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/runbook-walkthrough.md`) M5 und M8: in 7.3 bei neuer Plattform ein neues `--dir` verlangen (alte Client-Verzeichnisse nicht löschen) und Betriebsregeln für einen kompromittierten oder verlorenen Ingest- oder Admin-Schlüssel.
4. SPEC-ISSUES: S24, S25, S28 (Q8-Anteil), S76 auf „durch D93 erledigt“ setzen bzw. Stand nachführen.

## Fertig

- Ein Commit mit `Task: docs/tasks/21d-revocation-docs.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl21d/notes.md`. Keine Testläufe außer `TestRunbook` am Ende, falls RUNBOOK-Befehle geändert wurden.
