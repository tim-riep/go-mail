# Auftrag 22d: Dokumentation zu Auftrag 22 und 23 (nur Dokumentation)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree. Code-Stand zum Nachlesen: Commit 3cd9072 (Auftrag 22, Worktree `/home/user/go-mail/.claude/worktrees/agent-abc2aa7e11960965f`) und der Auftrag `docs/tasks/23-platform-single-read.md`, dessen Umsetzung noch läuft.
- Darf ändern: `docs/RUNBOOK.md`, `docs/DECISIONS.md` (nur Nachträge an D86 und D93), `docs/AUDIT.md`, `docs/tasks/20-notes.md` (nur „erledigt“-Vermerke). Keine `go`-Befehle; Code nur lesen (`git show 3cd9072:<pfad>`).
- Quellen: `docs/tasks/20-notes.md`, Abschnitte „Aus der Angreiferprüfung von 22“ und „Aus der Spezifikationsprüfung von 22“ (Vorschläge N4 bzw. die Doku-Punkte), Bericht des Implementierers in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl22/notes.md`.

## Umfang

1. RUNBOOK 7.3 und 8.6 (um Z. 490–495 und wo `publish` beschrieben ist): Eine Datei, deren Name einen gültigen Logeintrag hat, ersetzt `publish` nie durch anderen Inhalt. Eine fremde Datei unter einem geloggten Namen setzt eine Wiederholung derselben `publish`-Ausführung zurück, auch eine fremde `.pub` unter einem geloggten Zertifikat. Von Hand entfernen muss der Betreiber vier Fälle: Dateien, die sich nicht dekodieren oder verifizieren lassen; eine einzelne fremde `.pub` ohne geloggtes Zertifikat; Symlinks, auch hängende, unter `data/platform/` (N1/N2 der Angreiferprüfung). Dazu der Prüfbefehl `find data/platform -type l`. Die Prüfung „wäre nie gültig gewesen“ gilt nur für Ingest; für Admin gilt nur die Untergrenze 2025.
2. DECISIONS: Nachtrag 22 an D93 (Heilung durch `publish`, Admin-Widerruf nur mit Untergrenze, Begründung: `revoked_at_time` hat für Admin keine Bedeutung, die Admin-Gültigkeit hängt am Logindex). Nachtrag 22 an D86 (`resolveExisting` folgt hängenden Symlinks; `..` nach einem Symlink im Linkziel bleibt eine bekannte Lücke, angelegt wird trotzdem nichts). Nachtrag 23 an D93: Plattformzertifikate werden einmal gelesen; Signatur, Schlüssel und Logabgleich arbeiten auf denselben Bytes. Formuliere ihn so, dass er auch stimmt, falls 23 nicht zusammengeführt wird: „mit Auftrag 23“, ohne Commit.
3. AUDIT: R33 (Client-Verzeichnis) und die Stelle zu `publish`/`data/platform/` (R45 oder die passende) um 22 ergänzen; neuer Eintrag für den Fund aus 23 (zweimal gelesenes Zertifikat, mittel, behoben mit 23) mit nächster freier R-Nummer.
4. `docs/tasks/20-notes.md`: die Punkte R-low (21c), „nie gültig“ (21c) und `resolveExisting` (20o) als „erledigt mit 22“ vermerken.

## Fertig

- Nur die genannten Dateien geändert. Ein Commit mit `Task: docs/tasks/22d-docs.md`, ohne Co-Authored-By, ohne Modellnamen. Nicht pushen.
- Bericht: geänderte Stellen mit Zeilen.
