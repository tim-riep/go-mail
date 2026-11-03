# Auftrag 20n: Dokumentation zu 20i, 20l und zur Analyse der Zeremonie-Zeitgrenzen (nur Dokumentation)

Welle 5. Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 27994c6 oder später, eigener Worktree. Code-Stand für alle Aussagen: Branch `worktree-agent-a43f36171b533ec65`, Commit 1a57314 (enthält 20h, 20i, 20l; wird parallel zusammengeführt). Lies ihn mit `git show 1a57314:<pfad>`.
- Darf ändern: `docs/DECISIONS.md`, `docs/RUNBOOK.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`. Kein Code, keine Tests.
- Quelle: `docs/tasks/20-notes.md`, Abschnitte ab „Aus der Spezifikationsprüfung von 20h“ bis „Analyse der 4,5-s-Fehlschläge der Zeremonie“; Aufträge `docs/tasks/20i-last-lows.md`, `20l-tempdir-identity.md`, `20m-ceremony-stall-detect.md`.

## Umfang

1. **DECISIONS:**
   - Nachträge 20i und 20l an D86: `ErrExists` nur bei belegtem Ziel; `O_NOCTTY` in `store.OpenRegular`/`ReadFileLimited` und für bestehende Sperrdateien (`openExistingLock`, fstat regulär); Schlüsselspeicher über `store.ReadFileLimited`; Temp-Verzeichnis über einen Deskriptor (`os.OpenRoot`), Prüfungen der Identität (`sameDir`) vor `lockOnlyDir`, vor und nach dem Umbenennen, Aufräumen nur durch den Deskriptor und nur bei gleicher Identität; Symlink am Temp-Namen abgelehnt; Restfall (Wettlauf zwischen letzter Prüfung und Umbenennen) als bekannte Grenze.
   - **Neue Entscheidung D92: Betriebsvoraussetzung für Client-Verzeichnisse.** Das Elternverzeichnis eines Client-Verzeichnisses darf nur für den eigenen Benutzer beschreibbar sein (oder sticky). Begründung: Der Client schreibt nach dem Sperren über den Pfad (`user.rec`, Schlüsselspeicher bei `device lost`, `state.json`); ein anderer Benutzer mit Schreibrecht auf das Elternverzeichnis könnte das Client-Verzeichnis dazwischen austauschen und den Schlüsselspeicher eines anderen Client-Verzeichnisses desselben Kontos überschreiben (Angreiferprüfung 20l, mittel unter dieser Bedingung, vorbestehend). Abhilfe nach M1: `os.Root` des Client-Verzeichnisses ab `Open` halten und alle Schreibvorgänge darüber. Damit gilt der Fund unter der Voraussetzung als niedrig; das ist die nach Regel geforderte Begründung in DECISIONS.
   - D85: Satz, dass die Zeitgrenzen des Abbruchpfads (`outputGrace`, `abortWait`, `abortTotal`, `abortFloor`) in der Zeit des Programms gelten; kein Benutzerprogramm kann sie garantieren, während es nicht läuft. Ergebnis der Analyse (zwei Fehlschläge unter Stillstand der Maschine, kein Programmfehler) und Auftrag 20m (Tests erkennen Stillstand) nennen.
2. **RUNBOOK:** Betriebsvoraussetzung aus D92 an der Stelle, wo Client-Verzeichnisse angelegt werden (3.2) und in den Voraussetzungen; Prüfbefehl (`stat -c '%U %a' <eltern>`).
3. **AUDIT:** R33 (Stand 20i/20l, Restgrenzen), R41 (Schlüsselspeicher jetzt geschützt; offen bleibt `emptyDir` in `cmd/gomail-server/init.go`), neuer Eintrag R46 „pfadbasiertes Schreiben eines offenen Clients“ mit D92, 6.2 neue Tests (`TestTempDirSwapped*`, `TestOpenTempDirRefuses`, `TestKeystoreNotRegular`, `TestKeystoreNoCTTY`, `TestLockFileNotRegular`, `TestLockFileNoCTTY`, `TestOpenRegularNoCTTY`, `TestTempDirMovedAway`), 6.1 und HANDOFF: die 4,5-s-Fehlschläge nach der Analyse als Stillstand der Maschine einordnen (kein offener Fund im Produktivcode; Tests erkennen Stillstand ab 20m).
4. **HANDOFF:** Stand je Kriterium nachführen (keine Platzhalter füllen, für die es keine Daten gibt); Betriebsvoraussetzung D92; R46.

## Fertig

- Jede Aussage über Code mit Datei und Funktion belegt, geprüft an 1a57314.
- Ein Commit mit `Task: docs/tasks/20n-docs-20i-20l.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20n/notes.md`.
