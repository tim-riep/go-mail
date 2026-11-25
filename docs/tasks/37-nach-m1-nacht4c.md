# Auftrag 37: Testgerüst von `TestWriteTempInErrorSwapped` (Nacht 24./25.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md` (Haltepunkte, Sicherheit der Umgebung, Last). Neu bzw. abweichend gilt:

- **Nur Testcode** in `internal/store/fsroot36a_linux_test.go`. Kein Produktionscode, keine Skripte, keine Dokumente.
- **Commit-Zeile:** `Task: docs/tasks/37-nach-m1-nacht4c.md (Paket 37A)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl37a/notes.md`.

## Paket 37A: Liste nach M1, Nr. 130

Basis: der aktuelle Arbeitsbranch (Code gleich bde271b mit 36B).

Umsetzen, je so streng wie bisher (jede Prüfung des Falls bleibt; der Mutant aus 36A2 und ein Mutant, der den Rumpf im Kind auslässt, scheitern):

1. **Wächter früh:** Ist die Umgebungsvariable des Kinds nicht gesetzt, darf der Fall nie bis `limitFileSize` kommen; ein Rückfall scheitert sofort auf der Test-Goroutine (nicht erst nach den 60 s von `callWithin`).
2. **Frist des Kinds:** das Kind bekommt eine Frist mit Abstand vor der des Elternprozesses und ein eigenes `-test.timeout`; dazu `SysProcAttr.Pdeathsig = SIGKILL`. Bei Zeitüberschreitung des Kinds scheitert der Fall mit der Ausgabe des Kinds.
3. **Beleg des Rumpfs:** Das Kind schreibt eine Marke, sobald der Rumpf das Limit gesetzt hat (etwa `t.Log` in `limitFileSize`); der Elternprozess verlangt sie bei PASS.
4. **PASS/SKIP am Zeilenanfang** (nach Einrückung), nicht irgendwo in der Ausgabe.
5. **Abdeckung:** `-test.gocoverdir` des Elternprozesses, falls gesetzt, an das Kind weitergeben; sonst Grund in den Notizen.
6. **Umgebung:** Eine von außen gesetzte Variable `GOMAIL_STORE_TEST_FSIZE_CHILD` darf den alten Weg im Elternprozess nicht einschalten (etwa: das Kind erkennt sich an einem Wert, den nur der Elternprozess erzeugt, oder der Elternprozess entfernt die Variable vor dem eigenen Lauf nicht; wähle eine robuste Lösung und begründe sie).
7. **SKIP ohne Rauschen:** bei SKIP nur die SKIP-Zeile und den Grund zeigen.

**Läufe:** `go test ./internal/store` ohne `-count=1` (Testcache an) unter race mit Tags, race ohne Tags, 386 mit Tags; `-count=3` unter race mit Tags; `-coverprofile` einmal; gofmt und vet mit und ohne Tags. **Mutanten** (nur in Kopien): der Mutant aus 36A2; Kind lässt den Rumpf aus; Rückfall in den Elternprozess (Wächter); fehlende PASS-Zeile als Erfolg.

## Fertig

Genau ein Commit auf der Basis, nicht pushen; Patch mit `git format-patch -1` nach `scratchpad/patches/37a-<hash>.patch`; Bericht mit Läufen, Mutanten und Offenem.
