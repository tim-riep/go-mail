# Auftrag 38: `TestReleaseSwitches`, Nr. 129 H1 (Nacht 24./25.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md`. Neu bzw. abweichend gilt:

- **Nur Testcode** in `internal/e2e/release28b_test.go`. Kein Produktionscode, keine Skripte, keine Dokumente.
- **Commit-Zeile:** `Task: docs/tasks/38-nach-m1-nacht4d.md (Paket 38A)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl38a/notes.md`.

## Paket 38A: Liste nach M1, Nr. 129, H1

Basis: aktueller Arbeitsbranch.

1. **Fail closed:** Ein Link `_*`, `.*` oder `testdata`, dem `os.Stat` nicht folgen kann, mit einem Fehler außer `fs.ErrNotExist` (`ELOOP`, auch eine Kette `_l` → `_m` → `_l`, `EACCES`, `ENAMETOOLONG`), ist ein Fehler des Durchlaufs, wie ein Verzeichnis gleicher Pfadlänge. `fs.ErrNotExist` (verschwunden oder hängend) bleibt wie heute (nil für einen Link). Kommentar entsprechend („or cannot be followed“).
2. **Tests:** je ein Fall für `ELOOP` (Kette) und, wenn ohne root-Rechte herstellbar, `EACCES`; sonst Skip mit Grund (nicht still). Ein Mutant, der den alten Weg zurückbringt, scheitert.
3. **Läufe:** gofmt und vet für `internal/e2e` mit und ohne Tags; `TestCheckRelease` und `TestReleaseSwitches` ohne Tags, mit Tags und unter `-race` mit Tags; `TestReleaseSwitches` zusätzlich `-count=50`.

## Fertig

Genau ein Commit, nicht pushen; Patch nach `scratchpad/patches/38a-<hash>.patch`; Bericht mit Läufen, Mutanten, Offenem.

## Nacharbeit 38A2

Ausgangspunkt 4dbb3a4 (`docs/tasks/patches/38a-4dbb3a4.patch` auf df4bd58). Ergebnis: genau ein Commit auf df4bd58 mit 38A insgesamt. Fund der Prüfung (mittel, `scratchpad/rev38a/notes.md`): Der Fall `{"testdata", "_m"}` in `TestReleaseSwitchesLinkStat` erreicht den Link `testdata` nie, weil `_m` vorher besucht wird und schon scheitert; ein Mutant, der die Prüfung nur für `_*` und `.*` anwendet, übersteht. Abhilfe: Partner, der nach `testdata` sortiert und weder versteckt noch `testdata` ist (etwa `z`), und ein Beleg, dass der Mutant nun scheitert. Dazu die Hinweise: `ENOTDIR` (Ziel durch eine Datei) im Kommentar nennen; „like a directory of the same path“ → „of the same path length“ bzw. genauer. Läufe wie in Paket 38A.
