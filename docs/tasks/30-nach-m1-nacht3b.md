# Auftrag 30: zwei Testkorrekturen (Nacht 17./18.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und der Kopf von `docs/tasks/29-nach-m1-nacht3.md` (Haltepunkte, Sicherheit der Umgebung, Last). Neu bzw. abweichend gilt:

- **Nur Testcode.** Kein Produktionscode, keine Skripte, keine Dokumente.
- **Commit-Zeile:** `Task: docs/tasks/30-nach-m1-nacht3b.md (Paket 30X)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl30<x>/notes.md`.

## Paket 30A: Zufallsfehler in `TestDeviceLostWrongSeed`

Basis: 0854dab (`git reset --hard 0854dab` im eigenen Worktree).

1. **Fehler:** Im Volllauf scheiterte `TestDeviceLostWrongSeed` (`internal/client/devicelost_test.go`, Fall „wrong word“) mit `client: the seed does not belong to this user`. Der Test ersetzt Wort 5 der zufälligen Seed durch Wort 6 und erwartet `keys.ErrChecksum`. Die Prüfsumme hat 8 Bit (`internal/keys/seed.go`), also bleibt sie mit Wahrscheinlichkeit etwa 1/256 gültig, und `DeviceLost` meldet dann `client.ErrSeed`.
2. **Abhilfe:** Der Test wählt ein Ersatzwort, für das `keys.SeedFromWords` nachweislich `ErrChecksum` ergibt (etwa: der Reihe nach Wörter der Liste probieren). Der Fall bleibt so streng wie vorher: `errors.Is(err, keys.ErrChecksum)`. Ändere keine Prüfregel.
3. **Suche nach gleichen Mustern:** Suche in allen Tests des Moduls nach Stellen, die ein Wort einer zufälligen Seed tauschen oder ersetzen und `ErrChecksum` erwarten (auch Vertauschen zweier Wörter, auch in `cmd/` und `internal/e2e`). Behebe jede so; Stellen mit fester Seed bleiben.
4. **Beleg:**
   - Ein Test, der die Auswahl des Ersatzworts auf vielen Seeds prüft (oder eine kurze Schleife im Test selbst), so dass ein Rückfall auf „Wort 6“ zuverlässig scheitert.
   - Der alte Test scheitert mit einer Seed, bei der Wort 6 die Prüfsumme hält (konstruiert). Beschreibe das in den Notizen.
5. **Läufe:** die geänderten Tests mit `-run` unter race mit Tags und unter 386 mit Tags, je `-count=200` für den geänderten Test; gofmt und vet für die geänderten Pakete mit und ohne Tags.

## Paket 30B: `TestReleaseSwitches`, Reste aus 29D2

Basis: df5a202 (der Endstand von 29D; `git reset --hard df5a202`).

1. **Kein Hänger:** Der Walk-Test legt heute eine FIFO `fifo.go` mit dem Programm `mkfifo` an. Der Schutz gegen einen Hänger hilft nur gegen ein einziges Öffnen. Ersetze die FIFO durch einen Eintrag, dessen Öffnen sofort scheitert, etwa einen Unix-Socket (`net.Listen("unix", …)`, Öffnen ergibt `ENXIO`). Alternativ bleibt die FIFO, wird aber über einen Systemaufruf angelegt und der Schutz deckt jede Zahl von Öffnungen. Wähle die Variante, die auch bei einem fehlerhaften Rückfall in `releaseEnvReads` nie hängt.
2. **Kein stiller Wegfall:** Auf Linux darf der Fall nicht still wegfallen. Lässt sich der Eintrag nicht anlegen, scheitert der Test (`t.Fatal`). Auf anderen Systemen bleibt ein Skip mit Grund.
3. **Prüfung der Wurzel:** ein automatischer Test für die Modulwurzel über einen symbolischen Link (`EvalSymlinks`), falls ohne Eingriff in den Produktionscode baubar; sonst Grund in den Notizen.
4. **Läufe:** gofmt und vet für `internal/e2e` mit und ohne Tags; `TestCheckRelease` und `TestReleaseSwitches` ohne Tags, mit Tags und unter `-race` mit Tags, `TestReleaseSwitches` zusätzlich `-count=200`; die Mutanten aus `scratchpad/rev28b2/mut/` und aus den Notizen von 29D/29D2 scheitern weiter; ein Mutant, der den Eintrag öffnet, scheitert ohne Hänger.

## Fertig

Wie Auftrag 24: Läufe, Gegenbelege per Mutation, genau ein Commit auf der Basis des Pakets, Notizen. Der Bericht nennt Vorschläge für den Doku-Nachzug.
