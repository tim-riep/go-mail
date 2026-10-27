# Auftrag 18b: Nacharbeit `docs/AUDIT.md` (Funde der Prüfung von 18)

Welle 5. Nur Dokumentation. Feste Vorgaben: `docs/tasks/00-vorgaben.md`. Worktree `/home/user/go-mail/.claude/worktrees/agent-a4d09f65e77ed24eb` (Branch `worktree-agent-a4d09f65e77ed24eb`, Stand a20c6b4). Zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`: Seitdem sind SPEC-ISSUES bereinigt (S88–S92) und ORCHESTRATION enthält die M1-Kriterien A–F. Auftrag 18 bleibt gültig. Jede neue Aussage wird am Code oder an den Dokumenten des Branchs belegt.

## Funde mittel

1. **6.1 und R35: Produktionsbuild-Belege werden mit den genannten Befehlen nicht ausgeführt.**
   - Die Dateien von `TestKeygenPipeProduction` (`cmd/gomailctl/keygen_pipe_test.go`), `TestInitDevProduction` (`internal/ceremony/initdev_test.go`) und `TestUsageNoDev` (`cmd/gomail-ceremony/dev_test.go`) tragen `!gomail_test` bzw. `!gomail_dev`.
   - `TestNoTestSwitchInProduction` und `TestDevPinRefusedInProduction` überspringen sich im Lauf mit Tags.
   - `TestKeygenPipeProduction` läuft nur mit `-tags gomail_dev` ohne `gomail_test`.
   - Umsetzen:
     - In 6.1 einen Lauf `go test ./...` ohne Tags und einen Lauf `go test -tags gomail_dev ./cmd/gomailctl` aufnehmen. Je Lauf angeben, welche Belege er trägt.
     - Den Pauschalsatz „nur mit Tags aussagekräftig“ richtigstellen.
     - `internal/bench` zu den tag-abhängigen Paketen nehmen.
     - Ergänzen, dass `internal/e2e` `GOMAIL_TEST_MIN_FREE` selbst setzt (`cli_test.go`) und seine Programme immer mit `gomail_dev,gomail_test` baut.
     - Jeden Befehl selbst ausführen und das Ergebnis (PASS/SKIP je genanntem Test) prüfen, bevor er im Dokument steht.
2. **6.5 „Kompromittierte Identität“: Rezept nicht nachbaubar.**
   - Die Sperre sitzt in `internal/ceremony/init.go` (`runSucceed` → `ErrCompromised`), nicht in `cmd/gomail-ceremony`.
   - Selbst ohne Sperre verweigert `Publish` mangels `identity-<g>.succ` (Regel aus 15g).
   - Die R17-Aussage zeigt erst die Variante mit normaler Nachfolge (`Compromised: false`): `publish` nimmt Zertifikate der alten Generation mit dem neuen Pin an.
   - Umsetzen: Rezept und Erwartung so schreiben, dass sie an einer Wegwerfkopie nachbaubar sind. Das Rezept selbst nachstellen (Kopie im Scratchpad, danach löschen) und den Ablauf in AUDIT beschreiben.
3. **6.5 „Terminal: offene Punkte“: Belegung falsch.** Richtig ist: stdin und stderr auf Terminal A (angehalten), stdout auf B, Anteil auf B, dann SIGINT.

## Funde niedrig

4. **4.3, 4.2 und 4.1:**
   - In 4.3 `gomail/v1/work` ergänzen (AAD der ausgelagerten Spool-Daten, `internal/ingest/queue.go`).
   - In 4.2 den definierten, ungenutzten Kurznamen `mail` nennen, mit dem Hinweis, dass Mail-Dateien über `file_hash` in `meta` gebunden sind.
   - In 4.1 GCM ohne STREAM für Schlüsselspeicher und `work/` nennen.
   - Die Logsignatur ruft `ed25519.Sign` direkt (`translog/head.go`).
5. **R12:** Das Fenster an `translog/doc.go` angleichen: seit dem neuesten veröffentlichten Kopf, normalerweise die Einträge eines HeadInterval. Ohne Zeugen wächst es bis zum Stopp nach 24 h.
6. **Kopf, Zählung und R27:**
   - 09b in die Liste „in Arbeit“ aufnehmen, ebenso 15n (dritte Nacharbeit der Zeremonie-Terminalregeln: Schreibfehler und gestoppte Ausgabe im normalen Pfad, Doppel-Enter). Quelle ist der Verlauf in `docs/ORCHESTRATION.md`.
   - Die zurückgestellten Punkte aus D79 nennen: Datei-Hash im Merkzettel, doppelte Begriffsregeln, `from:`/`to:` bei überlangen Headern.
   - In R1/R3–R6 die Funde der Prüfung von 15m als offen aufnehmen: Ein Clear mit Fehler unter `O_NONBLOCK` gilt als erledigt. Gestopptes stderr hält den normalen Pfad mit sichtbarem Anteil fest. Ein Doppel-Enter mit Abstand bestätigt für den nächsten Inhaber. Stand: in Arbeit (15n).
7. **6.5 Vorlagen:** Hinweis, dass die Tests zu 15i/15l/15m/15n und 13e erst mit diesen Aufträgen ins Repository kommen. Bis dahin sind sie nicht aus dem Repository nachbaubar.
8. **Tabelle 2 „Dieb“:** Ergänzen, dass Dateien gültig bleiben, die ein Client vor dem Widerruf geprüft hat (Prüfvermerk nach 2.2 Punkt 4 und S13).
9. **R40:** DragonFly: alte BSD-Pty-Master (`/dev/ptyXX`) werden nicht als Master erkannt (`cmd/gomailctl/tty_master_dragonfly.go`, `TODO(ask)`).
10. **Abschnitt 7.2:**
    - An die bereinigte SPEC-ISSUES anpassen: S77 und S80 sind im Code gelöst. Neu sind S88–S92.
    - Den Vermerk zu D88 ohne SPEC-ISSUES-Eintrag entfernen, weil S88 und S89 jetzt bestehen.
    - Die Verweise auf die M1-Kriterien auf ORCHESTRATION Abschnitt 1, „M1-Kriterien A–F“, setzen.
11. **Bekannte Grenzen ohne S-Punkt** als Restrisiko aufnehmen, falls noch nicht enthalten:
    - D86: Passphrase-Echo und Löschen des Seeds vor der Abfrage (`TODO(ask)`).
    - D87 (4): Gruppenname bei `gomail-server init`.
    - Q19-Nachtrag: neuer `init` statt Nachfolge bei kompromittiertem Root.

## Fertig

- Ein Commit `docs: AUDIT rework after review (task 18b)` mit einer Zeile `Task: docs/tasks/18b-audit-rework.md`. Kein Modellname, keine Co-Authored-By-Zeile.
- Bericht: je Punkt erledigt mit Abschnitt/Zeile. Dazu die ausgeführten Befehle aus Punkt 1 mit Ergebnis.
