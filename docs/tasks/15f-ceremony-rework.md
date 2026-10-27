# Auftrag 15f: Nacharbeit Zeremonie-Log-Integration (Funde der Prüfung von 15b; Q19)

Welle 4. Sicherheitskritisch. Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich). Branch `worktree-agent-ab638240f368d50a7`, Worktree `/home/user/go-mail/.claude/worktrees/agent-ab638240f368d50a7` (Stand 11259ef; zuerst `git merge --no-edit claude/quirky-keller-hjsl5i`, seither nur Doku und `internal/client`/`cmd/gomailctl`-Änderungen aus 06b; Konflikte in `internal/client/words.go` möglich: die Datei bleibt bis Auftrag 14, 15b-Änderungen an anderen Dateien behalten). Auftrag 15b bleibt gültig. Lies `docs/QUESTIONS.md` Q19 (mit Nachtrag) und `internal/ceremony/api.go` (`Succeed`, `TODO(ask)`), `init.go` (`runSucceed`), `publish.go` (`checkWitnessFile`, Nachfolgeprüfung), `cmd/gomail-ceremony/main.go` (`succeed`, `publish`). Prüfertest als Vorlage: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/verify15b-spec/zz_verify_test.go` (`TestVerifyCompromisedIdentityStillIssues`, `TestVerifySuccessionGap`).

## Fund hoch (Haltepunkt 2, Q19: bis zur Antwort sperren)

1. **`succeed --compromised` wieder sperren.** Ohne Widerrufs-Kennzeichnung in Pin, Nachfolge oder Log kann die kompromittierte Identität weiter Zertifikate ausstellen, die `publish`, Log und Clients annehmen (Spezifikationslücke, Q19). Umsetzen: `--compromised` ist im Programm ein Nutzungsfehler (Exit 2) mit festem Text „noch nicht verfügbar: Widerruf einer Plattformgeneration ist nicht festgelegt (Q19)“; `ceremony.SucceedOptions.Compromised` liefert `ErrCompromised` (neuer Fehlerwert, `TODO(Q19)`); der Bibliothekscode des Kompromittierungsfalls bleibt erhalten, aber unerreichbar (Test `TestSucceedCompromised` erwartet die Ablehnung, der e2e-Teil „succeed --compromised“ in `TestSuccessionEndToEnd` wird zu „verweigert“, der Rest des Tests bleibt). Übernimm `TestVerifyCompromisedIdentityStillIssues` als **dokumentierenden** Test mit `t.Skip("Q19: …")` und Erklärung, damit der Pflichttest aus 10.1 beim Aufheben der Sperre vorliegt.

## Fund mittel

2. **Zeugenänderung erreicht `witnesses.rec` nicht.** Umsetzen: `publish --replace-witnesses` ersetzt die Arbeitskopie `platform/witnesses.rec` ausdrücklich durch die Zeugen des Pins (atomar, unter der Serversperre, nur wenn der Pin die Plattformgeneration des Datenverzeichnisses kennt; ohne Schalter weiter `ErrMismatch`); Meldung nennt alte und neue Quorumzahl und Zeugennamen. Test: `succeed --witness …` → `publish` ohne Schalter verweigert, mit Schalter ersetzt; danach startet der Server mit dem neuen Pin ohne Warnung. (Der Server verweigert bei Abweichung Pin/`witnesses.rec` weiterhin nur mit Warnung: Server-Scope, Hinweis im Bericht für Auftrag 19/AUDIT.)

## Funde niedrig

3. **Nachfolgelücke:** `publish` verlangt für `identity-<g>.succ` mit g ≥ 3, dass `identity-<g-1>.succ` im Log, in `platform/` oder im Export liegt; sonst `ErrPrerequisite` mit Hinweis (kein Flag, der Kompromittierungsfall ist gesperrt). Test `TestVerifySuccessionGap` übernehmen (erwartet jetzt die Ablehnung).
4. Uhrhinweis in `succeed` nur, wenn eine Nachfolge signiert wird.
5. `internal/translog/doc.go`: Sätze „until task 15b …“ und die Tabellenzeile `InitDev`/`Publish` auf den Stand bringen (nur Text).

Nicht in diesem Auftrag: Widerrufsdatensatz oder Pin-Feld (Q19 offen), `translog`-Gültigkeitsregeln, `internal/client`, Server.

Fertig: `gofmt -l .` leer, `go vet ./...` (mit und ohne `-tags gomail_dev,gomail_test`), `go test -race ./internal/ceremony ./cmd/gomail-ceremony ./internal/words` (mit und ohne `-tags gomail_dev`), `go test -race -tags gomail_dev,gomail_test ./internal/e2e` (`GOMAIL_TEST_MIN_FREE=0.000001` nur dort), `GOARCH=386 go test ./internal/ceremony ./cmd/gomail-ceremony`, Vektoren byte-gleich. Ein Commit `ceremony: succeed --compromised locked pending Q19, publish --replace-witnesses, succession gap check (task 15f)`; kein Modellname. Bericht nach `00-vorgaben.md`: Konfliktauflösungen, je Punkt Änderung und Testname.
