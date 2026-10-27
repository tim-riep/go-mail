# Auftrag 19: `docs/RUNBOOK.md` neu und `TestRunbook` (Zeremonie, Zeuge, drei Benutzer)

Welle 5. Feste Vorgaben: `docs/tasks/00-vorgaben.md` (gelten wörtlich; Produktivcode nur, wo ein Befehl für den Ablauf zwingend fehlt, dann minimal und mit `TODO(ask)`; sonst Doku und Tests). Basis: Arbeitsbranch nach den Merges von 13, 14, 15b, 15h, 15i (der Orchestrator nennt den Commit); eigener Worktree. Lies `docs/RUNBOOK.md` (Abschnitte 0–11 sind noch Phase-1-Stand mit `--insecure-no-log`; die Abschnitte „Server mit Transparenzlog“, „Zwei Maschinen“, „Erstinstallation“ aus 15d/16/15h bleiben als Grundlage), `docs/PLAN.md` 9, 11, 2.3, 2.7; `cmd/*/main.go` (Usage-Texte sind die Wahrheit), `internal/e2e/cli_test.go` (`TestRunbook`), `docs/DECISIONS.md` D70, D81–D86, `docs/QUESTIONS.md` Q17–Q20.

Umfang: (1) RUNBOOK vollständig neu gegen die tatsächlichen Befehle: Erstinstallation (Zeremonie offline `init --shares 3-of-5`, Pin und Zeugenschlüssel verteilen, `gomail-server init` (15h), `publish`, Zeuge `gomail-witness`, Server `serve --pin --log-listen [--require-client-lock]`), Benutzer anlegen (`invite`, `register`, `keygen` nur am Terminal, Seed sichern, `keygen --shares`), Postfach (`mailbox create`, `address add`, `mailbox share`/`revoke`, `search`, `flag`, `list` ohne Absender, Exit-Codes 0/1/2/3/130), Geräteverlust (`device lost` erzeugt immer eine neue Generation; `restore` aus Wörtern oder Anteilen), Ingest-Rotation, Nachfolge (`succeed`, `publish`, `--replace-witnesses`, Server mit neuem Pin; `succeed --compromised` gesperrt, Q19, Betriebsregel), Störungen (451 bei inkonsistentem Log, `log repair`, Signal an die Prozessgruppe, „Clients, deren Einträge verloren gingen“, Q18-Zustand), Zwei-Maschinen-Test (Skript, Testbuild-Tags, `GOMAILCTL_TEST_KEYGEN_PIPE` nur Testbuild), Zeitquellen (Uhr des Zeremonierechners vor `--valid-from`, NTP für Server/Client, 24-h-Regel). Alles ohne Geheimnisse, keine Beispielwerte, die wie echte Seeds aussehen. (2) `TestRunbook` in `internal/e2e` folgt dem RUNBOOK Schritt für Schritt mit den Produktionsbinaries (ohne `gomail_dev`, mit `gomail_test` nur für die Platten-/Taktschalter und den Keygen-Pipe-Schalter): echte Zeremonie über die Testseams (3-of-5 mit Probe-Rekonstruktion), `gomail-server init`, `publish`, Zeuge, Server, **drei Benutzer** (Einladen, Registrieren, Postfach, Teilen, Entziehen, Suche, Flags), Mail-Empfang, `device lost` eines Benutzers mit Neuausstellung, Nachfolge der Plattformidentität und Neustart mit neuem Pin; jeder Schritt mit Verweis auf den RUNBOOK-Abschnitt in der Testausgabe; Laufzeit unter 5 Minuten. (3) Aus früheren Prüfungen (niedrig): `scripts/two-host-test.sh`: `curl -q`, `set +o xtrace +o verbose`, `ln -s … || die` für `--mount`, `usage`-Zeile `--keep`; RUNBOOK „Inkonsistentes Log“: `seen`-Fall unter „Läuft er bereits“.

Fertig: `gofmt -l .` leer, `go vet ./...`, `go test -race -tags gomail_test ./internal/e2e` (`GOMAIL_TEST_MIN_FREE=0.000001`), `TestRunbook` auch ohne `-race`, `dash -n scripts/two-host-test.sh`, Vektoren byte-gleich. Ein Commit `docs, e2e: RUNBOOK for the log-based platform and TestRunbook with ceremony, witness and three users (task 19)`; kein Modellname. Bericht nach `00-vorgaben.md` mit der Liste der RUNBOOK-Abschnitte und der Schritte von `TestRunbook`.

## Nachtrag (Start nach 13e)

- **Basis:** b03135d. Zusammengeführt sind 13 bis 13f, 14, 15b, 15h/15k und 16.
- **Noch nicht zusammengeführt:**
  - Die Terminalregeln der Zeremonie aus 15i bis 15n laufen noch: SIGPIPE ab Start, stderr muss schreibbar sein, Abbruch ohne wartende Aufrufe, Bestätigungsverzögerung. Beschreibe die Bedienung so, wie sie im Usage-Text des Branchs steht. Lege dazu einen Abschnitt „Terminalregeln der Zeremonie“ an, mit einem Platzhalter-Satz `<!-- 15n: Bestätigungsverzögerung -->`. Den Satz ergänzt der Orchestrator beim Merge von 15n.
  - `TestRunbook` darf keine Annahme über diese Regeln treffen, die 15n ändern könnte, zum Beispiel ein Enter unmittelbar nach der Aufforderung. Nutze die Testseams der Zeremonie, nicht das Pseudoterminal.
- **`TestRunbook` gibt es schon** in `internal/e2e` (Phase-1-Stand). Er wird nach dem neuen RUNBOOK umgeschrieben. Das Paket setzt `GOMAIL_TEST_MIN_FREE` selbst (`testMinFree`). Seine Programme baut es mit festen Tags; für Produktionsbinaries gibt es `prodTags` (siehe `TestInitProduction`).
- **Zusätzlich ins RUNBOOK**, aus früheren Prüfungen:
  - Uhr des Zeremonierechners vor `--valid-from` stellen; der Rechner ist offline, ohne NTP.
  - Strg-C während der Anteilseingabe wirkt erst mit der Eingabetaste (ISIG aus).
  - stderr der Zeremonie muss zum Schreiben geöffnet sein, sonst Exit 2.
  - Ein Abbruch endet nach höchstens etwa 2 s.
  - Restgrenze: Ein Terminal, das nie wieder liest, zeigt das Löschen nicht.
  - `list` zeigt keine Absenderspalte (D86).
  - Exit 3 bei teilweisem Erfolg, auch für `sync`.
  - NFS: `vers=4` ohne `nolock`/`local_lock`, gleiche gid (D83).
  - Im Zwei-Maschinen-Modus den Zeugenkopf des Laufs abwarten (MinGap).
  - Ein zweiter Serverprozess braucht eine Kopie des Ingest-Schlüssels.
- **E2E-Lücke aus 14c:** Metadaten der Ingest-Generation 1 nach `valid_from` werden abgelehnt. Diese Regel ist im Client-Log von `gomailctl` durch keinen E2E-Test gedeckt. Decke sie in `TestRunbook` im Schritt Ingest-Rotation, mit einer Aussage über `gomailctl`.
- **Nicht in 19:**
  - `serve` liest den Ingest-Schlüssel vor der Rollensperre. Das ist Produktivcode und gehört zu Auftrag 20.
  - Die Seed-Wort-Heuristik `filesWithWords` gehört zu 20.
- **Tags für die Läufe:** `-tags gomail_dev,gomail_test` für `go vet ./...` und für `internal/e2e`. Zusätzlich läuft `TestRunbook` ohne Tags; er muss dort laufen und darf nicht übersprungen werden. Lies die Abschnitte 6.1 und R35 in `docs/AUDIT.md` auf dem Branch, sobald 18b zusammengeführt ist; bis dahin `git show worktree-agent-a4d09f65e77ed24eb:docs/AUDIT.md`.
