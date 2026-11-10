# Auftrag 27: Liste nach M1, zweite Nacht, zweite Welle (10./11.11.2026)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich, dazu die allgemeinen Regeln aus `docs/tasks/24-nach-m1-nacht1.md` (Abschnitt vor „Paket A“) und die Abweichungen aus `docs/tasks/26-nach-m1-nacht2.md` (Kopf). Neu bzw. abweichend gilt:

- **Basis:** die lokale Quelle `orch/n26` (Stand beff425: Arbeitsbranch mit 25, dazu 26B, 26C, 26D, 26E und 26F). Je Paket ein eigener Worktree mit `git reset --hard beff425`.
- **Nummern:** aus der Liste nach M1 im Stand nach 26g. Lies sie mit `git show c122809:docs/tasks/backlog-nach-m1.md`.
- **Commit-Zeile:** `Task: docs/tasks/27-nach-m1-nacht2b.md (Paket 27X)`.
- **Notizen:** `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl27<x>/notes.md`.
- **Halte an und berichte, statt umzusetzen,** wenn ein Punkt eines der folgenden Dinge berührt:
  - ein Dateiformat, einen signierten Datensatz, eine Signaturdomäne oder eine Prüfregel der Clients;
  - eine offene Frage (`TODO(ask)`, Q-Nummer);
  - einen neuen Befehl oder eine neue Option.
- **Platz:** Die Platte ist knapp. Lege nur kleine Kopien an und räume sie am Ende weg.

## Paket 27A: `publish`-Robustheit und Testlücken (Nr. 40 teilweise, 86, 87, 90). Sicherheitskritisch.

1. **Nr. 40, nur diese drei Teile:**
   - Ein Vorgänger-Zertifikat, das nur in `platform/` liegt, zählt für die Vorprüfung, und `Append` verweigert danach. Abhilfe: Solche Zertifikate werden wie Nachfolgen nachgeloggt, oder die Vorprüfung lehnt sie vorher ab. Wähle die Lösung, die nichts Neues annimmt.
   - Eine zweite echte Nachfolge derselben Generation wird geschrieben, bevor `ErrDuplicate` kommt. Abhilfe: Sie wird vor dem Schreiben abgelehnt.
   - `checkDataPlatform` überspringt nicht reguläre Einträge vor der Namensprüfung. Prüfe, ob das nach 25A/26B noch gilt.

   Die übrigen Teile von Nr. 40 brauchen eine Entscheidung und werden nur beschrieben: fremder Pin bei leerem `platform/` ohne Kopf; der Server warnt bei abweichendem Pin bzw. `witnesses.rec` nur.
2. **Nr. 86:** Tests für X4 (fehlendes `platform/` vor dem Log) und X6 (`os.SameFile` im Fehlerzweig von `lreadEntry`). Die Meldung „… opened and wrote to; nothing logged …“ soll nur dann „wrote to“ sagen, wenn etwas geschrieben wurde. Sonst kommt eine passende Variante.
3. **Nr. 87:** `TestKeyDirMode` überspringt ohne `CAP_CHOWN` nur den Teil, der die Rechte braucht.
4. **Nr. 90:** Seed mit gekipptem Signaturbyte in `FuzzCheckDataPlatform`.
5. **Läufe:**
   - `internal/ceremony` unter race mit und ohne Tags und unter 386 mit Tags;
   - `cmd/gomail-ceremony` unter race mit Tags;
   - die Fallmatrix aus `scratchpad/rev25a-robust/` ohne neue Verletzungen.

## Paket 27B: Prüfung des Release-Builds (Nr. 19)

1. Prüfe, was `TODO(ask)` in `keygen_pipe_tagged.go` fragt. Ist es eine offene Frage an den Auftraggeber, setzt du daran nichts um und nennst sie im Bericht.
2. Baue ein Skript `scripts/check-release.sh <binary>…`. Es prüft mit `go version -m`, dass ein Binary ohne die Tags `gomail_test` und `gomail_dev` gebaut ist. Zusätzlich prüft es, dass bekannte Testschalter nicht im Binary stehen, etwa die Namen `GOMAIL_TEST_*` und `GOMAILCTL_TEST_KEYGEN_PIPE`. Exit 0, wenn alles sauber ist, sonst 1 mit Meldung.
3. Ein Test im Repository: in `internal/...` oder als Go-Test, der die vier Binaries einmal ohne und einmal mit Tags baut und das Skript dagegen laufen lässt. Ohne Tags muss er rc=0 ergeben, mit Tags rc=1. Der Test läuft nur unter Linux und nur mit Go im PATH; sonst überspringt er sich.
4. Kein neuer Befehl in den Binaries, nur das Skript.

## Paket 27C: `from:`/`to:` für `unprocessed` (Nr. 47)

1. Prüfe, woher die gekürzten Metadaten kommen (4096 Byte, Umschlagabsender 320 Byte). Lassen sich `from:` und `to:` für Mails mit Marker `unprocessed` ohne Formatänderung vollständiger füllen? Zum Beispiel aus Daten, die der Client ohnehin entschlüsselt.
2. Berührt die Abhilfe ein Format oder einen signierten Datensatz, setzt du nichts um und beschreibst die Lage. Sonst setzt du sie mit Tests um.
3. `internal/client` nur mit `-run`.

## Paket 27D: kleine Reste (Nr. 84, 88, 89, 91)

1. **Nr. 84:** `TestReadPlatformCertRawReadsOnce` prüft nach dem Aufruf zusätzlich `/proc/self/fd`: Kein Deskriptor zeigt mehr auf die `.cert`. Die Kommentare nennen die Grenze richtig.
2. **Nr. 88:** Die AST-Auswertung in `TestBenchScriptNames` wertet Zuweisungen in Reihenfolge aus. `mode := mode` darf nicht abstürzen, und eine Neuzuweisung ergibt den Wert, den Go ergäbe. Ein Fall ohne Lösung bricht mit klarer Meldung ab.
3. **Nr. 89:** Das Skript `bench.sh` legt die FIFO des Wächters direkt nach `mktemp` an. Scheitert das, endet es mit Exit 2 und „nothing run“, vor jeder Ausgabe. Es gilt die Sicherheitsregel aus 26C: das echte Skript nur mit gültigem `-render`, den Messweg nur in Kopien ohne `go`.
4. **Nr. 91:** Den Protokollkommentar in `internal/witness` berichtigen. Die Wiederholung durch `http.Transport` gilt bei jedem Schluss einer wiederverwendeten Verbindung, auf einer anderen Verbindung.

## Fertig

Wie Auftrag 24. Der Bericht nennt außerdem Vorschläge für den Doku-Nachzug.
