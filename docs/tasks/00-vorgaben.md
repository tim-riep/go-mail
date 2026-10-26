# Feste Vorgaben für jeden Umsetzungsauftrag

Diese Vorgaben gelten wörtlich für jedes Arbeitspaket (Abschnitt 5 des Orchestrierungsauftrags):

* Go 1.26, nur Standardbibliothek plus `golang.org/x/crypto`, `golang.org/x/mod`, `golang.org/x/text` in fest vorgegebenen Versionen
* keine eigenen kryptografischen Primitive, Zufall nur aus `crypto/rand`
* kein `panic` bei fremden Eingaben, Längen vor jeder Speicherreservierung prüfen, fail closed, Fehler über `errors.Is`
* kein Klartext von Mails, Headern, Betreffs oder Suchbegriffen auf der Platte, in Logs oder in Fehlermeldungen
* keine privaten Schlüssel im Datenverzeichnis
* atomares Schreiben, Sperren nach 9.1
* Uhrzeit nur über die injizierbare Schnittstelle
* Pakete aus Phase 0 (`rec`, `keys`, `shamir`, `envelope`) nur ändern, wenn der Auftrag es ausdrücklich erlaubt
* Vektoren, die sich nicht ändern dürfen, vor jedem Commit auf Byte-Gleichheit prüfen

## Arbeitsweise

* Werkzeugkette: `export GOTOOLCHAIN=go1.26.10` vor jedem `go`-Befehl (installiert ist 1.24). `x/sys` darf nicht direkt importiert werden (nur indirekt über `x/crypto`); Systemaufrufe über `syscall`.
* Du arbeitest in einem eigenen Git-Worktree auf einem eigenen Branch. Du änderst nur die Dateien, die dein Auftrag unter „darf ändern“ nennt. Alles andere ist schreibgeschützt; fehlt dir etwas dort, schreibst du es in den Bericht.
* Vor dem Commit: `gofmt -l .` leer, `go vet ./...`, `go test -race ./...`, `GOARCH=386 go test ./...` fehlerfrei auf dem ganzen Modul, nicht nur auf deinem Paket.
* Commits auf deinem Branch, Nachricht auf Englisch im Stil des Repositorys (`store: ...`), Verweis auf die Auftragsdatei (`Task: docs/tasks/<nr>-<name>.md`). Keine Modellnamen in Commits, Code oder Dokumenten. Nichts pushen.
* Kommentare im Code auf Englisch wie im Bestand; Dokumente unter `docs/` auf Deutsch. Du änderst `docs/DECISIONS.md`, `docs/SPEC-ISSUES.md`, `docs/HANDOFF.md`, `docs/ORCHESTRATION.md` nicht; Vorschläge dafür gehören in deinen Bericht.
* Ist eine Stelle der Spezifikation für dich nicht eindeutig und betrifft sie ein Dateiformat, einen signierten Datensatz, eine Signaturdomäne oder eine Prüfregel im Client, baust du die strengste Lesart, markierst die Stelle mit `TODO(Qn)` oder `TODO(ask)` und meldest sie im Bericht. Du erfindest keine Anforderungen.
* Dein Bericht am Ende: Branch und Worktree-Pfad, Commit-IDs, was umgesetzt ist, was nicht, jede Abweichung vom Auftrag mit Grund, jede geänderte Datei außerhalb deines Pakets mit Begründung, Messwerte (Abdeckung, Fuzzing), offene Fragen und Vorschläge für `DECISIONS.md` und `SPEC-ISSUES.md`.
