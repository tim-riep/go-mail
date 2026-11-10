# Gesammelte Hinweise aus den Prüfungen der Wellen 2–5 (Arbeitsnotizen des Orchestrators, Eingang für Auftrag 20)

Rohfassung, gesichert nach einem Neustart des Containers. Viele Punkte sind inzwischen erledigt; Auftrag 20 ordnet sie ein.

Eingeordnet am Stand 3e06f23 in `docs/tasks/20-triage.md` (Auftrag 20c): jeder Punkt mit genau einer Klasse und Beleg, dazu die Vorschläge für DECISIONS, SPEC-ISSUES und RUNBOOK. Neue Hinweise kommen unten dazu und werden dort nachgetragen.

- Task 14 (Client-Log): `store.ReplaceEpoch` erhält die Funktion `unloggable(old) bool` = `Append(old)` → `errors.Is(err, translog.ErrOrder)`; ErrPrerequisite/ErrUnloggedSigner → nicht ersetzen (07-Angreifer, TestV_ReplaceLoggable). Aufrufer darf `Last` erst nach erfolgreichem Refresh persistieren (07b fixt die Reihenfolge). TODO(phase3-translog) in 06c: ob ein Log-Fehler „nie gültig“ beweist → mit ErrOrder ja.
- Task 14/15: Options.Now wird in Verifier.Now kopiert (07b Fund 4).
- Task 15: Testsperre in den Programmen (TODO(task-15)), Rollensperren verdrahten, `--insecure-no-log` entfernen.
- Task 11: SignHead fsync vor Signatur; Q10 Pflichten 2/4/5; headSizes-Performance (07b Fund 7) relevant bei vielen Köpfen.
- 06c Restlücken: nicht-reguläre epoch.rec (Verzeichnis/FIFO) bei Kopf+1 bleibt Dauersperre (fail closed); FIFO blockiert ReadFileLimited → SPEC-ISSUES/AUDIT bekannte Grenze.
- 12c (nach 09): Indexkosten je Mail, Segmentgröße je 1000 Mails.
- 10c (nach 07-Merge, auf main): TODO(task-07) in gomail-ceremony aufheben (Pin-Felder 4–8 aus Zeremonie schreiben; `succeed --compromised` freigeben: Block+errCompromised entfernen, Paketkommentar-Satz streichen, TestSucceedCompromised positiv, TestUsage-Fall entfernen); `term.wipe` nach stderr (10b-Angreifer Fund 1 niedrig); DECISIONS: Zeremonie-Umfang (succeed/publish) durch M1-Kriterium C gedeckt, Terminalregeln (Anteile nur am Terminal, Echo aus, Löschen nach jedem Schritt, KeyDir 0700/eigener Benutzer/kein Symlink, auf Systemen ohne termios Ablehnung).
- 07b (ddee74b) für Task 14: unloggable = `func(old []byte) bool { _, err := log.Append(translog.KindEpoch, old); return errors.Is(err, translog.ErrOrder) }`; unter Postfachsperre, nimmt log/lock selbst (Reihenfolge Postfach → Log); vorher Schritte 1/2 „Who writes“; bei ErrPrerequisite fehlende frühere Epochen aus dem Store anhängen; bei ErrUnloggedSigner user.rec des Signierers anhängen und wiederholen; Erfolg/ErrDuplicate/ErrPrerequisite/ErrConsistency/ErrIO → false. Pending-Eintrag nach Rollback um eins blockiert Refresh, bis der Aufrufer ihn aus Verifier.Pending entfernt und neu anhängt (Task 14 entscheidet; doc.go „Withheld entries“ nachtragen → 11 oder 14). Klebriger Fehler (ownErr) nach Pending-Prüfung ist fail closed. DECISIONS: ErrIO; Zeugen-Verifier nur aus NewWitnessVerifier; Quorum nach Schlüsseln.
- Task 20 (Abnahme): internal/shamir TestShareFromWordsRejects/swapped_words ist zufällig (gleiche erste zwei Wörter ~1/2048) → Test soll zwei verschiedene Wörter tauschen; Phase-0-Paket, nur Testdatei, Vektoren unverändert; ausdrücklich erlauben.
- 10c: Testseams exit/commitHook/now in cmd/gomail-ceremony; Build-Tag ceremony_notty; Ctrl-S hält Signalhandler (bekannte Grenze → AUDIT).
- 10d (nach 07-Merge, Worktree 10 oder main): TODO(task-07) aufheben (Pin-Felder 4–8 schreiben; succeed --compromised freigeben; Liste im 10b-Bericht); 10c-spec niedrig: (2) ioctl als Paketvariable, Test „TCSETS schluckt, ECHO bleibt“ → errNoTerminal; (3) Echo-Probe erst nach signal.Notify; (4) Goroutine prüft t.closed nach Lock; (5) `written` direkt nach root.Link ergänzen. 
- Task 15: `--dev`/InitDev hinter Build-Tag `gomail_dev` (10c-spec Fund 1 mittel); testenv/e2e/TestRunbook mit dem Tag bauen; DECISIONS begründen (M1-C lässt --dev mit Testkennzeichen zu; Klartext-Root ist Zweck des Dev-Pfads).
- SPEC-ISSUES aus 10c: 2.3 Schritt 2 (Export vor Probe) vs. Code (Export nach Probe) → klarstellend; Uhr des Zeremonierechners ohne NTP für --valid-from → RUNBOOK (Uhr vor der Zeremonie stellen); stderr kein Terminal nötig (keine Geheimnisse) → klarstellend.
- 07c (8650723) für Task 14: erster Append nach Rollback des festgeschriebenen Baums liefert einmal ErrConsistency (cur verworfen), zweiter gelingt → Task 14 wiederholt einmal oder translog setzt in getCur vom ref neu auf (11 entscheiden). ownErr-Löschung nur ab ownSize. IndexFile im Datenverzeichnis jetzt ErrIO (vorher ErrConsistency). DECISIONS (bei 07-Merge): ownErr nur aus CheckHead-bestandenem Kopf; Löschung ab ownSize; rebuilt nur nach Erfolg; EvalSymlinks; ErrIO.
- 09b (nach Prüfung 09 und nach 06b-Merge): Begriffsregeln in gemeinsames Paket `internal/terms` (ingest + client; Importzyklus über ingest_more_test.go → externen Testpaket/e2e lösen; D55-Regeln, eine Implementierung, TestMetaTermsMatchServer behalten); S13-Regel aus 06b (wrap-accept/Prüfvermerk) auf Metadaten-Benutzersignaturen und Segmente anwenden (09 TODO(S13), nach device lost fallen Mails sonst aus List); Merkzettel um Datei-Hash (gleiche Version, anderer Inhalt); TODO(ask): file_id Segment = Gerätekennung, Laufnummer nicht gebunden (Segmente desselben Geräts/Epoche vertauschbar, harmlos → DECISIONS); Flag-Namen seen/answered/flagged/deleted/draft Bits 0–4 (SPEC-ISSUES klarstellend; keine Formatänderung); nur Benutzer-Mitglieder der Epoche der Mail setzen Flags (SPEC-ISSUES); thread: bei unprocessed = eigene Message-ID (S23, Formatfrage offen → SPEC-ISSUES offen); TODO(Q3).
- Merge-Reihenfolge: 06b, dann 09 (Konflikte in client.go/mailbox.go mechanisch), dann 09b Integration, dann 12d.
- 11 (zusätzlich, aus 07c-spec niedrig): (1) translog.go Refresh: bei fortbestehendem ownErr wird ein bestandener Kopf übernommen und der zurückgegebene Kopf ist zu persistieren (oder Übernahme unterlassen) – festlegen + Test; (2) Client getCur nach Rollback: Cache stillschweigend verwerfen und einmal neu aufbauen statt einmaliges ErrConsistency (TestOwnErrCleared festnageln); (3) doc.go „Withheld entries“: „Fehler von Audit oder CheckHead“; doppelte Fehlerpräfixe in audit/included.
- 09b zusätzlich (09-Angreifer niedrig): Search warnt wie List bei Index-Treffer in Ordner außerhalb folders.gml; Warnung bei Segment-Kopie auf andere Laufnummer desselben Geräts (Q11, TODO(ask) bleibt).
- 11: Kommentar internal/client/client.go:86 'translog.Unverified' → translogtest.Unverified (Merge-Prüfer 07).
- Task 15/20: go vet GOOS=freebsd/openbsd/netbsd scheitert in internal/ingest (syscall.Mlock, Statfs_t.Bavail; seit 685b4fd) → Build-Tags/Varianten oder als bekannte Grenze (nur Linux/darwin) in AUDIT/HANDOFF; 10d: SetTraceback("none") wirkt nicht (Go 1.26), abfangbare Signale über Abbruchpfad; Strg-C während Anteilseingabe wirkt erst mit Eingabetaste (ISIG aus) → DECISIONS/RUNBOOK.
- 09b/10-Merge: client/words.go → internal/words (TODO(task-10)); dort Obergrenze der Tokenzahl vor Normalisierung (06b-Angreifer niedrig). AUDIT: Phase-2-Grenze — frisch per Restore aufgesetzter Client vertraut der Kette beim ersten Kontakt (2.7), Schutz gegen Dieb mit Schreibzugriff nur für Clients mit lokalem Zustand nachgewiesen; Log (14) schließt das.
- Task 15 (12d-Hinweis): ingest.New lehnt Config.BatchSize > store.MaxBatch (100) mit ErrConfig ab (sonst scheitert jeder Flush still am Schema); Test.
- Task 17 (12d niedrig): TestIndexSegments-Kommentar auf Geprüftes kürzen oder Glob-Summe je Lauf und ID-Vergleich ergänzen; Tabelle: Sync/list erklären (client.List über alle Mails, kein Teil von Sync).
- AUDIT (11-Angreifer niedrig): loghttp ohne Verbindungsobergrenze/Ratenbegrenzung (10.2: vor Produktion LimitListener + Rate); Content-Type nach begrenztem Lesen; RepairTree prüft deckende Generation nicht (Client-Sache, doc.go Schritt 2), stilles Verkürzen bei kombiniertem Angriff (doc.go „nicht abgedeckt“, Erkennung über Zeugen).
- Task 15 (11b-spec niedrig): `address add --admin-key` mit outsideData prüfen (Admin-Schlüssel nie im Datenverzeichnis); Paralleltest TestVerifyParallelAddressAdd (verify11b-spec/owntests) oder Injektionspunkt zwischen Prüfung und Append übernehmen; Erfolgsmeldung von address add ohne Adresse (SPEC-ISSUES klarstellend); Müll in heads/ stoppt SignHead (dokumentierte Lesart, SPEC-ISSUES); ErrOrder bei gleicher Millisekunde → Exit 2 oder Wiederholung festlegen.
- Task 14 (aus 15d-Verifikation, niedrig): doc.go „What write access…“ Client-Satz präzisieren (nur Schreiber verlorener Einträge via Pending-Prüfung: ErrConsistency/ErrWithheld); TestRepairTreeOrphans um Kachel+keys/-Prüfung erweitern (Vorlage scratchpad/verify15d/tests/verify15d_own_test.go); RepairTree-Kommentar „log/lock“.
- Task 19 (aus 15d): RUNBOOK „Inkonsistentes Log“: seen-Fall unter „Läuft er bereits“; „Clients, deren Einträge verloren gingen“; RUNBOOK 1–6 noch Phase 1 (--insecure-no-log) → komplett neu.
- Aus 16-Bericht: `gomailctl mailbox share` fehlt (9.2) → 13 prüfen/decken; `--insecure-no-log` noch in gomailctl (→14) und gomail-ceremony (→15b, `init --dev --insecure-no-log`); e2e-Helfer `GOMAIL_E2E_HELPER=log-append` in TestMain mit TODO(task-14) → 14 entfernt ihn, Skript nutzt dann gomailctl; Befehl/Testschalter zum Halten von locks/client für --require-client-lock (TODO(ask)) → SPEC-ISSUES offen + 13/14 erwägen; zweiter Server-Test braucht Ingest-Schlüsselkopie (serve liest Schlüssel vor Sperre) → 14/19 Hinweis; DECISIONS: NFS vers=4 ohne nolock/local_lock, gleiche gid (sec=sys); Zeugenkopf des Laufs im Zwei-Maschinen-Modus abwarten (MinGap) → 19/20.
- Aus 16-Verifikation (9b): `gomail-server serve` liest den Ingest-Schlüssel vor der Rollensperre → Serverprüfung der Sperre vor dem Laden des Schlüssels (Produktivcode, klein) → in 14 oder 19/20 aufnehmen; AUDIT erwähnen. Adresse im Klartext in addresses.json/Log = Produktentwurf (SPEC-ISSUES bereits? prüfen).
- Task 19 (aus 16c-Verifikation, niedrig): `curl -q`, `set +o xtrace +o verbose` am Skriptanfang; RUNBOOK: Signal an Prozessgruppe (oder lange Befehle via `wait`); `ln -s … || die` für --mount Elternverzeichnis (Exit 2); usage-Zeile --keep (Passphrase-Datei wird trotzdem gelöscht).
- Task 20/HANDOFF: `go test -race ./internal/client` braucht >10 min (Standard-Timeout von go test) → in scripts/Doku `-timeout 40m` nennen; 13/14/20 erwägen, langsame Clienttests zu bündeln oder mit t.Parallel zu beschleunigen (nur Testcode).
- S80 (SPEC-ISSUES Welle 4): kein `gomail-server init`; nur `init --dev` ruft store.Init auf und das nur unter gomail_dev → Produktionsweg zum Anlegen des Datenverzeichnisses fehlt (publish? Serverstart?) → nach 15b-Prüfung klären: kleiner Code-Auftrag (publish legt das Datenverzeichnis an, falls leer, oder `gomail-server init --pin`) vor 19/TestRunbook. S34 auf „erledigt durch D82 (4)“ setzen. Q11 ohne S-Punkt → 20.
- Aus 13-Bericht: `list` ohne Absenderspalte (strengste Lesart) → RUNBOOK 19 nachziehen, SPEC-ISSUES klarstellend; `restore` und `flag` nicht in 9.2 (TODO(ask)) → SPEC-ISSUES; Worteingabe ohne Echo-Abschaltung (TODO(ask)) → nach Prüfung entscheiden; TODO(task-13) in client/keygen.go (ShowShares im Prompter-Interface) → 14 oder 20; Exit 3 bei ErrPartial auch für sync → RUNBOOK; ForceNewGeneration-Schalter entfällt mit 14 (D84).
- Aus 13b: `filesWithWords` in internal/e2e/twohost_test.go zählt drei beliebige BIP39-Wörter als Treffer → flaky (protokoll.md mit client/lock/key/mail) → 20 (oder 14/19): nur nummerierte Wörter oder Folgen von ≥ 3 aufeinanderfolgenden Seed-Wörtern zählen. Testbuild-Schalter GOMAILCTL_TEST_KEYGEN_PIPE (nur -tags gomail_test) → SPEC-ISSUES/DECISIONS (D86 bei 13-Merge). TODO(task-13) in client/keygen.go → nach 14-Merge (20). CleanText C1/Bidi → D86. TODO(ask): Seed vor der Abfrage gelöscht; Passphrase am Terminal mit Echo → D86/SPEC-ISSUES.
- Aus 14-Bericht (für D86/SPEC-ISSUES beim Merge): Config.Log entfernt (Client baut Log selbst), BeforeRefresh Test-Hook; LogKeys nicht persistiert, gespeicherter Kopf ohne Signaturprüfung geparst (Vertrauenszone D57, TODO(ask) in doc.go); Verlierer-Epoche nur bei ErrOrder ersetzt, ErrDuplicate nie (doc.go Schritt 4); mailbox.rec hinter neuester geloggter Epoche = ErrRollback für Leser (SPEC-ISSUES 2.7 klarstellend); Adressprüfung: ein Refresh je Operation bei ErrNotInLog/ErrMismatch; Vermerk-Warnungen nur Postfach+Geräte-ID; Testschalter GOMAIL_TEST_DEV_IDENTITY, GOMAIL_TEST_HEAD_GAP (nur gomail_test); address add bleibt Argumentform (9.2); internal/client -race 1489 s, 386 868 s → 20/HANDOFF (-timeout 40m).
- Nach 14b-Merge (kleiner Auftrag oder 20): client/keygen.go schreibt keystore+user.rec vor state.json → Signal im Fenster hinterlässt halbes Verzeichnis, keygen lehnt danach ab (13c-Prüfung B15) → atomar (Temp-Verzeichnis + Rename) oder Wiederaufnahme erlauben.
- Task 20 (aus 15i): TestPTYSignalSalvo Teil „mixed“ (25 Läufe) unter Last fragil: Mindestabdeckung über beide Salven zusammen oder mehr Läufe; internal/bench/diskspace_unix_test.go unter openbsd: Statfs_t.Bavail → F_bavail (Build-Tag-Variante). D85-Ergänzung bei 15i-Merge: SIGPIPE von openTerm bis Exit angenommen/verworfen; EPIPE auf Prompt vor Commit → Abbruchpfad; Prompts schreiben nach Abbruchbeginn nichts mehr.
- D86 (14/14b bei Merge) + SPEC-ISSUES: 2.5 „entzogen“ nach Append (ohne deckenden Kopf); 2.4 Read geprüfter Epoche nach Rollback erlaubt; nie loggbare Epoche am Kopf wird mit gleicher Nummer durch Reparatur-Epoche ersetzt (Kopf sinkt nie; Ingest hat für sie nie verschlüsselt); Schritt 4: dem Log widersprechende Epoche ersetzt kein Client (Betreiber); 2.7: beidseitige Ordnung der Kopfzeiten (Vermerk größer+früher oder Kopf kleiner+später = ErrConsistency); „älterer Kopf veröffentlicht“ nur Warnung bei frischem Referenzkopf (ErrOlderHead, TODO(ask)); Q20 strengste Lesart gebaut; state.Checkpointed; Register-Abhilfe; Unconfirmed-Warnung bei jedem Open.
- Task 20 (aus 15k): store.ReadFileLimited mit O_NONBLOCK öffnen (dann hängt auch gomail-ceremony nicht an FIFO) → kleiner Auftrag oder 20 (store ist kein Phase-0-Paket). D87 (15h/15k): init legt an, publish nur vorhanden; Symlinks für --data und letztes Elternelement abgelehnt; Gruppe ≠ gomail nur Warnung (TODO(ask)); Dev-Pin außerhalb gomail_dev überall Exit 2; Restrisiko Inode-Wiederverwendung über Modus+Eigentümer.
- Aus 14b-Angreifer (niedrig, bei 14-Merge in D86 + AUDIT): kolludierendes gültiges Mitglied kann über frei signierten Vermerk (size/root/head_time nicht an Kopf gebunden) einen Mit-Benutzer dauerhaft sperren (ErrLog split view) → Restrisiko DoS im Modell (2.7 Erkennung, nicht Verfügbarkeit); Vorschlag Korroboration/Warnung statt Stopp → SPEC-ISSUES offen; warnContradicts auch am Kopf (n == head, errEpochContradicts) → 20 (nur Meldungstext).
- Task 20 / AUDIT (aus 15l): TCSETSF auf stdin wartet unter Linux auf abgeflossene Ausgabe → Abbruchpfad kann bei stdin-Terminal mit voller Ausgabe hängen (praktisch ausgeschlossen bei echtem Emulator; dokumentierte Grenze). D85-Ergänzung bei 15i/15l-Merge: stderr muss Terminal/Pipe/reguläre Datei sein (/dev/null, geschlossenes fd 2 → Exit 2); stdout wird vor stderr gelöscht; stderr-Flusssteuerung geräumt; Abbruchpfad je Schritt 400 ms.
- Aus 14b-Spezifikation (niedrig → 20): Test für commitHead-Absenkverbot (Mutation überlebt; über export_test.go); doc.go Schritt 4 „beyond the head“ präzisieren oder warnContradicts auch in der Kette; doppelter epochLogged-Aufruf in loadChain (Append zweimal unter log/lock). SPEC-ISSUES: head_time-Ordnung beidseitig als Betriebsregel (Server signiert nie kleinere Größe nach größerer) 2.7/9.1; Q20: Bestätigung durch eigenes zweites Gerät?; Reparatur-Epoche Grund regular + Beginn (Lesart); nicht loggbare Epoche 1 = DoS; Widerspruch in der Kette: Betreiber-Abhilfe unklar.
- Aus 14c: e2e-Lücke: Regel „Metadaten der Ingest-Generation 1 nach valid_from abgelehnt“ im Client-Log von gomailctl durch keinen e2e-Test gedeckt (succession_test prüft über eigenes Client-Log) → 19/20; HANDOFF: Tests in internal/client, cmd/gomailctl, internal/e2e nur mit -tags gomail_dev,gomail_test aussagekräftig (00-vorgaben-Fertigkriterien entsprechend lesen); weitere feste Sleeps in gomailctl-PTY-Tests (TestPtyWordsStdoutRedirected 100 ms, TestPtyDoubleEnterAtHolder 1 s, TestPtyRestoreStderrClosed 200 ms) → 20 auf quiet umstellen.
- Task 20 (aus 13e-Prüfung, niedrig): sameTerminal bei gleichem rdev außerhalb /dev/tty zusätzlich gleiches st_dev (devpts-Instanz) verlangen (zwei devpts-Instanzen, gleiche Pts-Nummer → angenommen, keine Wörter sichtbar); TestIsControllingFd letzter Block prüft TIOCGPGRP nicht (Kommentar/Test); Kommentar in sameControlling: TIOCGPGRP ist die tragende Prüfung. Merge-Reihenfolge: 14 vor 13e (beide ändern pty_linux_test.go).

## Merge-Prüfung 13e/13f (niedrig, für 20 / AUDIT)
- isControllingFd (TIOCGDEV==tty_nr) nur per TestIsControllingFd belegt; E2E hält allein durch TIOCGPGRP-ENOTTY aus fremder Sitzung. Doppelschutz ohne E2E-Nachweis → 20 prüfen, ob Test mit gleichem pgrp möglich.
- BSD: isDevTTYNumber immer false; ohne /dev/tty im FS (chroot) gelten geerbte /dev/tty-fds mit gleichem rdev als dasselbe Terminal. AUDIT: bekannte Grenze.
- Sitzungs-Trailer im Agent-Commit 431ca8e: entfällt durch Squash-Merge.

## Aus Auftrag 18 (für 20)
- Veraltete Paketkommentare: internal/translog/translog.go und translogtest/unverified.go („until task 15 … --insecure-no-log“), internal/ceremony/ceremony.go („only with --insecure-no-log … task 14“), translog/doc.go Pin („client.Config does not have AllowDevIdentity yet“), cmd/gomail-server Paketkommentar `address add` („no message names the address“ vs. Ausgabe `<adresse> -> <postfach>`).
- PLAN 9.3 nennt Paket `search`, Suche liegt in `client` → HANDOFF erwähnen.
- DECISIONS: D87 steht vor D86 (nur Reihenfolge).
- Kein Fuzz-Ziel für Client-Prüfpfade und Zeremonie → 20 prüfen, ob 10.1 eins verlangt.
- AUDIT nach Merges von 09b, 13e, 15m nachziehen (R1, R3–R6, R27; „in Arbeit“ ersetzen).

## Aus 15m (Implementierer)
- 19 RUNBOOK: Satz „stderr muss zum Schreiben geöffnet sein (Exit 2 sonst)“; Abbruch endet spätestens nach ~1,8 s; Restgrenze: Terminal, dessen Leser nie liest, zeigt den Clear nie.
- 20: TestPTY reshare Wortpaar-Heuristik (~0,2 %/Lauf): Paare ignorieren, die auch in später angezeigten neuen Anteilen stehen.
- 15m-Abweichung vom Auftragstext: TCOOFF+TCOON statt TCOON allein (XOFF/Scroll-Lock); normale Clears starten Ausgabe ebenfalls neu; TCOFLUSH nur bei hängendem Schreiber. → D85-Nachtrag.
- BSD/Darwin nur per vet geprüft → AUDIT/HANDOFF.

## Aus SPEC-ISSUES-Bereinigung (6ca78d9)
- 20: toter Kommentar cmd/gomailctl/commands.go:43-46 (`device lost --force-new-generation`, DeviceLostOptions, TODO(ask)) entfernen.
- S88/S89 nur per Codelesen belegt → 20: Test für Vermerk-DoS (ErrLog dauerhaft) und nicht loggbare Epoche 1 (ErrChain vor healHead; Warnung nennt unwirksame Abhilfe) – mindestens Warnungstext prüfen.
- Ohne S-Punkt, für AUDIT/HANDOFF: D86 Passphrase-Echo / Seed-Löschen vor Abfrage (TODO(ask)); D87 (4) Gruppenname; Q19-Nachtrag (neuer init statt Nachfolge bei kompromittiertem Root).

## Aus 18b
- D88 (9) präzisieren: internal/e2e nur für testenv-Tests tag-abhängig; e2e setzt GOMAIL_TEST_MIN_FREE selbst (testMinFree) → 09b-Nachtrag-Satz überholt (harmlos). Mein fullrun.sh setzt es trotzdem nur für e2e: ok.
- TestTwoHostScript scheiterte 1× unter Last ohne Tags (Teiltest nicht mitgeschrieben) → 20.
- AUDIT Kopf: Code-Stand ef083df; nach Merges 09b/13e/15n in 20 nachziehen.

## Aus 18b-Nachprüfung (niedrig, AUDIT in 20)
- R35: TestProductionBuild aus dem Nachsatz „im Lauf mit beiden Tags übersprungen“ nehmen (besteht in Lauf 3).
- 7.2: DragonFly-Eintrag steht nicht in DECISIONS/QUESTIONS, nur TODO(ask) im Code → Einleitung der Liste anpassen.
- 6.5: CLI lehnt --compromised ebenfalls ab (main.go usage(errCompromised)); 6.1: cmd/gomail-server überspringt über ceremony.InitDev-Fehler, nicht testenv; „überspringt sich nichts“ nur tag-bezogen.

## Aus 19
- 20 (Produktivcode, klein): `serve`/ingest.New lehnt Ingest-Schlüssel ab, dessen valid_from in der Zukunft liegt (sonst signiert ein zu früh gestarteter Server Mails, die Clients ablehnen; Verfügbarkeit). SPEC-ISSUES klarstellend.
- D88-Nachtrag: e2e-Lücke „Ingest-Gen 1 nach valid_from via gomailctl“ durch TestRunbook Schritt 6 geschlossen. D83-Nachtrag: vier Skriptpunkte in 19 erledigt.
- RUNBOOK Abschnitt 2 nimmt 15l/15m/15n vorweg (stderr schreibbar, ~2 s) → beim 15n-Merge prüfen + Platzhalter confirmDelay füllen.
- Q18: zweites Benutzer-Mitglied als Vorbeugung empfehlen (RUNBOOK 8.4).
- TestRunbook: --replace-witnesses nur in TestSuccessionEndToEnd; restore --shares mit shamir.Split statt PTY-keygen.
- 20: Doc-Kommentar von serve in cmd/gomail-server/main.go (~27–48, „checks, in this order“) an tatsächliche Reihenfolge / RUNBOOK 1.6 angleichen.

## Aus 15n (für D85-Nachtrag beim Merge, RUNBOOK-Platzhalter)
- D: outputGrace 2 s, Wiederanlauf alle 1 ms (push), Anteilszeile+Aufforderung teilen Frist (stallEnd), Fehler/Zeitüberschreitung → Exit 130, Inhaber n+1 erst nach vollständigem Clear; O_NONBLOCK auf stdout/stderr gelöscht, nicht wiederhergestellt; confirmDelay 1 s, frühe Eingabe → „Eingabe zu früh, bitte erneut bestätigen“, Verwerfen nur nach Wartezeit; Abbruch: Schreibfehler = Zeitüberschreitung, stdout-Clear nutzt Restzeit von abortTotal.
- RUNBOOK-Satz confirmDelay (aus Bericht) + optional „der Bildschirm nimmt nichts mehr an“ → Exit 130.
- Restgrenzen: unvollständige Zeile während Wartezeit zählt nicht als zu früh; µs-Fenster Prüfung/Verwerfen.
- TestPTYSignalSalvo >60 % der Paketlaufzeit (400–470 s race); Ausreißer TestPTYQuitInCommit 61 s → 20 beobachten.

## Aus 19b-Nachprüfung (niedrig, RUNBOOK in 20)
- RUNBOOK 1.6 Schritt 6: Reihenfolge in ingest.New: Zertifikat/Logeintrag → Serversperre → Client-Sperre → checkGeneration („nicht abgelöst“).
- RUNBOOK 4.7: revoke eines Vertreters (share --to) ergibt reason 4 (ReasonDelegationEnded); „Mail nach dem Entzug in neuer Epoche“ gilt bis zur nächsten geplanten Monatsepoche (auch ohne carol).

## Aus 09b-Angreifer (für 09c)
- Hinweis: readSegments hält alle Segmente im Speicher (Anzahl unbegrenzt, je bis 4 MiB) → 09c mitbegrenzen.
- Upgrade: Vermerke aus 06b ohne Tree zählen nicht mehr (nur PoC-relevant) → DECISIONS.

## Aus 15n-Prüfungen (niedrig, für 20)
- N1: vt.confirm in 15m/15n-Tests beantwortet earlyHint nicht (answerPause 120 ms fest) → unter Last kippbar; erneut bestätigen bei earlyHint.
- N2: Mutation „unblock als No-op“ überlebt (TCOFLUSH rettet) → Test mit O_NONBLOCK + kurzem TCOOFF ohne Verwerfen, normaler Pfad ohne Abbruch.
- N3: waking-Goroutinen bei exit nicht abgewartet; TCOOFF→TCOON-Fenster kann Terminal gestoppt lassen (0/300) → stop wartet auf done; letzter Schritt einzelnes TCOON.
- TestPTYSignalSalvo 256 s unter Last; Paket race knapp < 10 min → 20 beobachten.
- plan9 build scheitert (gewollt laut Kommentar) → HANDOFF.

## Aus 09c (Implementierer)
- D-Nachtrag D79/D84: Segment-Vermerke an (Epoche, file_id, SHA-256); alte Vermerke bleiben, zählen nicht; Lesegrenze 4096/256 MiB mit ErrPartial; Datenverzeichnis-Fehler vor Widerruf → Warnung+Vormerkung+ErrPartial, auch mailboxes/-Auflistung; Neusignatur-Fehler → Warnung. Legitimes Wachstum: 361 B/Mail gelistet, 330 B/Indexlauf, 232 B/Flags, 300 B/Zusammenfassung; worst ~920 B/Mail → ~70 000 Mails bis 64 MiB → AUDIT/HANDOFF (Grenze!).
- Folge (20 oder später): store.ListIndexSegments liest ganzes Verzeichnis vor der Grenze → ReadDir(n); writeSegments eigene Vermerke sofort (index-gone-Fall).
- AUDIT: >4096 ungültige Dateien → Search dauerhaft ErrPartial (sichtbares DoS).
- Q11 offen (Laufnummer nicht in Datei gebunden).

## Aus 20a (für DECISIONS beim Merge)
- Entscheidung des Orchestrators: Der Server verweigert einen Ingest-Schlüssel vor `valid_from` **ohne** `MaxClockSkew`-Toleranz. Grund: Clients prüfen die gestempelte Empfangszeit ohne Toleranz gegen `valid_from`, eine Toleranz ließe den Server Mails signieren, die Clients ablehnen. Abweichung vom Auftragstext ist damit strenger und bestätigt.
- D85: Abbruchpfad endet mit `stopWaking` (alle Wiederanlauf-Goroutinen) und einem einzelnen TCOON/TIOCSTART; Fenster „Terminal nach Exit gestoppt“ geschlossen; `TestPTYUnblockBrief` schließt die unblock-Lücke.
- D87: `ReadFileLimited` mit O_NONBLOCK. D86: `sameDevice` mit st_dev (devpts nur per Einheitstest).
- RUNBOOK 10 ergänzen: Server-Uhr gibt den Start mit neuem Ingest-Schlüssel frei.

## Aus 09d (für DECISIONS beim Merge)
- D84 (2) präzisieren: Kein Pfad entfernt Einträge aus `Checked`; ein Eintrag darf an Ort und Stelle zu `{hash, next}` geändert werden (zählt dann nie mehr für eine Übernahme), ohne zu wachsen.
- D79 (1): MergeThreshold zählt nur verschiedene gültige Segmente; byte-gleiche Kopien einmal je Lauf, Leser ignorieren, mergeSegments entfernt unter Sperre; Index schreibt keine schon enthaltenen Einträge; Altformat-Vermerke zählen für genau ihren Inhalt.
- D84 Schritt 4: gescheiterte Neuausstellung → ErrPartial + Vormerkung, Sync setzt fort; Search/List/Read tolerant.
- Orchestrator-Entscheidung: zurückgespieltes pending nach Segmentlöschung wird über Merkmal „indexiert“ im bestehenden Eintrag je Mail geschlossen (durch legitime Mails begrenzt).
- AUDIT: Nachfolger gelöscht + markierter Inhalt zurückgelegt → Treffer fehlen (Verfügbarkeit, Löschen kann der Angreifer ohnehin).

## Aus der Spezifikationsprüfung von 20a (niedrig, für 20)
- `TestPtyRestoreStderrClosed` (pty13d_linux_test.go:309): Schleife bis inputQueued==0 wartet meist nicht (TIOCINQ 0 in 884/1000 direkt nach dem Schreiben) → erst auf >0 warten oder quiet mit Echo.
- `terminalID` füllt st_dev ungeprüft → Test `terminalID(slave).dev == Stat(slave).Dev`.
- `wordRun` (twohost_test.go:1170): Trenner nur 1–4 Nicht-Buchstaben; eingerückter Seed wird nicht gefunden → Trenner beliebiger Länge aus Leerraum.
- Veraltete Kommentare: translog.go:43 („Warning is printed … with Unverified“), doc.go:1173 („only --insecure-no-log … until task 15“).
- AUDIT: ceremony/publish.go:84 readExport öffnet `<from>/platform` mit os.Open ohne Prüfung → FIFO lässt publish hängen (Betreibereingabe).

## Aus der Angreiferprüfung von 20a (niedrig, für 20 und AUDIT)
- `resume` (TCOON am Ende des Abbruchpfads) kann eine über das ganze Fenster blockierte Anteilszeile nach dem letzten Löschen durchlassen. Nur mit einer Mutante nachstellbar, die jeden Wiederanlauf verliert (5/30 ABA). Mit den echten Binaries kam der Anteil immer nach 8–198 ms durch. Vorschlag: stdout nur freigeben, wenn der Abbruchpfad `t.out` erhalten hat, oder nach `resume` ein begrenztes Löschen.
- O_NONBLOCK auf gemeinsamem Deskriptor macht auch stdin nicht blockierend (AAA/AAB enter/stop → Exit 1 statt 130, Anteil gelöscht; Basis gleich).
- Weitere `os.Open` ohne O_NONBLOCK: ceremony/files.go:109, translog/operator.go:341/776/810 (Verzeichnisse, syncFile) → FIFO hängt; Betreiber-/Datenverzeichnis-Pfade → AUDIT.
- `sameDevice`: statisch per mknod angelegter Knoten auf anderem FS (chroot) wird jetzt verweigert (sichere Richtung) → HANDOFF.
- hasWords findet keine Spalten mit ≥ 5 Füllzeichen, NUL-Füllung, ANSI zwischen Wörtern, UTF-16 (Formate, die das Programm nicht erzeugt).
- Alte Angriffsskripte (multi.py, salvo4.py, stuck.py) beantworten Fragen vor confirmDelay bzw. nie; angepasste Fassungen unter verify20a-attack2.

## Aus 09e (für DECISIONS beim Merge)
- (a) Vermerk „indexiert“ je Art (Marker `indexed`, Begriffsliste `indexed_terms`); Begriffsliste nach Marker wird indexiert, Marker nach Begriffsliste nicht; höchstens ein Feld mehr je Mail.
- (b) Zusammenfassen nur bei mehr verschiedenen Postings als bei der letzten eigenen Zusammenfassung (`merged` je Epoche, nur steigend) – begrenzt erzwungene Zusammenfassungen durch Postings der Epoche.
- (c) Unter Neuausstellung: Austausch/Entfernen im Fenster, errStale, nicht bestätigte eigene Generation, MaxUint32 → nicht neu ausgestellt (ErrPartial, Vormerkung).
- (d) AUDIT: Austausch/Entfernen vor dem Lesen in Schritt 4 betrifft nur Verfügbarkeit; MaxUint32-Metadatei eines Mitglieds hält die Vormerkung dauerhaft.
- (e) Kopie gilt nur nach Annahme der vorigen Datei gleichen Inhalts als erledigt.
- 09e: race client 2003 s, 386 1733 s, Abdeckung client 87,7 %.

## Aus der Spezifikationsprüfung von 09d (f982400; Fund mittel und Kopie-unter-Laufnummer-0 in 09e behoben)
- Testlücken (niedrig): Reihenfolge „Marken speichern vor Entfernen“ (merge V13, resign V14, Index V18) ohne Test; `reissuing` nicht zurückgesetzt (V8, nur im selben Prozess nach Sync sichtbar).
- D84 (2) Text um „ändern ohne Wachsen“ ergänzen (beim Merge von 09e).

## Flake aus dem Volllauf 09f (386)
- `internal/client` `TestWordErrorsNameNoInput` (generations_test.go:503): Der Test prüft, dass die Fehlermeldung `f.u.Words[0]` nicht enthält. Die feste Meldung „keys: word is not in the BIP-39 list: word 4“ enthält aber BIP-39-Wörter wie „word“ und „list“. Ist das erste Seed-Wort zufällig eines davon (etwa 2/2048), scheitert der Test. Er besteht seit vor 09f; nur Testcode, auf ganze Wörter prüfen, die nicht in der festen Meldung stehen.

## Aus 18c (für 20 und HANDOFF)
- D85: Abbruchdauer einheitlich formulieren („Schrittgrenze `abortTotal` 1,5 s, Ende unter 2 s“), Paketkommentar und D85 (c) abgleichen.
- HANDOFF: statisch per mknod angelegter Terminalknoten auf anderem Dateisystem wird von `gomailctl` verweigert (AUDIT R6 c).
- R41-Stellen (D87-Nachtrag) im Rahmen von 20 nach Art von `ReadFileLimited` absichern, soweit es Dateien sind.

## Aus der Prüfung von 18c (niedrig, AUDIT in 20)
- 6.2 „Kein Klartext“: `TestHasWords` (internal/e2e/twohost_test.go) nennen; `runbook_test.go` mit Präfix `internal/e2e/`.
- R3/6.5: Abbruch „etwa 1,5 s plus wenige `abortFloor`“ (TestAbortBounded 1,61 s), mit RUNBOOK 2 abgleichen.
- R14: „bis dahin muss der Server mit dem bisherigen Schlüssel weiterlaufen bzw. neu gestartet werden“.
- R3: Beleg 15b (Flusssteuerung auf beiden Terminals geräumt, Bildschirmschreiben nicht unter Handler-Sperre) wieder aufnehmen.

## Aus den Prüfungen von 09g (niedrig) und dem Merge der Linie 09b
- Testlücke: Einsparregel für Ergebnisse ab 32 Segmenten (Ergebnis aus zwei und mehr Segmenten, Schwelle `counted − written ≥ MergeThreshold − 1`).
- Belegtests der Prüfung von 09f (`zz_v09f_spec_test.go`, `TestZZV09f…`, Scratchpad der Prüfung) in die Tests übernehmen, soweit nicht schon durch `takeover09g_test.go` abgedeckt.
- P3-f in `internal/client/index.go` kommentieren.
- Wachstum je Epoche in `internal/client/index.go` ausdrücklich nennen (Formel aus D91: etwa 270 B · D · k je Sync, ab (D − 1) · k ≥ 16; ein Gerät 300 B · k).
- AUDIT: R27, 6.5 und 8.1 Punkt 3 auf den Stand nach D91 bringen (Übernahme für Metadaten und Segmente, `internal/terms`, Wachstumsformel und Messwerte); Zeile 5 und Kopf aktualisieren.
- D79-Nachtrag: SHA-256 der Metadatendatei im Merkzettel und `from:`/`to:` aus gekürzten Werten prüfen, ob 09b sie erledigt hat, sonst in AUDIT nennen.

## Aus der Prüfung von 20c (für 20 und später)
- D91 (5) und Kommentar an `TestAttack09fForcedMergesDevices` angleichen: Der Code fasst zusammen bei `counted − len(result) ≥ MergeThreshold − 1` und `counted ≥ 16`; das ergibt erzwungene Zusammenfassungen ab (D − 1) · k ≥ 15, nicht 16 (Hinweis, kein Fund).
- Vorschläge D-1 bis D-4, S-1 bis S-9, R-1 bis R-3 und P-1, P-2 stehen in `docs/tasks/20-triage.md`; der Orchestrator übernimmt sie (P-2 als kleiner Produktivcode-Auftrag nach 20b).

## Fuzzing für 10.2 (Orchestrator, 03.11.)
- 19 Ziele auf bf427c2 (Code gleich 3e06f23), je `-fuzztime 10m -parallel 1`, zwei Bahnen gleichzeitig: alle ohne Fund. Protokolle im Scratchpad unter `orch/fz/`.
- Die 6 Ziele in `translog` (5) und `store` (1) laufen auf dem Stand von 20b (WIP 84ca174), weil 20b dort Code ändert; ändert der endgültige 20b-Commit diese Pakete noch, wird nachgefuzzt.

| Paket | Ziel | Ausführungen in 10 min |
|---|---|---|
| `internal/envelope` | `FuzzParseAndOpen` | 829.752 |
| `internal/ingest` | `FuzzTerms` | 1.465.639 |
| `internal/keys` | `FuzzDecodeGenerationCert` | 9.322.292 |
| `internal/keys` | `FuzzOpenKeystore` | 10.126.628 |
| `internal/keys` | `FuzzParseWordlist` | 526.897 |
| `internal/keys` | `FuzzSeedFromWords` | 8.829.700 |
| `internal/loghttp` | `FuzzServer` | 3.093.479 |
| `internal/rec` | `FuzzDecode` | 10.877.835 |
| `internal/rec` | `FuzzIsNFC` | 9.876.698 |
| `internal/shamir` | `FuzzCombine` | 4.165.047 |
| `internal/shamir` | `FuzzShareFromBytes` | 12.377.691 |
| `internal/shamir` | `FuzzShareFromWords` | 9.791.607 |
| `internal/smtpd` | `FuzzCommands` | 3.568.702 |
| `internal/smtpd` | `FuzzData` | 3.901.203 |
| `internal/witness` | `FuzzCosign` | 3.365.961 |
| `internal/witness` | `FuzzDecodeWitnesses` | 4.052.309 |
| `internal/witness` | `FuzzParseProof` | 4.227.219 |
| `internal/witness` | `FuzzPoll` | 1.327.905 |
| `internal/words` | `FuzzNormalize` | 2.960.008 |

## Aus 20b (Implementierer, außerhalb des Auftrags)
- `client.Restore` (`restore.go`) schreibt das Client-Verzeichnis nicht atomar (wie `keygen` vor 20b) → Auftrag 20e.
- Ein abgebrochenes `keygen` hinterlässt `.<name>.keygen-*` neben dem Client-Verzeichnis (versiegelter Schlüsselspeicher, öffentliches `user.rec`); nichts räumt es auf → 20e oder HANDOFF/RUNBOOK.
- `ListIndexSegments` liest Namen, die keine Segmente sind, in `index/<n>/` ohne Grenze; nur Segmentnamen zählen zur Grenze → AUDIT oder 20e.
- Neue Abhilfe am Kopf (`warnContradicts`, „Datei durch den Inhalt des geprüften Logeintrags ersetzen“) → RUNBOOK und D86-Nachtrag beim Merge.
- `lockOnlyDir`: `keygen` ersetzt ein Verzeichnis, das nur die Sperrdatei von `Open` enthält → DECISIONS-Nachtrag beim Merge.
- `internal/client` unter race bei geteilten CPUs bis 44 Minuten → HANDOFF: `-timeout 60m` mindestens.
- P-2 aus `20-triage.md` (Vermerk für eigene neue Segmente) → 20e.

### Fuzzing, zweiter Teil (auf 84ca174; `translog` und `store` gleich cb2344c, Ergebnis von 20b)
- 6 Ziele, je 10 Minuten, zwei Bahnen: alle ohne Fund. Damit sind alle 25 Ziele aus 10.2 je 10 Minuten ohne Fund gelaufen. Protokolle im Scratchpad unter `orch/fz2/`.

| Paket | Ziel | Ausführungen in 10 min |
|---|---|---|
| `internal/store` | `FuzzDecodeRecords` | 9.012.891 |
| `internal/translog` | `FuzzAuditIndex` | 1.777.338 |
| `internal/translog` | `FuzzDecodeEntry` | 6.482.206 |
| `internal/translog` | `FuzzOpenHead` | 5.766.720 |
| `internal/translog` | `FuzzParseHeadText` | 7.979.507 |
| `internal/translog` | `FuzzProofs` | 4.926.791 |

## Aus der Spezifikationsprüfung von 20b (keine Funde über niedrig; für 20e)
- `internal/translog/files.go:183` `newestHeadSize` öffnet `heads/` noch mit `os.Open` (R41-Klasse wie `eachHead`) → `store.OpenDir`, `fs.ErrNotExist` beibehalten.
- `ListIndexSegments` über der Grenze: Teilmenge in Verzeichnisreihenfolge; `writeSegmentList` kann die höchste eigene Laufnummer verfehlen → `ErrExists`, bis 64 Versuche, fail closed. Im Funktionskommentar nennen.
- `createClientDir`: `syscall.Rename` auf ein leeres Ziel scheitert, wenn das Ziel ein Einhängepunkt ist (EBUSY/EXDEV) → RUNBOOK/Kommentar.
- Liegengebliebene `.<name>.keygen-*` beim nächsten `keygen` entfernen.
- Abhilfetext am Kopf in RUNBOOK und D86.
- Hinweis: `GOOS=solaris|illumos` vet scheitert an `syscall.Mkfifo` in den neuen FIFO-Tests (gleiches Muster wie bestehende Tests); `lockOnlyDir` könnte `store.OpenDir` nutzen.

## Aus der Angreiferprüfung von 20b (keine Funde über niedrig; für 20e und AUDIT)
- L1: `keygen` gegen gleichzeitiges `Open`/`Restore` desselben Verzeichnisses: `ENOTEMPTY` wird als `ErrExists` „nicht leer“ gemeldet (irreführend), kein Verlust, Wiederholen gelingt → einmal wiederholen oder Meldung „nicht leer oder in Benutzung“.
- L2: `lockOnlyDir` entfernt jede reguläre Datei `lock`, unabhängig vom Inhalt (nur mit Schreibzugriff auf das Client-Verzeichnis) → Kommentar.
- L3: liegengebliebene `.<name>.keygen-*` (0700; versiegelter Schlüsselspeicher, `user.rec`, `state.json`) → aufräumen oder AUDIT-Satz.
- L4: AUDIT R33 und D86 „Zurückgestellt“ beschreiben das halbe Verzeichnis von `keygen` noch als offen → beim Merge von 20b berichtigen.
- L5: über `MaxListedIndexSegments` Teilmenge in Verzeichnisreihenfolge (wie Spezifikationsprüfung).
- Hinweis, schon vorher: `OpenRegular`/`ReadFileLimited` ohne `O_NOCTTY`.
- Angriffstests: Scratchpad `verify20b-attack/src/` (`zz_attack20b_*`).

## Aus 20f und seiner Prüfung (für 20g und 20)
- `internal/testenv` hat 0 % Abdeckung (Test-Infrastruktur ohne eigene Tests). Entscheidung des Orchestrators: Kriterium E gilt für jedes Paket unter `internal/`, also bekommt `testenv` eigene Tests (20g); nicht gelockert.
- F-1 (Z3 ohne Volltext): Test Gerätewechsel mit Übernahme der Indexsegmente (`devicechange_test.go`, Beschreibung in `docs/tasks/20-mandatory-tests.md`) → 20g nach 20e.
- F-2 (S9) nach Q19/Q8; F-3 (S7) außerhalb M1.
- Prüfung (niedrig): `TestTypedRoundTripOutsideStore` doppelt bestehende Tests, Kommentar „vier Arten“ falsch → entfernen oder berichtigen; `TestAllSchemasListed` sucht per Regex (übersieht Struct-Literale und Aliasimporte, meldet auskommentierte Aufrufe) → mit `go/parser`; Text „Höchstlänge“ in der Testbeschreibung → „bis 300 Byte bzw. höchstens MaxLen“. → 20g.
- AUDIT 6.2 und HANDOFF (Abdeckungstabelle, Kriterium E) nach Vorschlag in 20f → 20.

## Aus 20g (Implementierer, Produktivcode, für 20h)
- `client.(*Client).CreateMailbox` nach `Close` panikt (nil-Dereferenz in `prepareMailbox`, `internal/client/mailbox.go:556`; `Close` setzt `c.ks` auf nil). Fehler über `errors.Is` statt Panik, für alle öffentlichen Methoden nach `Close` prüfen.
- Kommentar an `testenv.ImmediateEpoch` beschreibt einen Fall (reguläre Epoche mit Verwürfen), den der Code nicht erzeugt.
- Prüfung von 20g (niedrig): die meisten `fatalOn`/`expectFatal`-Fälle in `internal/testenv/dev_test.go` prüfen nur, dass Fatal kam, nicht den Grund → Teiltext je Fall prüfen (20h oder später).

## Aus 20e (Implementierer, für den Merge und 20)
- Commit bc0d0f9 im Worktree agent-ad3c9d3b67fe2389b (Squash-Basis 018bb56 = 2bbe23b + 20b). Alle Läufe grün (386 `client` nach Testberichtigung: Jahr 2200 passt nicht in 32-Bit-`time_t`); `client` 88,1 %.
- `Restore` verweigert jetzt ein nicht leeres Verzeichnis (`ErrExists`); neues Temp-Präfix `.<name>.restore-*`; Aufräumregel (nur eigene Art, eigener Benutzer, echte Verzeichnisse, älter als der eigene Lauf) → RUNBOOK und DECISIONS-Nachtrag (D84 oder D91) beim Merge.
- D91-Nachtrag: Seit 20e legt ein Schreiber den Vermerk für sein eigenes Segment beim Schreiben an (`noteWritten`); die gemessenen Raten sind unverändert.
- AUDIT R33/L3: Reste werden beim nächsten erfolgreichen Lauf derselben Art entfernt; ein Rest der anderen Art bleibt.
- `internal/client` unter race mit Tags bis 3401 s bei geteilten CPUs → HANDOFF: `-timeout 60m` knapp; Abschlussläufe ohne parallele Last.
- `translog/files.go` geändert → Fuzzing von `translog` nach dem Merge wiederholen (5 Ziele).

## Aus der Angreiferprüfung von 20e (keine Funde über niedrig; für 20h)
- F1: `removeLeftovers` löscht jedes eigene Verzeichnis mit Namen `.<name>.<kind>-*` rekursiv, nur nach Namensmuster (z. B. ein umbenanntes echtes Client-Verzeichnis). Abhilfe: Marker `.incomplete`, den `createClientDir` zuerst in tmp schreibt und kurz vor dem Umbenennen entfernt; `removeLeftovers` entfernt nur Verzeichnisse mit Marker, und dann nur die bekannten Namen plus `rmdir` (nicht rekursiv). AUDIT R33.
- F2 (aus 20b geerbt, nur zwei Prozesse desselben Benutzers): `lockOnlyDir` entfernt `lock` unter gehaltener Sperre; ein anderer Prozess mit Deskriptor auf dem alten Inode kann danach eine wirkungslose Sperre bekommen. Abhilfe: nach `lockPath` Inode von fd und Pfad vergleichen, sonst wiederholen; oder als bekannte Grenze dokumentieren.
- F3 (Hinweis): Verlierer zweier gleichzeitiger `keygen` meldet `ENOENT` statt `ErrExists`.
- Angriffstests: Scratchpad `verify20e-attack/internal/client/attack20e_test.go`.
- Nach Merge 20b: RUNBOOK braucht die Abhilfe am Kopf („Datei durch den geprüften Logeintrag ersetzen“) und die Regeln zu `keygen`/`restore` (leeres oder nur-`lock`-Verzeichnis, Temp-Präfixe, Aufräumen) → Auftrag 20.

## Flake aus dem Volllauf 20e
- `cmd/gomail-ceremony` `TestPTYPromptBlocked` (race, ohne Tags): „no exit within 4.5s of share 1, prompt not shown“ (Fall vermutlich `ABA`/`ABC` mit voll/angehaltenem stderr). Code der Zeremonie seit 20b unverändert, dort grün; Wiederholung einmal grün (401,8 s). Protokoll: Scratchpad `orch/fr-20e/flake1/`. → 20: `stuckLimit` unter race prüfen (Zeitgrenze des Tests oder echte Verzögerung des Abbruchpfads unter Last); bei erneutem Auftreten als Fund behandeln.

### Fuzzing, dritter Teil (auf d85da00, nach 20e; `translog/files.go` geändert)
- 5 Ziele in `translog`, je 10 Minuten, zwei Bahnen: alle ohne Fund. `store` ist seit 20b nur im Kommentar geändert; der zweite Teil gilt dort weiter. Protokolle: Scratchpad `orch/fz3/`.

| Paket | Ziel | Ausführungen in 10 min |
|---|---|---|
| `internal/translog` | `FuzzAuditIndex` | 1.656.812 |
| `internal/translog` | `FuzzDecodeEntry` | 6.272.210 |
| `internal/translog` | `FuzzOpenHead` | 6.272.278 |
| `internal/translog` | `FuzzParseHeadText` | 6.436.659 |
| `internal/translog` | `FuzzProofs` | 4.849.422 |

## Aus 20h (Implementierer, für den Merge)
- Commit b14d798 im Worktree agent-a7b23152bafa90687 (Basis df2b0af). Läufe grün (race/386 `client` und `testenv`, gomailctl, e2e); `client` 88,3 %.
- Vor 20h panikten 14 Methoden nach `Close` (CreateMailbox, Folders, Index, List, MailboxName, OpenPending, Read, Rename, Search, SetFlags, SetFolders, SetRecovery, Share, Sync); ClearRecovery, Revoke, ConfirmRecovery lieferten falsche Ergebnisse. Jetzt `client.ErrClosed`; `UserID`/`Mailboxes` ohne Fehlerergebnis liefern weiter die IDs im Speicher.
- D86 Nachtrag 20h: Marker `.incomplete`; Reste nur mit Marker und nur bekannte Namen; Sperrdatei vor und nach dem Sperren per `os.SameFile` verglichen (bis 8 Versuche, dann `ErrLocked`; Abweichung: `store.LockFile` gibt den Deskriptor nicht heraus); `ErrExists` für ein verlorenes Temp-Verzeichnis.
- RUNBOOK: ein Temp-Verzeichnis ohne Marker (Abbruch zwischen Entfernen des Markers und Umbenennen) von Hand löschen.
- Nachfolge möglich: `store`-Sperrfunktion, die den Deskriptor liefert, dann Inode direkt vergleichen.

## Aus der Spezifikationsprüfung von 20h (keine Funde über niedrig)
- `lockClientDir` (`internal/client/client.go`): Kommentar behauptet zu viel; der Vergleich der Pfad-Datei vor und nach `store.LockFile` hat eine theoretische Lücke bei Wiederverwendung der Inode-Nummer (ext4 vergibt sie sofort neu), wenn drei weitere Prozesse desselben Benutzers in ein Fenster von etwa 6 Systemaufrufen fallen. Abhilfe: Kommentar berichtigen und Restfall als bekannte Grenze (AUDIT R33/F2) nennen; später `store`-Variante, die den gesperrten Deskriptor prüft.
- `TestDeviceChangeThenDeviceLost` könnte den Übernahme-Hinweis (`index.go:913`) positiv prüfen (optional).
- Hinweis: `open()` ist Prüfen-dann-Handeln gegen ein gleichzeitiges `Close`; `Client` ist nicht als goroutinesicher dokumentiert (vorbestehend).

## Aus der Angreiferprüfung von 20h (keine Funde über niedrig)
- Marker-Aufräumen hält (Symlinks, harte Links, Marker als Verzeichnis/FIFO): kein Fund.
- Niedrig: `ErrExists`-Abbildung für ein verschwundenes Temp-Verzeichnis gilt für jedes ENOENT; wer nur das Elternverzeichnis beschreiben kann und das Temp-Verzeichnis verschiebt, erzeugt die irreführende Meldung „in use by another client“. Abhilfe optional: nur abbilden, wenn Sperre/Umbenennen ein belegtes Ziel sah.
- Niedrig: `Close` gegen gleichzeitige Methodenaufrufe aus anderen Goroutinen meldet Datenrennen (vorbestehend, auch Methode gegen Methode). → HANDOFF/Paketkommentar: `Client` ist nicht goroutinesicher, `Close` eingeschlossen.
- Angriffstests: Scratchpad `verify20h-attack/internal/client/attack20h_test.go`.
- Zweites Auftreten (Volllauf 20h, race mit Tags, Last 4–5): `TestPTYStopLoop`: „share 1 neither cleared nor the program ended within 4.5s“ (blocked15n_linux_test.go:491). Zwei Fehlschläge der 4,5-s-Grenze in zwei Läufen gelten als echter Fund; Analyse läuft, danach Fix-Auftrag. Protokoll: Scratchpad `orch/fr-20h/racetag-cmd_gomail-ceremony.log`.

## Aus der Prüfung von 20j (für den nächsten Code-Auftrag)
- Code-Kommentar an `maxReadSegments` (`internal/client/index.go:104`) nennt `rec.MaxRecordSize` „4 MiB“; richtig ist 1 MiB (`rec.go:37`). Ein Segment kodiert knapp 1 MiB (`segmentBudget`).
- Vorschlag nach M1: Befehl, der für Postfach und Epoche den Logeintrag findet und dessen `content` ausgibt (RUNBOOK 8.7 hat dafür kein Werkzeug).

## Aus der Angreiferprüfung von 20i (nichts über niedrig im Diff; vorbestehend → 20l)
- F1 (niedrig): Wer das Elternverzeichnis beschreiben kann und das fertige Temp-Verzeichnis auf das Ziel umbenennt, bekommt „in use by another client“ für den eigenen Inhalt; kein Verlust.
- F2 (vorbestehend; mittel, falls ein anderer Benutzer mit Schreibrecht auf ein nicht-sticky Elternverzeichnis im Modell liegt): Tausch des Temp-Verzeichnisses gegen ein anderes vollständiges Client-Verzeichnis → `keygen`/`restore` überschreibt es oder löscht es im Fehlerpfad (`RemoveAll(tmp)`), oder meldet Erfolg mit fremdem Inhalt. Entscheidung des Orchestrators: beheben in 20l (Deskriptor, Identitätsprüfung vor Umbenennen und Entfernen) und in AUDIT nennen, dass das Elternverzeichnis eines Client-Verzeichnisses nicht für andere Benutzer beschreibbar sein soll.
- F3 (niedrig, vorbestehend): ohne `O_NOCTTY` öffnen noch `keys.ReadKeystoreFile` (auch ohne `O_NONBLOCK`, R41) und die Sperrdateien in `store/lock_unix.go` (Rückfall nach `O_EXCL`, `probeLock`) → 20l.
- Angriffstests: Scratchpad `verify20i-attack/internal/client/attack20i_test.go`.

## Aus der Angreiferprüfung von 20l
- Niedrig, im Diff: `openTempDir` folgt einem Symlink am Temp-Namen; ein Link auf ein leeres, eigenes Verzeichnis besteht die Prüfung (chmod 0700 auf das Linkziel, Dateien und Marker landen dort, Lauf scheitert danach mit `errTempReplaced`). Abhilfe: `Lstat(tmp)` vor/nach `OpenRoot`, kein Symlink, `os.SameFile` mit dem Deskriptor. → Nacharbeit 20l.
- Mittel unter Bedingung (anderer Benutzer kann das nicht-sticky Elternverzeichnis beschreiben), vorbestehend, außerhalb 20l: `DeviceLost` (und jedes pfadbasierte Schreiben eines offenen Clients: `user.rec`, Schlüsselspeicher über `keys.WriteKeystoreFile`, `state.json`) schreibt nach dem Sperren über den Pfad; ein Tausch des Client-Verzeichnisses dazwischen überschreibt den Schlüsselspeicher eines anderen Client-Verzeichnisses desselben Kontos. Entscheidung des Orchestrators: Betriebsvoraussetzung „Elternverzeichnis eines Client-Verzeichnisses nur für den eigenen Benutzer beschreibbar“ (RUNBOOK, AUDIT, DECISIONS mit Begründung); Umbau auf ein über `Open` gehaltenes `os.Root` nach M1. Test: Scratchpad `verify20l-attack/internal/client/attack20l_test.go` `TestAttack20lDeviceLostDirSwapped`.

## Analyse der 4,5-s-Fehlschläge der Zeremonie (für 20m, D85)
- Kein Fehler im Programm gefunden: Der Abbruchpfad begrenzt die Zeit, die ein Anteil steht, auf etwa 3,6 s nach Beginn der Ausgabe (Abfrage-Frist 2 s, dann `abortTotal` 1,5 s plus wenige `abortFloor`), solange Programm und Test Rechenzeit bekommen. Beide Fehlschläge verlangen einen Stillstand von mindestens 2 s (Programm oder lesender Testteil). Maschine: Firecracker-VM, 4 vCPU geteilt, Last 2–6, I/O-Druck bis 65 %, Platte 90 % voll, kein Swap.
- Nicht nachgestellt (4 normale und rund 60 verfolgte Läufe, alle grün). Entscheidung des Orchestrators: kein offener Fund im Produktivcode; Tests erkennen künftig Stillstand (Auftrag 20m), Grenze bleibt 4,5 s. D85: ausdrücklich festhalten, dass die Grenzen in der Zeit des Programms gelten (kein Benutzerprogramm kann sie garantieren, während es nicht läuft).
- Protokolle und verfolgte Kopie: Scratchpad `flake-promptblocked/`.

## Aus der Prüfung von 20m (nach Nacharbeit keine Funde über niedrig)
- Erste Prüfung: hoch (CPU-verbrauchender Fehler im Abbruchpfad wurde als Stillstand übersprungen) und mittel (Selbst-Anhalten als Stillstand); Nacharbeit: Run-Queue-Wartezeit zählt nur bei höchstens 500 ms eigener CPU-Zeit, Zustand T nur mit Stopp des Tests; Mutanten spin/selfstop/sleep scheitern wieder.
- Restgrenzen (niedrig): ein Fehler, der auf einem Thread kreist und bei starker Überlast unter 11 % (4,5-s-Fenster) bzw. 25 % (2-s-Fenster) eines Kerns bekommt, gilt als Stillstand; ein Programm, das ein Terminal über 500 ms ununterbrochen flutet, vergrößert die Leselücke (vt-Poller in der inneren Leseschleife); CPU-Zeit beendeter Threads fehlt; unter Last 3–5 sammelt ein hängendes Programm 50–300 ms Run-Queue-Wartezeit. Jeder Skip dieser Tests ist im Abnahmelauf zu prüfen (`-v`, Thread-Dump).

## Aus 20p (für einen späteren Code-Auftrag)
- Kommentar „checks, in this order“ in `cmd/gomail-server/main.go:28` nennt die Serversperre vor den Zertifikatsprüfungen; `ingest.New` nimmt sie danach (RUNBOOK 1.6 stimmt). Triage Nr. 148 ist insoweit falsch.
- `--log-listen` nur loopback (außer `--isolated-test-network`, das auch SMTP öffnet): Zeuge auf anderer Maschine nur per SSH-Tunnel (RUNBOOK 0.1/1.7, nicht getestet; AUDIT R47). Nach M1: eigener Schalter nur für das Log oder TLS.

## Aus der Angreiferprüfung von 21a (für die Nacharbeit 21a und für 21c/21d)
- F1 (mittel): Admin-/Ingest-Generationen, die die gestohlene Identität vor `revoked_at_size` zertifiziert hat, bleiben gültig und können nach dem Widerruf mit rückdatiertem `valid_from` Adressen übernehmen (Test im Scratchpad `verify21a-attack/src/internal/translog/attack21a_test.go` `TestAttackForeignCertsBeforeBoundary`). Entscheidung des Orchestrators: Widerruf einer Identitätsgeneration g bei N wirkt auch auf alle Rollengenerationen, die g zertifiziert hat (deren Handlungen ab N ungültig); das deckt sich mit der Pflicht zur Neuausstellung (D93 (4)). → Nacharbeit 21a, D93-Nachtrag.
- F2 (niedrig): `admin-rotate` ohne `revoke` stoppt einen gestohlenen Admin-Schlüssel nicht (Rückdatierung); doc.go/RUNBOOK: nach Verlust immer `revoke`.
- F3 (niedrig, Q9): weit in der Zukunft liegendes `valid_from` friert eine Adresse ein; Abhilfe frühes `revoked_at_size`; Grenze für `valid_from` beim Anhängen erwägen.
- F4 (niedrig, für 21c): Lücke ohne Ingest-Generation, wenn `valid_from` des Nachfolgers nach `revoked_at_time` liegt → keine frischen Köpfe; Zeremonie muss das verhindern.
- F5 (niedrig): doc.go „Reading for the operator“ zu ErrPrerequisite irreführend (Neuausstellung unter gleichem Namen möglich).

## Aus 20o und seiner Prüfung (für die Doku-Abstimmung nach Auftrag 21)
- Doku: AUDIT R33 und DECISIONS (um Z. 560) nennen noch `writeClientDir`, jetzt `writeClientDirOutside`; RUNBOOK 8.6 braucht die Meldungen von `errIncompleteDir`, `errNotDurable` und die ErrLocked-Form von „not empty or in use by another client“; R33: ein Rest mit fremdem Eintrag bleibt jetzt ganz; Prüfung „nicht im Datenverzeichnis“ jetzt auch über Symlinks (D86-Nachtrag 20o).
- Prüfung (niedrig): `resolveExisting` hält an einem hängenden Symlink an; Meldung dann `mkdir …: file exists` statt `ErrInsideDataDir` (sicher, nichts angelegt). **Erledigt mit 22** (3cd9072: `resolveExisting` folgt hängenden Links, `TestClientDirDanglingLinkIntoDataDir`; D86 Nachtrag 22).

## Aus der Nachprüfung (Angriff) von 21a (keine Funde über niedrig)
- doc.go („Platform generations“, um Z. 835/847) sagt noch `revoked_at_time` = Zeit des bestätigten Kopfes und dass dieser Kopf verschoben wird; Entscheidung ist T + 1 ms → angleichen.
- 21c muss `valid_from` der neu ausgestellten Ingest-Generation = `revoked_at_time` erzwingen und das Zertifikat loggen, bevor der Server den neuen Pin lädt; gilt auch beim nachträglichen Widerruf einer älteren Identitätsgeneration.
- Client: nur `Verifier.RevokedCertAtTime` mit `identity_gen` des Zertifikats nutzen; `IsRevoked`/`RevokedAtTime` kennen die Kaskade ohne `LogKeys` nicht → Kommentarwarnung.
- RUNBOOK: Zuordnungen, die eine kaskadenhaft widerrufene Admin-Generation zwischen N und dem Pinwechsel geloggt hat, neu vornehmen; F2/F3 als Betriebsregeln.

## Aus der Spezifikationsprüfung von 21c
- Mittel (außerhalb der Dateien von 21c): zwei e2e-Tests erwarten den alten „Q19“-Text (`internal/e2e/runbook_test.go:799-801`, `succession_test.go:291-293`) → in 21b angepasst; Merge von 21c nur zusammen mit 21b.
- Niedrig: (1) `ingest-rotate` nach `succeed --compromised` verweigert ein `valid_from` später als die Grenze nicht (erst `publish`); (2) `boundOf` nimmt das eigene Ingest-Element statt des früheren von eigenem und Kaskade (Sackgasse bei Bedienfehler); (3) toter Teil `es[0].Index >= r.AtSize` in `checkRevocations`; Hinweis: Reihenfolge „log repair, dann publish“ in RUNBOOK 7.3.

## Aus der Spezifikationsprüfung von 21b (keine Funde über niedrig)
- L1: Serverstart mit einer Ingest-Generation, die nur über die Kaskade widerrufen ist, scheitert erst bei `checkHead` (Exit 1) statt mit `ingestRevoked` (Exit 2); optional `RevokedCertAtTime` in `ingest.New`.
- L2: Zweig ErrRevoked in `addressErr` ist heute nicht erreichbar (Index lässt ungültige Zuordnungen weg); Kommentar an `checkMeta` überzeichnet.
- L3: Auffrischen nach ErrOrder ungetestet.
- Hinweis: Client-Integrationstest für den Widerruf einer Identität (Kaskade bis zur Mail) fehlt noch; bisher Einheitstest und translog-Tests.

## Aus der Nachprüfung (Angriff) von 21c (keine Funde über niedrig)
- R-low: `publish` heilt `data/platform/` nicht, wenn nach geloggter Neuausstellung ein Dieb die Datei überschreibt (Name mit gültigem Eintrag wird nie ersetzt, auch wenn die Exportdatei genau dieser Eintrag ist); ebenso einzelne fremde `.pub`. Abhilfe: Name gilt als frei, wenn die Exportdatei gleich dem gültigen Eintrag ist; `.pub` ersetzen, wenn das Zertifikat der gültige Eintrag ist. Tests im Scratchpad `verify21c-attack/internal/ceremony/replace21c_attack_test.go`. **Erledigt mit 22** (3cd9072: `freeName`, `TestPublishHealsPlatform`, `TestPublishHealsOverwrittenCert`, `TestPublishHealsForeignPub`; einzelne fremde `.pub` ohne geloggtes Zertifikat bleibt Handarbeit, RUNBOOK 7.3; D93 Nachtrag 22).
- Nachprüfung (Spezifikation) von 21c, niedrig: die Prüfung „wäre nie gültig gewesen“ (`revoked_at_time ≤ valid_from`) in `checkRevocations` greift auch für Admin-Elemente, für die `revoked_at_time` keine Bedeutung hat; kann eine gewollte F3-Reparatur mit älterem Kopf verweigern (fail closed). Abhilfe: nur für Ingest, für Admin nur die Untergrenze 2025. **Erledigt mit 22** (3cd9072: `checkRevocations`, `TestRevocationTimes`; D93 Nachtrag 22).

### Fuzzing, vierter Teil (auf 56464da, nach 21a; `translog` und `store` geändert, 21b/21c ändern sie nicht)
- 6 Ziele je 10 Minuten, zwei Bahnen: alle ohne Fund. Protokolle: Scratchpad `orch/fz4/`.

| Paket | Ziel | Ausführungen in 10 min |
|---|---|---|
| `internal/store` | `FuzzDecodeRecords` | 9.146.068 |
| `internal/translog` | `FuzzAuditIndex` | 3.137.084 |
| `internal/translog` | `FuzzDecodeEntry` | 6.929.298 |
| `internal/translog` | `FuzzOpenHead` | 6.936.251 |
| `internal/translog` | `FuzzParseHeadText` | 7.142.506 |
| `internal/translog` | `FuzzProofs` | 4.665.887 |

## Aus der Nachprüfung (Angriff) von 21b (keine Funde über niedrig)
- F1 und F2 geschlossen; Restlücke F2 braucht eine Formatänderung: Version ≥ 2 muss Schlüssel oder Zertifikats-Hash des Signierers von Version 1 festhalten (nicht nur die Generationsnummer), sonst ist ein vor dem Pinwechsel geloggtes `ingest-2.cert` des Diebs nicht von der ehrlichen Neuausstellung gleichen Namens zu unterscheiden. → Liste nach M1.
- RUNBOOK: alte Plattformzertifikate in `platform/` nie entfernen (sonst scheitern auch Flags auf Mails späterer Generationen); Server am abgelesenen Kopf anhalten.

## Aus der Angreiferprüfung von 22 (keine Funde über niedrig im Diff; ein Fund mittel außerhalb des Diffs → Auftrag 23)
- N1 (niedrig): Ein Symlink unter einem geloggten Namen, dessen Ziel außerhalb von `data/platform/` den geloggten Inhalt hat, überlebt `publish` (`publish.go` Gleichheitsprüfung folgt dem Link, `checkDataPlatform` überspringt Nicht-Reguläre). Der Dieb kann später den Inhalt ändern; Clients bleiben fail closed (dauerhafter DoS). Schon vor 22 so. Abhilfe nach M1: Symlinks unter `data/platform/` in `publish` ablehnen oder ersetzen.
- N2 (niedrig): Ein hängender Symlink unter einem geloggten Namen blockiert die Heilung mit irreführender Meldung `ErrExists … (written meanwhile)`; fail closed, Betreiber entfernt von Hand.
- N3 (niedrig, Doku): Müll oder ein Zertifikat mit falscher Signatur unter einem geloggten Namen heilt `publish` nicht (`checkDataPlatform` lehnt vorher ab); Kommentar `cmd/gomail-ceremony/main.go:193-196` zu weit. RUNBOOK: solche Dateien von Hand entfernen.
- N4 (niedrig): `resolveExisting` bereinigt das Linkziel lexikalisch (`filepath.Join`/`Clean`); `L -> sub/../data/client` mit `sub` als Symlink entgeht der Prüfung. Angelegt wird trotzdem nichts (`createClientDir` scheitert an EvalSymlinks/`MkdirAll`); unvollständige Härtung, keine Verschlechterung. Kommentar „the prefix as it is“ nach 40 Sprüngen ungenau.
- Außerhalb des Diffs (mittel, Einstufung des Orchestrators): `Client.ingestKeyFor` liest `ingest-<g>.cert` zweimal (Schlüssel und Signatur aus dem ersten Lesen, `CheckPlatform` aus dem zweiten); ein Tausch dazwischen umgeht den Logabgleich. Gleiches Muster in `ingest.New` (niedrig). → Auftrag 23.

## Aus der Spezifikationsprüfung von 22 (keine Funde über niedrig; 21 Mutationen, 19 getötet)
- N1 (niedrig): wie N4 der Angreiferprüfung: `resolveExisting` bereinigt `..` im Linkziel lexikalisch; folgt ein `..` einem Symlink, wird der falsche Pfad geprüft. Angelegt wird nichts. Abhilfe nach M1: Linkziel stückweise auflösen.
- N2 (niedrig, Doku): Kommentare `cmd/gomail-ceremony/main.go:193-196`, `internal/ceremony/publish.go:745` versprechen Heilung auch für Dateien, die `checkDataPlatform` vorher ablehnt (Müll, Zertifikat unter falschem Namen).
- N3 (niedrig, Testlücke): Mutanten P1-4 (`.pub`-Rückfall ohne `bytes.Equal`, `publish.go:784`) und P1-6 (`os.WriteFile` statt `WriteFileAtomic`, `publish.go:668`) überleben die Tests des Repositorys; Belegtests des Prüfers `TestV22PubUnderUnloggedSameCert`, `TestV22SymlinkOverLogged` (Scratchpad `verify22-spec/`) nach M1 übernehmen.
- N4 (Doku, Vorschlag): RUNBOOK Z. 493 (gültiger Eintrag „ersetzt es nie“ → außer durch genau diesen Eintrag aus dem Export), Z. 492 (Prüfung „nie gültig“ nur Ingest); D86-Nachtrag 20o („hält an einem hängenden Symlink an“ gilt nicht mehr); D93-Nachtrag zur Heilung durch `publish`.

## Aus den Prüfungen von 22d (Doku zu 22 und 23)
- Erste Prüfung: 1 mittel (RUNBOOK 8.6: Abhilfe bei `… a valid entry is never replaced` nannte nicht den Fall eines vor `<N>` geloggten Zertifikats des Diebs) und 5 niedrig → Nacharbeit 5d88c4b; Nachprüfung: alle behoben.
- L1 (niedrig, nach M1): „ein Link mit anderem Zielinhalt wird ersetzt“ gilt nur, wenn `freeName` den Namen freigibt und das Ziel eine lesbare reguläre Datei ist; ein Link als `identity-<g>.pub` oder auf FIFO/Verzeichnis wird verweigert (`store: file exists: … with other content than … of the export`, ohne Zeile in RUNBOOK 8.6).
- L2 (niedrig): Liegt ein vor `<N>` geloggtes Zertifikat des Diebs nicht in `platform/`, schreibt `publish` die Neuausstellung gleichen Namens nach `platform/` und scheitert erst beim Loggen (`ceremony: logging <name>: translog: duplicate log entry: key taken by entry <k>`).
- Hinweis: DECISIONS D93 Nachtrag 21e „Dateien des Diebs ersetzt `publish`“ gilt nur für Zertifikate ab `<N>`.

## Läufe der Prüfungen von 23 (vom Orchestrator nach den Messungen ausgeführt, Protokolle im Scratchpad `orch/v23/`)
- Angriffstests des Prüfers (`TestAttack23ClientFlipRace`, `TestAttack23ClientCacheNotPoisoned`, `TestAttack23ClientAfterRevocation`, `TestAttack23IngestFlipRace`): auf 9a9d6cb grün; auf der Mutante mit wiederhergestelltem zweitem Lesen scheitern `ClientFlipRace`, `ClientAfterRevocation` und `IngestFlipRace`.
- Mutationen der Spezifikationsprüfung (M1–M9): getötet außer M4 (naive Doppel-Lese-Fassung in `store`; Testlücke niedrig, bekannt). Die Ergebnisse für `TestPlatformIngestCertSwapped` sind nicht aussagekräftig, solange der Test nicht deterministisch ist (scheitert auch ohne Mutation mit breitem `-run`, siehe 23b).
- `TestPlatformIngestCertSwapped/forged_then_logged` (Fall `list`) scheitert unter 386 und unter amd64 ohne race mit breitem `-run`; Sicherheitseigenschaft hält (Mail des Angreifers nie angezeigt). → Nacharbeit 23b.
- Nachprüfung 23b (c6fa0b3): ohne Funde über niedrig. Ursache bestätigt (zufällige IDs, `listIDs` sortiert nach Bytes, Cache nur bei Erfolg). Mutationen zweites Lesen, Cache auch bei Fehler, Ablehnung merken: je 5/5 getötet unter amd64 und 386. Niedrig: Jeder Lauf deckt zufällig nur eine Prüfreihenfolge ab; Vorschlag nach M1: zweiten Aufruf von `IngestKeyFor(1)` im Schlüssel-Zweig.

## Aus den Prüfungen von 17 (17b, 17c, 17d)
- Prüfung 17b: alle Zahlen gegen Rohdaten bestätigt; 3 mittel (Commits unerreichbar, Schluss D93 für Empfang, `bench.sh` nicht fail closed), 7 niedrig → 17c.
- Nachprüfung 17c: alle behoben; neu F1 mittel (`-render=` leer startet Messung; dabei versehentliche Messung des Prüfers 02:15–02:17 UTC neben dem Volllauf), F2/F3 niedrig → 17d.
- Nachprüfung 17d: F1 behoben für leere Werte; neu M1 mittel (Wert, der mit `-` beginnt, wird angenommen: `-o -render=F` misst) → als niedrig eingestuft, D94; N1 (fehlende `command:`/`env:`-Zeilen nicht abgeglichen), N2 (weitere Umgebungsvariablen nicht abgeglichen) niedrig; F3 aus 17c (fehlender Unter-Benchmark, eingerücktes `--- SKIP`) niedrig. Alles nach M1.

## Aus den Prüfungen von 20r
- Erste Prüfung: alle Zahlen bestätigt; 3 mittel (Urteil A „bedingt“ nicht belegt; R48 nannte `TestReadPlatformCertRaw` als Test mit Haken; Urteilsspalte ohne Vorbehalt `fr-m1`), 2 niedrig → Nacharbeit 94190c6.
- Nachprüfung: alle behoben; niedrig: N1 `clientdir22_test.go` gehört zu A statt C; N2 „je 5/5“ gilt nur für den Client-Test, für `ingest` gelten die Mutationen der Spezifikationsprüfung und `IngestFlipRace`; N3 Q2 (Einladungen unverändert aus Phase 1, D53) fehlt in der Begründung zu A; N4 Begründung zu A: „strengste Lesart“ ist für Q1 und Q7 als „nicht gebaut bzw. nicht freigegeben“ zu lesen, und die Regel in HANDOFF „als erfüllt gilt nur, was gebaut ist“ gilt für offene Haltepunkte nach ORCHESTRATION Abschnitt 3. Hinweis: B „nur für `testenv`“ ungenau, `translogtest` importieren weitere Testdateien.

## Aus der Prüfung von 17e
- Ohne Funde über niedrig: 43 Aufrufe über eine echo-Kopie, keiner misst mit `-render`; vier Rohdateien rendern mit rc=0; Messlogik unverändert; `nachtrag-17c.diff` byte-gleich. Niedrig: A, der Render-Befehl scheitert bei gesetztem `TMPDIR` (behoben in MEASUREMENTS mit `env -u TMPDIR`); B, Werte, die in den Rohdaten in Anführungszeichen stehen, stimmen nie überein (fail closed; Kommentar „empty or unset“ ungenau). Nach M1.
- Prüfung von 20s (niedrige Punkte aus 20r, D94 erledigt): ohne Funde über niedrig; zwei niedrige (Q2 als Ausnahme zur Regel für offene Haltepunkte, Satz „spätere Commits ändern nur Dokumente“ seit 17e ungenau) mit den Ersatztexten des Prüfers vom Orchestrator eingesetzt.

## Aus der Prüfung von 22e (RUNBOOK L1/L2, D93-Hinweis)
- Ohne Funde über niedrig; alle Meldungen wörtlich am Code bestätigt, die Abhilfe zu L2 widerspricht keinem Verbot. Niedrig, nach M1 (Ersatztexte im Prüfbericht; Kurzfassung):
  - N1: AUDIT R17 (b) und D93 Nachtrag 22 sagen weiter pauschal „ein Link mit anderem Zielinhalt wird ersetzt“; richtig nur, wenn das Ziel eine lesbare reguläre Datei ist und `freeName` den Namen freigibt.
  - N2: Liegt nur die `.pub` des Diebs in `platform/`, lautet die Meldung `store: file exists: …/<role>-<g>.pub with other content than … of the export, and <role>-<g>.cert is a valid entry …: a valid entry is never replaced` (ohne `translog: duplicate log entry:`); ohne eigene Zeile in 8.6.
  - N3: `is not a regular file` kommt auch bei `witnesses.rec` und einer im Export fehlenden Nachfolge; ein Link unter einem Namen, den `publish` nicht liest, fällt nicht auf.
  - N4: RUNBOOK 7.3.5 Schritt 2 nennt nicht, dass ein nur im Log stehendes Zertifikat des Diebs sich erst in Schritt 5 zeigt (dann Rotation mit der Generation darüber wiederholen).
- Prüfung von 22f (Ersatztexte N1–N4 aus 22e): ohne Funde über niedrig. Niedrig: F1 (7.3.5 Schritt 2 übersieht den Fall, dass nur die `.pub` des Diebs in `platform/` liegt), F2 („Nachfolge, die im Export fehlt“ zu weit: gemeint ist eine, die weder im Export noch gültig im Log steht und für die Kette gebraucht wird), F3 (Satz zu Links in AUDIT R17/D93 logisch unsauber; Links unter anderen Namen bemerkt `publish` nicht) → 22g.
- Prüfung von 22g (Ersatztexte F1–F3 aus 22f): ohne Funde über niedrig; ein niedriger (AUDIT R17/D93: „Links unter anderen Namen bemerkt es nicht“ zu weit, `witnesses.rec` und benötigte Nachfolgen liest `publish` auch) mit dem Ersatztext des Prüfers vom Orchestrator eingesetzt.

## Auftrag 24 (Nacht 09./10.11.): Prüfungen
- **C** (9414fcd): Spezifikations- und Angreiferprüfung ohne Funde über niedrig. Niedrig: Doku-Nachzug (RUNBOOK 4.2/8.6, D80 Nachtrag 20j, D93 Nachtrag 23, AUDIT R48); `sc.Verify` in `identityKey` ohne eigenen Test (gleichwertig nach dem `Lookup`-Vertrag). Der Wettlauf-Test der Angreiferprüfung ist übernommen.
- **E** (e597ccf): ohne Funde über niedrig. Niedrig: N1, `-render` druckt Werte, die Quoting brauchen, unquotiert (`envof`, `awk -v` wertet Escapes aus); N2, ganz fehlende Kinder einer Gruppe erkennt `grid()` nicht (Soll-Liste fehlt); N3, der Haken zählt nur Lesezugriffe über `ReadPlatformFile` (Mutante M4direct überlebt); N4, ungenaue Kommentare (`bench.sh` SKIP-Einrückung, `ErrNoLog`/`Unverified` „melden kein Log“, `doc.go` Task 14/15). `GOOS=solaris`/`illumos go vet` scheitern an `syscall.Mkfifo` in sechs Testdateien, Build ok.
- **A** (cdd01fd): Spezifikations- und Robustheitsprüfung ohne Funde über niedrig, kein Rückschritt (Matrix 126 Fälle: neu 2 Verletzungen, beide F4 und schon vorhanden; alt 29). Niedrig: FIFO-Regel ohne Test (R4 überlebt); Hinweis in `linkErr`; „written meanwhile“ folgt Links (F1); harter Link übersteht `publish` (F2); `Lstat`/Lesen ohne `O_NOFOLLOW` (F3); gleiche reguläre Datei bei anders belegtem Logeintrag erst beim Loggen abgelehnt (F4); `witnesses.rec` folgt Links. → Nacharbeit A2 (FIFO-Test, Meldung, F1, F2, F4 falls klein).
- **B** (caac1df): Spezifikationsprüfung ohne Funde über niedrig (Kernel-Vergleich 23 000 Pfade ohne Abweichung; N1 Ketten 41–255; N2 Testlücke `.` und `/`; N3 Kommentar EACCES). Die erste Angreiferprüfung brach ohne Ergebnis ab. Die Robustheitsprüfung fand einen Fund **mittel**: Rückschritt bei Pfaden tiefer als PATH_MAX (ENAMETOOLONG lässt die Komponente als Namen stehen; `keygen` legt im Datenverzeichnis an; die alte Fassung lehnte ab). Niedrig: relativer Pfad wird als absoluter gelesen. → Nacharbeit B2 (fail closed bei Fehlern außer ENOENT/ENOTDIR und an der Sprunggrenze, Schutz gegen relative Pfade, Tests).
- **D** (8c924de): Fund **hoch**: 16 Clients ohne Körper sperren `/cosign` unbegrenzt (Platz der Semaphore vor dem Lesen). Fund **mittel**, schon vorher vorhanden: ein wiederholt gesendeter, veröffentlichter Kopf schreibt `heads/<size>.sig` jedes Mal neu. Niedrig: 404/405 ohne `Connection: close`. → Nacharbeit D2 (Platz nach dem Lesen mit kurzem Warten, `PublishHead` nur bei neuer Zeile, `Connection: close`). Die Vorgabe „503 ohne Lesen des Körpers“ aus dem Auftrag ist damit aufgehoben.
- **24g** (39acb5a, Nacharbeit 967a41d): Nachprüfung ohne Funde über niedrig; M1–M3 und N1–N5 behoben. Niedrig, für den Doku-Nachzug zu 25: (1) RUNBOOK 8.6 `adminKeyMismatch`: Ursachenliste um „oder lässt sich aus einem anderen Grund nicht öffnen oder lesen (der Fehler des Systems, etwa `open …: permission denied`)“ ergänzen; (2) RUNBOOK 7.3 Fall 3 und 8.6: „deren Zertifikat nicht geloggt ist“ → „deren Zertifikat keinen gültigen Logeintrag hat und im Datenverzeichnis fehlt oder gleich dem des Exports ist“.

## Auftrag 25 (Nacht 09./10.11.): Prüfungen

- **25B** (704ff09): erste Prüfung (Vergleich alt/neu, 12 000 Zufallsfälle und feste Fälle, auch ohne Capabilities und unter 386) ohne Abweichung, ohne Funde über niedrig. Niedrig: `TestClientDirBelowFile` prüft bei `Register`/`DeviceLost` nur `err != nil`, der Kommentar verspricht „no registered user“. Zweite Prüfung (Spezifikation, Mutanten) läuft.
- **25C** (aaf2bd8): Prüfung ohne Funde über niedrig; Flood bestätigt `SlotWait` 5 s (7/7 statt 4/15 Runden, gleiche Zahl Goroutinen). Niedrig N1, schon vorher: `Tick` signiert vor dem Wiederholen von `publish`, ein Kopf mit Quorum kann bei gescheitertem `PublishHead` und Kandidatenwechsel unveröffentlicht bleiben (Verzögerung bis zum nächsten Quorum). Hinweise: N2 `merge` hängt vor `Sign` an; N3 Kostenkommentar unvollständig (`LogKeys` je Körper, `Head` bei älteren Noten); N4 `ReadTimeout + SlotWait` addieren sich, Faktor 4 im Test unbegründet. → Nacharbeit 25C2 (N1, N3, N4, N2 falls klein).
- **25D** (8270349): N1 und N2 erfüllt (83 Quoting-Fälle unter bash und dash, 3050 `shq`-Werte, 77 Fälle zur Soll-Liste, vier Tabellen gleich); die Gruppenregel bleibt. Fund **mittel B1**, schon in 7dfd935: Mit gawk 5.2.1 scheitert jedes `render`, weil `/[][.*+?(){}|^$\\]/` als Collating-Symbol gelesen wird; nach einer echten Messung gingen Tabelle und `-raw` verloren (Rohdaten nur auf stderr). Hinweise: B2 `rm -rf` ohne `--` bei `TMPDIR=-x`; B3 `|`, Backtick, Zeilenumbruch zerbrechen die Tabelle; B4 Soll-Liste von Hand gepflegt; B5 Meldung ohne Zahl. → Nacharbeit 25D2.
- **25B** zweite Prüfung (Spezifikation, 19 Mutanten, Meldungen über `gomailctl`): ohne Funde über niedrig. Meldungen: `client: cannot check that the client directory is outside the data directory: <errno-Text>` bzw. `client: the client directory must not be inside the data directory`. Niedrig F1: M12 (`createClientDir` ohne Ursache) überlebt als root; F2 bestätigt (Befund der ersten Prüfung). Hinweise: H1 `filepath.Abs`-Zweige ungetestet (M15/M16, über `gomailctl` nicht erreichbar); H2 zwei veraltete Kommentare in `clientdir24b_internal_test.go`; H3 `TestClientDirLeftovers` scheitert ohne Rechte statt zu überspringen. → Nacharbeit 25B2 (nur Testcode).
- **25A** (f6420a6) Robustheitsprüfung: ohne Funde über niedrig, kein Rückschritt (Matrix 426 Fälle: neu 0 Verletzungen, alt 26; 15 neue Ablehnungen, alle gewollt; Absturz an 14 Hakenstellen heilt). Niedrig: L1 `platform/` als Symlink → `RemoveTemp` löscht `.tmp-*` außerhalb (Schreiben dorthin schon vorher); L2 `.tmp-*` werden ohne Meldung entfernt, auch wenn `publish` danach ablehnt (RUNBOOK 7.3 „nicht ungesehen löschen“). Hinweise: H1 Fehler von `RemoveTemp` ohne Zusammenhang; H2 `os.Remove` entfernt ein im Wettlauf eingesetztes leeres Verzeichnis (`syscall.Unlink`); H3 Restfenster nach dem zweiten `Lstat` (wie alt); H4 ersetzter Link unter `witnesses.rec` ohne Ausgabe; H5 `succChain.need` liest mit `readData` (schon vorher); H6 RUNBOOK 7.3 veraltet (Doku-Nachzug).
- **25C2** (4f4535f) Nachprüfung: ohne Funde, nur Hinweise. N1–N4 erledigt; Reihenfolge in `Tick` ohne neue Fehler (kein Doppelschreiben, kein Veröffentlichen unter dem Quorum), `merge` nur unter `s.mu`, Kommentare gegen net/http go1.26.10 bestätigt. H1: `translog.operatorLog.PublishHead` ruft `refuse(tree)` nicht auf; ein Kopf kann im selben Tick veröffentlicht werden, in dem `SignHead` danach mit `ErrConsistency` ablehnt (auch über den Merge-Pfad, schon vorher; der Kopf passt zum Baum) → Liste nach M1. H2: Paketkommentar „the witnesses then cosign the next candidate“ → „…, once SignHead yields one“ (nächste Code-Änderung in `loghttp`).
- **25A** Spezifikationsprüfung: ohne Funde über niedrig, alle vier Punkte erfüllt, keine Rückschritte; Begründung zu N1 hält (nur `publish` unter der Sperre und `init` schreiben `platform/`; der Server entfernt `.tmp-*` beim Start ebenso). Niedrig: Testlücken (R3, R4, R7, R12 überleben die Tests des Repositorys); Link-Ersatz an `witnesses.rec` mit `--replace-witnesses` ohne Meldung (RUNBOOK 7.2 verspricht altes und neues Quorum); `succChain.need`/`checkDataPlatform` lesen über Links (schon vorher). Hinweise: Fehler von `RemoveTemp` ohne Zusammenhang, `platform/` als Symlink, Meldungen beim zweiten `Lstat` und Abhilfe bei `.succ`, RUNBOOK 7.3 veraltet. → Nacharbeit 25A2 mit den Punkten beider Prüfungen.
- **25B2** (23fc312) Nachprüfung: ohne Funde, zwei Hinweise (`TestInsideDataDirLongRealPath` prüft für `insideDataDir` nur `errors.Is`, abgedeckt durch `TestInsideDataDirCause`; `TestClientDirLeftovers` überspringt sich ohne Rechte ganz statt nur den Teil mit fremdem Besitzer). Paket 25B ist mit 23fc312 fertig.
- **25D2** (3beee11) Nachprüfung: B1 behoben (14 962 Eingaben unter mawk, gawk, gawk `--posix`, onetrue awk, busybox, C und C.UTF-8 gleich), ohne Funde über niedrig; vier Tabellen gleich (32/32). Niedrig: N1 scheiterndes `go test` oder Abbruch löscht `$work` (Rohdaten nur auf stderr, schon vorher); N2 nicht schreibbares `-raw` fällt erst nach der Messung auf; N4 `tablebad` prüft die übrigen env-Variablen und `-benchtime` nicht; busybox vergleicht nach `median()` als Zeichenkette (Rundung); relatives `TMPDIR` nach dem `cd`. Hinweise: N3 `-raw` = `-o` überschreibt still; N5 CDPATH; Zeilennummern bei `-render`. Mergefähig; Nacharbeit 25D3 für diese Punkte läuft (nur `bench.sh`, berührt keinen Go-Test).
- **25A2** (4b37e6d) Robustheitsnachprüfung: ohne Funde über niedrig, kein Rückschritt (Matrix 426 gleich f6420a6; neue Fälle `platform/` als Link, Nachloggen über 16 Arten von Links: neu überall verweigert; Absturz an 24 Stellen heilt; andere Aufrufer von `store.RemoveTemp` sind nur `witness.load`, dort unverändert). Niedrig N1: Ein Tausch von `platform/` gegen einen Link während des Laufs wird nicht erkannt (Fenster wie H3, nur mit fremdem Schreiber auf `data/`); Abhilfe über `os.Root`/`O_NOFOLLOW|O_DIRECTORY` und `unlinkat` → Liste nach M1. Niedrig N2: ersetzter Link an `witnesses.rec` bleibt ungemeldet, wenn `publish` danach scheitert. Hinweise: harter Link wird vor der `Nlink`-Prüfung geöffnet („nicht gelesen“ stimmt nur für Symlinks); Bind-Mount nicht erkennbar; `cp -al`-Datenverzeichnis verweigert auch das Nachloggen.
- **25A2** Spezifikationsnachprüfung: ohne Funde über niedrig, alle sieben Punkte erfüllt, keine Rückschritte (Matrix 426/0/0, Quorumszeile bytegleich, neue Ablehnungen Exit 1). Unlink wirkt nur in `witness.load` und `publish`; Server-Start und Ingest nutzen `Store.RemoveTempFiles` (weiter `os.Remove`). Niedrig: Testlücken S12 (`WitnessesLinkReplaced` beim ersten Schreiben) und S14 (harter Link in `checkDataPlatform`); weitere überlebende Mutanten S1, S2, S4, S16. Hinweise: H1 `Store.RemoveTempFiles` ebenfalls auf `removeName` umstellen → Liste nach M1; H2 Windows; H3–H6 Meldungstexte; H7 Restfenster `platform/`-Tausch (wie N1 der Robustheitsprüfung); H8 `cp -al`; H9 Doku. → Nacharbeit 25A3 (nur `ceremony` und `cmd/gomail-ceremony`: Tests, sofortige Meldung des Ersatzes von `witnesses.rec`, Meldungstexte).
- **25D3** (79bd462) Nachprüfung: ohne Funde über niedrig; vier Tabellen unter fünf awk-Varianten gleich (40/40), Trap behält Rohdaten bei jedem Abbruch, `tablebad` gleich `envNames`, `TestBenchScriptLimits` grün. Niedrig, für die Liste nach M1: N-1 Probe `: >>` auf ein FIFO mit Leser (`-raw` als benannte Pipe) beendet den Leser, der Lauf hängt am Ende; N-2 `samefile` ohne GNU `realpath -m` oder über Bind-Mount übersieht gleiche neue Dateien (`-o` überschreibt dann `-raw`). Hinweise: hängender Symlink als `-raw` hinterlässt leere Datei; falsche Treffer bei `/dev/null`; `-benchtime`-Regex nimmt `0x`/`0s` an und lehnt `1μs` ab; `-o` nicht vorab geprüft; TERM nur an bash lässt `go test` weiterlaufen; INT nur an bash wirkungslos; kein Test `tablebad` gegen `envNames`. Paket 25D ist mit 79bd462 fertig.
- **25A3** (9fd2156) Robustheitsnachprüfung: ohne Funde über niedrig, kein Rückschritt (Matrix 426/0/0; Absturz mit SIGKILL an jedem Haken über die CLI: Ersatzzeile genau einmal, vor dem Ersatz keine; auf 4b37e6d fehlte sie nach dem Ersatz). Fehlendes `platform/` ist über die CLI nicht erreichbar (`store.Open` lehnt vorher ab), war nie heilbar. Linkziel mit `%q` gequotet. Niedrig, schon vorher: scheitert nach dem `rename` von `witnesses.rec` der fsync von `platform/`, fehlt die Ersatzzeile dauerhaft (EIO beim fsync nötig) → Liste nach M1. Hinweise: Lücke rename–Callback bei SIGKILL (RUNBOOK: nach Abbruch ohne Zeile `witnesses.rec` selbst prüfen); Linkziel ungekürzt; Restfenster `checkPlatformDir`–`RemoveTempReport` (wie zuvor, `os.Root`).
- **25A3** Spezifikationsnachprüfung: ohne Funde über niedrig, alle Ziele erfüllt, kein Rückschritt (Callbacks erst nach gelungenem `WriteFileAtomic`, keine Doppelausgabe, `%q` maskiert). Niedrig, nur Tests: N1 Reihenfolge der Callbacks nur durch den chattr-Test belegt (R1 überlebt, R2 ohne Root); N2 stdout bei Erfolg nur mit `Contains` geprüft (R3, R4 überleben); N3 der chattr-Test hinterlässt bei Abbruch ein unveränderliches Verzeichnis. Hinweise: `%q` ungetestet (R5); `Readlink`-Fehlerzweig ungetestet; `platform/` als Datei erst bei `RemoveTempReport` gemeldet. → Nacharbeit 25A4, nur Testcode.
- **25A4** (49c98e6, nur Tests) Nachprüfung: ohne Funde über niedrig; R1–R5 getötet, auch ohne Capabilities; `blockLogAppend` macht den Test bei jeder Abweichung laut rot, nie fälschlich grün; Ausgabevergleiche ohne Zufall (`-race -count=5`, `-shuffle=on`). Niedrig B1: `blockLogAppend` schreibt das Namensformat der Einträge selbst aus (besser `translog.EntryPath` und die Größe aus dem Log). Hinweise: Bindung an den Text „leftover entry“, Diagnose bei falschem Inhalt, R6 weiter ungetestet. Paket 25A ist mit 49c98e6 fertig.
- **Stand beim Anhalten 10.11., 09:00 MEZ:** Auftrag 25 ist vollständig geprüft (Endstände 25A 49c98e6, 25B 23fc312, 25C 4f4535f, 25D 79bd462, 25g 0c4d1a9), aber nicht zusammengeführt. Grund: Der Volllauf `fr-n25` steht bei 25 von 67 Schritten (keiner rot), weil der Container von 03:28 bis 08:00 UTC stand. Die nächsten Schritte stehen in ORCHESTRATION, Abschnitt 9.
