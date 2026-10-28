# Gesammelte Hinweise aus den Prüfungen der Wellen 2–5 (Arbeitsnotizen des Orchestrators, Eingang für Auftrag 20)

Rohfassung, gesichert nach einem Neustart des Containers. Viele Punkte sind inzwischen erledigt; Auftrag 20 ordnet sie ein.

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
