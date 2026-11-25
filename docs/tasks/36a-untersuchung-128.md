# Untersuchung Nr. 128 (Paket 36A, 25.11.2026)

Auszug aus den Notizen des Implementierers von 36A (`scratchpad/impl36a/notes.md`, Punkt 4), unverändert übernommen, damit die Tabelle einen Neustart des Containers übersteht. Geprüft in Stichproben von Prüfer 1 von 36A (20-notes „36A“).

## Punkt 4: Nr. 128 (nur Untersuchung, kein Code)
Funktionen: `WriteFileAtomic` (W, rename, ersetzt), `WritePrivateFileAtomic` (WP, wie W mit 0600), `CreateFileAtomic` (C, link, nie ersetzt),
`CreatePrivateFileAtomic` (CP), `WritePrivateFileAtomicIn` (WPIn, rename über os.Root). Aufrufer per grep über das Modul ohne `_test.go`
(Skript `callers.py`). Sperren nach D70: Postfachsperre `mailboxes/<id>/lock` (LockMailbox/LockMailboxes, Client: `mutate`/`withMailboxLock`),
Logsperre `log/lock` (LockPath), `addresses.lock`, Benutzersperre `users/<id>/lock`, Client-Verzeichnissperre `<client>/lock` (lockClientDir, eine
Client-Instanz je Verzeichnis), Rollensperren `locks/server`/`locks/client`.
"Nebenläufig" = zwei rechtmäßige Schreiber (Server, Ingest, mehrere Clients/Geräte, Zeremonie) schreiben **dieselbe Datei** gleichzeitig.

| # | Aufrufer (Datei:Zeile, Funktion) | Fn | Datei | rechtmäßig nebenläufig? | Sperre | Wirkung einer Prüfung nach rename/link |
|---|---|---|---|---|---|---|
| 1 | store/store.go:343 AddAddress | W | addresses.rec | nein | `addresses.lock` (in der Funktion) | nur zusätzliche Ablehnungen bei Fremdeingriff |
| 2 | store/store.go:470 WriteMailbox ← client finishMailbox (mailbox.go:732/758), commitHead (members.go:291), testenv | W | mailbox.rec | nein | Postfachsperre (finishMailbox laut Kommentar unter ihr; commitHead aus mutate) | nur Fremdeingriff |
| 3 | store/store.go:542/545 writeEpochKeys ← WriteEpoch, EnsureEpoch, ReplaceEpoch, ReplaceInvalidEpoch | W | content.pub, meta.pub einer Epoche | **ja, möglich**: WriteEpoch selbst nimmt keine Sperre; EnsureEpoch (client mailbox.go:719, finishMailbox) und createEpoch laufen unter der Postfachsperre, ReplaceEpoch/ReplaceInvalidEpoch nehmen sie; Inhalt ist aus der Epoche abgeleitet (gleich) | Postfachsperre bei allen gefundenen Aufrufern; testenv ohne | bei gleichem Inhalt zweier Schreiber würde ein check „another file“ melden → **neue Ablehnung**, falls je ein Aufrufer ohne Sperre dazukommt; heute keiner gefunden |
| 4 | store/store.go:585 ReplaceEpoch | W | epoch.rec | nein | Postfachsperre (in der Funktion; Client gibt die eigene dafür frei, withoutLock) | nur Fremdeingriff |
| 5 | store/store.go:680 ReplaceInvalidEpoch ← client createEpoch | W | epoch.rec | nein | Postfachsperre (Kommentar; createEpoch: „caller holds the lock“) | nur Fremdeingriff |
| 6 | store/store.go:720 WriteWrap ← client sealOwn (devicelost.go:1233), sealAgain (1598), testenv | W | members/<user>.wrap | nein: sealAgain und rewrapOwn aus reissue → mutate; healOwnWrap/sealOwn("sync-rewrap") aus syncMailbox → mutate (verfolgt) | Postfachsperre | nur Fremdeingriff |
| 7 | store/store.go:838 WriteNote ← ingest noteFallback | W | epoch-fallback.rec | nein | Postfachsperre (Kommentar „The caller holds the mailbox lock“) | nur Fremdeingriff |
| 8 | store/store.go:869 WriteFolders ← client rewriteFolders (folders.go:129, aus mutate), resignFolders (accept.go:583, nimmt die Sperre), testenv | W | folders.gml | nein | Postfachsperre | nur Fremdeingriff |
| 9 | store/user.go:222 ReplaceUser | W | users/<id>/user.rec | nein | Benutzersperre (in der Funktion) | nur Fremdeingriff |
| 10 | store/accept.go:130 WriteAccept ← client writeAccept ← acceptWrap (keysFor, mailbox.go:1520; devicelost.go:1202/746/1239) | W | members/<user>.accept | **ja**: Annahme des eigenen Benutzers; zwei Geräte desselben Benutzers (getrennte Client-Verzeichnisse) können gleichzeitig annehmen; keysFor hält nur `c.mu` (prozessintern) | keine gemeinsame Sperre gefunden | **neue Ablehnung** bei rechtmäßiger Nebenläufigkeit (heute: letzter gewinnt, beide gültig) → Verhaltensänderung |
| 11 | store/checkpoint.go:160 WriteCheckpoint ← client writeCheckpoints (client.go:801, logcheck.go:32) | W | checkpoints/<user>-<device>.rec | nein (je Gerät eine Datei; ein Gerät = ein Client-Verzeichnis) | Client-Verzeichnissperre | nur Fremdeingriff |
| 12 | client/flags.go:206 replaceMeta | W | Metadatei einer Mail | nein | Postfachsperre (withMailboxLock) | nur Fremdeingriff |
| 13 | client/mailbox.go:432 replaceUnlogged | W | epoch.rec (ungeloggt) | nein | Postfachsperre (withMailboxLock im Rumpf) | nur Fremdeingriff |
| 14 | client/devicelost.go:1598 sealAgain → WriteFileAtomic(RecoveryWrapFile) | W | Recovery-Wrap | nein | Postfachsperre (reissue → mutate) | nur Fremdeingriff |
| 15 | translog/files.go:110 writeTree; :271, operator.go:1028 Schlüsseldatei; operator.go:718 PublishHead; operator.go:923 repairTree | W | log/tree.rec, log/keys/*, log/heads/*.sig | nein | Logsperre `log/lock` (appendEntry, Init, PublishHead, repairTree) | nur Fremdeingriff |
| 16 | translog/impl.go:1600 saveIndex | WP | Audit-Index des Clients (Options.IndexFile, client/log.go:188) | nein | Client-Verzeichnissperre | nur Fremdeingriff |
| 17 | client/client.go:583 saveState | WP | <client>/state.json | nein | Client-Verzeichnissperre (Open hält sie) | nur Fremdeingriff |
| 18 | client/devicelost.go:266 DeviceLost | WP | <client>/user.rec | nein | Client-Verzeichnissperre (openForDeviceLost) | nur Fremdeingriff |
| 19 | client/mailbox.go:600 prepareMailbox | WP | <client>/<newMailboxesDir>/<id>/… (neue, zufällige ID) | nein | Client-Verzeichnissperre; Name neu | nur Fremdeingriff |
| 20 | testenv/testenv.go:478/479 Rotate | W/WP | user.rec | nein (Test) | – | – |
| 21 | client/keygen.go:197/203/213 writeClientDirOutside (keygen, restore) | WPIn | user.rec, keystore, state.json im frischen `os.MkdirTemp`-Ordner | nein (Ordner neu, 0700, erst danach umbenannt) | eigener neuer Ordner; lockOnlyDir am Ziel | nur Fremdeingriff (derselbe Benutzer) |
| 22 | store/store.go:155 CreateUser | C | user.rec | keine Aufrufer außerhalb von Tests | – | – |
| 23 | store/store.go:177 createOrSame; client/mailbox.go:772 createOrSame (finishMailbox); translog/files.go:167 createOrSame | C | verschiedene (gleicher Inhalt erlaubt) | ja (gleicher Inhalt; zweiter bekommt ErrExists und vergleicht) | Postfachsperre bzw. Logsperre bei den gefundenen Aufrufern | link ersetzt nie: check nach dem Link sieht nur dann etwas anderes, wenn danach jemand den Namen ersetzt/entfernt; rechtmäßig nur über W derselben Datei unter derselben Sperre → nur Fremdeingriff |
| 24 | store/store.go:222 CreateInvite | C | invites/<zufällige ID> | nein (Zufallsname) | – | nur Fremdeingriff |
| 25 | store/store.go:358 WritePlatformFile ← ceremony initdev (dev) | C | platform/* | nein (Entwicklung) | – | – |
| 26 | store/store.go:502 WriteEpoch ← client createEpoch (mailbox.go:329), EnsureEpoch, testenv | C | epoch.rec | ja (K2 Regel 3: zwei Clients erzeugen dieselbe Nummer; Verlierer bekommt ErrExists → errRace) | Postfachsperre (createEpoch: „caller holds the lock“) | link: kein Ersatz; ReplaceEpoch/ReplaceInvalidEpoch ersetzen nur unter derselben Sperre → nur Fremdeingriff |
| 27 | store/index.go:154 WriteIndexSegment ← client writeSegmentList | C | Indexsegment je Gerät und Laufnummer | nein (Name je Gerät) | Postfachsperre (mergeSegments) bzw. Client-Verzeichnissperre | nur Fremdeingriff |
| 28 | store/recovery.go:128 WriteRecoveryPub ← client SetRecovery (in mutate); :169 CreateRecoveryWrap (keine Aufrufer außerhalb von Tests) | C | recovery.pub | nein | Postfachsperre | nur Fremdeingriff |
| 29 | client/mailbox.go:310 createEpoch → CreateFileAtomic(FoldersFile); :392 createWrapNoted | C | folders.gml, Wraps einer neuen Epoche | Wettlauf um die Epoche wie #26 | Postfachsperre (mutate) | nur Fremdeingriff |
| 30 | ingest/queue.go:353 flushLocked | C | pending/<n>/<batch-id>.gml | nein (Batch-ID neu) | Postfachsperre | nur Fremdeingriff |
| 31 | ingest/delivery.go:630 commit (Journal) | C | spool/<txn>/journal | nein (eigener Transaktionsordner) | Postfachsperren (LockMailboxes) | nur Fremdeingriff |
| 32 | ingest/delivery.go:718/740 writeMeta, writeMarker | C | spool/<txn>/<id>/meta.gml, marker.gml | nein (eigener Spool-Ordner der Zustellung, vor der Sperre) | Ordner neu | nur Fremdeingriff |
| 33 | translog/impl.go:562 write; files.go:264 writeKeyFile | C | log/entries/<n>.rec, log/keys/* | nein | Logsperre | nur Fremdeingriff |
| 34 | ceremony/files.go:227 commit | C | Export im neuen Staging-Ordner | nein (Zeremonie offline, Ordner neu) | – | nur Fremdeingriff |
| 35 | witness/key.go:43 Keygen; ceremony/initdev_dev.go:113/125/145/214; testenv.go:183 | CP | private Schlüssel | nein (exklusiv angelegt) | – | nur Fremdeingriff |

**Ergebnis:** Für fast alle Aufrufer serialisiert eine Sperre (Postfach, Log, Adressen, Benutzer, Client-Verzeichnis) oder der Name ist neu
(Zufall, eigener Ordner); dort brächte eine Prüfung nach dem Umbenennen nur zusätzliche Ablehnungen bei Fremdeingriff.
**Ausnahmen mit rechtmäßiger Nebenläufigkeit ohne gemeinsame Sperre:** #10 `WriteAccept` über `acceptWrap` aus `keysFor` (Lesewege
ohne Postfachsperre; zwei Geräte desselben Benutzers), potenziell #3 `writeEpochKeys` (heute alle gefundenen Aufrufer unter der
Postfachsperre, aber `WriteEpoch` nimmt sie nicht selbst). Grenzen der Untersuchung: Aufrufketten über `ch *chain` wurden bis `mutate`
verfolgt für #2, #6, #8, #14, #28, #29; für die übrigen Client-Zeilen gilt die Sperre aus Kommentar bzw. Funktionsrumpf. Dort würde ein check nach dem rename einen rechtmäßigen Verlierer ablehnen, wo heute
„letzter gewinnt“ gilt → Verhaltensänderung; vor einer Umsetzung zu entscheiden (Haltepunkt: Prüfregel/Option), etwa Annahme/Wrap unter die
Postfachsperre oder check nur auf Typ (regulär, kein Verzeichnis), nicht auf Identität.
**Dieselbe Klasse wie 34A N1/Fenster 2 in den Pfad-Varianten:** `writeTemp` und `writeAtomic` entfernen den Temp-Namen im Fehlerweg mit
`os.Remove` (fällt auf rmdir zurück: entfernt auch ein leeres Verzeichnis, das ein anderer Prozess unterschob), `createAtomic` mit
`defer os.Remove(tmp)` nach dem Link (entfernt, was dann unter dem Temp-Namen liegt); `WritePrivateFileAtomicIn` mit `root.Remove(tmp)`
(os.Root.Remove fällt ebenfalls auf rmdir zurück). Keine Prüfung nach rename/link. Eine Übernahme von check/dropTemp dorthin müsste über
den Pfad laufen (Lstat auf dem Pfad; ein getauschtes Elternverzeichnis würde nicht erkannt) oder auf os.Root umgestellt werden.

## Stand
- Container-Neustart 00:34 UTC: Store-Wettlauf new/inst und cmd/gomail-ceremony-Lauf abgebrochen, neu gestartet (old war fertig, 72 Konfigurationen). Abgebrochenes Log: race/logs/store-new-400.aborted.log.
- Commit 3e007ca auf c8cda58 (Baum = WIP cda73e3, auf dem die Läufe liefen); Patch scratchpad/patches/36a.patch.

## Nachtrag 00:53: Verzeichnis vor dem Lstat öffnen
`openDirIn`/`removeNameInDir` (removenamein_unlinkat.go; anderswo Stubs, die removeNameIn aufrufen): dropTemp öffnet "." vor
dem Root.Lstat von aside, damit Fenster 2' kein open mehr enthält (Hinweis H1 Prüfer 2). Gemessen ohne messbaren Effekt
(inst 72 → inst2 80 im Fenster, Rauschen); behalten, weil korrekt und das Fenster um einen Systemaufruf kürzer ist.
Mutant M11 (d nicht geschlossen) getötet (Deskriptorzählung der Tests).

