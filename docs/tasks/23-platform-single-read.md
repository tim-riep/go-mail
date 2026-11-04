# Auftrag 23: Plattformzertifikat einmal lesen (Fund mittel aus der Angreiferprüfung von 22)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` (aktueller Stand), eigener Worktree. Auftrag 22 (3cd9072, `internal/ceremony`, `internal/client/client.go` `resolveExisting`) wird getrennt zusammengeführt; die Dateien überschneiden sich nicht.
- Darf ändern: `internal/client/read.go`, `internal/ingest/ingest.go`, `internal/store/store.go` (nur Lesefunktionen für Plattformdateien, keine Schemata), Tests dazu.
- Nicht ändern: Dateiformate, signierte Datensätze, Signaturdomänen, Prüfregeln der Clients (welche Zertifikate gelten), Phase-0-Vektoren.

## Fund

`Client.ingestKeyFor` (`internal/client/read.go`) liest `ingest-<g>.cert` zweimal. Der Schlüssel `cert.Pub` und die Signaturprüfung kommen aus dem ersten Lesen (`store.ReadPlatformCert`). Der Abgleich mit dem Log (`Log.CheckPlatform(name, raw)`) läuft über ein zweites Lesen (`ReadPlatformFile`). Ein Angreifer mit Schreibrecht auf `data/platform/` und einem gestohlenen, zu diesem Zeitpunkt noch nicht widerrufenen Identitätsschlüssel kann die Datei zwischen den beiden Lesevorgängen tauschen. Beim ersten Lesen liegt dort ein eigenes, nicht geloggtes Zertifikat mit eigenem Ingest-Schlüssel, beim zweiten die geloggte Datei. Der Client übernimmt dann den fremden Schlüssel, obwohl der Logabgleich besteht. Das umgeht die Transparenz aus 2.3 und 7 (S9). Den Fund hat die Angreiferprüfung von 22 als Nebenbeobachtung gemeldet, die Einstufung mittel stammt vom Orchestrator. Dasselbe Muster gibt es in `ingest.New` (`internal/ingest/ingest.go`, `ReadPlatformCert` und danach `ReadPlatformFile` für `CheckPlatform`), dort mit niedriger Folge, weil Clients selbst prüfen.

## Umfang

1. Eine Lesefunktion in `store`, etwa `ReadPlatformCertRaw(role, gen) (*keys.PlatformCert, []byte, error)`. Sie liest die Datei einmal, dekodiert und prüft dieselben Bytes wie `ReadPlatformCert` (Rolle, Generation, `.pub` gleich) und gibt die gelesenen Bytes zurück. `ReadPlatformCert` ruft sie auf.
2. `ingestKeyFor`: Signaturprüfung, Schlüssel und `CheckPlatform` arbeiten auf denselben Bytes. Es gibt kein zweites Lesen von `ingest-<g>.cert`.
3. `ingest.New`: ebenso.
4. Prüfe alle weiteren Aufrufer von `ReadPlatformCert`/`ReadPlatformFile` im Produktivcode (`grep`) auf dasselbe Muster, also Lesen, Prüfen und erneutes Lesen für den Log oder für den Schlüssel. Nenne sie im Bericht mit Einordnung. Behebe nur Stellen in den erlaubten Dateien; andere stehen als Vorschlag im Bericht.
5. Tests, die auf dem alten Code deterministisch scheitern: Ein Testhaken im Lesepfad (etwa eine Variable in `store` nur für Tests, über `export_test.go` gesetzt, oder ein Lesezähler) tauscht die Datei nach dem ersten Lesen. Der neue Code nimmt dann entweder den geloggten Schlüssel oder scheitert mit `ErrPlatform`, übernimmt aber nie den fremden Schlüssel. Ein Gegenbeleg zeigt, dass der Test auf dem alten Stand scheitert (Mutation: zweites Lesen wiederherstellen). Für `ingest` gilt dasselbe.

## Fertig

- gofmt, `go vet` mit und ohne Tags. race mit und ohne Tags und 386 mit Tags für `internal/store` und `internal/ingest`. `internal/client` nur gezielt mit `-run` (race mit Tags, 386 mit Tags), dazu die bestehenden Tests mit `Platform`, `Ingest`, `Revoked` im Namen. `internal/e2e` mit `-run 'Revoked|Succession'` mit Tags.
- **Ruhige Maschine:** Jeder `go`-Befehl läuft mit `nice -n 19`. Vor jedem `go test`/`go vet`/`go build` prüfst du `test -e /tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/orch/QUIET`. Solange die Datei existiert (Messungen), startest du keinen solchen Befehl. Du schreibst dann nur Code und Tests und prüfst alle paar Minuten mit `ls`, ob sie verschwunden ist. Nach 04:15 UTC committest du den erreichten Stand und berichtest, auch wenn Läufe fehlen.
- Ein Commit mit `Task: docs/tasks/23-platform-single-read.md`, ohne Co-Authored-By, ohne Modellnamen. Nicht pushen. WIP-Commits nach jedem Punkt (Container startet etwa stündlich neu). Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl23/notes.md`.
- Bericht: je Punkt erledigt oder nicht; die Liste aus Punkt 4; Läufe; Commit und Worktree.
