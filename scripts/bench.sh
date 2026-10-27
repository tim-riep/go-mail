#!/usr/bin/env bash
# Runs the benchmarks of docs/tasks/12-benchmarks.md (package
# internal/bench) and prints a Markdown table, the template of
# docs/MEASUREMENTS.md: hardware, environment and every number with the
# command that measures it again.
#
# Usage: scripts/bench.sh [-short] [-count N] [-benchtime T] [-dir DIR] [-o FILE] [-raw FILE]
# (every option with a value also as -option=value)
#
#   -short       quick run: 20 iterations, 500 mails for Sync, 100 for
#                the memory load (the numbers only check the harness)
#   -count N     run every benchmark N times; the table shows the mean
#   -benchtime T benchtime of the throughput, Sync and Index benchmarks
#                (default 1s); the memory and the segment size benchmarks
#                always run once per -count (1x)
#   -dir DIR     temporary directory of the benchmarks (TMPDIR); its file
#                system is part of the result
#   -o FILE      write the Markdown table to FILE as well
#   -raw FILE    keep the raw go test output in FILE (benchstat format)
#
# Relative paths of -dir, -o and -raw are taken from the directory
# bench.sh is called from, not from the root of the repository.
#
# Environment: GOTOOLCHAIN (default go1.26.10), GOMAIL_BENCH_SYNC_MAILS
# (default 10000), GOMAIL_BENCH_MEM_MAILS (default 1000),
# GOMAIL_BENCH_MEM_CONNS (default 20, at most 64: MaxConns of the
# benchmark server).
#
# Every group of benchmarks runs in a go test process of its own. The
# memory benchmark runs every load (each size class and each repetition
# of -count) in a child process of its own, since Sys and VmRSS keep the
# peak of whatever ran before in a process; the table averages the runs.
set -euo pipefail

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.10}"

# abspath makes a path of the command line absolute against the
# directory bench.sh was called from; the script changes to the root of
# the repository after the options are read.
abspath() {
	case "$1" in
	/*) printf '%s' "$1" ;;
	*) printf '%s/%s' "$PWD" "$1" ;;
	esac
}

short=0
count=1
benchtime=1s
dir=""
out=""
raw=""
while [ $# -gt 0 ]; do
	case "$1" in
	-short) short=1 ;;
	-count) count="${2:?-count needs a value}"; shift ;;
	-count=*) count="${1#-count=}" ;;
	-benchtime) benchtime="${2:?-benchtime needs a value}"; shift ;;
	-benchtime=*) benchtime="${1#-benchtime=}" ;;
	-dir) dir="${2:?-dir needs a value}"; shift ;;
	-dir=*) dir="${1#-dir=}" ;;
	-o) out="${2:?-o needs a value}"; shift ;;
	-o=*) out="${1#-o=}" ;;
	-raw) raw="${2:?-raw needs a value}"; shift ;;
	-raw=*) raw="${1#-raw=}" ;;
	-h | -help | --help)
		sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "bench.sh: unknown argument $1" >&2
		exit 2
		;;
	esac
	shift
done
case "$count" in '' | *[!0-9]* | 0) echo "bench.sh: -count needs a positive number" >&2; exit 2 ;; esac
if [ -n "$dir" ]; then export TMPDIR="$(abspath "$dir")"; fi
if [ -n "$out" ]; then out="$(abspath "$out")"; fi
if [ -n "$raw" ]; then raw="$(abspath "$raw")"; fi

cd "$(dirname "$0")/.."

memtime=1x
if [ "$short" = 1 ]; then
	benchtime=20x
	export GOMAIL_BENCH_SYNC_MAILS="${GOMAIL_BENCH_SYNC_MAILS:-500}"
	export GOMAIL_BENCH_MEM_MAILS="${GOMAIL_BENCH_MEM_MAILS:-100}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rawfile="$work/raw.txt"
: >"$rawfile"

# run <benchtime> <regex> runs one group in a go test process of its own
# and notes the benchtime before the group's lines: the table needs it
# for the command of every number.
run() {
	local bt="$1" re="$2"
	echo "group-benchtime: $bt" >>"$rawfile"
	echo "bench.sh: go test -run '^\$' -bench '$re' -benchtime=$bt -count=$count ./internal/bench" >&2
	go test -run '^$' -bench "$re" -benchtime="$bt" -count="$count" -timeout 0 ./internal/bench | tee -a "$rawfile" >&2
}

run "$benchtime" '^BenchmarkReceive$'
run "$benchtime" '^BenchmarkSync$'
run "$memtime" '^BenchmarkServerMemory$'
run "$benchtime" '^BenchmarkIndex$'
# One operation of BenchmarkIndexSegments is the whole procedure (sizes,
# not times), as one of BenchmarkServerMemory is the whole load.
run "$memtime" '^BenchmarkIndexSegments$'

commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git status --porcelain -- . 2>/dev/null)" ]; then commit="$commit (mit lokalen Änderungen)"; fi

# envof <names...> prints "NAME=value " for every variable that is set.
envof() {
	local p="" v
	for v in "$@"; do
		if [ -n "${!v:-}" ]; then p="$p$v=${!v} "; fi
	done
	printf '%s' "$p"
}

render() {
	awk -v commit="$commit" -v date="$(date -u +%Y-%m-%dT%H:%MZ)" -v count="$count" \
		-v envall="$(envof TMPDIR)" -v envsync="$(envof GOMAIL_BENCH_SYNC_MAILS)" \
		-v envmem="$(envof GOMAIL_BENCH_MEM_MAILS GOMAIL_BENCH_MEM_CONNS)" '
	function point(name) {
		if (name ~ /^BenchmarkReceive/) return "1"
		if (name ~ /^BenchmarkIndexSegments/) return "3"
		if (name ~ /^BenchmarkIndex/) return "2"
		if (name ~ /^BenchmarkSync/) return "4"
		if (name ~ /^BenchmarkServerMemory/) return "5"
		return "?"
	}
	function envfor(name) {
		if (name ~ /^BenchmarkSync/) return envsync envall
		if (name ~ /^BenchmarkServerMemory/) return envmem envall
		return envall
	}
	# regex turns a benchmark name into an anchored -bench pattern.
	function regex(name,   n, parts, i, p, r) {
		n = split(name, parts, "/")
		r = ""
		for (i = 1; i <= n; i++) {
			p = parts[i]
			gsub(/[][.*+?(){}|^$\\]/, "\\\\&", p)
			r = r (i > 1 ? "/" : "") "^" p "$"
		}
		return r
	}
	# keep drops what the benchmarks report in better units: MB/s
	# (decimal, the same as MiB/s) and ns/op (the custom metrics are per
	# mail, per sync or per load).
	function keep(unit) { return unit != "MB/s" && unit != "ns/op" }
	function num(v) { return sprintf(v >= 100 ? "%.0f" : (v >= 1 ? "%.2f" : "%.4f"), v) }
	/^group-benchtime: / { bt = $2; next }
	/^[a-z]+: / {
		k = $1; sub(/:$/, "", k)
		v = $0; sub(/^[a-z]+: /, "", v)
		if (k == "command" || k == "pkg") next
		if (!(k in cfg)) { cfg[k] = v; order[++ncfg] = k }
		next
	}
	/^Benchmark/ {
		name = $1; sub(/-[0-9]+$/, "", name)
		if (!(name in seen)) { seen[name] = 1; names[++nnames] = name; btof[name] = bt }
		for (i = 3; i + 1 <= NF; i += 2) {
			unit = $(i + 1)
			if (!keep(unit)) continue
			key = name SUBSEP unit
			if (!(key in sum)) { nu[name]++; units[name, nu[name]] = unit }
			sum[key] += $i; cnt[key]++
		}
	}
	END {
		print "# Messwerte"
		print ""
		print "Erzeugt mit `scripts/bench.sh` am " date " auf Commit " commit "."
		print ""
		print "## Umgebung"
		print ""
		print "| Merkmal | Wert |"
		print "|---|---|"
		for (i = 1; i <= ncfg; i++) printf "| %s | `%s` |\n", order[i], cfg[order[i]]
		print ""
		print "## Ergebnisse"
		print ""
		print "Punkte nach docs/tasks/12-benchmarks.md: 1 Empfang, 2 Indexierung, 3 Indexsegmente, 4 Sync, 5 Speicher des Servers (base vor, peak während, rest nach der Last)."
		print ""
		print "* Punkt 1 in drei Betriebsarten je Größe und Verbindungszahl: `enc` = Ingest vollständig; `proto` = gleiches Ablageprotokoll ohne Verschlüsselung, samt Platzprüfung (`Accepting()`, zwei statfs je Mail) und Worker (je 100 Mails eine Begriffsliste in der Größe, die Ingest für die Größenklasse schreibt, danach Löschen der 100 Marker); `plain` = Minimal-Senke (Protokollkosten = proto − plain)."
		print "* Verschlüsselungskosten = enc − proto. Darin stecken außer der Verschlüsselung: Signaturen, Selbstprüfung, Auswertung der Kopfzeilen, Adressauflösung (`addresses.json`), Lesen von `mailbox.rec`, Kettenprüfung über Cache (Hashvergleich von `epoch.rec` und `user.rec`, je Mail zweimal), Hash über den Mailstrom, Termzerlegung im Worker. Die Begriffslisten sind in beiden Betriebsarten enthalten, soweit der Worker sie im Zeitfenster schreibt (bei b.N ≥ 100); die zuletzt offene Liste schreiben beide erst nach dem Zeitfenster."
		print "* Bei `enc` wächst das Postfachverzeichnis während des Laufs (und über die Läufe einer Größe hinweg), bei `proto` ebenfalls bis zum Ende des Laufs: `mail.gml`, `meta.gml` und die Begriffslisten löscht `proto` erst nach dem Zeitfenster."
		print "* Lockerungen gegenüber 5.1: MaxConns 64 statt 20, MaxConnsPerIP 64 statt 5, kein Mail-Limit je IP und Stunde (Benchmark-Server); MinFree 1 % statt 10 % (Ingest und `proto`; die gemeinsam genutzte Maschine hat weniger freien Platz, die Grenze wird nicht gemessen, statfs läuft trotzdem); GOMAIL_BENCH_MEM_CONNS ist auf MaxConns (64) begrenzt."
		print "* Punkte 1 und 5: Uhr eingefroren (kein Alters-Flush), Logausgabe verworfen (Server und Ingest); der Worker schreibt Begriffslisten nur nach je 100 Mails und beim Flush. Bei den Punkten 2 bis 4 stellt die Zustellung des Korpus (Vorbereitung, nicht gemessen) die Uhr tageweise vor, dort schreibt der Worker auch nach Alter."
		print "* Der Lastgenerator (net/smtp) läuft im selben Prozess wie der Server; bei Punkt 5 zählen seine Verbindungspuffer mit."
		print "* Punkt 2: `client.Index` über 1000 Mails des Korpus (10 Absender, 3 Empfänger, 30 Tage, 20 % Anhänge, Threads), je Durchlauf; vor jedem Durchlauf werden außerhalb der Zeitmessung die Segmente gelöscht und pending/ so wiederhergestellt, wie Ingest es hinterließ. `terms` = Begriffslisten des Workers (je Liste bis 100 Mails, eine Datei); `unprocessed` = nur Marker (eine Datei je Mail; der Worker lief bei der Zustellung nicht, kein Flush), Index liest und prüft dann die Metadaten jeder Mail und löscht jede Markerdatei einzeln (RemoveDurable, ein fsync je Mail). allocs/op und B/op gelten je Durchlauf, allocs/mail und B/mail je Mail."
		print "* Punkt 3: Korpus mit 1000 Mails im November 2026 (eine Epoche), in 15 Teilen zugestellt, nach jedem Teil `client.Index` (ein Segment je Lauf); gezählt werden die Bytes aller `index/<n>/*.gml` über `store`. B-unmerged = 15 Segmente mit allen 1000 Mails, B/segment = deren Mittel; Lauf 16 indexiert die Begriffslisten von Teil 1 noch einmal (dieselben Mails), sein Segment ist das 16., und der Client fasst ab 16 Segmenten zusammen: B-merged und segments-merged danach (doppelte Mail-IDs entfallen). Die Größen hängen nicht von der Maschine ab."
		print "* Punkt 4: `Sync` hält den Epochenvorrat und ruft `client.Index` auf. index=off = pending/ leer (alles schon indexiert); index=on = pending/ wie nach der Zustellung (Begriffslisten aller Mails), vor jedem Sync außerhalb der Zeitmessung wiederhergestellt, Segmente gelöscht."
		print "* Punkt 5: jeder Lauf (jede Größe, jede Wiederholung bei -count) läuft in einem eigenen Kindprozess; Grund- und Ruhewert werden gleich vorbereitet (1 s Leerlauf, dann debug.FreeOSMemory(), dann Messung). Die Grundwerte getrennter Läufe streuen um höchstens 5 MiB (Rauschanteil, geprüft von TestServerMemoryRuns; Sys wächst in Schritten von 4 MiB); der VmRSS-Grundwert von Lauf 2 liegt höchstens 1 MiB über dem von Lauf 1 (getrennte Prozesse streuen um weniger als 0,2 MiB)."
		if (count > 1) print "* Jede Zahl ist der Mittelwert aus " count " Läufen."
		print ""
		print "| Punkt | Benchmark | Messwerte | Befehl zum Nachmessen |"
		print "|---|---|---|---|"
		for (j = 1; j <= nnames; j++) {
			s = names[j]
			vals = ""
			for (u = 1; u <= nu[s]; u++) {
				key = s SUBSEP units[s, u]
				vals = vals (u > 1 ? ", " : "") num(sum[key] / cnt[key]) " " units[s, u]
			}
			disp = s; sub(/^Benchmark/, "", disp)
			cmd = envfor(s) "go test -run '\''^$'\'' -bench '\''" regex(s) "'\'' -benchtime=" btof[s] " ./internal/bench"
			printf "| %s | %s | %s | `%s` |\n", point(s), disp, vals, cmd
		}
	}' "$rawfile"
}

table="$(render)"
printf '%s\n' "$table"
if [ -n "$out" ]; then printf '%s\n' "$table" >"$out"; fi
if [ -n "$raw" ]; then grep -v '^group-benchtime: ' "$rawfile" >"$raw"; fi
