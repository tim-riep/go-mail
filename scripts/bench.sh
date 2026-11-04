#!/usr/bin/env bash
# Runs the benchmarks of docs/tasks/12-benchmarks.md (package
# internal/bench) and prints a Markdown table, the template of
# docs/MEASUREMENTS.md: hardware, environment and every number with the
# command that measures it again.
#
# Usage: scripts/bench.sh [-short] [-count N] [-benchtime T] [-maxload L] [-dir DIR] [-o FILE] [-raw FILE]
#        scripts/bench.sh -render FILE [-count N] [-benchtime T] [-o FILE]
# (every option with a value also as -option=value)
#
#   -short       quick run: 20 iterations, 500 mails for Sync, 100 for
#                the memory load (the numbers only check the harness)
#   -count N     run every benchmark N times; the table shows the median
#                and the smallest and largest value
#   -benchtime T benchtime of the throughput, Sync and Index benchmarks
#                (default 1s); the memory and the segment size benchmarks
#                always run once per -count (1x)
#   -maxload L   before every group, wait until the load average of the
#                last minute is below L (a positive number such as 0.5;
#                polled every 10 s, at most 30 minutes); the load and the
#                steal time of every group are noted in the raw output and
#                the table either way
#   -dir DIR     temporary directory of the benchmarks (TMPDIR); its file
#                system is part of the result
#   -o FILE      write the Markdown table to FILE as well
#   -raw FILE    keep the raw go test output in FILE (benchstat format)
#   -render FILE measure nothing: print the table of the raw output FILE
#                of an earlier run (-raw); -count, -benchtime and
#                GOMAIL_BENCH_MIN_FREE must be those of that run (checked
#                against the command and env lines of FILE, exit 1
#                otherwise), the table names no commit
#
# An option given with an empty value (-render=, -o "", ...) ends
# bench.sh with 2 before anything runs.
#
# The table is fail closed: every group needs at least one benchmark line,
# every number of a benchmark exactly N values (-count), no line may
# report a failure or a skipped benchmark; otherwise bench.sh prints what
# is missing, writes no table (and no -raw file) and exits with 1.
#
# Relative paths of -dir, -o, -raw and -render are taken from the directory
# bench.sh is called from, not from the root of the repository.
#
# Environment: GOTOOLCHAIN (default go1.26.10), GOMAIL_BENCH_MIN_FREE
# (MinFree in percent, default 1; for a file system with less free space
# than that), GOMAIL_BENCH_SYNC_MAILS
# (default 10000), GOMAIL_BENCH_MEM_MAILS (default 1000),
# GOMAIL_BENCH_MEM_CONNS (default 20, at most 64: MaxConns of the
# benchmark server).
#
# Every group of benchmarks runs in a go test process of its own. The
# memory benchmark runs every load (each size class and each repetition
# of -count) in a child process of its own, since Sys and VmRSS keep the
# peak of whatever ran before in a process; the table takes the median of
# the runs.
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

# need ends bench.sh with 2 if option $1 has an empty value: an empty
# value would count as "not set" (no -render, no -o, ...) and start a
# full measurement instead.
need() {
	if [ -z "$2" ]; then
		echo "bench.sh: $1 needs a non-empty value" >&2
		exit 2
	fi
}

short=0
count=1
benchtime=1s
dir=""
out=""
raw=""
maxload=""
maxloadset=0
renderin=""
renderset=0
while [ $# -gt 0 ]; do
	case "$1" in
	-short) short=1 ;;
	-count) need -count "${2-}"; count="$2"; shift ;;
	-count=*) count="${1#-count=}"; need -count "$count" ;;
	-benchtime) need -benchtime "${2-}"; benchtime="$2"; shift ;;
	-benchtime=*) benchtime="${1#-benchtime=}"; need -benchtime "$benchtime" ;;
	-maxload) need -maxload "${2-}"; maxload="$2"; maxloadset=1; shift ;;
	-maxload=*) maxload="${1#-maxload=}"; maxloadset=1; need -maxload "$maxload" ;;
	-dir) need -dir "${2-}"; dir="$2"; shift ;;
	-dir=*) dir="${1#-dir=}"; need -dir "$dir" ;;
	-o) need -o "${2-}"; out="$2"; shift ;;
	-o=*) out="${1#-o=}"; need -o "$out" ;;
	-raw) need -raw "${2-}"; raw="$2"; shift ;;
	-raw=*) raw="${1#-raw=}"; need -raw "$raw" ;;
	-render) need -render "${2-}"; renderin="$2"; renderset=1; shift ;;
	-render=*) renderin="${1#-render=}"; renderset=1; need -render "$renderin" ;;
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
case "$count" in '' | *[!0-9]* | 0*) echo "bench.sh: -count needs a positive number" >&2; exit 2 ;; esac
if [ "$maxloadset" = 1 ]; then
	if ! [[ "$maxload" =~ ^[0-9]+([.][0-9]+)?$ ]] || [[ "$maxload" =~ ^0+([.]0+)?$ ]]; then
		echo "bench.sh: -maxload needs a positive number such as 0.5, not '$maxload'" >&2
		exit 2
	fi
fi
if [ "$renderset" = 1 ]; then
	if [ -n "$raw" ] || [ -n "$dir" ] || [ "$maxloadset" = 1 ] || [ "$short" = 1 ]; then
		echo "bench.sh: -render measures nothing; only -count, -benchtime and -o go with it" >&2
		exit 2
	fi
	renderin="$(abspath "$renderin")"
	if [ ! -f "$renderin" ] || [ ! -r "$renderin" ]; then
		echo "bench.sh: -render: cannot read $renderin" >&2
		exit 2
	fi
fi
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

# load1 prints the load average of the last minute.
load1() { cut -d' ' -f1 /proc/loadavg; }

# groupmark prints the time, the load averages and the CPU ticks of
# /proc/stat (sum of user to steal, then steal) for group-start and
# group-end.
groupmark() {
	printf '%s loadavg=%s cpu=%s' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' /)" \
		"$(awk '$1 == "cpu" { t = 0; for (i = 2; i <= 9; i++) t += $i; print t "/" $9; exit }' /proc/stat)"
}

# waitload waits until load1 is below -maxload (if set).
waitload() {
	[ -n "$maxload" ] || return 0
	local i=0
	while awk -v l="$(load1)" -v m="$maxload" 'BEGIN { exit !(l >= m) }'; do
		if [ "$i" -ge 180 ]; then
			echo "bench.sh: load $(load1) not below $maxload after 30 minutes" >&2
			exit 1
		fi
		i=$((i + 1))
		sleep 10
	done
}

# run <benchtime> <regex> runs one group in a go test process of its own
# and notes the benchtime before the group's lines: the table needs it
# for the command of every number. Around the group it notes time, load
# and CPU ticks (group-start, group-end); with -maxload it first waits
# for a quiet machine.
run() {
	local bt="$1" re="$2"
	waitload
	echo "group-benchtime: $bt" >>"$rawfile"
	echo "group-start: $re $(groupmark)" | tee -a "$rawfile" >&2
	echo "bench.sh: go test -tags gomail_dev -run '^\$' -bench '$re' -benchtime=$bt -count=$count ./internal/bench" >&2
	go test -tags gomail_dev -run '^$' -bench "$re" -benchtime="$bt" -count="$count" -timeout 0 ./internal/bench | tee -a "$rawfile" >&2
	echo "group-end: $re $(groupmark)" | tee -a "$rawfile" >&2
}

# groups are the -bench patterns of the groups in the order they run;
# groupbt prints the benchtime of a group. One operation of
# BenchmarkIndexSegments is the whole procedure (sizes, not times), as
# one of BenchmarkServerMemory is the whole load.
groups=('^BenchmarkReceive$' '^BenchmarkSync$' '^BenchmarkServerMemory$' '^BenchmarkIndex$' '^BenchmarkIndexSegments$')
groupbt() {
	case "$1" in
	'^BenchmarkServerMemory$' | '^BenchmarkIndexSegments$') printf '%s' "$memtime" ;;
	*) printf '%s' "$benchtime" ;;
	esac
}

if [ "$renderset" = 1 ]; then
	# The raw output of -raw has no group-benchtime lines; they come
	# from groupbt, as in a run with the same -benchtime.
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		group-benchtime:*) continue ;;
		group-start:*)
			re="${line#group-start: }"
			echo "group-benchtime: $(groupbt "${re%% *}")"
			;;
		esac
		printf '%s\n' "$line"
	done <"$renderin" >"$rawfile"
	commit="unbekannt (nur dargestellt mit -render aus $(basename "$renderin"), nicht gemessen)"
else
	for re in "${groups[@]}"; do
		run "$(groupbt "$re")" "$re"
	done
	commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	if [ -n "$(git status --porcelain -- . 2>/dev/null)" ]; then commit="$commit (mit lokalen Änderungen)"; fi
fi

# envof <names...> prints "NAME=value " for every variable that is set.
envof() {
	local p="" v
	for v in "$@"; do
		if [ -n "${!v:-}" ]; then p="$p$v=${!v} "; fi
	done
	printf '%s' "$p"
}

# render prints the table of $rawfile, or names what is missing on
# stderr and fails (fail closed: no table from incomplete data).
render() {
	awk -v commit="$commit" -v date="$(date -u +%Y-%m-%dT%H:%MZ)" -v count="$count" -v render="$renderset" -v groups="${groups[*]}" \
		-v envall="$(envof GOMAIL_BENCH_MIN_FREE TMPDIR)" -v minfree="${GOMAIL_BENCH_MIN_FREE:-}" -v envsync="$(envof GOMAIL_BENCH_SYNC_MAILS)" \
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
	# median sorts the values of key (insertion sort, few values) and
	# sets lo and hi.
	function median(key,   n, a, i, j, x) {
		n = cnt[key]
		for (i = 1; i <= n; i++) a[i] = vals[key, i]
		for (i = 2; i <= n; i++) {
			x = a[i]
			for (j = i - 1; j >= 1 && a[j] > x; j--) a[j + 1] = a[j]
			a[j + 1] = x
		}
		lo = a[1]; hi = a[n]
		return n % 2 ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
	}
	function field(rec, name,   i, n, f) {
		n = split(rec, f, " ")
		for (i = 1; i <= n; i++) if (index(f[i], name "=") == 1) return substr(f[i], length(name) + 2)
		return ""
	}
	# fail names what is wrong with the raw output and ends awk with 1;
	# END then prints nothing.
	function fail(msg) {
		print "bench.sh: no table: " msg > "/dev/stderr"
		failed = 1
		exit 1
	}
	/^(FAIL|--- FAIL|--- SKIP|panic: )/ { fail("line " NR " reports a failure or a skip: " $0) }
	/^group-benchtime: / { bt = $2; next }
	/^group-start: / {
		if (open) fail("group " gname[ng] " has no group-end")
		ng++; open = 1; gname[ng] = $2; gstart[ng] = $3; gload[ng] = field($0, "loadavg"); gcpu0[ng] = field($0, "cpu"); next
	}
	/^group-end: / {
		if (!open || $2 != gname[ng]) fail("group-end of " $2 " in line " NR " without its group-start")
		open = 0; gend[ng] = $3; gloadend[ng] = field($0, "loadavg"); gcpu1[ng] = field($0, "cpu"); next
	}
	# With -render, the command and env lines of the raw output must match
	# -benchtime, -count and GOMAIL_BENCH_MIN_FREE of this call: the table
	# names them in every command.
	render && /^command: / && (index($0 " ", " -benchtime=" bt " ") == 0 || index($0 " ", " -count=" count " ") == 0) {
		fail("line " NR " (" $0 ") does not match -benchtime " bt " and -count " count " of this call")
	}
	render && /^env: / && field($0, "GOMAIL_BENCH_MIN_FREE") != minfree {
		fail("line " NR " (" $0 ") does not match GOMAIL_BENCH_MIN_FREE=" minfree " of this call")
	}
	/^[a-z]+: / {
		k = $1; sub(/:$/, "", k)
		v = $0; sub(/^[a-z]+: /, "", v)
		if (k == "command" || k == "pkg") next
		if (!(k in cfg)) { cfg[k] = v; order[++ncfg] = k }
		next
	}
	/^Benchmark/ {
		if (!open) fail("benchmark line " NR " outside a group: " $1)
		if (NF < 4 || NF % 2 || $2 !~ /^[0-9]+$/) fail("benchmark line " NR " is not name, iterations and value-unit pairs: " $0)
		gnb[ng]++
		name = $1; sub(/-[0-9]+$/, "", name)
		if (!(name in seen)) { seen[name] = 1; names[++nnames] = name; btof[name] = bt }
		for (i = 3; i + 1 <= NF; i += 2) {
			if ($i !~ /^-?[0-9]+([.][0-9]+)?$/) fail("benchmark line " NR ": value " $i " is not a number")
			unit = $(i + 1)
			if (!keep(unit)) continue
			key = name SUBSEP unit
			if (!(key in sum)) { nu[name]++; units[name, nu[name]] = unit }
			vals[key, ++cnt[key]] = $i; sum[key] += $i
		}
	}
	END {
		if (failed) exit 1
		if (open) fail("group " gname[ng] " has no group-end")
		n = split(groups, want, " ")
		if (ng != n) fail(ng " groups in the raw output, " n " expected (" groups ")")
		for (i = 1; i <= n; i++) {
			if (gname[i] != want[i]) fail("group " i " is " gname[i] ", expected " want[i])
			if (gnb[i] < 1) fail("group " gname[i] " has no benchmark line")
		}
		for (j = 1; j <= nnames; j++) {
			s = names[j]
			if (nu[s] < 1) fail(s " reports no number the table shows")
			for (u = 1; u <= nu[s]; u++) {
				key = s SUBSEP units[s, u]
				if (cnt[key] != count + 0) fail(s ": " cnt[key] " values of " units[s, u] ", -count " count " expected")
			}
		}
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
		print "* Punkt 2: `client.Index` über 1000 Mails des Korpus (10 Absender, 3 Empfänger, 30 Tage, 20 % Anhänge, Threads), je Durchlauf; vor jedem Durchlauf werden außerhalb der Zeitmessung die Segmente gelöscht und pending/ so wiederhergestellt, wie Ingest es hinterließ. Der Client bleibt offen, sein Verzeichnis unverändert; er indexiert pending/ erneut, weil kein Segment die Einträge mehr enthält. `terms` = Begriffslisten des Workers (je Liste bis 100 Mails, eine Datei); `unprocessed` = nur Marker (eine Datei je Mail; der Worker lief bei der Zustellung nicht, kein Flush), Index liest und prüft dann die Metadaten jeder Mail und löscht jede Markerdatei einzeln (RemoveDurable, ein fsync je Mail). allocs/op und B/op gelten je Durchlauf, allocs/mail und B/mail je Mail."
		print "* Punkt 3: Korpus mit 1000 Mails im November 2026 (eine Epoche), in 16 Teilen zugestellt, nach jedem Teil `client.Index` (ein Segment je Lauf); gezählt werden die Bytes aller `index/<n>/*.gml` über `store`. Der Lauf von Teil 16 schreibt das 16. Segment und fasst im selben Lauf zusammen (ab 16 Segmenten, wenn das Ergebnis ein Segment ist). Während dieses Laufs hält die Messung die Postfachsperre, bis das 16. Segment geschrieben ist: B-unmerged = diese 16 Segmente mit allen 1000 Mails, unmittelbar vor dem Zusammenfassen, B/segment = deren Mittel; B-merged und segments-merged nach dem Zusammenfassen. Die Größen hängen nicht von der Maschine ab."
		print "* Punkt 4: `Sync` hält den Epochenvorrat und ruft `client.Index` auf. index=off = pending/ leer (alles schon indexiert); index=on = pending/ wie nach der Zustellung (Begriffslisten aller Mails), vor jedem Sync außerhalb der Zeitmessung wiederhergestellt, Segmente gelöscht. `Sync/…/list` ist `client.List` über alle Mails des Eingangs, kein Teil von `Sync`: der Schritt, dessen Kosten mit der Zahl der Mails wachsen, solange `Sync` keine Mails liest."
		print "* Punkt 5: jeder Lauf (jede Größe, jede Wiederholung bei -count) läuft in einem eigenen Kindprozess; Grund- und Ruhewert werden gleich vorbereitet (1 s Leerlauf, dann debug.FreeOSMemory(), dann Messung). Die Grundwerte getrennter Läufe streuen um höchstens 5 MiB (Rauschanteil, geprüft von TestServerMemoryRuns; Sys wächst in Schritten von 4 MiB); der VmRSS-Grundwert von Lauf 2 liegt höchstens 1 MiB über dem von Lauf 1 (getrennte Prozesse streuen um weniger als 0,2 MiB)."
		if (minfree != "") print "* Dieser Lauf setzt GOMAIL_BENCH_MIN_FREE=" minfree ": MinFree " minfree " % statt der 1 % oben (Ingest und `proto`; statfs läuft unverändert je Mail zweimal)."
		if (count > 1) print "* Jede Zahl ist der Median aus " count " Läufen, in Klammern der kleinste und der größte Wert."
		print ""
		print "| Punkt | Benchmark | Messwerte | Befehl zum Nachmessen |"
		print "|---|---|---|---|"
		for (j = 1; j <= nnames; j++) {
			s = names[j]
			out = ""
			for (u = 1; u <= nu[s]; u++) {
				key = s SUBSEP units[s, u]
				m = median(key)
				v = num(m) " " units[s, u]
				if (cnt[key] > 1 && num(lo) != num(hi)) v = v " (" num(lo) "–" num(hi) ")"
				out = out (u > 1 ? ", " : "") v
			}
			disp = s; sub(/^Benchmark/, "", disp)
			cmd = envfor(s) "go test -tags gomail_dev -run '\''^$'\'' -bench '\''" regex(s) "'\'' -benchtime=" btof[s] " ./internal/bench"
			printf "| %s | %s | %s | `%s` |\n", point(s), disp, out, cmd
		}
		if (ng > 0) {
			print ""
			print "## Last und Steal je Gruppe"
			print ""
			print "Load average (1, 5, 15 min) vor und nach jeder Gruppe; Steal = Anteil der Steal-Ticks an allen CPU-Ticks (`/proc/stat`, user bis steal) während der Gruppe."
			print ""
			print "| Gruppe | Beginn (UTC) | Ende (UTC) | Last vorher | Last nachher | Steal |"
			print "|---|---|---|---|---|---|"
			for (i = 1; i <= ng; i++) {
				split(gcpu0[i], c0, "/"); split(gcpu1[i], c1, "/")
				st = (c1[1] > c0[1]) ? sprintf("%.2f %%", 100 * (c1[2] - c0[2]) / (c1[1] - c0[1])) : "–"
				printf "| `%s` | %s | %s | %s | %s | %s |\n", gname[i], gstart[i], gend[i], gload[i], gloadend[i], st
			}
		}
	}' "$rawfile"
}

if ! table="$(render)"; then
	if [ "$renderset" = 1 ]; then
		echo "bench.sh: no table written" >&2
	else
		echo "bench.sh: no table written; the go test output of the run is on stderr above" >&2
	fi
	exit 1
fi
printf '%s\n' "$table"
if [ -n "$out" ]; then printf '%s\n' "$table" >"$out"; fi
if [ -n "$raw" ]; then grep -v '^group-benchtime: ' "$rawfile" >"$raw"; fi
