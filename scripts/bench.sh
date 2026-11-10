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
#                (default 1s): a count such as 20x or a duration of Go
#                with one unit (ns, us, µs, ms, s, m, h) such as 1.5s,
#                exit 2 otherwise; the memory and the segment size
#                benchmarks always run once per -count (1x)
#   -maxload L   before every group, wait until the load average of the
#                last minute is below L (a positive number such as 0.5;
#                polled every 10 s, at most 30 minutes); the load and the
#                steal time of every group are noted in the raw output and
#                the table either way
#   -dir DIR     temporary directory of the benchmarks (TMPDIR); its file
#                system is part of the result
#   -o FILE      write the Markdown table to FILE as well
#   -raw FILE    keep the raw go test output in FILE (benchstat format);
#                exit 2 before anything runs if FILE cannot be written (a
#                directory, a missing directory, a file not writable) or
#                is the -o FILE
#   -render FILE measure nothing: print the table of the raw output FILE
#                of an earlier run (-raw); -count, -benchtime and
#                GOMAIL_BENCH_MIN_FREE, GOMAIL_BENCH_SYNC_MAILS,
#                GOMAIL_BENCH_MEM_MAILS, GOMAIL_BENCH_MEM_CONNS and TMPDIR
#                must be those of that run (checked against the command and
#                env lines of FILE, exactly one of each per group, exit 1
#                otherwise; an empty variable counts as unset), the table
#                names no commit; exit 2 if FILE is the -o FILE
#
# An option given with an empty value (-render=, -o "", ...) or with a
# value that starts with - (-o -render=F, -count -5, ...) ends bench.sh
# with 2 before anything runs; a path that starts with - is written ./-...
# So does a line break (LF or CR), a | or a backtick in a variable of
# the env line of internal/bench (GOTOOLCHAIN, GOMAXPROCS, GOGC,
# GOMEMLIMIT, GODEBUG, GOAMD64, GOARM64, TMPDIR, also from -dir,
# GOMAIL_BENCH_MIN_FREE, GOMAIL_BENCH_SYNC_MAILS, GOMAIL_BENCH_MEM_MAILS,
# GOMAIL_BENCH_MEM_CONNS) or in the name of the -render FILE: the table
# shows them, and these characters would break it.
#
# The table is fail closed: every group needs at least one benchmark line,
# every benchmark exactly N lines (-count) with at least one iteration
# and exactly N values of every number, every benchmark of the list in
# bench.sh (wantnames, the names of internal/bench) and every
# sub-benchmark of a group that its siblings have (see render), every
# benchmark line must be in the group of its benchmark, no line may
# report a failure or a skipped benchmark, also indented, and no value
# the table shows (names, units, the key: value lines, the times and
# loads of the groups) may have a |, a backtick or a carriage return;
# otherwise bench.sh prints what is missing, writes no table and exits
# with 1. wantnames is kept by hand: a benchmark that internal/bench
# adds is not required, one that it renames or drops makes every table
# fail until wantnames follows. A line number in these messages counts
# the lines of the raw output as the user has it (-raw, bench-raw.txt
# below or the -render FILE).
#
# The raw output of a measurement is kept before the table is made:
# with -raw in FILE, written first. It stays in a new directory under
# TMPDIR, in bench-raw.txt, as bench.sh prints, if it is not in FILE
# and the run does not end with a table: without -raw if no table comes
# out, if FILE cannot be written (bench.sh then writes no table and
# exits with 1), if go test fails or bench.sh is stopped (INT, TERM,
# HUP). -render FILE takes bench-raw.txt as it is.
#
# Relative paths of -dir, -o, -raw and -render and a relative TMPDIR are
# taken from the directory bench.sh is called from, not from the root of
# the repository; a CDPATH of the environment does not count.
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
# A CDPATH from the environment would let the cd to the root of the
# repository below go elsewhere and print the directory on stdout.
unset CDPATH

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.10}"

# abspath NAME PATH sets the variable NAME to PATH made absolute
# against the directory bench.sh was called from; the script changes to
# the root of the repository after the options are read. It sets the
# variable itself: a command substitution would drop a line break at the
# end of PATH, and bench.sh would use another path than the one given.
abspath() {
	case "$2" in
	/*) printf -v "$1" '%s' "$2" ;;
	*) printf -v "$1" '%s/%s' "$PWD" "$2" ;;
	esac
}

# need ends bench.sh with 2 if option $1 has an empty value or one that
# starts with -: an empty value would count as "not set" (no -render, no
# -o, ...) and start a full measurement instead, and a value such as
# -render=F in -o -render=F is most likely the next option, taken as the
# value of an option whose value is missing.
need() {
	if [ -z "$2" ]; then
		echo "bench.sh: $1 needs a non-empty value" >&2
		exit 2
	fi
	case "$2" in
	-*)
		case "$1" in -count | -benchtime | -maxload) set -- "$1" "$2" "" ;; *) set -- "$1" "$2" " (write a path that starts with - as ./$2)" ;; esac
		echo "bench.sh: $1 needs a value that does not start with -, not '$2'$3" >&2
		exit 2
		;;
	esac
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
		sed -n '2,/^set -euo/p' <"$0" | sed '$d' | sed 's/^# \{0,1\}//'
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
# -benchtime is a count with x or a duration of Go (time.ParseDuration,
# one number and unit): go test refuses anything else only when its
# group starts, and the table puts the value in its commands.
btre='^([0-9]+x|[0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h))$'
if ! [[ "$benchtime" =~ $btre ]]; then
	echo "bench.sh: -benchtime needs a count such as 20x or a duration such as 1s or 1.5m, not '$benchtime'" >&2
	exit 2
fi
if [ "$renderset" = 1 ]; then
	if [ -n "$raw" ] || [ -n "$dir" ] || [ "$maxloadset" = 1 ] || [ "$short" = 1 ]; then
		echo "bench.sh: -render measures nothing; only -count, -benchtime and -o go with it" >&2
		exit 2
	fi
	abspath renderin "$renderin"
	if [ ! -f "$renderin" ] || [ ! -r "$renderin" ]; then
		echo "bench.sh: -render: cannot read $renderin" >&2
		exit 2
	fi
fi
# A relative TMPDIR is made absolute here, against the directory
# bench.sh is called from, as -dir: after the cd below, mktemp would
# take it from the root of the repository and go test (the benchmarks
# run in ./internal/bench) from its package directory.
if [ -n "$dir" ]; then
	abspath TMPDIR "$dir"
	export TMPDIR
elif [ -n "${TMPDIR:-}" ]; then
	abspath TMPDIR "$TMPDIR"
	export TMPDIR
fi
if [ -n "$out" ]; then abspath out "$out"; fi
if [ -n "$raw" ]; then abspath raw "$raw"; fi

# samefile is true if the paths $1 and $2 name the same file: the same
# device and inode if both exist, otherwise the same path once every
# symlink in it is resolved (realpath -m; a file need not exist). The x
# keeps a trailing line break of a path.
samefile() {
	local a b
	[ "$1" -ef "$2" ] && return 0
	a="$(realpath -m -- "$1" 2>/dev/null && echo x)" || a=""
	b="$(realpath -m -- "$2" 2>/dev/null && echo x)" || b=""
	if [ -z "$a" ] || [ -z "$b" ]; then a="$1" b="$2"; fi
	[ "$a" = "$b" ]
}
# -o is written last: as the -raw FILE it would replace the raw output
# by the table, as the -render FILE the input of the table.
if [ -n "$out" ] && [ -n "$raw" ] && samefile "$raw" "$out"; then
	echo "bench.sh: -raw and -o are the same file ($raw); nothing run" >&2
	exit 2
fi
if [ -n "$out" ] && [ "$renderset" = 1 ] && samefile "$renderin" "$out"; then
	echo "bench.sh: -render and -o are the same file ($renderin); nothing run" >&2
	exit 2
fi

# The values the table shows must not break it: a line break (LF or
# CR) ends the row, a | the cell and a backtick the code span of the
# command. Checked before anything runs (exit 2), for the variables of
# the env line of internal/bench (envNames in main_test.go: the table
# shows that line, and puts some of them in its commands, envof in
# render) and for the name of the -render file (in the "Erzeugt mit"
# line); what the raw output brings is checked by render (cell).
tablebad() {
	case "$1" in *$'\n'* | *$'\r'* | *'|'* | *'`'*) return 0 ;; esac
	return 1
}
for v in GOTOOLCHAIN GOMAXPROCS GOGC GOMEMLIMIT GODEBUG GOAMD64 GOARM64 \
	TMPDIR GOMAIL_BENCH_MIN_FREE GOMAIL_BENCH_SYNC_MAILS GOMAIL_BENCH_MEM_MAILS GOMAIL_BENCH_MEM_CONNS; do
	if tablebad "${!v:-}"; then
		echo "bench.sh: $v has a line break, a | or a backtick, which would break the table; nothing run" >&2
		exit 2
	fi
done
if [ "$renderset" = 1 ] && tablebad "$(basename -- "$renderin")"; then
	echo "bench.sh: the name of the -render file has a line break, a | or a backtick, which would break the table; nothing run" >&2
	exit 2
fi
# -raw must be writable before the first group: a missing directory, a
# directory or a file that cannot be written would only show after the
# whole run. The test opens FILE for appending (its content stays) and
# removes it again if it was not there.
if [ "$renderset" = 0 ] && [ -n "$raw" ]; then
	rawnew=0
	if [ ! -e "$raw" ] && [ ! -L "$raw" ]; then rawnew=1; fi
	if [ -d "$raw" ] || ! { : >>"$raw"; } 2>/dev/null; then
		echo "bench.sh: -raw: cannot write $raw (a directory, a missing directory or not writable); nothing run" >&2
		exit 2
	fi
	if [ "$rawnew" = 1 ]; then rm -f -- "$raw"; fi
fi

cd -- "$(dirname -- "$0")/.."

memtime=1x
if [ "$short" = 1 ]; then
	benchtime=20x
	export GOMAIL_BENCH_SYNC_MAILS="${GOMAIL_BENCH_SYNC_MAILS:-500}"
	export GOMAIL_BENCH_MEM_MAILS="${GOMAIL_BENCH_MEM_MAILS:-100}"
fi

# $work holds the raw output of the run (raw.txt). The EXIT trap
# removes it, except on the measurement path when the run did not end
# normally (an exit status other than 0, also from go test, or a signal
# such as INT, TERM or HUP, after which bash runs the trap with status
# 0 and finished still 0) and the raw output is neither empty (nothing
# ran yet) nor in -raw: then it writes bench-raw.txt (raw.txt without
# the group-benchtime lines, for -render) into $work, keeps $work and
# names it on stderr, after why (what went wrong, if bench.sh knows it).
work="$(mktemp -d)"
rawfile="$work/raw.txt"
why=""
rawsafe=0
finished=0
onexit() {
	local rc=$?
	if [ "$renderset" = 1 ] || [ "$rawsafe" = 1 ] || [ ! -s "$rawfile" ] || { [ "$rc" = 0 ] && [ "$finished" = 1 ]; }; then
		rm -rf -- "$work"
		return
	fi
	if [ -z "$why" ]; then
		if [ "$rc" = 0 ]; then why="the run was stopped"; else why="the run did not finish (exit $rc)"; fi
	fi
	if sed '/^group-benchtime: /d' <"$rawfile" >"$work/bench-raw.txt" 2>/dev/null; then
		echo "bench.sh: $why; the raw output of the run is in $work/bench-raw.txt" >&2
	else
		echo "bench.sh: $why; the raw output of the run is in $work/raw.txt (with group-benchtime lines)" >&2
	fi
}
trap onexit EXIT
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
	echo "group-start: $re $(groupmark)" | tee -a -- "$rawfile" >&2
	echo "bench.sh: go test -tags gomail_dev -run '^\$' -bench '$re' -benchtime=$bt -count=$count ./internal/bench" >&2
	go test -tags gomail_dev -run '^$' -bench "$re" -benchtime="$bt" -count="$count" -timeout 0 ./internal/bench | tee -a -- "$rawfile" >&2
	echo "group-end: $re $(groupmark)" | tee -a -- "$rawfile" >&2
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

# wantnames are the benchmarks of internal/bench by group, every one by
# its full name as b.Run makes it: receive_test.go (receiveModes, Sizes,
# receiveConns), sync_test.go, memory_test.go and index_test.go
# (indexKinds, BenchmarkIndexSegments); change them together. @SYNC@,
# @MEMMAILS@ and @MEMCONNS@ stand for the numbers internal/bench takes
# from GOMAIL_BENCH_SYNC_MAILS, GOMAIL_BENCH_MEM_MAILS and
# GOMAIL_BENCH_MEM_CONNS (10000, 1000 and 20 if empty or unset). render
# fails if one of them has no line in the raw output: a sub-benchmark
# that skips or fails before its first iteration prints nothing without
# -v, and grid sees that only through a sibling with the same name.
wantnames=(
	BenchmarkReceive/mode={enc,proto,plain}/size={4KiB,64KiB,1MiB,10MiB}/conns={1,4}
	BenchmarkSync/mails=@SYNC@/{index=off,index=on,list}
	BenchmarkServerMemory/size={64KiB,1MiB}/mails=@MEMMAILS@/conns=@MEMCONNS@
	BenchmarkIndex/pending={terms,unprocessed}
	BenchmarkIndexSegments/mails=1000
)

if [ "$renderset" = 1 ]; then
	# The raw output of -raw has no group-benchtime lines; they come
	# from groupbt, as in a run with the same -benchtime. One that FILE
	# has itself (raw.txt of a kept run) is written with a # in front:
	# no rule of render takes it, and it still counts as a line of FILE
	# for the line numbers of the messages.
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		group-benchtime:*) printf '#%s\n' "$line"; continue ;;
		group-start:*)
			re="${line#group-start: }"
			echo "group-benchtime: $(groupbt "${re%% *}")"
			;;
		esac
		printf '%s\n' "$line"
	done <"$renderin" >"$rawfile"
	commit="unbekannt (nur dargestellt mit -render aus $(basename -- "$renderin"), nicht gemessen)"
else
	for re in "${groups[@]}"; do
		run "$(groupbt "$re")" "$re"
	done
	commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	if [ -n "$(git status --porcelain -- . 2>/dev/null)" ]; then commit="$commit (mit lokalen Änderungen)"; fi
fi

# shq prints $1 quoted for a POSIX shell: bare if it is not empty and
# has only ASCII letters, digits and _./:=,+@%-, otherwise in single
# quotes, a quote in it written as quote, backslash, quote, quote (as
# shellQuote of internal/bench, which lists the special characters
# instead). The list is spelled out: a range such as a-z depends on the
# locale.
shq() {
	local q="'\\''"
	case "$1" in
	'' | *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=,+@%-]*) printf "'%s'" "${1//\'/$q}" ;;
	*) printf '%s' "$1" ;;
	esac
}

# envof <names...> prints "NAME=value " for every variable that is set
# and not empty, the value quoted by shq: the table puts it in front of
# go test, and the command must run as it is printed.
envof() {
	local p="" v
	for v in "$@"; do
		if [ -n "${!v:-}" ]; then p="$p$v=$(shq "${!v}") "; fi
	done
	printf '%s' "$p"
}

# render prints the table of $rawfile, or names what is missing on
# stderr and fails (fail closed: no table from incomplete data). Strings
# that come from outside (the environment, the name of the -render file)
# reach awk through ENVIRON, not -v: awk -v turns backslash sequences
# such as \n or \\ into other characters.
render() {
	BENCHSH_COMMIT="$commit" BENCHSH_WANT="${wantnames[*]}" BENCHSH_ENVALL="$(envof GOMAIL_BENCH_MIN_FREE TMPDIR)" \
		BENCHSH_ENVSYNC="$(envof GOMAIL_BENCH_SYNC_MAILS)" BENCHSH_ENVMEM="$(envof GOMAIL_BENCH_MEM_MAILS GOMAIL_BENCH_MEM_CONNS)" \
		awk -v date="$(date -u +%Y-%m-%dT%H:%MZ)" -v count="$count" -v render="$renderset" -v groups="${groups[*]}" '
	# envchk are the variables the table names in its commands (envof
	# above); with -render, every env line must carry the value of this
	# call. An env line (internal/bench configLines) names every variable
	# of the run that was set, also one set to empty (NAME= and two single
	# quotes), with its value in shell quoting (shellQuote: bare, or in
	# single quotes, a quote in the value written as quote, backslash,
	# quote, quote); envval unquotes it before the comparison. A variable
	# that is not in the env line has the value "". Empty and unset
	# compare equal: ENVIRON has "" for both, and internal/bench treats an
	# empty variable as unset.
	BEGIN {
		nchk = split("GOMAIL_BENCH_MIN_FREE GOMAIL_BENCH_SYNC_MAILS GOMAIL_BENCH_MEM_MAILS GOMAIL_BENCH_MEM_CONNS TMPDIR", envchk, " ")
		commit = ENVIRON["BENCHSH_COMMIT"]; minfree = ENVIRON["GOMAIL_BENCH_MIN_FREE"]
		envall = ENVIRON["BENCHSH_ENVALL"]; envsync = ENVIRON["BENCHSH_ENVSYNC"]; envmem = ENVIRON["BENCHSH_ENVMEM"]
	}
	# envnum returns the number internal/bench takes from variable name
	# (lookupEnvInt: def if empty or unset, else strconv.Atoi, which also
	# takes a sign and leading zeros). A value it refuses makes the group
	# fail before any benchmark line, so its number here does not matter.
	function envnum(name, def,   v) {
		v = ENVIRON[name]
		return v == "" ? def : sprintf("%d", v + 0)
	}
	# envval returns the unquoted value of variable name in env line rec
	# ("" if it is not there; the first one if it is there twice). It
	# reads rec as shell words: outside single quotes a blank ends a word
	# and a backslash takes the next character literally, inside them
	# every character up to the next quote is literal. An unterminated
	# quote or a trailing backslash is an error (fail).
	function envval(rec, name,   i, n, c, w, q, found, val) {
		sub(/^env: /, "", rec)
		n = length(rec); w = ""; q = 0; found = 0; val = ""
		for (i = 1; i <= n + 1; i++) {
			c = (i <= n) ? substr(rec, i, 1) : ""
			if (q) {
				if (c == "") fail("line " ln " (env) has an unterminated quote")
				if (c == "\047") q = 0; else w = w c
				continue
			}
			if (c == "" || c == " " || c == "\t") {
				if (w != "" && !found && index(w, name "=") == 1) { found = 1; val = substr(w, length(name) + 2) }
				w = ""
				continue
			}
			if (c == "\047") { q = 1; continue }
			if (c == "\\") {
				if (i == n) fail("line " ln " (env) ends with a backslash")
				i++; w = w substr(rec, i, 1)
				continue
			}
			w = w c
		}
		return val
	}
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
	# regex turns a benchmark name into an anchored -bench pattern. In the
	# class, ] comes first and [ last: [ followed by . = or : inside a
	# class starts a collating element or a class name for gawk, busybox
	# and others ([][.*...] is an error there and escapes nothing in
	# onetrue awk); the order here reads the same everywhere.
	function regex(name,   n, parts, i, p, r) {
		n = split(name, parts, "/")
		r = ""
		for (i = 1; i <= n; i++) {
			p = parts[i]
			gsub(/[].*+?(){}|^$\\[]/, "\\\\&", p)
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
	# grid fails if a sub-benchmark is missing that its siblings have. A
	# sub-benchmark that skips (b.Skip) or ends before its first
	# iteration prints nothing without -v, so the only trace of it is
	# that the same name is there under the other children of its
	# parent. The sub-benchmarks of every group form a grid: below a
	# benchmark, each child has the same sub-benchmarks (names split at
	# "/"; true for all five groups of internal/bench, BenchmarkReceive
	# for example has every size and connection count under every mode).
	# For every parent P, child c and suffix x of a leaf P/c/x, every
	# other child c2 of P must have the leaf P/c2/x.
	function grid(   j, k, n, parts, par, suf, key, p, c, x, sib) {
		for (j = 1; j <= nnames; j++) {
			n = split(names[j], parts, "/")
			par = parts[1]
			for (k = 2; k <= n; k++) {
				suf = ""
				for (p = k + 1; p <= n; p++) suf = suf (p > k + 1 ? "/" : "") parts[p]
				key = gof[names[j]] SUBSEP par
				if (!((key, parts[k]) in gchild)) { gchild[key, parts[k]] = 1; gnc[key]++; gc[key, gnc[key]] = parts[k] }
				if (!((key, suf) in gsuf)) { gsuf[key, suf] = parts[k]; gns[key]++; gs[key, gns[key]] = suf }
				gleaf[key, parts[k], suf] = 1
				if (!(key in gpar)) { gpar[key] = par; gkeys[++ngkeys] = key }
				par = par "/" parts[k]
			}
		}
		for (j = 1; j <= ngkeys; j++) {
			key = gkeys[j]
			for (c = 1; c <= gnc[key]; c++) for (x = 1; x <= gns[key]; x++) {
				if ((key, gc[key, c], gs[key, x]) in gleaf) continue
				sib = gsuf[key, gs[key, x]]
				fail(gpar[key] "/" gc[key, c] (gs[key, x] != "" ? "/" gs[key, x] : "") " is missing, " gpar[key] "/" sib (gs[key, x] != "" ? "/" gs[key, x] : "") " is there")
			}
		}
	}
	# fail names what is wrong with the raw output and ends awk with 1;
	# END then prints nothing.
	function fail(msg) {
		print "bench.sh: no table: " msg > "/dev/stderr"
		failed = 1
		exit 1
	}
	# cell returns v, a value of line ln that the table shows; it fails
	# if v has a | (ends the cell), a backtick (ends the code span) or a
	# carriage return (a line break in Markdown; a raw file with CRLF).
	function cell(v, what) {
		if (index(v, "|") || index(v, "`") || index(v, "\r")) fail("line " ln " (" what ") has a |, a backtick or a carriage return, which would break the table")
		return v
	}
	# bench.sh writes the group-benchtime lines itself (run, or the loop
	# of -render); they are not lines of the raw output the user has
	# (-raw, bench-raw.txt or the -render FILE): ln, the line number
	# every message names, does not count them.
	/^group-benchtime: / { bt = $2; nbt++; next }
	{ ln = NR - nbt }
	# A failed or skipped sub-benchmark is reported indented (4 blanks a
	# level).
	/^(FAIL|panic: )/ || /^[ \t]*--- (FAIL|SKIP)/ { fail("line " ln " reports a failure or a skip: " $0) }
	/^group-start: / {
		if (open) fail("group " gname[ng] " has no group-end")
		ng++; open = 1; gname[ng] = $2; gstart[ng] = cell($3, "group-start"); gload[ng] = cell(field($0, "loadavg"), "group-start"); gcpu0[ng] = field($0, "cpu"); next
	}
	/^group-end: / {
		if (!open || $2 != gname[ng]) fail("group-end of " $2 " in line " ln " without its group-start")
		open = 0; gend[ng] = cell($3, "group-end"); gloadend[ng] = cell(field($0, "loadavg"), "group-end"); gcpu1[ng] = field($0, "cpu"); next
	}
	# With -render, every group has exactly one command and one env line,
	# and they must match -benchtime, -count and the variables of envchk of
	# this call: the table names them in every command.
	render && /^(command|env): / {
		if (!open) fail("line " ln " (" $1 ") outside a group")
		if ((ng, $1) in hdr) fail("group " gname[ng] " has a second " $1 " line in line " ln)
		hdr[ng, $1] = 1
	}
	render && /^command: / && (index($0 " ", " -benchtime=" bt " ") == 0 || index($0 " ", " -count=" count " ") == 0) {
		fail("line " ln " (" $0 ") does not match -benchtime " bt " and -count " count " of this call")
	}
	render && /^env: / {
		for (ci = 1; ci <= nchk; ci++) if (envval($0, envchk[ci]) != ENVIRON[envchk[ci]]) fail("line " ln " (" $0 ") does not match " envchk[ci] "=" ENVIRON[envchk[ci]] " of this call")
	}
	/^[a-z]+: / {
		k = $1; sub(/:$/, "", k)
		v = $0; sub(/^[a-z]+: /, "", v)
		if (k == "command" || k == "pkg") next
		if (!(k in cfg)) { cfg[k] = cell(v, k); order[++ncfg] = k }
		next
	}
	/^Benchmark/ {
		if (!open) fail("benchmark line " ln " outside a group: " $1)
		if (NF < 4 || NF % 2 || $2 !~ /^[0-9]+$/) fail("benchmark line " ln " is not name, iterations and value-unit pairs: " $0)
		# 0 iterations: the benchmark did not run in this repetition (a
		# b.Skip after the first one leaves such a line, NaN ns/op).
		if ($2 !~ /^[1-9]/) fail("benchmark line " ln " reports 0 iterations: " $0)
		gnb[ng]++
		name = $1; sub(/-[0-9]+$/, "", name)
		top = name; sub(/\/.*/, "", top)
		if ("^" top "$" != gname[ng]) fail("benchmark line " ln " (" name ") is in group " gname[ng])
		if (!(name in seen)) { seen[name] = 1; names[++nnames] = cell(name, "benchmark name"); btof[name] = bt; gof[name] = ng }
		nlines[name]++
		for (i = 3; i + 1 <= NF; i += 2) {
			if ($i !~ /^-?[0-9]+([.][0-9]+)?$/) fail("benchmark line " ln ": value " $i " is not a number")
			unit = $(i + 1)
			if (!keep(unit)) continue
			key = name SUBSEP unit
			if (!(key in sum)) { nu[name]++; units[name, nu[name]] = cell(unit, "unit") }
			# + 0: the value is a number in every awk; busybox awk
			# compares a field kept as it is like a string (num and
			# median below: 5.66 >= 100).
			vals[key, ++cnt[key]] = $i + 0; sum[key] += $i
		}
	}
	END {
		if (failed) exit 1
		if (open) fail("group " gname[ng] " has no group-end")
		n = split(groups, want, " ")
		if (ng != n) fail(ng + 0 " groups in the raw output, " n " expected (" groups ")")
		for (i = 1; i <= n; i++) {
			if (gname[i] != want[i]) fail("group " i " is " gname[i] ", expected " want[i])
			if (gnb[i] < 1) fail("group " gname[i] " has no benchmark line")
			if (render && !((i, "command:") in hdr && (i, "env:") in hdr)) fail("group " gname[i] " has no command or no env line")
		}
		for (j = 1; j <= nnames; j++) {
			s = names[j]
			if (nlines[s] != count + 0) fail(s ": " nlines[s] " lines, -count " count " expected")
		}
		# Every name of wantnames, its numbers filled in, must be there.
		nw = split(ENVIRON["BENCHSH_WANT"], wn, " ")
		for (j = 1; j <= nw; j++) {
			s = wn[j]
			gsub(/@SYNC@/, envnum("GOMAIL_BENCH_SYNC_MAILS", 10000), s)
			gsub(/@MEMMAILS@/, envnum("GOMAIL_BENCH_MEM_MAILS", 1000), s)
			gsub(/@MEMCONNS@/, envnum("GOMAIL_BENCH_MEM_CONNS", 20), s)
			if (!(s in seen)) fail(s " is missing: no line in the raw output (wantnames)")
		}
		grid()
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
	}' <"$rawfile"
}

# The raw output of a measurement goes to -raw before render, so that a
# table that fails does not lose the run (fail closed: no table if the
# file cannot be written; the EXIT trap then keeps the raw output in
# $work). The file has no group-benchtime lines.
if [ "$renderset" = 0 ] && [ -n "$raw" ]; then
	if sed '/^group-benchtime: /d' <"$rawfile" >"$raw"; then
		rawsafe=1
	else
		why="cannot write the raw output to $raw; no table written"
		exit 1
	fi
fi
if ! table="$(render)"; then
	if [ "$renderset" = 1 ]; then
		echo "bench.sh: no table written" >&2
	elif [ -n "$raw" ]; then
		echo "bench.sh: no table written; the raw output of the run is in $raw" >&2
	else
		# Without -raw, the EXIT trap keeps the raw output in $work.
		why="no table written"
	fi
	exit 1
fi
printf '%s\n' "$table"
if [ -n "$out" ]; then printf '%s\n' "$table" >"$out"; fi
finished=1
