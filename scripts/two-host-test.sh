#!/bin/sh
# two-host-test.sh: test of two machines per docs/PLAN.md 9.1 (task 16).
#
# Two-host mode (the acceptance test of 9.1, 10.2):
#
#   scripts/two-host-test.sh --server-host srv --client-host cli \
#       --export /srv/gomail --mount /mnt/gomail [--pin FILE] [--witness FILE] \
#       [--bin DIR] [--workdir DIR] [--out DIR] [--keep]
#
# The server host exports --export over NFSv4, the client host has it
# mounted at --mount. Both are reached over SSH (BatchMode, keys, a POSIX
# login shell) as two different OS users, both members of the group
# gomail. The script runs on a third machine or on either host. --pin
# and --witness say where the pin (client host) and the witness key
# (server host) from the development ceremony of step b are placed: they
# must not exist yet, their directories must (task 16b finding 3).
# TODO(task-15b): pin and witness of a real ceremony.
#
# Production path (task 15h, docs/RUNBOOK.md "Erstinstallation"): a
# build without the tag gomail_dev has no "gomail-ceremony init --dev".
# There the real ceremony runs offline, "gomail-server init --data <dir>
# --pin <pin> [--witnesses <export>/platform/witnesses.rec]" creates the
# empty data directory (rights 2770, platform/witnesses.rec from the
# pin, nothing else), "gomail-ceremony publish --from <export> --data
# <dir> --pin <pin>" writes the certificates into it and its log, and
# the server starts with that pin. This script keeps the development
# ceremony of the test build for step b (internal/e2e
# TestInitProduction runs the production path).
#
# Local mode (no NFS, no second machine, no root, no second user):
#
#   scripts/two-host-test.sh --local [--bin DIR] [--out DIR]
#
# Steps (each aborts the run on failure, set -eu):
#   a  prerequisites: tools, programs, users, group gomail, umask, NFSv4
#      mount with vers=4 and local_lock=none, export and mount show the
#      same directory
#   b  data directory on the server host (development ceremony), rights
#      2770/0660 (and group gomail in two-host mode)
#   c  lock test (9.1 "Testsperre", D70): a client without a server
#      refuses; a server with --require-client-lock without a client
#      refuses; the server holds locks/server and the client sees it over
#      the mount; a second server on the client host refuses; a client on
#      the client host holds locks/client while a server with
#      --require-client-lock starts and sees it
#   d  end to end: the witness, keygen, invite, register, mailbox,
#      address, mail over SMTP to the server, sync/list/read on the
#      client host, a second user on the client host who reads the
#      mailbox only after "gomailctl mailbox share", a log head cosigned
#      by the witness
#   e  evidence on the export: no private keys (0600 files, key files,
#      key stores), no plaintext (subject and body token), rights of
#      every file and directory
#   f  protocol as Markdown with every command and its output under --out
#
# What the local mode proves, and what it does not: server and client run
# as one OS user on one kernel, on one local file system; the "mount" is a
# symbolic link to the "export". It proves that the programs, the start
# checks of both sides, the rights 2770/0660, the absence of private keys
# and plaintext in the data directory and the end-to-end flow work as the
# two-host mode runs them, and that the record locks conflict between
# separate processes. It proves nothing of 9.1: neither that NFSv4
# enforces the locks between two machines (the server on one kernel, the
# client on another), nor that two OS users of the group gomail can work
# on the same files, nor that the key store stays on the client machine
# and the ingest key on the server machine. Only the two-host mode with an
# NFSv4 mount shows that.
#
# Files (task 16b): on each host the script makes exactly one directory
# of its own, mktemp -d <workdir>/two-host.XXXXXX, and works in it; it
# deletes only what it made itself (that directory, the data directory,
# the files at --pin and --witness, a --workdir, --export or --mount it
# had to create), never anything that was there before. Seed words and
# decrypted mail never reach a file: keygen reads the words from a FIFO
# into the memory of the shell, list and read are checked in a pipe.
# Every shell that makes temporary files ends through its EXIT trap on
# SIGINT, SIGTERM and SIGHUP, and the script stops every process it
# started (exit status 130).
#
# Output names IDs and paths only: addresses, subject, body and the
# passphrase are replaced by placeholders in the protocol; mail content
# and seed words never reach it.
#
# Environment (task 16c): the script reads PATH, TMPDIR,
# GOMAIL_TEST_MIN_FREE and what ssh needs, nothing else. It sets two
# switches of a test build itself (task 14): GOMAIL_TEST_DEV_IDENTITY=1
# for gomailctl, which accepts the pin of the development ceremony only
# with it, and GOMAIL_TEST_HEAD_GAP=1s for gomail-server, so that a head
# covering the new entries is signed within seconds, not a minute. Every variable
# of its own starts empty or 0 before the EXIT trap is set, and the
# clean-up deletes only paths this run made itself (its flags, checked
# against the paths it derives). Subject, body token and passphrase
# never appear in a command line (/proc/*/cmdline): they reach the
# commands through the environment, on the hosts through the standard
# input of the remote shell. The addresses are arguments of curl and of
# "gomail-server address add" (their interface).
#
# gomailctl appends its records to the transparency log itself and works
# only with a head cosigned by the witness (task 14): the witness starts
# at the beginning of step d, and every client command that needs a head
# covering the newest entries is repeated until one is published (at
# most a minute). The programs must be a test build (go build -tags
# gomail_test): the development ceremony gives a development pin, which
# a production gomailctl refuses. --log-helper of task 16 is gone (a
# usage error).
# Step d registers a second user, checks that it cannot read the mailbox,
# shares the mailbox with it from epoch 1 ("gomailctl mailbox share",
# task 13) and checks that it reads the mail then.

set -eu

# Every variable of this script starts here, empty or 0 (task 16c
# finding 1): no value comes from the environment, and unset drops the
# export flag, so none reaches the programs either. GOMAILCTL_PASSPHRASE
# would take precedence over --passphrase-file; CDPATH, ENV and BASH_ENV
# change cd and the shells started.
unset GOMAILCTL_PASSPHRASE GOMAILCTL_TEST_KEYGEN_PIPE GOMAIL_E2E_HELPER CDPATH ENV BASH_ENV \
	LOCAL KEEP GROUP SERVER_HOST CLIENT_HOST EXPORT MOUNT PIN WITNESS OUT BIN WORKDIR \
	RUNID SUBJECT BODY ADDR FROM PASSPHRASE RCM P T TBASE T_OURS STATUS STEP MODE WARN PROTO RC XRUN \
	SRV CER WIT CTL CTLE ENV_SRV REDACT PIDS TOOLS RW SW CW RW_OURS SW_OURS CW_OURS \
	SDATA CDATA KEYS SPIN INGEST ADMIN CPIN WKEY PASS ALICE BOB ROOT BUILD \
	SID SHOST SUMASK CID CHOST CUMASK GCHECK SGID CGID MOUNTS MLINE FSTYPE MOPTS MARK MARKF MKWORK \
	DATA_OURS WKEY_OURS PIN_OURS PASS_OURS MARK_OURS MADE_LINK MADE_EXPORT MADE_WORKDIR MADE_SWORKDIR MADE_CWORKDIR \
	RIGHTS C_ARGS SERVE SMTP LOG KEYGEN INV_A INV_B UID_A UID_B MBX MAILID VKEY ORIGIN WNAME HEADF \
	rc why a b e f m n p w
IFS=$(printf ' \t\nx')
IFS=${IFS%x}
LOCAL=0 KEEP=0 GROUP=gomail
SERVER_HOST='' CLIENT_HOST='' EXPORT='' MOUNT='' PIN='' WITNESS='' OUT='' BIN='' WORKDIR=''
RUNID='' SUBJECT='' BODY='' ADDR='' FROM='' PASSPHRASE='' RCM='' P='' T='' TBASE='' T_OURS=0
STATUS=abgebrochen STEP=Start MODE='' WARN='' PROTO=0 RC=0 XRUN=run_on
SRV='' CER='' WIT='' CTL='' CTLE='' ENV_SRV='' REDACT='' PIDS='' TOOLS=''
RW='' SW='' CW='' RW_OURS=0 SW_OURS=0 CW_OURS=0
SDATA='' CDATA='' KEYS='' SPIN='' INGEST='' ADMIN='' CPIN='' WKEY='' PASS='' ALICE='' BOB='' ROOT='' BUILD=''
SID='' SHOST='' SUMASK='' CID='' CHOST='' CUMASK='' GCHECK='' SGID='' CGID='' MOUNTS='' MLINE='' FSTYPE='' MOPTS=''
MARK='' MARKF='' MKWORK=''
DATA_OURS=0 WKEY_OURS=0 PIN_OURS=0 PASS_OURS=0 MARK_OURS=0
MADE_LINK=0 MADE_EXPORT=0 MADE_WORKDIR=0 MADE_SWORKDIR=0 MADE_CWORKDIR=0
RIGHTS='' C_ARGS='' SERVE='' SMTP='' LOG='' KEYGEN='' INV_A='' INV_B='' UID_A='' UID_B='' MBX='' MAILID=''
VKEY='' ORIGIN='' WNAME='' HEADF=''
rc=0 why='' a='' b='' e='' f='' m='' n='' p='' w=''

usage() {
	cat <<'EOF'
Aufruf:
  two-host-test.sh --server-host <ssh-ziel> --client-host <ssh-ziel>
                   --export <dir> --mount <dir>
                   [--pin <datei>] [--witness <datei>] [--bin <dir>]
                   [--workdir <dir>] [--out <dir>] [--group gomail] [--keep]
  two-host-test.sh --local [--bin <dir>]
                   [--workdir <dir>] [--out <dir>] [--keep]

  --server-host, --client-host  SSH-Ziele (Server-Host exportiert, Client-Host mountet)
  --export   NFS-Export auf dem Server-Host (darin entsteht das Datenverzeichnis)
  --mount    Mountpunkt des Exports auf dem Client-Host (NFSv4)
  --pin      Ablageort des Pins auf dem Client-Host (Standard: im eigenen Verzeichnis)
  --witness  Ablageort des Zeugenschlüssels auf dem Server-Host (Standard: im eigenen
             Verzeichnis); beide dürfen noch nicht existieren, ihr Verzeichnis muss es;
             das Skript schreibt sie (0600) und löscht sie am Ende (außer mit --keep)
  --bin      Verzeichnis der Programme auf beiden Hosts, Testbuild (-tags gomail_test: keygen über
             FIFOs) (Standard: PATH; lokal: wird gebaut), gebaut mit -tags gomail_dev,gomail_test
             (gomail-ceremony init --dev)
  --workdir  darunter legt das Skript auf jedem Host sein eigenes Verzeichnis two-host.XXXXXX
             an, außerhalb von Export und Mount (Standard /tmp, lokal $TMPDIR oder /tmp)
  --out      Verzeichnis für das Protokoll (protokoll.md, darf noch nicht existieren)
  --keep     eigene Verzeichnisse, Datenverzeichnis, Pin und Zeugenschlüssel nicht löschen
  --local    alles auf dieser Maschine, ohne NFS (kein Nachweis nach 9.1)

Exit: 0 bestanden, 1 abgebrochen, 2 Aufruffehler, 130 Abbruch durch Signal
EOF
}

# die reports an invocation error (exit status 2), also one the script
# finds only on a host (an existing --pin, a missing --workdir parent).
die() {
	printf 'two-host-test: %s\n' "$*" >&2
	[ "$PROTO" = 0 ] || md "" "**Aufruffehler:** $*"
	exit 2
}

while [ $# -gt 0 ]; do
	case $1 in
	--local) LOCAL=1 ;;
	--keep) KEEP=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	--log-helper)
		die "--log-helper entfällt seit Auftrag 14: gomailctl trägt seine Einträge selbst ins Log ein"
		;;
	--server-host | --client-host | --export | --mount | --pin | --witness | --out | --bin | --workdir | --group)
		[ $# -ge 2 ] || die "$1 braucht einen Wert"
		case $1 in
		--server-host) SERVER_HOST=$2 ;;
		--client-host) CLIENT_HOST=$2 ;;
		--export) EXPORT=$2 ;;
		--mount) MOUNT=$2 ;;
		--pin) PIN=$2 ;;
		--witness) WITNESS=$2 ;;
		--out) OUT=$2 ;;
		--bin) BIN=$2 ;;
		--workdir) WORKDIR=$2 ;;
		--group) GROUP=$2 ;;
		esac
		shift
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
	shift
done

# rand prints n random bytes as hex.
rand() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

RUNID=$(date -u +%Y%m%dT%H%M%SZ)-$(rand 3)
abs() { case $1 in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$(pwd)" "$1" ;; esac; }

if [ "$LOCAL" = 1 ]; then
	[ -z "$SERVER_HOST$CLIENT_HOST" ] || die "--local und --server-host/--client-host schließen sich aus"
	# Commands run in the work directories: relative paths would break.
	WORKDIR=$(abs "${WORKDIR:-${TMPDIR:-/tmp}}")
	[ -z "$EXPORT" ] || EXPORT=$(abs "$EXPORT")
	[ -z "$MOUNT" ] || MOUNT=$(abs "$MOUNT")
	[ -z "$PIN" ] || PIN=$(abs "$PIN")
	[ -z "$WITNESS" ] || WITNESS=$(abs "$WITNESS")
	[ -z "$BIN" ] || BIN=$(abs "$BIN")
else
	[ -n "$SERVER_HOST" ] && [ -n "$CLIENT_HOST" ] && [ -n "$EXPORT" ] && [ -n "$MOUNT" ] ||
		die "--server-host, --client-host, --export und --mount sind erforderlich (oder --local)"
	WORKDIR=${WORKDIR:-/tmp}
	for p in "$EXPORT" "$MOUNT" "$WORKDIR" ${PIN:+"$PIN"} ${WITNESS:+"$WITNESS"}; do
		case $p in /*) ;; *) die "Pfade auf den Hosts müssen absolut sein: $p" ;; esac
	done
fi
OUT=$(abs "${OUT:-two-host-out.$RUNID}")
[ "$WORKDIR" != / ] || die "--workdir darf nicht / sein"

# Secrets and plaintext of this run: they must appear neither in the
# export nor in the protocol.
SUBJECT=Nordlicht-$(rand 8)
BODY=Kennwort-$(rand 8)
ADDR=empfang-$(rand 4)@brownbear.example
FROM=rechnung@lieferant.example
PASSPHRASE=geheim-$(rand 16)
# RCM marks the exit status of a program inside a pipe (list, read).
RCM=exit-$(rand 6)

mkdir -p "$OUT"
P=$OUT/protokoll.md
(set -C && : >"$P") 2>/dev/null || die "Protokoll $P existiert schon (anderes --out wählen)"
TBASE=${TMPDIR:-/tmp}
T=$(mktemp -d "$TBASE/two-host-test.XXXXXX")
T_OURS=1
: >"$T/results"

# q quotes a word for sh.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

prog() { printf '%s' "${BIN:+$BIN/}$1"; }
progs() {
	SRV=$(q "$(prog gomail-server)")
	CER=$(q "$(prog gomail-ceremony)")
	WIT=$(q "$(prog gomail-witness)")
	CTL=$(q "$(prog gomailctl)")
	# The client of a test build accepts the development pin only with
	# GOMAIL_TEST_DEV_IDENTITY=1 (task 14).
	CTLE="env GOMAIL_TEST_DEV_IDENTITY=1 $CTL"
}
progs
# Read only by a test build (-tags gomail_test): a head at most every
# second while the log grows (task 14), and the free space (task 15c
# finding 7).
ENV_SRV="env GOMAIL_TEST_HEAD_GAP=1s "
if [ -n "${GOMAIL_TEST_MIN_FREE:-}" ]; then
	ENV_SRV="env GOMAIL_TEST_HEAD_GAP=1s GOMAIL_TEST_MIN_FREE=$(q "$GOMAIL_TEST_MIN_FREE") "
fi

# redact replaces subject, body token, addresses and passphrase by
# placeholders. The values reach awk through its environment, never
# through its arguments (task 16c finding 8), and are replaced as
# literal strings.
REDACT='function rep(s, f, r,   o, i) {
	if (f == "") return s
	o = ""
	while ((i = index(s, f)) > 0) { o = o substr(s, 1, i - 1) r; s = substr(s, i + length(f)) }
	return o s
}
{
	l = rep($0, ENVIRON["GM_R1"], "<Betreff>"); l = rep(l, ENVIRON["GM_R2"], "<Text>")
	l = rep(l, ENVIRON["GM_R3"], "<Adresse>"); l = rep(l, ENVIRON["GM_R4"], "<Absender>")
	print rep(l, ENVIRON["GM_R5"], "<Passphrase>")
}'
redact() {
	GM_R1=$SUBJECT GM_R2=$BODY GM_R3=$ADDR GM_R4=$FROM GM_R5=$PASSPHRASE LC_ALL=C awk "$REDACT"
}

md() { printf '%s\n' "$@" | redact >>"$P"; }
PROTO=1
say() {
	printf '%s\n' "$*"
	md "$*"
}
step() {
	STEP=$1
	printf '\n== %s\n' "$1"
	md "" "## $1" ""
}
ok() {
	printf '   ok: %s\n' "$*"
	printf -- '- [x] %s\n' "$*" >>"$T/results"
	md "" "**ok:** $*"
}
fail() {
	printf 'FEHLER in %s: %s\n' "$STEP" "$*" | redact >&2
	md "" "**FEHLER:** $*"
	exit 1
}

# run_on SIDE CMD runs CMD with sh on the server or client host; standard
# input passes through.
run_on() {
	if [ "$LOCAL" = 1 ]; then
		sh -c "$2"
	else
		case $1 in
		server) ssh -o BatchMode=yes -- "$SERVER_HOST" "sh -c $(q "$2")" ;;
		client) ssh -o BatchMode=yes -- "$CLIENT_HOST" "sh -c $(q "$2")" ;;
		esac
	fi
}

# run_sec SIDE CMD is run_on with the subject and the body token of this
# run in the variables GM_S and GM_B of the shell that runs CMD, never in
# a command line (task 16c finding 8): locally in its environment, on a
# host through the standard input of the remote shell, which reads them
# and then gets /dev/null.
run_sec() {
	if [ "$LOCAL" = 1 ]; then
		GM_S=$SUBJECT GM_B=$BODY sh -c "$2" </dev/null
	else
		printf '%s\n%s\n' "$SUBJECT" "$BODY" | run_on "$1" "IFS= read -r GM_S && IFS= read -r GM_B && export GM_S GM_B || exit 1
exec </dev/null
$2"
	fi
}

# x SIDE CMD [DISPLAY] runs CMD, records DISPLAY (default CMD) and the
# output in the protocol and sets RC; standard output is in $T/out,
# standard error in $T/err. Commands print IDs, paths and check results
# only, never seed words or mail text.
x() {
	RC=0
	$XRUN "$1" "$2" </dev/null >"$T/out" 2>"$T/err" || RC=$?
	{
		printf '\n```console\n%s$ %s\n' "$1" "${3:-$2}"
		cat "$T/out" "$T/err"
		printf '(Exit %s)\n```\n' "$RC"
	} | redact >>"$P"
}

# must SIDE CMD [DISPLAY] is x that stops the run on an exit status other
# than 0.
must() {
	x "$@"
	[ "$RC" -eq 0 ] || fail "Exit $RC: ${3:-$2}"
}

# must_sec SIDE CMD [DISPLAY] is must with GM_S and GM_B (run_sec).
must_sec() {
	XRUN=run_sec
	must "$@"
	XRUN=run_on
}

# refuse SIDE CMD PATTERN [DISPLAY] runs a program that must refuse to
# start: exit status 1 within 30 s and PATTERN in its output. A program
# that keeps running is stopped and fails the run.
refuse() {
	x "$1" "( $2 ) 2>&1 &
p=\$!; i=0
while kill -0 \$p 2>/dev/null; do
	if [ \$i -ge 300 ]; then kill \$p; wait \$p; echo 'LÄUFT NOCH'; exit 99; fi
	sleep 0.1; i=\$((i + 1))
done
wait \$p" "${4:-$2}"
	[ "$RC" -eq 1 ] || fail "erwartet: Verweigerung mit Exit 1, erhalten: Exit $RC"
	grep -q -- "$3" "$T/out" || fail "erwartet: Meldung mit \"$3\""
}

# free SIDE PATH OPTION checks that the file at PATH (the target of --pin
# or --witness) does not exist yet and that its directory does; anything
# else is an invocation error. The script never overwrites or deletes a
# file it did not write.
free() {
	x "$1" "if [ -e $(q "$2") ] || [ -L $(q "$2") ]; then echo 'existiert schon'; exit 3; fi
[ -d $(q "$(dirname "$2")") ] || { echo 'Verzeichnis fehlt'; exit 3; }
echo 'frei'"
	[ "$RC" -ne 3 ] || die "$3 $2 auf dem $1-Host: $(cat "$T/out"). $3 ist ein Ablageort, der noch nicht existieren darf (sein Verzeichnis muss existieren); vorhandene Dateien überschreibt und löscht das Skript nicht"
	[ "$RC" -eq 0 ] || fail "Exit $RC: Prüfung von $3"
}

# copy SIDE PATH SIDE PATH FLAG copies a file between the hosts and
# compares the checksums. The target must not exist (set -C), is written
# with mode 0600, and FLAG=1 marks it as written by this run (cleanup
# deletes it); a target that exists is never touched.
copy() {
	eval "$5=1"
	rc=0
	run_on "$1" "cat $(q "$2")" </dev/null |
		run_on "$3" "umask 077; set -C; true 2>/dev/null >$(q "$4") || { echo 'existiert schon'; exit 3; }; chmod 600 $(q "$4") && cat >>$(q "$4")" || rc=$?
	if [ "$rc" -eq 3 ]; then
		eval "$5=0"
		die "Ziel $4 auf dem $3-Host existiert schon; das Skript überschreibt keine vorhandenen Dateien"
	fi
	[ "$rc" -eq 0 ] || fail "Kopie $2 -> $4: Exit $rc"
	a=$(run_on "$1" "cksum <$(q "$2")" </dev/null)
	b=$(run_on "$3" "cksum <$(q "$4")" </dev/null)
	[ "$a" = "$b" ] || fail "Kopie $2 -> $4 unvollständig"
	md "" "Kopiert: $1:$2 -> $3:$4 (0600, cksum $a)"
}

# bg PIDFILE LOGFILE SCRIPT is a command line that runs SCRIPT in the
# background; the background shell writes its own process ID to PIDFILE
# before SCRIPT starts (SCRIPT ends with exec), so cleanup finds every
# process the run started, also when a signal arrives right after the
# start (task 16b finding 4).
bg() {
	printf 'sh -c %s >%s 2>&1 </dev/null &' "$(q "echo \$\$ >$(q "$1") || exit 1
$3")" "$(q "$2")"
}

# waitpid PIDFILE... is a command that waits until the background shells
# have written their process IDs.
waitpid() {
	printf 'i=0; for f in'
	for f; do printf ' %s' "$(q "$f")"; done
	printf '; do until [ -s "$f" ]; do [ $i -lt 100 ] || { echo "keine PID in $f"; exit 1; }; sleep 0.1; i=$((i + 1)); done; done'
}

# ownwork DIR is true for a directory this run made with mktemp under
# --workdir: exactly <workdir>/two-host.XXXXXX (task 16c finding 1).
ownwork() {
	case $1 in
	"$WORKDIR"/two-host.*/*) return 1 ;;
	"$WORKDIR"/two-host.??????) return 0 ;;
	esac
	return 1
}

# below DIR PATH is true when DIR is not empty and PATH lies below it.
below() {
	[ -n "$1" ] || return 1
	case $2 in "$1"/?*) return 0 ;; esac
	return 1
}

# ownfile FILE is true when FILE lies in an own directory of this run:
# RW in local mode, SW (server host) or CW (client host) on two hosts.
ownfile() {
	if [ "$LOCAL" = 1 ]; then
		[ "$RW_OURS" = 1 ] && ownwork "$RW" && below "$RW" "$1"
	else
		{ [ "$SW_OURS" = 1 ] && ownwork "$SW" && below "$SW" "$1"; } ||
			{ [ "$CW_OURS" = 1 ] && ownwork "$CW" && below "$CW" "$1"; }
	fi
}

# PIDS lists side:pidfile of background processes, added before the
# start. cleanup deletes nothing but what this run made itself: each
# path needs the flag the script set when it made it (*_OURS, MADE_*)
# and must be the path the script derives for it (task 16b finding 2, 3;
# task 16c finding 1).
cleanup() {
	rc=$?
	set +e
	trap - EXIT
	# Nothing interrupts the clean-up: it stops processes and deletes
	# keys and data of this run.
	trap '' INT TERM HUP
	for e in $PIDS; do
		ownfile "${e#*:}" || continue
		run_on "${e%%:*}" "p=\$(cat $(q "${e#*:}") 2>/dev/null) || exit 0
[ -n \"\$p\" ] || exit 0
kill \$p 2>/dev/null || exit 0
i=0; while kill -0 \$p 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done
! kill -0 \$p 2>/dev/null || kill -KILL \$p 2>/dev/null; true" </dev/null >/dev/null 2>&1
	done
	if [ "$MARK_OURS" = 1 ] && [ -n "$EXPORT" ] && [ "$MARKF" = "$EXPORT/.two-host-$RUNID" ]; then
		run_on server "rm -f $(q "$MARKF")" </dev/null >/dev/null 2>&1
	fi
	# The passphrase file goes also with --keep (task 16c finding 6).
	if [ "$PASS_OURS" = 1 ] && ownfile "$PASS" && [ "$PASS" = "$CW/passphrase" ]; then
		run_on client "rm -f $(q "$PASS")" </dev/null
	fi
	if [ "$rc" -eq 0 ] && [ "$STATUS" = bestanden ]; then
		md "" "## Ergebnis" "" "**bestanden** ($MODE)" ""
	else
		STATUS=abgebrochen
		why="in Schritt \"$STEP\""
		[ "$rc" -ne 2 ] || why="$why (Aufruffehler)"
		[ "$rc" -ne 130 ] || why="$why durch ein Signal"
		md "" "## Ergebnis" "" "**abgebrochen** $why (Exit $rc)" ""
		[ "$rc" -ne 0 ] || rc=1
	fi
	cat "$T/results" >>"$P"
	if [ "$KEEP" = 1 ]; then
		md "" "Behalten (--keep): $SW und $SDATA (Server-Host), $CW (Client-Host), Pin $CPIN, Zeugenschlüssel $WKEY; gelöscht: Passphrase-Datei"
	else
		if [ "$DATA_OURS" = 1 ] && [ -n "$EXPORT" ] && [ "$SDATA" = "$EXPORT/gomail-$RUNID" ]; then
			run_on server "rm -rf $(q "$SDATA")" </dev/null
		fi
		if [ "$WKEY_OURS" = 1 ] && [ -n "$WKEY" ] && { [ "$WKEY" = "$WITNESS" ] || { ownfile "$WKEY" && [ "$WKEY" = "$SW/witness/witness.key" ]; }; }; then
			run_on server "rm -f $(q "$WKEY")" </dev/null
		fi
		if [ "$PIN_OURS" = 1 ] && [ -n "$CPIN" ] && { [ "$CPIN" = "$PIN" ] || { ownfile "$CPIN" && [ "$CPIN" = "$CW/identity-1.pin" ]; }; }; then
			run_on client "rm -f $(q "$CPIN")" </dev/null
		fi
		if [ "$LOCAL" = 1 ]; then
			if [ "$RW_OURS" = 1 ] && ownwork "$RW"; then rm -rf "$RW"; fi
			if [ "$MADE_LINK" = 1 ] && [ -L "$MOUNT" ]; then rm -f "$MOUNT"; fi
			[ "$MADE_EXPORT" = 0 ] || rmdir "$EXPORT" 2>/dev/null
			[ "$MADE_WORKDIR" = 0 ] || rmdir "$WORKDIR" 2>/dev/null
		else
			if [ "$SW_OURS" = 1 ] && ownwork "$SW"; then run_on server "rm -rf $(q "$SW")" </dev/null; fi
			if [ "$CW_OURS" = 1 ] && ownwork "$CW"; then run_on client "rm -rf $(q "$CW")" </dev/null; fi
			[ "$MADE_SWORKDIR" = 0 ] || run_on server "rmdir $(q "$WORKDIR") 2>/dev/null" </dev/null
			[ "$MADE_CWORKDIR" = 0 ] || run_on client "rmdir $(q "$WORKDIR") 2>/dev/null" </dev/null
		fi
	fi
	if [ "$T_OURS" = 1 ]; then
		case $T in "$TBASE"/two-host-test.??????) rm -rf "$T" ;; esac
	fi
	printf '\nErgebnis: %s; Protokoll: %s\n' "$STATUS" "$P"
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [ "$LOCAL" = 1 ]; then
	MODE="lokaler Modus, ohne NFS"
else
	MODE="zwei Maschinen, NFSv4"
fi

{
	printf '# Test auf zwei Maschinen nach 9.1\n\n'
	printf -- '- Lauf: %s\n- Modus: %s\n' "$RUNID" "$MODE"
	if [ "$LOCAL" = 1 ]; then
		printf -- '- Server-Host und Client-Host: diese Maschine\n'
	else
		printf -- '- Server-Host: %s\n- Client-Host: %s\n' "$SERVER_HOST" "$CLIENT_HOST"
	fi
	printf '\nIm Protokoll stehen nur IDs und Pfade; Adressen, Betreff, Text und Passphrase sind ersetzt (<Adresse>, <Betreff>, <Text>, <Passphrase>).\n'
} >>"$P"

if [ "$LOCAL" = 1 ]; then
	WARN="WARNUNG: kein Nachweis nach 9.1. Lokaler Modus: Server und Client laufen als derselbe Betriebssystembenutzer auf derselben Maschine und demselben lokalen Dateisystem (der Mount ist ein symbolischer Link auf den Export). Nachgewiesen sind Programme, Startprüfungen beider Seiten, Sperrkonflikte zwischen getrennten Prozessen eines Kernels, Rechte 2770/0660, keine privaten Schlüssel und kein Klartext im Datenverzeichnis und der Ablauf Ende zu Ende. Nicht nachgewiesen: Durchsetzung der Satzsperren durch NFSv4 zwischen zwei Maschinen, getrennte Benutzer in der Gruppe gomail, Schlüsselspeicher nur auf dem Client-Host und Ingest-Schlüssel nur auf dem Server-Host."
	printf '\n%s\n' "$WARN" >&2
	md "" "> **$WARN**"
fi

# ---------------------------------------------------------------- a
step "a) Voraussetzungen"

TOOLS="cat chmod cksum cut dirname find grep head sed sort awk od tr wc mkdir rm rmdir mkfifo mktemp kill sleep tail ls id uname"
must server "for t in $TOOLS curl base64 dd chgrp; do command -v \$t >/dev/null || { echo \"fehlt: \$t\"; exit 1; }; done
command -v sha256sum >/dev/null || command -v shasum >/dev/null || { echo 'fehlt: sha256sum oder shasum'; exit 1; }
curl --version | grep -qi 'smtp' || { echo 'curl ohne SMTP'; exit 1; }
echo 'Werkzeuge vorhanden'"
must client "for t in $TOOLS; do command -v \$t >/dev/null || { echo \"fehlt: \$t\"; exit 1; }; done; echo 'Werkzeuge vorhanden'"
ok "Werkzeuge auf beiden Seiten vorhanden (curl mit SMTP auf dem Server-Host)"

# One directory of its own on each host under --workdir (task 16b
# finding 2): nothing else under --workdir is touched.
if [ "$LOCAL" = 1 ]; then
	if [ ! -d "$WORKDIR" ]; then
		mkdir "$WORKDIR" 2>/dev/null || die "--workdir $WORKDIR fehlt und lässt sich nicht anlegen (das Elternverzeichnis muss existieren)"
		MADE_WORKDIR=1
	fi
	RW=$(umask 077 && mktemp -d "$WORKDIR/two-host.XXXXXX") || die "kein eigenes Verzeichnis unter --workdir $WORKDIR"
	RW_OURS=1
	SW=$RW/server # work directory on the server host
	CW=$RW/client # work directory on the client host
	(umask 077 && mkdir "$SW" "$CW")
	EXPORT=${EXPORT:-$RW/export}
	MOUNT=${MOUNT:-$RW/mount}
	md "" "Eigenes Verzeichnis: $RW (Server-Seite $SW, Client-Seite $CW)"
else
	MKWORK="w=$(q "$WORKDIR")
if [ ! -d \"\$w\" ]; then mkdir \"\$w\" || exit 3; echo 'angelegt: --workdir'; fi
d=\$(umask 077 && mktemp -d \"\$w/two-host.XXXXXX\") || exit 3
echo \"eigenes Verzeichnis \$d\""
	x server "$MKWORK"
	if grep -q '^angelegt: --workdir' "$T/out"; then MADE_SWORKDIR=1; fi
	SW=$(sed -n 's/^eigenes Verzeichnis //p' "$T/out")
	[ "$RC" -eq 0 ] && [ -n "$SW" ] || die "kein eigenes Verzeichnis unter --workdir $WORKDIR auf dem Server-Host (Elternverzeichnis vorhanden?)"
	SW_OURS=1
	x client "$MKWORK"
	if grep -q '^angelegt: --workdir' "$T/out"; then MADE_CWORKDIR=1; fi
	CW=$(sed -n 's/^eigenes Verzeichnis //p' "$T/out")
	[ "$RC" -eq 0 ] && [ -n "$CW" ] || die "kein eigenes Verzeichnis unter --workdir $WORKDIR auf dem Client-Host (Elternverzeichnis vorhanden?)"
	CW_OURS=1
fi

SDATA=$EXPORT/gomail-$RUNID
CDATA=$MOUNT/gomail-$RUNID
KEYS=$SW/keys
SPIN=$KEYS/identity-1.pin
INGEST=$KEYS/ingest-1.key
ADMIN=$KEYS/admin-1.key
CPIN=${PIN:-$CW/identity-1.pin}
WKEY=${WITNESS:-$SW/witness/witness.key}
PASS=$CW/passphrase
ALICE=$CW/alice
BOB=$CW/bob
for p in "$SW" "$CW" "$CPIN" "$WKEY"; do
	case $p in "$EXPORT" | "$EXPORT"/* | "$MOUNT" | "$MOUNT"/*)
		die "Arbeitsverzeichnis, Pin und Zeugenschlüssel müssen außerhalb von Export und Mount liegen: $p"
		;;
	esac
done
md "" "- Export (Server-Host): $EXPORT" "- Mount (Client-Host): $MOUNT" \
	"- Datenverzeichnis: $SDATA (Server-Host), $CDATA (Client-Host)" \
	"- Eigene Verzeichnisse: $SW (Server-Host), $CW (Client-Host)" \
	"- Pin: $CPIN (Client-Host), Zeugenschlüssel: $WKEY (Server-Host)"

# --pin and --witness name places that must not exist yet (task 16b
# finding 3).
[ -z "$PIN" ] || free client "$PIN" --pin
[ -z "$WITNESS" ] || free server "$WITNESS" --witness
[ -z "$PIN$WITNESS" ] || ok "Ablageorte von --pin/--witness existieren noch nicht"

if [ "$LOCAL" = 1 ]; then
	ROOT=$(cd "$(dirname "$0")/.." && pwd)
	if [ -z "$BIN" ]; then
		command -v go >/dev/null || die "--bin fehlt und go ist nicht vorhanden"
		BUILD=$RW/bin
		mkdir "$BUILD"
		BIN=$BUILD
		say "Baue Programme (-tags gomail_dev,gomail_test) nach $BUILD"
		(cd "$ROOT" && go build -tags gomail_dev,gomail_test -o "$BUILD/" ./cmd/...)
		progs
	fi
fi

must server "for p in $SRV $CER $WIT; do command -v \"\$p\" >/dev/null || { echo \"fehlt: \$p\"; exit 1; }; done; echo 'Programme vorhanden'"
must client "for p in $CTL $SRV; do command -v \"\$p\" >/dev/null || { echo \"fehlt: \$p\"; exit 1; }; done; echo 'Programme vorhanden'"
ok "Programme vorhanden: Server-Host gomail-server, gomail-ceremony, gomail-witness; Client-Host gomailctl, gomail-server"

must server "echo \"Benutzer \$(id -un) uid \$(id -u) Gruppen \$(id -nG)\"; echo \"Maschine \$(uname -n)\"; echo \"umask \$(umask)\""
SID=$(sed -n 's/^Benutzer \([^ ]*\) uid \([0-9]*\).*/\1:\2/p' "$T/out")
SHOST=$(sed -n 's/^Maschine //p' "$T/out")
SUMASK=$(sed -n 's/^umask //p' "$T/out")
must client "echo \"Benutzer \$(id -un) uid \$(id -u) Gruppen \$(id -nG)\"; echo \"Maschine \$(uname -n)\"; echo \"umask \$(umask)\""
CID=$(sed -n 's/^Benutzer \([^ ]*\) uid \([0-9]*\).*/\1:\2/p' "$T/out")
CHOST=$(sed -n 's/^Maschine //p' "$T/out")
CUMASK=$(sed -n 's/^umask //p' "$T/out")
for m in "$SUMASK" "$CUMASK"; do
	# Second-last digit: the group; last digit: others (7 = nothing).
	case $m in
	*[01]7) ;;
	*) md "" "Hinweis: umask $m entzieht der Gruppe Rechte oder lässt andere zu (empfohlen 0007); die Programme setzen 0660/2770 selbst per Chmod (D70)." ;;
	esac
done
ok "umask Server-Host $SUMASK, Client-Host $CUMASK (die Programme setzen die Rechte selbst, D70)"

if [ "$LOCAL" = 1 ]; then
	say "Lokaler Modus: Benutzer $SID auf beiden Seiten; Gruppe $GROUP und NFS nicht geprüft."
	if [ ! -d "$EXPORT" ]; then
		mkdir "$EXPORT" 2>/dev/null || die "--export $EXPORT fehlt und lässt sich nicht anlegen (das Elternverzeichnis muss existieren)"
		MADE_EXPORT=1
	fi
	if [ ! -e "$MOUNT" ] && [ ! -L "$MOUNT" ]; then
		ln -s "$EXPORT" "$MOUNT"
		MADE_LINK=1
	fi
	md "" "Mount als symbolischer Link: $MOUNT -> $EXPORT"
else
	[ "$SHOST" != "$CHOST" ] || fail "Server-Host und Client-Host sind dieselbe Maschine ($SHOST)"
	ok "zwei Maschinen: $SHOST (Server), $CHOST (Client)"
	[ "${SID%%:*}" != "${CID%%:*}" ] && [ "${SID#*:}" != "${CID#*:}" ] ||
		fail "Server ($SID) und Client ($CID) laufen nicht unter verschiedenen Benutzern (Name und uid)"
	ok "getrennte Benutzer: $SID (Server), $CID (Client)"
	GCHECK="g=\$(getent group $(q "$GROUP") 2>/dev/null || awk -F: -v g=$(q "$GROUP") '\$1 == g' /etc/group)
[ -n \"\$g\" ] || { echo $(q "keine Gruppe $GROUP"); exit 1; }
echo \"gid \$(echo \"\$g\" | head -n 1 | cut -d: -f3)\"
id -nG | tr ' ' '\n' | grep -qx -e $(q "$GROUP") || { echo $(q "Benutzer nicht in $GROUP"); exit 1; }"
	must server "$GCHECK"
	SGID=$(sed -n 's/^gid //p' "$T/out")
	must client "$GCHECK"
	CGID=$(sed -n 's/^gid //p' "$T/out")
	[ "$SGID" = "$CGID" ] || fail "Gruppe $GROUP hat verschiedene gid ($SGID, $CGID)"
	ok "beide Benutzer in der Gruppe $GROUP (gid $SGID auf beiden Seiten)"
	# The effective mount: the longest mount point that holds the
	# directory, and of equal ones the last line (mounted last).
	# /proc/mounts writes space, tab, newline and backslash in a path as
	# octal escapes (\040, \011, \012, \134): they are decoded before
	# the comparison (task 16c finding 4).
	MOUNTS='function dec(s,   o) {
	o = ""
	while (match(s, /\\[0-7][0-7][0-7]/)) {
		o = o substr(s, 1, RSTART - 1) sprintf("%c", substr(s, RSTART + 1, 1) * 64 + substr(s, RSTART + 2, 1) * 8 + substr(s, RSTART + 3, 1))
		s = substr(s, RSTART + 4)
	}
	return o s
}
BEGIN { m = ENVIRON["GM_MP"] }
{
	d = dec($2)
	if ((m == d || index(m, d "/") == 1 || d == "/") && length(d) >= best) { best = length(d); line = $0 }
}
END { print line }'
	must client "m=\$(cd $(q "$MOUNT") && pwd -P) || exit 1
[ -r /proc/mounts ] || { echo 'kein /proc/mounts: Mount nicht prüfbar'; exit 1; }
GM_MP=\$m LC_ALL=C awk $(q "$MOUNTS") /proc/mounts"
	MLINE=$(tail -n 1 "$T/out")
	FSTYPE=$(printf '%s' "$MLINE" | awk '{ print $3 }')
	MOPTS=$(printf '%s' "$MLINE" | awk '{ print $4 }')
	case $FSTYPE in nfs4 | nfs) ;; *) fail "Mount ist kein NFS ($FSTYPE)" ;; esac
	case ,$MOPTS, in *,vers=4*) ;; *) fail "NFS-Mount ohne vers=4 ($MOPTS)" ;; esac
	case ,$MOPTS, in *,nolock,* | *,local_lock=posix,* | *,local_lock=all,*)
		fail "NFS-Mount mit lokalen Sperren ($MOPTS): Satzsperren wirken nicht über Maschinen"
		;;
	esac
	case ,$MOPTS, in *,local_lock=none,*) ;; *) md "" "Hinweis: local_lock=none nicht in den Optionen" ;; esac
	ok "Mount $MOUNT: $FSTYPE mit $(printf '%s' "$MOPTS" | tr ',' '\n' | grep -E '^(vers|local_lock)=' | tr '\n' ' ')"
	MARK=$(rand 8)
	MARKF=$EXPORT/.two-host-$RUNID
	MARK_OURS=1 # cleanup removes it, also after a failed check
	must server "test -d $(q "$EXPORT") && umask 007 && set -C && printf '%s\n' $MARK >$(q "$MARKF") && chgrp $(q "$GROUP") $(q "$MARKF") && echo geschrieben"
	must client "cat $(q "$MOUNT/.two-host-$RUNID")"
	grep -qx "$MARK" "$T/out" || fail "Export und Mount zeigen nicht dasselbe Verzeichnis"
	must server "rm -f $(q "$MARKF")"
	MARK_OURS=0
	ok "Export $SERVER_HOST:$EXPORT ist auf $CLIENT_HOST unter $MOUNT sichtbar"
fi

# ---------------------------------------------------------------- b
step "b) Datenverzeichnis auf dem Server-Host"

must server "test ! -e $(q "$SDATA") || { echo $(q "existiert schon: $SDATA"); exit 1; }; echo frei"
DATA_OURS=1
if [ -z "$WITNESS" ]; then
	must server "umask 077 && mkdir $(q "$(dirname "$WKEY")") && echo angelegt"
fi
must server "$CER init --dev --data $(q "$SDATA") --keys $(q "$KEYS")"
if [ "$LOCAL" = 0 ]; then
	must server "chgrp -R $(q "$GROUP") $(q "$SDATA") && echo $(q "Gruppe $GROUP gesetzt")"
fi

# rights checks every entry of the data directory (on the server host):
# directories 2770, files 0660, nothing for others, no symbolic links,
# in two-host mode group gomail.
RIGHTS="cd $(q "$SDATA") || exit 1
bad=\$(find . \\( -type d ! -perm 2770 \\) -o \\( -type f ! -perm 0660 \\) -o \\( ! -type d ! -type f \\))
grp=''
[ $LOCAL = 1 ] || grp=\$(find . ! -group $(q "$GROUP"))
echo \"Verzeichnisse: \$(find . -type d | wc -l | tr -d ' '), Dateien: \$(find . -type f | wc -l | tr -d ' ')\"
if [ -n \"\$bad\$grp\" ]; then echo 'Abweichungen:'; ls -ld \$bad \$grp; exit 1; fi
echo 'alle Verzeichnisse 2770, alle Dateien 0660'"
must server "$RIGHTS"
if [ "$LOCAL" = 1 ]; then
	ok "Rechte im Datenverzeichnis: Verzeichnisse 2770, Dateien 0660 (Gruppe nicht geprüft)"
else
	ok "Rechte im Datenverzeichnis: Verzeichnisse 2770, Dateien 0660, Gruppe $GROUP"
fi

copy server "$SPIN" client "$CPIN" PIN_OURS
copy server "$KEYS/witness-dev.key" server "$WKEY" WKEY_OURS
must server "rm -f $(q "$KEYS/witness-dev.key") && echo $(q "Zeugenschlüssel nur noch unter $WKEY")"
# The passphrase goes through a pipe (printf is built in): no here
# document, which some shells keep in a temporary file. cleanup deletes
# the file also with --keep (task 16c finding 6).
PASS_OURS=1
printf '%s\n' "$PASSPHRASE" | run_on client "umask 077; set -C; cat >$(q "$PASS")"
ok "Pin auf dem Client-Host ($CPIN), Zeugenschlüssel getrennt von den Plattformschlüsseln ($WKEY), beide 0600; Passphrase-Datei 0600"

C_ARGS="--data $(q "$CDATA") --pin $(q "$CPIN") --passphrase-file $(q "$PASS")"

# ---------------------------------------------------------------- c
step "c) Sperrtest (9.1 Testsperre, D70)"

refuse client "$CTLE sync $C_ARGS --dir $(q "$ALICE")" "Testsperre"
ok "ohne laufenden Server verweigert der Client auf dem Client-Host (Testsperre)"

SERVE="$ENV_SRV$SRV serve --data $(q "$SDATA") --listen 127.0.0.1:0 --ingest-key $(q "$INGEST") --pin $(q "$SPIN") --log-listen 127.0.0.1:0"
refuse server "$SERVE --require-client-lock" "Client-Sperre"
ok "Server mit --require-client-lock verweigert ohne Client-Sperre"

# start_server NAME ARGS starts gomail-server in the background on the
# server host and waits for both listeners (SMTP, LOG). Its PID file is
# known to cleanup before the start.
start_server() {
	PIDS="$PIDS server:$SW/$1.pid"
	must server "cd $(q "$SW") || exit 1
$(bg "$SW/$1.pid" "$SW/$1.log" "exec $SERVE $2")
$(waitpid "$SW/$1.pid")
echo \"gestartet: pid \$(cat $(q "$SW/$1.pid"))\"
i=0
until grep -q 'msg=\"log listening\"' $(q "$SW/$1.log") && grep -q 'msg=\"smtp listening\"' $(q "$SW/$1.log"); do
	kill -0 \$(cat $(q "$SW/$1.pid")) 2>/dev/null || { echo 'Server beendet:'; cat $(q "$SW/$1.log"); exit 1; }
	[ \$i -lt 600 ] || { echo 'Server nicht bereit'; exit 1; }
	sleep 0.1; i=\$((i + 1))
done
sed -n -e 's/.*msg=\"smtp listening\" addr=\\([0-9.:]*\\).*/smtp \\1/p' -e 's/.*msg=\"log listening\" addr=\\([0-9.:]*\\).*/log \\1/p' $(q "$SW/$1.log")" \
		"gomail-server serve --data $SDATA ... $2 >$SW/$1.log 2>&1 &   # warten auf die Listener"
	SMTP=$(sed -n 's/^smtp //p' "$T/out")
	LOG=$(sed -n 's/^log //p' "$T/out")
}

# stop_server NAME stops it with SIGTERM.
stop_server() {
	must server "p=\$(cat $(q "$SW/$1.pid")); kill \$p; i=0
while kill -0 \$p 2>/dev/null; do [ \$i -lt 300 ] || { kill -KILL \$p; echo 'nicht beendet'; exit 1; }; sleep 0.1; i=\$((i + 1)); done
rm -f $(q "$SW/$1.pid"); echo \"beendet: pid \$p\""
}

start_server server-a ""
ok "Server A läuft auf dem Server-Host und hält locks/server (SMTP $SMTP, Log $LOG)"

# Positive proof: the client passes the lock check and fails only later,
# at the missing user (task 16b finding 7).
x client "$CTLE sync $C_ARGS --dir $(q "$ALICE")"
[ "$RC" -eq 1 ] || fail "sync ohne Benutzer: erwartet Exit 1, erhalten: Exit $RC"
if grep -q Testsperre "$T/err"; then fail "Client sieht die Serversperre über den Mount nicht"; fi
grep -q 'no registered user' "$T/err" || fail "sync ohne Benutzer: erwartet \"no registered user\" nach der Sperrprüfung"
ok "Client auf dem Client-Host sieht die Serversperre über den Mount (besteht die Sperrprüfung und scheitert erst am fehlenden Benutzer: \"no registered user\")"

# A second server on the client host: "gomail-server log repair" takes
# the same server lock locks/server as "serve" (store.HoldRoleLock), but
# needs no ingest key, so no copy of the key leaves the server host (9.1).
refuse client "$SRV log repair --data $(q "$CDATA") --pin $(q "$CPIN")" "Server-Sperre: store: in use"
ok "zweiter Server auf dem Client-Host verweigert (gomail-server log repair bekommt die Serversperre locks/server über den Mount nicht; kein Ingest-Schlüssel auf dem Client-Host)"

# A client on the client host that holds locks/client: gomailctl waits
# for the passphrase on a FIFO after its lock check. Both PID files are
# known to cleanup before the start (task 16b finding 4).
PIDS="$PIDS client:$CW/holder.pid client:$CW/holder.sleep"
must client "cd $(q "$CW") && mkfifo holder.in || exit 1
$(bg "$CW/holder.pid" "$CW/holder.log" "unset GOMAILCTL_PASSPHRASE; exec <$(q "$CW/holder.in"); exec $CTLE sync --data $(q "$CDATA") --pin $(q "$CPIN") --dir $(q "$ALICE")")
$(bg "$CW/holder.sleep" /dev/null "exec sleep 3600 >$(q "$CW/holder.in")")
$(waitpid "$CW/holder.pid" "$CW/holder.sleep")
i=0
until grep -q 'Passphrase:' holder.log; do
	kill -0 \$(cat holder.pid) 2>/dev/null || { cat holder.log; exit 1; }
	[ \$i -lt 300 ] || { echo 'Client wartet nicht'; exit 1; }
	sleep 0.1; i=\$((i + 1))
done
echo \"Client hält locks/client: pid \$(cat holder.pid)\"" \
	"gomailctl sync --dir $ALICE <holder.in &   # wartet auf die Passphrase und hält locks/client"
stop_server server-a
start_server server-b "--require-client-lock"
must server "grep -c 'client lock in force' $(q "$SW/server-b.log")"
must client "cd $(q "$CW") && kill \$(cat holder.sleep) && i=0
while kill -0 \$(cat holder.pid) 2>/dev/null; do [ \$i -lt 100 ] || exit 1; sleep 0.1; i=\$((i + 1)); done
rm -f holder.in holder.sleep holder.pid; cat holder.log; echo" "Client freigeben (Eingabe schließen)"
ok "Server B mit --require-client-lock startet, weil die Client-Sperre vom Client-Host wirkt (SMTP $SMTP, Log $LOG)"

# ---------------------------------------------------------------- d
step "d) Ende zu Ende"

# The witness first (task 14): gomailctl works only with a head that the
# witness cosigned.
must server "pub=$(q "$SDATA/platform/ingest-1.pub")
h=\$({ printf 'gomail-log\n\001'; cat \"\$pub\"; } | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-8)
k=\$({ printf '\001'; cat \"\$pub\"; } | base64 | tr -d '\n')
echo \"gomail-log+\$h+\$k\"" "Prüfschlüssel des Logs aus platform/ingest-1.pub (note: gomail-log+<hash>+<schlüssel>)"
VKEY=$(tail -n 1 "$T/out")
must client "$CTL inspect $(q "$CPIN")"
ORIGIN=$(sed -n 's/.*"origin": "\(.*\)".*/\1/p' "$T/out")
WNAME=$(sed -n 's/.*"name": "\(.*\)".*/\1/p' "$T/out" | head -n 1)
[ -n "$ORIGIN" ] && [ -n "$WNAME" ] || fail "Pin ohne Origin oder Zeugen"
PIDS="$PIDS server:$SW/witness.pid"
must server "cd $(q "$SW") || exit 1
$(bg "$SW/witness.pid" "$SW/witness.log" "exec $WIT serve --log $(q "http://$LOG") --log-key $(q "$VKEY") --origin $(q "$ORIGIN") --key $(q "$WKEY") --state $(q "$SW/witness-state") --interval 1s")
$(waitpid "$SW/witness.pid")
echo \"Zeuge gestartet: pid \$(cat $(q "$SW/witness.pid"))\"" \
	"gomail-witness serve --log http://$LOG --key $WKEY --interval 1s ... >$SW/witness.log 2>&1 &"
ok "Zeuge läuft auf dem Server-Host (Origin $ORIGIN, Zeuge $WNAME)"

# again CMD is a command that runs CMD until it succeeds, at most 120
# times every half second: a client command that needs a head covering
# the newest log entries (the server signs one at most every second
# while the log grows, the witness cosigns it within a second).
again() {
	printf 'i=0; until %s; do [ $i -lt 120 ] || exit 1; sleep 0.5; i=$((i + 1)); done' "$1"
}

# KEYGEN answers the three word questions of gomailctl keygen. The words
# never reach a file (task 16b finding 1): standard output comes through
# a FIFO and stays in the memory of this shell; the answers go through a
# FIFO to standard input. A production gomailctl shows the seed only on
# a terminal (task 13b); the test build (-tags gomail_test) runs keygen
# on the FIFOs with GOMAILCTL_TEST_KEYGEN_PIPE=1. On SIGINT, SIGTERM or SIGHUP the shell exits
# through its EXIT trap, which stops keygen and removes the FIFOs and
# the PID file. The PID of keygen is in the file $kp, which cleanup
# knows before the start: a keygen left on a host after the connection
# broke is stopped there, and the shell gives up as soon as its
# directory is gone (task 16c finding 3). On failure only the last line
# of the error output is shown, without the word questions (finding 2).
KEYGEN='set -eu
umask 077
p=""
t=""
trap '"'"'[ -z "$p" ] || kill "$p" 2>/dev/null; [ -z "$t" ] || rm -rf "$t"; rm -f "$kp"'"'"' EXIT
trap "exit 130" INT TERM HUP
t=$(mktemp -d "$cw/keygen.XXXXXX")
errline() {
	sed "s/Wort Nr\. [0-9]*: //g" "$t/err" 2>/dev/null | awk "NF { l = \$0 } END { if (l != \"\") print l }" >&2
}
mkfifo "$t/in" "$t/out"
env GOMAILCTL_TEST_KEYGEN_PIPE=1 GOMAIL_TEST_DEV_IDENTITY=1 "$ctl" keygen --data "$data" --dir "$dir" --pin "$pin" --passphrase-file "$pass" <"$t/in" >"$t/out" 2>"$t/err" &
p=$!
echo "$p" >"$kp"
exec 3>"$t/in" 4<"$t/out"
w=""
while :; do
	if ! IFS= read -r l <&4; then wait "$p" || true; p=""; errline; exit 1; fi
	w="$w $l"
	case "$w " in *" 24. "*) break ;; esac
done
n=0
while [ "$n" -lt 3 ]; do
	i=0
	while [ "$(grep -o "Wort Nr\. [0-9]*" "$t/err" 2>/dev/null | wc -l | tr -d " ")" -le "$n" ]; do
		[ -d "$t" ] || exit 1
		if ! kill -0 "$p" 2>/dev/null; then errline; exit 1; fi
		i=$((i + 1)); if [ "$i" -gt 600 ]; then echo "keine Wortfrage" >&2; exit 1; fi
		sleep 0.1
	done
	n=$((n + 1))
	k=$(grep -o "Wort Nr\. [0-9]*" "$t/err" | sed -n "${n}p" | sed "s/.* //")
	printf "%s\n" "$w" | awk -v k="$k." "{ for (i = 1; i < NF; i++) if (\$i == k) print \$(i + 1) }" >&3
done
w=""
exec 3>&-
last=""
while IFS= read -r l <&4; do [ -z "$l" ] || last=$l; done
exec 4<&-
if ! wait "$p"; then p=""; errline; exit 1; fi
p=""
printf "%s\n" "$last"'
# keygen DIR creates a user on the client host and answers the three
# word questions from the words shown (they never reach a file or the
# protocol).
keygen() {
	PIDS="$PIDS client:$CW/keygen.pid"
	must client "ctl=$CTL data=$(q "$CDATA") dir=$(q "$1") pin=$(q "$CPIN") pass=$(q "$PASS") cw=$(q "$CW") kp=$(q "$CW/keygen.pid")
$KEYGEN" "gomailctl keygen $C_ARGS --dir $1   # drei Wortfragen aus der Anzeige beantwortet; die 24 Wörter bleiben im Speicher der Shell"
}
keygen "$ALICE"
keygen "$BOB"
ok "zwei Benutzer auf dem Client-Host erzeugt (Schlüsselspeicher in $ALICE, $BOB; Seed-Wörter in keiner Datei)"

must server "$SRV invite create --data $(q "$SDATA")"
INV_A=$(tail -n 1 "$T/out")
must server "$SRV invite create --data $(q "$SDATA")"
INV_B=$(tail -n 1 "$T/out")
must client "$CTLE register --invite $(q "$INV_A") $C_ARGS --dir $(q "$ALICE")"
UID_A=$(sed -n 's/^Registriert: //p' "$T/out")
must client "$CTLE register --invite $(q "$INV_B") $C_ARGS --dir $(q "$BOB")"
UID_B=$(sed -n 's/^Registriert: //p' "$T/out")
[ -n "$UID_A" ] && [ -n "$UID_B" ] || fail "keine Benutzer-ID"
ok "Einladungen auf dem Server-Host, Registrierung auf dem Client-Host (user.rec von gomailctl ins Log eingetragen): $UID_A, $UID_B"

# mailbox create needs a head that covers the own user entry; the
# epochs it creates are appended to the log by gomailctl itself.
must client "$(again "$CTLE mailbox create Buero $C_ARGS --dir $(q "$ALICE")")" "gomailctl mailbox create Buero $C_ARGS --dir $ALICE   # wiederholt, bis ein Kopf den Benutzereintrag enthält"
MBX=$(tail -n 1 "$T/out")
must server "$SRV address add $(q "$ADDR") --mailbox $(q "$MBX") --data $(q "$SDATA") --admin-key $(q "$ADMIN") --pin $(q "$SPIN")"
ok "Postfach $MBX mit Adresse <Adresse> (signiert und geloggt auf dem Server-Host)"

RC=0
printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n' "$FROM" "$ADDR" "$SUBJECT" "$BODY" |
	run_on server "curl --silent --show-error --url $(q "smtp://$SMTP") --mail-from $(q "$FROM") --mail-rcpt $(q "$ADDR") --upload-file - && echo 'eingeliefert'" >"$T/out" 2>"$T/err" || RC=$?
{
	printf '\n```console\nserver$ curl --url smtp://%s --mail-from <Absender> --mail-rcpt <Adresse> --upload-file -   # Mail mit <Betreff> und <Text>\n' "$SMTP"
	cat "$T/out" "$T/err"
	printf '(Exit %s)\n```\n' "$RC"
} | redact >>"$P"
[ "$RC" -eq 0 ] || fail "SMTP: Exit $RC"
must server "grep 'status=250' $(q "$SW/server-b.log") | tail -n 1"
ok "Mail über SMTP an den Server auf dem Server-Host eingeliefert (250)"

# list and read are checked in one awk pass over the pipe: decrypted
# subject and text never reach a file, also not with --keep (task 16b
# finding 5). The exit status of gomailctl comes through the pipe as a
# line "$RCM <status>"; subject and text reach awk through the
# environment (GM_S, GM_B from run_sec), neither through its arguments
# nor through the command line of the shell (task 16c finding 8).
must client "$(again "$CTLE sync $C_ARGS --dir $(q "$ALICE")")" "gomailctl sync $C_ARGS --dir $ALICE   # wiederholt, bis ein Kopf die Epochen enthält"
# list is repeated until a head covers the address assignment as well
# (the client shows no mail whose address the log does not assign); only
# the result of the last run is printed, from a variable of the shell.
must_sec client "i=0
while :; do
	o=\$({ $CTLE list $(q "$MBX") $C_ARGS --dir $(q "$ALICE") || echo $RCM \$?; } |
GM_M=$RCM LC_ALL=C awk '
\$1 == ENVIRON[\"GM_M\"] && NF == 2 { rc = \$2; next }
{ print \$1, \"Größe\", \$4; if (index(\$0, ENVIRON[\"GM_S\"])) n++ }
END { print \"Zeilen mit dem Betreff: \" n + 0; if (rc != \"\") print \"Exit \" rc }')
	case \$o in *'Zeilen mit dem Betreff: 1'*) break ;; esac
	[ \$i -lt 120 ] || break
	sleep 0.5; i=\$((i + 1))
done
printf '%s\\n' \"\$o\"
case \$o in *'Exit '*) exit 1 ;; esac" \
	"gomailctl list $MBX $C_ARGS --dir $ALICE | awk ...   # nur Mail-ID und Größe ins Protokoll, keine Datei; wiederholt, bis ein Kopf die Adresse enthält"
grep -q 'Zeilen mit dem Betreff: 1' "$T/out" || fail "die Mail fehlt in der Liste"
MAILID=$(awk 'NR == 1 { print $1 }' "$T/out")
must_sec client "{ $CTLE read $(q "$MBX") $(q "$MAILID") $C_ARGS --dir $(q "$ALICE") || echo $RCM \$?; } |
GM_M=$RCM LC_ALL=C awk '
\$1 == ENVIRON[\"GM_M\"] && NF == 2 { rc = \$2; next }
{ n += length(\$0) + 1 }
NR == 1 && /^Received: / { r = 1 }
index(\$0, \"Subject: \" ENVIRON[\"GM_S\"]) { s = 1 }
index(\$0, ENVIRON[\"GM_B\"]) { b = 1 }
END {
	print \"Bytes: \" n + 0
	if (r) print \"Received-Kopf: ja\"
	if (s) print \"Betreff: ja\"
	if (b) print \"Text: ja\"
	if (rc != \"\") { print \"Exit \" rc; exit 1 }
}'" "gomailctl read $MBX $MAILID $C_ARGS --dir $ALICE | awk ...   # nur Größe und Prüfergebnis ins Protokoll, keine Datei"
for w in 'Received-Kopf: ja' 'Betreff: ja' 'Text: ja'; do
	grep -q "$w" "$T/out" || fail "read: $w fehlt"
done
ok "sync, list und read auf dem Client-Host: Mail $MAILID entschlüsselt, Betreff und Text stimmen (geprüft in der Pipe, ohne Datei)"

# Only the exit status and standard error count: standard output (a list
# the second user must not see) goes to /dev/null (task 16c finding 5).
x client "$CTLE list $(q "$MBX") $C_ARGS --dir $(q "$BOB") >/dev/null"
[ "$RC" -ne 0 ] || fail "der zweite Benutzer liest das Postfach ohne Freigabe"
if grep -q Testsperre "$T/err"; then fail "zweiter Benutzer scheitert an der Testsperre statt am fehlenden Zugang"; fi
ok "zweiter Benutzer $UID_B auf dem Client-Host liest $MBX ohne Freigabe nicht"

# The share (2.5, 9.2): the wrap of epoch 1 for the second user and an
# epoch member-added with its supply, which gomailctl appends to the log
# itself (task 14). The list of the second user is repeated until a head
# covers the new epoch as well (until then it shows the mail of epoch 1
# but ends with an error for the uncovered epoch).
must client "$CTLE mailbox share $(q "$MBX") $(q "$UID_B") --from 1 $C_ARGS --dir $(q "$ALICE")"
grep -q "Verpackt für $UID_B: Epochen 1" "$T/out" || fail "share: Epoche 1 nicht für den zweiten Benutzer verpackt"
must_sec client "i=0
while :; do
	o=\$({ $CTLE list $(q "$MBX") $C_ARGS --dir $(q "$BOB") || echo $RCM \$?; } |
GM_M=$RCM LC_ALL=C awk '
\$1 == ENVIRON[\"GM_M\"] && NF == 2 { rc = \$2; next }
{ print \$1, \"Größe\", \$4; if (index(\$0, ENVIRON[\"GM_S\"])) n++ }
END { print \"Zeilen mit dem Betreff: \" n + 0; if (rc != \"\") print \"Exit \" rc }')
	case \$o in *'Exit '*) ;; *'Zeilen mit dem Betreff: 1'*) break ;; esac
	[ \$i -lt 120 ] || break
	sleep 0.5; i=\$((i + 1))
done
printf '%s\\n' \"\$o\"
case \$o in *'Exit '*) exit 1 ;; esac" \
	"gomailctl list $MBX $C_ARGS --dir $BOB | awk ...   # nur Mail-ID und Größe ins Protokoll, keine Datei; wiederholt, bis ein Kopf die neue Epoche enthält"
grep -q 'Zeilen mit dem Betreff: 1' "$T/out" || fail "der zweite Benutzer sieht die Mail nach der Freigabe nicht"
must_sec client "{ $CTLE read $(q "$MBX") $(q "$MAILID") $C_ARGS --dir $(q "$BOB") || echo $RCM \$?; } |
GM_M=$RCM LC_ALL=C awk '
\$1 == ENVIRON[\"GM_M\"] && NF == 2 { rc = \$2; next }
index(\$0, ENVIRON[\"GM_B\"]) { b = 1 }
END {
	if (b) print \"Text: ja\"
	if (rc != \"\") { print \"Exit \" rc; exit 1 }
}'" "gomailctl read $MBX $MAILID $C_ARGS --dir $BOB | awk ...   # nur das Prüfergebnis ins Protokoll, keine Datei"
grep -q 'Text: ja' "$T/out" || fail "read des zweiten Benutzers: Text fehlt"
ok "mailbox share $MBX an $UID_B ab Epoche 1: der zweite Benutzer liest die Mail $MAILID nach der Freigabe (geprüft in der Pipe, ohne Datei)"

# The server host waits for the head while the witness lives (task 16b
# finding 7); then the client host reads it over the mount.
must server "h=$(q "$SDATA/log/heads"); w=\$(cat $(q "$SW/witness.pid")); i=0
until ls \"\$h\" 2>/dev/null | grep -q '\\.sig\$'; do
	kill -0 \"\$w\" 2>/dev/null || { echo 'Zeuge beendet:'; cat $(q "$SW/witness.log"); exit 1; }
	[ \$i -lt 1800 ] || { echo 'kein Kopf mit Zeugensignatur:'; cat $(q "$SW/witness.log"); exit 1; }
	sleep 0.1; i=\$((i + 1))
done
echo \"Kopf \$(ls \"\$h\" | grep '\\.sig\$' | sort -n | tail -n 1)\"" "warten auf einen Kopf mit Zeugensignatur, solange der Zeuge läuft"
HEADF=$(sed -n 's/^Kopf //p' "$T/out")
[ -n "$HEADF" ] || fail "kein Kopf mit Zeugensignatur"
must client "f=$(q "$CDATA/log/heads/$HEADF"); i=0
until [ -f \"\$f\" ]; do [ \$i -lt 600 ] || { echo 'Kopf auf dem Client-Host nicht sichtbar'; exit 1; }; sleep 0.1; i=\$((i + 1)); done
cat \"\$f\"" "cat $CDATA/log/heads/$HEADF   # über den Mount gelesen"
grep -q -F -- "— gomail-log " "$T/out" || fail "Kopf ohne Signatur des Logs"
grep -q -F -- "— $WNAME " "$T/out" || fail "Kopf ohne Signatur des Zeugen $WNAME"
ok "Log-Kopf mit Signatur des Logs und des Zeugen $WNAME, auf dem Client-Host über den Mount gelesen"

# ---------------------------------------------------------------- e
step "e) Nachweis im Export"

stop_server server-b
must server "p=\$(cat $(q "$SW/witness.pid")); kill \$p; i=0
while kill -0 \$p 2>/dev/null; do [ \$i -lt 100 ] || kill -KILL \$p; sleep 0.1; i=\$((i + 1)); done
rm -f $(q "$SW/witness.pid"); echo 'Zeuge beendet'"

must server "cd $(q "$SDATA") || exit 1
f=\$(find . -type f -perm 0600); n=\$(find . \\( -name '*keystore*' -o -name '*.key' -o -name '*INSECURE*' -o -name '*.pin' \\))
m=\$(grep -r -l -a -F -e 'gomail/v1/rec/platform-key' -e 'PRIVATE+KEY+' -e 'UNSICHER - NUR' . || true)
s=\$(find . -type f -exec sh -c 'for x; do [ \"\$(dd if=\"\$x\" bs=4 count=1 2>/dev/null)\" != GMKS ] || echo \"\$x\"; done' sh {} +)
echo \"0600-Dateien: \${f:-keine}\"; echo \"Schlüsseldateien nach Namen: \${n:-keine}\"
echo \"Kennungen privater Schlüssel im Inhalt: \${m:-keine}\"; echo \"Schlüsselspeicher (GMKS): \${s:-keine}\"
[ -z \"\$f\$n\$m\$s\" ]" "Suche im Export nach 0600-Dateien, Schlüsseldateien, Kennungen privater Schlüssel und Schlüsselspeichern"
ok "keine privaten Schlüssel im Export (keine 0600-Datei, kein keystore, keine Schlüsseldatei, keine Kennung)"

# grep reads subject and body token as patterns from its standard input
# (printf is built in): they appear in no command line (task 16c
# finding 8).
must_sec server "r=\$(printf '%s\\n%s\\n' \"\$GM_S\" \"\$GM_B\" | grep -r -l -a -F -f /dev/stdin $(q "$SDATA") $(q "$SW/server-a.log") $(q "$SW/server-b.log") $(q "$SW/witness.log") || true)
echo \"Fundstellen von Betreff und Text: \${r:-keine}\"; [ -z \"\$r\" ]" \
	"printf '%s\\n' <Betreff> <Text> | grep -r -F -f /dev/stdin $SDATA $SW/*.log   # Muster über stdin, in keiner Kommandozeile"
must_sec client "r=\$(printf '%s\\n%s\\n' \"\$GM_S\" \"\$GM_B\" | grep -r -l -a -F -f /dev/stdin $(q "$CW") || true)
echo \"Fundstellen von Betreff und Text: \${r:-keine}\"; [ -z \"\$r\" ]" \
	"printf '%s\\n' <Betreff> <Text> | grep -r -F -f /dev/stdin $CW   # Muster über stdin, in keiner Kommandozeile"
ok "kein Klartext von Betreff und Text im Export, in den Protokollen von Server und Zeuge und im eigenen Verzeichnis des Client-Hosts"

must server "$RIGHTS"
ok "Rechte aller Dateien und Verzeichnisse im Export nach dem Lauf: 2770/0660"

must client "cd $(q "$CW") || exit 1
k=\$(find . -name keystore ! -perm 0600); c=\$(find . -name 'ingest*')
echo \"Schlüsselspeicher: \$(find . -name keystore | tr '\n' ' ')\"
[ -z \"\$k\$c\" ] && echo 'alle 0600, kein Ingest-Schlüssel auf dem Client-Host'" "Schlüsselspeicher auf dem Client-Host"
ok "Schlüsselspeicher nur auf dem Client-Host ($CW), Rechte 0600; kein Ingest-Schlüssel auf dem Client-Host"

# ---------------------------------------------------------------- f
step "f) Protokoll"

for n in server-a server-b witness; do
	x server "cat $(q "$SW/$n.log")" "cat $SW/$n.log"
done
if printf '%s\n' "$SUBJECT" "$BODY" "$ADDR" "$PASSPHRASE" | grep -q -F -f /dev/stdin "$P"; then
	fail "das Protokoll enthält Klartext"
fi
ok "Protokoll $P ohne Adresse, Betreff, Text und Passphrase"
STATUS=bestanden
