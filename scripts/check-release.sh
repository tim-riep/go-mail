#!/bin/sh
# check-release.sh: checks that programs to be shipped are production
# builds (task 27 package 27B; docs/AUDIT.md R35, list after M1 no. 19).
#
#   scripts/check-release.sh <program>...
#
# The test switches (GOMAIL_TEST_MIN_FREE, GOMAIL_TEST_DEV_IDENTITY,
# GOMAIL_TEST_HEAD_GAP, GOMAILCTL_TEST_KEYGEN_PIPE) exist only in a build
# with the tag gomail_test, the development ceremony ("gomail-ceremony
# init --dev") and the acceptance of a development pin only in a build
# with the tag gomail_dev. Nothing in the programs refuses to run as such
# a build; this script is the check before shipping. For every program:
#
#   1. "go version -m" reads its build information. A file without it
#      (not a Go program, the build information removed) or without the
#      build setting GOOS (go build always records it) is not clean: its
#      tags are unknown (fail closed).
#   2. The build setting -tags names neither gomail_test nor gomail_dev.
#      Other tags are not checked. A value that go prints quoted, or that
#      holds a character for which it would quote it, is not clean either
#      (fail closed, see below).
#   3. The file contains no known mark of a test build: no name of a
#      test switch (the four above, and any name that matches
#      GOMAIL[A-Z_]*_TEST_, that is only capital letters and underscores
#      between GOMAIL and _TEST_, no digits) and neither the text nor the
#      name of the root file of the development ceremony
#      (internal/ceremony: initdev_dev.go, RootFile).
#
# Exit status 0 when every program is clean, 1 otherwise: a program that
# is not clean or not checkable, a file that is missing or not a
# readable regular file, no program given, a missing tool, a go command
# that fails. Every finding is one message on standard error, a clean
# program one message on standard output; each ends with a newline and
# is one line unless a file name or a tag value holds a newline. The
# script has no options (an argument starting with - is a file name) and
# does not run the programs it checks. It needs go (any version that
# reads the build information of the programs), awk, tr, grep and sort;
# when one of them is missing, or "go version" fails, it checks nothing.
# A tool that fails (exit status not 0) during a check makes that
# program not clean, never clean. A tool that exits with 0 but prints
# wrong output (an awk that prints a number whatever it reads, a grep
# that passes lines it should not) is not detected.
#
# The script guards against shipping a test build by mistake, not against
# a build made to pass it: a build that swaps the files of a tag in
# without the tag (go build -overlay), renames a switch or removes the
# build information on purpose is not what it is for.

set -uf

me=check-release.sh

# switches are the names of the test switches of the tag gomail_test;
# any other name that matches pattern is a finding as well.
switches='GOMAIL_TEST_MIN_FREE GOMAIL_TEST_DEV_IDENTITY GOMAIL_TEST_HEAD_GAP GOMAILCTL_TEST_KEYGEN_PIPE'
pattern='GOMAIL[A-Z_]*_TEST_'

# devText and devFile are the text and the name of the root file that
# only the development ceremony writes (tag gomail_dev).
devText='INSECURE - DEVELOPMENT ONLY'
devFile='platform-root.INSECURE-DEV-ONLY.txt'

nl='
'
cr=$(printf '\r')

if [ $# -eq 0 ]; then
	printf '%s\n' "Aufruf: scripts/check-release.sh <programm>..." >&2
	printf '%s: kein Programm angegeben; nichts geprüft\n' "$me" >&2
	exit 1
fi
missing=0
for tool in go awk tr grep sort; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		case $tool in
		go) printf '%s: kein go-Befehl im PATH (go version -m liest die Build-Tags)\n' "$me" >&2 ;;
		*) printf '%s: kein %s im PATH\n' "$me" "$tool" >&2 ;;
		esac
		missing=1
	fi
done
if [ $missing -ne 0 ]; then
	printf '%s: Hilfsprogramm fehlt; nichts geprüft\n' "$me" >&2
	exit 1
fi
# A go command that cannot run (GOTOOLCHAIN or GOFLAGS not usable, the
# toolchain not available) would fail on every program; it is named once
# with its last line of output instead.
gov=$(go version 2>&1)
rc=$?
if [ $rc -ne 0 ] || [ -z "$gov" ]; then
	case $gov in
	'') gov='keine Ausgabe' ;;
	*) gov=${gov##*"$nl"} ;;
	esac
	printf '%s: go version gescheitert (Status %s: %s); nichts geprüft\n' "$me" "$rc" "$gov" >&2
	exit 1
fi

bad=0
for arg in "$@"; do
	# go version would read a name starting with - as an option.
	case $arg in
	-*) f=./$arg ;;
	*) f=$arg ;;
	esac
	found=0
	if [ ! -e "$f" ]; then
		printf '%s: %s: nicht vorhanden\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
	fi
	if [ ! -f "$f" ] || [ ! -r "$f" ]; then
		printf '%s: %s: keine lesbare reguläre Datei\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
	fi

	# 1. build information. go version -m prints "<file>: <go version>"
	# and then one line per entry, each starting with a tab. body is the
	# output without "<file>: ", so that a file name with a newline or a
	# tab cannot pass for an entry; awk skips its first line (the go
	# version) as well.
	if ! info=$(go version -m "$f" 2>/dev/null) || [ -z "$info" ]; then
		printf '%s: %s: keine Build-Informationen (kein Go-Programm?); Build-Tags unbekannt\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
	fi
	body=${info#"$f: "}
	if [ "$body" = "$info" ]; then
		printf '%s: %s: Ausgabe von go version -m nicht lesbar; Build-Tags unbekannt\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
	fi
	ver=${body%%"$nl"*}
	if ! settings=$(printf '%s\n' "$body" | awk -F '\t' 'NR > 1 && $2 == "build" && index($3, "GOOS=") == 1 { n++ } END { print n + 0 }'); then
		settings=
	fi
	case $settings in
	'' | *[!0-9]*)
		printf '%s: %s: Auswertung der Build-Informationen gescheitert (awk); Build-Tags unbekannt\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
		;;
	esac
	if [ "$settings" -eq 0 ]; then
		printf '%s: %s: keine Build-Einstellungen in den Build-Informationen; Build-Tags unbekannt\n' "$me" "$arg" >&2
		found=1
	fi

	# 2. tags. go prints a value in quotes (with escapes) when it holds a
	# space, tab, CR, LF, " or `; such a value, or more than one line
	# -tags=, is not read but refused. A -tags=gomail_dev,x" would
	# otherwise hide gomail_dev: in a build with gomail_dev alone,
	# gomail-server, gomail-witness and gomailctl carry no mark of check 3,
	# so only this check refuses them.
	if ! tags=$(printf '%s\n' "$body" | awk -F '\t' 'NR > 1 && $2 == "build" && index($3, "-tags=") == 1 { print substr($3, 7) }'); then
		printf '%s: %s: Auswertung der Build-Informationen gescheitert (awk); Build-Tags unbekannt\n' "$me" "$arg" >&2
		bad=$((bad + 1))
		continue
	fi
	case $tags in
	*[\"\`\ \	]* | *"$cr"* | *"$nl"*)
		printf '%s: %s: Build-Tags nicht eindeutig lesbar (-tags=%s)\n' "$me" "$arg" "$tags" >&2
		found=1
		;;
	esac
	oldIFS=$IFS
	IFS=,
	for tag in $tags; do
		case $tag in
		gomail_test | gomail_dev)
			printf '%s: %s: mit dem Tag %s gebaut (-tags=%s)\n' "$me" "$arg" "$tag" "$tags" >&2
			found=1
			;;
		esac
	done
	IFS=$oldIFS

	# 3. marks in the file; tr makes every run of capital letters, digits
	# and underscores one line (strings in a Go program are not
	# terminated, so a line can hold two names). The line -end- comes
	# after the output of tr only when tr succeeded and cannot come from
	# tr (it holds -); grep and sort pass it on only when they read
	# their input to the end. Without it the search failed. It starts
	# with a newline: a file that ends with a capital letter, digit or
	# underscore leaves the last line of tr open (a darwin/arm64 program
	# ends with a hash of its code signature); where the output of tr
	# ends with a newline already, it makes an empty line, which grep
	# does not pass on.
	names=$({ LC_ALL=C tr -c 'A-Z0-9_' '\n' <"$f" && printf '\n%s\n' -end-; } | LC_ALL=C grep -E -e "$pattern" -e '^-end-$' | LC_ALL=C sort -u)
	case $nl$names$nl in
	*"$nl-end-$nl"*) ;;
	*)
		printf '%s: %s: Suche nach Testschaltern gescheitert (tr, grep, sort); nicht geprüft\n' "$me" "$arg" >&2
		found=1
		;;
	esac
	for s in $switches; do
		case $names in
		*"$s"*)
			printf '%s: %s: enthält den Testschalter %s\n' "$me" "$arg" "$s" >&2
			found=1
			;;
		esac
	done
	for n in $names; do
		[ "$n" = -end- ] && continue
		known=0
		for s in $switches; do
			case $n in *"$s"*) known=1 ;; esac
		done
		if [ $known -eq 0 ]; then
			printf '%s: %s: enthält den Namen %s (Muster %s)\n' "$me" "$arg" "$n" "$pattern" >&2
			found=1
		fi
	done
	# grep reads the file itself: exit status 0 found, 1 not found,
	# anything else an error.
	for m in "$devText" "$devFile"; do
		LC_ALL=C grep -q -F -e "$m" <"$f"
		case $? in
		0)
			printf '%s: %s: enthält "%s" (Entwicklungszeremonie)\n' "$me" "$arg" "$m" >&2
			found=1
			;;
		1) ;;
		*)
			printf '%s: %s: Suche nach "%s" gescheitert (grep); nicht geprüft\n' "$me" "$arg" "$m" >&2
			found=1
			;;
		esac
	done

	if [ $found -ne 0 ]; then
		bad=$((bad + 1))
	else
		printf '%s: Produktionsbuild (%s, ohne gomail_test und gomail_dev, kein Testschalter)\n' "$arg" "$ver"
	fi
done

if [ $bad -ne 0 ]; then
	printf '%s: %s von %s Programmen kein Produktionsbuild oder nicht prüfbar; nicht ausliefern\n' "$me" "$bad" "$#" >&2
	exit 1
fi
exit 0
