# Library for simple test scripts
# Copyright (C) 2009, 2011-2013 Free Software Foundation, Inc.
#
# Copying and distribution of this file, with or without modification,
# in any medium, are permitted without royalty provided the copyright
# notice and this notice are preserved.

require_cat() {
    if ! type cat > /dev/null 2> /dev/null; then
	echo "This test requires the cat utility" >&2
	exit 77
    fi
}

use_tmpdir() {
    tmpdir=$abs_top_builddir/tests/tmp.$$
    mkdir "$tmpdir" && cd "$tmpdir" || exit 2
}

use_local_logscan() {
    test -n "$XTEST" || XTEST=$abs_top_builddir/logscan

    eval 'logscan() {
          $XTEST "$@"
    }'
}

if diff -u -L expected -L got /dev/null /dev/null 2> /dev/null; then
    eval '_compare() {
	diff -u -L expected -L got "$1" "$2"
    }'
else
    eval '_compare() {
	echo "expected:"
	cat "$1"
	echo "got:"
	cat "$2"
    }'
fi

_check() {
    _start_test "$@"
    expected=`cat`
    if got=`set +x; eval "$*" 3>&2 </dev/null 2>&1` && \
            test "$expected" = "$got" ; then
	echo "ok"
	checks_succeeded="$checks_succeeded + 1"
    else
	echo "FAILED"
	if test "$expected" != "$got" ; then
	    echo "$expected" > expected~
	    echo "$got" > got~
	    _compare expected~ got~
	    rm -f expected~ got~
	fi
	checks_failed="$checks_failed + 1"
    fi
}

check() {
    _check "$@"
}

ncheck() {
    _check "$@" < /dev/null
}

cleanup() {
    status=$?
    checks_succeeded=`expr $checks_succeeded`
    checks_failed=`expr $checks_failed`
    checks_total=`expr $checks_succeeded + $checks_failed`
    if test $checks_total -gt 0 ; then
	if test $checks_failed -gt 0 && test $status -eq 0 ; then
	    status=1
	fi
	echo "$checks_total tests ($checks_succeeded passed," \
	     "$checks_failed failed)"
    fi
    if test -n "$tmpdir" ; then
	chmod -R u+rwx "$tmpdir" 2>/dev/null
	cd / && rm -rf "$tmpdir"
    fi
    exit $status
}

if test -z "`echo -n`"; then
    if eval 'test -n "${BASH_LINENO[0]}" 2>/dev/null'; then
	eval '
	    _start_test() {
		echo -n "[${BASH_LINENO[2]}] $* -- "
	    }'
    else
	eval '
	    _start_test() {
		echo -n "* $* -- "
	    }'
    fi
else
    eval '
	_start_test() {
	    echo "* $*"
	}'
fi

require_cat

checks_succeeded=0
checks_failed=0
trap cleanup 0
