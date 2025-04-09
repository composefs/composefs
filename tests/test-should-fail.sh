#!/bin/bash
set -e
bindir=$(cd $1 && pwd)
shift
. $(dirname $0)/test-lib.sh

tmpd=$(mktemp -d -t lcfs-test.XXXXXX)
trap 'rm -rf -- "$tmpd"' EXIT
for f in $@; do
    rc=0
    $bindir/mkcomposefs --from-file $f $tmpd/out.cfs >/dev/null 2>$tmpd/err.txt || rc=$?
    if test $rc == 0; then
        fatal "Test case $f should have failed"
    fi
    if test $rc != 1; then
        cat $tmpd/err.txt
        fatal "Test case $f exited with code $rc, not 1"
    fi
    echo "ok $f"
done
