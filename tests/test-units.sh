#!/bin/bash

BINDIR=$(cd "$1" && pwd)

# Its more likely that fsverity works in /var/tmp than in /tmp (which
# is typically tmpfs) so use that here.
export TMPDIR=${TMPDIR:-/var/tmp}

set -e

workdir=$(mktemp --directory --tmpdir lcfs-test.XXXXXX)
trap 'rm -rf -- "$workdir"' EXIT

. $(dirname $0)/test-lib.sh

function makeimage () {
    local dir=$1
    ${VALGRIND_PREFIX} $BINDIR/mkcomposefs --digest-store=$dir/objects $dir/root $dir/test.cfs
}

function countobjects () {
    local dir=$1
    find $dir/objects -type f | wc -l
}

# Ensure small files are inlined
function  test_inline () {
    local dir=$1

    echo foo > $dir/root/a-file

    makeimage $dir

    objects=$(countobjects $dir)
    if [ $objects != 0 ]; then
        return 1
    fi
}

# Ensure we generate objects for large files
function  test_objects () {
    local dir=$1
    dd if=/dev/zero bs=1 count=1024 2>/dev/null > $dir/root/a-file

    makeimage $dir

    objects=$(countobjects $dir)
    if [ $objects != 1 ]; then
        return 1
    fi
}

function  test_mount_digest () {
    local dir=$1

    if [ $has_fsverity = y ]; then
        echo foo > $dir/root/a-file
        makeimage $dir

        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "non-fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has no fs-verity"

        fsverity enable $dir/test.cfs

        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "wrong fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has wrong fs-verity"

        local DIGEST=$(fsverity measure $dir/test.cfs | awk "{ print \$1 }" | sed s/sha256://)

        # We should either successfully mount, or start trying and fail for one of these reasons:
        #  * Permission denied, if not root
        #  * No such file or directory, if /dev/loop-control is missing
        #  * Operation not permitted, when running in a sandbox
        # What should not happen is that it should fail for fs-verity reasons before trying to mount.
        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=$DIGEST $dir/test.cfs $dir/mnt 2> $dir/stderr || assert_file_has_content $dir/stderr "Permission denied\|No such file or directory\|Operation not permitted"
        umount $dir/mnt 2> $dir/stderr || true
    fi
}

function test_composefs_info_measure_files () {
    local dir=$1
    cd $dir

    echo hello world > test.txt
    echo foo bar baz > test2.txt
    $BINDIR/composefs-info measure-file test.txt test2.txt > out.txt
    assert_streq "$(head -1 out.txt)" "37061ef2ac4c21bec68489b56138c5780306a4ad7fe6676236ecdf2c9027cd92"
    assert_streq "$(tail -1 out.txt)" "91e7d88cb7bc9cf6d8db3b0ecf89af4abf204bef5b3ade5113d5b62ef374e70b"

    if [ $has_fsverity = y ]; then
        fsverity enable --hash-alg=sha256 test.txt
        digest=$($BINDIR/composefs-info measure-file test.txt)
        assert_streq "$digest" "37061ef2ac4c21bec68489b56138c5780306a4ad7fe6676236ecdf2c9027cd92"
    fi
    cd - &> /dev/null
}

function test_composefs_info_help () {
    $BINDIR/composefs_info --help
}

TESTS="test_inline test_objects test_mount_digest test_composefs_info_measure_files"
res=0
for i in $TESTS; do
    testdir=$(mktemp -d $workdir/$i.XXXXXX)
    mkdir $testdir/root $testdir/objects $testdir/mnt
    if $i $testdir ; then
        echo "Test $i: OK"
    else
        res=1
        echo "Test $i Failed"
    fi

    rm -rf $testdir
done

exit $res
