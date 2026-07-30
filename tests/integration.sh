#!/bin/bash
# A basic integration test for composefs; we capture /usr/bin
# from the host environment into a cfs, then mount it and compare
# the output of ls -lR (without hardlink counts).
set -xeuo pipefail

# Set to setup an explicit temporary ext4 loopback mounted fs with fsverity
WITH_TEMP_VERITY=${WITH_TEMP_VERITY:-}
if test -n "${WITH_TEMP_VERITY}"; then
    tmpdisk=$(mktemp -p /var/tmp)
    truncate -s 100G ${tmpdisk}
    mkfs.ext4 -O verity ${tmpdisk}
    tmp_mnt=$(mktemp -d)
    mount -o loop ${tmpdisk} ${tmp_mnt}
    rm -f ${tmpdisk}
    cfsroot=${tmp_mnt}
fi

orig=$(pwd)
cfsroot=${cfsroot:-/composefs}
rm ${cfsroot}/tmp -rf
mkdir -p ${cfsroot}/{objects,roots,tmp}

cd ${cfsroot}/tmp

run_test() {
    local testsrc=$1
    local dumpdir_args="$2"
    mkcomposefs --print-digest --digest-store=${cfsroot}/objects ${testsrc} ${cfsroot}/roots/test.cfs | tee digest.txt
    prev_digest=$(cat digest.txt)
    new_digest=$(mkcomposefs --print-digest-only ${testsrc})
    test "$prev_digest" = "$new_digest"

    if which fsck.erofs &>/dev/null; then
        fsck.erofs ${cfsroot}/roots/test.cfs
    fi

    mkdir -p mnt
    mount.composefs -o basedir=${cfsroot}/objects ${cfsroot}/roots/test.cfs mnt
    $orig/tests/dumpdir $dumpdir_args ${testsrc} > src-dump.txt
    $orig/tests/dumpdir $dumpdir_args mnt > mnt-dump.txt
    failed=
    if ! diff -u src-dump.txt mnt-dump.txt; then
        failed=1
    fi
    if test -n "${failed}"; then
        umount mnt
        exit 1
    fi

    new_digest=$(mkcomposefs --print-digest-only mnt)
    test "$prev_digest" = "$new_digest"

    umount mnt
}

run_test /usr/bin "--no-nlink"

# Regression test for https://github.com/composefs/composefs/issues/444:
# building directly from a directory (as opposed to --from-file) used to
# silently drop hardlinks, giving every file nlink=1 even if two paths
# were hardlinked to each other. This is opt-in via --hardlinks, so also
# confirm the (unchanged) default behavior. Runs for both regular files and
# symlinks, since any non-directory type can be hardlinked (`ln -P`), not
# just regular files.
test_hardlinks() {
    local dir=hardlink-test
    local create=$1

    rm -rf "${dir}"
    mkdir -p "${dir}/src"
    "${create}" "${dir}/src/file1"
    ln "${dir}/src/file1" "${dir}/src/file2"

    # Default (no --hardlinks): every path gets its own independent inode
    # with nlink=1, matching this tool's historical behavior.
    mkcomposefs "${dir}/src" "${dir}/default.cfs"
    default_dump=$(composefs-info dump "${dir}/default.cfs")
    test "$(echo "${default_dump}" | awk '$1=="/file1"{print $4}')" = "1"
    test "$(echo "${default_dump}" | awk '$1=="/file2"{print $4}')" = "1"
    ! echo "${default_dump}" | grep -q '^/file[12] [0-9]* @'

    # --hardlinks: file1 and file2 are the same inode (nlink=2), with
    # exactly one of the two recorded as a hardlink (the "@" marker from
    # composefs-dump(5)) pointing at the other.
    mkcomposefs --hardlinks "${dir}/src" "${dir}/hardlinks.cfs"
    hl_dump=$(composefs-info dump "${dir}/hardlinks.cfs")
    test "$(echo "${hl_dump}" | awk '$1=="/file1"{print $4}')" = "2"
    test "$(echo "${hl_dump}" | awk '$1=="/file2"{print $4}')" = "2"
    test "$(echo "${hl_dump}" | grep -c '^/file[12] [0-9]* @')" = "1"

    rm -rf "${dir}"
}
create_regular_file() {
    dd if=/dev/urandom "of=$1" bs=1024 count=4 status=none
}
create_symlink() {
    ln -s target-does-not-need-to-exist "$1"
}
test_hardlinks create_regular_file
test_hardlinks create_symlink

check_fsverity () {
    fsverity --version >/dev/null 2>&1 || return 1
    tmpfile=$(mktemp --tmpdir lcfs-fsverity.XXXXXX)
    echo foo > $tmpfile
    fsverity enable $tmpfile >/dev/null 2>&1  || return 1
    return 0
}

echo "fsverity test" > ${cfsroot}/test-fsverity
if fsverity enable ${cfsroot}/test-fsverity; then
    echo "fsverity is supported"
else
    if test -n "${WITH_TEMP_VERITY}"; then
        echo "fsverity unsupported, but is required" 1>&2
        exit 1
    fi
    echo "fsverity unsupported"
fi
rm -f ${cfsroot}/test-fsverity

# Don't create whiteouts, as they depend on a very recent kernel to work at all
$orig/tests/gendir --privileged --nowhiteout ${cfsroot}/tmp/rootfs
# nlink doesn't work for the toplevel dir in composefs, because that is from overlayfs, not erofs
run_test ${cfsroot}/tmp/rootfs "--no-root-nlink"
