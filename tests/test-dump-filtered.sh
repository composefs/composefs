#!/bin/bash

BINDIR="$1"
ASSET_DIR="$2"

. $(dirname $0)/test-lib.sh

set -eu
tmpd=$(mktemp -d)
trap 'rm -rf -- "$tmpd"' EXIT

${BINDIR}/mkcomposefs --from-file $ASSET_DIR/special.dump $tmpd/out.cfs
${BINDIR}/composefs-info --filter=chardev --filter=inline --filter=whiteout dump $tmpd/out.cfs > $tmpd/dump.txt
foundlines=$(wc -l < $tmpd/dump.txt)
if test "${foundlines}" != "4"; then
    fatal "Filtered dump failed, expected 4 lines, found $foundlines"
fi
assert_file_has_content $tmpd/dump.txt '^/ 0 40555.*trusted.foo1'
assert_file_has_content $tmpd/dump.txt '^/chardev 0 20777'
assert_file_has_content $tmpd/dump.txt '^/inline 15 100777.*FOOBAR'
assert_file_has_content $tmpd/dump.txt '^/whiteout 0 20777'
echo "ok"
