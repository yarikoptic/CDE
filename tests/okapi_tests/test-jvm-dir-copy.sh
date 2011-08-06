#!/bin/sh

source okapi_test_common.sh
okapi_test_init # call init function

COPY_DIR_BIN="python /home/pgbovine/CDE/scripts/copy_dir_into_package.py"

rm -rf cde-package/
mkdir -p cde-package/cde-root/

$COPY_DIR_BIN /usr/lib/jvm/ cde-package/

diff -ur /usr/lib/jvm/ cde-package/cde-root/usr/lib/jvm/ # should show no diffs

rm -rf cde-package/
