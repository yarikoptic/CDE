#!/bin/sh

source okapi_test_common.sh
okapi_test_init # call init function

mkdir "$OKAPI_TESTDIR/java-test"
$OKAPI_BIN /usr/bin/java "" "$OKAPI_TESTDIR/java-test"
pushd $OKAPI_TESTDIR/java-test > /dev/null
find . | xargs file | sort > contents.txt
popd > /dev/null
diff -u $OKAPI_TESTDIR/java-test/contents.txt java-test.golden
