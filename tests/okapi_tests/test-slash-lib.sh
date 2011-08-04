#!/bin/sh

source okapi_test_common.sh
okapi_test_init # call init function

# ok, we're gonna try to copy ALL of /lib into $TESTDIR, which should be fun!
for f in `find /lib`
do
  $OKAPI_BIN $f "" $TESTDIR
done

# also copy the entirety of /usr/src/kernels since something in lib references it
for f in `find /usr/src/kernels`
do
  $OKAPI_BIN $f "" $TESTDIR
done

pushd $TESTDIR > /dev/null
find . | xargs file | sort > contents.txt
popd > /dev/null

diff -u $TESTDIR/contents.txt $TESTNAME.golden
