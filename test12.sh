#!/bin/sh
# test: Passing invalid input filename
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c in.test1235666 out.test.$$
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
