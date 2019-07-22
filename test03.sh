#!/bin/sh
# test: Output file missing from the command line
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c in.test.$$
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
