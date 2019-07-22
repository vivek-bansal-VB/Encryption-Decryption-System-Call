#!/bin/sh
# test: Extra credit tasks validation of -l and -u flags
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -e in.test.$$ out.test.$$ -p password -l 128 -u 256
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi

