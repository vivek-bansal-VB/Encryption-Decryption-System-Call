#!/bin/sh
# test: Extra credit tasks validation. Invalid cipher name passed in -C flag
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -e in.test.$$ out.test.$$ -p password -l 128 -u 256 -C junk
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
