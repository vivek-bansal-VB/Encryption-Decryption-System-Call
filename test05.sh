#!/bin/sh
# test: Password missing from command line with -p flag
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c in.test.$$ out.test.$$ -p
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
