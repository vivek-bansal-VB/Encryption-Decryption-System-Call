#!/bin/sh
# test: Invalid command line argument
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c -e in.test.$$ out.test.$$ -p password
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
