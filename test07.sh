#!/bin/sh
# test: Password length less than 6
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -e in.test.$$ out.test.$$ -p pass
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
