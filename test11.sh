#!/bin/sh
# test: Extra credit testing by passing -l and -u and -C flags. Passing invalid key size which is not a multiple of 8
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c in.test.$$ out.test.$$ -p password -l 81
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
