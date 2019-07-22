#!/bin/sh
# test: Input file is a directory
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -c ../Test out.test.$$
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
