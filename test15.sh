#!/bin/sh
# test: Extra credit tasks validation. Support for multiple ciphers handling padding as well.
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -e in.test.$$ out.test.$$ -p password -l 256 -C "xts(aes)"
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
