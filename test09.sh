#!/bin/sh
# Encryption and Decryption without valid key in decryption
set -x
echo dummy test > ../infile.test
/bin/rm -f ../out.test
.././xcpenc -e ../infile.test ../out.test -p password
retval=$?
if test $retval != 0 ; then
        echo xcpenc failed with error: $retval
        exit $retval
else
        echo xcpenc program succeeded
fi
/bin/rm -f ../decty.test
.././xcpenc -d ../out.test ../decty.test -p password1
retval=$?
if test $retval != 0 ; then
        echo xcpenc decrption failed with error: $retval
        exit $retval
else
        echo xcpenc program decryption succeeded
fi
