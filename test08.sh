#!/bin/sh
# test Encryption and Decryption functionality with a valid key passed in Decryption
set -x
echo dummy test > in.test.$$
/bin/rm -f out.test.$$
.././xcpenc -e in.test.$$ out.test.$$ -p password

.././xcpenc -d out.test.$$ decrpty.test.$$ -p password

# now verify that the two files are the same
if cmp in.test.$$ decrpty.test.$$ ; then
        echo "xcpenc: input and output files contents are the same"
        exit 0
else
        echo "xcpenc: input and output files contents DIFFER"
        exit 1
fi
