# Encryption-Decryption-System-Call

* PURPOSE:

To get your Linux kernel development environment working; to make small
changes to the kernel and test them out; to learn about system calls.

* BACKGROUND:

Encrypting files is very useful and important nowadays, but many OSs do not
support this feature natively (yet).  Your task is to create a new system
call that can take an input file, encrypt or decrypt it, and then produce an
output file.

Note that while we give you more details below, it is up to you to inspect
the kernel sources to find out similar helpful examples of code; those will
provide you with even greater details than what we provide here.

The expected amount of written code for this assignment would be 500-700
lines of kernel code, and another 200-300 lines of user-level code; plus
some shell scripts to prove you've tested your code.  Note, however, that a
lot of time may be spent reading existing sources and debugging the code you
write.

* TASK:

Create a Linux kernel module (in vanilla 4.20.y Linux that's in your HW1 GIT
repository) that, when loaded into Linux, will support a new system call
called

	sys_cpenc(infile, outfile, keybuf, keylen, flags)

where "infile" is the name of an input file to encrypt or decrypt, "outfile"
is the output file, "keybuf" is a buffer holding the cipher key, "keylen" is
the length of that buffer, and "flags" determine if you're encrypting or
decrypting.

If "flags & 0x1" is non-zero, then you should encrypt the infile onto outfile.
If "flags & 0x2" is non-zero, then you should decrypt the infile onto outfile.
If "flags & 0x4" is non-zero, then you should just copy the infile to outfile.

An unencrypted (cleartext) file is just a sequence of arbitrary bytes.  An
encrypted (ciphertext) file has two sections.  The first section is a fixed
length "preamble" and contains some information to validate the decryption
key (e.g., a secure hash/checksum of the user-level pass-phrase).  This
first section may include other information as you see fit (e.g., original
file size, and stuff for validating extra-credit part of this
assignment---see below).  The second section is just the input file data,
encrypted as per the cipher block size, cipher key, etc.  With this header,
for example, you can verify in the kernel that the user is passing the same
decryption key that was used to encrypt the file (else error).

The most important thing system calls do first is ensure the validity of the
input they are given.  You must check for ALL possible bad conditions that
could occur as the result of bad inputs to the system call.  In that case,
the system call should return the proper errno value (EINVAL, EPERM, EACCES,
etc.)  Consult the system errno table and pick the right error numbers for
different conditions.

The kinds of errors that could occur early during the system call's
execution are as follows (this is a non-exhaustive list):

- missing arguments passed
- null arguments
- pointers to bad addresses
- keylen and length of keybuf don't match
- invalid flags or combinations of flags
- input file cannot be opened or read
- output file cannot be opened or written
- input or output files are not regular, or they point to the same file
- trying to decrypt a file w/ the wrong key (what errno should you return?)
- ANYTHING else you can think of (the more error checking you do, the better)

After checking for these errors, you should open the input and output files
and begin copying data between the two, optionally encrypting or decrypting
the data before it is written.  Your code must be efficient.  Therefore, do
not waste extra kernel memory (dynamic or stack) for the system call.  Make
sure you're not leaking any memory.  On the other hand, for efficiency, you
should copy the data in chunks that are native to the system this code is
compiled on, the system page size (PAGE_CACHE_SIZE or PAGE_SIZE).  Hint:
allocate one page as temporary buffer.

Note that the last page you write could be partially filled.  So your code
should handle files whose size isn't a perfect multiple of the page size, as
well as zero length files.  Also note that ciphers have a native block size
(e.g., 64 bit) and your file may have to be padded to the cipher block size.
Lastly, certain ciphers/modes don't care about blocking sizes so they won't
need padding; I recommend you use the "CTR" mode of encryption, so you don't
have to worry about such padding.

The output file should be created with the user/group ownership of the
running process, and its protection mode should NOT be less than the input
file.

Both the input and output files may be specified using relative or absolute
pathnames.  Do not assume that the files are always in the current working
directory.

If no error occurred, sys_cpenc() should return 0 to the calling process.
If an error occurred, it should return -1 and ensure that errno is set for
the calling process.  Choose your errno's appropriately.

If an error occurred in trying to write some of the output file, the system
call should NOT produce a partial output file.  Instead, remove any
partially-written output file and return the appropriate error code.

Write a C program called "tcpenc" that will test call your syscall.  The
program should have no output upon success and use perror() to print out
information about what errors occurred.  The program should take three
arguments:

- flag: -e to encrypt; -d to decrypt; -c to copy
- flag: -C ARG to specify the type of cipher (as a string name)
  [Note: this flag is mainly for the extra credit part]
- flag: -p ARG to specify the encryption/decryption key if needed
- flag: -h to provide a helpful usage message
- input file name
- output file name
- any other options you see fit.

