#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "struct.h"
#include <string.h>
#include <openssl/evp.h>

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

/* Reference: https://stackoverflow.com/questions/9771212/how-to-use-pkcs5-pbkdf2-hmac-sha1 */
#define KEK_KEY_LEN  16 // default key length of ctr(aes) is 128 bits.
#define ITERATION    1000
#define ENCRYPT_SIZE 4096
#define DEFAULT_CIPHER "ctr(aes)"

/* When user has given -h option */
void helpmessages(char *argv[])
{
	printf("Usage: %s [-p password] [-e | -d | -c] [inputfilename outputfilename]\n", argv[0]);
	printf("Use -e for encrypt file\n");
	printf("Use -d for decrypt file\n");
	printf("Use -c for copy file\n");
	printf("Use -h for help messages\n");
	printf("Use -p for password\n");
#ifdef EXTRA_CREDIT
	printf("Use -C for cipher name\n");
	printf("Use -l for key length in bits\n");
	printf("Use -u for encryption size in bytes\n");
#endif
}

/* When error occurs in the input */
void showerrormessages(char *argv[])
{
	printf("Usage: %s [-p password] [-e | -d | -c] [inputfilename outputfilename] [-C] [Cipher Name] [-l] [keylength size] [-e] [encryption block size]\n", argv[0]);
}

int main(int argc, char *argv[])
{
    int rc = 0, opt;
    int encrypt = 0, decrypt = 0, copy_flag = 0, error_flag = 0, normal_exit = 0; 
    char myoptarg[12] = {'e', 'd', 'c', 'p', ':', 'C', ':', 'l', ':', 'u', ':', 'h'};
    char *inputfile = NULL, *outputfile = NULL, *pwd_key = NULL;
    unsigned int keylen = 0, flag = 0, len = 0, mylength = 0;
    struct mystruct obj;
    extern char *optarg;
    extern int optind, optopt;
    void *out = NULL;
    /* Reference: https://stackoverflow.com/questions/9771212/how-to-use-pkcs5-pbkdf2-hmac-sha1 */
    unsigned char salt_value[] = {'s', 'a', 'l', 't'};	
    char* cipher_name = NULL;
    int encrypt_size = 0;
#ifdef EXTRA_CREDIT
    int key_length = 0;
#endif

/*  Reference : https://linux.die.net/man/3/getopt
	       http://pubs.opengroup.org/onlinepubs/009695399/functions/getopt.html */
											 	
    /* parsing arguments of command line and validating input from the user */
    while ((opt = getopt(argc, argv, (char*)myoptarg)) != -1) {
	if(error_flag == 1)
		break;
        switch (opt) {
        case 'e':
            encrypt = 1;
	    flag |= 0x1;
	    if(decrypt || copy_flag) /* both encrypt and decrypt/copy not valid */
		error_flag = 1;
            break;
        case 'd':
	    decrypt = 1;
	    flag |= 0x2;
	    if(encrypt || copy_flag) /* both decyrpt and encrypt/copy not valid */
		error_flag = 1;
            break;
	case 'c':
	    copy_flag = 1;
            flag |= 0x4;
	    if(encrypt || decrypt) /* both copy and encrypt/decrypt not valid */
		error_flag = 1;
	    break;
	case 'p': /* password case */
		pwd_key = malloc(strlen(optarg) + 1);
		memset(pwd_key, 0, strlen(optarg) + 1);
        	strcpy(pwd_key, optarg);
		keylen = strlen((char*)pwd_key);
		break;
	case 'h': /* option for help */
		helpmessages(argv);
		goto exit_block;
		break;

#ifdef EXTRA_CREDIT
        case 'C': /* cipher name */
                cipher_name = malloc(strlen(optarg) + 1);
                memset(cipher_name, 0, strlen(optarg) + 1);
                strcpy(cipher_name, optarg);
                cipher_name[strlen(optarg)] = '\0';
		printf("Cipher name is %s\n", cipher_name);
                break;
        case 'l': /* key length in bits */
                key_length = atoi(optarg);
		if(key_length == 0 || (key_length % 8 != 0)){
			printf("Invalid Key length bytes are given by the user\n");
			goto exit_block;
		}
                key_length = key_length / 8; /* converting to bytes */
                break;
        case 'u': /* encryption size in bytes */
                encrypt_size = atoi(optarg);
                if(encrypt_size == 0){
                        printf("Invalid encryption size\n");
                        goto exit_block;
                } 
                break;
#endif

	case ':': /* -p without operand */
		printf("Option -%c requires an operand for the valid command line\n", optopt);
		goto exit_block;

        default:
		error_flag = 1;
		break;
       	   }	
	}

    /* more than 2 arguments are there which don't have optional flag */
    /*if((argc - optind) != 2){
        printf("Only inputfile and outfile should be passed without optional flags\n");
        goto exit_block;
    }*/
	
    /* Input/Output file missing from command line */
    if(argv[optind] == NULL || argv[optind + 1] == NULL){
	printf("Input/Output file missing from command line\n");
	goto exit_block;
    } 

    /* both inout and output files are same which is not possible */
    if(!strcmp(argv[optind], argv[optind + 1])){
        printf("Input and output files are same\n");
        goto exit_block;
    }
	
    /* atleast one out of 3 options: encrypt, decrypt and copy should be set */
    if(!encrypt && !decrypt && !copy_flag){
	printf("Atleast one of encrpyt, decrypt or copy should be enabled\n");
	goto exit_block;
    }
	
    /* if getopt signals some error, then show error message and exit */
    if(error_flag == 1){
	showerrormessages(argv);
	goto exit_block;
    } 

    /* if -p option occurs in the command */
    if(pwd_key != NULL){
	if(!encrypt && !decrypt) /* no encryption and decyrption required */
		printf("Ignoring cipher key since we don't want to encrypt or decrypt the file\n");
	else if(strlen((char*)pwd_key) < 6){ /* password too short */
                printf("Password too short\n");
                goto exit_block;
	}

	mylength = KEK_KEY_LEN;
#ifdef EXTRA_CREDIT
	if(key_length)
		mylength = key_length;
#endif
	/* Reference: https://stackoverflow.com/questions/9771212/how-to-use-pkcs5-pbkdf2-hmac-sha1 */
    	out = malloc(mylength);
        if( !PKCS5_PBKDF2_HMAC_SHA1(pwd_key, keylen, salt_value, sizeof(salt_value), ITERATION, mylength, out)){
		printf("PKCS5_PBKDF2_HMAC_SHA1 failed\n");
		goto exit_block;
	}
    }
    else{
	if(encrypt || decrypt){
		printf("Password key is missing in encryption/decryption\n");
		goto exit_block;
	}
    }

    inputfile = malloc(strlen(argv[optind]) + 1);
    if(inputfile == NULL){
	goto exit_block;
    }
    memset(inputfile, 0, strlen(argv[optind]) + 1);
    strcpy(inputfile, argv[optind]);

    outputfile = malloc(strlen(argv[optind + 1]) + 1);
    if(outputfile == NULL){
        goto exit_block;
    }
    memset(outputfile, 0, strlen(argv[optind + 1]) + 1);
    strcpy(outputfile, argv[optind + 1]);

    /* packing arguments in a structure to send them to the kernel */
    obj.infile = inputfile;
    obj.outfile = outputfile;

    if(out == NULL)
	len = 0;
    else
	len = mylength;
    obj.keybuf = out;
    obj.keylen = len;
    obj.flags = flag;

#ifdef EXTRA_CREDIT
    if(cipher_name)
    	obj.cipher_name = cipher_name;
    if(encrypt_size)
    	obj.encrypt_size = encrypt_size;
#endif

    if(cipher_name == NULL){
   	cipher_name = malloc(strlen(DEFAULT_CIPHER) + 1);
        memset(cipher_name, 0, strlen(DEFAULT_CIPHER) + 1);
        strcpy(cipher_name, DEFAULT_CIPHER);
        cipher_name[strlen(DEFAULT_CIPHER)] = '\0';
        obj.cipher_name = cipher_name;
    }
    if(encrypt_size == 0){
	obj.encrypt_size = ENCRYPT_SIZE;
    }

    rc = syscall(__NR_cpenc,(void*)&obj);
    if (rc == 0)
	printf("syscall returned %d\n", rc);
    else
	printf("syscall returned %d (errno=%d)\n", rc, errno);
    
    normal_exit = 1;

exit_block :
	if(inputfile)
		free(inputfile);
	if(outputfile)
		free(outputfile);
	if(pwd_key)
		free(pwd_key);
	if(out)
		free(out);
	if(cipher_name)
		free(cipher_name);
	if(normal_exit){
		exit(rc);
	}
	else{
		exit(EXIT_FAILURE);
	}
}
