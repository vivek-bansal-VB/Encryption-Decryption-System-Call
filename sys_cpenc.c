#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include "struct.h"
// Reference : https://people.netfilter.org/rusty/unreliable-guides/kernel-hacking/routines-kmalloc.html
#include <linux/slab.h>
//#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/random.h>

#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs_stack.h>

#define HASH_LENGTH 16
#define BLOCK_SIZE_CIPHER 4096

asmlinkage extern long (*sysptr)(void *arg);

/* reference: https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html#code-example-for-symmetric-key-cipher-operation
I took help from above to populate skcipher_def data and tcrypt_result structures */
/* tie all data structures together */
struct tcrypt_result {
    struct completion completion;
    int err;
};

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* reference: https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html#code-examples */
/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    printk("Encryption finished successfully\n");
}

/* Reference: https://stackoverflow.com/questions/16861332/how-to-compute-sha1-of-an-array-in-linux-kernel
https://stackoverflow.com/questions/11126027/using-md5-in-kernel-space-of-linux
I took help from the above links in calculating the hash value of the key */
long computehash(void* key, int len, char* hash_val){
	// Declaration part
	struct shash_desc* desc;
	desc = kmalloc(sizeof(*desc), GFP_KERNEL); 

	// Initialisation part
	desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc->tfm))
		return PTR_ERR(desc->tfm);

	// Hashing part
	crypto_shash_init(desc);
	crypto_shash_update(desc, key, len);
	crypto_shash_final(desc, hash_val);

	//cleanup
	crypto_free_shash(desc->tfm);
	kfree(desc);
	return 0;
}

/* Reference: https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html#code-example-for-symmetric-key-cipher-operation */
/* took help from above link to encrypt and decrypt the data */
int perform_cipher(void* key, unsigned int keylen, char* data, int datalen, int isencrypt, char* cipher_algo)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	char src[16] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'};
	int ret = 0;

	skcipher = crypto_alloc_skcipher(cipher_algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(skcipher)) {
        	printk("could not allocate skcipher handle\n");
        	return PTR_ERR(skcipher);
	}

    	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    	if (!req) {
        	printk("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
    	}

   	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

	if (crypto_skcipher_setkey(skcipher, (char*)key, keylen)) {
        	printk("key could not be set\n");
        	ret = -EAGAIN;
		goto out;
    	}

	/* IV will be of 16 bytes */
	ivdata = kmalloc(16, GFP_KERNEL);
    	if (!ivdata) {
        	printk("could not allocate ivdata\n");
		ret = -ENOMEM;
		goto out;
    	}
        memcpy(ivdata, src, 16);
        sk.tfm = skcipher;
        sk.req = req;

        /* We encrypt one block of 16 bytes */
        sg_init_one(&sk.sg, data, datalen);
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 1, ivdata);
        init_completion(&sk.result.completion);
       
	 /* encrypt data */
        if (isencrypt)
                ret = crypto_skcipher_encrypt(sk.req);
        else
                ret = crypto_skcipher_decrypt(sk.req);

        switch (ret) {
                case 0:
                        break;
                case -EINPROGRESS:
                case -EBUSY:
                        ret = wait_for_completion_interruptible(
                                &sk.result.completion);
                         if (!ret && !sk.result.err) {
                                reinit_completion(&sk.result.completion);
                                break;
                         }
                default:
                        printk("skcipher encrypt returned with %d result %d\n", ret, sk.result.err);
                        break;
        }
 
        init_completion(&sk.result.completion);

out:
	if (skcipher)
        	crypto_free_skcipher(skcipher);
        if (req)
        	skcipher_request_free(req);
        if (ivdata)
                kfree(ivdata);
	return ret;
	
}

/* reference : https://www3.cs.stonybrook.edu/~ezk/cse506-s19/hw1.txt */
asmlinkage long cpenc(void* arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	if (arg == NULL){
		return -EINVAL;
	}
	else
	{
		long error_val = 0, err_code = 0, ret_value = 0;
		void* kaddr = NULL, *buf = NULL;
		//struct filename *inputfilename = NULL, *outputfilename = NULL;
                struct file* filp_read = NULL,  *filp_write = NULL;
		struct mystruct* kaddr_struct = NULL, *vaddr_struct = NULL;
		int read_bytes = 0, write_bytes = 0, total_bytes = 0, isencrypt = 0, i = 0, cipher_length = 0;
		mm_segment_t old_fs;
		char* hash_val = NULL, *buf1 = NULL;
		struct dentry* parent_dentry = NULL;
		struct path filepath;

		/* checking whether access on user space is valid */
		if(!access_ok(VERIFY_READ, (void*)arg, sizeof(struct mystruct)))
		{
			error_val = -EFAULT;
			goto failure;
		}

		/* creating an area for kernel address space */
	        kaddr = kmalloc(sizeof(struct mystruct), GFP_KERNEL);
		if(kaddr == NULL){
			error_val = -ENOMEM;
			goto failure;
		}

		/* copying data from user space to kernel space */
		if(copy_from_user(kaddr, arg, sizeof(struct mystruct))){
			error_val = -EFAULT;
			goto failure;
		}

		/* creating a structure into kernel space from the kaddr created above */
		kaddr_struct = (struct mystruct*)kaddr;
		vaddr_struct = (struct mystruct*)arg;
		if(kaddr_struct == NULL || vaddr_struct == NULL){
                        error_val = -EINVAL;
                        goto failure;
		}
		kaddr_struct->keylen = vaddr_struct->keylen;
		kaddr_struct->flags = vaddr_struct->flags;	
		kaddr_struct->encrypt_size = vaddr_struct->encrypt_size;
		kaddr_struct->cipher_name = NULL;

		if(vaddr_struct->infile == NULL){
                        error_val = -EINVAL;
                        goto failure;
		}
		if(vaddr_struct->outfile == NULL){
                        error_val = -EINVAL;
                        goto failure;
                }
		/*inputfilename = getname(vaddr_struct->infile);
		if(inputfilename == NULL){
			 error_val = -EINVAL;
			 goto failure;
		}
		kaddr_struct->infile = (char*)inputfilename->name;
		if(vaddr_struct->outfile == NULL){
                        error_val = -EINVAL;
                        goto failure;
		}
                outputfilename = getname(vaddr_struct->outfile);
		if(outputfilename == NULL){
                        error_val = -EINVAL;
                        goto failure;
		}
                kaddr_struct->outfile = (char*)outputfilename->name;
		*/

		/* invalid combination of flags passed : so bad */
		if(kaddr_struct->flags != 0x01 && kaddr_struct->flags != 0x02 && kaddr_struct->flags != 0x04){
                        error_val = -EINVAL;
                        goto failure;
		}

		/* validation checks on password provided from user */
		if(vaddr_struct->keybuf == NULL){
			if(kaddr_struct->keylen || (kaddr_struct->flags != 0x04)){
                        	error_val = -EINVAL;
                        	goto failure;	
			}
			kaddr_struct->keybuf = NULL;
		}
		else{
			if((kaddr_struct->keylen < 6) || (kaddr_struct->flags != 0x01 && kaddr_struct->flags != 0x02)){
                                error_val = -EINVAL;
                                goto failure;
			}

                	if(! access_ok(VERIFY_READ,vaddr_struct->keybuf, vaddr_struct->keylen)){
                        	error_val = -EFAULT;
                        	goto failure;
			}
                	kaddr_struct->keybuf = kmalloc(vaddr_struct->keylen, GFP_KERNEL);
                	if(kaddr_struct->keybuf == NULL){
                        	error_val = -ENOMEM;
                        	goto failure;
			}
        		if(copy_from_user(kaddr_struct->keybuf, vaddr_struct->keybuf, vaddr_struct->keylen)){                			
				error_val = -EFAULT;
                        	goto failure;
			}
			
			cipher_length = strlen((char*)vaddr_struct->cipher_name);
	                if(! access_ok(VERIFY_READ, vaddr_struct->cipher_name, cipher_length)){
                                error_val = -EFAULT;
                                goto failure;
                        }
			kaddr_struct->cipher_name = kmalloc(cipher_length + 1, GFP_KERNEL);
			if(kaddr_struct->cipher_name == NULL){
                                error_val = -ENOMEM;
                                goto failure;
			}
                        if(copy_from_user(kaddr_struct->cipher_name, vaddr_struct->cipher_name, cipher_length)){
                                error_val = -EFAULT;
                                goto failure;
                        }
			kaddr_struct->cipher_name[cipher_length] = '\0';
		}
      		
		/* Now we come here : that means input is valid whoaa !!!
	           Start processing the files */		
                        filp_read = filp_open(vaddr_struct->infile, O_RDONLY, 0);
                        if(!filp_read || IS_ERR(filp_read)){
                       		err_code = (long)PTR_ERR(filp_read);
                                printk("wrapfs_read_file err %ld\n", err_code);
                                error_val = -err_code;
                                goto failure;
                         }

		/* check if input file is directory or not */
			if(S_ISDIR(filp_read->f_inode->i_mode)){
				printk("Input file is a directory\n");
				error_val = -EIO;
				goto failure;
			}		
	
                        filp_write = filp_open(vaddr_struct->outfile, O_CREAT | O_WRONLY | O_TRUNC, filp_read->f_inode->i_mode);
                        if(!filp_write || IS_ERR(filp_write)){
                        	err_code = (long)PTR_ERR(filp_write);
                                printk("wrapfs_write_file err %ld\n", err_code);
                                error_val = -err_code;
                                goto failure;
                                }

			/* checking whether input file and output file are same or not */
                        if(filp_read->f_path.dentry->d_inode->i_ino == filp_write->f_path.dentry->d_inode->i_ino){
                                printk("Input and Output files are same\n");
                                error_val = -EINVAL;
                                goto failure;
                        }

                        /* setting read and write offsets of files to 0 */
                        filp_read->f_pos = 0;
                        filp_write->f_pos = 0;
                        old_fs = get_fs();
                        set_fs(KERNEL_DS);

		switch(kaddr_struct->flags)
		{
			case 0x01:
				isencrypt = 1;
			case 0x02:
				/* compute hash value from the key */
				hash_val = (char*)kmalloc(HASH_LENGTH, GFP_KERNEL);
				memset(hash_val, 0, HASH_LENGTH);
				error_val = computehash(kaddr_struct->keybuf, kaddr_struct->keylen, hash_val);
				if(error_val != 0){
					printk("Unable to compute hash value of key\n");
					goto failure1;
				}
	
                               /* ivret = getinitialIVdata(&src);
                                if(ivret){
                                	error_val = ivret;
                                        goto failure1;
                                } */
				
				/* write hash_value to the output file so that it can be used later on while decrypting */
				if(isencrypt)
				{ /* Encryption case */
                                	write_bytes = vfs_write(filp_write, hash_val, HASH_LENGTH, &filp_write->f_pos);
                                	if(write_bytes != HASH_LENGTH){
                                        	printk("Write of hash value failed\n");
                                        	error_val = -EIO;
                                        	goto failure1;
                                	}
/*					
#ifdef EXTRA_CREDIT
		                        write_bytes = vfs_write(filp_write, src, 16, &filp_write->f_pos);
                                        if(write_bytes != 16){
                                                printk("Write of IV data failed\n");
                                                error_val = -EIO;
                                                goto failure1;
					}
#endif*/
				}
				else{ /* Decryption case */
					buf1 = kmalloc(HASH_LENGTH, GFP_KERNEL);
                                        read_bytes = vfs_read(filp_read, buf1, HASH_LENGTH, &filp_read->f_pos);
                                        if(read_bytes != HASH_LENGTH){
						printk("Decryption validity of hash failed1\n");
						error_val = -EIO;
                                                goto failure1;
					}
					for(i = 0; i < HASH_LENGTH; i++)
						if(buf1[i] != hash_val[i]){
                                                	printk("Decryption validity of hash failed2 at index: %d\n", i);
                                                	error_val = -EIO;
                                                	goto failure1;
						}
/*
#ifdef EXTRA_CREDIT
	                                read_bytes = vfs_read(filp_read, src, 16, &filp_read->f_pos);
                                        if(read_bytes != 16){
                                                printk("Validity of IV failed while decryption\n");
                                                error_val = -EIO;
                                                goto failure1;
                                        }
#endif*/
					total_bytes += HASH_LENGTH;
				}

				if(buf1)
					kfree(buf1);
				if(hash_val)
					kfree(hash_val);

				/* Reference: https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html#code-example-for-symmetric-key-cipher-operation */
				/* took help from above link to encrypt and decrypt the data */
				while(total_bytes < filp_read->f_inode->i_size){
					buf1 = kmalloc(kaddr_struct->encrypt_size, GFP_KERNEL);
                                        if(buf1 == NULL){
                                                error_val = -ENOMEM;
                                                goto failure1;
                                        }

					read_bytes = vfs_read(filp_read, buf1, kaddr_struct->encrypt_size, &filp_read->f_pos);

					ret_value = perform_cipher(kaddr_struct->keybuf, kaddr_struct->keylen, buf1, read_bytes, isencrypt,  kaddr_struct->cipher_name);

					if(ret_value){
						error_val = ret_value;
						kfree(buf1);
						printk("performing cipher failed\n");
						goto failure1;
					}
					write_bytes = vfs_write(filp_write, buf1, read_bytes, &filp_write->f_pos);
					total_bytes += kaddr_struct->encrypt_size;
					kfree(buf1);
				}
				error_val = 0;
				break;

			case 0x04: /* reading from inputfile and writing to outputfile */
                		while(true)
                		{
                        		buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
                        		memset(buf, 0, PAGE_SIZE);
                        		if(buf == NULL){
                                		error_val = -ENOMEM;
                                		goto failure1;
                        		}
                        		read_bytes = vfs_read(filp_read, buf, PAGE_SIZE, &filp_read->f_pos);
					if(read_bytes == 0){
						kfree(buf);
						break;
					}
                        		write_bytes = vfs_write(filp_write, buf, read_bytes, &filp_write->f_pos);
					total_bytes += write_bytes;
                        		kfree(buf);
                        		if(read_bytes < PAGE_SIZE)
                                		break;
                		}

				error_val = 0;
				break;

			default:
				goto failure1;
		}

	/* Handling of case when there are partial written files */
	if(filp_read->f_inode->i_size > total_bytes){
		if(filp_write){
			filepath = filp_write->f_path;
			parent_dentry = filepath.dentry->d_parent;
                	filp_close(filp_write, NULL);
			filp_write = NULL;
			if(unlikely(!spin_trylock(&parent_dentry->d_lock))){
				printk("Not able to delete partial written files");
				error_val = -EAGAIN;
				goto failure1;
			}
			error_val = vfs_unlink(filepath.dentry->d_parent->d_inode, filepath.dentry, NULL);
			spin_unlock(&parent_dentry->d_lock);
		}		
        }

	failure1:
		set_fs(old_fs);
	
	failure:
		if(kaddr_struct->cipher_name)
			kfree(kaddr_struct->cipher_name);
		if(kaddr_struct->keybuf)
			kfree(kaddr_struct->keybuf);
		if(kaddr)
			kfree(kaddr);
		if(filp_read && !IS_ERR(filp_read))
		        filp_close(filp_read, NULL);
		if(filp_write && !IS_ERR(filp_write))
                       filp_close(filp_write, NULL);
		return error_val;
	}
}

static int __init init_sys_cpenc(void)
{
	printk("installed new sys_cpenc module\n");
	if (sysptr == NULL)
		sysptr = cpenc;
	return 0;
}
static void  __exit exit_sys_cpenc(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
