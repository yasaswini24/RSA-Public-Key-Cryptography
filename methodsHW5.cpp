//HW5 Functions . . . (provided by "The Saleh Darzi" :D)

/* ==================================================================
                        Getting LibTomMath
=====================================================================
====You Must download and install LibTomMath and ReConfigure your LibTomCrypt====
*For getting LibTomMath:
        $ git clone https://github.com/libtom/libtommath.git
        $ mkdir -p libtommath/build
        $ cd libtommath/build
        $ cmake ..
        $ make -j$(nproc)
* For reconfigureation of LibTomCrypt, go to LibTomCrypt directory:
        $ sudo make install CFLAGS="-DUSE_LTM -DLTM_DESC" EXTRALIBS="-ltommath"
*/


/*==========================================================================
                                Notes
============================================================================
* * * * *You can define each function and then use them as a solution to the HW5
        Or you can put the content of each function appropriately in your main function 
        (That's why I have provided the raw functions for you to better undestand them).

* * * * *Put this at the beggining of your main function to use LibTomMath:
        ltc_mp=ltm_desc;

* * * * *I have provided the "RSA Key Generation" and "RSA Key Export" function for completeness or if you
        liked to create your own sets of keys instead of importing my keys.
        1. You run the PRNG
        2. You create rsa_key
        3. You can export the Public Key and send it to the other side via ZeroMQ (Alice->Bob and Bob->Alice)
        4. You can use the appropriate keys for Encryption, Decryption, Signature, and Verification
*/

/*******************************
      H e a d e r s
*******************************/
#define LTM_DESC
#define USE_LTM
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <fstream>
#include <tomcrypt.h>
#include <string>
#include <math.h>


//===================SHA256 Function=========================================
unsigned char* hashSHA2(unsigned char *input)
{
    unsigned char *hash_res = new unsigned char[sha256_desc.hashsize];
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*) input, sha256_desc.hashsize);
    sha256_done(&md, hash_res);
    return hash_res;
}

//=====Use this function=====
rsa_key Import_Key(unsigned char *in,/*the input key*/
                    unsigned long inlen,/*the input key length*/
                    rsa_key *key/*the output would be stored in this data structure*/){
    int err;
    if ((err = rsa_import(in,
                          inlen,
                          key)
    ) != CRYPT_OK) {
        printf("Error in importing rsa key: %s\n", error_to_string(err));
        exit(-1);
   }
   return *key;
}


//=====Use this function=====
void Do_RSA_Encryption(const unsigned char* in, /*The message*/
                        unsigned long inlen,/*message length*/
                        unsigned char *out, /*The ciphertext*/
                        unsigned long *outlen, /*ciphertext length*/
                        prng_state *prng, /*the utilized PRNG*/
                        rsa_key *key/*This is Bob's key*/) {
    int err;
    if ((err = rsa_encrypt_key_ex(in,
                                inlen,
                                out,
                                outlen,
                                (const unsigned char*)"SalehDarzi",
                                10,
                                prng,
                                find_prng("fortuna"),
                                find_hash("sha256"),
                                LTC_PKCS_1_OAEP,
                                key)
        ) != CRYPT_OK) {
            printf("RSA Encryption Failure %s", error_to_string(err));
            exit(-1);
        }
}

/****************************************************************************
                            RSA Decryption
****************************************************************************/

//======Use-case======
void Do_RSA_Decryption(const unsigned char *in,/*The Ciphertext*/
                        unsigned long inlen, /*ciphertext length*/
                        unsigned char *out,/*The plaintext*/
                        unsigned long *outlen,/*plaintext length*/
                        rsa_key *key/*this is Bob's key*/){
    int err;
    int stat=1;
    if ((err = rsa_decrypt_key_ex(in,
                                inlen,
                                out,
                                outlen,
                                (const unsigned char*)"SalehDarzi",
                                10,
                                find_hash("sha256"),
                                LTC_PKCS_1_OAEP,
                                &stat,
                                key)
    ) != CRYPT_OK) {
            printf("RSA Decryption Failure %s", error_to_string(err));
            exit(-1);
    }
}

/****************************************************************************
                            RSA Signature
****************************************************************************/
//======Use this function=====
void Do_RSA_Sign(const unsigned char *in,/*The ciphertext*/
                 unsigned long inlen,/*ciphetext length*/
                 unsigned char *out,/*The Signature*/
                 unsigned long *outlen,/*Signature length*/
                 prng_state *prng, /*This is the utilized PRNG*/
                 rsa_key *key/*This is Alice's key*/){
    int err;
    if((err = rsa_sign_hash_ex(in,
                               inlen,
                               out,
                               outlen,
                                LTC_PKCS_1_PSS,
                               prng,
                               find_prng("fortuna"),
                               find_hash("sha256"),
                               8,
                               key)
    ) != CRYPT_OK) {
            printf("RSA Signature Failure %s", error_to_string(err));
            exit(-1);
    }
}
/****************************************************************************
                            RSA Verification
****************************************************************************/

//=====Use this function=====
int* Do_RSA_Verify(const unsigned char *sig,/*The signature*/
                 unsigned long siglen, /*signature length*/
                 unsigned char *hash, /*the hash*/
                 unsigned long hashlen, /*the hash length*/
                 int *stat, /*this is the output of you verification, [zero:fail, non-zero:pass]*/
                 rsa_key *key/*This is Alice's key*/){

    int err;
    if((err = rsa_verify_hash_ex(sig,
                                   siglen,
                                   hash,
                                   hashlen,
                                   LTC_PKCS_1_PSS,
                                   find_hash("sha256"),
                                   8,
                                   stat,
                                   key)
        ) != CRYPT_OK) {
                printf("RSA Verification Failure %s", error_to_string(err));
                exit(-1);
        }
        return stat;
} 





