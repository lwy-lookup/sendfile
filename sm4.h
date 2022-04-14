/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifndef SM4_H
#define SM4_H

#include <string.h>
#include <stdio.h>

# define SMS4_KEY_LENGTH        16
# define SMS4_BLOCK_SIZE        16
# define SMS4_IV_LENGTH        (SMS4_BLOCK_SIZE)
# define SMS4_NUM_ROUNDS        32

# define SM4_ERROR_UNKNOW                      -1
# define SM4_MALLOC_FAIL                       -2
# define SM4_BAD_KEY_LENGTH                    -3
# define SM4_BAD_PADDING_FORMAT                -4
# define SM4_BAD_LENGTH                        -5

#define FAR
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
//typedef long long   __int64;
//typedef __int64 int64_t;
//typedef unsigned __int64 uint64_t;

//typedef   unsigned int size_t ;

extern const uint8_t SMS4_S[256];
extern const uint32_t SMS4_T[256];
extern const uint32_t SMS4_D[65536];

typedef struct {
    uint32_t rk[SMS4_NUM_ROUNDS];
} sms4_key_t;

typedef struct {
    sms4_key_t k1;
    sms4_key_t k2;
    sms4_key_t k3;
} sms4_ede_key_t;

# define sms4_decrypt(in, out, key)  sms4_encrypt(in,out,key)
void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char user_key[16]);
void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char user_key[16]);
void sms4_encrypt(const unsigned char in[16], unsigned char out[16], const sms4_key_t *key);
void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key, int enc);

void sms4_ecb_encrypt_blocks(const uint8_t *in,int ilen, uint8_t *out, const sms4_key_t *key);
void sms4_ecb_decrypt_blocks(const uint8_t *in,int ilen, uint8_t *out, const sms4_key_t *key);
int sms4_ecb_decrypt_nopadding(const uint8_t *in,int ilen, uint8_t *out,int *olen , const sms4_key_t *key);
int sms4_ecb_encrypt_nopadding(const uint8_t *in,int ilen, uint8_t *out,int *olen, const sms4_key_t *key);
int sms4_ecb_encrypt_zeropadding(const uint8_t *in,int ilen, uint8_t *out,int *olen, const sms4_key_t *key);
int sms4_ecb_decrypt_zeropadding(const uint8_t *in,int ilen, uint8_t *out,int *olen, const sms4_key_t *key);
int sms4_ecb_encrypt_pkcs7padding(const uint8_t *in,int ilen, uint8_t *out,int *olen, const sms4_key_t *key);
int sms4_ecb_decrypt_pkcs7padding(const uint8_t *in,int ilen, uint8_t *out,int *olen, const sms4_key_t *key);

void sms4_cbc_encrypt_blocks(const unsigned char *in, int ilen, unsigned char *out,unsigned char *iv, const sms4_key_t *key);
void sms4_cbc_decrypt_blocks(const unsigned char *in, int ilen, unsigned char *out,unsigned char *iv, const sms4_key_t *key);
int sms4_cbc_decrypt_nopadding(const uint8_t *in,int ilen, uint8_t *out,int *olen, uint8_t *iv,const sms4_key_t *key);
int sms4_cbc_encrypt_nopadding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv, const sms4_key_t *key);
int sms4_cbc_encrypt_zeropadding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv, const sms4_key_t *key);
int sms4_cbc_decrypt_zeropadding(const uint8_t *in,int ilen, uint8_t *out,int *olen, uint8_t *iv, const sms4_key_t *key);
int sms4_cbc_encrypt_pkcs7padding(const uint8_t *in,int ilen, uint8_t *out,int *olen, uint8_t *iv, const sms4_key_t *key);
int sms4_cbc_decrypt_pkcs7padding(const uint8_t *in,int ilen, uint8_t *out,int *olen, uint8_t *iv, const sms4_key_t *key);

#endif