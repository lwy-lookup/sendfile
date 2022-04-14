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
#include "sm4.h"

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }

/*
 * Expanded SM4 S-boxes
 /* Sbox table: 8bits input convert to 8 bits output*/

static const uint8_t SboxTable[16][16] =
        {
                {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
                {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
                {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
                {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
                {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
                {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
                {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
                {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
                {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
                {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
                {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
                {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
                {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
                {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
                {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
                {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
        };

/* System parameter */
static const uint32_t FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};

/* fixed parameter */
static const uint32_t CK[32] =
        {
                0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
                0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
                0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
                0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
                0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
                0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
                0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
                0x10171e25,0x2c333a41,0x484f565d,0x646b7279
        };

/**
 * @brief padding zero
 * 
 */
int ZEROPadding(const uint8_t *input, int ilen, uint8_t *output, int *olen) {
	int padding_len = 0;
	if (ilen % 16 == 0) {
		padding_len = ilen + 16;
	}
	else {
		padding_len = ilen + (16 - ilen % 16);
	}
	memset(output, 0x00, sizeof(char) * padding_len);
	memcpy(output, input, ilen);
	*olen =  padding_len;
	return *olen;
}

int  ZEROUnpadding(uint8_t *input, int *ilen) {
	if ( *ilen % 16 != 0) {
		return SM4_BAD_PADDING_FORMAT;
	}
	while (*(input + *ilen - 1) == 0x00) {
		(*ilen)--;
	}
	return *ilen;
}

int	 PKCS7Padding(const uint8_t *input, int ilen, uint8_t *output , int *olen) {
    int len_after_Padding;
	uint8_t padding_value;
	if (ilen == 0)
	{
		return SM4_BAD_LENGTH;
	}
	padding_value = 16 - ilen % 16;
	len_after_Padding = ilen + padding_value;

	memset(output, 0x00, sizeof(char) * len_after_Padding);
	memcpy(output, input, ilen);
    int i;
	for (i = ilen; i < len_after_Padding; i++) {
		*(output + i) = padding_value;
	}
	*olen = len_after_Padding;	
	return *olen;
}

int PKCS7Unpadding(uint8_t *input, int *ilen) {
	if (*ilen % 16 != 0) {
		return SM4_BAD_PADDING_FORMAT;
	}
	uint8_t value = *(input + *ilen - 1);
	*ilen = *ilen - value;
	*(input + *ilen) = 0x00;
	return *ilen;
}



/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static uint8_t sm4Sbox(uint8_t inch)
{
    uint8_t *pTable = (uint8_t *)SboxTable;
    uint8_t retVal = (uint8_t)(pTable[inch]);
    return retVal;
}

/*
 * private F(Lt) function:
 * "T algorithm" == "L algorithm" + "t algorithm".
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
 */
static uint32_t sm4Lt(uint32_t ka)
{
    uint32_t bb = 0;
    uint32_t c = 0;
    uint8_t a[4];
    uint8_t b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb,b,0)
    c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
    return c;
}

/*
 * private F function:
 * Calculating and getting encryption/decryption contents.
 * args:    [in] x0: original contents;
 * args:    [in] x1: original contents;
 * args:    [in] x2: original contents;
 * args:    [in] x3: original contents;
 * args:    [in] rk: encryption/decryption key;
 * return the contents of encryption/decryption contents.
 */
static uint32_t sm4F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk)
{
    return (x0^sm4Lt(x1^x2^x3^rk));
}


/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static uint32_t sm4CalciRK(uint32_t ka)
{
    uint32_t bb = 0;
    uint32_t rk = 0;
    uint8_t a[4];
    uint8_t b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}

void sms4_set_key(sms4_key_t *key, const uint8_t ukey[16]){
    uint32_t *SK = key->rk;
    uint32_t MK[4];
    uint32_t k[36];
    uint32_t i = 0;

    GET_ULONG_BE( MK[0], ukey, 0 );
    GET_ULONG_BE( MK[1], ukey, 4 );
    GET_ULONG_BE( MK[2], ukey, 8 );
    GET_ULONG_BE( MK[3], ukey, 12 );
    k[0] = MK[0]^FK[0];
    k[1] = MK[1]^FK[1];
    k[2] = MK[2]^FK[2];
    k[3] = MK[3]^FK[3];
    for( i = 0 ; i<32; i++)
    {
        k[i+4] = k[i] ^ (sm4CalciRK(k[i+1]^k[i+2]^k[i+3]^CK[i]));
        SK[i] = k[i+4];
    }
}

void sms4_set_encrypt_key(sms4_key_t *key, const uint8_t ukey[16])
{
    sms4_set_key(key,ukey);
}

void sms4_set_decrypt_key(sms4_key_t *key, const uint8_t ukey[16])
{
    sms4_set_key(key,ukey);
    int i;
    for(i = 0; i < 16; i ++ )
    {
        SWAP( key->rk[ i ], key->rk[ 31-i] );
    }
}

void sms4_encrypt(const uint8_t input[16], uint8_t output[16], const sms4_key_t *key)
{
    uint32_t i = 0;
    uint32_t ulbuf[36];

    memset(ulbuf, 0, sizeof(ulbuf));
    GET_ULONG_BE( ulbuf[0], input, 0 )
    GET_ULONG_BE( ulbuf[1], input, 4 )
    GET_ULONG_BE( ulbuf[2], input, 8 )
    GET_ULONG_BE( ulbuf[3], input, 12 )
    while(i<32)
    {
        ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], key->rk[i]);
        i++;
    }
    PUT_ULONG_BE(ulbuf[35],output,0);
    PUT_ULONG_BE(ulbuf[34],output,4);
    PUT_ULONG_BE(ulbuf[33],output,8);
    PUT_ULONG_BE(ulbuf[32],output,12);
}

void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const sms4_key_t *key, int enc)
{
    if (enc)
        sms4_encrypt(in, out, key);
    else    sms4_decrypt(in, out, key);
}

void sms4_ecb_encrypt_blocks(const uint8_t *in, int ilen, uint8_t *out,
                             const sms4_key_t *key)
{
    int blocks;
    blocks = ilen / 16;

    while (blocks--) {
        sms4_encrypt(in, out, key);
        in += 16;
        out += 16;

    }
}

void sms4_ecb_decrypt_blocks(const uint8_t *in, int ilen, uint8_t *out, const sms4_key_t *key)
{
    int blocks;
    blocks = ilen / 16;

    while (blocks--) {
        sms4_decrypt(in, out, key);
        in += 16;
        out += 16;
    }
}

int sms4_ecb_decrypt_nopadding(const uint8_t *in, int ilen, uint8_t *out, int *olen , const sms4_key_t *key)
{
    if ( ilen % 16 != 0){
        return SM4_BAD_LENGTH;
    }
    memset(out, 0x00, sizeof(char) * ilen);
    sms4_ecb_decrypt_blocks(in ,ilen, out , key );
    *olen = ilen;
    return *olen;
}

int sms4_ecb_encrypt_nopadding(const uint8_t *in, int ilen, uint8_t *out, int *olen,
                               const sms4_key_t *key)
{
    if ( ilen % 16 != 0){
        return SM4_BAD_LENGTH;
    }
    memset(out, 0x00, sizeof(char) * ilen);
    sms4_ecb_encrypt_blocks(in ,ilen, out , key );
    *olen = ilen;
    return *olen;
}


int sms4_ecb_encrypt_zeropadding(const uint8_t *in, int ilen, uint8_t *out, int *olen,
                                 const sms4_key_t *key)
{
    uint8_t *padding_value;
    int plen;
    int res ;
    res = ZEROPadding(in, ilen, out, olen);
    if (res < 0){
        return res;
    }
    sms4_ecb_encrypt_blocks(out, *olen, out, key);
    return *olen;
}

int sms4_ecb_decrypt_zeropadding(const uint8_t *in, int ilen, uint8_t *out, int *olen,
                                 const sms4_key_t *key)
{
    int res = 0;
    sms4_ecb_decrypt_blocks(in, ilen, out, key);
    res = ZEROUnpadding(out, olen);
    return res;
}

int sms4_ecb_encrypt_pkcs7padding(const uint8_t *in, int ilen, uint8_t *out, int *olen,
                                  const sms4_key_t *key)
{
    int res;
    res = PKCS7Padding(in, ilen, out, olen);
    if (res < 0) {
        return res;
    }
    sms4_ecb_encrypt_blocks(out, *olen, out, key);
    return *olen;
}

int sms4_ecb_decrypt_pkcs7padding(const uint8_t *in, int ilen, uint8_t *out, int *olen,
                                  const sms4_key_t *key)
{
    int res;
    sms4_ecb_decrypt_blocks(in, ilen, out, key);
    res = PKCS7Unpadding(out, olen);
    return res;
}

void sms4_cbc_encrypt_blocks(const unsigned char *in,  int ilen, unsigned char *out,unsigned char *iv,
                             const sms4_key_t *key)
{
    int blocks, i;
    blocks = ilen / 16;
    while (blocks--) {
        for( i = 0; i < 16; i++ )
            out[i] = (unsigned char)( in[i] ^ iv[i] );
        sms4_encrypt(out, out, key);
        memcpy( iv, out, 16 );
        in += 16;
        out += 16;
    }
}

void sms4_cbc_decrypt_blocks(const unsigned char *in,  int ilen, unsigned char *out,unsigned char *iv,
                             const sms4_key_t *key)
{
    int blocks, i;
    blocks = ilen / 16;
    unsigned char temp[16];
    while (blocks--) {
        memcpy( temp, in, 16 );
        sms4_decrypt(in, out, key);
        for( i = 0; i < 16; i++ )
            out[i] = (unsigned char)( out[i] ^ iv[i] );
        memcpy( iv, temp, 16 );
        in += 16;
        out += 16;
    }
}

int sms4_cbc_decrypt_nopadding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv,const sms4_key_t *key)
{
    if ( ilen % 16 != 0){
        return SM4_BAD_LENGTH;
    }
    *olen = ilen;
    sms4_cbc_decrypt_blocks(in , ilen, out ,iv, key );
    return *olen;
}

int  sms4_cbc_encrypt_nopadding(const uint8_t *in, int ilen, uint8_t *out, int *olen,uint8_t *iv,
                                const sms4_key_t *key)
{
    if ( ilen % 16 != 0){
        return SM4_BAD_LENGTH;
    }
    *olen = ilen;
    sms4_cbc_encrypt_blocks(in , ilen, out , iv,  key );
    return *olen;
}

int sms4_cbc_encrypt_zeropadding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv,
                                 const sms4_key_t *key)
{
    int res ;
    res = ZEROPadding(in, ilen, out, olen);
    if (res < 0)
        return res;
    sms4_cbc_encrypt_blocks(out, *olen, out,iv, key);
    return *olen;
}

int sms4_cbc_decrypt_zeropadding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv,
                                 const sms4_key_t *key)
{

    *olen = ilen;
    int res ;
    sms4_cbc_decrypt_blocks(in, ilen, out,iv, key);
    res = ZEROUnpadding(out, olen);
    return res;
}

int sms4_cbc_encrypt_pkcs7padding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv,
                                  const sms4_key_t *key)
{
    int res;
    res = PKCS7Padding(in, ilen, out, olen);
    if (res < 0)
        return res;
    sms4_cbc_encrypt_blocks(out, *olen, out,iv, key);
    return *olen;
}

int sms4_cbc_decrypt_pkcs7padding(const uint8_t *in, int ilen, uint8_t *out, int *olen, uint8_t *iv,
                                  const sms4_key_t *key)
{
    *olen = ilen;
    int res;
    sms4_cbc_decrypt_blocks(in, ilen, out,iv, key);
    res = PKCS7Unpadding(out, olen);
    return res;
}

/* caller make sure counter not overflow */
/*
void sms4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                               int blocks, const sms4_key_t *key, const unsigned char iv[16])
{
    const uint *rk = key->rk;
    unsigned int c0 = GETU32(iv);
    unsigned int c1 = GETU32(iv + 4);
    unsigned int c2 = GETU32(iv + 8);
    unsigned int c3 = GETU32(iv + 12);
    uint x0, x1, x2, x3, x4;
    uint t0, t1;

    while (blocks--) {
        x0 = c0;
        x1 = c1;
        x2 = c2;
        x3 = c3;
        ROUNDS(x0, x1, x2, x3, x4);
        PUTU32(out, GETU32(in) ^ x0);
        PUTU32(out + 4, GETU32(in + 4) ^ x4);
        PUTU32(out + 8, GETU32(in + 8) ^ x3);
        PUTU32(out + 12, GETU32(in + 12) ^ x2);
        in += 16;
        out += 16;
        c3++;
    }
}*/
