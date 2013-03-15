/*
 * libcryptsvc - device unique key
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _SEC_CRYPTO_SVC_H
#define _SEC_CRYPTO_SVC_H

#ifdef __cplusplus
extern "C"
{
#endif

//#ifdef OPENSSL_NO_ENGINE
//#error Do not use define <OPENSSL_NO_ENGINE>
//#else
#include <openssl/engine.h>
//#endif

/*typedef enum
{
	SEC_CRYPTO_CIPHER_NULL = 0,
	SEC_CRYPTO_CIPHER_AES_CBC_128,
	SEC_CRYPTO_CIPHER_SEED_CBC,
	SEC_CRYPTO_CIPHER_AES_CBC_192,
	SEC_CRYPTO_CIPHER_AES_CBC_256,
	SEC_CRYPTO_CIPHER_AES_CTR_128,
	SEC_CRYPTO_CIPHER_AES_ECB_128,
	SEC_CRYPTO_CIPHER_AES_ECB_192,
	SEC_CRYPTO_CIPHER_AES_ECB_256
} SecCryptoCipherAlg;

typedef enum
{
	SEC_SUCCESS = 0,
	SEC_CRYPTO_ERROR_1, //algorithm error
	SEC_CRYPTO_ERROR_2, //init error
	SEC_CRYPTO_ERROR_3, //update error
	SEC_CRYPTO_ERROR_4, //final error
	SEC_CRYPTO_ERROR_5, //wrong param
	SEC_CRYPTO_ERROR_6, //Memory alloc
	SEC_CRYPTO_ERROR_7, //Internal error
} SecError;
*/
//#ifndef bool
#ifdef _bool_cryptsvc
typedef enum {false, true} bool;
#endif

#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif

#ifndef NULL
#define NULL 0
#endif
#ifndef BOOL
#define BOOL bool
#endif
#ifndef ULONG
#define ULONG unsigned int
#endif
#ifndef UINT8
#define UINT8 unsigned char
#endif
#ifndef UINT32
#define UINT32 unsigned int
#endif

//#define EVP_ERROR			0
//#define SEC_CRYPTO_ENCRYPT		1
//#define SEC_CRYPTO_DECRYPT		0
#define SEC_DUK_SIZE			16
//#define SEC_CRYPTO_KEY_LENGTH		16
//#define SEC_CRYPTP_ARR_LENGTH		1024
#define SEC_FRAME_OSP_KEY		"uniqueKey"
//#define SHA1_DIGEST_VALUE_LEN		20
#define SHA256_DIGEST_VALUE_LEN		32
//#define KDF_KEYLEN			16
#define HASH_LEN			20
//#define SEC_KEYMGR_FEK_SIZE		16


/**
	* This function provides Device UniqueKey for crypto with Hash
	* @return		This function returns TRUE on success
	* @param[in]		uLen	Length of Device UniqueKey
	* @param[in,out]	pCek	Device UniqueKey(Hashed)
*/
__attribute__((visibility("default")))
bool SecFrameGeneratePlatformUniqueKey(IN UINT32  uLen,IN OUT UINT8  *pCek);

#ifdef __cplusplus
}
#endif

#endif	// _SEC_CRYPTO_SVC_H

