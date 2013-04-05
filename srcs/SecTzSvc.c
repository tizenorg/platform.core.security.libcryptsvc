/*
 * libTzSvc - encryption and decryption with the TZ-based HW key
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

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlog.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

#include "SecTzSvc.h"
#include "SecCryptoSvc.h"
#include "tlc_tzcrypt.h"
#include "tltzcrypt_api.h"

#define LOG_TAG "tlcTzCrypt"
#ifndef CRYPTOSVC_TZ
#define	SIZE_CHUNK	1024
#define	SIZE_SECUREOBJECT	1116
#define KEY_SIZE 16
#endif

unsigned char* AES_Crypto(unsigned char* p_text, unsigned char* c_text, unsigned char* aes_key, unsigned char* iv, int mode,  unsigned long size)
{
    AES_KEY e_key, d_key;

    AES_set_encrypt_key(aes_key, 128, &e_key);
    AES_set_decrypt_key(aes_key, 128, &d_key);

    if(mode == 1)
    {
		AES_cbc_encrypt(p_text, c_text, size, &e_key, iv, AES_ENCRYPT);
		return c_text;
	}
	else
	{
	    AES_cbc_encrypt(c_text, p_text, size, &d_key, iv, AES_DECRYPT);
	    return p_text;
	}
}
TZCRYPT_Result SecEncryptTZCrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen, TZCRYPT_UINT8 *AppInfo, TZCRYPT_UINT32 AppInfoLen, TZCRYPT_UINT8 *WrapAppInfo, TZCRYPT_UINT32 *WrapAppInfoLen)
{

	TZCRYPT_Result   ret = SEC_CRYPTO_ENCRYPT_ERROR;
#ifndef CRYPTOSVC_TZ
	int outLen = 0;
	unsigned char key[KEY_SIZE] = {0,};
	unsigned char hashOut[SHA_DIGEST_LENGTH] = {0,};
	unsigned char iv[] = {0x3E, 0xB5, 0x01, 0x45, 0xE4, 0xF8, 0x75, 0x3F, 0x08, 0x9D, 0x9F, 0x57, 0x3B, 0x63, 0xEF, 0x4B };
#endif

#ifdef CRYPTOSVC_TZ
	if(SrcLen % SIZE_CHUNK != 0 || *DstLen % SIZE_SECUREOBJECT != 0){
                LOGE("Plain chunk size :: Test for Encryption of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
				LOGE("source length = %d, destination length = %d\n", SrcLen, *DstLen);
                return ret;
	}
#endif

	LOGI("Start Encryption of TZ Crypt!\n");

#ifdef CRYPTOSVC_TZ
	ret = TzCrypt_WrapIdentity(AppInfo, AppInfoLen, WrapAppInfo, WrapAppInfoLen);
	if (ret) {
       	LOGE("Failed to wrap  AppInfo of TZ [Return Value] = %.8x\n", ret);
		return SEC_CRYPTO_WRAPIDENTITY_ERROR;
	}
	ret = TzCrypt_Encrypt(Src, SrcLen, Dst, DstLen);
	if (ret) {
		LOGE("Test for Encryption of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
		return SEC_CRYPTO_ENCRYPT_ERROR;
    }
#else
	if(!SecFrameGeneratePlatformUniqueKey(KEY_SIZE, key))
	{
		LOGE("Failed to generate device unique key\n");
		return SEC_CRYPTO_ENCRYPT_ERROR;
	}
	if(AES_Crypto(Src, Dst, key, iv, 1, SrcLen) == NULL)
	{
		LOGE("Failed to encrypt data \n");
		return SEC_CRYPTO_ENCRYPT_ERROR;
	}
	*DstLen = SrcLen;
	EVP_Digest(AppInfo, AppInfoLen, hashOut, (unsigned int*)&outLen, EVP_sha1(), NULL);
    *WrapAppInfoLen = outLen;
	memcpy(WrapAppInfo, hashOut, *WrapAppInfoLen);
#endif
	LOGI("Encryption of TZ Crypt is Success! [Return Value] = %.8x\n", ret);

	return SEC_CRYPTO_SUCCESS;
}

TZCRYPT_Result SecDecryptTZCrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen, TZCRYPT_UINT8 *AppInfo, TZCRYPT_UINT32 AppInfoLen, TZCRYPT_UINT8 *WrapAppInfo, TZCRYPT_UINT32 WrapAppInfoLen)
{
	TZCRYPT_Result   ret = SEC_CRYPTO_DECRYPT_ERROR;
#ifndef CRYPTOSVC_TZ
    int outLen = 0;
    unsigned char key[KEY_SIZE] = {0,};
    unsigned char hashOut[SHA_DIGEST_LENGTH] = {0,};
    unsigned char iv[] = {0x3E, 0xB5, 0x01, 0x45, 0xE4, 0xF8, 0x75, 0x3F, 0x08, 0x9D, 0x9F, 0x57, 0x3B, 0x63, 0xEF, 0x4B };
#endif
#ifdef CRYPTOSVC_TZ
	if(SrcLen % SIZE_SECUREOBJECT != 0 ){
                LOGE("Ciphertext chunk size :: Test for Encryption of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
                return ret;
	}

	if(WrapAppInfoLen != SIZE_WRAPAPPIDENTITY){
		LOGE("Wrapped App Identity Size :: failed!!! [Return Value] = %.8x\n", ret);
		return ret;
	}

	TZCRYPT_UINT8 *unwrapData = NULL;
	TZCRYPT_UINT32 unwrapDatalen = SIZE_HASHAPPIDENTITY;
	unwrapData = (TZCRYPT_UINT8 *)malloc(unwrapDatalen);

	ret = TzCrypt_UnwrapIdentity(WrapAppInfo, WrapAppInfoLen, unwrapData, &unwrapDatalen);
        if (ret) {
                LOGE("Test for Unwrap AppInfo of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
                return SEC_CRYPTO_UNWRAPIDENTITY_ERROR;
        }
	LOGI("Unwrap AppInfo of TZ Crypt is Success! [Return Value] = %.8x\n", ret);

	TZCRYPT_UINT8 *hashData = NULL;
	TZCRYPT_UINT32 hashDatalen =  SIZE_HASHAPPIDENTITY;
	hashData = (TZCRYPT_UINT8 *)malloc(hashDatalen);

	ret = TzCrypt_Hash(AppInfo, AppInfoLen, hashData, &hashDatalen);
	if (ret) {
		LOGE("Test for Hash AppInfo of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
		return SEC_CRYPTO_HASH_ERROR;
    }

	if( 0 != memcmp(unwrapData, hashData, hashDatalen) || hashDatalen != unwrapDatalen){
		LOGE("App Info Identity is NOT same as hash Info of a given Identity\n");
		return SEC_CRYPTO_HASH_ERROR;
	}

	LOGI("Start Decryption of TZ Crypt!\n");
    ret = TzCrypt_Decrypt(Src, SrcLen, Dst, DstLen);
	if (ret) {
		LOGE("Test for Decryption of TZ Crypt failed!!! [Return Value] = %.8x\n", ret);
		return SEC_CRYPTO_DECRYPT_ERROR;
    }
#else
	if(!SecFrameGeneratePlatformUniqueKey(KEY_SIZE, key))
	{
		LOGE("Failed to generate device unique key\n");
		return SEC_CRYPTO_DECRYPT_ERROR;
	}

	EVP_Digest(AppInfo, AppInfoLen, hashOut, (unsigned int*)&outLen, EVP_sha1(), NULL);

	if( 0 != memcmp(WrapAppInfo, hashOut, outLen) || outLen != WrapAppInfoLen){
		LOGE("AppInfo Identifier Information is wrong\n");
		return SEC_CRYPTO_HASH_ERROR;
	}

	if(AES_Crypto(Dst, Src, key, iv, 0, SrcLen) == NULL)
	{
		LOGE("Failed to decrypt data \n");
		return SEC_CRYPTO_DECRYPT_ERROR;
	}
	*DstLen = SrcLen;

#endif
    LOGI("Test for Decryption of TZ Crypt is Success! [Return Value] = %.8x\n", ret);

	return SEC_CRYPTO_SUCCESS;
}

TZCRYPT_UINT32 SecGetCipherLen(TZCRYPT_UINT32 srclen)
{
#ifdef CRYPTOSVC_TZ
	TZCRYPT_UINT32 cipherLength = TzCrypt_GetSOLen(srclen);
#else
	int  cipherLength = (srclen / EVP_aes_128_cbc()->block_size + 1) * EVP_aes_128_cbc()->block_size;
#endif
	return cipherLength;
}
