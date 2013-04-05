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

#ifndef _SEC_TZ_SVC_H
#define _SEC_TZ_SVC_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef unsigned int    TZCRYPT_Result;
typedef unsigned char   TZCRYPT_UINT8;
typedef unsigned int    TZCRYPT_UINT32;
typedef unsigned long   TZCRYPT_UINT64;

#define SHA256_DIGEST_VALUE_LEN         32

/*
 * This function provides an encryption of user data.
 *
 * @param [in] Src  : User data to be encrypted
 * @param [in] SrcLen : Length of user data to be encrypted (multiple by chunk size, SIZE_CHUNK)
 * @param [out] Dst : Encrypted data
 * @param [out] *DstLen : a pointer to length of encrypted data (multiple by secure object size, SIZE_SECUREOBJECT)
 * @param [in] AppInfo : Application information
 * @param [in] AppInfoLen : Length of Application information
 * @param [out] WrapAppInfo : Hashed and wrapped Application Information  as an identifier
 * @param [out] *WrapAppInfo : a pointer to length of hashed and wraped Application Information  as an identifier
 *
 * return SEC_CRYPTO_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 */
__attribute__((visibility("default")))
TZCRYPT_Result SecEncryptTZCrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen, TZCRYPT_UINT8 *AppInfo, TZCRYPT_UINT32 AppInfoLen, TZCRYPT_UINT8 *WrapAppInfo, TZCRYPT_UINT32 *WrapAppInfoLen);

/*
 * This function provides an decryption of user data.
 *
 * @param [in] Src  : Cipher data to be decrypted
 * @param [in] SrcLen : Length of Cipher data to be decrypted (multiple by chunk size, SIZE_SECUREOBJECT)
 * @param [out] Dst : Encrypted data
 * @param [out] *DstLen : a pointer to length of encrypted data (multiple by secure object size, SIZE_CHUNK)
 * @param [in] AppInfo : Application information
 * @param [in] AppInfoLen : Length of Application information
 * @param [in] WrapAppInfo : Hashed and wrapped Application Information  as an identifier
 * @param [in] WrapAppInfo : Length of hashed and wraped Application Information  as an identifier
 *
 * return SEC_CRYPTO_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 * If a given application information (identifier) is wrong, then return UNIT_TEXT_HASH_ERROR
 */
__attribute__((visibility("default")))
TZCRYPT_Result SecDecryptTZCrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen, TZCRYPT_UINT8 *AppInfo, TZCRYPT_UINT32 AppInfoLen, TZCRYPT_UINT8 *WrapAppInfo, TZCRYPT_UINT32 WrapAppInfoLen);

/*
 * This function provides the length of a given src len
 *
 * @param [in] source length
 *
 * return length of cipher text
 */
__attribute__((visibility("default")))
TZCRYPT_UINT32 SecGetCipherLen(TZCRYPT_UINT32 srclen);

#ifdef __cplusplus
}
#endif

#endif
