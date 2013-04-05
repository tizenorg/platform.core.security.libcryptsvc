/*
 * tlc_tzcrypto.h
 *
 */

#ifndef TLC_TZCRYPT_H_
#define TLC_TZCRYPT_H_

#ifdef __cplusplus
extern "C"
{
#endif
/*
typedef unsigned int	TZCRYPT_Result;
typedef unsigned char	TZCRYPT_UINT8;
typedef unsigned int	TZCRYPT_UINT32;
typedef unsigned long	TZCRYPT_UINT64;
*/

/* TLC error code */
#define TZCRYPT_SUCCESS					0x00000000
#define TZCRYPT_ERROR_INIT_FAILED			0x20000001
#define TZCRYPT_ERROR_TERMINATE_FAILED			0x20000002
#define TZCRYPT_ERROR_ENCRYPT_FAILED			0x20000003
#define TZCRYPT_ERROR_DECRYPT_FAILED			0x20000004
#define TZCRYPT_ERROR_WRAPIDENTITY_FAILED			0x20000005
#define TZCRYPT_ERROR_UNWRAPIDENTITY_FAILED			0x20000006
#define TZCRYPT_ERROR_HASH_FAILED			0x20000007
#define TZCRYPT_ERROR_INVALID_PARAMETER			0x20000008

/* Sec Crypto error code */
#define SEC_CRYPTO_SUCCESS				0x00000000
#define SEC_CRYPTO_ENCRYPT_ERROR				0x30000001
#define SEC_CRYPTO_DECRYPT_ERROR				0x30000002
#define SEC_CRYPTO_WRAPIDENTITY_ERROR				0x30000003
#define SEC_CRYPTO_UNWRAPIDENTITY_ERROR				0x30000004
#define SEC_CRYPTO_HASH_ERROR				0x30000005

/*
 * This function provides an encryption of user data.
 *
 * @param [in] Src  : User data to be encrypted
 * @param [in] SrcLen : Length of user data to be encrypted (multiple by chunk size, SIZE_CHUNK)
 * @param [out] Dst : Encrypted data
 * @param [out] *DstLen : a pointer to length of encrypted data (multiple by secure object size, SIZE_SECUREOBJECT)
 *
 * return TZCRYPT_SUCCESS if operation has been succesfully completed. (Refer to the previous TLC error code)
 */
TZCRYPT_Result TzCrypt_Encrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen);

/*
 * This function provides an decryption of user data.
 *
 * @param [in] Src  : Cipher data to be decrypted
 * @param [in] SrcLen : Length of Cipher data to be decrypted (multiple by chunk size, SIZE_SECUREOBJECT)
 * @param [out] Dst : Encrypted data
 * @param [out] *DstLen : a pointer to length of encrypted data (multiple by secure object size, SIZE_CHUNK)
 *
 * return TZCRYPT_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 */
TZCRYPT_Result TzCrypt_Decrypt(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen);

/*
 * This function provides an hash of user data.
 *
 * @param [in] Src : Plain information
 * @param [in] SrcLen : Length of Plain information
 * @param [out] Dst : Hashed information
 * @param [out] *DstLen : a pointer to length of hashed information

 * return TZCRYPT_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 */
TZCRYPT_Result TzCrypt_Hash(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen);

/*
 * This function provides an wrapping of App data. (+ include hash operation)
 *
 * @param [in] Src : Plain information
 * @param [in] SrcLen : Length of Plain information
 * @param [out] Dst : Wrapped information
 * @param [out] *DstLen : a pointer to length of wrapped information

 * return TZCRYPT_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 */
TZCRYPT_Result TzCrypt_WrapIdentity(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen);

/*
 * This function provides an unwrapping of App data. (- exclude hash operation)
 *
 * @param [in] Src : Plain information
 * @param [in] SrcLen : Length of Plain information
 * @param [out] Dst : Wrapped information
 * @param [out] *DstLen : a pointer to length of wrapped information

 * return TZCRYPT_SUCCESS if operation has been succesfully completed. (Refer to the tlc error code)
 */
TZCRYPT_Result TzCrypt_UnwrapIdentity(TZCRYPT_UINT8 *Src, TZCRYPT_UINT32 SrcLen, TZCRYPT_UINT8 *Dst, TZCRYPT_UINT32 *DstLen);

/*
 * This function provides the length of secure object from a given length of source data
 *
 * @param [in] SrcLen : Length of Plain information
 *
 * return TZCRYPT_UINT32 (size) if operation has been succesfully completed.
 */
TZCRYPT_UINT32 TzCrypt_GetSOLen(TZCRYPT_UINT32 SrcLen);

#ifdef __cplusplus
}
#endif

#endif
