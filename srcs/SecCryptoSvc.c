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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <dlog.h>

#include "SecCryptoSvc.h"

#define CS_API __attribute__((visibility("default")))

#define SYS_SECBOOT_DEV_ID_LEN	16
#define NAND_CID_NAME	"/sys/block/mmcblk0/device/cid"
#define NAND_CID_SIZE	32


#ifdef CRYPTOSVC_TARGET
static int __AsciiToHex(const char AsciiHexUpper,const char AsciiHexLower)
{
	char hexReturn=0;

	//First convert upper hex ascii value
	if (AsciiHexUpper >= '0' && AsciiHexUpper <= '9')
		hexReturn = (AsciiHexUpper - '0') * 16;
	else if (AsciiHexUpper >= 'A' && AsciiHexUpper <= 'F')
		hexReturn = ((AsciiHexUpper - 'A') + 10) * 16;
	else if (AsciiHexUpper >= 'a' && AsciiHexUpper <= 'f')
		hexReturn = ((AsciiHexUpper - 'a') + 10) * 16;

	//Convert lower hex ascii value
	if (AsciiHexLower >= '0' && AsciiHexLower <= '9')
		hexReturn = hexReturn + (AsciiHexLower - '0');
	else if (AsciiHexLower >= 'A' && AsciiHexLower <= 'F')
		hexReturn = hexReturn + (AsciiHexLower - 'A') + 10;
	else if (AsciiHexLower >= 'a' && AsciiHexLower <= 'f')
		hexReturn = hexReturn + (AsciiHexLower - 'a') + 10;

	return hexReturn;
}

static bool OemNandInfoUID(unsigned char *pUID, int nBufferSize)
{
	int fd = 0;
	char szCID[NAND_CID_SIZE + 1] = {0,};

	memset(pUID, 0x00, nBufferSize);

	fd = open(NAND_CID_NAME, O_RDONLY);
	if (fd < 0) {
		SLOGE("cid open error!");
		return false;
	}

	if (read(fd, szCID, NAND_CID_SIZE) == -1) {
		SLOGE("cid read fail!!");
		close(fd);
		return false;
	}

	//manufacturer_id
	pUID[0] =  __AsciiToHex(szCID[0], szCID[1]);
	//oem_id
	pUID[4] =  __AsciiToHex(szCID[4], szCID[5]);
	//prod_rev
	pUID[8] =  __AsciiToHex(szCID[18], szCID[19]);
	//serial
	pUID[15] = __AsciiToHex(szCID[20], szCID[21]);
	pUID[14] =  __AsciiToHex(szCID[22], szCID[23]);
	pUID[13] = __AsciiToHex(szCID[24], szCID[25]);
	pUID[12] =  __AsciiToHex(szCID[26], szCID[27]);

	// random permutation
	pUID[1] = __AsciiToHex(szCID[2], szCID[3]);
	pUID[2] = __AsciiToHex(szCID[6], szCID[7]);
	pUID[3] = __AsciiToHex(szCID[8], szCID[9]);

	pUID[5] = __AsciiToHex(szCID[10], szCID[11]);
	pUID[6] = __AsciiToHex(szCID[12], szCID[13]);
	pUID[7] = __AsciiToHex(szCID[14], szCID[15]);

	pUID[9] = __AsciiToHex(szCID[16], szCID[17]);
	pUID[10] = __AsciiToHex(szCID[28], szCID[29]);
	pUID[11] = __AsciiToHex(szCID[30], szCID[31]);

	SLOGD(" UID : %8X %8X %8X %8X",
		*(int *)pUID,
		*(int *)(pUID + 4),
		*(int *)(pUID + 8),
		*(int *)(pUID + 12));

	close(fd);
	return true;
}

static void SysSecBootGetDeviceUniqueKey(unsigned char *pUniquekey)
{
	if (!OemNandInfoUID(pUniquekey, SYS_SECBOOT_DEV_ID_LEN))
		memset(pUniquekey, 0x00, SYS_SECBOOT_DEV_ID_LEN);
}
#endif


CS_API
bool SecFrameGeneratePlatformUniqueKey(unsigned int uLen, unsigned char *pCek)
{
	bool bResult = true;
	unsigned int i = 0;
	unsigned char Key[73] = {0};
	unsigned char hashedValue[HASH_LEN] = {0};
	int nTempLen = SEC_DUK_SIZE;
	int nHashLen = 0;
	int remain = 0;
	unsigned char *result = NULL;

#ifdef CRYPTOSVC_TARGET
	SysSecBootGetDeviceUniqueKey(Key);
#else
	memset(Key, 0xFF, nTempLen);
#endif

	memcpy(Key+nTempLen, SEC_FRAME_OSP_KEY, 9);
	nTempLen += 9;

	remain = uLen;

	for (i = 0; i < uLen; i += HASH_LEN) {
		result = SHA1(Key, nTempLen, hashedValue);
		nHashLen = HASH_LEN;

		if (!result) {
			SLOGE("SecCryptoHash fail");
			bResult = false;
			goto ERR;
		}

		nTempLen = nHashLen;

		if (remain < HASH_LEN)
			memcpy(pCek + i, hashedValue, remain);
		else
			memcpy(pCek + i, hashedValue, nHashLen);

		remain -= HASH_LEN;
		memset(Key, 0, sizeof(Key));
		memcpy(Key, hashedValue, nHashLen);
	}

	SLOGD("SecFrameGeneratePlatformUniqueKey Success.");

ERR:
	return bResult;
}

CS_API
char *Base64Encoding(const char *data, int size)
{
	char *pEncodedBuf = NULL;
	const char *pPointer = NULL;
	const char *pLength = data + size - 1;
	unsigned char pInput[3] = {0,0,0};
	unsigned char poutput[4] = {0,0,0,0};
	int index = 0;
	int loopCnt = 0;
	int stringCnt = 0;
	int sizeEncodedString = (4 * (size / 3)) + (size % 3 ? 4 : 0) + 1;

	if (!(pEncodedBuf = (char *)calloc(sizeEncodedString, sizeof(char)))) {
		SLOGE("Failed to allocate memory");
		return NULL;
	}

	for (loopCnt = 0, pPointer = data; pPointer <= pLength; loopCnt++, pPointer++) {
		index = loopCnt % 3;
		pInput[index] = *pPointer;

		if (index == 2 || pPointer == pLength) {
			poutput[0] = ((pInput[0] & 0xFC) >> 2);
			poutput[1] = ((pInput[0] & 0x3) << 4) | ((pInput[1] & 0xF0) >> 4);
			poutput[2] = ((pInput[1] & 0xF) << 2) | ((pInput[2] & 0xC0) >> 6);
			poutput[3] = (pInput[2] & 0x3F);

			pEncodedBuf[stringCnt++] = Base64EncodingTable[poutput[0]];
			pEncodedBuf[stringCnt++] = Base64EncodingTable[poutput[1]];
			pEncodedBuf[stringCnt++] = index == 0 ? '=' : Base64EncodingTable[poutput[2]];
			pEncodedBuf[stringCnt++] = index < 2 ? '=' : Base64EncodingTable[poutput[3]];

			pInput[0] = pInput[1] = pInput[2] = 0;
		}
	}

	pEncodedBuf[stringCnt] = '\0';

	return pEncodedBuf;
}

CS_API
char *GetDuid(int idSize)
{
	const char *version = "1.0#";
	char info[] = {0xca, 0xfe, 0xbe, 0xbe, 0x78, 0x07, 0x02, 0x03};

	unsigned char *pKey = NULL;
	unsigned char *pDuid = NULL;
	char *pId = NULL;
	char *pKeyVersion = NULL;

	if (idSize <= 0) {
		SLOGE("Invalid Input [%d]", idSize);
		return NULL;
	}

	if (!(pKey = (unsigned char *)malloc(idSize))) {
		SLOGE("Failed to allocate memory for key");
		return NULL;
	}

	if (!SecFrameGeneratePlatformUniqueKey(idSize, pKey)) {
		SLOGE("Failed to get duid");
		goto exit;
	}

	if (!(pDuid = (unsigned char *)malloc(idSize))) {
		SLOGE("Failed to allocate memory");
		goto exit;
	}

	PKCS5_PBKDF2_HMAC_SHA1(info, 8, pKey, idSize, 1, idSize, pDuid);

	if (!(pId = Base64Encoding((char *)pDuid, idSize))) {
		SLOGE("Failed to convert to base64 string");
		goto exit;
	}

	if (!(pKeyVersion = (char *)calloc(strlen(pId) + strlen(version) + 1, sizeof(char)))) {
		SLOGE("Failed to allocate memory");
		goto exit;
	}
	strncpy(pKeyVersion, version, strlen(version));
	strncat(pKeyVersion, pId, strlen(pId));

exit:
	free(pKey);
	free(pDuid);
	free(pId);

	return pKeyVersion;
}

CS_API
int cs_derive_key_with_pass(const char *pass, int passlen, int keylen, unsigned char **key)
{
	const int PBKDF_ITERATE_NUM = 1;
	unsigned char *platform_key = NULL;
	unsigned char *derived_key = NULL;
	int retval = CS_ERROR_NONE;

	if (pass == NULL || key == NULL || keylen <= 0)
		return CS_ERROR_INVALID_PARAM;

	platform_key = (unsigned char *)malloc(sizeof(unsigned char) * keylen);
	if (platform_key == NULL)
		return CS_ERROR_BAD_ALLOC;

	if (!SecFrameGeneratePlatformUniqueKey(keylen, platform_key)) {
		retval = CS_ERROR_INTERNAL;
		goto exit;
	}

	derived_key = (unsigned char *)malloc(sizeof(unsigned char) * keylen);
	if (derived_key == NULL) {
		retval = CS_ERROR_BAD_ALLOC;
		goto exit;
	}

	retval = PKCS5_PBKDF2_HMAC(pass, passlen,
			platform_key, keylen,
			PBKDF_ITERATE_NUM, EVP_sha1(),
			keylen, derived_key);
	if (retval != 1) {
		retval = CS_ERROR_INTERNAL;
		goto exit;
	}

	*key = derived_key;

	return CS_ERROR_NONE;

exit:
	free(platform_key);
	free(derived_key);

	return retval;
}
