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

#include "SecCryptoSvc.h"
//#include "SecKmBase64.h"
//#include "CryptoSvc-debug.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <dlog.h>

bool SecFrameGeneratePlatformUniqueKey(IN UINT32  uLen, IN OUT UINT8  *pCek)
{
	bool 		bResult = true;
	unsigned int 	i = 0;
	unsigned char 	Key[73] = {0};
	unsigned char 	hashedValue[HASH_LEN] = {0};
	int 		nTempLen = SEC_DUK_SIZE;
	int 		nHashLen = 0;
	int 		remain = 0;
	unsigned char	*result = NULL;

	SLOGD("[LOG][%s:L%d] Enter \n", __func__,__LINE__);
#ifdef CRYPTOSVC_TARGET
	SysSecBootGetDeviceUniqueKey(Key);
#else
	memset(Key, 0xFF, nTempLen);
#endif

	/* for debugging */
	SLOGD("Device Unique Key Information \n");

	memcpy(Key+nTempLen, SEC_FRAME_OSP_KEY, 9);
	nTempLen += 9;

	remain = uLen;

	for( i = 0 ; i < uLen ; i += HASH_LEN )
	{
		result = SHA1(Key, nTempLen, hashedValue);
		nHashLen = HASH_LEN;

		if( result == NULL)
		{
			SLOGE("SecCryptoHash fail \n");
			bResult = false;
			goto ERR;
		}

		nTempLen = nHashLen;

		if( remain < HASH_LEN )
		{
			memcpy(pCek+i, hashedValue, remain);
		}
		else
		{
			memcpy(pCek+i, hashedValue, nHashLen);
		}

		remain -= HASH_LEN;
		memset(Key, 0, sizeof(Key));
		memcpy(Key, hashedValue, nHashLen);
	}
	SLOGD("[LOG][%s:L%d] End \n", __func__,__LINE__);
ERR:
	SLOGD("[LOG][%s:L%d] End with ERROR \n", __func__,__LINE__);
	return bResult;
}


