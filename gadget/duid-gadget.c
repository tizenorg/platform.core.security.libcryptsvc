/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <SecCryptoSvc.h>

int main()
{
	const char *version = "1.0#";
	char info[] = {0xca, 0xfe, 0xbe, 0xbe, 0x78, 0x07, 0x02, 0x03};

	int ret = 0;
	int keyLen = 20;
	unsigned char *pKey = NULL;
	unsigned char *pDuid = NULL;
	char *pId = NULL;
	char *pKeyVersion = NULL;

	if (!(pKey = (unsigned char *)malloc(keyLen)))
		goto exit;

	if (!SecFrameGeneratePlatformUniqueKey(keyLen, pKey)) {
		fprintf(stderr, "Failed to get duid\n");
		goto exit;
	}

	if (!(pDuid = (unsigned char *)malloc(keyLen)))
		goto exit;

	PKCS5_PBKDF2_HMAC_SHA1(info, 8, pKey, keyLen, 1, keyLen, pDuid);

	if (!(pId = Base64Encoding((char *)pDuid, keyLen)))
		goto exit;

	if (!(pKeyVersion = (char *)calloc(strlen(pId) + strlen(version) + 1, sizeof(char))))
		goto exit;

	strncpy(pKeyVersion, version, strlen(version));
	strncat(pKeyVersion, pId, strlen(pId));
	printf("%s", pKeyVersion);

	ret = 1;

exit:
	free(pKey);
	free(pDuid);
	free(pId);
	free(pKeyVersion);

	return ret;
}

