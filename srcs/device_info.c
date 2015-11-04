/*
 * device info
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <pthread.h>

#include <dlog.h>
#include <system_info.h>

#include <device_info.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "LIBCRYPTSVC"
#endif

#define TIZENID_STRING "http://tizen.org/system/tizenid"

char* _device_id = NULL;
int _is_loaded = false;
pthread_once_t _load_once_block = PTHREAD_ONCE_INIT;

void load_device_id(void)
{
	if (!_device_id
		&& system_info_get_platform_string(TIZENID_STRING, &_device_id) != SYSTEM_INFO_ERROR_NONE) {
		SECURE_LOGE("Failed to generate DUID.");
		return;
	}

	_is_loaded = true;
}


__attribute__((visibility("default")))
const char *get_device_id(void)
{
	if (!_is_loaded) {
		pthread_once(&_load_once_block, load_device_id);
		if (!_is_loaded
			|| !_device_id
			|| !strlen(_device_id)) {
			LOGE("failed to get device id");
			_load_once_block = PTHREAD_ONCE_INIT;
			return NULL;
		}
	}

	return _device_id;
}
