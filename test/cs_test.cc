/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Kyungwook Tak <k.tak@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 * @file        cs_test.cc
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version
 * @brief
 */

#include <stdlib.h>
#include <memory>
#include <iostream>

#include <boost/test/unit_test.hpp>

#include <SecCryptoSvc.h>

BOOST_AUTO_TEST_SUITE(CRYPTO_SERVICE_TEST)

BOOST_AUTO_TEST_CASE(PLATFORM_UNIQUE_KEY)
{
    constexpr unsigned int KeyLen = 16;
    unsigned char cek[KeyLen] = {0};

    BOOST_REQUIRE_MESSAGE(SecFrameGeneratePlatformUniqueKey(KeyLen, cek),
        "Failed to SecFrameGeneratePlatformUniqueKey.");

    std::unique_ptr<char, void(*)(void *)> encoded_cek(
        Base64Encoding(reinterpret_cast<char *>(cek), static_cast<int>(KeyLen)),
        free);
    BOOST_REQUIRE_MESSAGE(!!encoded_cek, "Failed to base64 encoding.");

    std::cout << "base64 encoded platform unique key(with len 16): "
        << encoded_cek.get() << std::endl;
}

BOOST_AUTO_TEST_CASE(GETDUID_16)
{
    std::unique_ptr<char, void(*)(void *)> duid(GetDuid(16), free);
    BOOST_REQUIRE_MESSAGE(!!duid, "returned duid shouldn't be null");
    std::cout << "duid: " << duid.get() << std::endl;
}

BOOST_AUTO_TEST_CASE(GETDUID_20)
{
    std::unique_ptr<char, void(*)(void *)> duid(GetDuid(20), free);
    BOOST_REQUIRE_MESSAGE(!!duid, "returned duid shouldn't be null");
    std::cout << "duid: " << duid.get() << std::endl;
}

static void derive_key_with_pass(const char *pass, int passlen)
{
    int retval = CS_ERROR_NONE;

    constexpr unsigned int KeyLen = 20;
    unsigned char *key = nullptr;
    BOOST_REQUIRE_MESSAGE(
        (retval = cs_derive_key_with_pass(pass, passlen, KeyLen, &key)) == CS_ERROR_NONE,
        "Failed to cs_derive_key_with_pass with retval: " << retval);

    std::unique_ptr<unsigned char, void(*)(void *)> pKey(key, free);

    std::unique_ptr<char, void(*)(void *)> encoded_key(
        Base64Encoding(reinterpret_cast<char *>(key), static_cast<int>(KeyLen)),
        free);
    BOOST_REQUIRE_MESSAGE(!!encoded_key, "Failed to base64 encoding.");

    std::cout << "base64 encoded key derived from pass(len " << KeyLen
        << "): " << encoded_key.get() << std::endl;
}

BOOST_AUTO_TEST_CASE(DERIVE_KEY_WITH_PASS)
{
    const char *test_pass = "test-password";
    derive_key_with_pass(test_pass, 5);
    derive_key_with_pass(test_pass, 10);
    derive_key_with_pass(test_pass, strlen(test_pass));

    const char empty_pass[30] = {0, };
    derive_key_with_pass(empty_pass, strlen(empty_pass));
}

BOOST_AUTO_TEST_SUITE_END()
