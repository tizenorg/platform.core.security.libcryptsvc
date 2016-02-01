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
#include <iostream>

#include <boost/test/unit_test.hpp>

#include <SecCryptoSvc.h>

BOOST_AUTO_TEST_SUITE(CRYPTO_SERVICE_TEST)

BOOST_AUTO_TEST_CASE(PLATFORM_UNIQUE_KEY)
{
    constexpr unsigned int KeyLen = 16;
    unsigned char cek[KeyLen] = {0};
    char *encoded_cek = nullptr;

    BOOST_REQUIRE_MESSAGE(SecFrameGeneratePlatformUniqueKey(KeyLen, cek),
        "Failed to SecFrameGeneratePlatformUniqueKey.");

    encoded_cek = Base64Encoding(
            reinterpret_cast<char *>(cek),
            static_cast<int>(KeyLen));
    BOOST_REQUIRE_MESSAGE(encoded_cek != nullptr, "Failed to base64 encoding.");

    std::cout << "base64 encoded platform unique key(with len 16): "
        << encoded_cek << std::endl;
}

BOOST_AUTO_TEST_CASE(GETDUID_16)
{
    char *duid = GetDuid(16);
    BOOST_REQUIRE_MESSAGE(duid != nullptr, "returned duid shouldn't be null");
    std::cout << "duid: " << duid << std::endl;
}

BOOST_AUTO_TEST_CASE(GETDUID_20)
{
    char *duid = GetDuid(20);
    BOOST_REQUIRE_MESSAGE(duid != nullptr, "returned duid shouldn't be null");
    std::cout << "duid: " << duid << std::endl;
}


BOOST_AUTO_TEST_SUITE_END()
