// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.operator.service;

public class TokenUtils {
    public static String getEmailHash(String emailAddress) {
        return EncodingUtils.getSha256(emailAddress);
    }

    public static String getFirstLevelKey(String emailHash, String firstLevelSalt) {
        return EncodingUtils.getSha256(emailHash, firstLevelSalt);
    }

    public static String getAdvertisingId(String firstLevelKey, String rotatingSalt) {
        return EncodingUtils.getSha256(firstLevelKey, rotatingSalt);
    }

    public static String getAdvertisingIdFromEmail(String emailAddress, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingIdFromEmailHash(getEmailHash(emailAddress), firstLevelSalt, rotatingSalt);
    }

    public static String getAdvertisingIdFromEmailHash(String emailHash, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingId(getFirstLevelKey(emailHash, firstLevelSalt), rotatingSalt);
    }
}
