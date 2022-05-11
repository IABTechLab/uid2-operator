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

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

public class TokenUtils {
    public static byte[] getIdentityHash(String identityString) {
        return EncodingUtils.getSha256Bytes(identityString);
    }

    public static String getIdentityHashString(String identityString) {
        return EncodingUtils.toBase64String(getIdentityHash(identityString));
    }

    public static byte[] getFirstLevelHash(byte[] identityHash, String firstLevelSalt) {
        return getFirstLevelHashFromIdentityHash(EncodingUtils.toBase64String(identityHash), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromIdentity(String identityString, String firstLevelSalt) {
        return getFirstLevelHash(getIdentityHash(identityString), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromIdentityHash(String identityHash, String firstLevelSalt) {
        return EncodingUtils.getSha256Bytes(identityHash, firstLevelSalt);
    }

    public static byte[] getAdvertisingIdV2(byte[] firstLevelHash, String rotatingSalt) {
        return EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
    }

    public static byte[] getAdvertisingIdV2FromIdentity(String identityString, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingIdV2(getFirstLevelHashFromIdentity(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getAdvertisingIdV2FromIdentityHash(String identityString, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingIdV2(getFirstLevelHashFromIdentityHash(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getAdvertisingIdV3(IdentityScope scope, IdentityType type, byte[] firstLevelHash, String rotatingSalt) {
        final byte[] sha = EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
        final byte[] id = new byte[33];
        id[0] = (byte)((scope.value << 4) | (type.value << 2));
        System.arraycopy(sha, 0, id, 1, 32);
        return id;
    }
}
