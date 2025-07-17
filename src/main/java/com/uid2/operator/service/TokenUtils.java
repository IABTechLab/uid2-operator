package com.uid2.operator.service;

import com.uid2.operator.model.identities.IdentityScope;
import com.uid2.operator.model.identities.DiiType;

import java.util.HashSet;
import java.util.Set;

public class TokenUtils {
    public static byte[] getHashedDii(String rawDii) {
        return EncodingUtils.getSha256Bytes(rawDii);
    }

    public static String getHashedDiiString(String rawDii) {
        return EncodingUtils.toBase64String(getHashedDii(rawDii));
    }

    public static byte[] getFirstLevelHashFromHashedDii(byte[] hashedDii, String firstLevelSalt) {
        return getFirstLevelHashFromHashedDii(EncodingUtils.toBase64String(hashedDii), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromRawDii(String rawDii, String firstLevelSalt) {
        return getFirstLevelHashFromHashedDii(getHashedDii(rawDii), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromHashedDii(String hashedDii, String firstLevelSalt) {
        return EncodingUtils.getSha256Bytes(hashedDii, firstLevelSalt);
    }

    public static byte[] getRawUidV2(byte[] firstLevelHash, String rotatingSalt) {
        return EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
    }

    public static byte[] getRawUidV2FromRawDii(String rawDii, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV2(getFirstLevelHashFromRawDii(rawDii, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV2FromHashedDii(String hashedDii, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV2(getFirstLevelHashFromHashedDii(hashedDii, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV3(IdentityScope scope, DiiType type, byte[] firstLevelHash, String rotatingSalt) {
        final byte[] sha = EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
        final byte[] rawUid = new byte[33];
        rawUid[0] = (byte)(encodeIdentityScope(scope) | encodeIdentityType(type));
        System.arraycopy(sha, 0, rawUid, 1, 32);
        return rawUid;
    }

    public static byte[] getRawUidV3FromRawDii(IdentityScope scope, DiiType type, String rawDii, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV3(scope, type, getFirstLevelHashFromRawDii(rawDii, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV3FromHashedDii(IdentityScope scope, DiiType type, String hashedDii, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV3(scope, type, getFirstLevelHashFromHashedDii(hashedDii, firstLevelSalt), rotatingSalt);
    }

    public static byte encodeIdentityScope(IdentityScope identityScope) {
        return (byte) (identityScope.value << 4);
    }

    public static byte encodeIdentityType(DiiType diiType) {
        return (byte) (diiType.value << 2);
    }
}
