package com.uid2.operator.service;

import com.uid2.operator.model.identities.IdentityScope;
import com.uid2.operator.model.identities.DiiType;

import java.util.HashSet;
import java.util.Set;

public class TokenUtils {
    public static byte[] getDiiHash(String identityString) {
        return EncodingUtils.getSha256Bytes(identityString);
    }

    public static String getDiiHashString(String identityString) {
        return EncodingUtils.toBase64String(getDiiHash(identityString));
    }

    public static byte[] getFirstLevelHash(byte[] identityHash, String firstLevelSalt) {
        return getFirstLevelHashFromIdentityHash(EncodingUtils.toBase64String(identityHash), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromIdentity(String identityString, String firstLevelSalt) {
        return getFirstLevelHash(getDiiHash(identityString), firstLevelSalt);
    }

    public static byte[] getFirstLevelHashFromIdentityHash(String identityHash, String firstLevelSalt) {
        return EncodingUtils.getSha256Bytes(identityHash, firstLevelSalt);
    }

    public static byte[] getRawUidV2(byte[] firstLevelHash, String rotatingSalt) {
        return EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
    }

    public static byte[] getRawUidV2FromIdentity(String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV2(getFirstLevelHashFromIdentity(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV2FromIdentityHash(String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV2(getFirstLevelHashFromIdentityHash(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV3(IdentityScope scope, DiiType type, byte[] firstLevelHash, String rotatingSalt) {
        final byte[] sha = EncodingUtils.getSha256Bytes(EncodingUtils.toBase64String(firstLevelHash), rotatingSalt);
        final byte[] rawUid = new byte[33];
        rawUid[0] = (byte)(encodeIdentityScope(scope) | encodeIdentityType(type));
        System.arraycopy(sha, 0, rawUid, 1, 32);
        return rawUid;
    }

    public static byte[] getRawUidV3FromIdentity(IdentityScope scope, DiiType type, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV3(scope, type, getFirstLevelHashFromIdentity(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getRawUidV3FromIdentityHash(IdentityScope scope, DiiType type, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUidV3(scope, type, getFirstLevelHashFromIdentityHash(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte encodeIdentityScope(IdentityScope identityScope) {
        return (byte) (identityScope.value << 4);
    }

    public static byte encodeIdentityType(DiiType diiType) {
        return (byte) (diiType.value << 2);
    }

    public static Set<Integer> getSiteIdsUsingV4Tokens(String siteIdsUsingV4TokensInString) {
        String[] siteIdsV4TokensList = siteIdsUsingV4TokensInString.split(",");

        Set<Integer> siteIdsV4TokensSet = new HashSet<>();
        try {
            for (String siteId : siteIdsV4TokensList) {
                String siteIdTrimmed = siteId.trim();
                if (!siteIdTrimmed.isEmpty()) {
                    siteIdsV4TokensSet.add(Integer.parseInt(siteIdTrimmed));
                }
            }
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(String.format("Invalid integer format found in site_ids_using_v4_tokens:  %s", siteIdsUsingV4TokensInString));
        }
        return siteIdsV4TokensSet;
    }
}
