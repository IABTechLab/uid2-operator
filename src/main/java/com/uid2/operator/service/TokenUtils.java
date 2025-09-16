package com.uid2.operator.service;

import com.uid2.operator.model.IdentityEnvironment;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.operator.model.IdentityVersion;
import com.uid2.shared.model.SaltEntry;

public final class TokenUtils {
    private TokenUtils() {
    }

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
        id[0] = (byte) (encodeIdentityScope(scope) | encodeIdentityType(type));
        System.arraycopy(sha, 0, id, 1, 32);
        return id;
    }

    public static byte[] getAdvertisingIdV3FromIdentity(IdentityScope scope, IdentityType type, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingIdV3(scope, type, getFirstLevelHashFromIdentity(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getAdvertisingIdV3FromIdentityHash(IdentityScope scope, IdentityType type, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getAdvertisingIdV3(scope, type, getFirstLevelHashFromIdentityHash(identityString, firstLevelSalt), rotatingSalt);
    }

    public static byte[] getAdvertisingIdV4(IdentityScope scope, IdentityType type, IdentityEnvironment environment, byte[] firstLevelHash, SaltEntry.KeyMaterial encryptingKey) throws Exception {
        byte metadata = encodeV4Metadata(scope, type, environment);
        return V4TokenUtils.buildAdvertisingIdV4(metadata, firstLevelHash, encryptingKey.id(), encryptingKey.key(), encryptingKey.salt());
    }

    public static byte[] getAdvertisingIdV4FromIdentity(IdentityScope scope, IdentityType type, IdentityEnvironment environment, String identityString, String firstLevelSalt, SaltEntry.KeyMaterial encryptingKey) throws Exception {
        return getAdvertisingIdV4(scope, type, environment, getFirstLevelHashFromIdentity(identityString, firstLevelSalt), encryptingKey);
    }

    public static byte[] getAdvertisingIdV4FromIdentityHash(IdentityScope scope, IdentityType type, IdentityEnvironment environment, String identityString, String firstLevelSalt, SaltEntry.KeyMaterial encryptingKey) throws Exception {
        return getAdvertisingIdV4(scope, type, environment, getFirstLevelHashFromIdentityHash(identityString, firstLevelSalt), encryptingKey);
    }

    public static byte encodeV4Metadata(IdentityScope scope, IdentityType type, IdentityEnvironment environment) {
        return (byte) (encodeIdentityVersion(IdentityVersion.V4) | encodeIdentityScope(scope) | encodeIdentityType(type) | encodeIdentityEnvironment(environment));
    }

    public static byte encodeIdentityScope(IdentityScope identityScope) {
        return (byte) (identityScope.getValue() << 4);
    }

    public static byte encodeIdentityType(IdentityType identityType) {
        return (byte) (identityType.getValue() << 2);
    }

    public static byte encodeIdentityVersion(IdentityVersion identityVersion) {
        return (byte) (identityVersion.getValue() << 5);
    }

    public static byte encodeIdentityEnvironment(IdentityEnvironment identityEnvironment) {
        return (byte) (identityEnvironment.getValue() << 6);
    }
}
