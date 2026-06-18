package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.util.Tuple;
import com.uid2.operator.vertx.ClientInputValidationException;
import com.uid2.shared.Const.Data;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.encryption.Uid2Base64UrlCoder;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.buffer.Buffer;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import io.vertx.core.json.JsonObject;

public class EncryptedTokenEncoder implements ITokenEncoder {
    private final KeyManager keyManager;
    private final Map<Tuple.Tuple2<String, String>, Counter> siteKeysetStatusMetrics = new HashMap<>();

    public EncryptedTokenEncoder(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public byte[] encode(AdvertisingToken t, Instant asOf) {
        final KeysetKey masterKey = this.keyManager.getMasterKey(asOf);
        final KeysetKey siteEncryptionKey = this.keyManager.getActiveKeyBySiteIdWithFallback(t.publisherIdentity.siteId, Data.AdvertisingTokenSiteId, asOf, siteKeysetStatusMetrics);
        return encodeV3(t, masterKey, siteEncryptionKey); // TokenVersion.V4 calls encodeV3() since the byte array is identical between V3 and V4
    }

    private byte[] encodeV3(AdvertisingToken t, KeysetKey masterKey, KeysetKey siteKey) {
        final Buffer sitePayload = Buffer.buffer(69);
        encodePublisherIdentityV3(sitePayload, t.publisherIdentity);
        sitePayload.appendInt(t.userIdentity.privacyBits);
        sitePayload.appendLong(t.userIdentity.establishedAt.toEpochMilli());
        sitePayload.appendLong(t.userIdentity.refreshedAt.toEpochMilli());
        sitePayload.appendBytes(t.userIdentity.id); // 32 or 33 bytes

        final Buffer masterPayload = Buffer.buffer(130);
        masterPayload.appendLong(t.expiresAt.toEpochMilli());
        masterPayload.appendLong(t.createdAt.toEpochMilli());
        encodeOperatorIdentityV3(masterPayload, t.operatorIdentity);
        masterPayload.appendInt(siteKey.getId());
        masterPayload.appendBytes(AesGcm.encrypt(sitePayload.getBytes(), siteKey).getPayload());

        final Buffer b = Buffer.buffer(164);
        b.appendByte(encodeIdentityTypeV3(t.userIdentity));
        b.appendByte((byte) t.version.rawVersion);
        b.appendInt(masterKey.getId());
        b.appendBytes(AesGcm.encrypt(masterPayload.getBytes(), masterKey).getPayload());

        return b.getBytes();
    }

    @Override
    public RefreshToken decodeRefreshToken(String s) {
        if (s != null && !s.isEmpty()) {
            final byte[] bytes;
            try {
                bytes = EncodingUtils.fromBase64(s);
            } catch (IllegalArgumentException e) {
                throw new ClientInputValidationException("Invalid refresh token");
            }
            final Buffer b = Buffer.buffer(bytes);
            if (bytes.length >= 6 && (b.getByte(1) & 0xff) == TokenVersion.V4.rawVersion) {
                return decodeRefreshTokenV4(b, bytes);
            }
        }

        throw new ClientInputValidationException("Invalid refresh token version");
    }

    /**
     * Unwraps the V2 API refresh token envelope (scope + keyId + encrypted JSON) and returns
     * the inner refresh token string. Used when the response body contains refresh_response_key
     * and refresh_token is this wrapped form rather than the raw V4 token.
     */
    public String unwrapV2RefreshEnvelope(String wrappedBase64) {
        byte[] bytes = EncodingUtils.fromBase64(wrappedBase64);
        if (bytes.length < 5) {
            throw new ClientInputValidationException("Invalid V2 refresh envelope");
        }
        Buffer b = Buffer.buffer(bytes);
        int keyId = b.getInt(1);
        KeysetKey key = this.keyManager.getKey(keyId);
        if (key == null) {
            throw new ClientInputValidationException("Failed to fetch key with id: " + keyId);
        }
        byte[] decrypted = AesGcm.decrypt(bytes, 5, key);
        JsonObject json = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));
        String innerToken = json.getString("refresh_token");
        if (innerToken == null) {
            throw new ClientInputValidationException("V2 refresh envelope missing refresh_token");
        }
        return innerToken;
    }

    private RefreshToken decodeRefreshTokenV4(Buffer b, byte[] bytes) {
        final int keyId = b.getInt(2);
        final KeysetKey key = this.keyManager.getKey(keyId);

        if (key == null) {
            throw new ClientInputValidationException("Failed to fetch key with id: " + keyId);
        }

        final byte[] decryptedPayload = AesGcm.decrypt(bytes, 6, key);

        final Buffer b2 = Buffer.buffer(decryptedPayload);
        final Instant expiresAt = Instant.ofEpochMilli(b2.getLong(0));
        final Instant createdAt = Instant.ofEpochMilli(b2.getLong(8));
        final OperatorIdentity operatorIdentity = decodeOperatorIdentityV3(b2, 16);
        final PublisherIdentity publisherIdentity = decodePublisherIdentityV3(b2, 29);
        final int privacyBits = b2.getInt(45);
        final Instant establishedAt = Instant.ofEpochMilli(b2.getLong(49));
        final IdentityScope identityScope = decodeIdentityScopeV3(b2.getByte(57));
        final IdentityType identityType = decodeIdentityTypeV3(b2.getByte(57));
        final byte[] id = b2.getBytes(58, 90);

        if (identityScope != decodeIdentityScopeV3(b.getByte(0))) {
            throw new ClientInputValidationException("Failed to decode refreshTokenV4: Identity scope mismatch");
        }
        if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
            throw new ClientInputValidationException("Failed to decode refreshTokenV4: Identity type mismatch");
        }

        return new RefreshToken(
                TokenVersion.V4, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, null));
    }

    @Override
    public AdvertisingToken decodeAdvertisingToken(String base64AdvertisingToken) {
        if (base64AdvertisingToken.length() < 4) {
            throw new ClientInputValidationException("Advertising token is too short");
        }

        String headerStr = base64AdvertisingToken.substring(0, 4);
        boolean isBase64UrlEncoding = (headerStr.indexOf('-') != -1 || headerStr.indexOf('_') != -1);
        byte[] headerBytes = isBase64UrlEncoding ? Uid2Base64UrlCoder.decode(headerStr) : Base64.getDecoder().decode(headerStr);

        int unsignedByte = ((int) headerBytes[1]) & 0xff;
        if (unsignedByte != TokenVersion.V4.rawVersion) {
            throw new ClientInputValidationException("V2/V3 advertising token no longer supported");
        }

        final byte[] bytes = Uid2Base64UrlCoder.decode(base64AdvertisingToken);
        final Buffer b = Buffer.buffer(bytes);
        return decodeAdvertisingTokenV3orV4(b, bytes, TokenVersion.V4);
    }

    public AdvertisingToken decodeAdvertisingTokenV3orV4(Buffer b, byte[] bytes, TokenVersion tokenVersion) {
        final int masterKeyId = b.getInt(2);

        final byte[] masterPayloadBytes = AesGcm.decrypt(bytes, 6, this.keyManager.getKey(masterKeyId));
        final Buffer masterPayload = Buffer.buffer(masterPayloadBytes);
        final Instant expiresAt = Instant.ofEpochMilli(masterPayload.getLong(0));
        final Instant createdAt = Instant.ofEpochMilli(masterPayload.getLong(8));
        final OperatorIdentity operatorIdentity = decodeOperatorIdentityV3(masterPayload, 16);
        final int siteKeyId = masterPayload.getInt(29);

        final Buffer sitePayload = Buffer.buffer(AesGcm.decrypt(masterPayloadBytes, 33, this.keyManager.getKey(siteKeyId)));
        final PublisherIdentity publisherIdentity = decodePublisherIdentityV3(sitePayload, 0);
        final int privacyBits = sitePayload.getInt(16);
        final Instant establishedAt = Instant.ofEpochMilli(sitePayload.getLong(20));
        final Instant refreshedAt = Instant.ofEpochMilli(sitePayload.getLong(28));
        final byte[] id = sitePayload.slice(36, sitePayload.length()).getBytes();
        final IdentityScope identityScope = id.length == 32 ? IdentityScope.UID2 : decodeIdentityScopeV3(id[0]);
        final IdentityType identityType = id.length == 32 ? IdentityType.Email : decodeIdentityTypeV3(id[0]);

        if (id.length > 32) {
            if (identityScope != decodeIdentityScopeV3(b.getByte(0))) {
                throw new ClientInputValidationException("Failed decoding advertisingTokenV3: Identity scope mismatch");
            }
            if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
                throw new ClientInputValidationException("Failed decoding advertisingTokenV3: Identity type mismatch");
            }
        }

        return new AdvertisingToken(
                tokenVersion, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, refreshedAt),
                siteKeyId
        );
    }

    private void recordRefreshTokenVersionCount(String siteId, TokenVersion tokenVersion) {
        Counter.builder("uid2_refresh_token_served_count_total")
                .description(String.format("Counter for the amount of refresh token %s served", tokenVersion.toString().toLowerCase()))
                .tags("site_id", String.valueOf(siteId))
                .tags("refresh_token_version", tokenVersion.toString().toLowerCase())
                .register(Metrics.globalRegistry).increment();
    }

    public byte[] encode(RefreshToken t, Instant asOf) {
        final KeysetKey serviceKey = this.keyManager.getRefreshKey(asOf);

        if (t.version != TokenVersion.V4) {
            throw new ClientInputValidationException("RefreshToken version " + t.version + " not supported");
        }
        recordRefreshTokenVersionCount(String.valueOf(t.publisherIdentity.siteId), TokenVersion.V4);
        return encodeV4(t, serviceKey);
    }

    private byte[] encodeV4(RefreshToken t, KeysetKey serviceKey) {
        final Buffer refreshPayload = Buffer.buffer(90);
        refreshPayload.appendLong(t.expiresAt.toEpochMilli());
        refreshPayload.appendLong(t.createdAt.toEpochMilli());
        encodeOperatorIdentityV3(refreshPayload, t.operatorIdentity);
        encodePublisherIdentityV3(refreshPayload, t.publisherIdentity);
        refreshPayload.appendInt(t.userIdentity.privacyBits);
        refreshPayload.appendLong(t.userIdentity.establishedAt.toEpochMilli());
        refreshPayload.appendByte(encodeIdentityTypeV3(t.userIdentity));
        refreshPayload.appendBytes(t.userIdentity.id);

        final Buffer b = Buffer.buffer(124);
        b.appendByte(encodeIdentityTypeV3(t.userIdentity));
        b.appendByte((byte) TokenVersion.V4.rawVersion);
        b.appendInt(serviceKey.getId());
        b.appendBytes(AesGcm.encrypt(refreshPayload.getBytes(), serviceKey).getPayload());

        return b.getBytes();
    }

    public static String bytesToBase64Token(byte[] advertisingTokenBytes, TokenVersion tokenVersion) {
        return (tokenVersion == TokenVersion.V4) ?
                Uid2Base64UrlCoder.encode(advertisingTokenBytes) : EncodingUtils.toBase64String(advertisingTokenBytes);
    }

    @Override
    public IdentityTokens encode(AdvertisingToken advertisingToken, RefreshToken refreshToken, Instant refreshFrom, Instant asOf) {
        final byte[] advertisingTokenBytes = encode(advertisingToken, asOf);
        final String base64AdvertisingToken = bytesToBase64Token(advertisingTokenBytes, advertisingToken.version);

        return new IdentityTokens(
                base64AdvertisingToken,
                advertisingToken.version,
                EncodingUtils.toBase64String(encode(refreshToken, asOf)),
                advertisingToken.expiresAt,
                refreshToken.expiresAt,
                refreshFrom
        );
    }

    private static byte encodeIdentityTypeV3(UserIdentity userIdentity) {
        return (byte) (TokenUtils.encodeIdentityScope(userIdentity.identityScope) | (userIdentity.identityType.getValue() << 2) | 3);
        // "| 3" is used so that the 2nd char matches the version when V3 or higher. Eg "3" for V3 and "4" for V4
    }

    private static IdentityScope decodeIdentityScopeV3(byte value) {
        return IdentityScope.fromValue((value & 0x10) >> 4);
    }

    private static IdentityType decodeIdentityTypeV3(byte value) {
        return IdentityType.fromValue((value & 0xf) >> 2);
    }

    static void encodePublisherIdentityV3(Buffer b, PublisherIdentity publisherIdentity) {
        b.appendInt(publisherIdentity.siteId);
        b.appendLong(publisherIdentity.publisherId);
        b.appendInt(publisherIdentity.clientKeyId);
    }

    static PublisherIdentity decodePublisherIdentityV3(Buffer b, int offset) {
        return new PublisherIdentity(b.getInt(offset), b.getInt(offset + 12), b.getLong(offset + 4));
    }

    static void encodeOperatorIdentityV3(Buffer b, OperatorIdentity operatorIdentity) {
        b.appendInt(operatorIdentity.siteId);
        b.appendByte((byte) operatorIdentity.operatorType.value);
        b.appendInt(operatorIdentity.operatorVersion);
        b.appendInt(operatorIdentity.operatorKeyId);
    }

    static OperatorIdentity decodeOperatorIdentityV3(Buffer b, int offset) {
        return new OperatorIdentity(b.getInt(offset), OperatorType.fromValue(b.getByte(offset + 4)), b.getInt(offset + 5), b.getInt(offset + 9));
    }
}
