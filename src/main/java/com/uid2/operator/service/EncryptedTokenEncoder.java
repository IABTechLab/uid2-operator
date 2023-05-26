package com.uid2.operator.service;

import com.uid2.operator.Const;
import com.uid2.operator.model.*;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.encryption.AesCbc;
import com.uid2.shared.encryption.AesGcm;
import io.vertx.core.buffer.Buffer;

import java.time.Instant;
import java.util.Base64;

public class EncryptedTokenEncoder implements ITokenEncoder {

    private final IKeyStore keyStore;

    public EncryptedTokenEncoder(IKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public byte[] encode(AdvertisingToken t, Instant asOf) {
        final EncryptionKey masterKey = this.keyStore.getSnapshot().getMasterKey(asOf);
        final EncryptionKey siteEncryptionKey = EncryptionKeyUtil.getActiveSiteKey(
                this.keyStore.getSnapshot(), t.publisherIdentity.siteId, Const.Data.AdvertisingTokenSiteId, asOf);

        return t.version == TokenVersion.V2
                ? encodeV2(t, masterKey, siteEncryptionKey)
                : encodeV3(t, masterKey, siteEncryptionKey); //TokenVersion.V4 also calls encodeV3() since the byte array is identical between V3 and V4
    }

    private byte[] encodeV2(AdvertisingToken t, EncryptionKey masterKey, EncryptionKey siteKey) {
        final Buffer b = Buffer.buffer();

        b.appendByte((byte) t.version.rawVersion);
        b.appendInt(masterKey.getId());

        Buffer b2 = Buffer.buffer();
        b2.appendLong(t.expiresAt.toEpochMilli());
        encodeSiteIdentityV2(b2, t.publisherIdentity, t.userIdentity, siteKey);

        final byte[] encryptedId = AesCbc.encrypt(b2.getBytes(), masterKey).getPayload();

        b.appendBytes(encryptedId);

        return b.getBytes();
    }

    private byte[] encodeV3(AdvertisingToken t, EncryptionKey masterKey, EncryptionKey siteKey) {
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
        final byte[] bytes = EncodingUtils.fromBase64(s);
        final Buffer b = Buffer.buffer(bytes);

        if (b.getByte(1) == TokenVersion.V3.rawVersion) {
            return decodeRefreshTokenV3(b, bytes);
        } else if (b.getByte(0) == TokenVersion.V2.rawVersion) {
            return decodeRefreshTokenV2(b);
        }

        throw new IllegalArgumentException("Invalid refresh token version");
    }

    private RefreshToken decodeRefreshTokenV2(Buffer b) {
        final Instant createdAt = Instant.ofEpochMilli(b.getLong(1));
        //final Instant expiresAt = Instant.ofEpochMilli(b.getLong(9));
        final Instant validTill = Instant.ofEpochMilli(b.getLong(17));
        final int keyId = b.getInt(25);

        final EncryptionKey key = this.keyStore.getSnapshot().getKey(keyId);

        final byte[] decryptedPayload = AesCbc.decrypt(b.slice(29, b.length()).getBytes(), key);

        final Buffer b2 = Buffer.buffer(decryptedPayload);

        final int siteId = b2.getInt(0);
        final int length = b2.getInt(4);
        final byte[] identity;
        try {
            identity = EncodingUtils.fromBase64(b2.slice(8, 8 + length).getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode refreshTokenV2: Identity segment is not valid base64.", e);
        }

        final int privacyBits = b2.getInt(8 + length);
        final long establishedMillis = b2.getLong(8 + length + 4);

        return new RefreshToken(
                TokenVersion.V2, createdAt, validTill,
                new OperatorIdentity(0, OperatorType.Service, 0, 0),
                new PublisherIdentity(siteId, 0, 0),
                new UserIdentity(IdentityScope.UID2, IdentityType.Email, identity, privacyBits, Instant.ofEpochMilli(establishedMillis), null));
    }

    private RefreshToken decodeRefreshTokenV3(Buffer b, byte[] bytes) {
        final int keyId = b.getInt(2);
        final EncryptionKey key = this.keyStore.getSnapshot().getKey(keyId);

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
            throw new IllegalArgumentException("Failed to decode refreshTokenV3: Identity scope mismatch");
        }
        if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
            throw new IllegalArgumentException("Failed to decode refreshTokenV3: Identity type mismatch");
        }

        return new RefreshToken(
                TokenVersion.V3, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, null));
    }

    @Override
    public AdvertisingToken decodeAdvertisingToken(String base64AdvertisingToken) {
        if (base64AdvertisingToken.length() < 4) {
            throw new IllegalArgumentException("Advertising token is too short");
        }

        String headerStr = base64AdvertisingToken.substring(0, 4);
        boolean isBase64UrlEncoding = (headerStr.indexOf('-') != -1 || headerStr.indexOf('_') != -1);
        byte[] headerBytes = isBase64UrlEncoding ? Uid2Base64UrlCoder.decode(headerStr) : Base64.getDecoder().decode(headerStr);

        if (headerBytes[0] == TokenVersion.V2.rawVersion) {
            final byte[] bytes = EncodingUtils.fromBase64(base64AdvertisingToken);
            final Buffer b = Buffer.buffer(bytes);
            return decodeAdvertisingTokenV2(b);
        }

        //Java's byte is signed, so we convert to unsigned before checking the enum
        int unsignedByte = ((int) headerBytes[1]) & 0xff;

        byte[] bytes;
        TokenVersion tokenVersion;
        if (unsignedByte == TokenVersion.V3.rawVersion) {
            bytes = EncodingUtils.fromBase64(base64AdvertisingToken);
            tokenVersion = TokenVersion.V3;
        } else if (unsignedByte == TokenVersion.V4.rawVersion) {
            bytes = Uid2Base64UrlCoder.decode(base64AdvertisingToken);  //same as V3 but use Base64URL encoding
            tokenVersion = TokenVersion.V4;
        } else {
            throw new IllegalArgumentException("Invalid advertising token version");
        }

        final Buffer b = Buffer.buffer(bytes);
        return decodeAdvertisingTokenV3orV4(b, bytes, tokenVersion);
    }

    public AdvertisingToken decodeAdvertisingTokenV2(Buffer b) {
        try {
            final int masterKeyId = b.getInt(1);

            final byte[] decryptedPayload = AesCbc.decrypt(b.slice(5, b.length()).getBytes(), this.keyStore.getSnapshot().getKey(masterKeyId));

            final Buffer b2 = Buffer.buffer(decryptedPayload);

            final long expiresMillis = b2.getLong(0);
            final int siteKeyId = b2.getInt(8);

            final byte[] decryptedSitePayload = AesCbc.decrypt(b2.slice(12, b2.length()).getBytes(), this.keyStore.getSnapshot().getKey(siteKeyId));

            final Buffer b3 = Buffer.buffer(decryptedSitePayload);

            final int siteId = b3.getInt(0);
            final int length = b3.getInt(4);

            final byte[] advertisingId = EncodingUtils.fromBase64(b3.slice(8, 8 + length).getBytes());

            final int privacyBits = b3.getInt(8 + length);
            final long establishedMillis = b3.getLong(8 + length + 4);

            return new AdvertisingToken(
                    TokenVersion.V2,
                    Instant.ofEpochMilli(establishedMillis),
                    Instant.ofEpochMilli(expiresMillis),
                    new OperatorIdentity(0, OperatorType.Service, 0, 0),
                    new PublisherIdentity(siteId, 0, 0),
                    new UserIdentity(IdentityScope.UID2, IdentityType.Email, advertisingId, privacyBits, Instant.ofEpochMilli(establishedMillis), null)
            );

        } catch (Exception e) {
            throw new RuntimeException("Couldn't decode advertisingTokenV2", e);
        }

    }

    public AdvertisingToken decodeAdvertisingTokenV3orV4(Buffer b, byte[] bytes, TokenVersion tokenVersion) {
        final int masterKeyId = b.getInt(2);

        final byte[] masterPayloadBytes = AesGcm.decrypt(bytes, 6, this.keyStore.getSnapshot().getKey(masterKeyId));
        final Buffer masterPayload = Buffer.buffer(masterPayloadBytes);
        final Instant expiresAt = Instant.ofEpochMilli(masterPayload.getLong(0));
        final Instant createdAt = Instant.ofEpochMilli(masterPayload.getLong(8));
        final OperatorIdentity operatorIdentity = decodeOperatorIdentityV3(masterPayload, 16);
        final int siteKeyId = masterPayload.getInt(29);

        final Buffer sitePayload = Buffer.buffer(AesGcm.decrypt(masterPayloadBytes, 33, this.keyStore.getSnapshot().getKey(siteKeyId)));
        final PublisherIdentity publisherIdentity = decodePublisherIdentityV3(sitePayload, 0);
        final int privacyBits = sitePayload.getInt(16);
        final Instant establishedAt = Instant.ofEpochMilli(sitePayload.getLong(20));
        final Instant refreshedAt = Instant.ofEpochMilli(sitePayload.getLong(28));
        final byte[] id = sitePayload.slice(36, sitePayload.length()).getBytes();
        final IdentityScope identityScope = id.length == 32 ? IdentityScope.UID2 : decodeIdentityScopeV3(id[0]);
        final IdentityType identityType = id.length == 32 ? IdentityType.Email : decodeIdentityTypeV3(id[0]);

        if (id.length > 32)
        {
            if (identityScope != decodeIdentityScopeV3(b.getByte(0))) {
                throw new IllegalArgumentException("Failed decoding advertisingTokenV3: Identity scope mismatch");
            }
            if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
                throw new IllegalArgumentException("Failed decoding advertisingTokenV3: Identity type mismatch");
            }
        }

        return new AdvertisingToken(
                tokenVersion, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, refreshedAt)
        );
    }

    public byte[] encode(RefreshToken t, Instant asOf) {
        final EncryptionKey serviceKey = this.keyStore.getSnapshot().getRefreshKey(asOf);

        if (t.version == TokenVersion.V2) {
            return encodeV2(t, serviceKey);
        } else if (t.version == TokenVersion.V3) {
            return encodeV3(t, serviceKey);
        } else {
            throw new IllegalArgumentException("RefreshToken version " + t.version + " not supported");
        }
    }

    public byte[] encodeV2(RefreshToken t, EncryptionKey serviceKey) {
        final Buffer b = Buffer.buffer();
        b.appendByte((byte) t.version.rawVersion);
        b.appendLong(t.createdAt.toEpochMilli());
        b.appendLong(t.expiresAt.toEpochMilli()); // should not be used
        // give an extra minute for clients which are trying to refresh tokens close to or at the refresh expiry timestamp
        b.appendLong(t.expiresAt.plusSeconds(60).toEpochMilli());
        b.appendInt(serviceKey.getId());
        final byte[] encryptedIdentity = encryptIdentityV2(t.publisherIdentity, t.userIdentity, serviceKey);
        b.appendBytes(encryptedIdentity);
        return b.getBytes();
    }

    public byte[] encodeV3(RefreshToken t, EncryptionKey serviceKey) {
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
        b.appendByte((byte) t.version.rawVersion);
        b.appendInt(serviceKey.getId());
        b.appendBytes(AesGcm.encrypt(refreshPayload.getBytes(), serviceKey).getPayload());

        return b.getBytes();
    }

    private void encodeSiteIdentityV2(Buffer b, PublisherIdentity publisherIdentity, UserIdentity userIdentity, EncryptionKey siteEncryptionKey) {
        b.appendInt(siteEncryptionKey.getId());
        final byte[] encryptedIdentity = encryptIdentityV2(publisherIdentity, userIdentity, siteEncryptionKey);
        b.appendBytes(encryptedIdentity);
    }

    public byte[] encode(UserToken t, Instant asOf) {
        return encodeV2(t, asOf);
    }

    private byte[] encodeV2(UserToken t, Instant asOf) {
        final EncryptionKey siteEncryptionKey = EncryptionKeyUtil.getActiveSiteKey(
                this.keyStore.getSnapshot(), t.publisherIdentity.siteId, Const.Data.AdvertisingTokenSiteId, asOf);
        final Buffer b = Buffer.buffer();
        b.appendByte((byte) TokenVersion.V2.rawVersion);
        encodeSiteIdentityV2(b, t.publisherIdentity, t.userIdentity, siteEncryptionKey);
        return b.getBytes();
    }

    public static String bytesToBase64Token(byte[] advertisingTokenBytes, TokenVersion tokenVersion) {
        return (tokenVersion == TokenVersion.V4) ?
                Uid2Base64UrlCoder.encode(advertisingTokenBytes) : EncodingUtils.toBase64String(advertisingTokenBytes);
    }

    @Override
    public IdentityTokens encode(AdvertisingToken advertisingToken, UserToken userToken, RefreshToken refreshToken, Instant refreshFrom, Instant asOf) {

        final byte[] advertisingTokenBytes = encode(advertisingToken, asOf);
        final String base64AdvertisingToken = bytesToBase64Token(advertisingTokenBytes, advertisingToken.version);

        return new IdentityTokens(
                base64AdvertisingToken,
                EncodingUtils.toBase64String(encode(userToken, asOf)),
                EncodingUtils.toBase64String(encode(refreshToken, asOf)),
                advertisingToken.expiresAt,
                refreshToken.expiresAt,
                refreshFrom
        );
    }

    private byte[] encryptIdentityV2(PublisherIdentity publisherIdentity, UserIdentity identity, EncryptionKey key) {
        Buffer b = Buffer.buffer();
        try {
            b.appendInt(publisherIdentity.siteId);
            final byte[] identityBytes = EncodingUtils.toBase64(identity.id);
            b.appendInt(identityBytes.length);
            b.appendBytes(identityBytes);
            b.appendInt(identity.privacyBits);
            b.appendLong(identity.establishedAt.toEpochMilli());
            return AesCbc.encrypt(b.getBytes(), key).getPayload();
        } catch (Exception e) {
            throw new RuntimeException("Could not turn Identity into UTF-8", e);
        }
    }

    static private byte encodeIdentityTypeV3(UserIdentity userIdentity) {
        return (byte) (TokenUtils.encodeIdentityScope(userIdentity.identityScope) | (userIdentity.identityType.value << 2) | 3);
        // "| 3" is used so that the 2nd char matches the version when V3 or higher. Eg "3" for V3 and "4" for V4
    }

    static private IdentityScope decodeIdentityScopeV3(byte value) {
        return IdentityScope.fromValue((value & 0x10) >> 4);
    }

    static private IdentityType decodeIdentityTypeV3(byte value) {
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
        b.appendByte((byte)operatorIdentity.operatorType.value);
        b.appendInt(operatorIdentity.operatorVersion);
        b.appendInt(operatorIdentity.operatorKeyId);
    }

    static OperatorIdentity decodeOperatorIdentityV3(Buffer b, int offset) {
        return new OperatorIdentity(b.getInt(offset), OperatorType.fromValue(b.getByte(offset + 4)), b.getInt(offset + 5), b.getInt(offset + 9));
    }
}
