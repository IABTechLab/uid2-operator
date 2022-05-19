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

import com.uid2.operator.Const;
import com.uid2.operator.model.*;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.model.EncryptionKey;
import io.vertx.core.buffer.Buffer;

import java.time.Instant;

public class EncryptedTokenEncoder implements ITokenEncoder {

    private final IKeyStore keyStore;

    public EncryptedTokenEncoder(IKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public byte[] encode(AdvertisingToken t, Instant asOf) {
        final EncryptionKey masterKey = this.keyStore.getSnapshot().getMasterKey(asOf);
        final EncryptionKey siteEncryptionKey = EncryptionKeyUtil.getActiveSiteKey(
                this.keyStore.getSnapshot(), t.publisherIdentity.siteId, Const.Data.AdvertisingTokenSiteId, asOf);

        return t.version == TokenVersion.V3
            ? encodeV3(t, masterKey, siteEncryptionKey)
            : encodeV2(t, masterKey, siteEncryptionKey);
    }

    private byte[] encodeV2(AdvertisingToken t, EncryptionKey masterKey, EncryptionKey siteKey) {
        final Buffer b = Buffer.buffer();

        b.appendByte((byte) t.version.rawVersion);
        b.appendInt(masterKey.getId());

        Buffer b2 = Buffer.buffer();
        b2.appendLong(t.expiresAt.toEpochMilli());
        encodeSiteIdentityV2(b2, t.publisherIdentity, t.userIdentity, siteKey);

        final byte[] encryptedId = EncryptionHelper.encrypt(b2.getBytes(), masterKey).getPayload();

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
        masterPayload.appendBytes(EncryptionHelper.encryptGCM(sitePayload.getBytes(), siteKey).getPayload());

        final Buffer b = Buffer.buffer(164);
        b.appendByte(encodeIdentityTypeV3(t.userIdentity));
        b.appendByte((byte) t.version.rawVersion);
        b.appendInt(masterKey.getId());
        b.appendBytes(EncryptionHelper.encryptGCM(masterPayload.getBytes(), masterKey).getPayload());

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

        final byte[] decryptedPayload = EncryptionHelper.decrypt(b.slice(29, b.length()).getBytes(), key);

        final Buffer b2 = Buffer.buffer(decryptedPayload);

        final int siteId = b2.getInt(0);
        final int length = b2.getInt(4);
        final byte[] identity;
        try {

            identity = EncodingUtils.fromBase64(b2.slice(8, 8 + length).getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Couldn't decode Entity", e);
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

        final byte[] decryptedPayload = EncryptionHelper.decryptGCM(bytes, 6, key);

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
            throw new IllegalArgumentException("Identity scope mismatch");
        }
        if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
            throw new IllegalArgumentException("Identity type mismatch");
        }

        return new RefreshToken(
                TokenVersion.V3, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, null));
    }

    @Override
    public AdvertisingToken decodeAdvertisingToken(String s) {
        final byte[] bytes = EncodingUtils.fromBase64(s);
        final Buffer b = Buffer.buffer(bytes);

        if (b.getByte(1) == TokenVersion.V3.rawVersion) {
            return decodeAdvertisingTokenV3(b, bytes);
        } else if (b.getByte(0) == TokenVersion.V2.rawVersion) {
            return decodeAdvertisingTokenV2(b);
        }

        throw new IllegalArgumentException("Invalid advertising token version");
    }

    public AdvertisingToken decodeAdvertisingTokenV2(Buffer b) {
        try {
            final int masterKeyId = b.getInt(1);

            final byte[] decryptedPayload = EncryptionHelper.decrypt(b.slice(5, b.length()).getBytes(), this.keyStore.getSnapshot().getKey(masterKeyId));

            final Buffer b2 = Buffer.buffer(decryptedPayload);

            final long expiresMillis = b2.getLong(0);
            final int siteKeyId = b2.getInt(8);

            final byte[] decryptedSitePayload = EncryptionHelper.decrypt(b2.slice(12, b2.length()).getBytes(), this.keyStore.getSnapshot().getKey(siteKeyId));

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
            throw new RuntimeException("Couldn't decode Entity", e);
        }

    }

    public AdvertisingToken decodeAdvertisingTokenV3(Buffer b, byte[] bytes) {
        final int masterKeyId = b.getInt(2);

        final byte[] masterPayloadBytes = EncryptionHelper.decryptGCM(bytes, 6, this.keyStore.getSnapshot().getKey(masterKeyId));
        final Buffer masterPayload = Buffer.buffer(masterPayloadBytes);
        final Instant expiresAt = Instant.ofEpochMilli(masterPayload.getLong(0));
        final Instant createdAt = Instant.ofEpochMilli(masterPayload.getLong(8));
        final OperatorIdentity operatorIdentity = decodeOperatorIdentityV3(masterPayload, 16);
        final int siteKeyId = masterPayload.getInt(29);

        final Buffer sitePayload = Buffer.buffer(EncryptionHelper.decryptGCM(masterPayloadBytes, 33, this.keyStore.getSnapshot().getKey(siteKeyId)));
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
                throw new IllegalArgumentException("Identity scope mismatch");
            }
            if (identityType != decodeIdentityTypeV3(b.getByte(0))) {
                throw new IllegalArgumentException("Identity type mismatch");
            }
        }

        return new AdvertisingToken(
                TokenVersion.V3, createdAt, expiresAt, operatorIdentity, publisherIdentity,
                new UserIdentity(identityScope, identityType, id, privacyBits, establishedAt, refreshedAt)
        );
    }

    public byte[] encode(RefreshToken t, Instant asOf) {
        final EncryptionKey serviceKey = this.keyStore.getSnapshot().getRefreshKey(asOf);

        return t.version == TokenVersion.V3
                ? encodeV3(t, serviceKey)
                : encodeV2(t, serviceKey);
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
        b.appendBytes(EncryptionHelper.encryptGCM(refreshPayload.getBytes(), serviceKey).getPayload());

        return b.getBytes();
    }

    private byte[] encodeSiteIdentityV2(Buffer b, PublisherIdentity publisherIdentity, UserIdentity userIdentity, EncryptionKey siteEncryptionKey) {

        b.appendInt(siteEncryptionKey.getId());
        final byte[] encryptedIdentity = encryptIdentityV2(publisherIdentity, userIdentity, siteEncryptionKey);
        b.appendBytes(encryptedIdentity);

        return b.getBytes();
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

    @Override
    public IdentityTokens encode(AdvertisingToken advertisingToken, UserToken userToken, RefreshToken refreshToken, Instant refreshFrom, Instant asOf) {
        return new IdentityTokens(
                EncodingUtils.toBase64String(encode(advertisingToken, asOf)),
                EncodingUtils.toBase64String(encode(userToken, asOf)),
                EncodingUtils.toBase64String(encode(refreshToken, asOf)),
                advertisingToken.expiresAt,
                refreshToken.expiresAt,
                refreshFrom
        );
    }

    private byte[] encryptIdentityV2(PublisherIdentity publisherIdentity, UserIdentity identity, EncryptionKey key) {
        Buffer b = Buffer.buffer();
        b.appendInt(publisherIdentity.siteId);
        try {
            final byte[] identityBytes = EncodingUtils.toBase64(identity.id);
            b.appendInt(identityBytes.length);
            b.appendBytes(identityBytes);
        } catch (Exception e) {
            throw new RuntimeException("Could not turn Identity into UTF-8");
        }
        b.appendInt(identity.privacyBits);
        b.appendLong(identity.establishedAt.toEpochMilli());
        return EncryptionHelper.encrypt(b.getBytes(), key).getPayload();
    }

    static private byte encodeIdentityTypeV3(UserIdentity userIdentity) {
        return (byte) (TokenUtils.encodeIdentityScope(userIdentity.identityScope) | (userIdentity.identityType.value << 2) | 3);
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
