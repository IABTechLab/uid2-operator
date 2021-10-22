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

import java.security.SecureRandom;
import java.time.Instant;

public class EncryptedTokenEncoder implements ITokenEncoder {

    private static final byte FIELD_SEPARATOR = (byte) 95;
    private final IKeyStore keyStore;
    private final SecureRandom random = new SecureRandom();

    public EncryptedTokenEncoder(IKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public byte[] encode(AdvertisingToken t) {
        final Instant now = Instant.now();
        final EncryptionKey masterKey = this.keyStore.getSnapshot().getMasterKey(now);
        final EncryptionKey siteEncryptionKey = EncryptionKeyUtil.getActiveSiteKey(
                this.keyStore.getSnapshot(), t.getIdentity().getSiteId(), Const.Data.AdvertisingTokenSiteId, now);
        final Buffer b = Buffer.buffer();

        // <version><space><master key id><space>

        b.appendByte((byte) t.getVersion());
        b.appendByte(FIELD_SEPARATOR);
        b.appendInt(masterKey.getId());
        b.appendByte(FIELD_SEPARATOR);

        Buffer b2 = Buffer.buffer();
        encodeSiteIdentity(b2, t.getIdentity(), siteEncryptionKey);

        byte[] encryptedId = EncryptionHelper.encrypt(b2.getBytes(), masterKey).getPayload();

        b.appendBytes(encryptedId);

        return b.getBytes();
    }

    @Override
    public RefreshToken decode(String s) {
        return decode(EncodingUtils.fromBase64(s));
    }

    @Override
    public RefreshToken decode(byte[] bytes) {
        final Buffer b = Buffer.buffer(bytes);

        final int version = b.getByte(0);
        final Instant createdAt = Instant.ofEpochMilli(b.getLong(2));
        final Instant expiresAt = Instant.ofEpochMilli(b.getLong(11));
        final Instant validTill = Instant.ofEpochMilli(b.getLong(20));
        final int keyId = b.getInt(29);

        final EncryptionKey key = this.keyStore.getSnapshot().getKey(keyId);

        final byte[] decryptedPayload = EncryptionHelper.decrypt(b.slice(34, b.length()).getBytes(), key);

        final Buffer b2 = Buffer.buffer(decryptedPayload);

        final int siteId = b2.getInt(0);
        final int length = b2.getInt(5);
        final String identity;
        try {

            identity = new String(b2.slice(10, 10 + length).getBytes(), "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Couldn't decode Entity", e);
        }

        final int privacyBits = b2.getInt(10 + length + 1);

        return new RefreshToken(
            version, createdAt, expiresAt, validTill,
            new UserIdentity(identity, siteId, privacyBits, EncodingUtils.NowUTCMillis()));
    }

    public AdvertisingToken decodeAdvertisingToken(String s) {
        return decodeAdvertisingToken(EncodingUtils.fromBase64(s));
    }

    public AdvertisingToken decodeAdvertisingToken(byte[] bytes) {
        try {
            final Buffer b = Buffer.buffer(bytes);
            final int version = b.getByte(0);
            final int masterKeyId = b.getInt(2);

            final byte[] decryptedPayload = EncryptionHelper.decrypt(b.slice(7, b.length()).getBytes(), this.keyStore.getSnapshot().getKey(masterKeyId));

            final Buffer b2 = Buffer.buffer(decryptedPayload);

            final int siteKeyId = b2.getInt(0);

            final byte[] decryptedSitePayload = EncryptionHelper.decrypt(b2.slice(5, b2.length()).getBytes(), this.keyStore.getSnapshot().getKey(siteKeyId));

            final Buffer b3 = Buffer.buffer(decryptedSitePayload);

            final int siteId = b3.getInt(0);
            final int length = b3.getInt(5);

            final String value = new String(b3.slice(10, 10 + length).getBytes(), "UTF-8");

            final int privacyBits = b3.getInt(10 + length + 1);

            return new AdvertisingToken(
                version,
                Instant.now(),
                Instant.now(),
                new UserIdentity(value, siteId, privacyBits, EncodingUtils.NowUTCMillis())
            );

        } catch (Exception e) {
            throw new RuntimeException("Couldn't decode Entity", e);
        }

    }

    @Override
    public byte[] encode(RefreshToken t) {
        final EncryptionKey serviceKey = this.keyStore.getSnapshot().getMasterKey(Instant.now());

        final Buffer b = Buffer.buffer();
        b.appendByte((byte) t.getVersion());
        b.appendByte(FIELD_SEPARATOR);
        b.appendLong(t.getCreatedAt().toEpochMilli());
        b.appendByte(FIELD_SEPARATOR);
        b.appendLong(t.getExpiresAt().toEpochMilli());
        b.appendByte(FIELD_SEPARATOR);
        b.appendLong(t.getValidTill().toEpochMilli());
        b.appendByte(FIELD_SEPARATOR);
        b.appendInt(serviceKey.getId());
        b.appendByte(FIELD_SEPARATOR);
        final byte[] encryptedIdentity = encryptIdentity(t.getIdentity(), serviceKey);
        b.appendBytes(encryptedIdentity);
        return b.getBytes();
    }

    private byte[] encodeSiteIdentity(Buffer b, UserIdentity identity, EncryptionKey siteEncryptionKey) {

        // <key-id><space><encrypted payload>

        b.appendInt(siteEncryptionKey.getId());
        b.appendByte(FIELD_SEPARATOR);
        final byte[] encryptedIdentity = encryptIdentity(identity, siteEncryptionKey);
        b.appendBytes(encryptedIdentity);

        return b.getBytes();
    }

    @Override
    public byte[] encode(UserToken t) {
        final EncryptionKey siteEncryptionKey = EncryptionKeyUtil.getActiveSiteKey(
                this.keyStore.getSnapshot(), t.getIdentity().getSiteId(), Const.Data.AdvertisingTokenSiteId, Instant.now());
        Buffer b = Buffer.buffer();
        b.appendByte((byte) t.getVersion());
        b.appendByte(FIELD_SEPARATOR);
        encodeSiteIdentity(b, t.getIdentity(), siteEncryptionKey);
        return b.getBytes();

    }

    @Override
    public IdentityTokens encode(AdvertisingToken advertisingToken, UserToken userToken, RefreshToken refreshToken) {
        return new IdentityTokens(
            EncodingUtils.toBase64String(encode(advertisingToken)),
            EncodingUtils.toBase64String(encode(userToken)),
            EncodingUtils.toBase64String(encode(refreshToken)),
            EncodingUtils.generateIdGuid(advertisingToken.getIdentity().getId())
        );
    }

    private byte[] encryptIdentity(UserIdentity identity, EncryptionKey key) {
        Buffer b = Buffer.buffer();
        b.appendInt(identity.getSiteId());
        b.appendByte(FIELD_SEPARATOR);
        try {
            byte[] identityBytes = identity.getId().getBytes("UTF-8");
            b.appendInt(identityBytes.length);
            b.appendByte(FIELD_SEPARATOR);
            b.appendBytes(identityBytes);
        } catch (Exception e) {
            throw new RuntimeException("Could not turn Identity into UTF-8");
        }
        b.appendByte(FIELD_SEPARATOR);
        b.appendInt(identity.getPrivacyBits());
        b.appendBytes(this.getNononce());
        return EncryptionHelper.encrypt(b.getBytes(), key).getPayload();
    }

    private byte[] getNononce() {
        // This is to encure that Nonce itself doesn't have seperator
        // This is no longer necessary
        return EncodingUtils.toBase64(this.random.generateSeed(16));

    }

}
