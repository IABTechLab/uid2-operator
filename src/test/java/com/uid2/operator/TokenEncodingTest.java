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

package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class TokenEncodingTest {

    private final IKeyStore keyStoreInstance;

    public TokenEncodingTest() throws Exception {
        RotatingKeyStore keyStore = new RotatingKeyStore(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/keys/metadata.json");;

        JsonObject m = keyStore.getMetadata();
        keyStore.loadContent(m);

        this.keyStoreInstance = keyStore;
    }

    @Test
    public void testRefreshTokenEncodingV2() {
        final EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStoreInstance);
        final Instant now = EncodingUtils.NowUTCMillis();
        final RefreshToken token = new RefreshToken(TokenVersion.V2,
            now,
            now.plusSeconds(360),
            new OperatorIdentity(101, OperatorType.Service, 102, 103),
            new PublisherIdentity(111, 112, 113),
            new UserIdentity(IdentityScope.UID2, IdentityType.Email, "some-id".getBytes(StandardCharsets.UTF_8), 121, now, now.minusSeconds(122)),
            null
        );

        final byte[] encodedBytes = encoder.encode(token, now);
        final RefreshToken decoded = encoder.decodeRefreshToken(EncodingUtils.toBase64String(encodedBytes));

        Assert.assertEquals(TokenVersion.V2, decoded.version);
        Assert.assertEquals(token.createdAt, decoded.createdAt);
        Assert.assertEquals(token.expiresAt.plusSeconds(60), decoded.expiresAt);
        Assert.assertTrue(token.userIdentity.matches(decoded.userIdentity));
        Assert.assertEquals(token.userIdentity.privacyBits, decoded.userIdentity.privacyBits);
        Assert.assertEquals(token.userIdentity.establishedAt, decoded.userIdentity.establishedAt);
        Assert.assertEquals(token.publisherIdentity.siteId, decoded.publisherIdentity.siteId);

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(25);
        EncryptionKey key = this.keyStoreInstance.getSnapshot().getKey(keyId);
        Assert.assertEquals(Const.Data.RefreshKeySiteId, key.getSiteId());
    }

    @Test
    public void testAdvertisingTokenEncodingV2() {
        final EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStoreInstance);
        final Instant now = EncodingUtils.NowUTCMillis();
        final AdvertisingToken token = new AdvertisingToken(
            TokenVersion.V2,
            now,
            now.plusSeconds(60),
            new OperatorIdentity(101, OperatorType.Service, 102, 103),
            new PublisherIdentity(111, 112, 113),
            new UserIdentity(IdentityScope.UID2, IdentityType.Email, "some-id".getBytes(StandardCharsets.UTF_8), 121, now, now.minusSeconds(122))
        );

        final byte[] encodedBytes = encoder.encode(token, now);
        final AdvertisingToken decoded = encoder.decodeAdvertisingToken(EncodingUtils.toBase64String(encodedBytes));

        Assert.assertEquals(TokenVersion.V2, decoded.version);
        Assert.assertEquals(token.createdAt, decoded.createdAt);
        Assert.assertEquals(token.expiresAt, decoded.expiresAt);
        Assert.assertTrue(token.userIdentity.matches(decoded.userIdentity));
        Assert.assertEquals(token.userIdentity.privacyBits, decoded.userIdentity.privacyBits);
        Assert.assertEquals(token.userIdentity.establishedAt, decoded.userIdentity.establishedAt);
        Assert.assertEquals(token.publisherIdentity.siteId, decoded.publisherIdentity.siteId);

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(1);
        EncryptionKey key = this.keyStoreInstance.getSnapshot().getKey(keyId);
        Assert.assertEquals(Const.Data.MasterKeySiteId, key.getSiteId());
    }
}
