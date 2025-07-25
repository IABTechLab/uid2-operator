package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.TokenUtils;
import com.uid2.shared.Const.Data;
import com.uid2.shared.model.TokenVersion;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.reader.RotatingKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.junit.Assert;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class TokenEncodingTest {

    private final KeyManager keyManager;

    public TokenEncodingTest() throws Exception {
        RotatingKeysetKeyStore keysetKeyStore = new RotatingKeysetKeyStore(
            new EmbeddedResourceStorage(Main.class),
            new GlobalScope(new CloudPath("/com.uid2.core/test/keyset_keys/metadata.json")));

        JsonObject m1 = keysetKeyStore.getMetadata();
        keysetKeyStore.loadContent(m1);

        RotatingKeysetProvider keysetProvider = new RotatingKeysetProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keysets/metadata.json")));

        JsonObject m2 = keysetProvider.getMetadata();
        keysetProvider.loadContent(m2);

        this.keyManager = new KeyManager(keysetKeyStore, keysetProvider);
    }

    @ParameterizedTest
    @EnumSource(value = TokenVersion.class, names = {"V3", "V4"})
    public void testRefreshTokenEncoding(TokenVersion tokenVersion) {
        final EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(this.keyManager);
        final Instant now = EncodingUtils.NowUTCMillis();

        final byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity("test@example.com", "some-salt");

        final RefreshToken token = new RefreshToken(tokenVersion,
            now,
            now.plusSeconds(360),
            new OperatorIdentity(101, OperatorType.Service, 102, 103),
            new PublisherIdentity(111, 112, 113),
            new UserIdentity(IdentityScope.UID2, IdentityType.Email, firstLevelHash, 121, now, now.minusSeconds(122))
        );

        if (tokenVersion == TokenVersion.V4) {
            Assert.assertThrows(Exception.class, () -> encoder.encode(token, now));
            return; //V4 not supported for RefreshTokens
        }
        final byte[] encodedBytes = encoder.encode(token, now);
        final RefreshToken decoded = encoder.decodeRefreshToken(EncodingUtils.toBase64String(encodedBytes));

        assertEquals(tokenVersion, decoded.version);
        assertEquals(token.createdAt, decoded.createdAt);
        int addSeconds = (tokenVersion == TokenVersion.V2) ? 60 : 0; //todo: why is there a 60 second buffer in encodeV2() but not in encodeV3()?
        assertEquals(token.expiresAt.plusSeconds(addSeconds), decoded.expiresAt);
        assertTrue(token.userIdentity.matches(decoded.userIdentity));
        assertEquals(token.userIdentity.privacyBits, decoded.userIdentity.privacyBits);
        assertEquals(token.userIdentity.establishedAt, decoded.userIdentity.establishedAt);
        assertEquals(token.publisherIdentity.siteId, decoded.publisherIdentity.siteId);

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(tokenVersion == TokenVersion.V2 ? 25 : 2);
        assertEquals(Data.RefreshKeySiteId, keyManager.getSiteIdFromKeyId(keyId));

        assertNotNull(Metrics.globalRegistry
                .get("uid2_refresh_token_served_count_total")
                .counter());
    }

    @ParameterizedTest
    @CsvSource({"false, V4", //same as current UID2 prod (as at 2024-12-10)
            "true, V4", //same as current EUID prod  (as at 2024-12-10)
            //the following combinations aren't used in any UID2/EUID environments but just testing them regardless
            "false, V3",
            "true, V3",
            "false, V2",
            "true, V2",
        }
    )
    public void testAdvertisingTokenEncodings(boolean useRawUIDv3, TokenVersion adTokenVersion) {
        final EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(this.keyManager);
        final Instant now = EncodingUtils.NowUTCMillis();

        final byte[] rawUid = UIDOperatorVerticleTest.getRawUid(IdentityType.Email, "test@example.com", IdentityScope.UID2, useRawUIDv3);

        final AdvertisingToken token = new AdvertisingToken(
            adTokenVersion,
            now,
            now.plusSeconds(60),
            new OperatorIdentity(101, OperatorType.Service, 102, 103),
            new PublisherIdentity(111, 112, 113),
            new UserIdentity(IdentityScope.UID2, IdentityType.Email, rawUid, 121, now, now.minusSeconds(122))
        );

        final byte[] encodedBytes = encoder.encode(token, now);
        final AdvertisingToken decoded = encoder.decodeAdvertisingToken(EncryptedTokenEncoder.bytesToBase64Token(encodedBytes, adTokenVersion));

        assertEquals(adTokenVersion, decoded.version);
        assertEquals(token.createdAt, decoded.createdAt);
        assertEquals(token.expiresAt, decoded.expiresAt);
        assertTrue(token.userIdentity.matches(decoded.userIdentity));
        assertEquals(token.userIdentity.privacyBits, decoded.userIdentity.privacyBits);
        assertEquals(token.userIdentity.establishedAt, decoded.userIdentity.establishedAt);
        assertEquals(token.publisherIdentity.siteId, decoded.publisherIdentity.siteId);

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(adTokenVersion == TokenVersion.V2 ? 1 : 2); //TODO - extract master key from token should be a helper function
        assertEquals(Data.MasterKeySiteId, keyManager.getSiteIdFromKeyId(keyId));
    }
}
