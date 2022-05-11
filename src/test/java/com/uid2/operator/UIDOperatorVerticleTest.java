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

import com.uid2.operator.model.AdvertisingToken;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptionHelper;
import com.uid2.operator.service.UIDOperatorService;
<<<<<<< HEAD
import com.uid2.shared.ApplicationVersion;
import com.uid2.shared.attest.NoAttestationProvider;
import com.uid2.shared.attest.UidCoreClient;
import com.uid2.shared.cloud.CloudUtils;
=======
import com.uid2.shared.Utils;
>>>>>>> master
import com.uid2.shared.model.EncryptionKey;
import com.uid2.operator.model.RefreshToken;
import com.uid2.operator.service.TokenUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.store.*;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.IClientKeyProvider;
import com.uid2.shared.store.IKeyAclProvider;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.store.ISaltProvider;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
<<<<<<< HEAD
import java.util.Arrays;
=======
import java.util.*;
>>>>>>> master

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class UIDOperatorVerticleTest {
    private AutoCloseable mocks;
<<<<<<< HEAD
    @Mock private IClientKeyProvider clientKeyProvider;
    @Mock private IKeyStore keyStore;
    @Mock private IKeyStore.IKeyStoreSnapshot keyStoreSnapshot;
    @Mock private IKeyAclProvider keyAclProvider;
    @Mock private IKeyAclProvider.IKeysAclSnapshot keyAclProviderSnapshot;
    @Mock private ISaltProvider saltProvider;
    @Mock private ISaltProvider.ISaltSnapshot saltProviderSnapshot;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    private UidCoreClient fakeCoreClient = new UidCoreClient("", "", new ApplicationVersion("test", "test"), CloudUtils.defaultProxy, new NoAttestationProvider(), false);
=======
    @Mock
    private IClientKeyProvider clientKeyProvider;
    @Mock
    private IKeyStore keyStore;
    @Mock
    private IKeyStore.IKeyStoreSnapshot keyStoreSnapshot;
    @Mock
    private IKeyAclProvider keyAclProvider;
    @Mock
    private IKeyAclProvider.IKeysAclSnapshot keyAclProviderSnapshot;
    @Mock
    private ISaltProvider saltProvider;
    @Mock
    private ISaltProvider.ISaltSnapshot saltProviderSnapshot;
    @Mock
    private IOptOutStore optOutStore;
    @Mock
    private Clock clock;
>>>>>>> master
    private static final String firstLevelSalt = "first-level-salt";
    private static final SaltEntry rotatingSalt123 = new SaltEntry(123, "hashed123", 0, "salt123");
    private static final Duration identityExpiresAfter = Duration.ofMinutes(10);
    private static final Duration refreshExpiresAfter = Duration.ofMinutes(15);
    private static final Duration refreshIdentityAfter = Duration.ofMinutes(5);
    private static final byte[] clientSecret = EncryptionHelper.getRandomKeyBytes();

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        mocks = MockitoAnnotations.openMocks(this);
        when(keyStore.getSnapshot()).thenReturn(keyStoreSnapshot);
        when(keyAclProvider.getSnapshot()).thenReturn(keyAclProviderSnapshot);
        when(saltProvider.getSnapshot(any())).thenReturn(saltProviderSnapshot);
        when(clock.instant()).thenAnswer(i -> Instant.now());

        final JsonObject config = new JsonObject();
        config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, identityExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, refreshExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, refreshIdentityAfter.toMillis() / 1000);
        config.put(Const.Config.FailureShutdownWaitHoursProp, 24);

        UIDOperatorVerticle verticle = new UIDOperatorVerticle(config, clientKeyProvider, keyStore, keyAclProvider, saltProvider, optOutStore, clock, fakeCoreClient);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }

    @AfterEach
    void teardown() throws Exception {
        mocks.close();
    }

    private static byte[] makeAesKey(String prefix) {
        return String.format("%1$16s", prefix).getBytes();
    }

    private void addEncryptionKeys(EncryptionKey... keys) {
        when(keyStoreSnapshot.getActiveKeySet()).thenReturn(Arrays.asList(keys));
    }

    private void fakeAuth(int siteId, Role... roles) {
        ClientKey clientKey = new ClientKey("test-key", Utils.toBase64String(clientSecret))
            .withSiteId(siteId).withRoles(roles);
        when(clientKeyProvider.get(any())).thenReturn(clientKey);
    }

    private void clearAuth() {
        when(clientKeyProvider.get(any())).thenReturn(null);
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return null;
        }
    }

    private String getUrlForEndpoint(String endpoint) {
        return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForOperator + Utils.getPortOffset(), endpoint);
    }

    private void send(String apiVersion, Vertx vertx, String endpoint, boolean isV1Get, String v1GetParam, JsonObject postPayload, int expectedHttpCode, Handler<JsonObject> handler) {
        if (apiVersion.equals("v2")) {
            ClientKey ck = (ClientKey) clientKeyProvider.get("");

            long nonce = new Random().nextLong();

            postV2(ck, vertx, endpoint, postPayload, nonce, ar -> {
                Assert.assertTrue(ar.succeeded());
                Assert.assertEquals(expectedHttpCode, ar.result().statusCode());

                if (ar.result().statusCode() == 200) {
                    byte[] decrypted = EncryptionHelper.decryptGCM(Utils.decodeBase64String(ar.result().bodyAsString()), 0, ck.getSecretBytes());
                    JsonObject respJson = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));

                    Buffer buffer = Buffer.buffer();
                    Assert.assertEquals(Utils.toBase64String(buffer.appendLong(nonce).getBytes()), respJson.getString("nonce"));

                    handler.handle(respJson);
                } else {
                    handler.handle(tryParseResponse(ar.result()));
                }
            });
        } else if (isV1Get) {
            get(vertx, endpoint + (v1GetParam != null ? "?" + v1GetParam : ""), ar -> {
                Assert.assertTrue(ar.succeeded());
                Assert.assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            });
        } else {
            post(vertx, endpoint, postPayload, ar -> {
                Assert.assertTrue(ar.succeeded());
                Assert.assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            });
        }
    }

    private JsonObject tryParseResponse(HttpResponse resp) {
        try {
            return resp.bodyAsJsonObject();
        }
        catch (Exception ex) {
            return null;
        }
    }

    private void get(Vertx vertx, String endpoint, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.getAbs(getUrlForEndpoint(endpoint)).send(handler);
    }

    private void post(Vertx vertx, String endpoint, JsonObject body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.postAbs(getUrlForEndpoint(endpoint)).sendJsonObject(body, handler);
    }

    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);

        Buffer b = Buffer.buffer();
        b.appendLong(Instant.now().toEpochMilli());
        b.appendLong(nonce);

        if (body != null)
            b.appendBytes(body.encode().getBytes(StandardCharsets.UTF_8));

        Buffer bufBody = Buffer.buffer();
        bufBody.appendByte((byte) 1);
        bufBody.appendBytes(EncryptionHelper.encryptGCM(b.getBytes(), ck.getSecretBytes()));

        client.postAbs(getUrlForEndpoint(endpoint))
            .putHeader("Authorization", "Bearer " + ck.getKey())
            .putHeader("content-type", "application/octet-stream")
            .sendBuffer(Buffer.buffer(Utils.toBase64String(bufBody.getBytes()).getBytes(StandardCharsets.UTF_8)), handler);
    }

    private void checkEncryptionKeysResponse(JsonObject response, EncryptionKey... expectedKeys) {
        assertEquals("success", response.getString("status"));
        final JsonArray responseKeys = response.getJsonArray("body");
        assertNotNull(responseKeys);
        assertEquals(expectedKeys.length, responseKeys.size());
        for (int i = 0; i < expectedKeys.length; ++i) {
            EncryptionKey expectedKey = expectedKeys[i];
            JsonObject actualKey = responseKeys.getJsonObject(i);
            assertEquals(expectedKey.getId(), actualKey.getInteger("id"));
            assertArrayEquals(expectedKey.getKeyBytes(), actualKey.getBinary("secret"));
            assertEquals(expectedKey.getCreated().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("created")));
            assertEquals(expectedKey.getActivates().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("activates")));
            assertEquals(expectedKey.getExpires().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("expires")));
            assertEquals(expectedKey.getSiteId(), actualKey.getInteger("site_id"));
        }
    }

    private void checkIdentityMapResponse(JsonObject response, String... expectedIdentifiers) {
        assertEquals("success", response.getString("status"));
        JsonObject body = response.getJsonObject("body");
        JsonArray mapped = body.getJsonArray("mapped");
        assertNotNull(mapped);
        assertEquals(expectedIdentifiers.length, mapped.size());
        for (int i = 0; i < expectedIdentifiers.length; ++i) {
            String expectedIdentifier = expectedIdentifiers[i];
            JsonObject actualMap = mapped.getJsonObject(i);
            assertEquals(expectedIdentifier, actualMap.getString("identifier"));
            assertFalse(actualMap.getString("advertising_id").isEmpty());
            assertFalse(actualMap.getString("bucket_id").isEmpty());
        }
    }

    private void setupSalts() {
        when(saltProviderSnapshot.getFirstLevelSalt()).thenReturn(firstLevelSalt);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(rotatingSalt123);
    }

    private void setupKeys() {
        EncryptionKey masterKey = new EncryptionKey(101, makeAesKey("masterKey"), Instant.now().minusSeconds(7), Instant.now(), Instant.now().plusSeconds(10), -1);
        EncryptionKey siteKey = new EncryptionKey(102, makeAesKey("siteKey"), Instant.now().minusSeconds(7), Instant.now(), Instant.now().plusSeconds(10), Const.Data.AdvertisingTokenSiteId);
        EncryptionKey refreshKey = new EncryptionKey(103, makeAesKey("refreshKey"), Instant.now().minusSeconds(7), Instant.now(), Instant.now().plusSeconds(10), -2);
        when(keyAclProviderSnapshot.canClientAccessKey(any(), any())).thenReturn(true);
        when(keyStoreSnapshot.getMasterKey(any())).thenReturn(masterKey);
        when(keyStoreSnapshot.getRefreshKey(any())).thenReturn(refreshKey);
        when(keyStoreSnapshot.getActiveSiteKey(eq(Const.Data.AdvertisingTokenSiteId), any())).thenReturn(siteKey);
        when(keyStoreSnapshot.getKey(101)).thenReturn(masterKey);
        when(keyStoreSnapshot.getKey(102)).thenReturn(siteKey);
        when(keyStoreSnapshot.getKey(103)).thenReturn(refreshKey);
        when(keyStoreSnapshot.getActiveKeySet()).thenReturn(Arrays.asList(new EncryptionKey[]{masterKey, siteKey, refreshKey}));
    }

    private void setupSiteKey(int siteId, int keyId) {
        EncryptionKey siteKey = new EncryptionKey(keyId, makeAesKey("siteKey" + siteId), Instant.now().minusSeconds(7), Instant.now(), Instant.now().plusSeconds(10), siteId);
        when(keyStoreSnapshot.getActiveSiteKey(eq(siteId), any())).thenReturn(siteKey);
        when(keyStoreSnapshot.getKey(keyId)).thenReturn(siteKey);
    }

    private void generateTokens(Vertx vertx, String inputType, String input, Handler<AsyncResult<JsonObject>> handler) {
        get(vertx, "v1/token/generate?" + inputType + "=" + input, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse responseGen = ar.result();
            assertEquals(200, responseGen.statusCode());
            JsonObject json = responseGen.bodyAsJsonObject();
            JsonObject body = json.getJsonObject("body");
            handler.handle(Future.succeededFuture(body));
        });
    }

    private static void assertEqualsClose(Instant expected, Instant actual, int withinSeconds) {
        assertTrue(expected.minusSeconds(withinSeconds).isBefore(actual));
        assertTrue(expected.plusSeconds(withinSeconds).isAfter(actual));
    }

    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
        testContext.completeNow();
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestNoAcl(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(205, Role.ID_READER);
        EncryptionKey[] encryptionKeys = {
            new EncryptionKey(101, "key101".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 201),
            new EncryptionKey(102, "key102".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 202),
        };
        addEncryptionKeys(encryptionKeys);
        when(keyAclProviderSnapshot.canClientAccessKey(any(), any())).thenReturn(true);

        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            checkEncryptionKeysResponse(respJson, encryptionKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestWithAcl(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(205, Role.ID_READER);
        EncryptionKey[] encryptionKeys = {
            new EncryptionKey(101, "key101".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 201),
            new EncryptionKey(102, "key102".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 202),
        };
        addEncryptionKeys(encryptionKeys);
        when(keyAclProviderSnapshot.canClientAccessKey(any(), any())).then((i) -> {
            return i.getArgument(1, EncryptionKey.class).getId() > 101;
        });

        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            checkEncryptionKeysResponse(respJson, Arrays.copyOfRange(encryptionKeys, 1, 2));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestClientBelongsToReservedSiteId(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Const.Data.AdvertisingTokenSiteId, Role.ID_READER);
        EncryptionKey[] encryptionKeys = {
            new EncryptionKey(101, "key101".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 201),
            new EncryptionKey(102, "key102".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 202),
        };
        addEncryptionKeys(encryptionKeys);
        when(keyAclProviderSnapshot.canClientAccessKey(any(), any())).thenReturn(true);

        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 401, respJson -> {
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestHideRefreshKey(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(205, Role.ID_READER);
        EncryptionKey[] encryptionKeys = {
            new EncryptionKey(101, "key101".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), -1),
            new EncryptionKey(102, "key102".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), -2),
            new EncryptionKey(103, "key103".getBytes(), Instant.now(), Instant.now(), Instant.now().plusSeconds(10), 202),
        };
        addEncryptionKeys(encryptionKeys);
        when(keyAclProviderSnapshot.canClientAccessKey(any(), any())).thenReturn(true);

        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            checkEncryptionKeysResponse(respJson,
                Arrays.stream(encryptionKeys).filter(k -> k.getSiteId() != -2).toArray(EncryptionKey[]::new));
            testContext.completeNow();
        });
    }


    @Test
    void tokenGenerateBothEmailAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        final String emailHash = TokenUtils.getIdentityHashString(emailAddress);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        get(vertx, "v1/token/generate?email=" + emailAddress + "&email_hash=" + urlEncode(emailHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateNoEmailOrHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        get(vertx, "v1/token/generate", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateForEmail(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        get(vertx, "v1/token/generate?email=" + emailAddress, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStore);

            AdvertisingToken advertisingToken = encoder.decodeAdvertisingToken(body.getString("advertising_token"));
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getAdvertisingIdV2FromIdentity(emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

            assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateForEmailHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        get(vertx, "v1/token/generate?email_hash=" + urlEncode(emailHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStore);

            AdvertisingToken advertisingToken = encoder.decodeAdvertisingToken(body.getString("advertising_token"));
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getAdvertisingIdV2FromIdentityHash(emailHash, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(emailHash, firstLevelSalt), refreshToken.userIdentity.id);

            assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateThenRefresh(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(vertx, "email", emailAddress, arGen -> {
            assertTrue(arGen.succeeded());
            JsonObject bodyGen = arGen.result();
            String refreshTokenString = bodyGen.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshTokenString), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("success", json.getString("status"));
                JsonObject body = json.getJsonObject("body");
                assertNotNull(body);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStore);

                AdvertisingToken advertisingToken = encoder.decodeAdvertisingToken(body.getString("advertising_token"));
                assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getAdvertisingIdV2FromIdentity(emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

                assertNotEquals(refreshTokenString, body.getString("refresh_token"));
                RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("refresh_token"));
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithEmail_Match(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(vertx, "email", emailAddress, arGen -> {
            assertTrue(arGen.succeeded());
            JsonObject bodyGen = arGen.result();
            String advertisingTokenString = bodyGen.getString("advertising_token");

            get(vertx, "v1/token/validate?token=" + urlEncode(advertisingTokenString) + "&email=" + emailAddress, ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithEmailHash_Match(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(vertx, "email", emailAddress, arGen -> {
            assertTrue(arGen.succeeded());
            JsonObject bodyGen = arGen.result();
            String advertisingTokenString = bodyGen.getString("advertising_token");

            get(vertx, "v1/token/validate?token=" + urlEncode(advertisingTokenString) + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInput)), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithBothEmailAndEmailHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(vertx, "email", emailAddress, arGen -> {
            assertTrue(arGen.succeeded());
            JsonObject bodyGen = arGen.result();
            String advertisingTokenString = bodyGen.getString("advertising_token");

            get(vertx, "v1/token/validate?token=" + urlEncode(advertisingTokenString) + "&email=" + emailAddress + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInput)), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(400, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertFalse(json.containsKey("body"));
                assertEquals("client_error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateUsingCustomSiteKey(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final int siteKeyId = 1201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        setupSiteKey(clientSiteId, siteKeyId);
        get(vertx, "v1/token/generate?email=" + emailAddress, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStore);

            AdvertisingToken advertisingToken = encoder.decodeAdvertisingToken(body.getString("advertising_token"));
            verify(keyStoreSnapshot).getKey(eq(siteKeyId));
            verify(keyStoreSnapshot, times(0)).getKey(eq(Const.Data.AdvertisingTokenSiteId));
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getAdvertisingIdV2FromIdentity(emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

            testContext.completeNow();
        });
    }

    @Test
    void tokenRefreshNoToken(Vertx vertx, VertxTestContext testContext) {
        get(vertx, "v1/token/refresh", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenRefreshInvalidTokenAuthenticated(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        get(vertx, "v1/token/refresh?refresh_token=abcd", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("invalid_token", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenRefreshInvalidTokenUnauthenticated(Vertx vertx, VertxTestContext testContext) {
        get(vertx, "v1/token/refresh?refresh_token=abcd", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("error", json.getString("status"));

            testContext.completeNow();
        });
    }

    private void generateRefreshToken(Vertx vertx, String email, int siteId, Handler<String> handler) {
        fakeAuth(siteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(vertx, "email", email, arGen -> {
            assertTrue(arGen.succeeded());
            JsonObject bodyGen = arGen.result();
            handler.handle(bodyGen.getString("refresh_token"));
        });
    }

    @Test
    void tokenRefreshExpiredTokenAuthenticated(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, emailAddress, clientSiteId, refreshToken -> {
            when(clock.instant()).thenAnswer(i -> Instant.now().plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));
            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(400, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("expired_token", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenRefreshExpiredTokenUnauthenticated(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, emailAddress, clientSiteId, refreshToken -> {
            clearAuth();
            when(clock.instant()).thenAnswer(i -> Instant.now().plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));
            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(400, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenRefreshOptOut(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, emailAddress, clientSiteId, refreshToken -> {
            when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("optout", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenRefreshOptOutBeforeLogin(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, emailAddress, clientSiteId, refreshToken -> {
            when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now().minusSeconds(10));

            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenValidateWithEmail_Mismatch(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send(apiVersion, vertx, apiVersion + "/token/validate", true,
            "token=abcdef&email=" + emailAddress,
            new JsonObject().put("token", "abcdef").put("email", emailAddress),
            200,
            respJson -> {
                assertFalse(respJson.getBoolean("body"));
                assertEquals("success", respJson.getString("status"));

                testContext.completeNow();
            });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenValidateWithEmailHash_Mismatch(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send(apiVersion, vertx, apiVersion + "/token/validate", true,
            "token=abcdef&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInput)),
            new JsonObject().put("token", "abcdef").put("email_hash", UIDOperatorVerticle.ValidationInput),
            200,
            respJson -> {
                assertFalse(respJson.getBoolean("body"));
                assertEquals("success", respJson.getString("status"));

                testContext.completeNow();
            });
    }

    @Test
    void identityMapBothEmailAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        final String emailHash = TokenUtils.getIdentityHashString(emailAddress);
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?email=" + emailAddress + "&email_hash=" + urlEncode(emailHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapNoEmailOrHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapForEmail(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?email=" + emailAddress, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            assertEquals(emailAddress, body.getString("identifier"));
            assertFalse(body.getString("advertising_id").isEmpty());
            assertFalse(body.getString("bucket_id").isEmpty());

            testContext.completeNow();
        });
    }

    @Test
    void identityMapForEmailHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?email_hash=" + urlEncode(emailHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            assertEquals(emailHash, body.getString("identifier"));
            assertFalse(body.getString("advertising_id").isEmpty());
            assertFalse(body.getString("bucket_id").isEmpty());

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchBothEmailAndHashEmpty(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        JsonArray emailHashes = new JsonArray();
        req.put("email", emails);
        req.put("email_hash", emailHashes);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, respJson -> {
            checkIdentityMapResponse(respJson);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchBothEmailAndHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        JsonArray emailHashes = new JsonArray();
        req.put("email", emails);
        req.put("email_hash", emailHashes);

        emails.add("test1@uid2.com");
        emailHashes.add(TokenUtils.getIdentityHashString("test2@uid2.com"));

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchNoEmailOrHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchEmails(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        emails.add("test1@uid2.com");
        emails.add("test2@uid2.com");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchEmailHashes(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray hashes = new JsonArray();
        req.put("email_hash", hashes);
        final String[] email_hashes = {
            TokenUtils.getIdentityHashString("test1@uid2.com"),
            TokenUtils.getIdentityHashString("test2@uid2.com"),
        };

        for (String email_hash : email_hashes) {
            hashes.add(email_hash);
        }

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, email_hashes);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchEmailsOneEmailInvalid(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        emails.add("test1@uid2.com");
        emails.add("bogus");
        emails.add("test2@uid2.com");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchEmailsNoEmails(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchRequestTooLarge(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        final String email = "test@uid2.com";
        for (long requestSize = 0; requestSize < UIDOperatorVerticle.MAX_REQUEST_BODY_SIZE; requestSize += email.length()) {
            emails.add(email);
        }

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 413, json -> {
            testContext.completeNow();
        });
    }

    @Test
    void LogoutV2(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.OPTOUT);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("email", "test@uid2.com");

        doAnswer(invocation -> {
            Handler<AsyncResult<Instant>> handler = invocation.getArgument(2);
            handler.handle(Future.succeededFuture(Instant.now()));
            return null;
        }).when(this.optOutStore).addEntry(any(), any(), any());

        send("v2", vertx, "v2/token/logout", false, null, req, 200, respJson -> {
            Assert.assertEquals("success", respJson.getString("status"));
            Assert.assertEquals("OK", respJson.getJsonObject("body").getString("optout"));
            testContext.completeNow();
        });
    }

    @Test void disableOnDeauthorization(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        get(vertx, "v1/token/generate?email=test@uid2.com", ar -> {
            // Request should succeed before revoking auth
            assertEquals(200, ar.result().statusCode());

            // Revoke auth
            fakeCoreClient.notifyResponseStatusWatcher(401);

            // Request should fail after revoking auth
            get(vertx, "v1/token/generate?email=test@uid2.com", ar1 -> {
                assertEquals(503, ar1.result().statusCode());
                testContext.completeNow();
            });

            // Recovered
            fakeCoreClient.notifyResponseStatusWatcher(200);
            get(vertx, "v1/token/generate?email=test@uid2.com", ar2 -> {
                assertEquals(200, ar2.result().statusCode());
                testContext.completeNow();
            });
        });
    }

    @Test void disableOnFailure(Vertx vertx, VertxTestContext testContext) throws Exception {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        // Verify success before revoking auth
        get(vertx, "v1/token/generate?email=test@uid2.com", ar -> {
            assertEquals(200, ar.result().statusCode());

            // Failure starts
            fakeCoreClient.notifyResponseStatusWatcher(500);

            // Can server before waiting period passes
            when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
            fakeCoreClient.notifyResponseStatusWatcher(500);
            get(vertx, "v1/token/generate?email=test@uid2.com", ar1 -> {
                assertEquals(200, ar1.result().statusCode());

                // Can't serve after waiting period passes
                when(clock.instant()).thenAnswer(i -> Instant.now().plus(24, ChronoUnit.HOURS));
                fakeCoreClient.notifyResponseStatusWatcher(500);
                get(vertx, "v1/token/generate?email=test@uid2.com", ar2 -> {
                    assertEquals(503, ar2.result().statusCode());
                });

                // Recovered
                fakeCoreClient.notifyResponseStatusWatcher(200);
                get(vertx, "v1/token/generate?email=test@uid2.com", ar3 -> {
                    assertEquals(200, ar3.result().statusCode());
                    testContext.completeNow();
                });
            });
        });
    }
}

