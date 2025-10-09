package com.uid2.operator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.operator.model.*;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.service.*;
import com.uid2.operator.store.IConfigStore;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.store.RuntimeConfig;
import com.uid2.operator.util.HttpMediaType;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.operator.util.Tuple;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.Utils;
import com.uid2.shared.audit.Audit;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.auth.Role;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.encryption.Random;
import com.uid2.shared.encryption.Uid2Base64UrlCoder;
import com.uid2.shared.model.*;
import com.uid2.shared.secret.KeyHashResult;
import com.uid2.shared.secret.KeyHasher;
import com.uid2.shared.store.*;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.salt.ISaltProvider;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.uid2.operator.ClientSideTokenGenerateTestUtil.decrypt;
import static com.uid2.operator.IdentityConst.*;
import static com.uid2.operator.service.EncodingUtils.getSha256;
import static com.uid2.operator.vertx.UIDOperatorVerticle.*;
import static com.uid2.shared.Const.Data.*;
import static com.uid2.shared.Const.Http.ClientVersionHeader;
import static java.time.temporal.ChronoUnit.DAYS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith({VertxExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class UIDOperatorVerticleTest {
    private static final Instant legacyClientCreationDateTime = Instant.ofEpochSecond(OPT_OUT_CHECK_CUTOFF_DATE).minus(1, ChronoUnit.SECONDS);
    private static final Instant newClientCreationDateTime = Instant.ofEpochSecond(OPT_OUT_CHECK_CUTOFF_DATE).plus(1, ChronoUnit.SECONDS);
    private static final String firstLevelSalt = "first-level-salt";
    private static final SaltEntry rotatingSalt123 = new SaltEntry(123, "hashed123", 0, "salt123", 1000L, "prevSalt123", null, null);
    private static final Duration identityExpiresAfter = Duration.ofMinutes(10);
    private static final Duration refreshExpiresAfter = Duration.ofMinutes(15);
    private static final Duration refreshIdentityAfter = Duration.ofMinutes(5);
    private static final KeyHasher keyHasher = new KeyHasher();
    private static final String clientKey = "UID2-C-L-999-fCXrMM.fsR3mDqAXELtWWMS+xG1s7RdgRTMqdOH2qaAo=";
    private static final byte[] clientSecret = Random.getRandomKeyBytes();
    private static final String clientSideTokenGenerateSubscriptionId = "4WvryDGbR5";
    private static final String clientSideTokenGeneratePublicKey = "UID2-X-L-MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsziOqRXZ7II0uJusaMxxCxlxgj8el/MUYLFMtWfB71Q3G1juyrAnzyqruNiPPnIuTETfFOridglP9UQNlwzNQg==";
    private static final String clientSideTokenGeneratePrivateKey = "UID2-Y-L-MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBop1Dw/IwDcstgicr/3tDoyR3OIpgAWgw8mD6oTO+1ug==";
    private static final String androidClientVersionHeaderValue = "Android-1.2.3";
    private static final String iosClientVersionHeaderValue = "ios-1.2.3";
    private static final String tvosClientVersionHeaderValue = "tvos-1.2.3";
    private static final int clientSideTokenGenerateSiteId = 123;
    private static final int optOutStatusMaxRequestSize = 1000;

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    @Mock
    private ISiteStore siteProvider;
    @Mock
    private IClientKeyProvider clientKeyProvider;
    @Mock
    private IClientSideKeypairStore clientSideKeypairProvider;
    @Mock
    private IClientSideKeypairStore.IClientSideKeypairStoreSnapshot clientSideKeypairSnapshot;
    @Mock
    private IKeysetKeyStore keysetKeyStore;
    @Mock
    private RotatingKeysetProvider keysetProvider;
    @Mock
    private ISaltProvider saltProvider;
    @Mock
    private SecureLinkValidatorService secureLinkValidatorService;
    @Mock
    private ISaltProvider.ISaltSnapshot saltProviderSnapshot;
    @Mock
    private IOptOutStore optOutStore;
    @Mock
    private Clock clock;
    @Mock
    private IStatsCollectorQueue statsCollectorQueue;
    @Mock
    private OperatorShutdownHandler shutdownHandler;
    @Mock
    private IConfigStore configStore;
    private UidInstanceIdProvider uidInstanceIdProvider;

    private final JsonObject config = new JsonObject();
    private SimpleMeterRegistry registry;
    private ExtendedUIDOperatorVerticle uidOperatorVerticle;
    private RuntimeConfig runtimeConfig;
    private EncryptedTokenEncoder encoder;

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext, TestInfo testInfo) {
        when(saltProvider.getSnapshot(any())).thenReturn(saltProviderSnapshot);
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().plus(1, ChronoUnit.HOURS));
        when(clock.instant()).thenAnswer(i -> now);
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(true);
        when(this.clientKeyProvider.getClientKey(clientKey)).thenReturn(new ClientKey("key-hash", "key-salt", "secret", "name", Instant.now(), Set.of(), 1, "key-id"));

        setupConfig(config);
        runtimeConfig = setupRuntimeConfig(config);
        // TODO: Remove this when we remove tokenGenerateOptOutTokenWithDisableOptoutTokenFF test
        if (testInfo.getTestMethod().isPresent() &&
                testInfo.getTestMethod().get().getName().equals("tokenGenerateOptOutTokenWithDisableOptoutTokenFF")) {
            config.put(Const.Config.DisableOptoutTokenProp, true);
        }
        if (testInfo.getDisplayName().equals("cstgNoPhoneSupport(Vertx, VertxTestContext)")) {
            config.put("enable_phone_support", false);
        }
        when(configStore.getConfig()).thenAnswer(x -> runtimeConfig);

        this.uidInstanceIdProvider = new UidInstanceIdProvider("test-instance", "id");

        this.uidOperatorVerticle = new ExtendedUIDOperatorVerticle(configStore, config, config.getBoolean("client_side_token_generate"), siteProvider, clientKeyProvider, clientSideKeypairProvider, new KeyManager(keysetKeyStore, keysetProvider), saltProvider, optOutStore, clock, statsCollectorQueue, secureLinkValidatorService, shutdownHandler::handleSaltRetrievalResponse, uidInstanceIdProvider);
        vertx.deployVerticle(uidOperatorVerticle, testContext.succeeding(id -> testContext.completeNow()));

        this.registry = new SimpleMeterRegistry();
        Metrics.globalRegistry.add(registry);

        this.encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
    }

    @AfterEach
    void teardown() {
        Metrics.globalRegistry.remove(registry);
    }

    private RuntimeConfig setupRuntimeConfig(JsonObject config) {
        return config.mapTo(RuntimeConfig.class);
    }

    private void setupConfig(JsonObject config) {
        config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, identityExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, refreshExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, refreshIdentityAfter.toMillis() / 1000);
        config.put(Const.Config.IdentityEnvironmentProp, "test");

        config.put(Const.Config.FailureShutdownWaitHoursProp, 24);
        config.put(Const.Config.SharingTokenExpiryProp, 60 * 60 * 24 * 30);

        config.put("identity_scope", getIdentityScope().toString());
        config.put(Const.Config.IdentityV3Prop, useRawUidV3());
        config.put("client_side_token_generate", true);
        config.put("key_sharing_endpoint_provide_app_names", true);
        config.put("client_side_token_generate_log_invalid_http_origins", true);

        config.put(Const.Config.AllowClockSkewSecondsProp, 3600);
        config.put(Const.Config.OptOutStatusApiEnabled, true);
        config.put(Const.Config.OptOutStatusMaxRequestSize, optOutStatusMaxRequestSize);
        config.put(Const.Config.DisableOptoutTokenProp, false);
        config.put(Const.Config.ConfigScanPeriodMsProp, 10000);
    }

    private static byte[] makeAesKey(String prefix) {
        return String.format("%1$16s", prefix).getBytes();
    }

    protected void fakeAuth(int siteId, Role... roles) {
        fakeAuth(siteId, legacyClientCreationDateTime, roles);
    }

    protected void fakeAuth(int siteId, Instant created, Role... roles) {
        KeyHashResult khr = keyHasher.hashKey(clientKey);
        ClientKey clientKey = new ClientKey(
                khr.getHash(),
                khr.getSalt(),
                Utils.toBase64String(clientSecret),
                "test-contact",
                created,
                Set.of(roles),
                siteId,
                "key-id"
        );
        when(clientKeyProvider.get(any())).thenReturn(clientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(clientKey);
        when(clientKeyProvider.getOldestClientKey(anyInt())).thenReturn(clientKey);
    }

    private void clearAuth() {
        when(clientKeyProvider.get(any())).thenReturn(null);
    }

    private String getUrlForEndpoint(String endpoint) {
        return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForOperator + Utils.getPortOffset(), endpoint);
    }

    private void send(Vertx vertx, String endpoint, JsonObject postPayload, int expectedHttpCode, Handler<JsonObject> handler) {
        send(vertx, endpoint, postPayload, expectedHttpCode, handler, Collections.emptyMap());
    }

    private void send(Vertx vertx, String endpoint, JsonObject postPayload, int expectedHttpCode, Handler<JsonObject> handler, Map<String, String> additionalHeaders) {
        ClientKey ck = (ClientKey) clientKeyProvider.get("");
        long nonce = new BigInteger(Random.getBytes(8)).longValue();

        postV2(ck, vertx, endpoint, postPayload, nonce, null, ar -> {
            assertTrue(ar.succeeded());
            assertEquals(expectedHttpCode, ar.result().statusCode());

            if (ar.result().statusCode() == 200) {
                byte[] byteResp = new byte[0];
                if (ar.result().headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.APPLICATION_OCTET_STREAM.getType(), true)) {
                    byteResp = ar.result().bodyAsBuffer().getBytes();
                } else if (ar.result().headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.TEXT_PLAIN.getType(), true)) {
                    byteResp = Utils.decodeBase64String(ar.result().bodyAsString());
                }

                byte[] decrypted = AesGcm.decrypt(byteResp, 0, ck.getSecretBytes());

                assertArrayEquals(Buffer.buffer().appendLong(nonce).getBytes(), Buffer.buffer(decrypted).slice(8, 16).getBytes());

                JsonObject respJson = new JsonObject(new String(decrypted, 16, decrypted.length - 16, StandardCharsets.UTF_8));
                handler.handle(respJson);
            } else {
                handler.handle(tryParseResponse(ar.result()));
            }
        }, additionalHeaders);
    }

    protected void sendTokenGenerate(Vertx vertx, JsonObject v2PostPayload, int expectedHttpCode,
                                     Handler<JsonObject> handler) {
        sendTokenGenerate(vertx, v2PostPayload, expectedHttpCode, null, handler, true, Collections.emptyMap());
    }

    protected void sendTokenGenerate(Vertx vertx, JsonObject v2PostPayload, int expectedHttpCode,
                                     Handler<JsonObject> handler, Map<String, String> additionalHeaders) {
        sendTokenGenerate(vertx, v2PostPayload, expectedHttpCode, null, handler, true, additionalHeaders);
    }

    protected void sendTokenGenerate(Vertx vertx, JsonObject v2PostPayload, int expectedHttpCode,
                                     Handler<JsonObject> handler, boolean additionalParams) {
        sendTokenGenerate(vertx, v2PostPayload, expectedHttpCode, null, handler, additionalParams, Collections.emptyMap());
    }

    private void sendTokenGenerate(Vertx vertx, JsonObject v2PostPayload, int expectedHttpCode, String referer, Handler<JsonObject> handler, boolean additionalParams) {
        sendTokenGenerate(vertx, v2PostPayload, expectedHttpCode, referer, handler, additionalParams, Collections.emptyMap());
    }

    private void sendTokenGenerate(Vertx vertx, JsonObject v2PostPayload, int expectedHttpCode, String referer, Handler<JsonObject> handler, boolean additionalParams, Map<String, String> additionalHeaders) {
        ClientKey ck = (ClientKey) clientKeyProvider.get("");

        long nonce = new BigInteger(Random.getBytes(8)).longValue();

        if (additionalParams) {
            addAdditionalTokenGenerateParams(v2PostPayload);
        }

        postV2(ck, vertx, "v2/token/generate", v2PostPayload, nonce, referer, ar -> {
            assertTrue(ar.succeeded());
            assertEquals(expectedHttpCode, ar.result().statusCode());

            if (ar.result().statusCode() == 200) {
                byte[] byteResp = new byte[0];
                if (ar.result().headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.APPLICATION_OCTET_STREAM.getType(), true)) {
                    byteResp = ar.result().bodyAsBuffer().getBytes();
                } else if (ar.result().headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.TEXT_PLAIN.getType(), true)) {
                    byteResp = Utils.decodeBase64String(ar.result().bodyAsString());
                }
                byte[] decrypted = AesGcm.decrypt(byteResp, 0, ck.getSecretBytes());

                assertArrayEquals(Buffer.buffer().appendLong(nonce).getBytes(), Buffer.buffer(decrypted).slice(8, 16).getBytes());

                JsonObject respJson = new JsonObject(new String(decrypted, 16, decrypted.length - 16, StandardCharsets.UTF_8));

                decodeV2RefreshToken(respJson);

                handler.handle(respJson);
            } else {
                handler.handle(tryParseResponse(ar.result()));
            }
        }, additionalHeaders);

    }

    private void sendTokenRefresh(Vertx vertx, VertxTestContext testContext, String refreshToken, String v2RefreshDecryptSecret, int expectedHttpCode,
                                  Handler<JsonObject> handler) {
        sendTokenRefresh(vertx, testContext, refreshToken, v2RefreshDecryptSecret, expectedHttpCode, handler, Collections.emptyMap());
    }

    private void sendTokenRefresh(Vertx vertx, VertxTestContext testContext, String refreshToken, String v2RefreshDecryptSecret, int expectedHttpCode,
                                  Handler<JsonObject> handler, Map<String, String> additionalHeaders) {
        WebClient client = WebClient.create(vertx);
        HttpRequest<Buffer> refreshHttpRequest = client.postAbs(getUrlForEndpoint("v2/token/refresh"));
        refreshHttpRequest.putHeader(HttpHeaders.CONTENT_TYPE.toString(), HttpMediaType.TEXT_PLAIN.getType());
        for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
            refreshHttpRequest.putHeader(entry.getKey(), entry.getValue());
        }

        refreshHttpRequest
                .sendBuffer(Buffer.buffer(refreshToken.getBytes(StandardCharsets.UTF_8)), testContext.succeeding(response -> testContext.verify(() -> {
                    assertEquals(expectedHttpCode, response.statusCode());

                    if (response.statusCode() == 200 && v2RefreshDecryptSecret != null) {
                        byte[] byteResp = new byte[0];
                        if (response.headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.APPLICATION_OCTET_STREAM.getType(), true)) {
                            byteResp = response.bodyAsBuffer().getBytes();
                        } else if (response.headers().contains(HttpHeaders.CONTENT_TYPE, HttpMediaType.TEXT_PLAIN.getType(), true)) {
                            byteResp = Utils.decodeBase64String(response.bodyAsString());
                        }
                        byte[] decrypted = AesGcm.decrypt(byteResp, 0, Utils.decodeBase64String(v2RefreshDecryptSecret));
                        JsonObject respJson = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));

                        if (respJson.getString("status").equals("success"))
                            decodeV2RefreshToken(respJson);

                        handler.handle(respJson);
                    } else {
                        handler.handle(tryParseResponse(response));
                    }
                })));
    }

    private String decodeV2RefreshToken(JsonObject respJson) {
        if (respJson.containsKey("body")) {
            JsonObject bodyJson = respJson.getJsonObject("body");

            byte[] tokenBytes = Utils.decodeBase64String(bodyJson.getString("refresh_token"));
            KeysetKey refreshKey = keysetKeyStore.getSnapshot().getKey(Buffer.buffer(tokenBytes).getInt(1));

            byte[] decrypted = AesGcm.decrypt(tokenBytes, 5, refreshKey);
            JsonObject tokenKeyJson = new JsonObject(new String(decrypted));

            String refreshToken = tokenKeyJson.getString("refresh_token");
            bodyJson.put("decrypted_refresh_token", refreshToken);

            return refreshToken;
        }

        return null;
    }

    private JsonObject tryParseResponse(HttpResponse<Buffer> resp) {
        try {
            return resp.bodyAsJsonObject();
        } catch (Exception ex) {
            return null;
        }
    }

    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, String referer, Handler<AsyncResult<HttpResponse<Buffer>>> handler, Map<String, String> additionalHeaders) {
        postV2(ck, vertx, endpoint, body, nonce, referer, handler, additionalHeaders, false);
    }

    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, String referer, Handler<AsyncResult<HttpResponse<Buffer>>> handler, Map<String, String> additionalHeaders, boolean forceBase64RequestBody) {
        WebClient client = WebClient.create(vertx);
        final String apiKey = ck == null ? "" : clientKey;
        HttpRequest<Buffer> request = client.postAbs(getUrlForEndpoint(endpoint))
                .putHeader(HttpHeaders.AUTHORIZATION.toString(), "Bearer " + apiKey)
                .putHeader(HttpHeaders.CONTENT_TYPE.toString(), HttpMediaType.TEXT_PLAIN.getType());

        for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
            request.putHeader(entry.getKey(), entry.getValue());
        }

        Buffer b = Buffer.buffer();
        b.appendLong(now.toEpochMilli());
        b.appendLong(nonce);

        if (body != null)
            b.appendBytes(body.encode().getBytes(StandardCharsets.UTF_8));

        Buffer bufBody = Buffer.buffer();
        bufBody.appendByte((byte) 1);
        byte[] payload = b.getBytes();
        if (ck != null) {
            bufBody.appendBytes(AesGcm.encrypt(payload, ck.getSecretBytes()));
        }
        if (referer != null) {
            request.putHeader("Referer", referer);
        }

        if (request.headers().contains(HttpHeaders.CONTENT_TYPE.toString(), HttpMediaType.APPLICATION_OCTET_STREAM.getType(), true) && !forceBase64RequestBody) {
            request.sendBuffer(bufBody, handler);
        } else {
            request.sendBuffer(Buffer.buffer(Utils.toBase64String(bufBody.getBytes()).getBytes(StandardCharsets.UTF_8)), handler);
        }
    }

    private void checkEncryptionKeysResponse(JsonObject response, KeysetKey... expectedKeys) {
        assertEquals("success", response.getString("status"));

        final JsonArray expected = new JsonArray();
        for (KeysetKey key : expectedKeys) {
            final JsonObject expectedKey = new JsonObject();
            expectedKey.put("id", key.getId());
            expectedKey.put("secret", Base64.getEncoder().encodeToString(key.getKeyBytes()));
            expectedKey.put("created", key.getCreated().getEpochSecond());
            expectedKey.put("activates", key.getActivates().getEpochSecond());
            expectedKey.put("expires", key.getExpires().getEpochSecond());
            expectedKey.put("site_id", keysetProvider.getSnapshot().getKeyset(key.getKeysetId()).getSiteId());
            expected.add(expectedKey);
        }

        assertEquals(expected, response.getJsonArray("body"));
    }

    private void checkEncryptionKeys(JsonObject response, KeyDownloadEndpoint endpoint, int callersSiteId, KeysetKey... expectedKeys) {
        assertEquals("success", response.getString("status"));

        final JsonArray expected = new JsonArray();
        for (KeysetKey key : expectedKeys) {
            final Keyset expectedKeyset = this.keysetProvider.getSnapshot().getKeyset(key.getKeysetId());
            assertNotNull(expectedKeyset);
            assertTrue(expectedKeyset.isEnabled());

            final JsonObject expectedKey = new JsonObject();
            expectedKey.put("id", key.getId());
            expectedKey.put("secret", Base64.getEncoder().encodeToString(key.getKeyBytes()));
            expectedKey.put("created", key.getCreated().getEpochSecond());
            expectedKey.put("activates", key.getActivates().getEpochSecond());
            expectedKey.put("expires", key.getExpires().getEpochSecond());

            if (endpoint == KeyDownloadEndpoint.SHARING) {
                // We only send keyset ids if the caller is allowed to encrypt using that keyset (so only the caller's keysets and the master keyset)
                if (expectedKeyset.getSiteId() == callersSiteId) {
                    // SDKs currently have an assumption that keyset ids are positive; that will be fixed.
                    assertTrue(key.getKeysetId() > 0);
                    expectedKey.put("keyset_id", key.getKeysetId());
                } else if (expectedKeyset.getSiteId() == MasterKeySiteId) {
                    expectedKey.put("keyset_id", UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS);
                }
            }

            expected.add(expectedKey);
        }

        assertEquals(expected, response.getJsonObject("body").getJsonArray("keys"));
    }

    private enum KeyDownloadEndpoint {
        SHARING("/key/sharing"),
        BIDSTREAM("/key/bidstream");

        private final String path;

        KeyDownloadEndpoint(String path) {
            this.path = path;
        }

        public String getPath() {
            return this.path;
        }
    }

    private void checkIdentityMapResponse(JsonObject response, SaltEntry salt, boolean useV4Uid, IdentityType identityType, boolean useHash, String... expectedIdentifiers) {
        assertEquals("success", response.getString("status"));

        JsonObject body = response.getJsonObject("body");
        JsonArray mapped = body.getJsonArray("mapped");
        assertNotNull(mapped);
        assertEquals(expectedIdentifiers.length, mapped.size());

        for (int i = 0; i < expectedIdentifiers.length; ++i) {
            String expectedIdentifier = expectedIdentifiers[i];
            JsonObject actualMap = mapped.getJsonObject(i);
            assertEquals(expectedIdentifier, actualMap.getString("identifier"));
            try {
                if (useHash) {
                    assertEquals(EncodingUtils.toBase64String(getAdvertisingIdFromIdentityHash(identityType, expectedIdentifier, firstLevelSalt, salt, useV4Uid, false)), actualMap.getString("advertising_id"));
                } else {
                    assertEquals(EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(identityType, expectedIdentifier, firstLevelSalt, salt, useV4Uid, false)), actualMap.getString("advertising_id"));
                }
            } catch (Exception e) {
                org.junit.jupiter.api.Assertions.fail(e.getMessage());
            }
            assertFalse(actualMap.getString("bucket_id").isEmpty());
        }
    }

    private void checkIdentityMapResponse(JsonObject response) {
        checkIdentityMapResponse(response, null, false, null, false);
    }

    protected SaltEntry setupSalts(boolean useV4Uid, Boolean useV4PrevUid) {
        return useV4Uid ? setupSaltsForV4Uid(useV4PrevUid) : setupSaltsForV2V3Uid(useV4PrevUid);
    }

    protected SaltEntry setupSalts(boolean useV4Uid) {
        return setupSalts(useV4Uid, null);
    }

    protected SaltEntry setupSalts() {
        return setupSalts(false, null);
    }

    protected SaltEntry setupSaltsForV2V3Uid(Boolean useV4PrevUid) {
        when(saltProviderSnapshot.getFirstLevelSalt()).thenReturn(firstLevelSalt);

        var lastUpdated = Instant.now().minus(1, DAYS);
        var refreshFrom = lastUpdated.plus(30, DAYS);
        SaltEntry salt = new SaltEntry(
                rotatingSalt123.id(),
                rotatingSalt123.hashedId(),
                lastUpdated.toEpochMilli(),
                rotatingSalt123.currentSalt(),
                refreshFrom.toEpochMilli(),
                useV4PrevUid == null || useV4PrevUid ? null : rotatingSalt123.previousSalt(),
                null,
                useV4PrevUid == null || !useV4PrevUid ? null : new SaltEntry.KeyMaterial(1000001, "key12345key12345key12345key12346", "salt1234salt1234salt1234salt1235")
        );
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);
        return salt;
    }

    protected SaltEntry setupSaltsForV4Uid(Boolean useV4PrevUid) {
        when(saltProviderSnapshot.getFirstLevelSalt()).thenReturn(firstLevelSalt);

        var lastUpdated = Instant.now().minus(1, DAYS);
        var refreshFrom = lastUpdated.plus(30, DAYS);
        SaltEntry salt = new SaltEntry(
                1,
                "1",
                lastUpdated.toEpochMilli(),
                null,
                refreshFrom.toEpochMilli(),
                useV4PrevUid == null || useV4PrevUid ? null : "salt123",
                new SaltEntry.KeyMaterial(1000000, "key12345key12345key12345key12345", "salt1234salt1234salt1234salt1234"),
                useV4PrevUid == null || !useV4PrevUid ? null : new SaltEntry.KeyMaterial(1000001, "key12345key12345key12345key12346", "salt1234salt1234salt1234salt1235"));
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);
        return salt;
    }

    private HashMap<Integer, Keyset> keysetsToMap(Keyset... keysets) {
        return new HashMap<>(Arrays.stream(keysets).collect(Collectors.toMap(Keyset::getKeysetId, s -> s)));
    }

    private void setupKeysetsMock(Keyset... keysets) {
        setupKeysetsMock(keysetsToMap(keysets));
    }

    private void setupKeysetsMock(Map<Integer, Keyset> keysets) {
        KeysetSnapshot keysetSnapshot = new KeysetSnapshot(keysets);
        when(keysetProvider.getSnapshot()).thenReturn(keysetSnapshot);
    }

    private HashMap<Integer, List<KeysetKey>> keysetKeysToMap(KeysetKey... keys) {
        HashMap<Integer, List<KeysetKey>> resultMap = new HashMap<>();

        for (KeysetKey key : keys) {
            resultMap.computeIfAbsent(key.getKeysetId(), k -> new ArrayList<>()).add(key);
        }
        return resultMap;
    }

    private void setupKeysetsKeysMock(KeysetKey... keys) {
        setupKeysetsKeysMock(keysetKeysToMap(keys));
    }

    private HashMap<Integer, KeysetKey> keysetMapToKeyMap(HashMap<Integer, List<KeysetKey>> resultMap) {
        HashMap<Integer, KeysetKey> keyMap = new HashMap<>();
        for (List<KeysetKey> keyList : resultMap.values()) {
            for (KeysetKey key : keyList) {
                keyMap.put(key.getId(), key);
            }
        }
        return keyMap;
    }

    private void setupKeysetsKeysMock(HashMap<Integer, List<KeysetKey>> keysetIdToKeyList) {
        KeysetKeyStoreSnapshot keysetKeyStoreSnapshot = new KeysetKeyStoreSnapshot(keysetMapToKeyMap(keysetIdToKeyList), keysetIdToKeyList);

        when(keysetKeyStore.getSnapshot(any())).thenReturn(keysetKeyStoreSnapshot); //note that this getSnapshot() overload should be removed; it ignores the argument passed in
        when(keysetKeyStore.getSnapshot()).thenReturn(keysetKeyStoreSnapshot);
    }

    protected void setupKeys() {
        setupKeys(false);
    }

    protected void setupKeys(boolean expired) {
        Instant expiryTime = now.plus(25, ChronoUnit.HOURS); //Some tests move the clock forward to test token expiry, so ensure these keys expire after that time.
        if (expired) {
            expiryTime = now.minus(25, ChronoUnit.HOURS); //Some tests move the clock forward to test token expiry, so ensure these keys expire after that time.
        }
        KeysetKey masterKey = new KeysetKey(101, makeAesKey("masterKey"), now.minusSeconds(7), now, expiryTime, MasterKeysetId);
        KeysetKey refreshKey = new KeysetKey(102, makeAesKey("refreshKey"), now.minusSeconds(7), now, expiryTime, RefreshKeysetId);
        KeysetKey publisherKey = new KeysetKey(103, makeAesKey("publisherKey"), now.minusSeconds(7), now, expiryTime, FallbackPublisherKeysetId);
        KeysetKey siteKey = new KeysetKey(104, makeAesKey("siteKey"), now.minusSeconds(7), now, expiryTime, 4);

        Keyset masterKeyset = new Keyset(MasterKeysetId, MasterKeySiteId, "test", Set.of(-1, -2, 2, 201), now.getEpochSecond(), true, true);
        Keyset refreshKeyset = new Keyset(RefreshKeysetId, RefreshKeySiteId, "test", Set.of(-1, -2, 2, 201), now.getEpochSecond(), true, true);
        Keyset fallbackPublisherKeyset = new Keyset(FallbackPublisherKeysetId, AdvertisingTokenSiteId, "test", Set.of(-1, -2, 2, 201), now.getEpochSecond(), true, true);
        Keyset keyset4 = new Keyset(4, 201, "test", Set.of(-1, -2, 2, 201), now.getEpochSecond(), true, true);

        setupKeysetsMock(masterKeyset, refreshKeyset, fallbackPublisherKeyset, keyset4);
        setupKeysetsKeysMock(masterKey, refreshKey, publisherKey, siteKey);
    }

    protected void setupSiteKey(int siteId, int keyId, int keysetId) {
        Keyset keyset = new Keyset(keysetId, siteId, "test", Set.of(1, 2, 3), now.getEpochSecond(), true, true);
        Map<Integer, Keyset> keysetMap = keysetProvider.getSnapshot().getAllKeysets();
        keysetMap.put(keyset.getKeysetId(), keyset);
        setupKeysetsMock(keysetMap);

        final Instant expiryTime = now.plus(25, ChronoUnit.HOURS); //Some tests move the clock forward to test token expiry, so ensure these keys expire after that time.
        KeysetKey masterKey = new KeysetKey(101, makeAesKey("masterKey"), now.minusSeconds(7), now, expiryTime, MasterKeysetId);
        KeysetKey refreshKey = new KeysetKey(102, makeAesKey("refreshKey"), now.minusSeconds(7), now, expiryTime, RefreshKeysetId);
        KeysetKey siteKey = new KeysetKey(keyId, makeAesKey("siteKey" + siteId), now.minusSeconds(7), now, now.plusSeconds(10), keysetId);

        setupKeysetsKeysMock(masterKey, refreshKey, siteKey);
    }

    private void generateTokens(Vertx vertx, String inputType, String input, Handler<JsonObject> handler) {
        generateTokens(vertx, inputType, input, handler, Collections.emptyMap());
    }

    private void generateTokens(Vertx vertx, String inputType, String input, Handler<JsonObject> handler, Map<String, String> additionalHeaders) {
        JsonObject v2Payload = new JsonObject();
        v2Payload.put(inputType, input);
        sendTokenGenerate(vertx, v2Payload, 200, null, handler, true, additionalHeaders);
    }

    private static void assertEqualsClose(Instant expected, Instant actual, int withinSeconds) {
        assertTrue(expected.minusSeconds(withinSeconds).isBefore(actual));
        assertTrue(expected.plusSeconds(withinSeconds).isAfter(actual));
    }

    private void assertTokenStatusMetrics(Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, TokenResponseStatsCollector.PlatformType platformType) {
        final double actual = Metrics.globalRegistry
                .get("uid2_token_response_status_count")
                .tag("site_id", String.valueOf(siteId))
                .tag("token_endpoint", String.valueOf(endpoint))
                .tag("token_response_status", String.valueOf(responseStatus))
                .tag("advertising_token_version", responseStatus == TokenResponseStatsCollector.ResponseStatus.Success ? String.valueOf(getTokenVersion()) : "null")
                .tag("platform_type", String.valueOf(platformType))
                .counter().count();
        assertEquals(1, actual);
    }

    private byte[] getAdvertisingIdFromIdentity(IdentityType identityType, String identityString, String firstLevelSalt, SaltEntry salt, boolean getV4Uid, boolean getPrevUid) throws Exception {
        if (getV4Uid) {
            return getAdvertisingIdFromIdentity(identityType, identityString, firstLevelSalt, getPrevUid ? salt.previousKeySalt() : salt.currentKeySalt());
        } else {
            return getAdvertisingIdFromIdentity(identityType, identityString, firstLevelSalt, getPrevUid ? salt.previousSalt() : salt.currentSalt());
        }
    }

    private byte[] getAdvertisingIdFromIdentity(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUid(getIdentityScope(), identityType, identityString, firstLevelSalt, rotatingSalt, useRawUidV3());
    }

    private byte[] getAdvertisingIdFromIdentity(IdentityType identityType, String identityString, String firstLevelSalt, SaltEntry.KeyMaterial rotatingKey) throws Exception {
        return getRawUidV4(getIdentityScope(), identityType, IdentityEnvironment.TEST, identityString, firstLevelSalt, rotatingKey);
    }

    public static byte[] getRawUid(IdentityScope identityScope, IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt, boolean useRawUidV3) {
        return !useRawUidV3
                ? TokenUtils.getAdvertisingIdV2FromIdentity(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getAdvertisingIdV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt);
    }

    public static byte[] getRawUid(IdentityScope identityScope, IdentityType identityType, String identityString, boolean useRawUidV3) {
        return !useRawUidV3
                ? TokenUtils.getAdvertisingIdV2FromIdentity(identityString, firstLevelSalt, rotatingSalt123.currentSalt())
                : TokenUtils.getAdvertisingIdV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt123.currentSalt());
    }

    public static byte[] getRawUidV4(IdentityScope identityScope, IdentityType identityType, IdentityEnvironment identityEnvironment, String identityString, String firstLevelSalt, SaltEntry.KeyMaterial rotatingKey) throws Exception {
        return TokenUtils.getAdvertisingIdV4FromIdentity(identityScope, identityType, identityEnvironment, identityString, firstLevelSalt, rotatingKey);
    }

    private byte[] getAdvertisingIdFromIdentityHash(IdentityType identityType, String identityString, String firstLevelSalt, SaltEntry salt, boolean useV4Uid, boolean usePrevUid) throws Exception {
        if (useV4Uid) {
            return getAdvertisingIdFromIdentityHash(identityType, identityString, firstLevelSalt, usePrevUid ? salt.previousKeySalt() : salt.currentKeySalt());
        } else {
            return getAdvertisingIdFromIdentityHash(identityType, identityString, firstLevelSalt, usePrevUid ? salt.previousSalt() : salt.currentSalt());
        }
    }

    private byte[] getAdvertisingIdFromIdentityHash(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return !useRawUidV3()
                ? TokenUtils.getAdvertisingIdV2FromIdentityHash(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getAdvertisingIdV3FromIdentityHash(getIdentityScope(), identityType, identityString, firstLevelSalt, rotatingSalt);
    }

    private byte[] getAdvertisingIdFromIdentityHash(IdentityType identityType, String identityString, String firstLevelSalt, SaltEntry.KeyMaterial rotatingKey) throws Exception {
        return TokenUtils.getAdvertisingIdV4FromIdentityHash(getIdentityScope(), identityType, IdentityEnvironment.TEST, identityString, firstLevelSalt, rotatingKey);
    }

    private JsonObject createBatchEmailsRequestPayload() {
        JsonArray emails = new JsonArray();
        emails.add("test1@uid2.com");
        emails.add("test2@uid2.com");
        JsonObject req = new JsonObject();
        req.put("email", emails);
        return req;
    }

    private JsonObject setupIdentityMapServiceLinkTest() {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = createBatchEmailsRequestPayload();
        req.put("optout_check", 1);
        return req;
    }

    protected TokenVersion getTokenVersion() {
        return TokenVersion.V4;
    }

    protected boolean useRawUidV3() {
        return false;
    }

    protected IdentityScope getIdentityScope() {
        return IdentityScope.UID2;
    }

    protected void addAdditionalTokenGenerateParams(JsonObject payload) {
    }

    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
        testContext.completeNow();
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void keyLatestNoAcl(String contentType, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(5, Role.ID_READER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "masterKeyset", null, now.getEpochSecond(), true, true),
                new Keyset(11, 5, "test", null, now.getEpochSecond(), true, true),
                new Keyset(12, 6, "test", null, now.getEpochSecond(), true, true)
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(100, "masterKey".getBytes(), now, now.minusSeconds(15), now.plusSeconds(20), MasterKeysetId),
                new KeysetKey(101, "key101".getBytes(), now, now, now.plusSeconds(10), 11),
                new KeysetKey(102, "key102".getBytes(), now, now, now.plusSeconds(10), 12),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        Arrays.sort(encryptionKeys, Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2/key/latest", null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson, encryptionKeys);
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void keyLatestWithAcl(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(5, Role.ID_READER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "masterKeyset", null, now.getEpochSecond(), true, true),
                new Keyset(11, 5, "test", Set.of(6), now.getEpochSecond(), true, true),
                new Keyset(12, 6, "test", Set.of(), now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(100, "masterKey".getBytes(), now, now.minusSeconds(15), now.plusSeconds(20), MasterKeysetId),
                new KeysetKey(101, "key101".getBytes(), now, now.minusSeconds(15), now.plusSeconds(20), 11),
                new KeysetKey(102, "key102".getBytes(), now, now.plusSeconds(10), now.plusSeconds(20), 12),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));

        KeysetKey[] expectedKeys = new KeysetKey[]{encryptionKeys[0], encryptionKeys[1]}; // encryptionKeys[1] is shared but not activated. should not return encryptionKeys[1].
        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2/key/latest", null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson, expectedKeys);
            testContext.completeNow();
        });
    }

    @Test
    void keyLatestClientBelongsToReservedSiteId(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(AdvertisingTokenSiteId, Role.ID_READER);
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "key101".getBytes(), now, now, now.plusSeconds(10), 201),
                new KeysetKey(102, "key102".getBytes(), now, now, now.plusSeconds(10), 202),
        };
        setupKeysetsKeysMock(encryptionKeys);
        send(vertx, "v2/key/latest", null, 401, respJson -> testContext.completeNow());
    }

    @Test
    void keyLatestHideRefreshKey(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(5, Role.ID_READER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(RefreshKeysetId, RefreshKeySiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(FallbackPublisherKeysetId, AdvertisingTokenSiteId, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(10, 5, "test", Set.of(-1, -2, 2), now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "key101".getBytes(), now, now, now.plusSeconds(10), MasterKeysetId),
                new KeysetKey(102, "key102".getBytes(), now, now, now.plusSeconds(10), RefreshKeysetId),
                new KeysetKey(103, "key103".getBytes(), now, now, now.plusSeconds(10), 10),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        Arrays.sort(encryptionKeys, Comparator.comparing(KeysetKey::getId));

        send(vertx, "v2/key/latest", null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson,
                    Arrays.stream(encryptionKeys).filter(k -> k.getKeysetId() != RefreshKeysetId).toArray(KeysetKey[]::new));
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

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        v2Payload.put("email_hash", emailHash);

        sendTokenGenerate(vertx, v2Payload, 400,
                json -> {
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

        sendTokenGenerate(vertx, null, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            testContext.completeNow();
        });
    }

    private void assertStatsCollector(String path, String referer, String apiContact, Integer siteId) {
        final ArgumentCaptor<StatsCollectorMessageItem> messageCaptor = ArgumentCaptor.forClass(StatsCollectorMessageItem.class);
        verify(statsCollectorQueue).enqueue(any(), messageCaptor.capture());

        final StatsCollectorMessageItem messageItem = messageCaptor.getValue();
        assertEquals(path, messageItem.getPath());
        assertEquals(apiContact, messageItem.getApiContact());
        assertEquals(referer, messageItem.getReferer());
        assertEquals(siteId, messageItem.getSiteId());
    }

    private AdvertisingToken validateAndGetToken(EncryptedTokenEncoder encoder, JsonObject body, IdentityType identityType) { //See UID2-79+Token+and+ID+format+v3
        final String advertisingTokenString = body.getString("advertising_token");
        validateAdvertisingToken(advertisingTokenString, getTokenVersion(), getIdentityScope(), identityType);
        AdvertisingToken advertisingToken = encoder.decodeAdvertisingToken(advertisingTokenString);

        // without useIdentityV3() the assert will be trigger as there's no IdentityType in v4 token generated with
        // a raw UID v2 as old raw UID format doesn't store the identity type (and scope)
        if (useRawUidV3() && getTokenVersion() == TokenVersion.V4) {
            assertEquals(identityType, advertisingToken.userIdentity.identityType);
        }
        return advertisingToken;
    }

    public static void validateAdvertisingToken(String advertisingTokenString, TokenVersion tokenVersion, IdentityScope identityScope, IdentityType identityType) {
        if (tokenVersion == TokenVersion.V2) {
            assertEquals("Ag", advertisingTokenString.substring(0, 2));
        } else {
            String firstChar = advertisingTokenString.substring(0, 1);
            if (identityScope == IdentityScope.UID2) {
                assertEquals(identityType == IdentityType.Email ? "A" : "B", firstChar);
            } else {
                assertEquals(identityType == IdentityType.Email ? "E" : "F", firstChar);
            }

            String secondChar = advertisingTokenString.substring(1, 2);
            if (tokenVersion == TokenVersion.V3) {
                assertEquals("3", secondChar);
            } else {
                assertEquals("4", secondChar);

                //No URL-unfriendly characters allowed:
                assertEquals(-1, advertisingTokenString.indexOf('='));
                assertEquals(-1, advertisingTokenString.indexOf('+'));
                assertEquals(-1, advertisingTokenString.indexOf('/'));
            }
        }
    }

    RefreshToken decodeRefreshToken(EncryptedTokenEncoder encoder, String refreshTokenString, IdentityType identityType) {
        RefreshToken refreshToken = encoder.decodeRefreshToken(refreshTokenString);
        assertEquals(getIdentityScope(), refreshToken.userIdentity.identityScope);
        assertEquals(identityType, refreshToken.userIdentity.identityType);
        return refreshToken;
    }

    RefreshToken decodeRefreshToken(EncryptedTokenEncoder encoder, String refreshTokenString) {
        return decodeRefreshToken(encoder, refreshTokenString, IdentityType.Email);
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void identityMapNewClientNoPolicySpecified(String contentType, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);

        send(vertx, "v2/identity/map", req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertFalse(respJson.containsKey("client_error"));
            JsonArray unmappedArr = respJson.getJsonObject("body").getJsonArray("unmapped");
            Assertions.assertEquals(1, unmappedArr.size());
            Assertions.assertEquals(emails.getString(0), unmappedArr.getJsonObject(0).getString("identifier"));
            Assertions.assertEquals("optout", unmappedArr.getJsonObject(0).getString("reason"));
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void fallbackToBase64DecodingIfBinaryEnvelopeDecodeFails(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();
        ClientKey ck = (ClientKey) clientKeyProvider.get("");
        long nonce = new BigInteger(Random.getBytes(8)).longValue();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);
        emails.add("test1@uid2.com");

        postV2(ck, vertx, "v2/identity/map", req, nonce, null, ar -> {
            assertTrue(ar.succeeded());
            assertEquals(200, ar.result().statusCode());

            byte[] byteResp = Utils.decodeBase64String(ar.result().bodyAsString());
            byte[] decrypted = AesGcm.decrypt(byteResp, 0, ck.getSecretBytes());

            JsonObject respJson = new JsonObject(new String(decrypted, 16, decrypted.length - 16, StandardCharsets.UTF_8));
            assertEquals("success", respJson.getString("status"));

            // Check that response content type is text/plain
            assertEquals(HttpMediaType.TEXT_PLAIN.getType(), ar.result().getHeader(HttpHeaders.CONTENT_TYPE.toString()));

            testContext.completeNow();

            // Set request content type header to application/octet-stream, but force a base64 encoded request envelope
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), "application/octet-stream"), true);
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy", "optout_check"})
    void identityMapNewClientWrongPolicySpecified(String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();
        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));
        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);
        req.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        send(vertx, "v2/identity/map", req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertFalse(respJson.containsKey("client_error"));
            JsonArray unmappedArr = respJson.getJsonObject("body").getJsonArray("unmapped");
            Assertions.assertEquals(1, unmappedArr.size());
            Assertions.assertEquals(emails.getString(0), unmappedArr.getJsonObject(0).getString("identifier"));
            Assertions.assertEquals("optout", unmappedArr.getJsonObject(0).getString("reason"));
            testContext.completeNow();
        });
    }

    @Deprecated // We don't need a test for different behavior of new vs legacy participants
    @Test
    void identityMapNewClientNoPolicySpecifiedOlderKeySuccessful(Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime,
                Set.of(Role.MAPPER),
                201,
                null
        );
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.MAPPER),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);
        emails.add("test1@uid2.com");
        // policy parameter not passed but will still succeed as old participant

        send(vertx, "v2/identity/map", req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertEquals("success", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @Deprecated // We don't need a test for different behavior of new vs legacy participants
    @ParameterizedTest
    @ValueSource(strings = {"policy", "optout_check"})
    void identityMapNewClientWrongPolicySpecifiedOlderKeySuccessful(String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime,
                Set.of(Role.MAPPER),
                201,
                null
        );
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.MAPPER),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);
        req.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        emails.add("test1@uid2.com");

        send(vertx, "v2/identity/map", req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertEquals("success", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @CsvSource({
            // After - V4 UID, V4 previous UID
            "true,true,text/plain",
            "true,true,application/octet-stream",

            // Migration - V4 UID, V3 previous UID
            "true,false,text/plain",
            "true,false,application/octet-stream",

            // V4 UID, no previous UID
            "true,,text/plain",
            "true,,application/octet-stream",

            // Rollback - V3 UID, V4 previous UID
            "false,true,text/plain",
            "false,true,application/octet-stream",

            // Before - V3 UID, V3 previous UID
            "false,false,text/plain",
            "false,false,application/octet-stream",

            // V3 UID, no previous UID
            "false,,text/plain",
            "false,,application/octet-stream"
    })
    void v3IdentityMapMixedInputSuccess(
            boolean useV4Uid, Boolean useV4PrevUid, String contentType,
            Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);

        SaltEntry salt = setupSalts(useV4Uid, useV4PrevUid);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var phoneHash = TokenUtils.getIdentityHashString("+15555555555");
        JsonObject request = new JsonObject(String.format("""
                {
                    "email": ["test1@uid2.com", "test2@uid2.com"],
                    "phone": [],
                    "phone_hash": ["%s"]
                }
                """, phoneHash)
        );

        send(vertx, "v3/identity/map", request, 200, respJson -> {
            JsonObject body = respJson.getJsonObject("body");
            assertEquals(Set.of("email", "email_hash", "phone", "phone_hash"), body.fieldNames());

            var mappedEmails = body.getJsonArray("email");
            assertEquals(2, mappedEmails.size());
            JsonObject mappedEmailExpected1;
            JsonObject mappedEmailExpected2;

            var mappedPhoneHash = body.getJsonArray("phone_hash");
            assertEquals(1, mappedPhoneHash.size());
            JsonObject mappedPhoneHashExpected;

            try {
                mappedEmailExpected1 = JsonObject.of(
                        "u", EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test1@uid2.com", firstLevelSalt, salt, useV4Uid, false)),
                        "p", useV4PrevUid == null ? null : EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test1@uid2.com", firstLevelSalt, salt, useV4PrevUid, true)),
                        "r", Instant.ofEpochMilli(salt.refreshFrom()).getEpochSecond()
                );

                mappedEmailExpected2 = JsonObject.of(
                        "u", EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test2@uid2.com", firstLevelSalt, salt, useV4Uid, false)),
                        "p", useV4PrevUid == null ? null : EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test2@uid2.com", firstLevelSalt, salt, useV4PrevUid, true)),
                        "r", Instant.ofEpochMilli(salt.refreshFrom()).getEpochSecond()
                );

                mappedPhoneHashExpected = JsonObject.of(
                        "u", EncodingUtils.toBase64String(getAdvertisingIdFromIdentityHash(IdentityType.Phone, phoneHash, firstLevelSalt, salt, useV4Uid, false)),
                        "p", useV4PrevUid == null ? null : EncodingUtils.toBase64String(getAdvertisingIdFromIdentityHash(IdentityType.Phone, phoneHash, firstLevelSalt, salt, useV4PrevUid, true)),
                        "r", Instant.ofEpochMilli(salt.refreshFrom()).getEpochSecond()
                );
            } catch (Exception e) {
                org.junit.jupiter.api.Assertions.fail(e.getMessage());
                testContext.failNow(e);
                return;
            }
            assertEquals(mappedEmailExpected1, mappedEmails.getJsonObject(0));
            assertEquals(mappedEmailExpected2, mappedEmails.getJsonObject(1));
            assertEquals(mappedPhoneHashExpected, mappedPhoneHash.getJsonObject(0));

            assertEquals(0, body.getJsonArray("email_hash").size());
            assertEquals(0, body.getJsonArray("phone").size());

            assertEquals("success", respJson.getString("status"));
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void v3IdentityMapUnmappedIdentitiesOptoutAndInvalid(boolean useV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts(useV4Uid);

        // optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        JsonObject request = new JsonObject("""
                { "email": ["test1@uid2.com", "invalid_email"] }
                """
        );

        send(vertx, "v3/identity/map", request, 200, respJson -> {
            JsonObject body = respJson.getJsonObject("body");

            JsonObject expected = new JsonObject("""
                            {
                                "email": [{"e": "optout"}, {"e": "invalid identifier"}],
                                "email_hash": [],
                                "phone": [],
                                "phone_hash": []
                            }
                    """);

            assertEquals(expected, body);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"email\": []}", "{\"email_hash\": null}"})
    void v3IdentityMapEmptyInputFormats(String inputPayload, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();

        Instant lastUpdated = Instant.now().minus(1, DAYS);
        Instant refreshFrom = lastUpdated.plus(30, DAYS);

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated.toEpochMilli(), "salt", refreshFrom.toEpochMilli(), "previousSalt", null, null);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);

        JsonObject request = inputPayload == null ? null : new JsonObject(inputPayload);

        send(vertx, "v3/identity/map", request, 200, respJson -> {
            JsonObject body = respJson.getJsonObject("body");
            JsonObject expected = new JsonObject("""
                        {
                             "email": [],
                             "email_hash": [],
                             "phone": [],
                             "phone_hash": []
                        }
                    """);
            assertEquals(expected, body);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"{}"})
    void v3IdentityMapMissingValidInputKeys(String inputPayload, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);

        JsonObject request = inputPayload == null ? null : new JsonObject(inputPayload);

        send(vertx, "v3/identity/map", request, 400, respJson -> {
            assertEquals("Required Parameter Missing: one or more of [email, email_hash, phone, phone_hash] must be specified", respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"invalid_key\": []}",
            "{\"email\": [ null ]}",
            "{\"email\": [ \"some_email\", null ]}"
    })
    void v3IdentityMapIncorrectInputFormats(String inputPayload, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);

        JsonObject request = new JsonObject(inputPayload);

        send(vertx, "v3/identity/map", request, 400, respJson -> {
            assertEquals("Incorrect request format", respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"previousSalt"})
    void v3IdentityMapNoPreviousAdvertisingId(String previousSalt, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();

        var lastUpdatedOver90Days = Instant.now().minus(120, DAYS).toEpochMilli();
        var refreshFrom = Instant.now().plus(30, DAYS);

        SaltEntry salt = new SaltEntry(1, "1", lastUpdatedOver90Days, "salt", refreshFrom.toEpochMilli(), previousSalt, null, null);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);

        JsonObject request = new JsonObject("""
                        { "email": ["test1@uid2.com"] }
                """);

        send(vertx, "v3/identity/map", request, 200, respJson -> {
            JsonObject body = respJson.getJsonObject("body");
            var mappedEmails = body.getJsonArray("email");

            var expectedMappedEmails = JsonObject.of(
                    "u", EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test1@uid2.com", firstLevelSalt, salt.currentSalt())),
                    "p", null,
                    "r", refreshFrom.getEpochSecond()
            );
            assertEquals(expectedMappedEmails, mappedEmails.getJsonObject(0));

            testContext.completeNow();
        });
    }

    @Test
    void v3IdentityMapOutdatedRefreshFrom(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();

        Instant asOf = Instant.now();
        var lastUpdated = asOf.minus(120, DAYS).toEpochMilli();
        var outdatedRefreshFrom = asOf.minus(30, DAYS).toEpochMilli();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", outdatedRefreshFrom, null, null, null);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(salt);

        JsonObject request = new JsonObject("""
                        { "email": ["test1@uid2.com"] }
                """);

        send(vertx, "v3/identity/map", request, 200, respJson -> {
            JsonObject body = respJson.getJsonObject("body");
            var mappedEmails = body.getJsonArray("email");

            var expectedMappedEmails = JsonObject.of(
                    "u", EncodingUtils.toBase64String(getAdvertisingIdFromIdentity(IdentityType.Email, "test1@uid2.com", firstLevelSalt, salt.currentSalt())),
                    "p", null,
                    "r", asOf.truncatedTo(DAYS).plus(1, DAYS).getEpochSecond()
            );
            assertEquals(expectedMappedEmails, mappedEmails.getJsonObject(0));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateNewClientNoPolicySpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");

        sendTokenGenerate(vertx, v2Payload, 400,
                json -> {
                    assertFalse(json.containsKey("body"));
                    assertEquals("client_error", json.getString("status"));
                    assertEquals("Required opt-out policy argument for token/generate is missing or not set to 1", json.getString("message"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy", "optout_check"})
    void tokenGenerateNewClientWrongPolicySpecified(String policyParamterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put(policyParamterKey, OptoutCheckPolicy.DoNotRespect.policy);

        sendTokenGenerate(vertx,
                v2Payload, 400,
                json -> {
                    assertFalse(json.containsKey("body"));
                    assertEquals("client_error", json.getString("status"));
                    assertEquals("Required opt-out policy argument for token/generate is missing or not set to 1", json.getString("message"));
                    testContext.completeNow();
                });
    }

    @Test
    void tokenGenerateNewClientNoPolicySpecifiedOlderKeySuccessful(Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime,
                Set.of(Role.GENERATOR),
                201,
                null
        );
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.GENERATOR),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");

        sendTokenGenerate(vertx,
                v2Payload, 200,
                json -> {
                    assertTrue(json.containsKey("body"));
                    assertEquals("success", json.getString("status"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"policy", "optout_check"})
    void tokenGenerateNewClientWrongPolicySpecifiedOlderKeySuccessful(String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime,
                Set.of(Role.GENERATOR),
                201,
                null
        );
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.GENERATOR),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        sendTokenGenerate(vertx,
                v2Payload, 200,
                json -> {
                    assertTrue(json.containsKey("body"));
                    assertEquals("success", json.getString("status"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest // TODO: remove test after optout check phase 3
    @CsvSource({
            "policy,someoptout@example.com,Email",
            "policy,+01234567890,Phone",
            "optout_check,someoptout@example.com,Email",
            "optout_check,+01234567890,Phone"
    })
    void tokenGenerateOptOutToken(String policyParameterKey, String identity, IdentityType identityType,
                                  Vertx vertx, VertxTestContext testContext) {
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.GENERATOR),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(oldClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(oldClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put(identityType.name().toLowerCase(), identity);
        v2Payload.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        sendTokenGenerate(vertx,
                v2Payload, 200,
                json -> {
                    InputUtil.InputVal optOutTokenInput = identityType == IdentityType.Email ?
                            InputUtil.InputVal.validEmail(OptOutTokenIdentityForEmail, OptOutTokenIdentityForEmail) :
                            InputUtil.InputVal.validPhone(OptOutIdentityForPhone, OptOutTokenIdentityForPhone);

                    assertEquals("success", json.getString("status"));

                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    decodeV2RefreshToken(json);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, identityType);
                    RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("decrypted_refresh_token"));
                    final byte[] advertisingId = getAdvertisingIdFromIdentity(identityType,
                            optOutTokenInput.getNormalized(),
                            firstLevelSalt,
                            rotatingSalt123.currentSalt());
                    final byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity(optOutTokenInput.getNormalized(), firstLevelSalt);
                    assertArrayEquals(advertisingId, advertisingToken.userIdentity.id);
                    assertArrayEquals(firstLevelHash, refreshToken.userIdentity.id);

                    String advertisingTokenString = body.getString("advertising_token");
                    final Instant now = Instant.now();
                    final String token = advertisingTokenString;
                    final boolean matchedOptedOutIdentity = this.uidOperatorVerticle.getIdService().advertisingTokenMatches(token, optOutTokenInput.toUserIdentity(getIdentityScope(), 0, now), now, IdentityEnvironment.TEST);
                    assertTrue(matchedOptedOutIdentity);
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertTrue(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());

                    assertTokenStatusMetrics(
                            201,
                            TokenResponseStatsCollector.Endpoint.GenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success,
                            TokenResponseStatsCollector.PlatformType.Other);

                    sendTokenRefresh(vertx, testContext, body.getString("refresh_token"), body.getString("refresh_response_key"), 200, refreshRespJson -> {
                        assertEquals("optout", refreshRespJson.getString("status"));
                        JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                        assertNull(refreshBody);
                        assertTokenStatusMetrics(
                                201,
                                TokenResponseStatsCollector.Endpoint.RefreshV2,
                                TokenResponseStatsCollector.ResponseStatus.OptOut,
                                TokenResponseStatsCollector.PlatformType.InApp);
                        testContext.completeNow();
                    }, Map.of(ClientVersionHeader, tvosClientVersionHeaderValue));
                });
    }

    @ParameterizedTest // TODO: remove test after optout check phase 3
    @CsvSource({
            "policy,someoptout@example.com,Email",
            "policy,+01234567890,Phone",
            "optout_check,someoptout@example.com,Email",
            "optout_check,+01234567890,Phone"
    })
    void tokenGenerateOptOutTokenWithDisableOptoutTokenFF(String policyParameterKey, String identity, IdentityType identityType,
                                                          Vertx vertx, VertxTestContext testContext) {
        ClientKey oldClientKey = new ClientKey(
                null,
                null,
                Utils.toBase64String(clientSecret),
                "test-contact",
                newClientCreationDateTime.minusSeconds(5),
                Set.of(Role.GENERATOR),
                201,
                null
        );
        when(clientKeyProvider.get(any())).thenReturn(oldClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(oldClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put(identityType.name().toLowerCase(), identity);
        v2Payload.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        sendTokenGenerate(vertx,
                v2Payload, 200,
                json -> {
                    assertEquals("optout", json.getString("status"));

                    decodeV2RefreshToken(json);

                    assertTokenStatusMetrics(
                            201,
                            TokenResponseStatsCollector.Endpoint.GenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.OptOut,
                            TokenResponseStatsCollector.PlatformType.Other);

                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "true,text/plain",
            "true,application/octet-stream",

            "false,text/plain",
            "false,application/octet-stream"
    })
    void tokenGenerateForEmail(boolean useV4Uid, String contentType, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupKeys();

        SaltEntry salt = setupSalts(useV4Uid);

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(vertx, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    try {
                        assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, salt, useV4Uid, false), advertisingToken.userIdentity.id);
                    } catch (Exception e) {
                        org.junit.jupiter.api.Assertions.fail(e.getMessage());
                        testContext.failNow(e);
                        return;
                    }

                    RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"));
                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    assertStatsCollector("/v2/token/generate", null, "test-contact", clientSiteId);

                    testContext.completeNow();
                },
                Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void tokenGenerateForEmailHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email_hash", emailHash);

        sendTokenGenerate(vertx, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Email, emailHash, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

                    RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"));
                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(emailHash, firstLevelSalt), refreshToken.userIdentity.id);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            // Before - v4 UID, v4 refreshed UID
            "true,true,text/plain",
            "true,true,application/octet-stream",

            // Rollback - v4 UID, v3 refreshed UID
            "true,false,text/plain",
            "true,false,application/octet-stream",

            // Migration - v3 UID, v4 refreshed UID
            "false,true,text/plain",
            "false,true,application/octet-stream",

            // After - v3 UID, v3 refreshed UID
            "false,false,text/plain",
            "false,false,application/octet-stream"
    })
    void tokenGenerateThenRefresh(
            boolean useV4Uid, boolean useRefreshedV4Uid, String contentType,
            Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupKeys();

        SaltEntry salt = setupSalts(useV4Uid);

        Map<String, String> additionalHeaders = Map.of(ClientVersionHeader, iosClientVersionHeaderValue,
                HttpHeaders.CONTENT_TYPE.toString(), contentType);

        generateTokens(vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, bodyJson, IdentityType.Email);
            try {
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, salt, useV4Uid, false), advertisingToken.userIdentity.id);
            } catch (Exception e) {
                org.junit.jupiter.api.Assertions.fail(e.getMessage());
                testContext.failNow(e);
                return;
            }

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            SaltEntry refreshSalt = setupSalts(useRefreshedV4Uid);
            sendTokenRefresh(vertx, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);

                AdvertisingToken adTokenFromRefresh = validateAndGetToken(encoder, refreshBody, IdentityType.Email);

                assertFalse(PrivacyBits.fromInt(adTokenFromRefresh.userIdentity.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(adTokenFromRefresh.userIdentity.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, adTokenFromRefresh.publisherIdentity.siteId);
                try {
                    assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, refreshSalt, useRefreshedV4Uid, false), adTokenFromRefresh.userIdentity.id);
                } catch (Exception e) {
                    org.junit.jupiter.api.Assertions.fail(e.getMessage());
                    testContext.failNow(e);
                    return;
                }

                String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshToken refreshToken = decodeRefreshToken(encoder, refreshTokenStringNew);
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                assertTokenStatusMetrics(
                        clientSiteId,
                        TokenResponseStatsCollector.Endpoint.GenerateV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);
                assertTokenStatusMetrics(
                        clientSiteId,
                        TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);

                testContext.completeNow();
            }, additionalHeaders);
        }, additionalHeaders);
    }

    @Test
    void tokenGenerateThenRefreshSaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        Map<String, String> additionalHeaders = Map.of(ClientVersionHeader, androidClientVersionHeaderValue);

        generateTokens(vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            sendTokenRefresh(vertx, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);

                AdvertisingToken advertisingToken = validateAndGetToken(encoder, refreshBody, IdentityType.Email);

                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

                String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshToken refreshToken = decodeRefreshToken(encoder, refreshTokenStringNew);
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                assertTokenStatusMetrics(
                        clientSiteId,
                        TokenResponseStatsCollector.Endpoint.GenerateV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);
                assertTokenStatusMetrics(
                        clientSiteId,
                        TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);

                verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                testContext.completeNow();
            }, additionalHeaders);
        }, additionalHeaders);
    }

    @Test
    void tokenGenerateThenRefreshNoActiveKey(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put("optout_check", 1);

        sendTokenGenerate(vertx,
                v2Payload, 200,
                genRespJson -> {
                    assertEquals("success", genRespJson.getString("status"));
                    JsonObject bodyJson = genRespJson.getJsonObject("body");
                    assertNotNull(bodyJson);

                    String genRefreshToken = bodyJson.getString("refresh_token");

                    setupKeys(true);
                    sendTokenRefresh(vertx, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 500, refreshRespJson -> {
                        assertFalse(refreshRespJson.containsKey("body"));
                        assertEquals("No active encryption key available", refreshRespJson.getString("message"));
                        testContext.completeNow();
                    }, Map.of(ClientVersionHeader, androidClientVersionHeaderValue));
                });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void tokenGenerateThenValidateWithEmail_Match(boolean useV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupKeys();

        SaltEntry salt = setupSalts(useV4Uid);

        generateTokens(vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");
            AdvertisingToken advertisingToken = validateAndGetToken(encoder, genBody, IdentityType.Email);
            try {
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, salt, useV4Uid, false), advertisingToken.userIdentity.id);
            } catch (Exception e) {
                org.junit.jupiter.api.Assertions.fail(e.getMessage());
                testContext.failNow(e);
                return;
            }

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email", emailAddress);

            send(vertx, "v2/token/validate", v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithEmailHash_Match(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "email", ValidateIdentityForEmail, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email_hash", EncodingUtils.toBase64String(ValidateIdentityForEmailHash));

            send(vertx, "v2/token/validate", v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithBothEmailAndEmailHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email", emailAddress);
            v2Payload.put("email_hash", emailAddress);

            send(vertx, "v2/token/validate", v2Payload, 400, json -> {
                assertFalse(json.containsKey("body"));
                assertEquals("client_error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateUsingCustomSiteKey(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 4;
        final int clientKeysetId = 201;
        final int siteKeyId = 1201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        setupSiteKey(clientSiteId, siteKeyId, clientKeysetId);

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(vertx, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateSaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(vertx, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

                    RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"));
                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    assertStatsCollector("/v2/token/generate", null, "test-contact", clientSiteId);

                    verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                    testContext.completeNow();
                });
    }

    @Test
    void tokenGenerateNoActiveKey(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.GENERATOR);
        setupSalts();
        setupKeys(true);

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put("optout_check", 1);

        sendTokenGenerate(vertx,
                v2Payload, 500,
                json -> {
                    assertFalse(json.containsKey("body"));
                    assertEquals("No active encryption key available", json.getString("message"));
                    testContext.completeNow();
                });
    }

    @Test
    void tokenRefreshNoToken(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        sendTokenRefresh(vertx, testContext, "", "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken,
                    TokenResponseStatsCollector.PlatformType.Other);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"asdf", "invalidBase64%%%%"})
    void tokenRefreshInvalidTokenAuthenticated(String token, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);

        sendTokenRefresh(vertx, testContext, token, "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken,
                    TokenResponseStatsCollector.PlatformType.HasOriginHeader);
            testContext.completeNow();
        }, Map.of(ORIGIN_HEADER, "https://example.com"));
    }

    @Test
    void tokenRefreshInvalidTokenUnauthenticated(Vertx vertx, VertxTestContext testContext) {
        sendTokenRefresh(vertx, testContext, "abcd", "", 400, json -> {
            assertEquals("error", json.getString("status"));
            testContext.completeNow();
        });
    }

    private void generateRefreshToken(Vertx vertx, String identityType, String identity, int siteId, boolean useV4Uid, Handler<JsonObject> handler) {
        fakeAuth(siteId, Role.GENERATOR);
        setupKeys();
        setupSalts(useV4Uid);

        generateTokens(vertx, identityType, identity, handler);
    }

    private void generateRefreshToken(Vertx vertx, String identityType, String identity, int siteId, Handler<JsonObject> handler) {
        generateRefreshToken(vertx, identityType, identity, siteId, false, handler);
    }

    @Test
    void captureDurationsBetweenRefresh(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusSeconds(300));

            sendTokenRefresh(vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                assertEquals(300, Metrics.globalRegistry
                        .get("uid2_token_refresh_duration_seconds")
                        .tag("api_contact", "test-contact")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .summary().mean());

                assertEquals(1, Metrics.globalRegistry
                        .get("uid2_advertising_token_expired_on_refresh_total")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .tag("is_expired", "false")
                        .counter().count());

                testContext.completeNow();
            });
        });
    }

    @Test
    void captureExpiredAdvertisingTokenStatus(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusSeconds(identityExpiresAfter.toSeconds() + 1));

            sendTokenRefresh(vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));

                assertEquals(1, Metrics.globalRegistry
                        .get("uid2_advertising_token_expired_on_refresh_total")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .tag("is_expired", "true")
                        .counter().count());

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenRefreshExpiredTokenAuthenticated(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));

            sendTokenRefresh(vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 400, refreshRespJson -> {
                assertEquals("expired_token", refreshRespJson.getString("status"));
                assertNotNull(Metrics.globalRegistry
                        .get("uid2_refresh_token_received_count_total").counter());
                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenRefreshExpiredTokenUnauthenticated(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";

        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            String refreshToken = genRespJson.getJsonObject("body").getString("refresh_token");
            clearAuth();
            when(clock.instant()).thenAnswer(i -> now.plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));

            sendTokenRefresh(vertx, testContext, refreshToken, "", 400, refreshRespJson -> {
                assertEquals("error", refreshRespJson.getString("status"));
                assertNotNull(Metrics.globalRegistry
                        .get("uid2_refresh_token_received_count_total").counter());
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void tokenRefreshOptOut(boolean useV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        setupSalts(useV4Uid);

        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

            sendTokenRefresh(vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("optout", refreshRespJson.getString("status"));
                assertTokenStatusMetrics(
                        clientSiteId,
                        TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.OptOut,
                        TokenResponseStatsCollector.PlatformType.Other);
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @CsvSource({
            "true,true",
            "true,false",
            "false,true",
            "false,false"
    })
    void tokenRefreshOptOutBeforeLogin(boolean useV4Uid, boolean useRefreshedV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(vertx, "email", emailAddress, clientSiteId, useV4Uid, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            String refreshTokenDecryptSecret = bodyJson.getString("refresh_response_key");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(now.minusSeconds(10));

            setupSalts(useRefreshedV4Uid);

            sendTokenRefresh(vertx, testContext, refreshToken, refreshTokenDecryptSecret, 200, refreshRespJson -> {
                assertEquals("optout", refreshRespJson.getString("status"));
                assertNull(refreshRespJson.getJsonObject("body"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void tokenValidateWithEmail_Mismatch(String contentType, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send(vertx, "v2/token/validate", new JsonObject().put("token", "abcdef").put("email", emailAddress),
                200,
                respJson -> {
                    assertFalse(respJson.getBoolean("body"));
                    assertEquals("success", respJson.getString("status"));

                    testContext.completeNow();
                },
                Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void tokenValidateWithEmailHash_Mismatch(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send(vertx, "v2/token/validate",
                new JsonObject().put("token", "abcdef").put("email_hash", EncodingUtils.toBase64String(ValidateIdentityForEmailHash)),
                200,
                respJson -> {
                    assertFalse(respJson.getBoolean("body"));
                    assertEquals("success", respJson.getString("status"));

                    testContext.completeNow();
                });
    }

    @Test
    void identityMapBatchBothEmailAndHashEmpty(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        JsonArray emailHashes = new JsonArray();
        req.put("email", emails);
        req.put("email_hash", emailHashes);

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchBothEmailAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
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

        send(vertx, "v2/identity/map", req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchNoEmailOrHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();

        send(vertx, "v2/identity/map", req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapSingleEmailProvided(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("email", "test@example.com");

        send(vertx, "v2/identity/map", req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("email must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapSingleEmailHashProvided(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("email_hash", "test@example.com");

        send(vertx, "v2/identity/map", req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("email_hash must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapSinglePhoneProvided(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("phone", "555-555-5555");

        send(vertx, "v2/identity/map", req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("phone must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapSinglePhoneHashProvided(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("phone_hash", "555-555-5555");

        send(vertx, "v2/identity/map", req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("phone_hash must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void identityMapBatchEmails(boolean useV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts(useV4Uid);

        JsonObject req = createBatchEmailsRequestPayload();

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, useV4Uid, IdentityType.Email, false, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchEmailHashes(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts();

        JsonObject req = new JsonObject();
        JsonArray hashes = new JsonArray();
        req.put("email_hash", hashes);
        final String[] emailHashes = {
                TokenUtils.getIdentityHashString("test1@uid2.com"),
                TokenUtils.getIdentityHashString("test2@uid2.com"),
        };

        for (String emailHash : emailHashes) {
            hashes.add(emailHash);
        }

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Email, true, emailHashes);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchEmailsOneEmailInvalid(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        emails.add("test1@uid2.com");
        emails.add("bogus");
        emails.add("test2@uid2.com");

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Email, false, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchEmailsNoEmails(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchRequestTooLarge(Vertx vertx, VertxTestContext testContext) {
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

        send(vertx, "v2/identity/map", req, 413, json -> testContext.completeNow());
    }

    private static Stream<Arguments> optOutStatusRequestData() {
        List<String> rawUIDS = Arrays.asList("RUQbFozFwnmPVjDx8VMkk9vJoNXUJImKnz2h9RfzzM24",
                "qAmIGxqLk_RhOtm4f1nLlqYewqSma8fgvjEXYnQ3Jr0K",
                "r3wW2uvJkwmeFcbUwSeM6BIpGF8tX38wtPfVc4wYyo71",
                "e6SA-JVAXnvk8F1MUtzsMOyWuy5Xqe15rLAgqzSGiAbz");
        Map<String, Long> optedOutIdsCase1 = new HashMap<>();

        optedOutIdsCase1.put(rawUIDS.get(0), Instant.now().minus(1, DAYS).getEpochSecond());
        optedOutIdsCase1.put(rawUIDS.get(1), Instant.now().minus(2, DAYS).getEpochSecond());
        optedOutIdsCase1.put(rawUIDS.get(2), -1L);
        optedOutIdsCase1.put(rawUIDS.get(3), -1L);

        Map<String, Long> optedOutIdsCase2 = new HashMap<>();
        optedOutIdsCase2.put(rawUIDS.get(2), -1L);
        optedOutIdsCase2.put(rawUIDS.get(3), -1L);
        return Stream.of(
                Arguments.arguments(true, optedOutIdsCase1, 2, Role.MAPPER),
                Arguments.arguments(true, optedOutIdsCase1, 2, Role.ID_READER),
                Arguments.arguments(true, optedOutIdsCase1, 2, Role.SHARER),
                Arguments.arguments(true, optedOutIdsCase2, 0, Role.MAPPER),

                Arguments.arguments(false, optedOutIdsCase1, 2, Role.MAPPER),
                Arguments.arguments(false, optedOutIdsCase1, 2, Role.ID_READER),
                Arguments.arguments(false, optedOutIdsCase1, 2, Role.SHARER),
                Arguments.arguments(false, optedOutIdsCase2, 0, Role.MAPPER)
        );
    }

    @ParameterizedTest
    @MethodSource("optOutStatusRequestData")
    void optOutStatusRequest(boolean useV4Uid, Map<String, Long> optedOutIds, int optedOutCount, Role role, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(126, role);
        setupKeys();
        setupSalts(useV4Uid);

        JsonArray rawUIDs = new JsonArray();
        for (String rawUID2 : optedOutIds.keySet()) {
            when(this.optOutStore.getOptOutTimestampByAdId(rawUID2)).thenReturn(optedOutIds.get(rawUID2));
            rawUIDs.add(rawUID2);
        }
        JsonObject requestJson = new JsonObject();
        requestJson.put("advertising_ids", rawUIDs);

        send(vertx, "v2/optout/status", requestJson, 200, respJson -> {
            assertEquals("success", respJson.getString("status"));
            JsonArray optOutJsonArray = respJson.getJsonObject("body").getJsonArray("opted_out");
            assertEquals(optedOutCount, optOutJsonArray.size());
            for (int i = 0; i < optOutJsonArray.size(); ++i) {
                JsonObject optOutObject = optOutJsonArray.getJsonObject(i);
                String advertisingId = optOutObject.getString("advertising_id");
                assertTrue(optedOutIds.containsKey(advertisingId));
                long expectedTimestamp = Instant.ofEpochSecond(optedOutIds.get(advertisingId)).toEpochMilli();
                assertEquals(expectedTimestamp, optOutObject.getLong("opted_out_since"));
            }
            testContext.completeNow();
        });
    }

    private static Stream<Arguments> optOutStatusValidationErrorData() {
        // Test case 1
        JsonArray rawUIDs = new JsonArray();

        for (int i = 0; i <= optOutStatusMaxRequestSize; ++i) {
            byte[] rawUid2Bytes = Random.getBytes(32);
            rawUIDs.add(Utils.toBase64String(rawUid2Bytes));
        }

        JsonObject requestJson1 = new JsonObject();
        requestJson1.put("advertising_ids", rawUIDs);
        // Test case 2
        JsonObject requestJson2 = new JsonObject();
        requestJson2.put("advertising", rawUIDs);
        return Stream.of(
                Arguments.arguments(requestJson1, "Request payload is too large"),
                Arguments.arguments(requestJson2, "Required Parameter Missing: advertising_ids")
        );
    }

    @ParameterizedTest
    @MethodSource("optOutStatusValidationErrorData")
    void optOutStatusValidationError(JsonObject requestJson, String errorMsg, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(126, Role.MAPPER);
        setupSalts();
        setupKeys();

        send(vertx, "v2/optout/status", requestJson, 400, respJson -> {
            assertEquals(com.uid2.shared.Const.ResponseStatus.ClientError, respJson.getString("status"));
            assertEquals(errorMsg, respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void optOutStatusUnauthorized(String contentType, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(126, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send(vertx, "v2/optout/status", new JsonObject(), 401, respJson -> {
            assertEquals(com.uid2.shared.Const.ResponseStatus.Unauthorized, respJson.getString("status"));
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @ParameterizedTest
    @CsvSource({
            "true,text/plain",
            "true,application/octet-stream",

            "false,text/plain",
            "false,application/octet-stream"
    })
    void logoutV2(boolean useV4Uid, String contentType, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.OPTOUT);
        setupKeys();
        setupSalts(useV4Uid);

        JsonObject req = new JsonObject();
        req.put("email", "test@uid2.com");

        doAnswer(invocation -> {
            Handler<AsyncResult<Instant>> handler = invocation.getArgument(4);
            handler.handle(Future.succeededFuture(Instant.now()));
            return null;
        }).when(this.optOutStore).addEntry(any(), any(), eq("uid-trace-id"), eq("test-instance-id"), any());

        send(vertx, "v2/token/logout", req, 200, respJson -> {
            assertEquals("success", respJson.getString("status"));
            assertEquals("OK", respJson.getJsonObject("body").getString("optout"));
            testContext.completeNow();
        }, Map.of(Audit.UID_TRACE_ID_HEADER, "uid-trace-id",
                HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void logoutV2SaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.OPTOUT);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        req.put("email", "test@uid2.com");

        doAnswer(invocation -> {
            Handler<AsyncResult<Instant>> handler = invocation.getArgument(4);
            handler.handle(Future.succeededFuture(Instant.now()));
            return null;
        }).when(this.optOutStore).addEntry(any(), any(), any(), any(), any());

        send(vertx, "v2/token/logout", req, 200, respJson -> {
            assertEquals("success", respJson.getString("status"));
            assertEquals("OK", respJson.getJsonObject("body").getString("optout"));

            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateBothPhoneAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);
        v2Payload.put("phone_hash", phoneHash);

        send(vertx, "v2/token/generate", v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateBothPhoneAndEmailSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);
        v2Payload.put("email", emailAddress);

        send(vertx, "v2/token/generate", v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateBothPhoneHashAndEmailHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        final String emailAddress = "test@uid2.com";
        final String emailHash = TokenUtils.getIdentityHashString(emailAddress);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone_hash", phoneHash);
        v2Payload.put("email_hash", emailHash);

        send(vertx, "v2/token/generate", v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateForPhone(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);

        sendTokenGenerate(vertx, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"), IdentityType.Phone);
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

            assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateForPhoneHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone_hash", phoneHash);

        sendTokenGenerate(vertx, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = decodeRefreshToken(encoder, body.getString("decrypted_refresh_token"), IdentityType.Phone);
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

            assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateThenRefreshForPhone(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            sendTokenRefresh(vertx, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);

                AdvertisingToken advertisingToken = validateAndGetToken(encoder, refreshBody, IdentityType.Phone);

                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.currentSalt()), advertisingToken.userIdentity.id);

                String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshToken refreshToken = decodeRefreshToken(encoder, refreshTokenStringNew, IdentityType.Phone);
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithPhone_Match(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);

            send(vertx, "v2/token/validate", v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateSaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);

            send(vertx, "v2/token/validate", v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithPhoneHash_Match(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phoneHash = EncodingUtils.toBase64String(ValidateIdentityForPhoneHash);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "phone", ValidateIdentityForPhone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone_hash", phoneHash);

            send(vertx, "v2/token/validate", v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void tokenGenerateThenValidateWithBothPhoneAndPhoneHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        final String phoneHash = EncodingUtils.toBase64String(ValidateIdentityForEmailHash);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);
            v2Payload.put("phone_hash", phoneHash);

            send(vertx, "v2/token/validate", v2Payload, 400, json -> {
                assertFalse(json.containsKey("body"));
                assertEquals("client_error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void identityMapBatchBothPhoneAndHashEmpty(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        JsonArray phoneHashes = new JsonArray();
        req.put("phone", phones);
        req.put("phone_hash", phoneHashes);

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchBothPhoneAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        JsonArray phoneHashes = new JsonArray();
        req.put("phone", phones);
        req.put("phone_hash", phoneHashes);

        phones.add("+15555555555");
        phoneHashes.add(TokenUtils.getIdentityHashString("+15555555555"));

        send(vertx, "v2/identity/map", req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchPhones(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        phones.add("+15555555555");
        phones.add("+15555555556");

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Phone, false, "+15555555555", "+15555555556");
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchPhoneHashes(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts();

        JsonObject req = new JsonObject();
        JsonArray hashes = new JsonArray();
        req.put("phone_hash", hashes);
        final String[] phoneHashes = {
                TokenUtils.getIdentityHashString("+15555555555"),
                TokenUtils.getIdentityHashString("+15555555556"),
        };

        for (String phoneHash : phoneHashes) {
            hashes.add(phoneHash);
        }

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Phone, true, phoneHashes);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchPhonesOnePhoneInvalid(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();

        SaltEntry salt = setupSalts();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        phones.add("+15555555555");
        phones.add("bogus");
        phones.add("+15555555556");

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Phone, false, "+15555555555", "+15555555556");
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchPhonesNoPhones(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @Test
    void identityMapBatchRequestTooLargeForPhone(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        final String phone = "+15555555555";
        for (long requestSize = 0; requestSize < UIDOperatorVerticle.MAX_REQUEST_BODY_SIZE; requestSize += phone.length()) {
            phones.add(phone);
        }

        send(vertx, "v2/identity/map", req, 413, json -> testContext.completeNow());
    }

    @ParameterizedTest
    @CsvSource({
            "true,policy",
            "true,optout_check",

            "false,policy",
            "false,optout_check"
    })
    void tokenGenerateRespectOptOutOption(boolean useV4Uid, String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupKeys();
        setupSalts(useV4Uid);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        req.put("email", "random-optout-user@email.io");
        req.put(policyParameterKey, 1);

        // for EUID
        addAdditionalTokenGenerateParams(req);

        send(vertx, "v2/token/generate", req, 200, json -> {
            try {
                Assertions.assertEquals(ResponseUtil.ResponseStatus.OptOut, json.getString("status"));
                Assertions.assertNull(json.getJsonObject("body"));
                assertTokenStatusMetrics(clientSiteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.OptOut, TokenResponseStatsCollector.PlatformType.Other);
                testContext.completeNow();
            } catch (Exception e) {
                testContext.failNow(e);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void identityMapOptoutDefaultOption(boolean useV4Uid, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();
        setupSalts(useV4Uid);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);

        send(vertx, "v2/identity/map", req, 200, json -> {
            try {
                Assertions.assertTrue(json.getJsonObject("body").getJsonArray("mapped") == null ||
                        json.getJsonObject("body").getJsonArray("mapped").isEmpty());
                JsonArray unmappedArr = json.getJsonObject("body").getJsonArray("unmapped");
                Assertions.assertEquals(1, unmappedArr.size());
                Assertions.assertEquals("random-optout-user@email.io", unmappedArr.getJsonObject(0).getString("identifier"));
                Assertions.assertEquals("optout", unmappedArr.getJsonObject(0).getString("reason"));
                testContext.completeNow();
            } catch (Exception e) {
                testContext.failNow(e);
            }
        });
    }

    @ParameterizedTest
    @CsvSource({
            "true,policy",
            "true,optout_check",

            "false,policy",
            "false,optout_check"
    })
    void identityMapRespectOptOutOption(boolean useV4Uid, String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupKeys();
        setupSalts(useV4Uid);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);
        req.put(policyParameterKey, 1);

        send(vertx, "v2/identity/map", req, 200, json -> {
            try {
                Assertions.assertTrue(json.getJsonObject("body").getJsonArray("mapped").isEmpty());
                Assertions.assertEquals(1, json.getJsonObject("body").getJsonArray("unmapped").size());
                Assertions.assertEquals("random-optout-user@email.io", json.getJsonObject("body").getJsonArray("unmapped").getJsonObject(0).getString("identifier"));
                Assertions.assertEquals("optout", json.getJsonObject("body").getJsonArray("unmapped").getJsonObject(0).getString("reason"));
                testContext.completeNow();
            } catch (Exception e) {
                testContext.failNow(e);
            }
        });
    }

    @Test
    void requestWithoutClientKeyOrReferer(Vertx vertx, VertxTestContext testContext) {
        final String emailAddress = "test@uid2.com";
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(vertx, v2Payload, 401,
                json -> {
                    assertEquals("unauthorized", json.getString("status"));

                    assertStatsCollector("/v2/token/generate", null, null, null);

                    testContext.completeNow();
                });
    }

    @Test
    void requestWithReferer(Vertx vertx, VertxTestContext testContext) {
        final String emailAddress = "test@uid2.com";
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(vertx, v2Payload, 401, "test-referer",
                json -> {
                    assertEquals("unauthorized", json.getString("status"));

                    assertStatsCollector("/v2/token/generate", "test-referer", null, null);

                    testContext.completeNow();
                }, true);
    }

    private void postCstg(Vertx vertx, String endpoint, String httpOriginHeader, JsonObject body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        HttpRequest<Buffer> req = client.postAbs(getUrlForEndpoint(endpoint));
        if (httpOriginHeader != null) {
            req.putHeader(ORIGIN_HEADER, httpOriginHeader);
        }
        req.sendJsonObject(body, handler);
    }

    private void sendCstg(Vertx vertx, String endpoint, String httpOriginHeader, JsonObject postPayload, SecretKey secretKey, int expectedHttpCode, VertxTestContext testContext, Handler<JsonObject> handler) {
        postCstg(vertx, endpoint, httpOriginHeader, postPayload, testContext.succeeding(result -> testContext.verify(() -> {
            assertEquals(expectedHttpCode, result.statusCode());

            // successful response is encrypted
            if (result.statusCode() == 200) {
                byte[] decrypted = decrypt(Utils.decodeBase64String(result.bodyAsString()), 0, secretKey.getEncoded());
                JsonObject respJson = new JsonObject(new String(decrypted, 0, decrypted.length - 0, StandardCharsets.UTF_8));
                handler.handle(respJson);
            } else { //errors is in plain text
                handler.handle(tryParseResponse(result));
            }
        })));
    }

    private void setupCstgBackend(String... domainNames) {
        setupCstgBackend(List.of(domainNames), Collections.emptyList());
    }

    private void setupCstgBackend(List<String> domainNames, List<String> appNames) {
        setupSalts();
        setupKeys();
        ClientSideKeypair keypair = new ClientSideKeypair(clientSideTokenGenerateSubscriptionId, clientSideTokenGeneratePublicKey, clientSideTokenGeneratePrivateKey, clientSideTokenGenerateSiteId, "", Instant.now(), false, "");
        when(clientSideKeypairProvider.getSnapshot()).thenReturn(clientSideKeypairSnapshot);
        when(clientSideKeypairSnapshot.getKeypair(clientSideTokenGenerateSubscriptionId)).thenReturn(keypair);
        final Site site = new Site(clientSideTokenGenerateSiteId, "test", true, Collections.emptySet(), new HashSet<>(domainNames), new HashSet<>(appNames));
        when(siteProvider.getSite(clientSideTokenGenerateSiteId)).thenReturn(site);
    }

    //if no identity is provided will get an error
    @Test
    void cstgNoIdentityHashProvided(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequestWithNoPayload(Instant.now().toEpochMilli());
        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                400,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("please provide exactly one of: email_hash, phone_hash", respJson.getString("message"));
                    assertEquals(ResponseUtil.ResponseStatus.ClientError, respJson.getString("status"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.MissingParams,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "https://blahblah.com",
            "http://local1host:8080" //intentionally spelling localhost wrong here!
    })
    void cstgDomainNameCheckFails(String httpOrigin, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend();
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());
        sendCstg(vertx,
                "v2/token/client-generate",
                httpOrigin,
                data.getItem1(),
                data.getItem2(),
                403,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("unexpected http origin", respJson.getString("message"));
                    assertEquals("invalid_http_origin", respJson.getString("status"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "''", // An empty quoted value results in the empty string.
            "com.123",
            "com."
    })
    void cstgAppNameCheckFails(String appName, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend(Collections.emptyList(), List.of("com.123.Game.App.android"));
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli(), appName);
        sendCstg(vertx,
                "v2/token/client-generate",
                null,
                data.getItem1(),
                data.getItem2(),
                403,
                testContext,
                respJson -> {
                    final JsonObject expectedResponse = new JsonObject()
                            .put("message", "unexpected app name")
                            .put("status", "invalid_app_name");

                    assertEquals(expectedResponse, respJson);

                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.InvalidAppName,
                            TokenResponseStatsCollector.PlatformType.InApp);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "http://gototest.com"
    })
    void cstgDomainNameCheckFailsAndLogInvalidHttpOrigin(String httpOrigin, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);
        this.uidOperatorVerticle.setLastInvalidOriginProcessTime(Instant.now().minusSeconds(3600));

        setupCstgBackend();
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());
        sendCstg(vertx,
                "v2/token/client-generate",
                httpOrigin,
                data.getItem1(),
                data.getItem2(),
                403,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("unexpected http origin", respJson.getString("message"));
                    assertEquals("invalid_http_origin", respJson.getString("status"));
                    assertThat(logWatcher.list.stream().map(ILoggingEvent::getFormattedMessage).collect(Collectors.toList())).contains("InvalidHttpOriginAndAppName: site test (123): http://gototest.com");
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"badAppName"})
    void cstgLogsInvalidAppName(String appName, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);
        this.uidOperatorVerticle.setLastInvalidOriginProcessTime(Instant.now().minusSeconds(3600));

        setupCstgBackend();
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli(), appName);
        sendCstg(vertx,
                "v2/token/client-generate",
                null,
                data.getItem1(),
                data.getItem2(),
                403,
                testContext,
                respJson -> {
                    Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("InvalidHttpOriginAndAppName: site test (123): " + appName));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.InvalidAppName,
                            TokenResponseStatsCollector.PlatformType.InApp);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgDisabledAsUnauthorized(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);
        this.uidOperatorVerticle.setLastInvalidOriginProcessTime(Instant.now().minusSeconds(3600));

        setupCstgBackend();
        String subscriptionID = "PpRrE5YY84";
        ClientSideKeypair keypairDisabled = new ClientSideKeypair(subscriptionID, clientSideTokenGeneratePublicKey, clientSideTokenGeneratePrivateKey, clientSideTokenGenerateSiteId, "", Instant.now(), true, "");
        when(clientSideKeypairProvider.getSnapshot()).thenReturn(clientSideKeypairSnapshot);
        when(clientSideKeypairSnapshot.getKeypair(subscriptionID)).thenReturn(keypairDisabled);

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);
        final long timestamp = Instant.now().toEpochMilli();

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", "");
        requestJson.put("iv", "");
        requestJson.put("public_key", serverPublicKey.toString());
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", subscriptionID);

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli(), null);
        sendCstg(vertx,
                "v2/token/client-generate",
                null,
                requestJson,
                secretKey,
                401,
                testContext,
                respJson -> {
                    assertEquals("Unauthorized", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Unauthorized,
                            TokenResponseStatsCollector.PlatformType.Other);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "http://gototest.com"
    })
    void cstgDomainNameCheckFailsAndLogSeveralInvalidHttpOrigin(String httpOrigin, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);
        this.uidOperatorVerticle.setLastInvalidOriginProcessTime(Instant.now().minusSeconds(3600));

        Map<Integer, Set<String>> siteIdToInvalidOrigins = new HashMap<>();
        siteIdToInvalidOrigins.put(clientSideTokenGenerateSiteId, new HashSet<>(Arrays.asList("http://localhost1.com", "http://localhost2.com")));
        siteIdToInvalidOrigins.put(124, new HashSet<>(Arrays.asList("http://xyz1.com", "http://xyz2.com")));

        this.uidOperatorVerticle.setSiteIdToInvalidOriginsAndAppNames(siteIdToInvalidOrigins);

        setupCstgBackend();
        when(siteProvider.getSite(124)).thenReturn(new Site(124, "test2", true, new HashSet<>()));

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());
        sendCstg(vertx,
                "v2/token/client-generate",
                httpOrigin,
                data.getItem1(),
                data.getItem2(),
                403,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("unexpected http origin", respJson.getString("message"));
                    assertEquals("invalid_http_origin", respJson.getString("status"));
                    Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("InvalidHttpOriginAndAppName: site test (123): http://localhost1.com, http://gototest.com, http://localhost2.com | site test2 (124): http://xyz1.com, http://xyz2.com"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "https://cstg.co.uk",
            "https://cstg2.com",
            "http://localhost:8080"
    })
    void cstgDomainNameCheckPasses(String httpOrigin, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk", "cstg2.com", "localhost");
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());
        sendCstg(vertx,
                "v2/token/client-generate",
                httpOrigin,
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                respJson -> {
                    assertEquals("success", respJson.getString("status"));

                    JsonObject refreshBody = respJson.getJsonObject("body");
                    assertNotNull(refreshBody);
                    validateAndGetToken(encoder, refreshBody, IdentityType.Email); //to validate token version is correct
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "com.123.Game.App.android",
            "com.123.game.app.android",
            "123456789"
    })
    void cstgAppNameCheckPasses(String appName, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend(Collections.emptyList(), List.of("com.123.Game.App.android", "123456789"));
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli(), appName);
        sendCstg(vertx,
                "v2/token/client-generate",
                null,
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                respJson -> {
                    assertEquals("success", respJson.getString("status"));

                    JsonObject refreshBody = respJson.getJsonObject("body");
                    assertNotNull(refreshBody);
                    validateAndGetToken(encoder, refreshBody, IdentityType.Email); //to validate token version is correct
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success,
                            TokenResponseStatsCollector.PlatformType.InApp);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgNoBody(Vertx vertx, VertxTestContext testContext) {
        setupCstgBackend("cstg.co.uk");

        postCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                null,
                testContext.succeeding(result -> testContext.verify(() -> {
                    JsonObject response = result.bodyAsJsonObject();
                    assertEquals("client_error", response.getString("status"));
                    assertEquals("json payload expected but not found", response.getString("message"));
                    testContext.completeNow();
                })));
    }

    @Test
    void cstgForInvalidJsonPayloadReturns400(Vertx vertx, VertxTestContext testContext) {
        setupCstgBackend("cstg.co.uk");

        WebClient client = WebClient.create(vertx);
        client.postAbs(getUrlForEndpoint("v2/token/client-generate"))
                .putHeader(ORIGIN_HEADER, "https://cstg.co.uk")
                .putHeader(HttpHeaders.CONTENT_TYPE.toString(), HttpMediaType.APPLICATION_JSON.getType())
                .sendBuffer(Buffer.buffer("not a valid json payload"), result -> testContext.verify(() -> {
                    assertEquals(400, result.result().statusCode());
                    testContext.completeNow();
                }));
    }

    @ParameterizedTest
    @ValueSource(strings = {"payload", "iv", "public_key"})
    void cstgMissingRequiredField(String testField, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        requestJson.remove(testField);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("required parameters: payload, iv, public_key", respJson.getString("message"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad-key", clientKey})
    void cstgBadPublicKey(String publicKey, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);

        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", publicKey);
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    if (publicKey.equals(clientKey)) { // if client api key is passed in to cstg, we should log
                        Assertions.assertTrue(logWatcher.list.stream().anyMatch(l -> l.getFormattedMessage().contains("Client side key is an api key with api_key_id=key-id for site_id=1")));
                    }
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("bad public key", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPublicKey,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad", clientKey})
    void cstgBadSubscriptionId(String subscriptionId, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(UIDOperatorVerticle.class)).addAppender(logWatcher);

        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", subscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    if (subscriptionId.equals(clientKey)) { // if client api key is passed in to cstg, we should log
                        Assertions.assertTrue(logWatcher.list.stream().anyMatch(l -> l.getFormattedMessage().contains("Client side key is an api key with api_key_id=key-id for site_id=1")));
                    }
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("bad subscription_id", respJson.getString("message"));
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadIvNotBase64(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", "............");
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("bad iv", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadIV,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadIvIncorrectLength(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", "aa");
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("bad iv", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadIV,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadEncryptedPayload(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", "not-encrypted");
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("payload decryption failed", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPayload,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgInvalidEncryptedPayloadJson(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt("not-json".getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("encrypted payload contains invalid json", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPayload,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgPhoneAndEmailProvided(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256("random@unifiedid.com"));
        identityPayload.put("phone_hash", getSha256("+10001110000"));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("please provide exactly one of: email_hash, phone_hash", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPayload,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgNoPhoneSupport(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        String rawId = "+10001110000";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("phone_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = Instant.now().toEpochMilli();
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
                    assertEquals("client_error", respJson.getString("status"));
                    assertEquals("phone support not enabled", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPayload,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequestWithPayload(JsonObject identityPayload, long timestamp, String appName) throws NoSuchAlgorithmException, InvalidKeyException {

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final JsonArray aad = JsonArray.of(timestamp);
        if (appName != null) {
            aad.add(appName);
        }
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad.toBuffer().getBytes());
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        if (appName != null) {
            requestJson.put("app_name", appName);
        }

        return new Tuple.Tuple2<>(requestJson, secretKey);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequest(IdentityType identityType, String rawId, long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {
        return createClientSideTokenGenerateRequest(identityType, rawId, timestamp, null);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequest(IdentityType identityType, String rawId, long timestamp, String appName) throws NoSuchAlgorithmException, InvalidKeyException {
        JsonObject identity = new JsonObject();

        if (identityType == IdentityType.Email) {
            identity.put("email_hash", getSha256(rawId));
        } else if (identityType == IdentityType.Phone) {
            identity.put("phone_hash", getSha256(rawId));
        } else { // can't be other types
            org.junit.jupiter.api.Assertions.fail("Identity type is not: [email_hash,phone_hash]");
        }

        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp, appName);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequestWithNoPayload(long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {
        JsonObject identity = new JsonObject();
        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp, null);
    }

    @ParameterizedTest
    @CsvSource({
            "true,true,test@example.com,Email",
            "true,true,+61400000000,Phone",

            "true,false,test@example.com,Email",
            "true,false,+61400000000,Phone",

            "false,true,test@example.com,Email",
            "false,true,+61400000000,Phone",

            "false,false,test@example.com,Email",
            "false,false,+61400000000,Phone"
    })
    void cstgUserOptsOutAfterTokenGenerate(
            boolean useV4Uid, boolean useRefreshedV4Uid, String id, IdentityType identityType,
            Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        SaltEntry salt = setupSalts(useV4Uid);

        final Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(identityType, id, Instant.now().toEpochMilli());

        // When we generate the token the user hasn't opted out.
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(null);

        final ArgumentCaptor<UserIdentity> argumentCaptor = ArgumentCaptor.forClass(UserIdentity.class);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                response -> {
                    verify(optOutStore, times(1)).getLatestEntry(argumentCaptor.capture());
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(id, firstLevelSalt), argumentCaptor.getValue().id);

                    assertEquals("success", response.getString("status"));
                    final JsonObject genBody = response.getJsonObject("body");

                    final AdvertisingToken advertisingToken = validateAndGetToken(encoder, genBody, identityType);
                    final RefreshToken refreshToken = decodeRefreshToken(encoder, decodeV2RefreshToken(response), identityType);

                    assertAreClientSideGeneratedTokens(advertisingToken, refreshToken, clientSideTokenGenerateSiteId, identityType, id, salt, false, useV4Uid, false);

                    // When we refresh the token the user has opted out.
                    when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                            .thenReturn(advertisingToken.userIdentity.establishedAt.plusSeconds(1));

                    setupSalts(useRefreshedV4Uid);

                    sendTokenRefresh(vertx, testContext, genBody.getString("refresh_token"), genBody.getString("refresh_response_key"), 200, refreshRespJson -> {
                        assertEquals("optout", refreshRespJson.getString("status"));
                        testContext.completeNow();
                    });
                });
    }

    // tests for opted out user should lead to generating ad tokens with optout success response
    // tests for non-opted out user should generate the UID2 identity and the generated refresh token can be
    // refreshed again
    // tests for all email/phone combos
    @ParameterizedTest
    @CsvSource({
            // After - v4 UID, refreshed v4 UID
            "true,true,true,abc@abc.com,Email",
            "true,true,true,+61400000000,Phone",
            "false,true,true,abc@abc.com,Email",
            "false,true,true,+61400000000,Phone",

            // Rollback - v4 UID, refreshed v3 UID
            "true,true,false,abc@abc.com,Email",
            "true,true,false,+61400000000,Phone",
            "false,true,false,abc@abc.com,Email",
            "false,true,false,+61400000000,Phone",

            // Migration - v3 UID, refreshed v4 UID
            "true,false,true,abc@abc.com,Email",
            "true,false,true,+61400000000,Phone",
            "false,false,true,abc@abc.com,Email",
            "false,false,true,+61400000000,Phone",

            // Before - v3 UID, refreshed v3 UID
            "true,false,false,abc@abc.com,Email",
            "true,false,false,+61400000000,Phone",
            "false,false,false,abc@abc.com,Email",
            "false,false,false,+61400000000,Phone"
    })
    void cstgSuccessForBothOptedAndNonOptedOutTest(
            boolean optOutExpected, boolean useV4Uid, boolean useRefreshedV4Uid,
            String id, IdentityType identityType,
            Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        SaltEntry salt = setupSalts(useV4Uid);

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(identityType, id, Instant.now().toEpochMilli());

        if (optOutExpected) {
            when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                    .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        } else {
            when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                    .thenReturn(null);
        }

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                respJson -> {
                    if (optOutExpected) {
                        assertEquals("optout", respJson.getString("status"));
                        testContext.completeNow();
                        return;
                    }

                    JsonObject genBody = respJson.getJsonObject("body");
                    assertNotNull(genBody);

                    decodeV2RefreshToken(respJson);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, genBody, identityType);
                    try {
                        assertArrayEquals(getAdvertisingIdFromIdentity(identityType, id, firstLevelSalt, salt, useV4Uid, false), advertisingToken.userIdentity.id);
                    } catch (Exception e) {
                        org.junit.jupiter.api.Assertions.fail(e.getMessage());
                        testContext.failNow(e);
                        return;
                    }

                    RefreshToken refreshToken = decodeRefreshToken(encoder, genBody.getString("decrypted_refresh_token"), identityType);

                    assertAreClientSideGeneratedTokens(advertisingToken, refreshToken, clientSideTokenGenerateSiteId, identityType, id, salt, false, useV4Uid, false);
                    assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("identity_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_from")), 10);

                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);

                    SaltEntry refreshSalt = setupSalts(useRefreshedV4Uid);
                    String genRefreshToken = genBody.getString("refresh_token");
                    //test a subsequent refresh from this cstg call and see if it still works
                    sendTokenRefresh(vertx, testContext, genRefreshToken, genBody.getString("refresh_response_key"), 200, refreshRespJson -> {
                        assertEquals("success", refreshRespJson.getString("status"));
                        JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                        assertNotNull(refreshBody);

                        //make sure the new advertising token from refresh looks right
                        AdvertisingToken adTokenFromRefresh = validateAndGetToken(encoder, refreshBody, identityType);
                        try {
                            assertArrayEquals(getAdvertisingIdFromIdentity(identityType, id, firstLevelSalt, refreshSalt, useRefreshedV4Uid, false), adTokenFromRefresh.userIdentity.id);
                        } catch (Exception e) {
                            org.junit.jupiter.api.Assertions.fail(e.getMessage());
                            testContext.failNow(e);
                            return;
                        }

                        String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                        assertNotEquals(genRefreshToken, refreshTokenStringNew);
                        RefreshToken refreshTokenAfterRefresh = decodeRefreshToken(encoder, refreshTokenStringNew, identityType);

                        assertAreClientSideGeneratedTokens(adTokenFromRefresh, refreshTokenAfterRefresh, clientSideTokenGenerateSiteId, identityType, id, refreshSalt, false, useRefreshedV4Uid, false);
                        assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                        assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                        assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                        assertTokenStatusMetrics(
                                clientSideTokenGenerateSiteId,
                                TokenResponseStatsCollector.Endpoint.RefreshV2,
                                TokenResponseStatsCollector.ResponseStatus.Success,
                                TokenResponseStatsCollector.PlatformType.Other);

                        testContext.completeNow();
                    });
                });
    }

    @ParameterizedTest
    @CsvSource({
            "https://cstg.co.uk",
            "https://cstg2.com",
            "http://localhost:8080"
    })
    void cstgSaltsExpired(String httpOrigin, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        setupCstgBackend("cstg.co.uk", "cstg2.com", "localhost");

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());

        sendCstg(vertx,
                "v2/token/client-generate",
                httpOrigin,
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                respJson -> {
                    assertEquals("success", respJson.getString("status"));

                    JsonObject refreshBody = respJson.getJsonObject("body");
                    assertNotNull(refreshBody);
                    validateAndGetToken(encoder, refreshBody, IdentityType.Email); //to validate token version is correct

                    verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                    testContext.completeNow();
                });
    }

    @Test
    void cstgNoActiveKey(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");
        setupKeys(true);

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(IdentityType.Email, "random@unifiedid.com", Instant.now().toEpochMilli());

        sendCstg(vertx,
                "v2/token/client-generate",
                "http://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                500,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("No active encryption key available", respJson.getString("message"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "email_hash,random@unifiedid.com",
            "phone_hash,1234567890"
    })
    void cstgInvalidInput(String identityType, String rawUID, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");
        setupKeys(true);

        JsonObject identity = new JsonObject();
        identity.put(identityType, getSha256(rawUID) + getSha256(rawUID));
        identity.put("optout_check", 1);
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequestWithPayload(identity, Instant.now().toEpochMilli(), null);

        sendCstg(vertx,
                "v2/token/client-generate",
                "http://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                400,
                testContext,
                respJson -> {
                    assertFalse(respJson.containsKey("body"));
                    assertEquals("Invalid Identifier", respJson.getString("message"));
                    testContext.completeNow();
                });
    }

    private void assertAreClientSideGeneratedTokens(AdvertisingToken advertisingToken, RefreshToken refreshToken, int siteId, IdentityType identityType, String identityString, SaltEntry salt, boolean expectedOptOut, boolean useV4Uid, boolean usePrevUid) {
        if (useV4Uid) {
            assertAreClientSideGeneratedTokens(advertisingToken, refreshToken, siteId, identityType, identityString, usePrevUid ? salt.previousKeySalt() : salt.currentKeySalt(), expectedOptOut);
        } else {
            assertAreClientSideGeneratedTokens(advertisingToken, refreshToken, siteId, identityType, identityString);
        }
    }

    private void assertAreClientSideGeneratedTokens(AdvertisingToken advertisingToken, RefreshToken refreshToken, int siteId, IdentityType identityType, String identityString, SaltEntry.KeyMaterial key, boolean expectedOptOut) {
        final PrivacyBits advertisingTokenPrivacyBits = PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits);
        final PrivacyBits refreshTokenPrivacyBits = PrivacyBits.fromInt(refreshToken.userIdentity.privacyBits);

        final byte[] advertisingId;
        if (key == null) {
            advertisingId = getAdvertisingIdFromIdentity(identityType,
                    identityString,
                    firstLevelSalt,
                    rotatingSalt123.currentSalt());
        } else {
            try {
                advertisingId = getAdvertisingIdFromIdentity(identityType,
                        identityString,
                        firstLevelSalt,
                        key);
            } catch (Exception e) {
                org.junit.jupiter.api.Assertions.fail(e.getMessage());
                return;
            }
        }

        final byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity(identityString, firstLevelSalt);

        assertAll(
                () -> assertTrue(advertisingTokenPrivacyBits.isClientSideTokenGenerated(), "Advertising token privacy bits CSTG flag is incorrect"),
                () -> assertEquals(expectedOptOut, advertisingTokenPrivacyBits.isClientSideTokenOptedOut(), "Advertising token privacy bits CSTG optout flag is incorrect"),

                () -> assertTrue(refreshTokenPrivacyBits.isClientSideTokenGenerated(), "Refresh token privacy bits CSTG flag is incorrect"),
                () -> assertEquals(expectedOptOut, refreshTokenPrivacyBits.isClientSideTokenOptedOut(), "Refresh token privacy bits CSTG optout flag is incorrect"),

                () -> assertEquals(siteId, advertisingToken.publisherIdentity.siteId, "Advertising token site ID is incorrect"),
                () -> assertEquals(siteId, refreshToken.publisherIdentity.siteId, "Refresh token site ID is incorrect"),

                () -> assertArrayEquals(advertisingId, advertisingToken.userIdentity.id, "Advertising token ID is incorrect"),
                () -> assertArrayEquals(firstLevelHash, refreshToken.userIdentity.id, "Refresh token ID is incorrect")
        );
    }

    private void assertAreClientSideGeneratedTokens(AdvertisingToken advertisingToken, RefreshToken refreshToken, int siteId, IdentityType identityType, String identityString) {
        assertAreClientSideGeneratedTokens(advertisingToken,
                refreshToken,
                siteId,
                identityType,
                identityString,
                null,
                false);
    }

    /********************************************************
     * MULTIPLE-KEYSETS TESTS: KEY SHARING & TOKEN GENERATE *
     ********************************************************/
    public class MultipleKeysetsTests {
        private final HashMap<Integer, Keyset> keysetIdToKeyset;
        private final HashMap<Integer, List<KeysetKey>> keysetIdToKeysetKeyList;
        public static final int FALLBACK_PUBLISHER_KEY_ID = 1002;

        public MultipleKeysetsTests(List<Keyset> keysets, List<KeysetKey> keys) {
            this.keysetIdToKeyset = new HashMap<>(keysets.stream().collect(Collectors.toMap(Keyset::getKeysetId, s -> s)));
            this.keysetIdToKeysetKeyList = keysetKeysToMap(keys.toArray(new KeysetKey[0]));
            setupMockitoApiInterception();
        }

        public MultipleKeysetsTests() {
            long nowL = now.toEpochMilli() / 1000;

            this.keysetIdToKeyset = keysetsToMap(
                    new Keyset(MasterKeysetId, MasterKeySiteId, "masterkeyKeyset", null, nowL, true, true),
                    new Keyset(RefreshKeysetId, RefreshKeySiteId, "refreshkeyKeyset", null, nowL, true, true),
                    new Keyset(FallbackPublisherKeysetId, AdvertisingTokenSiteId, "sitekeyKeyset", null, nowL, true, true),

                    new Keyset(4, 101, "keyset4", null, nowL, true, true),
                    new Keyset(5, 101, "keyset5", Set.of(), nowL, true, false), // non-default
                    new Keyset(6, 101, "keyset6", Set.of(), nowL, false, false), // disabled

                    new Keyset(7, 102, "keyset7", null, nowL, true, true),
                    new Keyset(8, 103, "keyset8", Set.of(102, 104), nowL, true, true),
                    new Keyset(9, 104, "keyset9", Set.of(101), nowL, true, true),
                    new Keyset(10, 105, "keyset10", Set.of(), nowL, true, true)
            );

            KeysetKey[] keys = {
                    createKey(1001, now.minusSeconds(5), now.plusSeconds(3600), MasterKeysetId),
                    createKey(FALLBACK_PUBLISHER_KEY_ID, now.minusSeconds(5), now.plusSeconds(3600), FallbackPublisherKeysetId),
                    createKey(1003, now.minusSeconds(5), now.plusSeconds(3600), RefreshKeysetId),

                    // keys in keyset4
                    createKey(1004, now.minusSeconds(6), now.plusSeconds(3600), 4),
                    createKey(1005, now.minusSeconds(4), now.plusSeconds(3600), 4),
                    createKey(1006, now.minusSeconds(2), now.plusSeconds(3600), 4),
                    createKey(1007, now, now.plusSeconds(3600), 4),
                    createKey(1008, now.plusSeconds(5), now.plusSeconds(3600), 4),
                    createKey(1009, now.minusSeconds(5), now.minusSeconds(2), 4),

                    // keys in keyset5
                    createKey(1010, now, now.plusSeconds(3600), 5),
                    createKey(1011, now.plusSeconds(5), now.plusSeconds(3600), 5),
                    createKey(1012, now.minusSeconds(5), now.minusSeconds(2), 5),

                    // keys in keyset6
                    createKey(1013, now, now.plusSeconds(3600), 6),
                    createKey(1014, now.plusSeconds(5), now.plusSeconds(3600), 6),
                    createKey(1015, now.minusSeconds(5), now.minusSeconds(2), 6),

                    // keys in keyset7
                    createKey(1016, now, now.plusSeconds(3600), 7),
                    createKey(1017, now.plusSeconds(5), now.plusSeconds(3600), 7),
                    createKey(1018, now.minusSeconds(5), now.minusSeconds(2), 7),

                    // keys in keyset8
                    createKey(1019, now, now.plusSeconds(3600), 8),
                    createKey(1020, now.plusSeconds(5), now.plusSeconds(3600), 8),
                    createKey(1021, now.minusSeconds(5), now.minusSeconds(2), 8),

                    // keys in keyset9
                    createKey(1022, now, now.plusSeconds(3600), 9),
                    createKey(1023, now.plusSeconds(5), now.plusSeconds(3600), 9),
                    createKey(1024, now.minusSeconds(5), now.minusSeconds(2), 9),

                    // keys in keyset10
                    createKey(1025, now, now.plusSeconds(3600), 10),
                    createKey(1026, now.plusSeconds(5), now.plusSeconds(3600), 10),
                    createKey(1027, now.minusSeconds(5), now.minusSeconds(2), 10)
            };

            this.keysetIdToKeysetKeyList = keysetKeysToMap(keys);
            setupMockitoApiInterception();
        }

        public void setupMockitoApiInterception() {
            setupKeysetsMock(this.keysetIdToKeyset);
            setupKeysetsKeysMock(this.keysetIdToKeysetKeyList);
        }

        private boolean containsKey(int keyId) {
            return keysetIdToKeysetKeyList.values().stream()
                    .flatMap(List::stream)
                    .anyMatch(keysetKey -> keysetKey.getId() == keyId);
        }

        public void addKey(KeysetKey key) {
            int keyId = key.getId();
            if (containsKey(keyId)) {
                throw new RuntimeException(String.format("Cannot insert a key with duplicate Key ID %d.", keyId));
            }
            keysetIdToKeysetKeyList.computeIfAbsent(key.getKeysetId(), k -> new ArrayList<>()).add(key);
        }

        public void deleteKey(int keyId) {
            if (!containsKey(keyId)) {
                throw new RuntimeException(String.format("Cannot find a key with Key ID %d.", keyId));
            }

            keysetIdToKeysetKeyList.values().forEach(keysetKeyList ->
                    keysetKeyList.removeIf(keysetKey -> keysetKey.getId() == keyId));
        }

        public void addKeyset(int keysetId, Keyset keyset) {
            if (this.keysetIdToKeyset.containsKey(keysetId)) {
                throw new RuntimeException(String.format("Cannot insert a keyset with duplicate Keyset ID %d.", keysetId));
            }
            this.keysetIdToKeyset.put(keysetId, keyset);
        }

        public void setKeysetEnabled(int keysetId, Boolean newValue) {
            if (!this.keysetIdToKeyset.containsKey(keysetId)) {
                throw new RuntimeException(String.format("Cannot find a keyset with Keyset ID %d.", keysetId));
            }
            Keyset k = this.keysetIdToKeyset.get(keysetId);
            Keyset t = new Keyset(k.getKeysetId(), k.getSiteId(), k.getName(), k.getAllowedSites(), k.getCreated(),
                    newValue, k.isDefault());
            this.keysetIdToKeyset.remove(keysetId);
            this.keysetIdToKeyset.put(keysetId, t);
        }
    }

    private KeysetKey createKey(int id, Instant activates, Instant expires, int keysetId) {
        return new KeysetKey(id, makeAesKey("key" + id), activates.minusSeconds(10), activates, expires, keysetId);
    }

    @Test
    void getActiveKeyTest() {
        final Instant past = now.minusSeconds(100);
        final Instant future = now.plusSeconds(100);

        Keyset masterKeyset = new Keyset(MasterKeysetId, MasterKeySiteId, "master", Set.of(), past.getEpochSecond(), true, true);
        setupKeysetsMock(masterKeyset);

        KeysetKey expired1 = createKey(101, past, past, MasterKeysetId);
        KeysetKey expired2 = createKey(102, past, past, MasterKeysetId);
        KeysetKey expired3 = createKey(103, past, past, MasterKeysetId);

        KeysetKey active1 = createKey(201, past, future, MasterKeysetId);
        KeysetKey active2 = createKey(202, past, future, MasterKeysetId);
        KeysetKey active3 = createKey(203, past, future, MasterKeysetId);

        KeysetKey activatesNow1 = createKey(401, now, future, MasterKeysetId);
        KeysetKey activatesNow2 = createKey(402, now, future, MasterKeysetId);
        KeysetKey activatesNow3 = createKey(403, now, future, MasterKeysetId);

        KeysetKey activatesInFuture1 = createKey(501, future, future, MasterKeysetId);
        KeysetKey activatesInFuture2 = createKey(502, future, future, MasterKeysetId);
        KeysetKey activatesInFuture3 = createKey(503, future, future, MasterKeysetId);

        setupKeysetsKeysMock(expired1, expired2, expired3,
                active1, active2, active3,
                activatesNow1, activatesNow2, activatesNow3,
                activatesInFuture1, activatesInFuture2, activatesInFuture3);

        var snapshot = keysetKeyStore.getSnapshot();
        KeysetKey activeKey = snapshot.getActiveKey(MasterKeysetId, now);

        assertEquals(activatesNow3, activeKey); //getActiveKey() returns the last key that is active ("activates" not in the future, and "expires" is in the future)
    }

    @ParameterizedTest
    @ValueSource(strings = {"MultiKeysets", "AddKey", "RotateKey", "DisableActiveKey", "DisableDefaultKeyset"})
    void tokenGenerateRotatingKeysets_GENERATOR(String testRun, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 101;
        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
        fakeAuth(clientSiteId, Role.GENERATOR);
        MultipleKeysetsTests test = new MultipleKeysetsTests();
        //To read these tests, open the MultipleKeysetsTests() constructor in another window so you can see the keyset contents and validate expectations

        long nowL = now.toEpochMilli() / 1000;
        setupSalts();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email_hash", emailHash);

        KeysetKey activeKey = keysetKeyStore.getSnapshot().getActiveKey(4, Instant.now());
        assertEquals(activeKey.getId(), 1007);

        switch (testRun) {
            case "MultiKeysets":
                break;
            // a. Add a keyset with a key to a publisher. '/token/generate' encrypts with the old key
            case "AddKey":
                Keyset keyset11 = new Keyset(11, 107, "keyset11", Set.of(101), nowL, true, true);
                KeysetKey key1128 = new KeysetKey(1128, makeAesKey("key128"), now.minusSeconds(10), now.plusSeconds(5), now.plusSeconds(3600), 11);
                KeysetKey key1129 = new KeysetKey(1129, makeAesKey("key129"), now.minusSeconds(10), now.minusSeconds(5), now.minusSeconds(5), 11);
                test.addKeyset(11, keyset11);
                test.addKey(key1128); // not activated
                test.addKey(key1129); // expired
                test.setupMockitoApiInterception();
                break;
            // b. Rotate keys within a keyset. '/token/generate' encrypts with the new key
            case "RotateKey":
                KeysetKey key1329 = createKey(1329, now, now.plusSeconds(3600), 4); // default keyset
                test.addKey(key1329); // activates now
                test.setupMockitoApiInterception();
                KeysetKey actual = keysetKeyStore.getSnapshot().getActiveKey(4, now);
                assertEquals(key1329, actual);
                break;
            // c. Disable the active key within a keyset. '/token/generate' no longer encrypts with that key
            case "DisableActiveKey":
                test.deleteKey(1007); // disable active key
                test.setupMockitoApiInterception();
                break;
            // d. Disable a publisher's default keyset. '/token/generate' should encrypt with publisher fallback key
            case "DisableDefaultKeyset":
                test.setKeysetEnabled(4, false);
                test.setupMockitoApiInterception();
                break;
        }

        sendTokenGenerate(vertx, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    //Uses a key from default keyset
                    int clientKeyId;
                    if (advertisingToken.version == TokenVersion.V3 || advertisingToken.version == TokenVersion.V4) {
                        String advertisingTokenString = body.getString("advertising_token");
                        byte[] bytes = null;
                        if (advertisingToken.version == TokenVersion.V3) {
                            bytes = EncodingUtils.fromBase64(advertisingTokenString);
                        } else if (advertisingToken.version == TokenVersion.V4) {
                            bytes = Uid2Base64UrlCoder.decode(advertisingTokenString);  //same as V3 but use Base64URL encoding
                        }
                        final Buffer b = Buffer.buffer(bytes);
                        final int masterKeyId = b.getInt(2);

                        final byte[] masterPayloadBytes = AesGcm.decrypt(bytes, 6, keysetKeyStore.getSnapshot().getKey(masterKeyId));
                        final Buffer masterPayload = Buffer.buffer(masterPayloadBytes);
                        clientKeyId = masterPayload.getInt(29);
                    } else {
                        clientKeyId = advertisingToken.publisherIdentity.clientKeyId;
                    }
                    switch (testRun) {
                        case "MultiKeysets":
                            assertEquals(1007, clientKeyId); // should encrypt with active key in default keyset
                            break;
                        case "AddKey":
                            assertEquals(1007, clientKeyId); // should encrypt with old key
                            break;
                        case "RotateKey":
                            assertEquals(1329, clientKeyId); // should encrypt with new key
                            break;
                        case "DisableActiveKey":
                            assertNotEquals(1007, clientKeyId); // should no longer encrypt with disabled key
                            break;
                        case "DisableDefaultKeyset":
                            assertEquals(MultipleKeysetsTests.FALLBACK_PUBLISHER_KEY_ID, clientKeyId); // should encrypt with publisher fallback key
                            break;
                    }

                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void keySharingKeysets_CorrectFiltering(String contentType, Vertx vertx, VertxTestContext testContext) {
        //Call should return
        // all keys they have access in ACL
        // The master key -1
        //Call Should not return
        // The master key -2
        // The publisher General 2
        // Any other key without an ACL
        int siteId = 4;
        fakeAuth(siteId, Role.SHARER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(RefreshKeysetId, RefreshKeySiteId, "test", Set.of(-1, -2, 2, 4, 42, 43, 44, 45), now.getEpochSecond(), true, true),
                new Keyset(FallbackPublisherKeysetId, AdvertisingTokenSiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(104, 42, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(105, 43, "test", Set.of(4, 42, 43, 44, 45), now.getEpochSecond(), true, true),
                new Keyset(106, 44, "test", Set.of(4, 42, 43, 44, 45), now.getEpochSecond(), true, true),
                new Keyset(107, 45, "test", Set.of(4, 42, 43, 44, 45), now.getEpochSecond(), true, true),
                new Keyset(108, 4, "test", Set.of(), now.getEpochSecond(), true, true),
        };

        final KeysetKey masterKey = new KeysetKey(3, "masterKey".getBytes(), now, now, now.plusSeconds(10), MasterKeysetId); // siteId = -1
        final KeysetKey clientsKey = new KeysetKey(7, "clientsKey".getBytes(), now, now, now.plusSeconds(10), 108); // siteId = 4
        final KeysetKey sharingkey12 = new KeysetKey(12, "sharingkey12".getBytes(), now, now, now.plusSeconds(10), 105); // siteId = 43
        final KeysetKey sharingkey13 = new KeysetKey(13, "sharingkey13".getBytes(), now, now, now.plusSeconds(10), 106); // siteId = 44
        final KeysetKey sharingkey14 = new KeysetKey(14, "sharingkey14".getBytes(), now, now, now.plusSeconds(10), 107); // siteId = 45

        KeysetKey[] encryptionKeys = {
                new KeysetKey(6, "sharingkey6".getBytes(), now, now, now.plusSeconds(10), 104), // siteId = 42
                sharingkey12, sharingkey13, sharingkey14, masterKey,
                new KeysetKey(42, "masterKey2".getBytes(), now, now, now.plusSeconds(10), RefreshKeysetId), // siteId = -2
                clientsKey,
                new KeysetKey(5, "publisherMaster".getBytes(), now, now, now.plusSeconds(10), FallbackPublisherKeysetId), // siteId = 2
                new KeysetKey(9, "key with no ACL".getBytes(), now, now, now.plusSeconds(10), FallbackPublisherKeysetId), // siteId = 2
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        KeysetKey[] expectedKeys = new KeysetKey[]{masterKey, clientsKey, sharingkey12, sharingkey13, sharingkey14};
        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));

        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, siteId, expectedKeys);
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    private static Site defaultMockSite(int siteId, boolean includeDomainNames, boolean includeAppNames) {
        Site site = new Site(siteId, "site" + siteId, true);
        if (includeDomainNames) {
            site.setDomainNames(Set.of(siteId + ".com", siteId + ".co.uk"));
        }
        if (includeAppNames) {
            site.setAppNames(Set.of(siteId + ".com.UID2.operator", siteId + "bundle123", "12345789"));
        }
        return site;
    }

    //set some default domain names for all possible sites for each unit test first
    private void setupSiteDomainAndAppNameMock(boolean includeDomainNames, boolean includeAppNames, int... siteIds) {

        Map<Integer, Site> sites = new HashMap<>();
        for (int siteId : siteIds) {
            sites.put(siteId, defaultMockSite(siteId, includeDomainNames, includeAppNames));
        }

        when(siteProvider.getAllSites()).thenReturn(new HashSet<>(sites.values()));
        when(siteProvider.getSite(anyInt())).thenAnswer(invocation -> {
            int siteId = invocation.getArgument(0);
            return sites.get(siteId);
        });
    }

    private void setupMockSites(Map<Integer, Site> sites) {
        when(siteProvider.getAllSites()).thenReturn(new HashSet<>(sites.values()));
        when(siteProvider.getSite(anyInt())).thenAnswer(invocation -> {
            int siteId = invocation.getArgument(0);
            return sites.get(siteId);
        });
    }

    static Map<Integer, Site> setupExpectation(boolean includeDomainNames, boolean includeAppNames, int... siteIds) {
        Map<Integer, Site> expectedSites = new HashMap<>();
        for (int siteId : siteIds) {
            if (includeDomainNames || includeAppNames) {
                expectedSites.put(siteId, defaultMockSite(siteId, includeDomainNames, includeAppNames));
            }
        }
        return expectedSites;
    }

    public void verifyExpectedSiteDetail(Map<Integer, Site> expectedSites, JsonArray actualResult) {
        assertEquals(expectedSites.size(), actualResult.size());
        for (int i = 0; i < actualResult.size(); i++) {
            JsonObject siteDetail = actualResult.getJsonObject(i);
            int siteId = siteDetail.getInteger("id");
            List<String> actualDomainList = (List<String>) siteDetail.getMap().get("domain_names");
            Site expectedSite = expectedSites.get(siteId);
            int size = 0;
            assertTrue(actualDomainList.containsAll(expectedSite.getDomainNames()));
            size += expectedSite.getDomainNames().size();
            assertTrue(actualDomainList.containsAll(expectedSite.getAppNames()));
            size += expectedSite.getAppNames().size();
            assertEquals(size, actualDomainList.size());
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    public class keyBidstreamCustomMaxBidstreamLifetime {
        // The @BeforeAll annotation will let setupConfig run before the outer class's @BeforeEach, allowing us to
        // customise the verticle config before it is deployed.
        @BeforeAll
        public void setupConfig() {
            UIDOperatorVerticleTest.this.config.put(Const.Config.MaxBidstreamLifetimeSecondsProp, 9999);
        }

        @Test
        public void keyBidstreamReturnsCustomMaxBidstreamLifetimeHeader(Vertx vertx, VertxTestContext testContext) {
            final KeyDownloadEndpoint endpoint = KeyDownloadEndpoint.BIDSTREAM;

            final int clientSiteId = 101;
            fakeAuth(clientSiteId, Role.ID_READER);

            // Required, sets up mock keys.
            new MultipleKeysetsTests();

            send(vertx, "v2" + endpoint.getPath(), null, 200, respJson -> {
                assertEquals("success", respJson.getString("status"));

                checkKeyDownloadResponseHeaderFields(endpoint, respJson.getJsonObject("body"), clientSiteId);

                testContext.completeNow();
            });
        }
    }

    private static Stream<Arguments> testKeyDownloadEndpointKeysetsData_IDREADER() {
        int[] expectedSiteIds = new int[]{101, 102};
        int[] allMockedSiteIds = new int[]{101, 102, 103, 105};
        Map<Integer, Site> expectedSitesDomainsOnly = setupExpectation(true, false, expectedSiteIds);
        Map<Integer, Site> mockSitesWithDomainsOnly = setupExpectation(true, false, allMockedSiteIds);

        Map<Integer, Site> expectedSitesWithBoth = setupExpectation(true, true, expectedSiteIds);
        Map<Integer, Site> mockSitesWithBoth = setupExpectation(true, true, allMockedSiteIds);

        Map<Integer, Site> expectedSitesWithAppNamesOnly = setupExpectation(false, true, expectedSiteIds);
        Map<Integer, Site> mockSitesWithAppNamesOnly = setupExpectation(false, true, allMockedSiteIds);
        Map<Integer, Site> emptySites = new HashMap<>();
        return Stream.of(
                // Both domains and app names should be present in response
                Arguments.of("true", KeyDownloadEndpoint.SHARING, mockSitesWithBoth, expectedSitesWithBoth),
                Arguments.of("true", KeyDownloadEndpoint.BIDSTREAM, mockSitesWithBoth, expectedSitesWithBoth),

                // only domains should be present in response
                Arguments.of("false", KeyDownloadEndpoint.SHARING, mockSitesWithDomainsOnly, expectedSitesDomainsOnly),
                Arguments.of("false", KeyDownloadEndpoint.BIDSTREAM, mockSitesWithDomainsOnly, expectedSitesDomainsOnly),

                // only app names should be present in response
                Arguments.of("true", KeyDownloadEndpoint.SHARING, mockSitesWithAppNamesOnly, expectedSitesWithAppNamesOnly),
                Arguments.of("true", KeyDownloadEndpoint.BIDSTREAM, mockSitesWithAppNamesOnly, expectedSitesWithAppNamesOnly),

                // None
                Arguments.of("false", KeyDownloadEndpoint.SHARING, emptySites, emptySites),
                Arguments.of("false", KeyDownloadEndpoint.BIDSTREAM, emptySites, emptySites)
        );
    }

    @ParameterizedTest
    @MethodSource("testKeyDownloadEndpointKeysetsData_IDREADER")
        // Test the /key/sharing and /key/bidstream endpoints when called with the ID_READER role.
        //
        // Tests:
        //   ID_READER has access to a keyset that has the same site_id as ID_READER's  - direct access
        //   ID_READER has access to a keyset with a missing allowed_sites              - access through sharing
        //   ID_READER has access to a keyset with allowed_sites that includes us       - access through sharing
        //   ID_READER has no access to a keyset that is disabled                       - direct reject
        //   ID_READER has no access to a keyset with an empty allowed_sites            - reject by sharing
        //   ID_READER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keyDownloadEndpointKeysets_IDREADER(boolean provideAppNames, KeyDownloadEndpoint endpoint,
                                             Map<Integer, Site> mockSites, Map<Integer, Site> expectedSites,
                                             Vertx vertx, VertxTestContext testContext) {
        if (!provideAppNames) {
            this.uidOperatorVerticle.setKeySharingEndpointProvideAppNames(false);
        }
        int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.ID_READER);
        MultipleKeysetsTests test = new MultipleKeysetsTests();

        //To read these tests, open the MultipleKeysetsTests() constructor in another window so you can see the keyset contents and validate against expectedKeys

        //Keys from these keysets are not expected: keyset6 (disabled keyset), keyset8 (not sharing with site 101), keyset10 (not sharing with anyone)
        KeysetKey[] expectedKeys = {
                createKey(1001, now.minusSeconds(5), now.plusSeconds(3600), MasterKeysetId),
                createKey(1002, now.minusSeconds(5), now.plusSeconds(3600), RefreshKeysetId),
                // keys in keyset4
                createKey(1004, now.minusSeconds(6), now.plusSeconds(3600), 4),
                createKey(1005, now.minusSeconds(4), now.plusSeconds(3600), 4),
                createKey(1006, now.minusSeconds(2), now.plusSeconds(3600), 4),
                createKey(1007, now, now.plusSeconds(3600), 4),
                createKey(1008, now.plusSeconds(5), now.plusSeconds(3600), 4),
                createKey(1009, now.minusSeconds(5), now.minusSeconds(2), 4),
                // keys in keyset5
                createKey(1010, now, now.plusSeconds(3600), 5),
                createKey(1011, now.plusSeconds(5), now.plusSeconds(3600), 5),
                createKey(1012, now.minusSeconds(5), now.minusSeconds(2), 5),
                // keys in keyset7
                createKey(1016, now, now.plusSeconds(3600), 7),
                createKey(1017, now.plusSeconds(5), now.plusSeconds(3600), 7),
                createKey(1018, now.minusSeconds(5), now.minusSeconds(2), 7),
                // keys in keyset9
                createKey(1022, now, now.plusSeconds(3600), 9),
                createKey(1023, now.plusSeconds(5), now.plusSeconds(3600), 9),
                createKey(1024, now.minusSeconds(5), now.minusSeconds(2), 9)
        };

        setupMockSites(mockSites);
        //site 104 domain name list will be returned but we will set a blank list for it
        doReturn(new Site(104, "site104", true, new HashSet<>())).when(siteProvider).getSite(104);

        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2" + endpoint.getPath(), null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals("success", respJson.getString("status"));

            final JsonObject body = respJson.getJsonObject("body");

            checkKeyDownloadResponseHeaderFields(endpoint, body, clientSiteId);

            checkEncryptionKeys(respJson, endpoint, clientSiteId, expectedKeys);

            // site 104 has empty domain name list intentionally previously so while site 104 should be included in
            // this /key/sharing response, it won't appear in this domain name list
            verifyExpectedSiteDetail(expectedSites, body.getJsonArray("site_data"));
            testContext.completeNow();
        });
    }

    @Test
    void keySharingKeysets_SHARER_CustomMaxSharingLifetimeSeconds(Vertx vertx, VertxTestContext testContext) {
        this.runtimeConfig = this.runtimeConfig.toBuilder().withMaxSharingLifetimeSeconds(999999).build();
        keySharingKeysets_SHARER(true, true, vertx, testContext, 999999);
    }

    @ParameterizedTest
    @CsvSource({
            "true, true",
            "true, false",
            "false, false",
            "true, false"
    })
    void keySharingKeysets_SHARER_defaultMaxSharingLifetimeSeconds(boolean provideSiteDomainNames, boolean provideAppNames, Vertx vertx, VertxTestContext testContext) {
        keySharingKeysets_SHARER(provideSiteDomainNames, provideAppNames, vertx, testContext, this.config.getInteger(Const.Config.SharingTokenExpiryProp));
    }

    // Tests:
//   SHARER has access to a keyset that has the same site_id as ID_READER's  - direct access
//   SHARER has access to a keyset with allowed_sites that includes us       - access through sharing
//   SHARER has no access to a keyset that is disabled                       - direct reject
//   SHARER has no access to a keyset with a missing allowed_sites           - reject by sharing
//   SHARER has no access to a keyset with an empty allowed_sites            - reject by sharing
//   SHARER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keySharingKeysets_SHARER(boolean provideSiteDomainNames, boolean provideAppNames, Vertx vertx, VertxTestContext testContext, int expectedMaxSharingLifetimeSeconds) {
        if (!provideAppNames) {
            this.uidOperatorVerticle.setKeySharingEndpointProvideAppNames(false);
        }
        int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.SHARER);
        MultipleKeysetsTests test = new MultipleKeysetsTests();
        //To read these tests, open the MultipleKeysetsTests() constructor in another window so you can see the keyset contents and validate against expectedKeys
        setupSiteDomainAndAppNameMock(provideSiteDomainNames, provideAppNames, 101, 102, 103, 104, 105);
        //Keys from these keysets are not expected: keyset6 (disabled keyset), keyset7 (sharing with ID_READERs but not SHARERs), keyset8 (not sharing with 101), keyset10 (not sharing with anyone)
        KeysetKey[] expectedKeys = {
                createKey(1001, now.minusSeconds(5), now.plusSeconds(3600), MasterKeysetId),
                // keys in keyset4
                createKey(1004, now.minusSeconds(6), now.plusSeconds(3600), 4),
                createKey(1005, now.minusSeconds(4), now.plusSeconds(3600), 4),
                createKey(1006, now.minusSeconds(2), now.plusSeconds(3600), 4),
                createKey(1007, now, now.plusSeconds(3600), 4),
                createKey(1008, now.plusSeconds(5), now.plusSeconds(3600), 4),
                createKey(1009, now.minusSeconds(5), now.minusSeconds(2), 4),
                // keys in keyset5
                createKey(1010, now, now.plusSeconds(3600), 5),
                createKey(1011, now.plusSeconds(5), now.plusSeconds(3600), 5),
                createKey(1012, now.minusSeconds(5), now.minusSeconds(2), 5),
                // keys in keyset9
                createKey(1022, now, now.plusSeconds(3600), 9),
                createKey(1023, now.plusSeconds(5), now.plusSeconds(3600), 9),
                createKey(1024, now.minusSeconds(5), now.minusSeconds(2), 9)
        };

        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals("success", respJson.getString("status"));
            assertEquals(clientSiteId, respJson.getJsonObject("body").getInteger("caller_site_id"));
            assertEquals(UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS, respJson.getJsonObject("body").getInteger("master_keyset_id"));
            assertEquals(4, respJson.getJsonObject("body").getInteger("default_keyset_id"));

            assertEquals(config.getInteger(Const.Config.SharingTokenExpiryProp), Integer.parseInt(respJson.getJsonObject("body").getString("token_expiry_seconds")));
            assertEquals(expectedMaxSharingLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds(), respJson.getJsonObject("body").getLong("max_sharing_lifetime_seconds"));
            assertEquals(getIdentityScope().toString(), respJson.getJsonObject("body").getString("identity_scope"));
            assertNotNull(respJson.getJsonObject("body").getInteger("allow_clock_skew_seconds"));

            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, clientSiteId, expectedKeys);

            Map<Integer, Site> expectedSites = setupExpectation(provideSiteDomainNames, provideAppNames, 101, 104);
            verifyExpectedSiteDetail(expectedSites, respJson.getJsonObject("body").getJsonArray("site_data"));

            testContext.completeNow();
        });
    }

    @Test
    void keySharingKeysets_ReturnsMasterAndSite(Vertx vertx, VertxTestContext testContext) {
        int siteId = 5;
        fakeAuth(siteId, Role.SHARER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(10, 5, "siteKeyset", null, now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "master key".getBytes(), now, now, now.plusSeconds(10), MasterKeysetId),
                new KeysetKey(102, "site key".getBytes(), now, now, now.plusSeconds(10), 10),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        setupSiteDomainAndAppNameMock(true, false, 101, 102, 103, 104, 105);
        Arrays.sort(encryptionKeys, Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            System.out.println(respJson);
            verifyExpectedSiteDetail(new HashMap<>(), respJson.getJsonObject("body").getJsonArray("site_data"));
            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, siteId, encryptionKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"NoKeyset", "NoKey", "SharedKey"})
    void keySharingKeysets_CorrectIDS(String testRun, Vertx vertx, VertxTestContext testContext) {
        int siteId = 0;
        KeysetKey[] keys = null;

        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(RefreshKeysetId, RefreshKeySiteId, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(FallbackPublisherKeysetId, AdvertisingTokenSiteId, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(4, 10, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(5, 11, "test", Set.of(10), now.getEpochSecond(), true, true),
                new Keyset(6, 12, "test", Set.of(), now.getEpochSecond(), true, true),
                new Keyset(7, 13, "test", Set.of(12), now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(1, makeAesKey("masterKey"), now, now, now.plusSeconds(10), MasterKeysetId),
                new KeysetKey(2, makeAesKey("siteKey"), now, now, now.plusSeconds(10), RefreshKeysetId),
                new KeysetKey(3, makeAesKey("refreshKey"), now, now, now.plusSeconds(10), FallbackPublisherKeysetId),
                new KeysetKey(4, "key4".getBytes(), now, now, now.plusSeconds(10), 7),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        setupSiteDomainAndAppNameMock(true, false, 10, 11, 12, 13);
        switch (testRun) {
            case "NoKeyset":
                siteId = 8;
                keys = new KeysetKey[]{encryptionKeys[0]}; // only master key should return. 'default_keyset_id' should not exist in json
                break;
            case "NoKey":
                siteId = 10;
                keys = new KeysetKey[]{encryptionKeys[0]}; // only master key should return. 'default_keyset_id' should be 4
                break;
            case "SharedKey":
                siteId = 12;
                keys = new KeysetKey[]{encryptionKeys[0], encryptionKeys[3]}; // master key and key4 should return. 'default_keyset_id' should be 6
                break;
        }

        final int clientSiteId = siteId;
        fakeAuth(clientSiteId, Role.SHARER);
        final KeysetKey[] expectedKeys = Arrays.copyOfRange(keys, 0, keys.length);
        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));

        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals(clientSiteId, respJson.getJsonObject("body").getInteger("caller_site_id"));
            assertEquals(UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS, respJson.getJsonObject("body").getInteger("master_keyset_id"));

            JsonArray siteData = respJson.getJsonObject("body").getJsonArray("site_data");

            switch (testRun) {
                case "NoKeyset":
                    assertNull(respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    //no site downloaded
                    verifyExpectedSiteDetail(new HashMap<>(), siteData);
                    break;
                case "NoKey":
                    assertEquals(4, respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    //no site downloaded
                    verifyExpectedSiteDetail(new HashMap<>(), siteData);
                    break;
                case "SharedKey":
                    assertEquals(6, respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    //key 4 returned which has keyset id 7 which in turns has site id 13
                    Map<Integer, Site> expectedSites = setupExpectation(true, false, 13);
                    verifyExpectedSiteDetail(expectedSites, siteData);
                    break;
            }
            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, clientSiteId, expectedKeys);
            testContext.completeNow();
        });
    }

    private static List<Arguments> keyDownloadEndpointRotatingKeysets_IDREADER_source() {
        final String[] testRuns = {"KeysetAccess", "AddKeyset", "AddKey", "RotateKey", "DisableKey", "DisableKeyset"};

        final List<Arguments> arguments = new ArrayList<>();
        for (KeyDownloadEndpoint endpoint : KeyDownloadEndpoint.values()) {
            for (String testRun : testRuns) {
                arguments.add(Arguments.of(testRun, endpoint));
            }
        }
        return arguments;
    }

    @ParameterizedTest
    @MethodSource("keyDownloadEndpointRotatingKeysets_IDREADER_source")
        // Test the /key/sharing and /key/bidstream endpoints when called with the ID_READER role.
        //
        // "KeysetAccess"
        //   ID_READER has access to a keyset that has the same site_id as ID_READER's  - direct access
        //   ID_READER has access to a keyset with a missing allowed_sites              - access through sharing
        //   ID_READER has access to a keyset with allowed_sites that includes us       - access through sharing
        //   ID_READER has no access to a keyset that is disabled                       - direct reject
        //   ID_READER has no access to a keyset with an empty allowed_sites            - reject by sharing
        //   ID_READER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keyDownloadEndpointRotatingKeysets_IDREADER(String testRun, KeyDownloadEndpoint endpoint, Vertx vertx, VertxTestContext testContext) {
        int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.ID_READER);
        MultipleKeysetsTests test = new MultipleKeysetsTests();
        //To read these tests, open the MultipleKeysetsTests() constructor in another window so you can see the keyset contents and validate against expectedKeys

        long nowL = now.toEpochMilli() / 1000;
        List<KeysetKey> expectedKeys = new ArrayList<>(Arrays.asList(
                createKey(1001, now.minusSeconds(5), now.plusSeconds(3600), MasterKeysetId),
                createKey(1002, now.minusSeconds(5), now.plusSeconds(3600), RefreshKeysetId),

                // keys in keyset4
                createKey(1004, now.minusSeconds(6), now.plusSeconds(3600), 4),
                createKey(1005, now.minusSeconds(4), now.plusSeconds(3600), 4),
                createKey(1006, now.minusSeconds(2), now.plusSeconds(3600), 4),
                createKey(1007, now, now.plusSeconds(3600), 4),
                createKey(1008, now.plusSeconds(5), now.plusSeconds(3600), 4),
                createKey(1009, now.minusSeconds(5), now.minusSeconds(2), 4),
                // keys in keyset5
                createKey(1010, now, now.plusSeconds(3600), 5),
                createKey(1011, now.plusSeconds(5), now.plusSeconds(3600), 5),
                createKey(1012, now.minusSeconds(5), now.minusSeconds(2), 5),
                // keys in keyset7
                createKey(1016, now, now.plusSeconds(3600), 7),
                createKey(1017, now.plusSeconds(5), now.plusSeconds(3600), 7),
                createKey(1018, now.minusSeconds(5), now.minusSeconds(2), 7),
                // keys in keyset9
                createKey(1022, now, now.plusSeconds(3600), 9),
                createKey(1023, now.plusSeconds(5), now.plusSeconds(3600), 9),
                createKey(1024, now.minusSeconds(5), now.minusSeconds(2), 9)
        ));

        switch (testRun) {
            // a. Add a keyset with keys (1 active & 1 expired). Test '/key/sharing' includes the new active key
            case "AddKeyset":
                Keyset keyset11 = new Keyset(11, 107, "keyset11", Set.of(101), nowL, true, true);
                KeysetKey key1128 = new KeysetKey(1128, makeAesKey("key128"), now.minusSeconds(10), now.minusSeconds(5), now.plusSeconds(3600), 11);
                KeysetKey key1129 = new KeysetKey(1129, makeAesKey("key129"), now.minusSeconds(10), now.minusSeconds(5), now.minusSeconds(5), 11);
                test.addKeyset(11, keyset11);
                test.addKey(key1128);
                test.addKey(key1129); // key129 is expired but should return
                test.setupMockitoApiInterception();
                expectedKeys.add(key1128);
                expectedKeys.add(key1129);
                break;

            // b. Add keys to existing keysets (1 default, 1 non-default, 1 disabled, 1 shared). Test '/key/sharing' includes the new keys from enabled, default & allowed access keysets
            case "AddKey":
                KeysetKey key1229 = new KeysetKey(1229, makeAesKey("key229"), now.minusSeconds(10), now.minusSeconds(5), now.plusSeconds(3600), 4); // default keyset
                KeysetKey key1230 = new KeysetKey(1230, makeAesKey("key230"), now.minusSeconds(10), now.minusSeconds(5), now.plusSeconds(3600), 5); // non-default keyset
                KeysetKey key1231 = new KeysetKey(1231, makeAesKey("key231"), now.minusSeconds(10), now.minusSeconds(5), now.plusSeconds(3600), 6); // disabled keyset
                KeysetKey key1232 = new KeysetKey(1232, makeAesKey("key232"), now.minusSeconds(10), now.minusSeconds(5), now.plusSeconds(3600), 9); // sharing through 'allowed_site'
                test.addKey(key1229);
                test.addKey(key1230);
                test.addKey(key1231); // keyset6 is disabled
                test.addKey(key1232);
                test.setupMockitoApiInterception();
                expectedKeys.add(key1229);
                expectedKeys.add(key1230);
                expectedKeys.add(key1232);
                break;

            // c. Rotate keys within a keyset. Test /key/sharing shows the rotation
            case "RotateKey":
                KeysetKey key329 = createKey(329, now /* activate immediately */, now.plusSeconds(3600), 4); // default keyset
                test.addKey(key329);
                test.setupMockitoApiInterception();
                expectedKeys.add(key329);
                KeysetKey actual = keysetKeyStore.getSnapshot().getActiveKey(4, now);
                assertEquals(key329, actual);
                break;

            // d. Disable(delete) a key within a keyset. Test /key/sharing no longer shows the disabled key
            case "DisableKey":
                test.deleteKey(1008);
                test.setupMockitoApiInterception();
                expectedKeys.removeIf(x -> x.getId() == 1008); // key108 is deleted and should not return.
                break;

            // e. Disable a keyset. Test /key/sharing no longer shows keys from the disabled keyset
            case "DisableKeyset":
                test.setKeysetEnabled(5, false); // disable keyset5 that contains key10 & key11
                test.setupMockitoApiInterception();
                expectedKeys.removeIf(x -> x.getId() == 1010 || x.getId() == 1011 || x.getId() == 1012); // key10, key11, key12 should not return.
                break;
        }

        // test and validate results
        expectedKeys.sort(Comparator.comparing(KeysetKey::getId));
        send(vertx, "v2" + endpoint.getPath(), null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals("success", respJson.getString("status"));
            final JsonObject body = respJson.getJsonObject("body");

            checkKeyDownloadResponseHeaderFields(endpoint, body, clientSiteId);

            checkEncryptionKeys(respJson, endpoint, clientSiteId, expectedKeys.toArray(new KeysetKey[0]));
            testContext.completeNow();
        });
    }

    private void checkKeyDownloadResponseHeaderFields(KeyDownloadEndpoint endpoint, JsonObject body, int clientSiteId) {
        final JsonObject bodyHeaders = body.copy();
        bodyHeaders.remove("site_data");
        bodyHeaders.remove("keys");

        final JsonObject expected = new JsonObject()
                .put("identity_scope", this.getIdentityScope().toString())
                .put("allow_clock_skew_seconds", config.getInteger(Const.Config.AllowClockSkewSecondsProp));

        switch (endpoint) {
            case SHARING:
                expected.put("caller_site_id", clientSiteId);
                expected.put("master_keyset_id", UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS);
                expected.put("default_keyset_id", 4);
                // NOTE: this is intentionally a string, not an integer. See comment in UIDOperatorVerticle.
                expected.put("token_expiry_seconds", config.getInteger(Const.Config.SharingTokenExpiryProp).toString());
                break;
            case BIDSTREAM:
                final int expectedMaxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp, config.getInteger(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
                expected.put("max_bidstream_lifetime_seconds", expectedMaxBidstreamLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds());
                break;
        }

        assertEquals(expected, bodyHeaders);
    }

    @Test
    void secureLinkValidationPassesReturnsIdentity(Vertx vertx, VertxTestContext testContext) {
        SaltEntry salt = setupSalts();

        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(true);

        send(vertx, "v2/identity/map", req, 200, json -> {
            checkIdentityMapResponse(json, salt, false, IdentityType.Email, false,"test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @Test
    void secureLinkValidationFailsReturnsIdentityError(Vertx vertx, VertxTestContext testContext) {
        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(false);

        send(vertx, "v2/identity/map", req, 401, json -> {
            assertEquals("unauthorized", json.getString("status"));
            assertEquals("Invalid link_id", json.getString("message"));
            testContext.completeNow();
        });
    }

    @Test
    void tokenGenerateRespectsConfigValues(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        Duration newIdentityExpiresAfter = Duration.ofMinutes(20);
        Duration newRefreshExpiresAfter = Duration.ofMinutes(30);
        Duration newRefreshIdentityAfter = Duration.ofMinutes(10);

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withIdentityTokenExpiresAfterSeconds((int) newIdentityExpiresAfter.toSeconds())
                .withRefreshTokenExpiresAfterSeconds((int) newRefreshExpiresAfter.toSeconds())
                .withRefreshIdentityTokenAfterSeconds((int) newRefreshIdentityAfter.toSeconds())
                .build();

        sendTokenGenerate(vertx, v2Payload, 200,
                respJson -> {
                    testContext.verify(() -> {
                        JsonObject body = respJson.getJsonObject("body");
                        assertNotNull(body);
                        assertEquals(now.plusMillis(newIdentityExpiresAfter.toMillis()).toEpochMilli(), body.getLong("identity_expires"));
                        assertEquals(now.plusMillis(newRefreshExpiresAfter.toMillis()).toEpochMilli(), body.getLong("refresh_expires"));
                        assertEquals(now.plusMillis(newRefreshIdentityAfter.toMillis()).toEpochMilli(), body.getLong("refresh_from"));
                    });
                    testContext.completeNow();
                });
    }

    @Test
    void keySharingRespectsConfigValues(Vertx vertx, VertxTestContext testContext) {
        int newSharingTokenExpiry = config.getInteger(Const.Config.SharingTokenExpiryProp) + 1;
        int newMaxSharingLifetimeSeconds = config.getInteger(Const.Config.SharingTokenExpiryProp) + 1;

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withSharingTokenExpirySeconds(newSharingTokenExpiry)
                .withMaxBidstreamLifetimeSeconds(newMaxSharingLifetimeSeconds)
                .build();

        int siteId = 5;
        fakeAuth(siteId, Role.SHARER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(10, 5, "siteKeyset", null, now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "master key".getBytes(), now, now, now.plusSeconds(10), MasterKeysetId),
                new KeysetKey(102, "site key".getBytes(), now, now, now.plusSeconds(10), 10),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        setupSiteDomainAndAppNameMock(true, false, 101, 102, 103, 104, 105);
        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            testContext.verify(() -> {
                JsonObject body = respJson.getJsonObject("body");
                assertNotNull(body);
                assertEquals(newSharingTokenExpiry, Integer.parseInt(body.getString("token_expiry_seconds")));
                assertEquals(newMaxSharingLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds(), body.getLong(Const.Config.MaxSharingLifetimeProp));
            });
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/octet-stream"})
    void keyBidstreamRespectsConfigValues(String contentType, Vertx vertx, VertxTestContext testContext) {
        int newMaxBidstreamLifetimeSeconds = 999999;

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withMaxBidstreamLifetimeSeconds(newMaxBidstreamLifetimeSeconds)
                .build();

        final KeyDownloadEndpoint endpoint = KeyDownloadEndpoint.BIDSTREAM;

        final int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.ID_READER);

        // Required, sets up mock keys.
        new MultipleKeysetsTests();

        send(vertx, "v2" + endpoint.getPath(), null, 200, respJson -> {
            testContext.verify(() -> {
                JsonObject body = respJson.getJsonObject("body");
                assertNotNull(body);
                assertEquals(newMaxBidstreamLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds(), body.getLong(Const.Config.MaxBidstreamLifetimeSecondsProp));
            });
            testContext.completeNow();
        }, Map.of(HttpHeaders.CONTENT_TYPE.toString(), contentType));
    }

    @Test
    void tokenGenerateRespectsConfigValuesWithRemoteConfig(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        Duration newIdentityExpiresAfter = Duration.ofMinutes(20);
        Duration newRefreshExpiresAfter = Duration.ofMinutes(30);
        Duration newRefreshIdentityAfter = Duration.ofMinutes(10);

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withIdentityTokenExpiresAfterSeconds((int) newIdentityExpiresAfter.toSeconds())
                .withRefreshTokenExpiresAfterSeconds((int) newRefreshExpiresAfter.toSeconds())
                .withRefreshIdentityTokenAfterSeconds((int) newRefreshIdentityAfter.toSeconds())
                .build();

        sendTokenGenerate(vertx, v2Payload, 200,
                respJson -> {
                    testContext.verify(() -> {
                        JsonObject body = respJson.getJsonObject("body");
                        assertNotNull(body);
                        assertEquals(now.plusMillis(newIdentityExpiresAfter.toMillis()).toEpochMilli(), body.getLong("identity_expires"));
                        assertEquals(now.plusMillis(newRefreshExpiresAfter.toMillis()).toEpochMilli(), body.getLong("refresh_expires"));
                        assertEquals(now.plusMillis(newRefreshIdentityAfter.toMillis()).toEpochMilli(), body.getLong("refresh_from"));
                    });
                    testContext.completeNow();
                });
    }

    @Test
    void keySharingRespectsConfigValuesWithRemoteConfig(Vertx vertx, VertxTestContext testContext) {
        int newSharingTokenExpiry = config.getInteger(Const.Config.SharingTokenExpiryProp) + 1;
        int newMaxSharingLifetimeSeconds = config.getInteger(Const.Config.SharingTokenExpiryProp) + 1;

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withSharingTokenExpirySeconds(newSharingTokenExpiry)
                .withMaxSharingLifetimeSeconds(newMaxSharingLifetimeSeconds)
                .build();

        int siteId = 5;
        fakeAuth(siteId, Role.SHARER);
        Keyset[] keysets = {
                new Keyset(MasterKeysetId, MasterKeySiteId, "test", null, now.getEpochSecond(), true, true),
                new Keyset(10, 5, "siteKeyset", null, now.getEpochSecond(), true, true),
        };
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "master key".getBytes(), now, now, now.plusSeconds(10), MasterKeysetId),
                new KeysetKey(102, "site key".getBytes(), now, now, now.plusSeconds(10), 10),
        };
        MultipleKeysetsTests test = new MultipleKeysetsTests(Arrays.asList(keysets), Arrays.asList(encryptionKeys));
        setupSiteDomainAndAppNameMock(true, false, 101, 102, 103, 104, 105);
        send(vertx, "v2/key/sharing", null, 200, respJson -> {
            testContext.verify(() -> {
                JsonObject body = respJson.getJsonObject("body");
                assertNotNull(body);
                assertEquals(newSharingTokenExpiry, Integer.parseInt(body.getString("token_expiry_seconds")));
                assertEquals(newMaxSharingLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds(), body.getLong(Const.Config.MaxSharingLifetimeProp));
            });
            testContext.completeNow();
        });
    }

    @Test
    void keyBidstreamRespectsConfigValuesWithRemoteConfig(Vertx vertx, VertxTestContext testContext) {
        int newMaxBidstreamLifetimeSeconds = 999999;

        this.runtimeConfig = this.runtimeConfig
                .toBuilder()
                .withMaxBidstreamLifetimeSeconds(newMaxBidstreamLifetimeSeconds)
                .build();

        final KeyDownloadEndpoint endpoint = KeyDownloadEndpoint.BIDSTREAM;

        final int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.ID_READER);

        // Required, sets up mock keys.
        new MultipleKeysetsTests();

        send(vertx, "v2" + endpoint.getPath(), null, 200, respJson -> {
            testContext.verify(() -> {
                JsonObject body = respJson.getJsonObject("body");
                assertNotNull(body);
                assertEquals(newMaxBidstreamLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds(), body.getLong(Const.Config.MaxBidstreamLifetimeSecondsProp));
            });
            testContext.completeNow();
        });
    }

    private void assertLastUpdatedHasMillis(JsonArray buckets) {
        for (int i = 0; i < buckets.size(); i++) {
            JsonObject bucket = buckets.getJsonObject(i);
            String lastUpdated = bucket.getString("last_updated");
            // Verify pattern yyyy-MM-dd'T'HH:mm:ss.SSS
            assertTrue(lastUpdated.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}"),
                    "last_updated does not contain millisecond precision: " + lastUpdated);
        }
    }

    @Test
    void identityBucketsAlwaysReturnMilliseconds(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();

        // SaltEntry with a lastUpdated that has 0 milliseconds
        long lastUpdatedMillis = Instant.parse("2024-01-01T00:00:00Z").toEpochMilli();
        SaltEntry bucketEntry = new SaltEntry(456, "hashed456", lastUpdatedMillis, "salt456", 1000L, null, null, null);
        when(saltProviderSnapshot.getModifiedSince(any())).thenReturn(List.of(bucketEntry));

        String sinceTimestamp = "2023-12-31T00:00:00"; // earlier timestamp

        JsonObject req = new JsonObject().put("since_timestamp", sinceTimestamp);

        send(vertx, "v2/identity/buckets", req, 200, respJson -> {
            JsonArray buckets = respJson.getJsonArray("body");
            assertFalse(buckets.isEmpty());
            assertLastUpdatedHasMillis(buckets);
            testContext.completeNow();
        });
    }
}
