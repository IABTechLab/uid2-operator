package com.uid2.operator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.operator.model.*;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.userIdentity.FirstLevelHashIdentity;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.service.*;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.operator.util.Tuple;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.Utils;
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
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.LoggerFactory;
import static org.assertj.core.api.Assertions.*;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.URLEncoder;
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
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class UIDOperatorVerticleTest {
    private final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    private static final Instant legacyClientCreationDateTime = Instant.ofEpochSecond(OPT_OUT_CHECK_CUTOFF_DATE).minus(1, ChronoUnit.SECONDS);
    private static final Instant newClientCreationDateTime = Instant.ofEpochSecond(OPT_OUT_CHECK_CUTOFF_DATE).plus(1, ChronoUnit.SECONDS);
    private static final String firstLevelSalt = "first-level-salt";
    private static final SaltEntry rotatingSalt123 = new SaltEntry(123, "hashed123", 0, "salt123");
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

    private AutoCloseable mocks;
    @Mock private ISiteStore siteProvider;
    @Mock private IClientKeyProvider clientKeyProvider;
    @Mock private IClientSideKeypairStore clientSideKeypairProvider;
    @Mock private IClientSideKeypairStore.IClientSideKeypairStoreSnapshot clientSideKeypairSnapshot;
    @Mock private IKeysetKeyStore keysetKeyStore;
    @Mock private RotatingKeysetProvider keysetProvider;
    @Mock private ISaltProvider saltProvider;
    @Mock private SecureLinkValidatorService secureLinkValidatorService;
    @Mock private ISaltProvider.ISaltSnapshot saltProviderSnapshot;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    @Mock private IStatsCollectorQueue statsCollectorQueue;
    @Mock private OperatorShutdownHandler shutdownHandler;

    private SimpleMeterRegistry registry;
    private ExtendedUIDOperatorVerticle uidOperatorVerticle;
    private final JsonObject config = new JsonObject();

    @BeforeEach
    public void deployVerticle(Vertx vertx, VertxTestContext testContext, TestInfo testInfo) {
        mocks = MockitoAnnotations.openMocks(this);
        when(saltProvider.getSnapshot(any())).thenReturn(saltProviderSnapshot);
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().plus(1, ChronoUnit.HOURS));
        when(clock.instant()).thenAnswer(i -> now);
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(true);

        setupConfig(config);
        if(testInfo.getDisplayName().equals("cstgNoPhoneSupport(Vertx, VertxTestContext)")) {
            config.put("enable_phone_support", false);
        }

        this.uidOperatorVerticle = new ExtendedUIDOperatorVerticle(config, config.getBoolean("client_side_token_generate"), siteProvider, clientKeyProvider, clientSideKeypairProvider, new KeyManager(keysetKeyStore, keysetProvider), saltProvider,  optOutStore, clock, statsCollectorQueue, secureLinkValidatorService, shutdownHandler::handleSaltRetrievalResponse);

        vertx.deployVerticle(uidOperatorVerticle, testContext.succeeding(id -> testContext.completeNow()));

        this.registry = new SimpleMeterRegistry();
        Metrics.globalRegistry.add(registry);
    }

    @AfterEach
    public void teardown() throws Exception {
        Metrics.globalRegistry.remove(registry);
        mocks.close();
    }

    private void setupConfig(JsonObject config) {
        config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, identityExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, refreshExpiresAfter.toMillis() / 1000);
        config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, refreshIdentityAfter.toMillis() / 1000);

        config.put(Const.Config.FailureShutdownWaitHoursProp, 24);
        config.put(Const.Config.SharingTokenExpiryProp, 60 * 60 * 24 * 30);

        config.put("identity_scope", getIdentityScope().toString());
        config.put("advertising_token_v3", getTokenVersion() == TokenVersion.V3);
        config.put("advertising_token_v4_percentage", getTokenVersion() == TokenVersion.V4 ? 100 : 0);
        config.put("site_ids_using_v4_tokens", "");
        config.put("identity_v3", useIdentityV3());
        config.put("client_side_token_generate", true);
        config.put("key_sharing_endpoint_provide_app_names", true);
        config.put("client_side_token_generate_log_invalid_http_origins", true);

        config.put(Const.Config.AllowClockSkewSecondsProp, 3600);
        config.put(Const.Config.OptOutStatusApiEnabled, true);
        config.put(Const.Config.OptOutStatusMaxRequestSize, optOutStatusMaxRequestSize);
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

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
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

            long nonce = new BigInteger(Random.getBytes(8)).longValue();

            postV2(ck, vertx, endpoint, postPayload, nonce, null, ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());

                if (ar.result().statusCode() == 200) {
                    byte[] decrypted = AesGcm.decrypt(Utils.decodeBase64String(ar.result().bodyAsString()), 0, ck.getSecretBytes());
                    assertArrayEquals(Buffer.buffer().appendLong(nonce).getBytes(), Buffer.buffer(decrypted).slice(8, 16).getBytes());

                    JsonObject respJson = new JsonObject(new String(decrypted, 16, decrypted.length - 16, StandardCharsets.UTF_8));

                    handler.handle(respJson);
                } else {
                    handler.handle(tryParseResponse(ar.result()));
                }
            });
        } else if (isV1Get) {
            get(vertx, endpoint + (v1GetParam != null ? "?" + v1GetParam : ""), ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            });
        } else {
            post(vertx, endpoint, postPayload, ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            });
        }
    }

    protected void sendTokenGenerate(String apiVersion, Vertx vertx, String v1GetParam, JsonObject v2PostPayload, int expectedHttpCode,
                                     Handler<JsonObject> handler) {
        sendTokenGenerate(apiVersion, vertx, v1GetParam, v2PostPayload, expectedHttpCode, null, handler, true);
    }

    protected void sendTokenGenerate(String apiVersion, Vertx vertx, String v1GetParam, JsonObject v2PostPayload, int expectedHttpCode,
                                     Handler<JsonObject> handler, boolean additionalParams) {
        sendTokenGenerate(apiVersion, vertx, v1GetParam, v2PostPayload, expectedHttpCode, null, handler, additionalParams);
    }

    private void sendTokenGenerate(String apiVersion, Vertx vertx, String v1GetParam, JsonObject v2PostPayload, int expectedHttpCode, String referer, Handler<JsonObject> handler, boolean additionalParams) {
        sendTokenGenerate(apiVersion, vertx, v1GetParam, v2PostPayload, expectedHttpCode, referer, handler, additionalParams, null, null);
    }

    private void sendTokenGenerate(String apiVersion, Vertx vertx, String v1GetParam, JsonObject v2PostPayload, int expectedHttpCode, String referer, Handler<JsonObject> handler, boolean additionalParams, String headerName, String headerValue) {
        if (apiVersion.equals("v2")) {
            ClientKey ck = (ClientKey) clientKeyProvider.get("");

            long nonce = new BigInteger(Random.getBytes(8)).longValue();

            if(additionalParams) {
                addAdditionalTokenGenerateParams(v2PostPayload);
            }

            postV2(ck, vertx, apiVersion + "/token/generate", v2PostPayload, nonce, referer, ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());

                if (ar.result().statusCode() == 200) {
                    byte[] decrypted = AesGcm.decrypt(Utils.decodeBase64String(ar.result().bodyAsString()), 0, ck.getSecretBytes());

                    assertArrayEquals(Buffer.buffer().appendLong(nonce).getBytes(), Buffer.buffer(decrypted).slice(8, 16).getBytes());

                    JsonObject respJson = new JsonObject(new String(decrypted, 16, decrypted.length - 16, StandardCharsets.UTF_8));

                    decodeV2RefreshToken(respJson);

                    handler.handle(respJson);
                } else {
                    handler.handle(tryParseResponse(ar.result()));
                }
            }, headerName, headerValue);
        } else {
            get(vertx, apiVersion + "/token/generate" + (v1GetParam != null ? "?" + v1GetParam : ""), ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            }, headerName, headerValue);
        }
    }

    private void sendTokenRefresh(String apiVersion, Vertx vertx, VertxTestContext testContext, String refreshToken, String v2RefreshDecryptSecret, int expectedHttpCode,
                                  Handler<JsonObject> handler) {
        sendTokenRefresh(apiVersion, vertx, null, null, testContext, refreshToken, v2RefreshDecryptSecret, expectedHttpCode, handler);
    }

    private void sendTokenRefresh(String apiVersion, Vertx vertx, String headerName, String headerValue, VertxTestContext testContext, String refreshToken, String v2RefreshDecryptSecret, int expectedHttpCode,
                                  Handler<JsonObject> handler) {
        if (apiVersion.equals("v2")) {
            WebClient client = WebClient.create(vertx);
            HttpRequest<Buffer> refreshHttpRequest = client.postAbs(getUrlForEndpoint("v2/token/refresh"));
            if (headerName != null) {
                refreshHttpRequest.putHeader(headerName, headerValue);
            }
            refreshHttpRequest
                    .putHeader("content-type", "text/plain")
                    .sendBuffer(Buffer.buffer(refreshToken.getBytes(StandardCharsets.UTF_8)), testContext.succeeding(response -> testContext.verify(() -> {
                        assertEquals(expectedHttpCode, response.statusCode());

                        if (response.statusCode() == 200 && v2RefreshDecryptSecret != null) {
                            byte[] decrypted = AesGcm.decrypt(Utils.decodeBase64String(response.bodyAsString()), 0, Utils.decodeBase64String(v2RefreshDecryptSecret));
                            JsonObject respJson = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));

                            if (respJson.getString("status").equals("success"))
                                decodeV2RefreshToken(respJson);

                            handler.handle(respJson);
                        } else {
                            handler.handle(tryParseResponse(response));
                        }
                    })));
        } else {
            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), testContext.succeeding(response -> testContext.verify(() -> {
                assertEquals(expectedHttpCode, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                handler.handle(json);
            })), headerName, headerValue);
        }
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

    private void get(Vertx vertx, String endpoint, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        ClientKey ck = clientKeyProvider.getClientKey("");
        HttpRequest<Buffer> req = client.getAbs(getUrlForEndpoint(endpoint));
        if (ck != null)
            req.putHeader("Authorization", "Bearer " + clientKey);
        req.send(handler);
    }

    private void get(Vertx vertx, String endpoint, Handler<AsyncResult<HttpResponse<Buffer>>> handler, String headerName, String headerValue) {
        WebClient client = WebClient.create(vertx);
        ClientKey ck = clientKeyProvider.getClientKey("");
        HttpRequest<Buffer> req = client.getAbs(getUrlForEndpoint(endpoint));
        if (ck != null) {
            req.putHeader("Authorization", "Bearer " + clientKey);
        }
        if (headerName != null) {
            req.putHeader(headerName, headerValue);
        }
        req.send(handler);
    }

    private void post(Vertx vertx, String endpoint, JsonObject body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        ClientKey ck = clientKeyProvider.getClientKey("");
        HttpRequest<Buffer> req = client.postAbs(getUrlForEndpoint(endpoint));
        if (ck != null)
            req.putHeader("Authorization", "Bearer " + clientKey);
        req.sendJsonObject(body, handler);
    }

    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, String referer, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        postV2(ck, vertx, endpoint, body, nonce, referer, handler, null, null);
    }
    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, String referer, Handler<AsyncResult<HttpResponse<Buffer>>> handler, String headerName, String headerValue) {
        WebClient client = WebClient.create(vertx);

        Buffer b = Buffer.buffer();
        b.appendLong(now.toEpochMilli());
        b.appendLong(nonce);

        if (body != null)
            b.appendBytes(body.encode().getBytes(StandardCharsets.UTF_8));

        Buffer bufBody = Buffer.buffer();
        bufBody.appendByte((byte) 1);
        if (ck != null) {
            bufBody.appendBytes(AesGcm.encrypt(b.getBytes(), ck.getSecretBytes()));
        }

        final String apiKey = ck == null ? "" : clientKey;
        HttpRequest<Buffer> request = client.postAbs(getUrlForEndpoint(endpoint))
                .putHeader("Authorization", "Bearer " + apiKey)
                .putHeader("content-type", "text/plain");
        if (headerName != null) {
            request.putHeader(headerName, headerValue);
        }

        if (referer != null) {
            request.putHeader("Referer", referer);
        }
        request.sendBuffer(Buffer.buffer(Utils.toBase64String(bufBody.getBytes()).getBytes(StandardCharsets.UTF_8)), handler);
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

        private String path;

        KeyDownloadEndpoint(String path) {
            this.path = path;
        }

        public String getPath() {
            return this.path;
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

    protected void setupSalts() {
        when(saltProviderSnapshot.getFirstLevelSalt()).thenReturn(firstLevelSalt);
        when(saltProviderSnapshot.getRotatingSalt(any())).thenReturn(rotatingSalt123);
    }

    private HashMap<Integer, Keyset> keysetsToMap(Keyset... keysets) {
        return new HashMap<>(Arrays.stream(keysets).collect(Collectors.toMap(Keyset::getKeysetId, s -> s)));
    }

    private void setupKeysetsMock(Keyset... keysets) {
        setupKeysetsMock(keysetsToMap(keysets));
    }

    private void setupKeysetsMock(Map<Integer, Keyset> keysets) {
        KeysetSnapshot keysetSnapshot = new KeysetSnapshot(keysets);
        when(keysetProvider.getSnapshot(any())).thenReturn(keysetSnapshot); //note that this getSnapshot() overload should be removed; it ignores the argument passed in
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
        if(expired) {
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

    private void generateTokens(String apiVersion, Vertx vertx, String inputType, String input, Handler<JsonObject> handler) {
        generateTokens(apiVersion, vertx, inputType, input,  handler, null, null);
    }

    private void generateTokens(String apiVersion, Vertx vertx, String inputType, String input, Handler<JsonObject> handler, String headerName, String headerValue) {
        String v1Param = inputType + "=" + urlEncode(input);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put(inputType, input);
        sendTokenGenerate(apiVersion, vertx, v1Param, v2Payload, 200, null, handler, true, headerName, headerValue);
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

    private byte[] getRawUidFromIdentity(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUid(identityType, identityString, firstLevelSalt, rotatingSalt, getIdentityScope(), useIdentityV3());
    }

    private static byte[] getRawUid(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt, IdentityScope identityScope, boolean useIdentityV3) {
        return !useIdentityV3
                ? TokenUtils.getRawUidV2FromIdentity(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getRawUidV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt);
    }

    public static byte[] getRawUid(IdentityType identityType, String identityString, IdentityScope identityScope, boolean useIdentityV3) {
        return !useIdentityV3
                ? TokenUtils.getRawUidV2FromIdentity(identityString, firstLevelSalt, rotatingSalt123.getSalt())
                : TokenUtils.getRawUidV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt123.getSalt());
    }

    private byte[] getRawUidFromIdentityHash(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return !useIdentityV3()
                ? TokenUtils.getRawUidV2FromIdentityHash(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getRawUidV3FromIdentityHash(getIdentityScope(), identityType, identityString, firstLevelSalt, rotatingSalt);
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

    protected TokenVersion getTokenVersion() {return TokenVersion.V2;}

    final boolean useIdentityV3() { return getTokenVersion() != TokenVersion.V2; }
    protected IdentityScope getIdentityScope() { return IdentityScope.UID2; }
    protected void addAdditionalTokenGenerateParams(JsonObject payload) {}

    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
        testContext.completeNow();
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestNoAcl(String apiVersion, Vertx vertx, VertxTestContext testContext) {
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
        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson, encryptionKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestWithAcl(String apiVersion, Vertx vertx, VertxTestContext testContext) {
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
        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson, expectedKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestClientBelongsToReservedSiteId(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(AdvertisingTokenSiteId, Role.ID_READER);
        KeysetKey[] encryptionKeys = {
                new KeysetKey(101, "key101".getBytes(), now, now, now.plusSeconds(10), 201),
                new KeysetKey(102, "key102".getBytes(), now, now, now.plusSeconds(10), 202),
        };
        setupKeysetsKeysMock(encryptionKeys);
        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 401, respJson -> testContext.completeNow());
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void keyLatestHideRefreshKey(String apiVersion, Vertx vertx, VertxTestContext testContext) {
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
        send(apiVersion, vertx, apiVersion + "/key/latest", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysResponse(respJson,
                    Arrays.stream(encryptionKeys).filter(k -> k.getKeysetId() != RefreshKeysetId).toArray(KeysetKey[]::new));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateBothEmailAndHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        final String emailHash = TokenUtils.getIdentityHashString(emailAddress);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "email=" + emailAddress + "&email_hash=" + urlEncode(emailHash);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        v2Payload.put("email_hash", emailHash);

        sendTokenGenerate(apiVersion, vertx,
                v1Param, v2Payload, 400,
                json -> {
                    assertFalse(json.containsKey("body"));

                    assertEquals("client_error", json.getString("status"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateNoEmailOrHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        sendTokenGenerate(apiVersion, vertx,
                "", null, 400,
                json -> {
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

    private AdvertisingTokenInput validateAndGetToken(EncryptedTokenEncoder encoder, JsonObject body, IdentityType identityType) { //See UID2-79+Token+and+ID+format+v3
        final String advertisingTokenString = body.getString("advertising_token");
        validateAdvertisingToken(advertisingTokenString, getTokenVersion(), getIdentityScope(), identityType);
        AdvertisingTokenInput advertisingTokenInput = encoder.decodeAdvertisingToken(advertisingTokenString);
        if (getTokenVersion() == TokenVersion.V4) {
            assertEquals(identityType, advertisingTokenInput.rawUidIdentity.identityType);
        }
        return advertisingTokenInput;
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

    RefreshTokenInput decodeRefreshToken(EncryptedTokenEncoder encoder, String refreshTokenString, IdentityType identityType) {
        RefreshTokenInput refreshTokenInput = encoder.decodeRefreshToken(refreshTokenString);
        assertEquals(getIdentityScope(), refreshTokenInput.firstLevelHashIdentity.identityScope);
        assertEquals(identityType, refreshTokenInput.firstLevelHashIdentity.identityType);
        return refreshTokenInput;
    }
    RefreshTokenInput decodeRefreshToken(EncryptedTokenEncoder encoder, String refreshTokenString) {
        return decodeRefreshToken(encoder, refreshTokenString, IdentityType.Email);
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapNewClientNoPolicySpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
            .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertFalse(respJson.containsKey("client_error"));
            JsonArray unmappedArr = respJson.getJsonObject("body").getJsonArray("unmapped");
            Assertions.assertEquals(1, unmappedArr.size());
            Assertions.assertEquals(emails.getString(0), unmappedArr.getJsonObject(0).getString("identifier"));
            Assertions.assertEquals("optout", unmappedArr.getJsonObject(0).getString("reason"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @MethodSource("versionAndPolicy")
    void identityMapNewClientWrongPolicySpecified(String apiVersion, String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();
        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
            .thenReturn(now.minus(1, ChronoUnit.HOURS));
        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);
        req.put(policyParameterKey, OptoutCheckPolicy.DoNotRespect.policy);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, respJson -> {
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

        send("v2", vertx, "v2/identity/map", false, null, req, 200, respJson -> {
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

        send("v2", vertx, "v2/identity/map", false, null, req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertEquals("success", respJson.getString("status"));
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 400,
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 400,
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 200,
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 200,
                json -> {
                    assertTrue(json.containsKey("body"));
                    assertEquals("success", json.getString("status"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest // TODO: remove test after optout check phase 3
    @CsvSource({"policy,someoptout@example.com,Email",
            "policy,+01234567890,Phone",
            "optout_check,someoptout@example.com,Email",
            "optout_check,+01234567890,Phone"})
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 200,
                json -> {
                    InputUtil.InputVal optOutTokenInput = identityType == IdentityType.Email ?
                            InputUtil.InputVal.validEmail(OptOutTokenIdentityForEmail, OptOutTokenIdentityForEmail) :
                            InputUtil.InputVal.validPhone(OptOutIdentityForPhone, OptOutTokenIdentityForPhone);

                    assertEquals("success", json.getString("status"));

                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);

                    decodeV2RefreshToken(json);

                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, identityType);
                    RefreshTokenInput refreshTokenInput = encoder.decodeRefreshToken(body.getString("decrypted_refresh_token"));
                    final byte[] rawUid = getRawUidFromIdentity(identityType,
                            optOutTokenInput.getNormalized(),
                            firstLevelSalt,
                            rotatingSalt123.getSalt());
                    final byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity(optOutTokenInput.getNormalized(), firstLevelSalt);
                    assertArrayEquals(rawUid, advertisingTokenInput.rawUidIdentity.rawUid);
                    assertArrayEquals(firstLevelHash, refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                    String advertisingTokenString = body.getString("advertising_token");
                    final Instant now = Instant.now();
                    final String token = advertisingTokenString;
                    final boolean matchedOptedOutIdentity = this.uidOperatorVerticle.getIdService().advertisingTokenMatches(token, optOutTokenInput.toHashedDiiIdentity(getIdentityScope()), now);
                    assertTrue(matchedOptedOutIdentity);
                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                    assertTrue(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());

                    assertTokenStatusMetrics(
                            201,
                            TokenResponseStatsCollector.Endpoint.GenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success,
                            TokenResponseStatsCollector.PlatformType.Other);

                    sendTokenRefresh("v2", vertx, ClientVersionHeader, tvosClientVersionHeaderValue, testContext, body.getString("refresh_token"), body.getString("refresh_response_key"), 200, refreshRespJson ->
                    {
                        assertEquals("optout", refreshRespJson.getString("status"));
                        JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                        assertNull(refreshBody);
                        assertTokenStatusMetrics(
                                201,
                                TokenResponseStatsCollector.Endpoint.RefreshV2,
                                TokenResponseStatsCollector.ResponseStatus.OptOut,
                                TokenResponseStatsCollector.PlatformType.InApp);
                        testContext.completeNow();
                    });
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateForEmail(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(apiVersion, vertx,
                v1Param, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(getRawUidFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                    RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
                    assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    assertStatsCollector("/" + apiVersion + "/token/generate", null, "test-contact", clientSiteId);

                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateForEmailHash(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "email_hash=" + urlEncode(emailHash);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email_hash", emailHash);

        sendTokenGenerate(apiVersion, vertx,
                v1Param, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(getRawUidFromIdentityHash(IdentityType.Email, emailHash, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                    RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, apiVersion.equals("v2") ? body.getString("decrypted_refresh_token") : body.getString("refresh_token"));
                    assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(emailHash, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenRefresh(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            sendTokenRefresh(apiVersion,  vertx, ClientVersionHeader, iosClientVersionHeaderValue, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson ->
            {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, refreshBody, IdentityType.Email);

                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                assertArrayEquals(getRawUidFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                String refreshTokenStringNew = refreshBody.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, refreshTokenStringNew);
                assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.GenerateV1 : TokenResponseStatsCollector.Endpoint.GenerateV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);
                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);

                testContext.completeNow();
            });
        }, ClientVersionHeader, iosClientVersionHeaderValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenRefreshSaltsExpired(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            sendTokenRefresh(apiVersion, vertx, ClientVersionHeader, androidClientVersionHeaderValue, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson ->
            {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, refreshBody, IdentityType.Email);

                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                assertArrayEquals(getRawUidFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                String refreshTokenStringNew = refreshBody.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, refreshTokenStringNew);
                assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.GenerateV1 : TokenResponseStatsCollector.Endpoint.GenerateV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);
                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.Success,
                        TokenResponseStatsCollector.PlatformType.InApp);

                verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                testContext.completeNow();
            });
        }, ClientVersionHeader, androidClientVersionHeaderValue);
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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 200,
                genRespJson -> {
                    assertEquals("success", genRespJson.getString("status"));
                    JsonObject bodyJson = genRespJson.getJsonObject("body");
                    assertNotNull(bodyJson);

                    String genRefreshToken = bodyJson.getString("refresh_token");

                    setupKeys(true);
                    sendTokenRefresh("v2", vertx, ClientVersionHeader, androidClientVersionHeaderValue, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 500, refreshRespJson ->
                    {
                        assertFalse(refreshRespJson.containsKey("body"));
                        assertEquals("No active encryption key available", refreshRespJson.getString("message"));
                        testContext.completeNow();
                    });
                });
    }


    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithEmail_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&email=" + emailAddress;
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email", emailAddress);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithEmailHash_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", ValidateIdentityForEmail, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(ValidateIdentityForEmailHash));
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email_hash", EncodingUtils.toBase64String(ValidateIdentityForEmailHash));

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithBothEmailAndEmailHash(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&email=" + emailAddress + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(ValidateIdentityForEmailHash));
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email", emailAddress);
            v2Payload.put("email_hash", emailAddress);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 400, json -> {
                assertFalse(json.containsKey("body"));
                assertEquals("client_error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateUsingCustomSiteKey(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 4;
        final int clientKeysetId = 201;
        final int siteKeyId = 1201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        setupSiteKey(clientSiteId, siteKeyId, clientKeysetId);

        String v1Param = "email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(apiVersion, vertx, v1Param, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

            AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Email);
            assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
            assertArrayEquals(getRawUidFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

            RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
            assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateSaltsExpired(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(apiVersion, vertx,
                v1Param, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(getRawUidFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                    RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
                    assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                    assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
                    assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

                    assertStatsCollector("/" + apiVersion + "/token/generate", null, "test-contact", clientSiteId);

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

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 500,
                json -> {
                    assertFalse(json.containsKey("body"));
                    assertEquals("No active encryption key available", json.getString("message"));
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshNoToken(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        sendTokenRefresh(apiVersion, vertx, null, null, testContext, "", "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken,
                    TokenResponseStatsCollector.PlatformType.Other);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @CsvSource({"v1,asdf", "v2,asdf", "v1,invalidBase64%%%%", "v2,invalidBase64%%%%"})
    void tokenRefreshInvalidTokenAuthenticated(String apiVersion, String token, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);

        sendTokenRefresh(apiVersion, vertx, ORIGIN_HEADER, "example.com", testContext, token, "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken,
                    TokenResponseStatsCollector.PlatformType.HasOriginHeader);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshInvalidTokenUnauthenticated(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        sendTokenRefresh(apiVersion, vertx, null, null, testContext, "abcd", "", 400, json -> {
            assertEquals("error", json.getString("status"));
            testContext.completeNow();
        });
    }

    private void generateRefreshToken(String apiVersion, Vertx vertx, String identityType, String identity, int siteId, Handler<JsonObject> handler) {
        fakeAuth(siteId, Role.GENERATOR);
        setupSalts();
        setupKeys();
        generateTokens(apiVersion, vertx, identityType, identity, handler);
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void captureDurationsBetweenRefresh(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusSeconds(300));

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                assertEquals(300, Metrics.globalRegistry
                        .get("uid2.token_refresh_duration_seconds")
                        .tag("api_contact", "test-contact")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .summary().mean());

                assertEquals(1, Metrics.globalRegistry
                        .get("uid2.advertising_token_expired_on_refresh")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .tag("is_expired", "false")
                        .counter().count());

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void captureExpiredAdvertisingTokenStatus(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusSeconds(identityExpiresAfter.toSeconds() + 1));

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));

                assertEquals(1, Metrics.globalRegistry
                        .get("uid2.advertising_token_expired_on_refresh")
                        .tag("site_id", String.valueOf(clientSiteId))
                        .tag("is_expired", "true")
                        .counter().count());

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshExpiredTokenAuthenticated(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            when(clock.instant()).thenAnswer(i -> now.plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 400, refreshRespJson -> {
                assertEquals("expired_token", refreshRespJson.getString("status"));
                assertNotNull(Metrics.globalRegistry
                        .get("uid2_refresh_token_received_count").counter());
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshExpiredTokenUnauthenticated(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";

        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            String refreshToken = genRespJson.getJsonObject("body").getString("refresh_token");
            clearAuth();
            when(clock.instant()).thenAnswer(i -> now.plusMillis(refreshExpiresAfter.toMillis()).plusSeconds(60));

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, "", 400, refreshRespJson -> {
                assertEquals("error", refreshRespJson.getString("status"));
                assertNotNull(Metrics.globalRegistry
                        .get("uid2_refresh_token_received_count").counter());
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshOptOut(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("optout", refreshRespJson.getString("status"));
                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.OptOut,
                        TokenResponseStatsCollector.PlatformType.Other);
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshOptOutBeforeLogin(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        generateRefreshToken(apiVersion, vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");
            String refreshTokenDecryptSecret = bodyJson.getString("refresh_response_key");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(now.minusSeconds(10));

            sendTokenRefresh(apiVersion, vertx, testContext, refreshToken, refreshTokenDecryptSecret, 200, refreshRespJson -> {
                assertEquals("optout", refreshRespJson.getString("status"));
                assertNull(refreshRespJson.getJsonObject("body"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void v2HandleV1RefreshToken(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(201, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";

        generateRefreshToken("v1", vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            sendTokenRefresh("v2", vertx, testContext, refreshToken, null, 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));

                JsonObject refreshBodyJson = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBodyJson.getString("refresh_response_key"));

                decodeV2RefreshToken(refreshRespJson);

                testContext.completeNow();
            });
        });
    }

    @Test
    void v1HandleV2RefreshToken(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(201, Role.GENERATOR);
        final String emailAddress = "test@uid2.com";

        generateRefreshToken("v2", vertx, "email", emailAddress, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            sendTokenRefresh("v1", vertx, testContext, refreshToken, null, 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenValidateWithEmail_Mismatch(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = ValidateIdentityForEmail;
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
                "token=abcdef&email_hash=" + urlEncode(EncodingUtils.toBase64String(ValidateIdentityForEmailHash)),
                new JsonObject().put("token", "abcdef").put("email_hash", EncodingUtils.toBase64String(ValidateIdentityForEmailHash)),
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
            HttpResponse<Buffer> response = ar.result();
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
            HttpResponse<Buffer> response = ar.result();
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
            HttpResponse<Buffer> response = ar.result();
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
    void identityMapForSaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?email=" + emailAddress, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse<Buffer> response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            assertEquals(emailAddress, body.getString("identifier"));
            assertFalse(body.getString("advertising_id").isEmpty());
            assertFalse(body.getString("bucket_id").isEmpty());

            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

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
            HttpResponse<Buffer> response = ar.result();
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
    void identityMapSingleEmailProvided(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emailHashes = new JsonArray();
        req.put("email", "test@example.com");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("email must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapSingleEmailHashProvided(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emailHashes = new JsonArray();
        req.put("email_hash", "test@example.com");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("email_hash must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapSinglePhoneProvided(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emailHashes = new JsonArray();
        req.put("phone", "555-555-5555");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("phone must be an array", json.getString("message"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapSinglePhoneHashProvided(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emailHashes = new JsonArray();
        req.put("phone_hash", "555-555-5555");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));
            assertEquals("phone_hash must be an array", json.getString("message"));

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

        JsonObject req = createBatchEmailsRequestPayload();

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

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 413, json -> testContext.completeNow());
    }

    private static Stream<Arguments> optOutStatusRequestData() {
        List<String> rawUIDS = Arrays.asList("RUQbFozFwnmPVjDx8VMkk9vJoNXUJImKnz2h9RfzzM24",
            "qAmIGxqLk_RhOtm4f1nLlqYewqSma8fgvjEXYnQ3Jr0K",
            "r3wW2uvJkwmeFcbUwSeM6BIpGF8tX38wtPfVc4wYyo71",
            "e6SA-JVAXnvk8F1MUtzsMOyWuy5Xqe15rLAgqzSGiAbz");
        Map<String, Long> optedOutIdsCase1 = new HashMap<>();

        optedOutIdsCase1.put(rawUIDS.get(0), Instant.now().minus(1, ChronoUnit.DAYS).getEpochSecond());
        optedOutIdsCase1.put(rawUIDS.get(1), Instant.now().minus(2, ChronoUnit.DAYS).getEpochSecond());
        optedOutIdsCase1.put(rawUIDS.get(2), -1L);
        optedOutIdsCase1.put(rawUIDS.get(3), -1L);

        Map<String, Long> optedOutIdsCase2 = new HashMap<>();
        optedOutIdsCase2.put(rawUIDS.get(2), -1L);
        optedOutIdsCase2.put(rawUIDS.get(3), -1L);
        return Stream.of(
            Arguments.arguments(optedOutIdsCase1, 2, Role.MAPPER),
            Arguments.arguments(optedOutIdsCase1, 2, Role.ID_READER),
            Arguments.arguments(optedOutIdsCase1, 2, Role.SHARER),
            Arguments.arguments(optedOutIdsCase2, 0, Role.MAPPER)
        );
    }

    @ParameterizedTest
    @MethodSource("optOutStatusRequestData")
    void optOutStatusRequest(Map<String, Long> optedOutIds, int optedOutCount, Role role, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(126, role);
        setupSalts();
        setupKeys();

        JsonArray rawUIDs = new JsonArray();
        for (String rawUID2 : optedOutIds.keySet()) {
            when(this.optOutStore.getOptOutTimestampByAdId(rawUID2)).thenReturn(optedOutIds.get(rawUID2));
            rawUIDs.add(rawUID2);
        }
        JsonObject requestJson = new JsonObject();
        requestJson.put("advertising_ids", rawUIDs);

        send("v2", vertx, "v2/optout/status", false, null, requestJson, 200, respJson -> {
            assertEquals("success", respJson.getString("status"));
            JsonArray optOutJsonArray = respJson.getJsonObject("body").getJsonArray("opted_out");
            assertEquals(optedOutCount, optOutJsonArray.size());
            for (int i = 0; i < optOutJsonArray.size(); ++i) {
                JsonObject optOutObject = optOutJsonArray.getJsonObject(i);
                String rawUid = optOutObject.getString("advertising_id");
                assertTrue(optedOutIds.containsKey(rawUid));
                long expectedTimestamp = Instant.ofEpochSecond(optedOutIds.get(rawUid)).toEpochMilli();
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

        send("v2", vertx, "v2/optout/status", false, null, requestJson, 400, respJson -> {
            assertEquals(com.uid2.shared.Const.ResponseStatus.ClientError, respJson.getString("status"));
            assertEquals(errorMsg, respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @Test
    void optOutStatusUnauthorized(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(126, Role.GENERATOR);
        setupSalts();
        setupKeys();

        send("v2", vertx, "v2/optout/status", false, null, new JsonObject(), 401, respJson -> {
            assertEquals(com.uid2.shared.Const.ResponseStatus.Unauthorized, respJson.getString("status"));
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
            assertEquals("success", respJson.getString("status"));
            assertEquals("OK", respJson.getJsonObject("body").getString("optout"));
            testContext.completeNow();
        });
    }

    @Test
    void LogoutV2SaltsExpired(Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
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
            assertEquals("success", respJson.getString("status"));
            assertEquals("OK", respJson.getJsonObject("body").getString("optout"));

            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateBothPhoneAndHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "phone=" + urlEncode(phone) + "&phone_hash=" + urlEncode(phoneHash);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);
        v2Payload.put("phone_hash", phoneHash);

        send(apiVersion, vertx, apiVersion + "/token/generate", true, v1Param, v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateBothPhoneAndEmailSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "phone=" + urlEncode(phone) + "&email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);
        v2Payload.put("email", emailAddress);

        send(apiVersion, vertx, apiVersion + "/token/generate", true, v1Param, v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateBothPhoneHashAndEmailHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        final String emailAddress = "test@uid2.com";
        final String emailHash = TokenUtils.getIdentityHashString(emailAddress);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "phone_hash=" + urlEncode(phoneHash) + "&email_hash=" + urlEncode(emailHash);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone_hash", phoneHash);
        v2Payload.put("email_hash", emailHash);

        send(apiVersion, vertx, apiVersion + "/token/generate", true, v1Param, v2Payload, 400, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateForPhone(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "phone=" + urlEncode(phone);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone", phone);

        sendTokenGenerate(apiVersion, vertx, v1Param, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

            AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
            assertArrayEquals(getRawUidFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

            RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"), IdentityType.Phone);
            assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

            assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateForPhoneHash(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        String v1Param = "phone_hash=" + urlEncode(phoneHash);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("phone_hash", phoneHash);

        sendTokenGenerate(apiVersion, vertx, v1Param, v2Payload, 200, json -> {
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);
            EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

            AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
            assertArrayEquals(getRawUidFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

            RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"), IdentityType.Phone);
            assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

            assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
            assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenRefreshForPhone(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            assertNotNull(bodyJson);

            String genRefreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

            sendTokenRefresh(apiVersion, vertx, testContext, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson ->
            {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, refreshBody, IdentityType.Phone);

                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingTokenInput.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                assertArrayEquals(getRawUidFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingTokenInput.rawUidIdentity.rawUid);

                String refreshTokenStringNew = refreshBody.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, refreshTokenStringNew, IdentityType.Phone);
                assertEquals(clientSiteId, refreshTokenInput.sourcePublisher.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshTokenInput.firstLevelHashIdentity.firstLevelHash);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithPhone_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&phone=" + urlEncode(phone);
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateSaltsExpired(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        when(saltProviderSnapshot.getExpires()).thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&phone=" + urlEncode(phone);
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithPhoneHash_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phoneHash = EncodingUtils.toBase64String(ValidateIdentityForPhoneHash);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", ValidateIdentityForPhone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&phone_hash=" + urlEncode(phoneHash);
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone_hash", phoneHash);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 200, json -> {
                assertTrue(json.getBoolean("body"));
                assertEquals("success", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithBothPhoneAndPhoneHash(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = ValidateIdentityForPhone;
        final String phoneHash = EncodingUtils.toBase64String(ValidateIdentityForEmailHash);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", phone, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&phone=" + urlEncode(phone) + "&phone_hash=" + urlEncode(phoneHash);
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("phone", phone);
            v2Payload.put("phone_hash", phoneHash);

            send(apiVersion, vertx, apiVersion + "/token/validate", true, v1Param, v2Payload, 400, json -> {
                assertFalse(json.containsKey("body"));
                assertEquals("client_error", json.getString("status"));

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshOptOutForPhone(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        generateRefreshToken(apiVersion, vertx, "phone", phone, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), testContext.succeeding(response -> testContext.verify(() -> {
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("optout", json.getString("status"));
                assertTokenStatusMetrics(clientSiteId, TokenResponseStatsCollector.Endpoint.RefreshV1, TokenResponseStatsCollector.ResponseStatus.OptOut, TokenResponseStatsCollector.PlatformType.Other);

                testContext.completeNow();
            })));
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshOptOutBeforeLoginForPhone(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        generateRefreshToken(apiVersion, vertx, "phone", phone, clientSiteId, genRespJson -> {
            JsonObject bodyJson = genRespJson.getJsonObject("body");
            String refreshToken = bodyJson.getString("refresh_token");

            when(this.optOutStore.getLatestEntry(any())).thenReturn(now.minusSeconds(10));

            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse<Buffer> response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("optout", json.getString("status"));
                assertNull(json.getJsonObject("body"));

                testContext.completeNow();
            });
        });
    }

    @Test
    void identityMapBothPhoneAndHashSpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phoneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?phone=" + urlEncode(phone) + "&phone_hash=" + urlEncode(phoneHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse<Buffer> response = ar.result();
            assertEquals(400, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertFalse(json.containsKey("body"));
            assertEquals("client_error", json.getString("status"));

            testContext.completeNow();
        });
    }

    @Test
    void identityMapForPhone(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?phone=" + urlEncode(phone), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse<Buffer> response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            assertEquals(phone, body.getString("identifier"));
            assertFalse(body.getString("advertising_id").isEmpty());
            assertFalse(body.getString("bucket_id").isEmpty());

            testContext.completeNow();
        });
    }

    @Test
    void identityMapForPhoneHash(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = "+15555555555";
        final String phonneHash = TokenUtils.getIdentityHashString(phone);
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();
        get(vertx, "v1/identity/map?phone_hash=" + urlEncode(phonneHash), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse<Buffer> response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            assertEquals("success", json.getString("status"));
            JsonObject body = json.getJsonObject("body");
            assertNotNull(body);

            assertEquals(phonneHash, body.getString("identifier"));
            assertFalse(body.getString("advertising_id").isEmpty());
            assertFalse(body.getString("bucket_id").isEmpty());

            testContext.completeNow();
        });
    }

    @Test
    void sendInformationToStatsCollector(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = "test@uid2.com";
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        vertx.eventBus().consumer(Const.Config.StatsCollectorEventBus, message -> {
            String expected = "{\"path\":\"/v1/token/generate\",\"referer\":null,\"apiContact\":null,\"siteId\":201}";
            assertSame(message.body().toString(), expected);
        });

        get(vertx, "v1/token/generate?email=" + emailAddress, ar -> {
            verify(statsCollectorQueue, times(1)).enqueue(any(), any());
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchBothPhoneAndHashEmpty(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        JsonArray phoneHashes = new JsonArray();
        req.put("phone", phones);
        req.put("phone_hash", phoneHashes);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, respJson -> {
            checkIdentityMapResponse(respJson);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchBothPhoneAndHashSpecified(String apiVersion, Vertx vertx, VertxTestContext testContext) {
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

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchPhones(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        phones.add("+15555555555");
        phones.add("+15555555556");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "+15555555555", "+15555555556");
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchPhoneHashes(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray hashes = new JsonArray();
        req.put("phone_hash", hashes);
        final String[] email_hashes = {
                TokenUtils.getIdentityHashString("+15555555555"),
                TokenUtils.getIdentityHashString("+15555555556"),
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
    void identityMapBatchPhonesOnePhoneInvalid(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        phones.add("+15555555555");
        phones.add("bogus");
        phones.add("+15555555556");

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "+15555555555", "+15555555556");
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchPhonesNoPhones(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray phones = new JsonArray();
        req.put("phone", phones);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapBatchRequestTooLargeForPhone(String apiVersion, Vertx vertx, VertxTestContext testContext) {
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

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 413, json -> testContext.completeNow());
    }
    @ParameterizedTest
    @ValueSource(strings = {"policy", "optout_check"})
    void tokenGenerateRespectOptOutOption(String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        req.put("email", "random-optout-user@email.io");
        req.put(policyParameterKey, 1);

        // for EUID
        addAdditionalTokenGenerateParams(req);

        send("v2", vertx, "v2/token/generate", false, null, req, 200, json -> {
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
    @ValueSource(strings = {"v1", "v2"})
    void identityMapDefaultOption(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
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

    private static Stream<Arguments> versionAndPolicy() {
        return Stream.of(
                Arguments.arguments("v1", "policy"),
                Arguments.arguments("v1", "optout_check"),
                Arguments.arguments("v2", "policy"),
                Arguments.arguments("v2", "optout_check")
        );
    }

    @ParameterizedTest
    @MethodSource("versionAndPolicy")
    void identityMapRespectOptOutOption(String apiVersion, String policyParameterKey, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);
        req.put(policyParameterKey, 1);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
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

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void requestWithoutClientKeyOrReferer(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final String emailAddress = "test@uid2.com";
        setupSalts();
        setupKeys();

        String v1Param = "email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate(apiVersion, vertx,
                v1Param, v2Payload, 401,
                json -> {
                    assertEquals("unauthorized", json.getString("status"));

                    assertStatsCollector("/" + apiVersion + "/token/generate", null, null, null);

                    testContext.completeNow();
                });
    }

    @Test
    void requestWithReferer(Vertx vertx, VertxTestContext testContext) {
        final String emailAddress = "test@uid2.com";
        setupSalts();
        setupKeys();

        String v1Param = "email=" + emailAddress;
        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);

        sendTokenGenerate("v2", vertx,
                v1Param, v2Payload, 401, "test-referer",
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

    private void setupCstgBackend(List<String> domainNames, List<String> appNames)
    {
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
            "http://local1host:8080", //intentionally spelling localhost wrong here!
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
            "com.",
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
            "http://gototest.com",
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
    @ValueSource(strings = { "badAppName" })
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
            "http://gototest.com",
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
            "http://localhost:8080",
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
                    var encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
                    validateAndGetToken(encoder, refreshBody, IdentityType.Email); //to validate token version is correct
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @CsvSource({
            "com.123.Game.App.android",
            "com.123.game.app.android",
            "123456789",
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
                    var encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
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
            .putHeader("Content-Type", "application/json")
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

    @Test
    void cstgBadPublicKey(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
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
        requestJson.put("public_key", "bad-key");
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
                    assertEquals("bad public key", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadPublicKey,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadSubscriptionId(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
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
        requestJson.put("subscription_id", "bad");

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                requestJson,
                secretKey,
                400,
                testContext,
                respJson -> {
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

        if(identityType == IdentityType.Email) {
            identity.put("email_hash", getSha256(rawId));
        }
        else if(identityType == IdentityType.Phone) {
            identity.put("phone_hash", getSha256(rawId));
        }
        else { //can't be other types
            assertFalse(true);
        }
        
        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp, appName);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequestWithNoPayload(long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {
        JsonObject identity = new JsonObject();
        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp, null);
    }


    @ParameterizedTest
    @CsvSource({
            "test@example.com,Email",
            "+61400000000,Phone"
    })
    void cstgUserOptsOutAfterTokenGenerate(String id, IdentityType identityType, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        final Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(identityType, id, Instant.now().toEpochMilli());

        // When we generate the token the user hasn't opted out.
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(null);

        final EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
        final ArgumentCaptor<FirstLevelHashIdentity> argumentCaptor = ArgumentCaptor.forClass(FirstLevelHashIdentity.class);

        sendCstg(vertx,
                "v2/token/client-generate",
                "https://cstg.co.uk",
                data.getItem1(),
                data.getItem2(),
                200,
                testContext,
                response -> {
                    verify(optOutStore, times(1)).getLatestEntry(argumentCaptor.capture());
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(id, firstLevelSalt),
                            argumentCaptor.getValue().firstLevelHash);

                    assertEquals("success", response.getString("status"));
                    final JsonObject genBody = response.getJsonObject("body");

                    final AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, genBody, identityType);
                    final RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, decodeV2RefreshToken(response), identityType);

                    assertAreClientSideGeneratedTokens(advertisingTokenInput, refreshTokenInput, clientSideTokenGenerateSiteId, identityType, id);

                    // When we refresh the token the user has opted out.
                    when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                        .thenReturn(advertisingTokenInput.establishedAt.plusSeconds(1));

                    sendTokenRefresh("v2", vertx, testContext, genBody.getString("refresh_token"), genBody.getString("refresh_response_key"), 200, refreshRespJson -> {
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
            "true,abc@abc.com,Email",
            "true,+61400000000,Phone",
            "false,abc@abc.com,Email",
            "false,+61400000000,Phone",
    })
    void cstgSuccessForBothOptedAndNonOptedOutTest(boolean optOutExpected, String id, IdentityType identityType,
                          Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(identityType, id, Instant.now().toEpochMilli());

        if(optOutExpected)
        {
            when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                    .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        }
        else { //not expectedOptedOut
            when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
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
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, genBody, identityType);

                    RefreshTokenInput refreshTokenInput = decodeRefreshToken(encoder, genBody.getString("decrypted_refresh_token"), identityType);

                    assertAreClientSideGeneratedTokens(advertisingTokenInput, refreshTokenInput, clientSideTokenGenerateSiteId, identityType, id);
                    assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("identity_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_from")), 10);

                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success,
                            TokenResponseStatsCollector.PlatformType.HasOriginHeader);

                    String genRefreshToken = genBody.getString("refresh_token");
                    //test a subsequent refresh from this cstg call and see if it still works
                    sendTokenRefresh("v2", vertx, testContext, genRefreshToken, genBody.getString("refresh_response_key"), 200, refreshRespJson ->
                    {
                        assertEquals("success", refreshRespJson.getString("status"));
                        JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                        assertNotNull(refreshBody);
                        EncryptedTokenEncoder encoder2 = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                        //make sure the new advertising token from refresh looks right
                        AdvertisingTokenInput adTokenFromRefresh = validateAndGetToken(encoder2, refreshBody, identityType);

                        String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                        assertNotEquals(genRefreshToken, refreshTokenStringNew);
                        RefreshTokenInput refreshTokenAfterRefreshSource = decodeRefreshToken(encoder, refreshTokenStringNew, identityType);

                        assertAreClientSideGeneratedTokens(adTokenFromRefresh, refreshTokenAfterRefreshSource, clientSideTokenGenerateSiteId, identityType, id);
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
            "http://localhost:8080",
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
                    var encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));
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
            "phone_hash,1234567890",
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

    private void assertAreClientSideGeneratedTokens(AdvertisingTokenInput advertisingTokenInput, RefreshTokenInput refreshTokenInput, int siteId, IdentityType identityType, String identity) {
        assertAreClientSideGeneratedTokens(advertisingTokenInput,
                refreshTokenInput,
                siteId,
                identityType,
                identity,
                false);
    }

    private void assertAreClientSideGeneratedTokens(AdvertisingTokenInput advertisingTokenInput, RefreshTokenInput refreshTokenInput, int siteId, IdentityType identityType, String identity, boolean expectedOptOut) {
        final PrivacyBits advertisingTokenPrivacyBits = PrivacyBits.fromInt(advertisingTokenInput.privacyBits);
        final PrivacyBits refreshTokenPrivacyBits = PrivacyBits.fromInt(refreshTokenInput.firstLevelHashIdentity.privacyBits);

        final byte[] rawUid = getRawUidFromIdentity(identityType,
                identity,
                firstLevelSalt,
                rotatingSalt123.getSalt());

        final byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity(identity, firstLevelSalt);

        assertAll(
                () -> assertTrue(advertisingTokenPrivacyBits.isClientSideTokenGenerated(), "Advertising token privacy bits CSTG flag is incorrect"),
                () -> assertEquals(expectedOptOut, advertisingTokenPrivacyBits.isClientSideTokenOptedOut(), "Advertising token privacy bits CSTG optout flag is incorrect"),

                () -> assertTrue(refreshTokenPrivacyBits.isClientSideTokenGenerated(), "Refresh token privacy bits CSTG flag is incorrect"),
                () -> assertEquals(expectedOptOut, refreshTokenPrivacyBits.isClientSideTokenOptedOut(), "Refresh token privacy bits CSTG optout flag is incorrect"),

                () -> assertEquals(siteId, advertisingTokenInput.sourcePublisher.siteId, "Advertising token site ID is incorrect"),
                () -> assertEquals(siteId, refreshTokenInput.sourcePublisher.siteId, "Refresh token site ID is incorrect"),

                () -> assertArrayEquals(rawUid, advertisingTokenInput.rawUidIdentity.rawUid, "Advertising token ID is incorrect"),
                () -> assertArrayEquals(firstLevelHash, refreshTokenInput.firstLevelHashIdentity.firstLevelHash, "Refresh token ID is incorrect")
        );
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

        String v1Param = "email_hash=" + urlEncode(emailHash);
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

        sendTokenGenerate("v2", vertx,
                v1Param, v2Payload, 200,
                json -> {
                    assertEquals("success", json.getString("status"));
                    JsonObject body = json.getJsonObject("body");
                    assertNotNull(body);
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingTokenInput advertisingTokenInput = validateAndGetToken(encoder, body, IdentityType.Email);
                    assertEquals(clientSiteId, advertisingTokenInput.sourcePublisher.siteId);
                    //Uses a key from default keyset
                    int clientKeyId;
                    if (advertisingTokenInput.version == TokenVersion.V3 || advertisingTokenInput.version == TokenVersion.V4) {
                        String advertisingTokenString = body.getString("advertising_token");
                        byte[] bytes = null;
                        if (advertisingTokenInput.version == TokenVersion.V3) {
                            bytes = EncodingUtils.fromBase64(advertisingTokenString);
                        } else if (advertisingTokenInput.version == TokenVersion.V4) {
                            bytes = Uid2Base64UrlCoder.decode(advertisingTokenString);  //same as V3 but use Base64URL encoding
                        }
                        final Buffer b = Buffer.buffer(bytes);
                        final int masterKeyId = b.getInt(2);

                        final byte[] masterPayloadBytes = AesGcm.decrypt(bytes, 6, keysetKeyStore.getSnapshot().getKey(masterKeyId));
                        final Buffer masterPayload = Buffer.buffer(masterPayloadBytes);
                        clientKeyId = masterPayload.getInt(29);
                    } else {
                        clientKeyId = advertisingTokenInput.sourcePublisher.clientKeyId;
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

    @Test
    void keySharingKeysets_CorrectFiltering(Vertx vertx, VertxTestContext testContext) {
        //Call should return
        // all keys they have access in ACL
        // The master key -1
        //Call Should not return
        // The master key -2
        // The publisher General 2
        // Any other key without an ACL
        String apiVersion = "v2";
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

        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, siteId, expectedKeys);
            testContext.completeNow();
        });
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
        for(int siteId : siteIds) {
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

    static Map<Integer, Site> setupExpectation(boolean includeDomainNames, boolean includeAppNames, int... siteIds)
    {
        Map<Integer, Site> expectedSites = new HashMap<>();
        for (int siteId : siteIds)
        {
            if (includeDomainNames || includeAppNames) {
                expectedSites.put(siteId, defaultMockSite(siteId, includeDomainNames, includeAppNames));
            }
        }
        return expectedSites;
    }


    public void verifyExpectedSiteDetail(Map<Integer, Site> expectedSites, JsonArray actualResult) {

        assertEquals(expectedSites.size(), actualResult.size());
        for(int i = 0; i < actualResult.size(); i++) {

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
            final String apiVersion = "v2";
            final KeyDownloadEndpoint endpoint = KeyDownloadEndpoint.BIDSTREAM;

            final int clientSiteId = 101;
            fakeAuth(clientSiteId, Role.ID_READER);

            // Required, sets up mock keys.
            new MultipleKeysetsTests();

            send(apiVersion, vertx, apiVersion + endpoint.getPath(), true, null, null, 200, respJson -> {
                assertEquals("success", respJson.getString("status"));

                checkKeyDownloadResponseHeaderFields(endpoint, respJson.getJsonObject("body"), clientSiteId);

                testContext.completeNow();
            });
        }
    }


    private static Stream<Arguments> testKeyDownloadEndpointKeysetsData_IDREADER() {
        int[] expectedSiteIds = new int [] {101, 102};
        int[] allMockedSiteIds = new int [] {101, 102, 103, 105};
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
        String apiVersion = "v2";
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
        send(apiVersion, vertx, apiVersion + endpoint.getPath(), true, null, null, 200, respJson -> {
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
        this.uidOperatorVerticle.setMaxSharingLifetimeSeconds(999999);
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
        String apiVersion = "v2";
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
        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
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
        String apiVersion = "v2";
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
        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            verifyExpectedSiteDetail(new HashMap<>(), respJson.getJsonObject("body").getJsonArray("site_data"));
            checkEncryptionKeys(respJson, KeyDownloadEndpoint.SHARING, siteId, encryptionKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"NoKeyset", "NoKey", "SharedKey"})
    void keySharingKeysets_CorrectIDS(String testRun, Vertx vertx, VertxTestContext testContext) {
        String apiVersion = "v2";
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

        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
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
                    Map<Integer, Site> expectedSites = setupExpectation(true, false,13);
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
        String apiVersion = "v2";
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
        send(apiVersion, vertx, apiVersion + endpoint.getPath(), true, null, null, 200, respJson -> {
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
        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(true);

        send("v2", vertx, "v2" + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @Test
    void secureLinkValidationFailsReturnsIdentityError(Vertx vertx, VertxTestContext testContext) {
        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class), any(Role.class))).thenReturn(false);

        send("v2", vertx, "v2" + "/identity/map", false, null, req, 401, json -> {
            assertEquals("unauthorized", json.getString("status"));
            assertEquals("Invalid link_id", json.getString("message"));
            testContext.completeNow();
        });
    }
}
