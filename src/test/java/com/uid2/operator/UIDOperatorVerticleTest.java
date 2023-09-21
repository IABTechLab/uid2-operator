package com.uid2.operator;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.*;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.service.*;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.operator.util.Tuple;
import com.uid2.operator.vertx.OperatorDisableHandler;
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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

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

import static com.uid2.operator.ClientSideTokenGenerateTestUtil.decrypt;
import static com.uid2.operator.service.EncodingUtils.getSha256;
import static com.uid2.operator.service.V2RequestUtil.V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES;
import static com.uid2.operator.vertx.UIDOperatorVerticle.OPT_OUT_CHECK_CUTOFF_DATE;
import static com.uid2.shared.Const.Data.*;
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
    private static final byte[] clientSecret = Random.getRandomKeyBytes();
    private static final String clientSideTokenGenerateSubscriptionId = "4WvryDGbR5";
    private static final String clientSideTokenGeneratePublicKey = "UID2-X-L-MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsziOqRXZ7II0uJusaMxxCxlxgj8el/MUYLFMtWfB71Q3G1juyrAnzyqruNiPPnIuTETfFOridglP9UQNlwzNQg==";
    private static final String clientSideTokenGeneratePrivateKey = "UID2-Y-L-MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBop1Dw/IwDcstgicr/3tDoyR3OIpgAWgw8mD6oTO+1ug==";
    private static final int clientSideTokenGenerateSiteId = 123;

    private AutoCloseable mocks;
    @Mock private ISiteStore siteProvider;
    @Mock private IClientKeyProvider clientKeyProvider;
    @Mock private IClientSideKeypairStore clientSideKeypairProvider;
    @Mock private IClientSideKeypairStore.IClientSideKeypairStoreSnapshot clientSideKeypairSnapshot;
    @Mock private IKeysetKeyStore keysetKeyStore;
    @Mock private RotatingKeysetProvider keysetProvider;
    @Mock private ISaltProvider saltProvider;
    @Mock private IServiceStore serviceProvider;
    @Mock private IServiceLinkStore serviceLinkProvider;
    @Mock private SecureLinkValidatorService secureLinkValidatorService;
    @Mock private ISaltProvider.ISaltSnapshot saltProviderSnapshot;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    @Mock private IStatsCollectorQueue statsCollectorQueue;

    private SimpleMeterRegistry registry;
    private OperatorDisableHandler operatorDisableHandler;
    private ExtendedUIDOperatorVerticle uidOperatorVerticle;

    @BeforeEach
    public void deployVerticle(Vertx vertx, VertxTestContext testContext, TestInfo testInfo) {
        mocks = MockitoAnnotations.openMocks(this);
        when(saltProvider.getSnapshot(any())).thenReturn(saltProviderSnapshot);
        when(clock.instant()).thenAnswer(i -> now);
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class))).thenReturn(true);

        this.operatorDisableHandler = new OperatorDisableHandler(Duration.ofHours(24), clock);

        JsonObject config = new JsonObject();
        setupConfig(config);
        if(testInfo.getDisplayName().equals("cstgNoPhoneSupport(Vertx, VertxTestContext)")) {
            config.put("enable_phone_support", false);
        }

        this.uidOperatorVerticle = new ExtendedUIDOperatorVerticle(config, config.getBoolean("client_side_token_generate"), siteProvider, clientKeyProvider, clientSideKeypairProvider, new KeyManager(keysetKeyStore, keysetProvider), saltProvider,  optOutStore, clock, statsCollectorQueue, secureLinkValidatorService);
        uidOperatorVerticle.setDisableHandler(this.operatorDisableHandler);
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
        config.put("advertising_token_v4", getTokenVersion() == TokenVersion.V4);
        config.put("identity_v3", useIdentityV3());
        config.put("client_side_token_generate", true);
    }

    private static byte[] makeAesKey(String prefix) {
        return String.format("%1$16s", prefix).getBytes();
    }

    protected void fakeAuth(int siteId, Role... roles) {
        fakeAuth(siteId, legacyClientCreationDateTime, roles);
    }
    protected void fakeAuth(int siteId, Instant created, Role... roles) {
        ClientKey clientKey = new ClientKey(
                "test-key",
                "UID2-C-L-999-fCXrMM.fsR3mDqAXELtWWMS+xG1s7RdgRTMqdOH2qaAo=",
                "fsSGnDxa/V9eJZ9Tas+dowwyO/X1UsC68RN9qM2xUu9ZOaKEOv9EVd7pkt3As/nE5B6TRu0PzK+IDzSQhD1+rw==",
                Utils.toBase64String(clientSecret),
                "test-contact",
                created,
                Set.of(roles),
                siteId
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
        sendTokenGenerate(apiVersion, vertx, v1GetParam, v2PostPayload, expectedHttpCode, null, handler);
    }

    private void sendTokenGenerate(String apiVersion, Vertx vertx, String v1GetParam, JsonObject v2PostPayload, int expectedHttpCode, String referer, Handler<JsonObject> handler) {
        if (apiVersion.equals("v2")) {
            ClientKey ck = (ClientKey) clientKeyProvider.get("");

            long nonce = new BigInteger(Random.getBytes(8)).longValue();

            addAdditionalTokenGenerateParams(v2PostPayload);

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
            });
        } else {
            get(vertx, apiVersion + "/token/generate" + (v1GetParam != null ? "?" + v1GetParam : ""), ar -> {
                assertTrue(ar.succeeded());
                assertEquals(expectedHttpCode, ar.result().statusCode());
                handler.handle(tryParseResponse(ar.result()));
            });
        }
    }

    private void sendTokenRefresh(String apiVersion, Vertx vertx, String refreshToken, String v2RefreshDecryptSecret, int expectedHttpCode,
                                  Handler<JsonObject> handler) {
        if (apiVersion.equals("v2")) {
            WebClient client = WebClient.create(vertx);
            client.postAbs(getUrlForEndpoint("v2/token/refresh"))
                    .putHeader("content-type", "text/plain")
                    .sendBuffer(Buffer.buffer(refreshToken.getBytes(StandardCharsets.UTF_8)), ar -> {
                        assertTrue(ar.succeeded());
                        assertEquals(expectedHttpCode, ar.result().statusCode());

                        if (ar.result().statusCode() == 200 && v2RefreshDecryptSecret != null) {
                            byte[] decrypted = AesGcm.decrypt(Utils.decodeBase64String(ar.result().bodyAsString()), 0, Utils.decodeBase64String(v2RefreshDecryptSecret));
                            JsonObject respJson = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));

                            if (respJson.getString("status").equals("success"))
                                decodeV2RefreshToken(respJson);

                            handler.handle(respJson);
                        } else {
                            handler.handle(tryParseResponse(ar.result()));
                        }
                    });
        } else {
            get(vertx, "v1/token/refresh?refresh_token=" + urlEncode(refreshToken), ar -> {
                assertTrue(ar.succeeded());
                HttpResponse<Buffer> response = ar.result();
                assertEquals(expectedHttpCode, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                handler.handle(json);
            });
        }
    }

    private void decodeV2RefreshToken(JsonObject respJson) {
        if (respJson.containsKey("body")) {
            JsonObject bodyJson = respJson.getJsonObject("body");

            byte[] tokenBytes = Utils.decodeBase64String(bodyJson.getString("refresh_token"));
            KeysetKey refreshKey = keysetKeyStore.getSnapshot().getKey(Buffer.buffer(tokenBytes).getInt(1));

            byte[] decrypted = AesGcm.decrypt(tokenBytes, 5, refreshKey);
            JsonObject tokenKeyJson = new JsonObject(new String(decrypted));

            String refreshToken = tokenKeyJson.getString("refresh_token");
            bodyJson.put("decrypted_refresh_token", refreshToken);
        }
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
            req.putHeader("Authorization", "Bearer " + ck.getKey());
        req.send(handler);
    }

    private void post(Vertx vertx, String endpoint, JsonObject body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        ClientKey ck = clientKeyProvider.getClientKey("");
        HttpRequest<Buffer> req = client.postAbs(getUrlForEndpoint(endpoint));
        if (ck != null)
            req.putHeader("Authorization", "Bearer " + ck.getKey());
        req.sendJsonObject(body, handler);
    }

    private void postV2(ClientKey ck, Vertx vertx, String endpoint, JsonObject body, long nonce, String referer, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
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

        final String apiKey = ck == null ? "" : ck.getKey();
        HttpRequest<Buffer> request = client.postAbs(getUrlForEndpoint(endpoint))
                .putHeader("Authorization", "Bearer " + apiKey)
                .putHeader("content-type", "text/plain");
        if (referer != null) {
            request.putHeader("Referer", referer);
        }
        request.sendBuffer(Buffer.buffer(Utils.toBase64String(bufBody.getBytes()).getBytes(StandardCharsets.UTF_8)), handler);
    }

    private void checkEncryptionKeysResponse(JsonObject response, KeysetKey... expectedKeys) {
        assertEquals("success", response.getString("status"));
        final JsonArray responseKeys = response.getJsonArray("body");
        assertNotNull(responseKeys);
        assertEquals(expectedKeys.length, responseKeys.size());
        for (int i = 0; i < expectedKeys.length; ++i) {
            KeysetKey expectedKey = expectedKeys[i];
            Keyset keyset = keysetProvider.getSnapshot().getKeyset(expectedKey.getKeysetId());

            JsonObject actualKey = responseKeys.getJsonObject(i);
            assertEquals(expectedKey.getId(), actualKey.getInteger("id"));
            assertArrayEquals(expectedKey.getKeyBytes(), actualKey.getBinary("secret"));
            assertEquals(expectedKey.getCreated().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("created")));
            assertEquals(expectedKey.getActivates().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("activates")));
            assertEquals(expectedKey.getExpires().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("expires")));
            assertEquals(keyset.getSiteId(), actualKey.getInteger("site_id"));
        }
    }

    private void checkEncryptionKeysSharing(JsonObject response, int callersSiteId, KeysetKey... expectedKeys) {
        assertEquals("success", response.getString("status"));
        final JsonArray responseKeys = response.getJsonObject("body").getJsonArray("keys");
        assertNotNull(responseKeys);
        assertEquals(expectedKeys.length, responseKeys.size());
        for (int i = 0; i < expectedKeys.length; ++i) {
            KeysetKey expectedKey = expectedKeys[i];
            JsonObject actualKey = responseKeys.getJsonObject(i);
            assertEquals(expectedKey.getId(), actualKey.getInteger("id"));
            assertArrayEquals(expectedKey.getKeyBytes(), actualKey.getBinary("secret"));
            assertEquals(expectedKey.getCreated().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("created")));
            assertEquals(expectedKey.getActivates().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("activates")));
            assertEquals(expectedKey.getExpires().truncatedTo(ChronoUnit.SECONDS), Instant.ofEpochSecond(actualKey.getLong("expires")));

            Keyset expectedKeyset = this.keysetProvider.getSnapshot().getKeyset(expectedKey.getKeysetId());
            assertNotNull(expectedKeyset);
            assertTrue(expectedKeyset.isEnabled());

            final var actualKeysetId = actualKey.getInteger("keyset_id");
            assertTrue(actualKeysetId == null || actualKeysetId > 0); //SDKs currently have an assumption that keyset ids are positive; that will be fixed.
            if (expectedKeyset.getSiteId() == callersSiteId) {
                assertEquals(expectedKey.getKeysetId(), actualKeysetId);
            } else if (expectedKeyset.getSiteId() == MasterKeySiteId) {
                assertEquals(UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS, actualKeysetId);
            } else {
                assertNull(actualKeysetId); //we only send keyset ids if the caller is allowed to encrypt using that keyset (so only the caller's keysets and the master keyset)
            }
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
        final Instant expiryTime = now.plus(25, ChronoUnit.HOURS); //Some tests move the clock forward to test token expiry, so ensure these keys expire after that time.
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
        String v1Param = inputType + "=" + urlEncode(input);
        JsonObject v2Payload = new JsonObject();
        v2Payload.put(inputType, input);

        sendTokenGenerate(apiVersion, vertx, v1Param, v2Payload, 200, handler);
    }

    private static void assertEqualsClose(Instant expected, Instant actual, int withinSeconds) {
        assertTrue(expected.minusSeconds(withinSeconds).isBefore(actual));
        assertTrue(expected.plusSeconds(withinSeconds).isAfter(actual));
    }

    private void assertTokenStatusMetrics(Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus) {
        assertEquals(1, Metrics.globalRegistry
                .get("uid2.token_response_status_count")
                .tag("site_id", String.valueOf(siteId))
                .tag("token_endpoint", String.valueOf(endpoint))
                .tag("token_response_status", String.valueOf(responseStatus))
                .counter().count());
    }

    private byte[] getAdvertisingIdFromIdentity(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return getRawUid(identityType, identityString, firstLevelSalt, rotatingSalt, getIdentityScope(), useIdentityV3());
    }

    private static byte[] getRawUid(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt, IdentityScope identityScope, boolean useIdentityV3) {
        return !useIdentityV3
                ? TokenUtils.getAdvertisingIdV2FromIdentity(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getAdvertisingIdV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt);
    }

    public static byte[] getRawUid(IdentityType identityType, String identityString, IdentityScope identityScope, boolean useIdentityV3) {
        return !useIdentityV3
                ? TokenUtils.getAdvertisingIdV2FromIdentity(identityString, firstLevelSalt, rotatingSalt123.getSalt())
                : TokenUtils.getAdvertisingIdV3FromIdentity(identityScope, identityType, identityString, firstLevelSalt, rotatingSalt123.getSalt());
    }

    private byte[] getAdvertisingIdFromIdentityHash(IdentityType identityType, String identityString, String firstLevelSalt, String rotatingSalt) {
        return !useIdentityV3()
                ? TokenUtils.getAdvertisingIdV2FromIdentityHash(identityString, firstLevelSalt, rotatingSalt)
                : TokenUtils.getAdvertisingIdV3FromIdentityHash(getIdentityScope(), identityType, identityString, firstLevelSalt, rotatingSalt);
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
        req.put("policy", 1);
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

    private AdvertisingToken validateAndGetToken(EncryptedTokenEncoder encoder, JsonObject body, IdentityType identityType) { //See UID2-79+Token+and+ID+format+v3
        final String advertisingTokenString = body.getString("advertising_token");
        validateAdvertisingToken(advertisingTokenString, getTokenVersion(), getIdentityScope(), identityType);
        return encoder.decodeAdvertisingToken(advertisingTokenString);
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

    @Test
    void identityMapNewClientNoPolicySpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("test1@uid2.com");
        req.put("email", emails);

        send("v2", vertx, "v2/identity/map", false, null, req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            assertEquals("Required opt-out policy argument for identity/map is missing or not set to 1", respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @Test
    void identityMapNewClientWrongPolicySpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.MAPPER);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("test1@uid2.com");
        req.put("email", emails);
        req.put("policy", IdentityMapPolicy.JustMap.policy);

        send("v2", vertx, "v2/identity/map", false, null, req, 400, respJson -> {
            assertFalse(respJson.containsKey("body"));
            assertEquals("client_error", respJson.getString("status"));
            assertEquals("Required opt-out policy argument for identity/map is missing or not set to 1", respJson.getString("message"));
            testContext.completeNow();
        });
    }

    @Test
    void identityMapNewClientNoPolicySpecifiedOlderKeySuccessful(Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime)
                .withSiteId(201).withRoles(Set.of(Role.MAPPER)).withContact("test-contact");
        ClientKey oldClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime.minusSeconds(5))
                .withSiteId(201).withRoles(Set.of(Role.MAPPER)).withContact("test-contact");
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);
        emails.add("test1@uid2.com");

        send("v2", vertx, "v2/identity/map", false, null, req, 200, respJson -> {
            assertTrue(respJson.containsKey("body"));
            assertEquals("success", respJson.getString("status"));
            testContext.completeNow();
        });
    }

    @Test
    void identityMapNewClientWrongPolicySpecifiedOlderKeySuccessful(Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime)
                .withSiteId(201).withRoles(Set.of(Role.MAPPER)).withContact("test-contact");
        ClientKey oldClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime.minusSeconds(5))
                .withSiteId(201).withRoles(Set.of(Role.MAPPER)).withContact("test-contact");
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        req.put("email", emails);
        req.put("policy", IdentityMapPolicy.JustMap.policy);

        emails.add("test1@uid2.com");
        ;
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

    @Test
    void tokenGenerateNewClientWrongPolicySpecified(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, newClientCreationDateTime, Role.GENERATOR);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put("policy", TokenGeneratePolicy.JustGenerate.policy);

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
        ClientKey newClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime)
                .withSiteId(201).withRoles(Set.of(Role.GENERATOR)).withContact("test-contact");
        ClientKey oldClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime.minusSeconds(5))
                .withSiteId(201).withRoles(Set.of(Role.GENERATOR)).withContact("test-contact");
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

    @Test
    void tokenGenerateNewClientWrongPolicySpecifiedOlderKeySuccessful(Vertx vertx, VertxTestContext testContext) {
        ClientKey newClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime)
                .withSiteId(201).withRoles(Set.of(Role.GENERATOR)).withContact("test-contact");
        ClientKey oldClientKey = new ClientKey("test-key", null, null, Utils.toBase64String(clientSecret), newClientCreationDateTime.minusSeconds(5))
                .withSiteId(201).withRoles(Set.of(Role.GENERATOR)).withContact("test-contact");
        when(clientKeyProvider.get(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getClientKey(any())).thenReturn(newClientKey);
        when(clientKeyProvider.getOldestClientKey(201)).thenReturn(oldClientKey);
        setupSalts();
        setupKeys();

        JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", "test@email.com");
        v2Payload.put("policy", TokenGeneratePolicy.JustGenerate.policy);

        sendTokenGenerate("v2", vertx,
                "", v2Payload, 200,
                json -> {
                    assertTrue(json.containsKey("body"));
                    assertEquals("success", json.getString("status"));
                    testContext.completeNow();
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

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

                    RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

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

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);

                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                    assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Email, emailHash, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

                    RefreshToken refreshToken = encoder.decodeRefreshToken(apiVersion.equals("v2") ? body.getString("decrypted_refresh_token") : body.getString("refresh_token"));
                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(emailHash, firstLevelSalt), refreshToken.userIdentity.id);

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

            sendTokenRefresh(apiVersion, vertx, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson ->
            {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                AdvertisingToken advertisingToken = validateAndGetToken(encoder, refreshBody, IdentityType.Email);

                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

                String refreshTokenStringNew = refreshBody.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshToken refreshToken = encoder.decodeRefreshToken(refreshTokenStringNew);
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

                assertEqualsClose(now.plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                assertEqualsClose(now.plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.GenerateV1 : TokenResponseStatsCollector.Endpoint.GenerateV2,
                        TokenResponseStatsCollector.ResponseStatus.Success);
                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.Success);

                testContext.completeNow();
            });
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenGenerateThenValidateWithEmail_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
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
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash));
            JsonObject v2Payload = new JsonObject();
            v2Payload.put("token", advertisingTokenString);
            v2Payload.put("email_hash", EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash));

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
        final String emailAddress = UIDOperatorVerticle.ValidationInputEmail;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "email", emailAddress, genRespJson -> {
            assertEquals("success", genRespJson.getString("status"));
            JsonObject genBody = genRespJson.getJsonObject("body");
            assertNotNull(genBody);

            String advertisingTokenString = genBody.getString("advertising_token");

            String v1Param = "token=" + urlEncode(advertisingTokenString) + "&email=" + emailAddress + "&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash));
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

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Email, emailAddress, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(emailAddress, firstLevelSalt), refreshToken.userIdentity.id);

            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshNoToken(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        sendTokenRefresh(apiVersion, vertx, "", "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshInvalidTokenAuthenticated(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);

        sendTokenRefresh(apiVersion, vertx, "abcd", "", 400, json -> {
            assertEquals("invalid_token", json.getString("status"));
            assertTokenStatusMetrics(
                    clientSiteId,
                    apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                    TokenResponseStatsCollector.ResponseStatus.InvalidToken);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void tokenRefreshInvalidTokenUnauthenticated(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        sendTokenRefresh(apiVersion, vertx, "abcd", "", 400, json -> {
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, bodyJson.getString("refresh_response_key"), 400, refreshRespJson -> {
                assertEquals("expired_token", refreshRespJson.getString("status"));
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, "", 400, refreshRespJson -> {
                assertEquals("error", refreshRespJson.getString("status"));
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson -> {
                assertEquals("optout", refreshRespJson.getString("status"));
                assertTokenStatusMetrics(
                        clientSiteId,
                        apiVersion.equals("v1") ? TokenResponseStatsCollector.Endpoint.RefreshV1 : TokenResponseStatsCollector.Endpoint.RefreshV2,
                        TokenResponseStatsCollector.ResponseStatus.OptOut);
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

            sendTokenRefresh(apiVersion, vertx, refreshToken, refreshTokenDecryptSecret, 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));

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

            sendTokenRefresh("v2", vertx, refreshToken, null, 200, refreshRespJson -> {
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

            sendTokenRefresh("v1", vertx, refreshToken, null, 200, refreshRespJson -> {
                assertEquals("success", refreshRespJson.getString("status"));
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
                "token=abcdef&email_hash=" + urlEncode(EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash)),
                new JsonObject().put("token", "abcdef").put("email_hash", EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash)),
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
    void disableOnDeauthorization(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        get(vertx, "v1/token/generate?email=test@uid2.com", testContext.succeeding(response -> testContext.verify(() -> {
            // Request should succeed before revoking auth
            assertEquals(200, response.statusCode());

            // Revoke auth
            this.operatorDisableHandler.handleResponseStatus(401);

            // Request should fail after revoking auth
            get(vertx, "v1/token/generate?email=test@uid2.com", testContext.succeeding(response2 -> testContext.verify(() -> {
                assertEquals(503, response2.statusCode());

                // Recovered
                this.operatorDisableHandler.handleResponseStatus(200);
                get(vertx, "v1/token/generate?email=test@uid2.com", testContext.succeeding(response3 -> testContext.verify(() -> {
                    assertEquals(200, response3.statusCode());
                    testContext.completeNow();
                })));
            })));
        })));
    }

    @Test
    void disableOnFailure(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        // Verify success before revoking auth
        get(vertx, "v1/token/generate?email=test@uid2.com", ar -> {
            assertEquals(200, ar.result().statusCode());

            // Failure starts
            this.operatorDisableHandler.handleResponseStatus(500);

            // Can server before waiting period passes
            when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
            this.operatorDisableHandler.handleResponseStatus(500);
            get(vertx, "v1/token/generate?email=test@uid2.com", ar1 -> {
                assertEquals(200, ar1.result().statusCode());

                // Can't serve after waiting period passes
                when(clock.instant()).thenAnswer(i -> Instant.now().plus(24, ChronoUnit.HOURS));
                this.operatorDisableHandler.handleResponseStatus(500);
                get(vertx, "v1/token/generate?email=test@uid2.com", ar2 -> {
                    assertEquals(503, ar2.result().statusCode());

                    // Recovered
                    this.operatorDisableHandler.handleResponseStatus(200);
                    get(vertx, "v1/token/generate?email=test@uid2.com", ar3 -> {
                        assertEquals(200, ar3.result().statusCode());
                        testContext.completeNow();
                    });
                });
            });
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

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

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

            AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Phone);

            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
            assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
            assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
            assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

            RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token"));
            assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

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

            sendTokenRefresh(apiVersion, vertx, genRefreshToken, bodyJson.getString("refresh_response_key"), 200, refreshRespJson ->
            {
                assertEquals("success", refreshRespJson.getString("status"));
                JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                assertNotNull(refreshBody);
                EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                AdvertisingToken advertisingToken = validateAndGetToken(encoder, refreshBody, IdentityType.Phone);

                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                assertFalse(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
                assertArrayEquals(getAdvertisingIdFromIdentity(IdentityType.Phone, phone, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);

                String refreshTokenStringNew = refreshBody.getString(apiVersion.equals("v2") ? "decrypted_refresh_token" : "refresh_token");
                assertNotEquals(genRefreshToken, refreshTokenStringNew);
                RefreshToken refreshToken = encoder.decodeRefreshToken(refreshTokenStringNew);
                assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
                assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentity(phone, firstLevelSalt), refreshToken.userIdentity.id);

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
        final String phone = UIDOperatorVerticle.ValidationInputPhone;
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
    void tokenGenerateThenValidateWithPhoneHash_Match(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        final String phone = UIDOperatorVerticle.ValidationInputPhone;
        final String phoneHash = EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputPhoneHash);
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        generateTokens(apiVersion, vertx, "phone", phone, genRespJson -> {
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
        final String phone = UIDOperatorVerticle.ValidationInputPhone;
        final String phoneHash = EncodingUtils.toBase64String(UIDOperatorVerticle.ValidationInputEmailHash);
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
                assertTokenStatusMetrics(clientSiteId, TokenResponseStatsCollector.Endpoint.RefreshV1, TokenResponseStatsCollector.ResponseStatus.OptOut);

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
                assertEquals("success", json.getString("status"));

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
    @ValueSource(strings = {"v2"})
    void tokenGenerateRespectOptOutOption(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        req.put("email", "random-optout-user@email.io");
        req.put("policy", 1);

        // for EUID
        addAdditionalTokenGenerateParams(req);

        send(apiVersion, vertx, apiVersion + "/token/generate", false, null, req, 200, json -> {
            try {
                Assertions.assertEquals(UIDOperatorVerticle.ResponseStatus.OptOut, json.getString("status"));
                Assertions.assertNull(json.getJsonObject("body"));
                assertTokenStatusMetrics(clientSiteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.OptOut);
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
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);

        send(apiVersion, vertx, apiVersion + "/identity/map", false, null, req, 200, json -> {
            try {
                Assertions.assertTrue(json.getJsonObject("body").getJsonArray("unmapped") == null ||
                        json.getJsonObject("body").getJsonArray("unmapped").isEmpty());
                Assertions.assertEquals(1, json.getJsonObject("body").getJsonArray("mapped").size());
                Assertions.assertEquals("random-optout-user@email.io", json.getJsonObject("body").getJsonArray("mapped").getJsonObject(0).getString("identifier"));
                testContext.completeNow();
            } catch (Exception e) {
                testContext.failNow(e);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"v1", "v2"})
    void identityMapRespectOptOutOption(String apiVersion, Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.MAPPER);
        setupSalts();
        setupKeys();

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(now.minus(1, ChronoUnit.HOURS));

        JsonObject req = new JsonObject();
        JsonArray emails = new JsonArray();
        emails.add("random-optout-user@email.io");
        req.put("email", emails);
        req.put("policy", 1);

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
                });
    }

    private void postCstg(Vertx vertx, String endpoint, String httpOriginHeader, JsonObject body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        HttpRequest<Buffer> req = client.postAbs(getUrlForEndpoint(endpoint));
        req.putHeader("origin", httpOriginHeader);
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

    private void setupCstgBackend(String... domainNames)
    {
        setupSalts();
        setupKeys();
        ClientSideKeypair keypair = new ClientSideKeypair(clientSideTokenGenerateSubscriptionId, clientSideTokenGeneratePublicKey, clientSideTokenGeneratePrivateKey, clientSideTokenGenerateSiteId, "", Instant.now(), false);
        when(clientSideKeypairProvider.getSnapshot()).thenReturn(clientSideKeypairSnapshot);
        when(clientSideKeypairSnapshot.getKeypair(clientSideTokenGenerateSubscriptionId)).thenReturn(keypair);
        when(siteProvider.getSite(eq(clientSideTokenGenerateSiteId))).thenReturn(new Site(clientSideTokenGenerateSiteId, "test", true, new HashSet<>(List.of(domainNames))));
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
                    assertEquals(UIDOperatorVerticle.ResponseStatus.ClientError, respJson.getString("status"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.MissingParams);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://blahblah.com", "http://local1host:8080"})
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
                            TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://cstg.co.uk", "https://cstg2.com", "http://localhost:8080"})
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
                    assertTrue(respJson.containsKey("body"));
                    assertEquals("success", respJson.getString("status"));
                    testContext.completeNow();
                });
    }

    @Test
    void cstgNoBody(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
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
    void cstgBadTimestamp(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        IdentityType identityType = IdentityType.Email;
        String rawId = "random@unifiedid.com";

        JsonObject identityPayload = new JsonObject();
        identityPayload.put("email_hash", getSha256(rawId));

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final long timestamp = now.minus(V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES, ChronoUnit.MINUTES).toEpochMilli();
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
                    assertEquals("error", respJson.getString("status"));
                    assertEquals("invalid timestamp: request too old or client time drift", respJson.getString("message"));
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.BadTimestamp);
                    testContext.completeNow();
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"payload", "iv", "public_key"})
    void cstgMissingRequiredField(String testField, Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        IdentityType identityType = IdentityType.Email;
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

        IdentityType identityType = IdentityType.Email;
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
                            TokenResponseStatsCollector.ResponseStatus.BadPublicKey);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadSubscriptionId(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        IdentityType identityType = IdentityType.Email;
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

        IdentityType identityType = IdentityType.Email;
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
                            TokenResponseStatsCollector.ResponseStatus.BadIV);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadIvIncorrectLength(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        IdentityType identityType = IdentityType.Email;
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
                            TokenResponseStatsCollector.ResponseStatus.BadIV);
                    testContext.completeNow();
                });
    }

    @Test
    void cstgBadEncryptedPayload(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");

        IdentityType identityType = IdentityType.Email;
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
                            TokenResponseStatsCollector.ResponseStatus.BadPayload);
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
                            TokenResponseStatsCollector.ResponseStatus.BadPayload);
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
                            TokenResponseStatsCollector.ResponseStatus.BadPayload);
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
                            TokenResponseStatsCollector.ResponseStatus.BadPayload);
                    testContext.completeNow();
                });
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequestWithPayload(JsonObject identityPayload, long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {

        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = ClientSideTokenGenerateTestUtil.stringToPublicKey(clientSideTokenGeneratePublicKey, kf);
        final PrivateKey clientPrivateKey = ClientSideTokenGenerateTestUtil.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = ClientSideTokenGenerateTestUtil.deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = ClientSideTokenGenerateTestUtil.encrypt(identityPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", clientSideTokenGenerateSubscriptionId);

        return new Tuple.Tuple2<>(requestJson, secretKey);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequest(IdentityType identityType, String rawId, long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {

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
        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp);
    }

    private Tuple.Tuple2<JsonObject, SecretKey> createClientSideTokenGenerateRequestWithNoPayload(long timestamp) throws NoSuchAlgorithmException, InvalidKeyException {
        JsonObject identity = new JsonObject();
        return createClientSideTokenGenerateRequestWithPayload(identity, timestamp);
    }

    // tests for opted out user should lead to generating ad tokens with the default optout identity
    // tests for opted in user should lead to generating ad tokens that never match the default optout identity
    // tests for all email/phone combos
    @ParameterizedTest
    @CsvSource({"true,abc@abc.com,Email,optout@unifiedid.com",
            "true,+61400000000,Phone,+00000000001",
            "false,abc@abc.com,Email,optout@unifiedid.com",
            "false,+61400000000,Phone,+00000000001"})
    void cstgOptedOutTest(boolean optOutExpected, String id, IdentityType identityType, String expectedOptedOutIdentity,
                          Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException, InvalidKeyException {
        setupCstgBackend("cstg.co.uk");
        Tuple.Tuple2<JsonObject, SecretKey> data = createClientSideTokenGenerateRequest(identityType, id, Instant.now().toEpochMilli());
        if(optOutExpected)
        {
            when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                    .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));
        }
        else { //not expectedOptedOut
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
                    JsonObject genBody = respJson.getJsonObject("body");
                    assertNotNull(genBody);

                    decodeV2RefreshToken(respJson);
                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, genBody, identityType);
                    assertEquals(clientSideTokenGenerateSiteId, advertisingToken.publisherIdentity.siteId);

                    assertTrue(PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenGenerated());
                    assertEquals(optOutExpected, PrivacyBits.fromInt(advertisingToken.userIdentity.privacyBits).isClientSideTokenOptedOut());

                    if(identityType == IdentityType.Email) {
                        assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Email,
                                TokenUtils.getIdentityHashString(optOutExpected? expectedOptedOutIdentity : id),
                                firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);
                    }
                    else if(identityType == IdentityType.Phone) {
                        assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Phone,
                                TokenUtils.getIdentityHashString(optOutExpected? expectedOptedOutIdentity : id),
                                firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);
                    }
                    else { //should never happen
                        assertFalse(true);
                    }

                    RefreshToken refreshToken = encoder.decodeRefreshToken(genBody.getString("decrypted_refresh_token"));
                    assertEquals(clientSideTokenGenerateSiteId, refreshToken.publisherIdentity.siteId);
                    assertTrue(PrivacyBits.fromInt(refreshToken.userIdentity.privacyBits).isClientSideTokenGenerated());

                    if(optOutExpected) {
                        assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(getSha256(expectedOptedOutIdentity), firstLevelSalt), refreshToken.userIdentity.id);
                        assertTrue(PrivacyBits.fromInt(refreshToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    }
                    else {
                        assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(getSha256(id), firstLevelSalt), refreshToken.userIdentity.id);
                        assertFalse(PrivacyBits.fromInt(refreshToken.userIdentity.privacyBits).isClientSideTokenOptedOut());
                    }

                    assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("identity_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_expires")), 10);
                    assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(genBody.getLong("refresh_from")), 10);

                    String advertisingTokenString = genBody.getString("advertising_token");

                    InputUtil.InputVal input;
                    if(identityType == IdentityType.Email) {
                        input = InputUtil.InputVal.validEmail(expectedOptedOutIdentity, expectedOptedOutIdentity);
                    }
                    else if(identityType == IdentityType.Phone) {
                        input = InputUtil.InputVal.validPhone(expectedOptedOutIdentity, expectedOptedOutIdentity);
                    }
                    else { //should never happen
                        input = null;
                        assertFalse(true);
                    }

                    final Instant now = Instant.now();
                    final String token = advertisingTokenString;
                    final boolean matchedOptedOutIdentity = this.uidOperatorVerticle.getIdService().advertisingTokenMatches(token, input.toUserIdentity(getIdentityScope(), 0, now), now);

                    assertEquals(optOutExpected, matchedOptedOutIdentity);
                    assertTokenStatusMetrics(
                            clientSideTokenGenerateSiteId,
                            TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2,
                            TokenResponseStatsCollector.ResponseStatus.Success);

                    String genRefreshToken = genBody.getString("refresh_token");
                    //test a subsequent refresh from this cstg call and see if it still works
                    sendTokenRefresh("v2", vertx, genRefreshToken, genBody.getString("refresh_response_key"), 200, refreshRespJson ->
                    {
                        assertEquals("success", refreshRespJson.getString("status"));
                        JsonObject refreshBody = refreshRespJson.getJsonObject("body");
                        assertNotNull(refreshBody);
                        EncryptedTokenEncoder encoder2 = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

                        //make sure the new advertising token from refresh looks right
                        AdvertisingToken adTokenFromRefresh = validateAndGetToken(encoder2, refreshBody, identityType);
                        assertEquals(clientSideTokenGenerateSiteId, adTokenFromRefresh.publisherIdentity.siteId);

                        String refreshTokenStringNew = refreshBody.getString("decrypted_refresh_token");
                        assertNotEquals(genRefreshToken, refreshTokenStringNew);
                        RefreshToken refreshTokenAfterRefresh = encoder.decodeRefreshToken(refreshTokenStringNew);
                        assertEquals(clientSideTokenGenerateSiteId, refreshTokenAfterRefresh.publisherIdentity.siteId);

                        if(optOutExpected) {
                            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(getSha256(expectedOptedOutIdentity), firstLevelSalt), refreshTokenAfterRefresh.userIdentity.id);
                        }
                        else {
                            assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(getSha256(id), firstLevelSalt), refreshTokenAfterRefresh.userIdentity.id);
                        }

                        if(identityType == IdentityType.Email) {
                            assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Email,
                                    TokenUtils.getIdentityHashString(optOutExpected? expectedOptedOutIdentity : id),
                                    firstLevelSalt, rotatingSalt123.getSalt()), adTokenFromRefresh.userIdentity.id);
                        }
                        else if(identityType == IdentityType.Phone) {
                            assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Phone,
                                    TokenUtils.getIdentityHashString(optOutExpected? expectedOptedOutIdentity : id),
                                    firstLevelSalt, rotatingSalt123.getSalt()), adTokenFromRefresh.userIdentity.id);

                        }
                        else { //should never happen
                            assertFalse(true);
                        }

                        assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("identity_expires")), 10);
                        assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_expires")), 10);
                        assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(refreshBody.getLong("refresh_from")), 10);

                        assertTokenStatusMetrics(
                                clientSideTokenGenerateSiteId,
                                TokenResponseStatsCollector.Endpoint.RefreshV2,
                                TokenResponseStatsCollector.ResponseStatus.Success);

                        //check the CSTG-related privacy bits are still set correctly
                        assertTrue(PrivacyBits.fromInt(adTokenFromRefresh.userIdentity.privacyBits).isClientSideTokenGenerated());
                        assertTrue(PrivacyBits.fromInt(refreshTokenAfterRefresh.userIdentity.privacyBits).isClientSideTokenGenerated());
                        assertEquals(optOutExpected, PrivacyBits.fromInt(adTokenFromRefresh.userIdentity.privacyBits).isClientSideTokenOptedOut());
                        assertEquals(optOutExpected, PrivacyBits.fromInt(refreshTokenAfterRefresh.userIdentity.privacyBits).isClientSideTokenOptedOut());

                        testContext.completeNow();
                    });
                });
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
            checkEncryptionKeysSharing(respJson, siteId, expectedKeys);
            testContext.completeNow();
        });
    }

    @Test
        // Tests:
        //   ID_READER has access to a keyset that has the same site_id as ID_READER's  - direct access
        //   ID_READER has access to a keyset with a missing allowed_sites              - access through sharing
        //   ID_READER has access to a keyset with allowed_sites that includes us       - access through sharing
        //   ID_READER has no access to a keyset that is disabled                       - direct reject
        //   ID_READER has no access to a keyset with an empty allowed_sites            - reject by sharing
        //   ID_READER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keySharingKeysets_IDREADER(Vertx vertx, VertxTestContext testContext) {
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

        Arrays.sort(expectedKeys, Comparator.comparing(KeysetKey::getId));
        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals("success", respJson.getString("status"));
            assertEquals(clientSiteId, respJson.getJsonObject("body").getInteger("caller_site_id"));
            assertEquals(UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS, respJson.getJsonObject("body").getInteger("master_keyset_id"));
            assertEquals(4, respJson.getJsonObject("body").getInteger("default_keyset_id"));
            checkEncryptionKeysSharing(respJson, clientSiteId, expectedKeys);
            testContext.completeNow();
        });
    }

    @Test
        // Tests:
        //   SHARER has access to a keyset that has the same site_id as ID_READER's  - direct access
        //   SHARER has access to a keyset with allowed_sites that includes us       - access through sharing
        //   SHARER has no access to a keyset that is disabled                       - direct reject
        //   SHARER has no access to a keyset with a missing allowed_sites           - reject by sharing
        //   SHARER has no access to a keyset with an empty allowed_sites            - reject by sharing
        //   SHARER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keySharingKeysets_SHARER(Vertx vertx, VertxTestContext testContext) {
        String apiVersion = "v2";
        int clientSiteId = 101;
        fakeAuth(clientSiteId, Role.SHARER);
        MultipleKeysetsTests test = new MultipleKeysetsTests();
        //To read these tests, open the MultipleKeysetsTests() constructor in another window so you can see the keyset contents and validate against expectedKeys

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
            checkEncryptionKeysSharing(respJson, clientSiteId, expectedKeys);
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

        Arrays.sort(encryptionKeys, Comparator.comparing(KeysetKey::getId));
        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            checkEncryptionKeysSharing(respJson, siteId, encryptionKeys);
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

            switch (testRun) {
                case "NoKeyset":
                    assertNull(respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    break;
                case "NoKey":
                    assertEquals(4, respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    break;
                case "SharedKey":
                    assertEquals(6, respJson.getJsonObject("body").getInteger("default_keyset_id"));
                    break;
            }
            checkEncryptionKeysSharing(respJson, clientSiteId, expectedKeys);
            testContext.completeNow();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"KeysetAccess", "AddKeyset", "AddKey", "RotateKey", "DisableKey", "DisableKeyset"})
        // "KeysetAccess"
        //   ID_READER has access to a keyset that has the same site_id as ID_READER's  - direct access
        //   ID_READER has access to a keyset with a missing allowed_sites              - access through sharing
        //   ID_READER has access to a keyset with allowed_sites that includes us       - access through sharing
        //   ID_READER has no access to a keyset that is disabled                       - direct reject
        //   ID_READER has no access to a keyset with an empty allowed_sites            - reject by sharing
        //   ID_READER has no access to a keyset with an allowed_sites for other sites  - reject by sharing
    void keySharingRotatingKeysets_IDREADER(String testRun, Vertx vertx, VertxTestContext testContext) {
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
        send(apiVersion, vertx, apiVersion + "/key/sharing", true, null, null, 200, respJson -> {
            System.out.println(respJson);
            assertEquals("success", respJson.getString("status"));
            assertEquals(clientSiteId, respJson.getJsonObject("body").getInteger("caller_site_id"));
            assertEquals(UIDOperatorVerticle.MASTER_KEYSET_ID_FOR_SDKS, respJson.getJsonObject("body").getInteger("master_keyset_id"));
            assertEquals(4, respJson.getJsonObject("body").getInteger("default_keyset_id"));
            checkEncryptionKeysSharing(respJson, clientSiteId, expectedKeys.toArray(new KeysetKey[0]));
            testContext.completeNow();
        });
    }

    @Test
    void secureLinkValidationPassesReturnsIdentity(Vertx vertx, VertxTestContext testContext) {
        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class))).thenReturn(true);

        send("v2", vertx, "v2" + "/identity/map", false, null, req, 200, json -> {
            checkIdentityMapResponse(json, "test1@uid2.com", "test2@uid2.com");
            testContext.completeNow();
        });
    }

    @Test
    void secureLinkValidationFailsReturnsIdentityError(Vertx vertx, VertxTestContext testContext) {
        JsonObject req = setupIdentityMapServiceLinkTest();
        when(this.secureLinkValidatorService.validateRequest(any(RoutingContext.class), any(JsonObject.class))).thenReturn(false);

        send("v2", vertx, "v2" + "/identity/map", false, null, req, 401, json -> {
            assertEquals("unauthorized", json.getString("status"));
            assertEquals("Invalid link_id", json.getString("message"));
            testContext.completeNow();
        });
    }
}
