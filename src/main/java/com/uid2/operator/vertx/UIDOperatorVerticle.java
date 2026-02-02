package com.uid2.operator.vertx;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.Const;
import com.uid2.operator.Main;
import com.uid2.operator.model.*;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.StatsCollectorHandler;
import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.privacy.tcf.TransparentConsent;
import com.uid2.operator.privacy.tcf.TransparentConsentParseResult;
import com.uid2.operator.privacy.tcf.TransparentConsentPurpose;
import com.uid2.operator.privacy.tcf.TransparentConsentSpecialFeature;
import com.uid2.operator.service.*;
import com.uid2.operator.store.*;
import com.uid2.operator.store.IConfigStore;
import com.uid2.operator.util.*;
import com.uid2.shared.Const.Data;
import com.uid2.shared.Utils;
import com.uid2.shared.audit.Audit;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.auth.*;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.health.HealthComponent;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.*;
import com.uid2.shared.store.*;
import com.uid2.shared.store.ACLMode.MissingAclMode;
import com.uid2.shared.store.IClientKeyProvider;
import com.uid2.shared.store.IClientSideKeypairStore;
import com.uid2.shared.store.salt.ISaltProvider;
import com.uid2.shared.util.Mapper;
import com.uid2.shared.vertx.RequestCapturingHandler;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tag;
import io.netty.buffer.Unpooled;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.AllowForwardHeaders;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.StaticHandler;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.IdentityConst.*;
import static com.uid2.operator.service.ResponseUtil.*;
import static com.uid2.operator.vertx.Endpoints.*;

public class UIDOperatorVerticle extends AbstractVerticle {
    public static final long MAX_REQUEST_BODY_SIZE = 1 << 20; // 1MB
    /**
     * There is currently an issue with v2 tokens (and possibly also other ad token versions) where the token lifetime
     * is slightly longer than it should be. When validating token lifetimes, we add a small buffer to account for this.
     */
    public static final Duration TOKEN_LIFETIME_TOLERANCE = Duration.ofSeconds(10);
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorVerticle.class);
    // Use a formatter that always prints three-digit millisecond precision (e.g. 2024-07-02T14:15:16.000)
    private static final DateTimeFormatter API_DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZone(ZoneOffset.UTC);
    private static final ObjectMapper OBJECT_MAPPER = Mapper.getApiInstance();
    private static final long SECOND_IN_MILLIS = 1000;

    private static final String REQUEST = "request";
    private final HealthComponent healthComponent = HealthManager.instance.registerComponent("http-server");
    private final Cipher aesGcm;
    private final IConfigStore configStore;
    private final boolean clientSideTokenGenerate;
    private final AuthMiddleware auth;
    private final ISiteStore siteProvider;
    private final IClientSideKeypairStore clientSideKeypairProvider;
    private final ITokenEncoder encoder;
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final IClientKeyProvider clientKeyProvider;
    private final Clock clock;
    private final boolean identityV3Enabled;
    private final boolean disableOptoutToken;
    private final UidInstanceIdProvider uidInstanceIdProvider;
    protected IUIDOperatorService idService;

    private final Map<String, DistributionSummary> _identityMapMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple2<String, Boolean>, DistributionSummary> _refreshDurationMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple3<String, Boolean, Boolean>, Counter> _advertisingTokenExpiryStatus = new HashMap<>();
    private final Map<Tuple.Tuple3<String, OptoutCheckPolicy, String>, Counter> _tokenGeneratePolicyCounters = new HashMap<>();
    private final Map<String, Counter> _tokenGenerateTCFUsage = new HashMap<>();
    private final Map<String, Tuple.Tuple2<Counter, Counter>> _identityMapUnmappedIdentifiers = new HashMap<>();
    private final Map<String, Counter> _identityMapRequestWithUnmapped = new HashMap<>();
    private final Map<Tuple.Tuple2<String, String>, Counter> _clientVersions = new HashMap<>();
    private final Map<Tuple.Tuple2<String, String>, Counter> _tokenValidateCounters = new HashMap<>();

    private final Map<String, DistributionSummary> optOutStatusCounters = new HashMap<>();
    private final IdentityScope identityScope;
    private final V2PayloadHandler encryptedPayloadHandler;
    private final boolean phoneSupport;
    private final int tcfVendorId;
    private final IStatsCollectorQueue _statsCollectorQueue;
    private final KeyManager keyManager;
    private final SecureLinkValidatorService secureLinkValidatorService;
    private final boolean cstgDoDomainNameCheck;
    private final boolean clientSideTokenGenerateLogInvalidHttpOrigin;
    public static final int MASTER_KEYSET_ID_FOR_SDKS = 9999999; //this is because SDKs have an issue where they assume keyset ids are always positive; that will be fixed.
    public static final long OPT_OUT_CHECK_CUTOFF_DATE = Instant.parse("2023-09-01T00:00:00.00Z").getEpochSecond();
    private final Handler<Boolean> saltRetrievalResponseHandler;
    private final int allowClockSkewSeconds;
    private final WorkerExecutor computeWorkerPool;
    protected Map<Integer, Set<String>> siteIdToInvalidOriginsAndAppNames = new HashMap<>();
    protected boolean keySharingEndpointProvideAppNames;
    protected Instant lastInvalidOriginProcessTime = Instant.now();

    private final int optOutStatusMaxRequestSize;
    private final boolean optOutStatusApiEnabled;

    private final boolean isAsyncBatchRequestsEnabled;

    //"Android" is from https://github.com/IABTechLab/uid2-android-sdk/blob/ff93ebf597f5de7d440a84f7015a334ba4138ede/sdk/src/main/java/com/uid2/UID2Client.kt#L46
    //"ios"/"tvos" is from https://github.com/IABTechLab/uid2-ios-sdk/blob/91c290d29a7093cfc209eca493d1fee80c17e16a/Sources/UID2/UID2Client.swift#L36-L38
    private static final List<String> SUPPORTED_IN_APP = Arrays.asList("Android", "ios", "tvos");

    public static final String ORIGIN_HEADER = "Origin";
    private static final String ERROR_INVALID_INPUT_WITH_PHONE_SUPPORT = "Required Parameter Missing: exactly one of [email, email_hash, phone, phone_hash] must be specified";
    private static final String ERROR_INVALID_INPUT_EMAIL_MISSING = "Required Parameter Missing: exactly one of email or email_hash must be specified";
    private static final String ERROR_INVALID_MIXED_INPUT_WITH_PHONE_SUPPORT = "Required Parameter Missing: one or more of [email, email_hash, phone, phone_hash] must be specified";
    private static final String ERROR_INVALID_MIXED_INPUT_EMAIL_MISSING = "Required Parameter Missing: one or more of [email, email_hash] must be specified";
    private static final String RC_CONFIG_KEY = "remote-config";

    public UIDOperatorVerticle(IConfigStore configStore,
                               JsonObject config,
                               boolean clientSideTokenGenerate,
                               ISiteStore siteProvider,
                               IClientKeyProvider clientKeyProvider,
                               IClientSideKeypairStore clientSideKeypairProvider,
                               KeyManager keyManager,
                               ISaltProvider saltProvider,
                               IOptOutStore optOutStore,
                               Clock clock,
                               IStatsCollectorQueue statsCollectorQueue,
                               SecureLinkValidatorService secureLinkValidatorService,
                               Handler<Boolean> saltRetrievalResponseHandler,
                               UidInstanceIdProvider uidInstanceIdProvider,
                               WorkerExecutor computeWorkerPool) {
        this.keyManager = keyManager;
        this.secureLinkValidatorService = secureLinkValidatorService;
        try {
            aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        this.configStore = configStore;
        this.clientSideTokenGenerate = clientSideTokenGenerate;
        this.healthComponent.setHealthStatus(false, "not started");
        this.auth = new AuthMiddleware(clientKeyProvider);
        this.encoder = new EncryptedTokenEncoder(keyManager);
        this.siteProvider = siteProvider;
        this.clientSideKeypairProvider = clientSideKeypairProvider;
        this.saltProvider = saltProvider;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = IdentityScope.fromString(config.getString("identity_scope", "uid2"));
        this.encryptedPayloadHandler = new V2PayloadHandler(keyManager, config.getBoolean("enable_v2_encryption", true), this.identityScope, siteProvider);
        this.phoneSupport = config.getBoolean("enable_phone_support", true);
        this.tcfVendorId = config.getInteger("tcf_vendor_id", 21);
        this.cstgDoDomainNameCheck = config.getBoolean("client_side_token_generate_domain_name_check_enabled", true);
        this.keySharingEndpointProvideAppNames = config.getBoolean("key_sharing_endpoint_provide_app_names", false);
        this._statsCollectorQueue = statsCollectorQueue;
        this.clientKeyProvider = clientKeyProvider;
        this.clientSideTokenGenerateLogInvalidHttpOrigin = config.getBoolean("client_side_token_generate_log_invalid_http_origins", false);
        this.allowClockSkewSeconds = config.getInteger(Const.Config.AllowClockSkewSecondsProp, 1800);
        this.saltRetrievalResponseHandler = saltRetrievalResponseHandler;
        this.optOutStatusApiEnabled = config.getBoolean(Const.Config.OptOutStatusApiEnabled, true);
        this.optOutStatusMaxRequestSize = config.getInteger(Const.Config.OptOutStatusMaxRequestSize, 5000);
        this.identityV3Enabled = config.getBoolean(IdentityV3Prop, false);
        this.disableOptoutToken = config.getBoolean(DisableOptoutTokenProp, false);
        this.uidInstanceIdProvider = uidInstanceIdProvider;
        this.computeWorkerPool = computeWorkerPool;
        this.isAsyncBatchRequestsEnabled = config.getBoolean(EnableAsyncBatchRequestProp, false);
    }

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        this.healthComponent.setHealthStatus(false, "still starting");
        this.idService = new UIDOperatorService(
                this.optOutStore,
                this.saltProvider,
                this.encoder,
                this.clock,
                this.identityScope,
                this.saltRetrievalResponseHandler,
                this.identityV3Enabled,
                this.uidInstanceIdProvider,
                this.keyManager
        );

        final Router router = createRoutesSetup();
        final int port = Const.Port.ServicePortForOperator + Utils.getPortOffset();
        vertx.createHttpServer(new HttpServerOptions().setMaxFormBufferedBytes((int) MAX_REQUEST_BODY_SIZE))
                .requestHandler(router)
                .listen(port, result -> {
                    if (result.succeeded()) {
                        this.healthComponent.setHealthStatus(true);
                        // Record startup completion now that HTTP server is ready
                        Main.recordStartupComplete();
                        startPromise.complete();
                    } else {
                        this.healthComponent.setHealthStatus(false, result.cause().getMessage());
                        startPromise.fail(result.cause());
                    }

                    LOGGER.info("UIDOperatorVerticle instance started on HTTP port: {}", port);
                });

    }

    private CorsHandler createCorsHandler() {
        return CorsHandler.create()
                .addRelativeOrigin(".*.")
                .allowedMethod(io.vertx.core.http.HttpMethod.GET)
                .allowedMethod(io.vertx.core.http.HttpMethod.POST)
                .allowedMethod(io.vertx.core.http.HttpMethod.OPTIONS)
                .allowedHeader(Const.Http.ClientVersionHeader)
                .allowedHeader("Access-Control-Request-Method")
                .allowedHeader("Access-Control-Allow-Credentials")
                .allowedHeader("Access-Control-Allow-Origin")
                .allowedHeader("Access-Control-Allow-Headers")
                .allowedHeader("Content-Type");
    }

    private Router createRoutesSetup() throws IOException {
        final Router router = Router.router(vertx);

        router.allowForward(AllowForwardHeaders.X_FORWARD);
        router.route().handler(new RequestCapturingHandler(siteProvider));
        router.route().handler(new ClientVersionCapturingHandler("static/js", "*.js", clientKeyProvider));
        router.route(V2_TOKEN_VALIDATE.toString()).handler(createCorsHandler().allowedHeader("Authorization"));
        router.route().handler(createCorsHandler());
        router.route().handler(new StatsCollectorHandler(_statsCollectorQueue, vertx));
        router.route("/static/*").handler(StaticHandler.create("static"));
        router.route().handler(ctx -> {
            RuntimeConfig curConfig = configStore.getConfig();
            ctx.put(RC_CONFIG_KEY, curConfig);
            ctx.next();
        });
        router.route().failureHandler(new GenericFailureHandler());

        final BodyHandler bodyHandler = BodyHandler.create().setHandleFileUploads(false).setBodyLimit(MAX_REQUEST_BODY_SIZE);
        setUpEncryptedRoutes(router, bodyHandler);

        // Static and health check
        router.get(OPS_HEALTHCHECK.toString()).handler(this::handleHealthCheck);

        return router;
    }

    private void setUpEncryptedRoutes(Router mainRouter, BodyHandler bodyHandler) {
        mainRouter.post(V2_TOKEN_GENERATE.toString()).handler(bodyHandler).handler(auth.handleV1(
                rc -> encryptedPayloadHandler.handleTokenGenerate(rc, this::handleTokenGenerateV2), Role.GENERATOR));
        mainRouter.post(V2_TOKEN_REFRESH.toString()).handler(bodyHandler).handler(auth.handleWithOptionalAuth(
                rc -> encryptedPayloadHandler.handleTokenRefresh(rc, this::handleTokenRefreshV2)));
        mainRouter.post(V2_TOKEN_VALIDATE.toString()).handler(bodyHandler).handler(auth.handleV1(
                rc -> encryptedPayloadHandler.handle(rc, this::handleTokenValidateV2), Role.GENERATOR));
        mainRouter.post(V2_KEY_LATEST.toString()).handler(bodyHandler).handler(auth.handleV1(
                rc -> encryptedPayloadHandler.handle(rc, this::handleKeysRequestV2), Role.ID_READER));
        mainRouter.post(V2_TOKEN_LOGOUT.toString()).handler(bodyHandler).handler(auth.handleV1(
                rc -> encryptedPayloadHandler.handleAsync(rc, this::handleLogoutAsyncV2), Role.OPTOUT));
        if (this.optOutStatusApiEnabled) {
            mainRouter.post(V2_OPTOUT_STATUS.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleOptoutStatus),
                    Role.MAPPER, Role.SHARER, Role.ID_READER));
        }

        if (this.clientSideTokenGenerate)
            mainRouter.post(V2_TOKEN_CLIENTGENERATE.toString()).handler(bodyHandler).handler(this::handleClientSideTokenGenerate);

        if (isAsyncBatchRequestsEnabled) {
            LOGGER.info("Async batch requests enabled");
            mainRouter.post(V2_KEY_SHARING.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handleAsync(rc, this::handleKeysSharingAsync), Role.SHARER, Role.ID_READER));
            mainRouter.post(V2_KEY_BIDSTREAM.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handleAsync(rc, this::handleKeysBidstreamAsync), Role.ID_READER));
            mainRouter.post(V2_IDENTITY_BUCKETS.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handleAsync(rc, this::handleBucketsV2Async), Role.MAPPER));
            mainRouter.post(V2_IDENTITY_MAP.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handleAsync(rc, this::handleIdentityMapV2Async), Role.MAPPER));
            mainRouter.post(V3_IDENTITY_MAP.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handleAsync(rc, this::handleIdentityMapV3Async), Role.MAPPER));
        } else {
            mainRouter.post(V2_KEY_SHARING.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleKeysSharing), Role.SHARER, Role.ID_READER));
            mainRouter.post(V2_KEY_BIDSTREAM.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleKeysBidstream), Role.ID_READER));
            mainRouter.post(V2_IDENTITY_BUCKETS.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleBucketsV2), Role.MAPPER));
            mainRouter.post(V2_IDENTITY_MAP.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleIdentityMapV2), Role.MAPPER));
            mainRouter.post(V3_IDENTITY_MAP.toString()).handler(bodyHandler).handler(auth.handleV1(
                    rc -> encryptedPayloadHandler.handle(rc, this::handleIdentityMapV3), Role.MAPPER));
        }
    }

    private void handleClientSideTokenGenerate(RoutingContext rc) {
        try {
            handleClientSideTokenGenerateImpl(rc);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while handling client side token generate", null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e, TokenResponseStatsCollector.PlatformType.Other);
        }
    }

    private RuntimeConfig getConfigFromRc(RoutingContext rc) {
        return rc.get(RC_CONFIG_KEY);
    }

    private Set<String> getDomainNameListForClientSideTokenGenerate(ClientSideKeypair keypair) {
        Site s = siteProvider.getSite(keypair.getSiteId());
        if (s == null) {
            return Collections.emptySet();
        } else {
            return s.getDomainNames();
        }
    }

    private Set<String> getAppNames(ClientSideKeypair keypair) {
        final Site site = siteProvider.getSite(keypair.getSiteId());
        if (site == null) {
            return Collections.emptySet();
        }
        return site.getAppNames();
    }

    private void logIfApiKey(String key) {
        ClientKey clientKey = this.clientKeyProvider.getClientKey(key);
        if (clientKey != null) {
            LOGGER.error("Client side key is an api key with api_key_id={} for site_id={}", clientKey.getKeyId(), clientKey.getSiteId());
        }
    }

    private void handleClientSideTokenGenerateImpl(RoutingContext rc) throws NoSuchAlgorithmException, InvalidKeyException {
        final JsonObject body;

        RuntimeConfig config = this.getConfigFromRc(rc);

        Duration refreshIdentityAfter = Duration.ofSeconds(config.getRefreshIdentityTokenAfterSeconds());
        Duration refreshExpiresAfter = Duration.ofSeconds(config.getRefreshTokenExpiresAfterSeconds());
        Duration identityExpiresAfter = Duration.ofSeconds(config.getIdentityTokenExpiresAfterSeconds());
        IdentityEnvironment identityEnvironment = config.getIdentityEnvironment();

        TokenResponseStatsCollector.PlatformType platformType = TokenResponseStatsCollector.PlatformType.Other;
        try {
            body = rc.body().asJsonObject();
        } catch (DecodeException ex) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "json payload is not valid",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadJsonPayload, siteProvider, platformType);
            return;
        }

        if (body == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "json payload expected but not found",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.PayloadHasNoBody, siteProvider, platformType);
            return;
        }

        final CstgRequest request = body.mapTo(CstgRequest.class);
        platformType = request.getAppName() != null ? TokenResponseStatsCollector.PlatformType.InApp : getPlatformType(rc);

        final ClientSideKeypair clientSideKeypair = this.clientSideKeypairProvider.getSnapshot().getKeypair(request.getSubscriptionId());
        if (clientSideKeypair == null) {
            logIfApiKey(request.getSubscriptionId());
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad subscription_id",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadSubscriptionId, siteProvider, platformType);
            return;
        }
        rc.put(com.uid2.shared.Const.RoutingContextData.SiteId, clientSideKeypair.getSiteId());

        if (clientSideKeypair.isDisabled()) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.Unauthorized, 401, rc, "Unauthorized",
                    clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.Unauthorized, siteProvider, platformType);
            return;
        }

        if (!hasValidOriginOrAppName(rc, request, clientSideKeypair, platformType)) {
            return;
        }

        if (request.getPayload() == null || request.getIv() == null || request.getPublicKey() == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "required parameters: payload, iv, public_key", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider, platformType);
            return;
        }

        final KeyFactory kf = KeyFactory.getInstance("EC");

        final PublicKey clientPublicKey;
        try {
            final byte[] clientPublicKeyBytes = Base64.getDecoder().decode(request.getPublicKey());
            final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPublicKeyBytes);
            clientPublicKey = kf.generatePublic(pkSpec);
        } catch (Exception e) {
            logIfApiKey(request.getPublicKey());
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad public key", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPublicKey, siteProvider, platformType);
            return;
        }

        // Perform key agreement
        final KeyAgreement ka = CryptoProviderService.createKeyAgreement();
        ka.init(clientSideKeypair.getPrivateKey());
        ka.doPhase(clientPublicKey, true);

        // Read shared secret
        final byte[] sharedSecret = ka.generateSecret();

        final byte[] ivBytes;
        try {
            ivBytes = Base64.getDecoder().decode(request.getIv());
            if (ivBytes.length != 12) {
                SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad iv", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV, siteProvider, platformType);
                return;
            }
        } catch (IllegalArgumentException e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad iv", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV, siteProvider, platformType);
            return;
        }

        final JsonArray aad = JsonArray.of(request.getTimestamp());
        if (request.getAppName() != null) {
            aad.add(request.getAppName());
        }

        final byte[] requestPayloadBytes;
        try {
            final byte[] encryptedPayloadBytes = Base64.getDecoder().decode(request.getPayload());
            final byte[] ivAndCiphertext = Arrays.copyOf(ivBytes, 12 + encryptedPayloadBytes.length);
            System.arraycopy(encryptedPayloadBytes, 0, ivAndCiphertext, 12, encryptedPayloadBytes.length);
            requestPayloadBytes = decrypt(ivAndCiphertext, 0, sharedSecret, aad.toBuffer().getBytes());
        } catch (Exception e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "payload decryption failed", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider, platformType);
            return;
        }

        final JsonObject requestPayload;
        try {
            requestPayload = new JsonObject(Buffer.buffer(Unpooled.wrappedBuffer(requestPayloadBytes)));
        } catch (DecodeException e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "encrypted payload contains invalid json", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider, platformType);
            return;
        }

        final String emailHash = requestPayload.getString("email_hash");
        final String phoneHash = requestPayload.getString("phone_hash");
        final InputUtil.InputVal input;

        if (phoneHash != null && !phoneSupport) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "phone support not enabled", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider, platformType);
            return;
        }

        final String errString = phoneSupport ?  "please provide exactly one of: email_hash, phone_hash" : "please provide email_hash";
        if (emailHash == null && phoneHash == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, errString, clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider, platformType);
            return;
        } else if (emailHash != null && phoneHash != null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, errString, clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider, platformType);
            return;
        } else if (emailHash != null) {
            input = InputUtil.normalizeEmailHash(emailHash);
        } else {
            input = InputUtil.normalizePhoneHash(phoneHash);
        }

        if (!isTokenInputValid(input, rc)) {
            return;
        }

        PrivacyBits privacyBits = new PrivacyBits();
        privacyBits.setLegacyBit();
        privacyBits.setClientSideTokenGenerate();

        IdentityTokens identityTokens;
        try {
            identityTokens = this.idService.generateIdentity(
                    new IdentityRequest(
                            new PublisherIdentity(clientSideKeypair.getSiteId(), 0, 0),
                            input.toUserIdentity(this.identityScope, privacyBits.getAsInt(), Instant.now()),
                            OptoutCheckPolicy.RespectOptOut,
                            identityEnvironment
                    ),
                    refreshIdentityAfter,
                    refreshExpiresAfter,
                    identityExpiresAfter);
        } catch (KeyManager.NoActiveKeyException e) {
            SendServerErrorResponseAndRecordStats(rc, "No active encryption key available", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.NoActiveKey, siteProvider, e, platformType);
            return;
        }
        JsonObject response;
        TokenResponseStatsCollector.ResponseStatus responseStatus = TokenResponseStatsCollector.ResponseStatus.Success;

        if (identityTokens.isEmptyToken()) {
            response = ResponseUtil.SuccessNoBodyV2(ResponseStatus.OptOut);
            responseStatus = TokenResponseStatsCollector.ResponseStatus.OptOut;
        } else { // user not opted out and already generated valid identity token
            response = ResponseUtil.SuccessV2(toTokenResponseJson(identityTokens));
        }
        // if returning an optout token or a successful identity token created originally
        if (responseStatus == TokenResponseStatsCollector.ResponseStatus.Success) {
            V2RequestUtil.handleRefreshTokenInResponseBody(response.getJsonObject("body"), keyManager, this.identityScope);
        }
        final byte[] encryptedResponse = AesGcm.encrypt(response.toBuffer().getBytes(), sharedSecret);
        rc.response().setStatusCode(200).end(Buffer.buffer(Unpooled.wrappedBuffer(Base64.getEncoder().encode(encryptedResponse))));
        recordTokenResponseStats(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, responseStatus, siteProvider, identityTokens.getAdvertisingTokenVersion(), platformType);
    }

    private boolean hasValidOriginOrAppName(RoutingContext rc, CstgRequest request, ClientSideKeypair keypair, TokenResponseStatsCollector.PlatformType platformType) {
        final OriginOrAppNameValidationResult validationResult = validateOriginOrAppName(rc, request, keypair);
        if (validationResult.isSuccess) {
            return true;
        }

        if (clientSideTokenGenerateLogInvalidHttpOrigin) {
            logInvalidOriginOrAppName(keypair.getSiteId(), validationResult.originOrAppName);
        }
        SendClientErrorResponseAndRecordStats(validationResult.errorStatus, 403, rc, validationResult.message, keypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, validationResult.responseStatus, siteProvider, platformType);
        return false;
    }

    private OriginOrAppNameValidationResult validateOriginOrAppName(RoutingContext rc, CstgRequest request, ClientSideKeypair keypair) {
        if (!cstgDoDomainNameCheck) {
            return OriginOrAppNameValidationResult.SUCCESS;
        }

        final String appName = request.getAppName();
        if (appName != null) {
            return getAppNames(keypair).stream().anyMatch(appName::equalsIgnoreCase)
                    ? OriginOrAppNameValidationResult.SUCCESS
                    : OriginOrAppNameValidationResult.invalidAppName(appName);
        }

        final String origin = rc.request().getHeader(ORIGIN_HEADER);
        final Set<String> domainNames = getDomainNameListForClientSideTokenGenerate(keypair);

        return origin != null && DomainNameCheckUtil.isDomainNameAllowed(origin, domainNames)
                ? OriginOrAppNameValidationResult.SUCCESS
                : OriginOrAppNameValidationResult.invalidHttpOrigin(origin);
    }

    private static class OriginOrAppNameValidationResult {
        private final boolean isSuccess;

        private final String errorStatus;

        private final String message;

        private final TokenResponseStatsCollector.ResponseStatus responseStatus;

        private final String originOrAppName;

        public static final OriginOrAppNameValidationResult SUCCESS = new OriginOrAppNameValidationResult(true, null, null, null, null);

        public static OriginOrAppNameValidationResult invalidAppName(String appName) {
            return new OriginOrAppNameValidationResult(false, ResponseStatus.InvalidAppName, "unexpected app name", TokenResponseStatsCollector.ResponseStatus.InvalidAppName, appName);
        }

        public static OriginOrAppNameValidationResult invalidHttpOrigin(String origin) {
            return new OriginOrAppNameValidationResult(false, ResponseStatus.InvalidHttpOrigin, "unexpected http origin", TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin, origin);
        }

        private OriginOrAppNameValidationResult(boolean isSuccess, String errorStatus, String message, TokenResponseStatsCollector.ResponseStatus responseStatus, String originOrAppName) {
            this.isSuccess = isSuccess;
            this.errorStatus = errorStatus;
            this.message = message;
            this.responseStatus = responseStatus;
            this.originOrAppName = originOrAppName;
        }
    }

    private byte[] decrypt(byte[] encryptedBytes, int offset, byte[] secretBytes, byte[] aad) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey key = new SecretKeySpec(secretBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, encryptedBytes, offset, 12);
        aesGcm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        aesGcm.updateAAD(aad);
        return aesGcm.doFinal(encryptedBytes, offset + 12, encryptedBytes.length - offset - 12);
    }

    private void handleKeysRequestCommon(RoutingContext rc, Handler<JsonArray> onSuccess) {
        final ClientKey clientKey = AuthMiddleware.getAuthClient(ClientKey.class, rc);
        final int clientSiteId = clientKey.getSiteId();
        if (!clientKey.hasValidSiteId()) {
            ResponseUtil.LogWarningAndSendResponse(ResponseStatus.InvalidClient, 401, rc, "Unexpected client site id " + Integer.toString(clientSiteId));
            return;
        }

        final List<KeysetKey> keys = this.keyManager.getKeysForSharingOrDsps();
        onSuccess.handle(getAccessibleKeysAsJson(keys, clientKey));
    }

    public void handleKeysRequestV2(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> ResponseUtil.SuccessV2(rc, keys));
        } catch (Exception e) {
            LOGGER.error("Unknown error while handling keys request v2", e);
            rc.fail(500);
        }
    }

    public void handleKeysSharing(RoutingContext rc) {
        RuntimeConfig config = this.getConfigFromRc(rc);
        int sharingTokenExpirySeconds = config.getSharingTokenExpirySeconds();
        int maxSharingLifetimeSeconds = config.getMaxSharingLifetimeSeconds();
        try {
            final ClientKey clientKey = AuthMiddleware.getAuthClient(ClientKey.class, rc);

            KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
            List<KeysetKey> keysetKeyStore = keyManagerSnapshot.getKeysetKeys();
            Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();

            final JsonObject resp = new JsonObject();
            addSharingHeaderFields(resp, keyManagerSnapshot, clientKey, maxSharingLifetimeSeconds, sharingTokenExpirySeconds);

            final List<KeysetKey> accessibleKeys = getAccessibleKeys(keysetKeyStore, keyManagerSnapshot, clientKey);

            final JsonArray keys = new JsonArray();
            for (KeysetKey key : accessibleKeys) {
                JsonObject keyObj = toJson(key);
                Keyset keyset = keysetMap.get(key.getKeysetId());

                // Include keyset ID if:
                // - The key belongs to the caller's site, or
                // - The key belongs to the master keyset.
                // Otherwise, the key can be used for decryption only so we don't include the keyset ID.
                if (clientKey.getSiteId() == keyset.getSiteId()) {
                    keyObj.put("keyset_id", key.getKeysetId());
                } else if (key.getKeysetId() == Data.MasterKeysetId) {
                    keyObj.put("keyset_id", MASTER_KEYSET_ID_FOR_SDKS);
                }
                keys.add(keyObj);
            }
            resp.put("keys", keys);

            addSites(resp, accessibleKeys, keysetMap);

            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            LOGGER.error("handleKeysSharing", e);
            rc.fail(500);
        }
    }

    public void handleKeysBidstream(RoutingContext rc) {
        final ClientKey clientKey = AuthMiddleware.getAuthClient(ClientKey.class, rc);

        final KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
        final List<KeysetKey> keysetKeyStore = keyManagerSnapshot.getKeysetKeys();
        final Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();

        final List<KeysetKey> accessibleKeys = getAccessibleKeys(keysetKeyStore, keyManagerSnapshot, clientKey);

        final List<JsonObject> keysJson = accessibleKeys.stream()
                .map(UIDOperatorVerticle::toJson)
                .collect(Collectors.toList());

        final JsonObject resp = new JsonObject();

        RuntimeConfig config = this.getConfigFromRc(rc);
        int maxBidstreamLifetimeSeconds = config.getMaxBidstreamLifetimeSeconds();


        addBidstreamHeaderFields(resp, maxBidstreamLifetimeSeconds);
        resp.put("keys", keysJson);
        addSites(resp, accessibleKeys, keysetMap);

        ResponseUtil.SuccessV2(rc, resp);
    }

    private Future<Void> handleKeysSharingAsync(RoutingContext rc) {
        return computeWorkerPool.executeBlocking(() -> {
            handleKeysSharing(rc);
            return null;
        });
    }

    private Future<Void> handleKeysBidstreamAsync(RoutingContext rc) {
        return computeWorkerPool.executeBlocking(() -> {
            handleKeysBidstream(rc);
            return null;
        });
    }

    private void addBidstreamHeaderFields(JsonObject resp, int maxBidstreamLifetimeSeconds) {
        resp.put("max_bidstream_lifetime_seconds", maxBidstreamLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds());
        addIdentityScopeField(resp);
        addAllowClockSkewSecondsField(resp);
    }

    private void addSites(JsonObject resp, List<KeysetKey> keys, Map<Integer, Keyset> keysetMap) {
        final List<Site> sites = getSitesWithDomainOrAppNames(keys, keysetMap);
        if (sites != null) {
            /*
            The end result will look something like this:

            "site_data": [
                    {
                        "id": 101,
                        "domain_names": [
                            "101.co.uk",
                            "101.com"
                        ]
                    },
                    {
                        "id": 102,
                        "domain_names": [
                            "101.co.uk",
                            "101.com",
                            "com.uid2.operator",
                            "123456789"
                        ]
                    }
                ]
            */
            final List<JsonObject> sitesJson = sites.stream()
                    .map(site -> UIDOperatorVerticle.toJson(site, keySharingEndpointProvideAppNames))
                    .collect(Collectors.toList());
            resp.put("site_data", sitesJson);
        }
    }

    private void addSharingHeaderFields(JsonObject resp, KeyManagerSnapshot keyManagerSnapshot, ClientKey clientKey, int maxSharingLifetimeSeconds, int sharingTokenExpirySeconds) {
        resp.put("caller_site_id", clientKey.getSiteId());
        resp.put("master_keyset_id", MASTER_KEYSET_ID_FOR_SDKS);

        // defaultKeysetId allows calling sdk.Encrypt(rawUid) without specifying the keysetId
        final Keyset defaultKeyset = keyManagerSnapshot.getDefaultKeyset();
        if (defaultKeyset != null) {
            resp.put("default_keyset_id", defaultKeyset.getKeysetId());
        } else if (clientKey.hasRole(Role.SHARER)) {
            LOGGER.warn(String.format("Cannot get a default keyset with SITE ID %d. Caller will not be able to encrypt tokens..", clientKey.getSiteId()));
        }

        // this is written out as a String, i.e. in the JSON response of key/sharing endpoint, it would show:
        // "token_expiry_seconds" : "2592000"
        // it should be an integer instead, but we can't change it until we confirm that the oldest version of each of our SDKs support this
        resp.put("token_expiry_seconds", String.valueOf(sharingTokenExpirySeconds));

        if (clientKey.hasRole(Role.SHARER)) {
            resp.put("max_sharing_lifetime_seconds", maxSharingLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds());
        }

        addIdentityScopeField(resp);
        addAllowClockSkewSecondsField(resp);
    }

    private void addIdentityScopeField(JsonObject resp) {
        resp.put("identity_scope", this.identityScope.name());
    }

    private void addAllowClockSkewSecondsField(JsonObject resp) {
        resp.put("allow_clock_skew_seconds", allowClockSkewSeconds);
    }

    private List<Site> getSitesWithDomainOrAppNames(List<KeysetKey> keys, Map<Integer, Keyset> keysetMap) {
        //without cstg enabled, operator won't have site data and siteProvider could be null
        if (!clientSideTokenGenerate) {
            return null;
        }

        return keys.stream()
                .mapToInt(key -> keysetMap.get(key.getKeysetId()).getSiteId())
                .sorted()
                .distinct()
                .mapToObj(siteProvider::getSite)
                .filter(Objects::nonNull)
                .filter(site -> {
                    if (CollectionUtils.isNotEmpty(site.getDomainNames())) {
                        return true;
                    } else {
                        return keySharingEndpointProvideAppNames && CollectionUtils.isNotEmpty(site.getAppNames());
                    }
                })
                .collect(Collectors.toList());
    }

    /**
     * Converts the specified site to a JSON object.
     * Includes the following fields: id, domain_names.
     */
    private static JsonObject toJson(Site site, boolean includeAppNames) {
        JsonObject siteObj = new JsonObject();
        siteObj.put("id", site.getId());
        Set<String> domainOrAppNames = new HashSet<>(site.getDomainNames());

        if (includeAppNames) {
            domainOrAppNames.addAll(site.getAppNames());
        }
        siteObj.put("domain_names", domainOrAppNames.stream().sorted().collect(Collectors.toList()));
        return siteObj;
    }

    private void handleHealthCheck(RoutingContext rc) {
        if (HealthManager.instance.isHealthy()) {
            rc.response().end("OK");
        } else {
            HttpServerResponse resp = rc.response();
            String reason = HealthManager.instance.reason();
            resp.setStatusCode(503);
            resp.setChunked(true);
            resp.write(reason);
            resp.end();
        }
    }

    private void recordOperatorServedSdkUsage(RoutingContext rc, Integer siteId, String apiContact, String clientVersion) {
        if (siteId != null && apiContact != null && clientVersion != null) {
            final String path = RoutingContextUtil.getPath(rc);

            _clientVersions.computeIfAbsent(
                    new Tuple.Tuple2<>(Integer.toString(siteId), clientVersion),
                    tuple -> Counter
                            .builder("uid2_client_sdk_versions_total")
                            .description("counter for how many http requests are processed per each operator-served sdk version")
                            .tags("site_id", tuple.getItem1(), "api_contact", apiContact, "client_version", tuple.getItem2(), "path", path)
                            .register(Metrics.globalRegistry)
            ).increment();
        }
    }

    private void recordTokenValidateStats(Integer siteId, String result) {
        final String siteIdStr = siteId != null ? String.valueOf(siteId) : "unknown";
        _tokenValidateCounters.computeIfAbsent(
                new Tuple.Tuple2<>(siteIdStr, result),
                tuple -> Counter
                        .builder("uid2_token_validate_total")
                        .description("counter for token validate endpoint results")
                        .tags(
                            "site_id", tuple.getItem1(), 
                            "site_name", getSiteName(siteProvider, Integer.valueOf(tuple.getItem1())), 
                            "result", tuple.getItem2()
                        )
                        .register(Metrics.globalRegistry)
        ).increment();
    }

    private void handleTokenRefreshV2(RoutingContext rc) {
        Integer siteId = null;
        TokenResponseStatsCollector.PlatformType platformType = TokenResponseStatsCollector.PlatformType.Other;

        RuntimeConfig config = this.getConfigFromRc(rc);
        Duration identityExpiresAfter = Duration.ofSeconds(config.getIdentityTokenExpiresAfterSeconds());
        try {
            platformType = getPlatformType(rc);
            String tokenStr = (String) rc.data().get("request");
            final RefreshResponse r = this.refreshIdentity(rc, tokenStr);
            siteId = rc.get(Const.RoutingContextData.SiteId);
            final String apiContact = RoutingContextUtil.getApiContact(rc, clientKeyProvider);
            recordOperatorServedSdkUsage(rc, siteId, apiContact, rc.request().headers().get(Const.Http.ClientVersionHeader));
            if (!r.isRefreshed()) {
                if (r.isOptOut() || r.isDeprecated()) {
                    ResponseUtil.SuccessNoBodyV2(ResponseStatus.OptOut, rc);
                } else if (!AuthMiddleware.isAuthenticated(rc)) {
                    // unauthenticated clients get a generic error
                    ResponseUtil.LogWarningAndSendResponse(ResponseStatus.GenericError, 400, rc, "Error refreshing token");
                } else if (r.isInvalidToken()) {
                    ResponseUtil.LogWarningAndSendResponse(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented");
                } else if (r.isExpired()) {
                    ResponseUtil.LogWarningAndSendResponse(ResponseStatus.ExpiredToken, 400, rc, "Expired Token presented");
                } else if (r.noActiveKey()) {
                    SendServerErrorResponseAndRecordStats(rc, "No active encryption key available", siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, TokenResponseStatsCollector.ResponseStatus.NoActiveKey, siteProvider, new KeyManager.NoActiveKeyException("No active encryption key available"), platformType);
                } else {
                    ResponseUtil.LogErrorAndSendResponse(ResponseStatus.UnknownError, 500, rc, "Unknown State");
                }
            } else {
                ResponseUtil.SuccessV2(rc, toTokenResponseJson(r.getTokens()));
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains(ORIGIN_HEADER), identityExpiresAfter);
            }
            TokenResponseStatsCollector.recordRefresh(siteProvider, siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, r, platformType);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while refreshing token v2", siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e, platformType);
        }
    }

    private void handleTokenValidateV2(RoutingContext rc) {
        RuntimeConfig config = this.getConfigFromRc(rc);
        IdentityEnvironment env = config.getIdentityEnvironment();
        final Integer participantSiteId = AuthMiddleware.getAuthClient(rc).getSiteId();

        try {
            final JsonObject req = (JsonObject) rc.data().get("request");

            final InputUtil.InputVal input = getTokenInputV2(req);
            if (!isTokenInputValid(input, rc)) {
                recordTokenValidateStats(participantSiteId, "invalid_input");
                return;
            }

            final Instant now = Instant.now();
            final String token = req.getString("token");

            final TokenValidateResult result = this.idService.validateAdvertisingToken(participantSiteId, token, input.toUserIdentity(this.identityScope, 0, now), now, env);

            if (result == TokenValidateResult.MATCH) {
                recordTokenValidateStats(participantSiteId, "match");
                ResponseUtil.SuccessV2(rc, Boolean.TRUE);
            } else if (result == TokenValidateResult.MISMATCH) {
                recordTokenValidateStats(participantSiteId, "mismatch");
                ResponseUtil.SuccessV2(rc, Boolean.FALSE);
            } else if (result == TokenValidateResult.UNAUTHORIZED) {
                recordTokenValidateStats(participantSiteId, "unauthorized");
                ResponseUtil.LogInfoAndSend400Response(rc, "Unauthorised to validate token");
            } else if (result == TokenValidateResult.INVALID_TOKEN) {
                recordTokenValidateStats(participantSiteId, "invalid_token");
                ResponseUtil.LogInfoAndSend400Response(rc, "Invalid token");
            }
        } catch (Exception e) {
            recordTokenValidateStats(participantSiteId, "error");
            LOGGER.error("Unknown error while validating token", e);
            rc.fail(500);
        }
    }

    private void handleTokenGenerateV2(RoutingContext rc) {
        final Integer siteId = AuthMiddleware.getAuthClient(rc).getSiteId();
        TokenResponseStatsCollector.PlatformType platformType = TokenResponseStatsCollector.PlatformType.Other;

        RuntimeConfig config = this.getConfigFromRc(rc);
        Duration refreshIdentityAfter = Duration.ofSeconds(config.getRefreshIdentityTokenAfterSeconds());
        Duration refreshExpiresAfter = Duration.ofSeconds(config.getRefreshTokenExpiresAfterSeconds());
        Duration identityExpiresAfter = Duration.ofSeconds(config.getIdentityTokenExpiresAfterSeconds());
        IdentityEnvironment identityEnvironment = config.getIdentityEnvironment();

        try {
            JsonObject req = (JsonObject) rc.data().get("request");
            platformType = getPlatformType(rc);

            final InputUtil.InputVal input = this.getTokenInputV2(req);
            if (isTokenInputValid(input, rc)) {
                final String apiContact = getApiContact(rc);

                switch (validateUserConsent(req, apiContact)) {
                    case INVALID: {
                        SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "User consent is invalid", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InvalidUserConsentString, siteProvider, platformType);
                        return;
                    }
                    case INSUFFICIENT: {
                        ResponseUtil.SuccessNoBodyV2(ResponseStatus.InsufficientUserConsent, rc);
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InsufficientUserConsent, siteProvider, null, platformType);
                        return;
                    }
                    case SUFFICIENT: {
                        break;
                    }
                    default: {
                        final String errorMsg = "Please update UIDOperatorVerticle.handleTokenGenerateV2 when changing UserConsentStatus";
                        LOGGER.error(errorMsg);
                        throw new IllegalStateException(errorMsg);
                    }
                }

                final Tuple.Tuple2<OptoutCheckPolicy, String> optoutCheckPolicy = readOptoutCheckPolicy(req);
                recordTokenGeneratePolicy(apiContact, optoutCheckPolicy.getItem1(), optoutCheckPolicy.getItem2());

                if (!meetPolicyCheckRequirements(rc)) {
                    SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Required opt-out policy argument for token/generate is missing or not set to 1", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider, platformType);
                    return;
                }

                final IdentityTokens t = this.idService.generateIdentity(
                        new IdentityRequest(
                                new PublisherIdentity(siteId, 0, 0),
                                input.toUserIdentity(this.identityScope, 1, Instant.now()),
                                OptoutCheckPolicy.respectOptOut(),
                                identityEnvironment),
                        refreshIdentityAfter,
                        refreshExpiresAfter,
                        identityExpiresAfter);

                if (t.isEmptyToken()) {
                    if (optoutCheckPolicy.getItem1() == OptoutCheckPolicy.DoNotRespect && !this.disableOptoutToken) { // only legacy can use this policy
                        final InputUtil.InputVal optOutTokenInput = input.getIdentityType() == IdentityType.Email
                                ? InputUtil.InputVal.validEmail(OptOutTokenIdentityForEmail, OptOutTokenIdentityForEmail)
                                : InputUtil.InputVal.validPhone(OptOutTokenIdentityForPhone, OptOutTokenIdentityForPhone);

                        PrivacyBits pb = new PrivacyBits();
                        pb.setLegacyBit();
                        pb.setClientSideTokenGenerateOptout();

                        final IdentityTokens optOutTokens = this.idService.generateIdentity(
                                new IdentityRequest(
                                        new PublisherIdentity(siteId, 0, 0),
                                        optOutTokenInput.toUserIdentity(this.identityScope, pb.getAsInt(), Instant.now()),
                                        OptoutCheckPolicy.DoNotRespect,
                                        identityEnvironment),
                                refreshIdentityAfter,
                                refreshExpiresAfter,
                                identityExpiresAfter);

                        ResponseUtil.SuccessV2(rc, toTokenResponseJson(optOutTokens));
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, optOutTokens.getAdvertisingTokenVersion(), platformType);
                    } else { // new participant, or legacy specified policy/optout_check=1
                        ResponseUtil.SuccessNoBodyV2("optout", rc);
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.OptOut, siteProvider, null, platformType);
                    }
                } else {
                    ResponseUtil.SuccessV2(rc, toTokenResponseJson(t));
                    recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, t.getAdvertisingTokenVersion(), platformType);
                }
            }
        } catch (KeyManager.NoActiveKeyException e) {
            SendServerErrorResponseAndRecordStats(rc, "No active encryption key available", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.NoActiveKey, siteProvider, e, platformType);
        } catch (ClientInputValidationException cie) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "request body contains invalid argument(s)", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider, platformType);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while generating token v2", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider, e, platformType);
        }
    }

    private Future handleLogoutAsyncV2(RoutingContext rc) {
        RuntimeConfig config = getConfigFromRc(rc);
        IdentityEnvironment env = config.getIdentityEnvironment();

        final JsonObject req = (JsonObject) rc.data().get("request");
        final InputUtil.InputVal input = getTokenInputV2(req);
        final String uidTraceId = rc.request().getHeader(Audit.UID_TRACE_ID_HEADER);
        if (input != null && input.isValid()) {
            final Instant now = Instant.now();

            Promise promise = Promise.promise();
            final String email = req == null ? null : req.getString("email");
            final String phone = req == null ? null : req.getString("phone");
            final String clientIp = req == null ? null : req.getString("clientIp");

            this.idService.invalidateTokensAsync(input.toUserIdentity(this.identityScope, 0, now), now, uidTraceId, env,
                    email, phone, clientIp,
                    ar -> {
                if (ar.succeeded()) {
                    JsonObject body = new JsonObject();
                    body.put("optout", "OK");
                    ResponseUtil.SuccessV2(rc, body);
                } else {
                    rc.fail(500);
                }
                promise.complete();
            });
            return promise.future();
        } else {
            ResponseUtil.LogWarningAndSendResponse(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + input);
            return Future.failedFuture("");
        }
    }

    private Future<Void> handleBucketsV2Async(RoutingContext rc) {
        return computeWorkerPool.executeBlocking(() -> {
            handleBucketsV2(rc);
            return null;
        });
    }

    private void handleBucketsV2(RoutingContext rc) {
        final JsonObject req = (JsonObject) rc.data().get("request");
        final String qp = req.getString("since_timestamp");

        if (qp != null) {
            final Instant sinceTimestamp;
            try {
                LocalDateTime ld = LocalDateTime.parse(qp, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                sinceTimestamp = ld.toInstant(ZoneOffset.UTC);
                LOGGER.info(String.format("identity bucket endpoint is called with since_timestamp %s and site id %s", ld, AuthMiddleware.getAuthClient(rc).getSiteId()));
            } catch (Exception e) {
                ResponseUtil.LogInfoAndSend400Response(rc, "invalid date, must conform to ISO 8601");
                return;
            }
            final List<SaltEntry> modified = this.idService.getModifiedBuckets(sinceTimestamp);
            final JsonArray resp = new JsonArray();
            if (modified != null) {
                for (SaltEntry e : modified) {
                    final JsonObject o = new JsonObject();
                    o.put("bucket_id", e.hashedId());
                    Instant lastUpdated = Instant.ofEpochMilli(e.lastUpdated());

                    o.put("last_updated", API_DATE_TIME_FORMATTER.format(lastUpdated));
                    resp.add(o);
                }
                ResponseUtil.SuccessV2(rc, resp);
            }
        } else {
            ResponseUtil.LogInfoAndSend400Response(rc, "missing parameter since_timestamp");
        }
    }

    private InputUtil.InputVal getTokenInputV2(JsonObject req) {
        if (req == null)
            return null;

        Supplier<InputUtil.InputVal> getInput = null;

        final String email = req.getString("email");
        if (email != null) {
            getInput = () -> InputUtil.normalizeEmail(email);
        }

        final String emailHash = req.getString("email_hash");
        if (emailHash != null) {
            if (getInput != null)   // there can be only 1 set of valid input
                return null;
            getInput = () -> InputUtil.normalizeEmailHash(emailHash);
        }

        final String phone = this.phoneSupport ? req.getString("phone") : null;
        if (phone != null) {
            if (getInput != null)        // there can be only 1 set of valid input
                return null;
            getInput = () -> InputUtil.normalizePhone(phone);
        }

        final String phoneHash = this.phoneSupport ? req.getString("phone_hash") : null;
        if (phoneHash != null) {
            if (getInput != null)        // there can be only 1 set of valid input
                return null;
            getInput = () -> InputUtil.normalizePhoneHash(phoneHash);
        }

        return getInput != null ? getInput.get() : null;
    }

    private boolean isTokenInputValid(InputUtil.InputVal input, RoutingContext rc) {
        if (input == null) {
            String message = this.phoneSupport ? ERROR_INVALID_INPUT_WITH_PHONE_SUPPORT : ERROR_INVALID_INPUT_EMAIL_MISSING;
            ResponseUtil.LogInfoAndSend400Response(rc, message);
            return false;
        } else if (!input.isValid()) {
            ResponseUtil.LogInfoAndSend400Response(rc, "Invalid Identifier");
            return false;
        }
        return true;
    }

    private JsonObject handleIdentityMapCommon(RoutingContext rc, InputUtil.InputVal[] inputList) {
        RuntimeConfig config = getConfigFromRc(rc);
        IdentityEnvironment env = config.getIdentityEnvironment();

        final Instant now = Instant.now();
        final JsonArray mapped = new JsonArray();
        final JsonArray unmapped = new JsonArray();
        final int count = inputList.length;
        int invalidCount = 0;
        int optoutCount = 0;
        for (int i = 0; i < count; ++i) {
            final InputUtil.InputVal input = inputList[i];
            if (input != null && input.isValid()) {
                final MappedIdentity mappedIdentity = idService.mapIdentity(
                        new MapRequest(
                                input.toUserIdentity(this.identityScope, 0, now),
                                OptoutCheckPolicy.respectOptOut(),
                                now,
                                env));

                if (mappedIdentity.isOptedOut()) {
                    final JsonObject resp = new JsonObject();
                    resp.put("identifier", input.getProvided());
                    resp.put("reason", "optout");
                    unmapped.add(resp);
                    optoutCount++;
                } else {
                    final JsonObject resp = new JsonObject();
                    resp.put("identifier", input.getProvided());
                    resp.put("advertising_id", EncodingUtils.toBase64String(mappedIdentity.advertisingId));
                    resp.put("bucket_id", mappedIdentity.bucketId);
                    mapped.add(resp);
                }
            } else {
                final JsonObject resp = new JsonObject();
                resp.put("identifier", input == null ? "null" : input.getProvided());
                resp.put("reason", "invalid identifier");
                unmapped.add(resp);
                invalidCount++;
            }
        }

        recordIdentityMapStats(rc, inputList.length, invalidCount, optoutCount);

        final JsonObject resp = new JsonObject();
        resp.put("mapped", mapped);
        if (!unmapped.isEmpty()) resp.put("unmapped", unmapped);
        return resp;
    }

    private JsonObject processIdentityMapV3Response(RoutingContext rc, Map<String, InputUtil.InputVal[]> input) {
        RuntimeConfig config = getConfigFromRc(rc);
        IdentityEnvironment env = config.getIdentityEnvironment();

        final Instant now = Instant.now();
        final JsonObject mappedResponse = new JsonObject();
        int invalidCount = 0;
        int optoutCount = 0;
        int inputTotalCount = 0;

        for (Map.Entry<String, InputUtil.InputVal[]> identityType : input.entrySet()) {
            JsonArray mappedIdentityList = new JsonArray();
            final InputUtil.InputVal[] rawIdentityList = identityType.getValue();
            inputTotalCount += rawIdentityList.length;

            for (final InputUtil.InputVal rawId : rawIdentityList) {
                final JsonObject resp = new JsonObject();
                if (rawId != null && rawId.isValid()) {
                    final MappedIdentity mappedId = idService.mapIdentity(
                            new MapRequest(
                                    rawId.toUserIdentity(this.identityScope, 0, now),
                                    OptoutCheckPolicy.respectOptOut(),
                                    now,
                                    env));

                    if (mappedId.isOptedOut()) {
                        resp.put("e", IdentityMapResponseType.OPTOUT.getValue());
                        optoutCount++;
                    } else {
                        resp.put("u", EncodingUtils.toBase64String(mappedId.advertisingId));
                        resp.put("p", mappedId.previousAdvertisingId == null ? null : EncodingUtils.toBase64String(mappedId.previousAdvertisingId));
                        resp.put("r", mappedId.refreshFrom / SECOND_IN_MILLIS);
                    }
                } else {
                    resp.put("e", IdentityMapResponseType.INVALID_IDENTIFIER.getValue());
                    invalidCount++;
                }
                mappedIdentityList.add(resp);
            }
            mappedResponse.put(identityType.getKey(), mappedIdentityList);
        }

        recordIdentityMapStats(rc, inputTotalCount, invalidCount, optoutCount);

        return mappedResponse;
    }

    private boolean validateServiceLink(RoutingContext rc) {
        JsonObject requestJsonObject = (JsonObject) rc.data().get(REQUEST);
        if (this.secureLinkValidatorService.validateRequest(rc, requestJsonObject, Role.MAPPER)) {
            return true;
        }
        ResponseUtil.LogErrorAndSendResponse(ResponseStatus.Unauthorized, HttpStatus.SC_UNAUTHORIZED, rc, "Invalid link_id");
        return false;
    }

    private Future<Void> handleIdentityMapV2Async(RoutingContext rc) {
        return computeWorkerPool.executeBlocking(() -> {
            handleIdentityMapV2(rc);
            return null;
        });
    }

    private void handleIdentityMapV2(RoutingContext rc) {
        try {
            final Integer siteId = RoutingContextUtil.getSiteId(rc);
            final String apiContact = RoutingContextUtil.getApiContact(rc, clientKeyProvider);
            recordOperatorServedSdkUsage(rc, siteId, apiContact, rc.request().headers().get(Const.Http.ClientVersionHeader));

            final InputUtil.InputVal[] inputList = getIdentityMapV2Input(rc);
            if (inputList == null) {
                ResponseUtil.LogInfoAndSend400Response(rc, this.phoneSupport ? ERROR_INVALID_INPUT_WITH_PHONE_SUPPORT : ERROR_INVALID_INPUT_EMAIL_MISSING);
                return;
            }

            if (!validateServiceLink(rc)) { return; }

            final JsonObject resp = handleIdentityMapCommon(rc, inputList);
            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.UnknownError, 500, rc, "Unknown error while mapping identity v2", e);
        }
    }

    private InputUtil.InputVal[] getIdentityMapV2Input(RoutingContext rc) {
        final JsonObject obj = (JsonObject) rc.data().get("request");

        Supplier<InputUtil.InputVal[]> getInputList = null;
        final JsonArray emails = JsonParseUtils.parseArray(obj, "email", rc);
        if (emails != null && !emails.isEmpty()) {
            getInputList = () -> createInputList(emails, IdentityType.Email, InputUtil.IdentityInputType.Raw);
        }

        final JsonArray emailHashes = JsonParseUtils.parseArray(obj, "email_hash", rc);
        if (emailHashes != null && !emailHashes.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputList(emailHashes, IdentityType.Email, InputUtil.IdentityInputType.Hash);
        }

        final JsonArray phones = this.phoneSupport ? JsonParseUtils.parseArray(obj,"phone", rc) : null;
        if (phones != null && !phones.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputList(phones, IdentityType.Phone, InputUtil.IdentityInputType.Raw);
        }

        final JsonArray phoneHashes = this.phoneSupport ? JsonParseUtils.parseArray(obj,"phone_hash", rc) : null;
        if (phoneHashes != null && !phoneHashes.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputList(phoneHashes, IdentityType.Phone, InputUtil.IdentityInputType.Hash);
        }

        if (emails == null && emailHashes == null && phones == null && phoneHashes == null) {
            return null;
        }

        return getInputList == null ?
                createInputList(null, IdentityType.Email, InputUtil.IdentityInputType.Raw) :  // handle empty array
                getInputList.get();
    }

    private Future<Void> handleIdentityMapV3Async(RoutingContext rc) {
        return computeWorkerPool.executeBlocking(() -> {
            handleIdentityMapV3(rc);
            return null;
        });
    }

    private void handleIdentityMapV3(RoutingContext rc) {
        try {
            JsonObject jsonInput = (JsonObject) rc.data().get("request");

            if (jsonInput == null || jsonInput.isEmpty()) {
                ResponseUtil.LogInfoAndSend400Response(rc, phoneSupport ? ERROR_INVALID_MIXED_INPUT_WITH_PHONE_SUPPORT : ERROR_INVALID_MIXED_INPUT_EMAIL_MISSING);
                return;
            }

            IdentityMapV3Request input = OBJECT_MAPPER.readValue(jsonInput.toString(), IdentityMapV3Request.class);
            final Map<String, InputUtil.InputVal[]> normalizedInput = processIdentityMapMixedInput(rc, input);

            if (!validateServiceLink(rc)) { return; }

            final JsonObject response = processIdentityMapV3Response(rc, normalizedInput);
            ResponseUtil.SuccessV2(rc, response);
        } catch (ClassCastException | JsonProcessingException processingException) {
            ResponseUtil.LogInfoAndSend400Response(rc, "Incorrect request format");
        } catch (Exception e) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.UnknownError, 500, rc, "Unknown error while mapping identity v3", e);
        }
    }

    private Map<String, InputUtil.InputVal[]> processIdentityMapMixedInput(RoutingContext rc, IdentityMapV3Request input) {
        final Map<String, InputUtil.InputVal[]> normalizedIdentities = new HashMap<>();

        var normalizedEmails = parseIdentitiesInput(input.email(), IdentityType.Email, InputUtil.IdentityInputType.Raw, rc);
        normalizedIdentities.put("email", normalizedEmails);

        var normalizedEmailHashes = parseIdentitiesInput(input.email_hash(), IdentityType.Email, InputUtil.IdentityInputType.Hash, rc);
        normalizedIdentities.put("email_hash", normalizedEmailHashes);

        var normalizedPhones = parseIdentitiesInput(input.phone(), IdentityType.Phone, InputUtil.IdentityInputType.Raw, rc);
        normalizedIdentities.put("phone", normalizedPhones);

        var normalizedPhoneHashes = parseIdentitiesInput(input.phone_hash(), IdentityType.Phone, InputUtil.IdentityInputType.Hash, rc);
        normalizedIdentities.put("phone_hash", normalizedPhoneHashes);

        return normalizedIdentities;
    }

    private static String getApiContact(RoutingContext rc) {
        String apiContact;
        try {
            apiContact = (String) rc.data().get(AuthMiddleware.API_CONTACT_PROP);
            apiContact = apiContact == null ? "unknown" : apiContact;
        } catch (Exception ex) {
            apiContact = "error: " + ex.getMessage();
        }

        return apiContact;
    }

    private void recordIdentityMapStats(RoutingContext rc, int inputCount, int invalidCount, int optoutCount) {
        String apiContact = getApiContact(rc);

        DistributionSummary ds = _identityMapMetricSummaries.computeIfAbsent(apiContact, k -> DistributionSummary
                .builder("uid2_operator_identity_map_inputs")
                .description("number of emails or email hashes passed to identity map batch endpoint")
                .tags("api_contact", apiContact)
                .register(Metrics.globalRegistry));
        ds.record(inputCount);

        Tuple.Tuple2<Counter, Counter> ids = _identityMapUnmappedIdentifiers.computeIfAbsent(apiContact, k -> new Tuple.Tuple2<>(
                Counter.builder("uid2_operator_identity_map_unmapped_total")
                        .description("invalid identifiers")
                        .tags("api_contact", apiContact, "reason", "invalid")
                        .register(Metrics.globalRegistry),
                Counter.builder("uid2_operator_identity_map_unmapped_total")
                        .description("optout identifiers")
                        .tags("api_contact", apiContact, "reason", "optout")
                        .register(Metrics.globalRegistry)));
        if (invalidCount > 0) ids.getItem1().increment(invalidCount);
        if (optoutCount > 0) ids.getItem2().increment(optoutCount);

        Counter rs = _identityMapRequestWithUnmapped.computeIfAbsent(apiContact, k -> Counter
                .builder("uid2_operator_identity_map_unmapped_requests_total")
                .description("number of requests with unmapped identifiers")
                .tags("api_contact", apiContact)
                .register(Metrics.globalRegistry));
        if (invalidCount > 0 || optoutCount > 0) {
            rs.increment();
        }
        recordIdentityMapStatsForServiceLinks(rc, apiContact, inputCount, invalidCount, optoutCount);
    }

    private void recordIdentityMapStatsForServiceLinks(RoutingContext rc, String apiContact, int inputCount,
                                                       int invalidCount, int optOutCount) {
        // If request is from a service, break it down further by link_id
        String serviceLinkName = rc.get(SecureLinkValidatorService.SERVICE_LINK_NAME, "");
        if (!serviceLinkName.isBlank()) {
            // serviceName will be non-empty as it will be inserted during validation
            final String serviceName = rc.get(SecureLinkValidatorService.SERVICE_NAME);
            final String metricKey = serviceName + serviceLinkName;
            DistributionSummary ds = _identityMapMetricSummaries.computeIfAbsent(metricKey,
                    k -> DistributionSummary.builder("uid2_operator_identity_map_services_inputs")
                            .description("number of emails or phone numbers passed to identity map batch endpoint by services")
                            .tags(Arrays.asList(Tag.of("api_contact", apiContact),
                                    Tag.of("service_name", serviceName),
                                    Tag.of("service_link_name", serviceLinkName)))
                            .register(Metrics.globalRegistry));
            ds.record(inputCount);

            Tuple.Tuple2<Counter, Counter> counterTuple = _identityMapUnmappedIdentifiers.computeIfAbsent(metricKey,
                    k -> new Tuple.Tuple2<>(
                            Counter.builder("uid2_operator_identity_map_services_unmapped_total")
                                    .description("number of invalid identifiers passed to identity map batch endpoint by services")
                                    .tags(Arrays.asList(Tag.of("api_contact", apiContact),
                                            Tag.of("reason", "invalid"),
                                            Tag.of("service_name", serviceName),
                                            Tag.of("service_link_name", serviceLinkName)))
                                    .register(Metrics.globalRegistry),
                            Counter.builder("uid2_operator_identity_map_services_unmapped_total")
                                    .description("number of optout identifiers passed to identity map batch endpoint by services")
                                    .tags(Arrays.asList(Tag.of("api_contact", apiContact),
                                            Tag.of("reason", "optout"),
                                            Tag.of("service_name", serviceName),
                                            Tag.of("service_link_name", serviceLinkName)))
                                    .register(Metrics.globalRegistry)));
            if (invalidCount > 0) counterTuple.getItem1().increment(invalidCount);
            if (optOutCount > 0) counterTuple.getItem2().increment(optOutCount);
        }
    }

    private List<String> parseOptoutStatusRequestPayload(RoutingContext rc) {
        final JsonObject requestObj = (JsonObject) rc.data().get("request");
        if (requestObj == null) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.ClientError, HttpStatus.SC_BAD_REQUEST, rc, "Invalid request body");
            return null;
        }
        final JsonArray rawUidsJsonArray = requestObj.getJsonArray("advertising_ids");
        if (rawUidsJsonArray == null) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.ClientError, HttpStatus.SC_BAD_REQUEST, rc, "Required Parameter Missing: advertising_ids");
            return null;
        }
        if (rawUidsJsonArray.size() > optOutStatusMaxRequestSize) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.ClientError, HttpStatus.SC_BAD_REQUEST, rc, "Request payload is too large");
            return null;
        }
        List<String> rawUID2sInputList = new ArrayList<>(rawUidsJsonArray.size());
        for (int i = 0; i < rawUidsJsonArray.size(); ++i) {
            rawUID2sInputList.add(rawUidsJsonArray.getString(i));
        }
        return rawUID2sInputList;
    }

    private void handleOptoutStatus(RoutingContext rc) {
        try {
            // Parse request to get list of raw UID2 strings
            List<String> rawUID2sInput = parseOptoutStatusRequestPayload(rc);
            if (rawUID2sInput == null) {
                return;
            }
            final JsonArray optedOutJsonArray = new JsonArray();
            for (String rawUId : rawUID2sInput) {
                // Call opt out service to get timestamp of opted out identities
                long timestamp = optOutStore.getOptOutTimestampByAdId(rawUId);
                if (timestamp != -1) {
                    JsonObject optOutJsonObj = new JsonObject();
                    optOutJsonObj.put("advertising_id", rawUId);
                    optOutJsonObj.put("opted_out_since", Instant.ofEpochSecond(timestamp).toEpochMilli());
                    optedOutJsonArray.add(optOutJsonObj);
                }
            }
            // Create response and return
            final JsonObject bodyJsonObj = new JsonObject();
            bodyJsonObj.put("opted_out", optedOutJsonArray);
            ResponseUtil.SuccessV2(rc, bodyJsonObj);
            recordOptOutStatusEndpointStats(rc, rawUID2sInput.size(), optedOutJsonArray.size());
        } catch (Exception e) {
            ResponseUtil.LogErrorAndSendResponse(ResponseStatus.UnknownError, 500, rc,
                    "Unknown error while getting optout status", e);
        }
    }

    private void recordOptOutStatusEndpointStats(RoutingContext rc, int inputCount, int optOutCount) {
        String apiContact = getApiContact(rc);
        DistributionSummary inputDistSummary = optOutStatusCounters.computeIfAbsent(apiContact, k -> DistributionSummary
                .builder("uid2_operator_optout_status_input_size")
                .description("number of UIDs received in request")
                .tags("api_contact", apiContact)
                .register(Metrics.globalRegistry));
        inputDistSummary.record(inputCount);

        DistributionSummary optOutDistSummary = optOutStatusCounters.computeIfAbsent(apiContact, k -> DistributionSummary
                .builder("uid2_operator_optout_status_optout_size")
                .description("number of UIDs that have opted out")
                .tags("api_contact", apiContact)
                .register(Metrics.globalRegistry));
        optOutDistSummary.record(optOutCount);
    }

    public TokenVersion getRefreshTokenVersion(String s) {
        if (s != null && !s.isEmpty()) {
            final byte[] bytes = EncodingUtils.fromBase64(s);
            final Buffer b = Buffer.buffer(bytes);
            if (b.getByte(1) == TokenVersion.V3.rawVersion) {
                return TokenVersion.V3;
            } else if (b.getByte(0) == TokenVersion.V2.rawVersion) {
                return TokenVersion.V2;
            }
        }
        return null;
    }

    private void recordRefreshTokenVersionCount(String siteId, TokenVersion tokenVersion) {
        Counter.builder("uid2_refresh_token_received_count_total")
                .description(String.format("Counter for the amount of refresh token %s received", tokenVersion.toString().toLowerCase()))
                .tags("site_id", siteId)
                .tags("refresh_token_version", tokenVersion.toString().toLowerCase())
                .register(Metrics.globalRegistry).increment();
    }

    private RefreshResponse refreshIdentity(RoutingContext rc, String tokenStr) {
        final RefreshToken refreshToken;
        try {
            if (AuthMiddleware.isAuthenticated(rc)) {
                rc.put(Const.RoutingContextData.SiteId, AuthMiddleware.getAuthClient(ClientKey.class, rc).getSiteId());
            }
            refreshToken = this.encoder.decodeRefreshToken(tokenStr);
        } catch (ClientInputValidationException cie) {
            LOGGER.warn("Failed to decode refresh token for site ID: " + rc.data().get(Const.RoutingContextData.SiteId), cie);
            return RefreshResponse.Invalid;
        }
        if (refreshToken == null) {
            return RefreshResponse.Invalid;
        }
        if (!AuthMiddleware.isAuthenticated(rc)) {
            rc.put(Const.RoutingContextData.SiteId, refreshToken.publisherIdentity.siteId);
        }
        recordRefreshTokenVersionCount(String.valueOf(rc.data().get(Const.RoutingContextData.SiteId)), this.getRefreshTokenVersion(tokenStr));

        RuntimeConfig config = this.getConfigFromRc(rc);
        Duration refreshIdentityAfter = Duration.ofSeconds(config.getRefreshIdentityTokenAfterSeconds());
        Duration refreshExpiresAfter = Duration.ofSeconds(config.getRefreshTokenExpiresAfterSeconds());
        Duration identityExpiresAfter = Duration.ofSeconds(config.getIdentityTokenExpiresAfterSeconds());
        IdentityEnvironment identityEnvironment = config.getIdentityEnvironment();

        return this.idService.refreshIdentity(refreshToken, refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter, identityEnvironment);
    }

    public static String getSiteName(ISiteStore siteStore, Integer siteId) {
        if (siteId == null) return "unknown";
        if (siteStore == null) return "unknown"; //this is expected if CSTG is not enabled, eg for private operators

        final Site site = siteStore.getSite(siteId);
        return (site == null) ? "unknown" : site.getName();
    }

    private TokenResponseStatsCollector.PlatformType getPlatformType(RoutingContext rc) {
        final String clientVersionHeader = rc.request().getHeader(Const.Http.ClientVersionHeader);
        if (clientVersionHeader != null) {
            for (String supportedVersion : SUPPORTED_IN_APP) {
                if (clientVersionHeader.contains(supportedVersion)) {
                    return TokenResponseStatsCollector.PlatformType.InApp;
                }
            }
        }

        final String origin = rc.request().getHeader(ORIGIN_HEADER);

        return origin != null ? TokenResponseStatsCollector.PlatformType.HasOriginHeader : TokenResponseStatsCollector.PlatformType.Other;
    }

    private void recordRefreshDurationStats(Integer siteId, String apiContact, Duration durationSinceLastRefresh, boolean hasOriginHeader, Duration identityExpiresAfter) {
        DistributionSummary ds = _refreshDurationMetricSummaries.computeIfAbsent(new Tuple.Tuple2<>(apiContact, hasOriginHeader), k ->
                DistributionSummary
                        .builder("uid2_token_refresh_duration_seconds")
                        .description("duration between token refreshes")
                        .tag("site_id", String.valueOf(siteId))
                        .tag("site_name", getSiteName(siteProvider, siteId))
                        .tag("api_contact", apiContact)
                        .tag("has_origin_header", hasOriginHeader ? "true" : "false")
                        .register(Metrics.globalRegistry)
        );
        ds.record(durationSinceLastRefresh.getSeconds());

        boolean isExpired = durationSinceLastRefresh.compareTo(identityExpiresAfter) > 0;
        Counter c = _advertisingTokenExpiryStatus.computeIfAbsent(new Tuple.Tuple3<>(String.valueOf(siteId), hasOriginHeader, isExpired), k ->
                Counter
                        .builder("uid2_advertising_token_expired_on_refresh_total")
                        .description("status of advertiser token expiry")
                        .tag("site_id", String.valueOf(siteId))
                        .tag("site_name", getSiteName(siteProvider, siteId))
                        .tag("has_origin_header", hasOriginHeader ? "true" : "false")
                        .tag("is_expired", isExpired ? "true" : "false")
                        .register(Metrics.globalRegistry)
        );
        c.increment();
    }

    private InputUtil.InputVal[] createInputList(JsonArray a, IdentityType identityType, InputUtil.IdentityInputType inputType) {
        if (a == null || a.isEmpty()) {
            return new InputUtil.InputVal[0];
        }
        final int size = a.size();
        final InputUtil.InputVal[] resp = new InputUtil.InputVal[size];

        for (int i = 0; i < size; i++) {
            resp[i] = normalizeIdentity(a.getString(i), identityType, inputType);
        }

        return resp;
    }

    private InputUtil.InputVal normalizeIdentity(String identity, IdentityType identityType, InputUtil.IdentityInputType inputType) {
        return switch (identityType) {
            case Email -> switch (inputType) {
                case Raw -> InputUtil.normalizeEmail(identity);
                case Hash -> InputUtil.normalizeEmailHash(identity);
            };
            case Phone -> switch (inputType) {
                case Raw -> InputUtil.normalizePhone(identity);
                case Hash -> InputUtil.normalizePhoneHash(identity);
            };
        };
    }

    private InputUtil.InputVal[] parseIdentitiesInput(String[] identities, IdentityType identityType, InputUtil.IdentityInputType inputType, RoutingContext rc) {
        if (identities == null || identities.length == 0) {
            return new InputUtil.InputVal[0];
        }
        final var normalizedIdentities = new InputUtil.InputVal[identities.length];

        for (int i = 0; i < identities.length; i++) {
            normalizedIdentities[i] = normalizeIdentity(identities[i], identityType, inputType);
        }

        return normalizedIdentities;
    }

    private UserConsentStatus validateUserConsent(JsonObject req, String apiContact) {
        // TCF string is an optional parameter, and we should only check tcf if in EUID and the string is present
        if (identityScope.equals(IdentityScope.EUID) && req.containsKey("tcf_consent_string")) {
            recordTokenGenerateTCFUsage(apiContact);
            TransparentConsentParseResult tcResult = this.getUserConsentV2(req);
            if (!tcResult.isSuccess()) {
                return UserConsentStatus.INVALID;
            }
            final boolean userConsent = tcResult.getTCString().hasConsent(tcfVendorId,
                    TransparentConsentPurpose.STORE_INFO_ON_DEVICE,             // 1
                    TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,  // 3
                    TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,          // 4
                    TransparentConsentPurpose.SELECT_BASIC_ADS,                 // 2
                    TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,           // 7
                    TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS      // 10
            );
            final boolean allowPreciseGeo = tcResult.getTCString().hasSpecialFeature(TransparentConsentSpecialFeature.PreciseGeolocationData);

            if (!userConsent || !allowPreciseGeo) {
                return UserConsentStatus.INSUFFICIENT;
            }
        }

        return UserConsentStatus.SUFFICIENT;
    }

    private static final String POLICY_PARAM = "policy";
    private static final String OPTOUT_CHECK_POLICY_PARAM = "optout_check";

    private boolean meetPolicyCheckRequirements(RoutingContext rc) {
        JsonObject requestJsonObject = (JsonObject) rc.data().get(REQUEST);
        boolean respectOptOut = false;
        if (requestJsonObject.containsKey(OPTOUT_CHECK_POLICY_PARAM)) {
            respectOptOut = OptoutCheckPolicy.fromValue(requestJsonObject.getInteger(OPTOUT_CHECK_POLICY_PARAM)) == OptoutCheckPolicy.respectOptOut();
        } else if (requestJsonObject.containsKey(POLICY_PARAM)) {
            respectOptOut = OptoutCheckPolicy.fromValue(requestJsonObject.getInteger(POLICY_PARAM)) == OptoutCheckPolicy.respectOptOut();
        }

        final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(rc);
        final ClientKey oldestClientKey = this.clientKeyProvider.getOldestClientKey(clientKey.getSiteId());
        boolean newClient = oldestClientKey.getCreated() >= OPT_OUT_CHECK_CUTOFF_DATE;

        if (newClient && !respectOptOut) {
            // log policy violation
            LOGGER.warn(String.format("Failed to respect opt-out policy: siteId=%d, clientKeyName=%s, clientKeyCreated=%d",
                    oldestClientKey.getSiteId(), oldestClientKey.getName(), oldestClientKey.getCreated()));
            return false;
        }
        return true;
    }

    private Tuple.Tuple2<OptoutCheckPolicy, String> readOptoutCheckPolicy(JsonObject req) {
        if(req.containsKey(OPTOUT_CHECK_POLICY_PARAM)) {
            return new Tuple.Tuple2<>(OptoutCheckPolicy.fromValue(req.getInteger(OPTOUT_CHECK_POLICY_PARAM)), OPTOUT_CHECK_POLICY_PARAM);
        } else if(req.containsKey(POLICY_PARAM)) {
            return new Tuple.Tuple2<>(OptoutCheckPolicy.fromValue(req.getInteger(POLICY_PARAM)), POLICY_PARAM);
        } else {
            return new Tuple.Tuple2<>(OptoutCheckPolicy.defaultPolicy(), "null");
        }
    }

    private void recordTokenGeneratePolicy(String apiContact, OptoutCheckPolicy policy, String policyParameterKey) {
        _tokenGeneratePolicyCounters.computeIfAbsent(new Tuple.Tuple3<>(apiContact, policy, policyParameterKey), triple -> Counter
                .builder("uid2_token_generate_policy_usage_total")
                .description("Counter for token generate policy usage")
                .tags("api_contact", triple.getItem1(), "policy", String.valueOf(triple.getItem2()), "policy_parameter", triple.getItem3())
                .register(Metrics.globalRegistry)).increment();
    }

    private void recordTokenGenerateTCFUsage(String apiContact) {
        _tokenGenerateTCFUsage.computeIfAbsent(apiContact, contact -> Counter
                .builder("uid2_token_generate_tcf_usage_total")
                .description("Counter for token generate tcf usage")
                .tags("api_contact", contact)
                .register(Metrics.globalRegistry)).increment();
    }

    private TransparentConsentParseResult getUserConsentV2(JsonObject req) {
        final String rawTcString = req.getString("tcf_consent_string");
        if (rawTcString == null || rawTcString.isEmpty()) {
            return new TransparentConsentParseResult("empty tcf_consent_string");
        }

        try {
            final TransparentConsent consentPayload = new TransparentConsent(rawTcString);
            return new TransparentConsentParseResult(consentPayload);
        } catch (ClientInputValidationException e) {
            return new TransparentConsentParseResult(e.getMessage());
        }
    }

    private JsonObject toTokenResponseJson(IdentityTokens t) {
        final JsonObject json = new JsonObject();
        json.put("advertising_token", t.getAdvertisingToken());
        json.put("refresh_token", t.getRefreshToken());
        json.put("identity_expires", t.getIdentityExpires().toEpochMilli());
        json.put("refresh_expires", t.getRefreshExpires().toEpochMilli());
        json.put("refresh_from", t.getRefreshFrom().toEpochMilli());
        return json;
    }

    private static MissingAclMode getMissingAclMode(ClientKey clientKey) {
        return clientKey.hasRole(Role.ID_READER) ? MissingAclMode.ALLOW_ALL : MissingAclMode.DENY_ALL;
    }

    /**
     * Returns the keyset keys that can be accessed by the site belonging to the specified client key.
     * Keyset keys belonging to the master keyset can be accessed by any site.
     */
    private static List<KeysetKey> getAccessibleKeys(List<KeysetKey> keys, KeyManagerSnapshot keyManagerSnapshot, ClientKey clientKey) {
        final MissingAclMode mode = getMissingAclMode(clientKey);
        final KeysetSnapshot keysetSnapshot = keyManagerSnapshot.getKeysetSnapshot();

        return keys.stream()
                .filter(key -> key.getKeysetId() == Data.MasterKeysetId || keysetSnapshot.canClientAccessKey(clientKey, key, mode))
                .collect(Collectors.toList());
    }

    private JsonArray getAccessibleKeysAsJson(List<KeysetKey> keys, ClientKey clientKey) {
        KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
        Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();

        final JsonArray a = new JsonArray();
        for (KeysetKey k : getAccessibleKeys(keys, keyManagerSnapshot, clientKey)) {
            final JsonObject o = toJson(k);
            o.put("site_id", keysetMap.get(k.getKeysetId()).getSiteId());
            a.add(o);
        }
        return a;
    }

    /**
     * Converts the specified keyset key to a JSON object.
     * Includes the following fields: id, created, activates, expires, and secret.
     */
    private static JsonObject toJson(KeysetKey key) {
        final JsonObject json = new JsonObject();
        json.put("id", key.getId());
        json.put("created", key.getCreated().getEpochSecond());
        json.put("activates", key.getActivates().getEpochSecond());
        json.put("expires", key.getExpires().getEpochSecond());
        json.put("secret", EncodingUtils.toBase64String(key.getKeyBytes()));
        return json;
    }

    private void logInvalidOriginOrAppName(int siteId, String originOrAppName) {
        siteIdToInvalidOriginsAndAppNames.computeIfAbsent(siteId, k -> new HashSet<>())
                .add(originOrAppName);

        if (Duration.between(lastInvalidOriginProcessTime, Instant.now()).compareTo(Duration.ofMinutes(60)) >= 0) {
            lastInvalidOriginProcessTime = Instant.now();
            LOGGER.info(generateInvalidOriginAndAppNameMessage(siteIdToInvalidOriginsAndAppNames));
            siteIdToInvalidOriginsAndAppNames.clear();
        }
    }

    private String generateInvalidOriginAndAppNameMessage(Map<Integer, Set<String>> siteIdToInvalidOriginsAndAppNames) {
        List<String> logEntries = new ArrayList<>();
        for (Map.Entry<Integer, Set<String>> entry : siteIdToInvalidOriginsAndAppNames.entrySet()) {
            int siteId = entry.getKey();
            Set<String> origins = entry.getValue();
            String siteName = getSiteName(siteProvider, siteId);
            logEntries.add("site " + siteName + " (" + siteId + "): " + String.join(", ", origins));
        }
        return "InvalidHttpOriginAndAppName: " +
                String.join(" | ", logEntries);
    }

    public enum UserConsentStatus {
        SUFFICIENT,
        INSUFFICIENT,
        INVALID,
    }
}
