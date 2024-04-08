package com.uid2.operator.vertx;

import com.uid2.operator.Const;
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
import com.uid2.operator.util.DomainNameCheckUtil;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.operator.util.Tuple;
import com.uid2.shared.Const.Data;
import com.uid2.shared.Utils;
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
import com.uid2.shared.store.ISaltProvider;
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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
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

import static com.uid2.operator.IdentityConst.*;
import static com.uid2.operator.service.ResponseUtil.*;

public class UIDOperatorVerticle extends AbstractVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorVerticle.class);
    public static final long MAX_REQUEST_BODY_SIZE = 1 << 20; // 1MB
    /**
     * There is currently an issue with v2 tokens (and possibly also other ad token versions) where the token lifetime
     * is slightly longer than it should be. When validating token lifetimes, we add a small buffer to account for this.
     */
    public static final Duration TOKEN_LIFETIME_TOLERANCE = Duration.ofSeconds(10);
    private static final DateTimeFormatter APIDateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.of("UTC"));

    private static final String REQUEST = "request";
    private final HealthComponent healthComponent = HealthManager.instance.registerComponent("http-server");
    private final Cipher aesGcm;
    private final JsonObject config;
    private final boolean clientSideTokenGenerate;
    private final AuthMiddleware auth;
    private final ISiteStore siteProvider;
    private final IClientSideKeypairStore clientSideKeypairProvider;
    private final ITokenEncoder encoder;
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final IClientKeyProvider clientKeyProvider;
    private final Clock clock;
    protected IUIDOperatorService idService;
    private final Map<String, DistributionSummary> _identityMapMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple2<String, Boolean>, DistributionSummary> _refreshDurationMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple3<String, Boolean, Boolean>, Counter> _advertisingTokenExpiryStatus = new HashMap<>();
    private final Map<Tuple.Tuple3<String, OptoutCheckPolicy, String>, Counter> _tokenGeneratePolicyCounters = new HashMap<>();
    private final Map<String, Tuple.Tuple2<Counter, Counter>> _identityMapUnmappedIdentifiers = new HashMap<>();
    private final Map<String, Counter> _identityMapRequestWithUnmapped = new HashMap<>();
    private final IdentityScope identityScope;
    private final V2PayloadHandler v2PayloadHandler;
    private final boolean phoneSupport;
    private final int tcfVendorId;
    private final IStatsCollectorQueue _statsCollectorQueue;
    private final KeyManager keyManager;
    private final SecureLinkValidatorService secureLinkValidatorService;
    private final boolean cstgDoDomainNameCheck;
    private final boolean clientSideTokenGenerateLogInvalidHttpOrigin;
    public final static int MASTER_KEYSET_ID_FOR_SDKS = 9999999; //this is because SDKs have an issue where they assume keyset ids are always positive; that will be fixed.
    public final static long OPT_OUT_CHECK_CUTOFF_DATE = Instant.parse("2023-09-01T00:00:00.00Z").getEpochSecond();
    private final Handler<Boolean> saltRetrievalResponseHandler;

    private final int maxBidstreamLifetimeSeconds;
    private final int allowClockSkewSeconds;
    protected int maxSharingLifetimeSeconds;
    protected boolean keySharingEndpointProvideSiteDomainNames;
    protected Map<Integer, Set<String>> siteIdToInvalidOrigins = new HashMap<>();
    protected Instant lastInvalidOriginProcessTime = Instant.now();

    public UIDOperatorVerticle(JsonObject config,
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
                               Handler<Boolean> saltRetrievalResponseHandler) {
        this.keyManager = keyManager;
        this.secureLinkValidatorService = secureLinkValidatorService;
        try {
            aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        this.config = config;
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
        this.v2PayloadHandler = new V2PayloadHandler(keyManager, config.getBoolean("enable_v2_encryption", true), this.identityScope, siteProvider);
        this.phoneSupport = config.getBoolean("enable_phone_support", true);
        this.tcfVendorId = config.getInteger("tcf_vendor_id", 21);
        this.cstgDoDomainNameCheck = config.getBoolean("client_side_token_generate_domain_name_check_enabled", true);
        this.keySharingEndpointProvideSiteDomainNames = config.getBoolean("key_sharing_endpoint_provide_site_domain_names", false);
        this._statsCollectorQueue = statsCollectorQueue;
        this.clientKeyProvider = clientKeyProvider;
        this.clientSideTokenGenerateLogInvalidHttpOrigin = config.getBoolean("client_side_token_generate_log_invalid_http_origins", false);
        final Integer identityTokenExpiresAfterSeconds = config.getInteger(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        this.maxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp, identityTokenExpiresAfterSeconds);
        if (this.maxBidstreamLifetimeSeconds < identityTokenExpiresAfterSeconds) {
            LOGGER.error("Max bidstream lifetime seconds ({} seconds) is less than identity token lifetime ({} seconds)", maxBidstreamLifetimeSeconds, identityTokenExpiresAfterSeconds);
            throw new RuntimeException("Max bidstream lifetime seconds is less than identity token lifetime seconds");
        }
        this.allowClockSkewSeconds = config.getInteger(Const.Config.AllowClockSkewSecondsProp, 1800);
        this.maxSharingLifetimeSeconds = config.getInteger(Const.Config.MaxSharingLifetimeProp, config.getInteger(Const.Config.SharingTokenExpiryProp));
        this.saltRetrievalResponseHandler = saltRetrievalResponseHandler;
    }

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        this.healthComponent.setHealthStatus(false, "still starting");
        this.idService = new UIDOperatorService(
                this.config,
                this.optOutStore,
                this.saltProvider,
                this.encoder,
                this.clock,
                this.identityScope,
                this.saltRetrievalResponseHandler
        );

        final Router router = createRoutesSetup();
        final int port = Const.Port.ServicePortForOperator + Utils.getPortOffset();
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(port, result -> {
                    if (result.succeeded()) {
                        this.healthComponent.setHealthStatus(true);
                        startPromise.complete();
                    } else {
                        this.healthComponent.setHealthStatus(false, result.cause().getMessage());
                        startPromise.fail(result.cause());
                    }

                    LOGGER.info("UIDOperatorVerticle instance started on HTTP port: {}", port);
                });

    }

    private Router createRoutesSetup() throws IOException {
        final Router router = Router.router(vertx);

        router.allowForward(AllowForwardHeaders.X_FORWARD);
        router.route().handler(new RequestCapturingHandler());
        router.route().handler(new ClientVersionCapturingHandler("static/js", "*.js"));
        router.route().handler(CorsHandler.create()
                .addRelativeOrigin(".*.")
                .allowedMethod(io.vertx.core.http.HttpMethod.GET)
                .allowedMethod(io.vertx.core.http.HttpMethod.POST)
                .allowedMethod(io.vertx.core.http.HttpMethod.OPTIONS)
                .allowedHeader(Const.Http.ClientVersionHeader)
                .allowedHeader("Access-Control-Request-Method")
                .allowedHeader("Access-Control-Allow-Credentials")
                .allowedHeader("Access-Control-Allow-Origin")
                .allowedHeader("Access-Control-Allow-Headers")
                .allowedHeader("Content-Type"));
        router.route().handler(new StatsCollectorHandler(_statsCollectorQueue, vertx));
        router.route("/static/*").handler(StaticHandler.create("static"));
        router.route().failureHandler(new GenericFailureHandler());

        final BodyHandler bodyHandler = BodyHandler.create().setHandleFileUploads(false).setBodyLimit(MAX_REQUEST_BODY_SIZE);
        setupV2Routes(router, bodyHandler);

        // Static and health check
        router.get("/ops/healthcheck").handler(this::handleHealthCheck);

        if (this.config.getBoolean(Const.Config.AllowLegacyAPIProp, true)) {
            // V1 APIs
            router.get("/v1/token/generate").handler(auth.handleV1(this::handleTokenGenerateV1, Role.GENERATOR));
            router.get("/v1/token/validate").handler(this::handleTokenValidateV1);
            router.get("/v1/token/refresh").handler(auth.handleWithOptionalAuth(this::handleTokenRefreshV1));
            router.get("/v1/identity/buckets").handler(auth.handle(this::handleBucketsV1, Role.MAPPER));
            router.get("/v1/identity/map").handler(auth.handle(this::handleIdentityMapV1, Role.MAPPER));
            router.post("/v1/identity/map").handler(bodyHandler).handler(auth.handle(this::handleIdentityMapBatchV1, Role.MAPPER));
            router.get("/v1/key/latest").handler(auth.handle(this::handleKeysRequestV1, Role.ID_READER));

            // Deprecated APIs
            router.get("/key/latest").handler(auth.handle(this::handleKeysRequest, Role.ID_READER));
            router.get("/token/generate").handler(auth.handle(this::handleTokenGenerate, Role.GENERATOR));
            router.get("/token/refresh").handler(this::handleTokenRefresh);
            router.get("/token/validate").handler(this::handleValidate);
            router.get("/identity/map").handler(auth.handle(this::handleIdentityMap, Role.MAPPER));
            router.post("/identity/map").handler(bodyHandler).handler(auth.handle(this::handleIdentityMapBatch, Role.MAPPER));

            // Internal service APIs
            router.get("/token/logout").handler(auth.handle(this::handleLogoutAsync, Role.OPTOUT));

            // only uncomment to do local testing
            //router.get("/internal/optout/get").handler(auth.loopbackOnly(this::handleOptOutGet));

        }

        return router;
    }

    private void setupV2Routes(Router mainRouter, BodyHandler bodyHandler) {
        final Router v2Router = Router.router(vertx);

        v2Router.post("/token/generate").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handleTokenGenerate(rc, this::handleTokenGenerateV2), Role.GENERATOR));
        v2Router.post("/token/refresh").handler(bodyHandler).handler(auth.handleWithOptionalAuth(
                rc -> v2PayloadHandler.handleTokenRefresh(rc, this::handleTokenRefreshV2)));
        v2Router.post("/token/validate").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleTokenValidateV2), Role.GENERATOR));
        v2Router.post("/identity/buckets").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleBucketsV2), Role.MAPPER));
        v2Router.post("/identity/map").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleIdentityMapV2), Role.MAPPER));
        v2Router.post("/key/latest").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleKeysRequestV2), Role.ID_READER));
        v2Router.post("/key/sharing").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleKeysSharing), Role.SHARER, Role.ID_READER));
        v2Router.post("/key/bidstream").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handle(rc, this::handleKeysBidstream), Role.ID_READER));
        v2Router.post("/token/logout").handler(bodyHandler).handler(auth.handleV1(
                rc -> v2PayloadHandler.handleAsync(rc, this::handleLogoutAsyncV2), Role.OPTOUT));


        if (this.clientSideTokenGenerate)
            v2Router.post("/token/client-generate").handler(bodyHandler).handler(this::handleClientSideTokenGenerate);

        mainRouter.route("/v2/*").subRouter(v2Router);
    }


    private void handleClientSideTokenGenerate(RoutingContext rc) {
        try {
            handleClientSideTokenGenerateImpl(rc);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while handling client side token generate", null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }


    private Set<String> getDomainNameListForClientSideTokenGenerate(ClientSideKeypair keypair) {
        Site s = siteProvider.getSite(keypair.getSiteId());
        if (s == null) {
            return Collections.emptySet();
        } else {
            return s.getDomainNames();
        }
    }

    private void handleClientSideTokenGenerateImpl(RoutingContext rc) throws NoSuchAlgorithmException, InvalidKeyException {
        final JsonObject body;
        try {
            body = rc.body().asJsonObject();
        } catch (DecodeException ex) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "json payload is not valid",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadJsonPayload, siteProvider);
            return;
        }

        if (body == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "json payload expected but not found",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.PayloadHasNoBody, siteProvider);
            return;
        }

        final CstgRequest request = body.mapTo(CstgRequest.class);

        final ClientSideKeypair clientSideKeypair = this.clientSideKeypairProvider.getSnapshot().getKeypair(request.getSubscriptionId());
        if (clientSideKeypair == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad subscription_id",
                    null, TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadSubscriptionId, siteProvider);
            return;
        }

        if (cstgDoDomainNameCheck) {
            final Set<String> domainNames = getDomainNameListForClientSideTokenGenerate(clientSideKeypair);
            String origin = rc.request().getHeader("origin");

            boolean allowedDomain = DomainNameCheckUtil.isDomainNameAllowed(origin, domainNames);
            if (!allowedDomain) {
                if (clientSideTokenGenerateLogInvalidHttpOrigin) {
                    handleInvalidHttpOriginError(clientSideKeypair.getSiteId(), origin);
                }
                SendClientErrorResponseAndRecordStats(ResponseStatus.InvalidHttpOrigin, 403, rc, "unexpected http origin", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin, siteProvider);
                return;
            }
        }

        if (request.getPayload() == null || request.getIv() == null || request.getPublicKey() == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "required parameters: payload, iv, public_key", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider);
            return;
        }

        final KeyFactory kf = KeyFactory.getInstance("EC");

        final PublicKey clientPublicKey;
        try {
            final byte[] clientPublicKeyBytes = Base64.getDecoder().decode(request.getPublicKey());
            final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPublicKeyBytes);
            clientPublicKey = kf.generatePublic(pkSpec);
        } catch (Exception e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad public key", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPublicKey, siteProvider);
            return;
        }

        // Perform key agreement
        final KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(clientSideKeypair.getPrivateKey());
        ka.doPhase(clientPublicKey, true);

        // Read shared secret
        final byte[] sharedSecret = ka.generateSecret();

        final byte[] ivBytes;
        try {
            ivBytes = Base64.getDecoder().decode(request.getIv());
            if (ivBytes.length != 12) {
                SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad iv", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV, siteProvider);
                return;
            }
        } catch (IllegalArgumentException e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "bad iv", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV, siteProvider);
            return;
        }

        final byte[] aad = new JsonArray(List.of(request.getTimestamp())).toBuffer().getBytes();

        final byte[] requestPayloadBytes;
        try {
            final byte[] encryptedPayloadBytes = Base64.getDecoder().decode(request.getPayload());
            final byte[] ivAndCiphertext = Arrays.copyOf(ivBytes, 12 + encryptedPayloadBytes.length);
            System.arraycopy(encryptedPayloadBytes, 0, ivAndCiphertext, 12, encryptedPayloadBytes.length);
            requestPayloadBytes = decrypt(ivAndCiphertext, 0, sharedSecret, aad);
        } catch (Exception e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "payload decryption failed", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }

        final JsonObject requestPayload;
        try {
            requestPayload = new JsonObject(Buffer.buffer(Unpooled.wrappedBuffer(requestPayloadBytes)));
        } catch (DecodeException e) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "encrypted payload contains invalid json", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }

        final String emailHash = requestPayload.getString("email_hash");
        final String phoneHash = requestPayload.getString("phone_hash");
        final int optoutCheck = requestPayload.getInteger("optout_check", 0);
        final boolean cstgRequestHasOptoutCheckFlag = optoutCheck == OptoutCheckPolicy.RespectOptOut.ordinal();
        final InputUtil.InputVal input;


        if (phoneHash != null && !phoneSupport) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "phone support not enabled", clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }

        final String errString = phoneSupport ?  "please provide exactly one of: email_hash, phone_hash" : "please provide email_hash";
        if (emailHash == null && phoneHash == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, errString, clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider);
            return;
        }
        else if (emailHash != null && phoneHash != null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, errString, clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }
        else if(emailHash != null) {
            input = InputUtil.normalizeEmailHash(emailHash);
        }
        else {
            input = InputUtil.normalizePhoneHash(phoneHash);
        }

        PrivacyBits privacyBits = new PrivacyBits();
        privacyBits.setLegacyBit();
        privacyBits.setClientSideTokenGenerate();

        if(cstgRequestHasOptoutCheckFlag) {
            privacyBits.setClientSideTokenGenerateOptoutResponse();
        }

        IdentityTokens identityTokens = this.idService.generateIdentity(
                new IdentityRequest(
                        new PublisherIdentity(clientSideKeypair.getSiteId(), 0, 0),
                        input.toUserIdentity(this.identityScope, privacyBits.getAsInt(), Instant.now()),
                        OptoutCheckPolicy.RespectOptOut));

        JsonObject response;
        TokenResponseStatsCollector.ResponseStatus responseStatus = TokenResponseStatsCollector.ResponseStatus.Success;

        if (identityTokens.isEmptyToken()) {
            if (UIDOperatorService.shouldCstgOptedOutUserReturnOptOutResponse(identityScope, cstgRequestHasOptoutCheckFlag)) {
                response = ResponseUtil.SuccessNoBodyV2("optout");
                responseStatus = TokenResponseStatsCollector.ResponseStatus.OptOut;
            }
            else {
                privacyBits.setClientSideTokenGenerateOptout();
                //user opted out we will generate an optout token with the opted out user identity
                identityTokens = generateOptedOutIdentityTokens(privacyBits, input, clientSideKeypair);
                response = ResponseUtil.SuccessV2(toJsonV1(identityTokens));
            }
        }
        else { //user not opted out and already generated valid identity token
            response = ResponseUtil.SuccessV2(toJsonV1(identityTokens));
        }
        //if returning an optout token or a successful identity token created originally
        if (responseStatus == TokenResponseStatsCollector.ResponseStatus.Success) {
            V2RequestUtil.handleRefreshTokenInResponseBody(response.getJsonObject("body"), keyManager, this.identityScope);
        }
        final byte[] encryptedResponse = AesGcm.encrypt(response.toBuffer().getBytes(), sharedSecret);
        rc.response().setStatusCode(200).end(Buffer.buffer(Unpooled.wrappedBuffer(Base64.getEncoder().encode(encryptedResponse))));
        recordTokenResponseStats(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, responseStatus, siteProvider, identityTokens.getAdvertisingTokenVersion());
    }

    private IdentityTokens generateOptedOutIdentityTokens(PrivacyBits privacyBits, InputUtil.InputVal input, ClientSideKeypair clientSideKeypair) {
        UserIdentity cstgOptOutIdentity;
        if (input.getIdentityType() == IdentityType.Email) {
            cstgOptOutIdentity = InputUtil.InputVal.validEmail(OptOutTokenIdentityForEmail, OptOutTokenIdentityForEmail).toUserIdentity(identityScope, privacyBits.getAsInt(), Instant.now());
        } else {
            cstgOptOutIdentity = InputUtil.InputVal.validPhone(OptOutTokenIdentityForPhone, OptOutTokenIdentityForPhone).toUserIdentity(identityScope, privacyBits.getAsInt(), Instant.now());
        }
        return this.idService.generateIdentity(
                new IdentityRequest(
                        new PublisherIdentity(clientSideKeypair.getSiteId(), 0, 0),
                        cstgOptOutIdentity, OptoutCheckPolicy.DoNotRespect));
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
            ResponseUtil.Warning("invalid_client", 401, rc, "Unexpected client site id " + Integer.toString(clientSiteId));
            return;
        }

        final List<KeysetKey> keys = this.keyManager.getKeysForSharingOrDsps();
        onSuccess.handle(getAccessibleKeysAsJson(keys, clientKey));
    }

    public void handleKeysRequestV1(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> ResponseUtil.Success(rc, keys));
        } catch (Exception e) {
            LOGGER.error("Unknown error while handling keys request v1", e);
            rc.fail(500);
        }
    }

    public void handleKeysRequestV2(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> ResponseUtil.SuccessV2(rc, keys));
        } catch (Exception e) {
            LOGGER.error("Unknown error while handling keys request v2", e);
            rc.fail(500);
        }
    }

    public void handleKeysRequest(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> sendJsonResponse(rc, keys));
        } catch (Exception e) {
            LOGGER.error("Unknown error while handling keys request", e);
            rc.fail(500);
        }
    }

    private String getSharingTokenExpirySeconds() {
        return config.getString(Const.Config.SharingTokenExpiryProp);
    }

    public void handleKeysSharing(RoutingContext rc) {
        try {
            final ClientKey clientKey = AuthMiddleware.getAuthClient(ClientKey.class, rc);

            KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
            List<KeysetKey> keysetKeyStore = keyManagerSnapshot.getKeysetKeys();
            Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();

            final JsonObject resp = new JsonObject();
            addSharingHeaderFields(resp, keyManagerSnapshot, clientKey);

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
        addBidstreamHeaderFields(resp);
        resp.put("keys", keysJson);
        addSites(resp, accessibleKeys, keysetMap);

        ResponseUtil.SuccessV2(rc, resp);
    }

    private void addBidstreamHeaderFields(JsonObject resp) {
        resp.put("max_bidstream_lifetime_seconds", maxBidstreamLifetimeSeconds + TOKEN_LIFETIME_TOLERANCE.toSeconds());
        addIdentityScopeField(resp);
        addAllowClockSkewSecondsField(resp);
    }

    private void addSites(JsonObject resp, List<KeysetKey> keys, Map<Integer, Keyset> keysetMap) {
        final List<Site> sites = getSitesWithDomainNames(keys, keysetMap);
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
                            "102.co.uk",
                            "102.com"
                        ]
                    }
                ]
            */
            final List<JsonObject> sitesJson = sites.stream()
                    .map(UIDOperatorVerticle::toJson)
                    .collect(Collectors.toList());
            resp.put("site_data", sitesJson);
        }
    }

    private void addSharingHeaderFields(JsonObject resp, KeyManagerSnapshot keyManagerSnapshot, ClientKey clientKey) {
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
        resp.put("token_expiry_seconds", getSharingTokenExpirySeconds());

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

    private List<Site> getSitesWithDomainNames(List<KeysetKey> keys, Map<Integer, Keyset> keysetMap) {
        //without cstg enabled, operator won't have site data and siteProvider could be null
        //and adding keySharingEndpointProvideSiteDomainNames in case something goes wrong
        //and we can still enable cstg feature but turn off site domain name download in
        // key/sharing endpoint
        if (!keySharingEndpointProvideSiteDomainNames || !clientSideTokenGenerate) {
            return null;
        }

        return keys.stream()
                .mapToInt(key -> keysetMap.get(key.getKeysetId()).getSiteId())
                .sorted()
                .distinct()
                .mapToObj(siteProvider::getSite)
                .filter(Objects::nonNull)
                .filter(site -> !site.getDomainNames().isEmpty())
                .collect(Collectors.toList());
    }

    /**
     * Converts the specified site to a JSON object.
     * Includes the following fields: id, domain_names.
     */
    private static JsonObject toJson(Site site) {
        JsonObject siteObj = new JsonObject();
        siteObj.put("id", site.getId());
        siteObj.put("domain_names", site.getDomainNames().stream().sorted().collect(Collectors.toList()));
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

    private void handleTokenRefreshV1(RoutingContext rc) {
        final List<String> tokenList = rc.queryParam("refresh_token");
        Integer siteId = null;
        if (tokenList == null || tokenList.size() == 0) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Required Parameter Missing: refresh_token", siteId, TokenResponseStatsCollector.Endpoint.RefreshV1, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider);
            return;
        }

        String refreshToken = tokenList.get(0);
        if (refreshToken.length() == V2RequestUtil.V2_REFRESH_PAYLOAD_LENGTH) {
            // V2 token sent by V1 JSSDK. Decrypt and extract original refresh token
            V2RequestUtil.V2Request v2req = V2RequestUtil.parseRefreshRequest(refreshToken, this.keyManager);
            if (v2req.isValid()) {
                refreshToken = (String) v2req.payload;
            } else {
                SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, v2req.errorMessage, siteId, TokenResponseStatsCollector.Endpoint.RefreshV1, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
                return;
            }
        }

        try {
            final RefreshResponse r = this.refreshIdentity(rc, refreshToken);
            siteId = rc.get(Const.RoutingContextData.SiteId);
            if (!r.isRefreshed()) {
                if (r.isOptOut() || r.isDeprecated()) {
                    ResponseUtil.SuccessNoBody(ResponseStatus.OptOut, rc);
                } else if (!AuthMiddleware.isAuthenticated(rc)) {
                    // unauthenticated clients get a generic error
                    ResponseUtil.Warning(ResponseStatus.GenericError, 400, rc, "Error refreshing token");
                } else if (r.isInvalidToken()) {
                    ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + tokenList.get(0));
                } else if (r.isExpired()) {
                    ResponseUtil.Warning(ResponseStatus.ExpiredToken, 400, rc, "Expired Token presented");
                } else {
                    ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
                }
            } else {
                ResponseUtil.Success(rc, toJsonV1(r.getTokens()));
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }

            TokenResponseStatsCollector.recordRefresh(siteProvider, siteId, TokenResponseStatsCollector.Endpoint.RefreshV1, r);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while refreshing token", siteId, TokenResponseStatsCollector.Endpoint.RefreshV1, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }

    private void handleTokenRefreshV2(RoutingContext rc) {
        Integer siteId = null;
        try {
            String tokenStr = (String) rc.data().get("request");
            final RefreshResponse r = this.refreshIdentity(rc, tokenStr);
            siteId = rc.get(Const.RoutingContextData.SiteId);
            if (!r.isRefreshed()) {
                if (r.isOptOut() || r.isDeprecated()) {
                    ResponseUtil.SuccessNoBodyV2(ResponseStatus.OptOut, rc);
                } else if (!AuthMiddleware.isAuthenticated(rc)) {
                    // unauthenticated clients get a generic error
                    ResponseUtil.Warning(ResponseStatus.GenericError, 400, rc, "Error refreshing token");
                } else if (r.isInvalidToken()) {
                    ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented");
                } else if (r.isExpired()) {
                    ResponseUtil.Warning(ResponseStatus.ExpiredToken, 400, rc, "Expired Token presented");
                } else {
                    ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
                }
            } else {
                ResponseUtil.SuccessV2(rc, toJsonV1(r.getTokens()));
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }
            TokenResponseStatsCollector.recordRefresh(siteProvider, siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, r);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while refreshing token v2", siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }

    private void handleTokenValidateV1(RoutingContext rc) {
        try {
            final InputUtil.InputVal input = this.phoneSupport ? getTokenInputV1(rc) : getTokenInput(rc);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            }
            if ((Arrays.equals(ValidateIdentityForEmailHash, input.getIdentityInput()) && input.getIdentityType() == IdentityType.Email)
                    || (Arrays.equals(ValidateIdentityForPhoneHash, input.getIdentityInput()) && input.getIdentityType() == IdentityType.Phone)) {
                try {
                    final Instant now = Instant.now();
                    if (this.idService.advertisingTokenMatches(rc.queryParam("token").get(0), input.toUserIdentity(this.identityScope, 0, now), now)) {
                        ResponseUtil.Success(rc, Boolean.TRUE);
                    } else {
                        ResponseUtil.Success(rc, Boolean.FALSE);
                    }
                } catch (Exception e) {
                    ResponseUtil.Success(rc, Boolean.FALSE);
                }
            } else {
                ResponseUtil.Success(rc, Boolean.FALSE);
            }
        } catch (ClientInputValidationException cie) {
            ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented");
        } catch (Exception e) {
            LOGGER.error("Unknown error while validating token", e);
            rc.fail(500);
        }
    }

    private void handleTokenValidateV2(RoutingContext rc) {
        try {
            final JsonObject req = (JsonObject) rc.data().get("request");

            final InputUtil.InputVal input = getTokenInputV2(req);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            }
            if ((input.getIdentityType() == IdentityType.Email && Arrays.equals(ValidateIdentityForEmailHash, input.getIdentityInput()))
                    || (input.getIdentityType() == IdentityType.Phone && Arrays.equals(ValidateIdentityForPhoneHash, input.getIdentityInput()))) {
                try {
                    final Instant now = Instant.now();
                    final String token = req.getString("token");

                    if (this.idService.advertisingTokenMatches(token, input.toUserIdentity(this.identityScope, 0, now), now)) {
                        ResponseUtil.SuccessV2(rc, Boolean.TRUE);
                    } else {
                        ResponseUtil.SuccessV2(rc, Boolean.FALSE);
                    }
                } catch (Exception e) {
                    ResponseUtil.SuccessV2(rc, Boolean.FALSE);
                }
            } else {
                ResponseUtil.SuccessV2(rc, Boolean.FALSE);
            }
        } catch (Exception e) {
            LOGGER.error("Unknown error while validating token v2", e);
            rc.fail(500);
        }
    }

    private void handleTokenGenerateV1(RoutingContext rc) {
        final int siteId = AuthMiddleware.getAuthClient(rc).getSiteId();
        try {
            final InputUtil.InputVal input = this.phoneSupport ? this.getTokenInputV1(rc) : this.getTokenInput(rc);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            } else {
                final IdentityTokens t = this.idService.generateIdentity(
                        new IdentityRequest(
                                new PublisherIdentity(siteId, 0, 0),
                                input.toUserIdentity(this.identityScope, 1, Instant.now()),
                                OptoutCheckPolicy.defaultPolicy()));

                //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

                ResponseUtil.Success(rc, toJsonV1(t));
                recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV1, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, t.getAdvertisingTokenVersion());
            }
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while generating token v1", siteId, TokenResponseStatsCollector.Endpoint.GenerateV1, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }

    private void handleTokenGenerateV2(RoutingContext rc) {
        final Integer siteId = AuthMiddleware.getAuthClient(rc).getSiteId();
        try {
            JsonObject req = (JsonObject) rc.data().get("request");

            final InputUtil.InputVal input = this.getTokenInputV2(req);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            } else {
                final String apiContact = getApiContact(rc);

                switch (validateUserConsent(req)) {
                    case INVALID: {
                        SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "User consent is invalid", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InvalidUserConsentString, siteProvider);
                        return;
                    }
                    case INSUFFICIENT: {
                        ResponseUtil.SuccessNoBodyV2(ResponseStatus.InsufficientUserConsent, rc);
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InsufficientUserConsent, siteProvider, null);
                        return;
                    }
                    case SUFFICIENT: {
                        break;
                    }
                    default: {
                        assert false : "Please update UIDOperatorVerticle.handleTokenGenerateV2 when changing UserConsentStatus";
                        break;
                    }
                }

                final Tuple.Tuple2<OptoutCheckPolicy, String> optoutCheckPolicy = readOptoutCheckPolicy(req);
                recordTokenGeneratePolicy(apiContact, optoutCheckPolicy.getItem1(), optoutCheckPolicy.getItem2());

                if (!meetPolicyCheckRequirements(rc)) {
                    SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Required opt-out policy argument for token/generate is missing or not set to 1", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
                    return;
                }

                final IdentityTokens t = this.idService.generateIdentity(
                        new IdentityRequest(
                                new PublisherIdentity(siteId, 0, 0),
                                input.toUserIdentity(this.identityScope, 1, Instant.now()),
                                OptoutCheckPolicy.respectOptOut()));

                if (t.isEmptyToken()) {
                    if(optoutCheckPolicy.getItem1() == OptoutCheckPolicy.DoNotRespect) { // only legacy can use this policy
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
                                        OptoutCheckPolicy.DoNotRespect));

                        ResponseUtil.SuccessV2(rc, toJsonV1(optOutTokens));
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, optOutTokens.getAdvertisingTokenVersion());
                    } else { // new participant, or legacy specified policy/optout_check=1
                        ResponseUtil.SuccessNoBodyV2("optout", rc);
                        recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.OptOut, siteProvider, null);
                    }
                } else {
                    ResponseUtil.SuccessV2(rc, toJsonV1(t));
                    recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, t.getAdvertisingTokenVersion());
                }
            }
        } catch (ClientInputValidationException cie) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "request body contains invalid argument(s)", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while generating token v2", siteId, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider, e);
        }
    }

    private void handleTokenGenerate(RoutingContext rc) {
        final InputUtil.InputVal input = this.getTokenInput(rc);
        Integer siteId = null;
        if (input == null) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Required Parameter Missing: exactly one of email or email_hash must be specified", siteId, TokenResponseStatsCollector.Endpoint.GenerateV0, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }
        else if (!input.isValid()) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Invalid email or email_hash", siteId, TokenResponseStatsCollector.Endpoint.GenerateV0, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }

        try {
            siteId = AuthMiddleware.getAuthClient(rc).getSiteId();
            final IdentityTokens t = this.idService.generateIdentity(
                    new IdentityRequest(
                            new PublisherIdentity(siteId, 0, 0),
                            input.toUserIdentity(this.identityScope, 1, Instant.now()),
                            OptoutCheckPolicy.defaultPolicy()));

            //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

            recordTokenResponseStats(siteId, TokenResponseStatsCollector.Endpoint.GenerateV0, TokenResponseStatsCollector.ResponseStatus.Success, siteProvider, t.getAdvertisingTokenVersion());
            sendJsonResponse(rc, toJson(t));

        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while generating token", siteId, TokenResponseStatsCollector.Endpoint.GenerateV0, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }

    private void handleTokenRefresh(RoutingContext rc) {
        final List<String> tokenList = rc.queryParam("refresh_token");
        Integer siteId = null;
        if (tokenList == null || tokenList.size() == 0) {
            SendClientErrorResponseAndRecordStats(ResponseStatus.ClientError, 400, rc, "Required Parameter Missing: refresh_token", siteId, TokenResponseStatsCollector.Endpoint.RefreshV0, TokenResponseStatsCollector.ResponseStatus.MissingParams, siteProvider);
            return;
        }

        try {
            final RefreshResponse r = this.refreshIdentity(rc, tokenList.get(0));

            sendJsonResponse(rc, toJson(r.getTokens()));

            siteId = rc.get(Const.RoutingContextData.SiteId);
            if (r.isRefreshed()) {
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }
            TokenResponseStatsCollector.recordRefresh(siteProvider, siteId, TokenResponseStatsCollector.Endpoint.RefreshV0, r);
        } catch (Exception e) {
            SendServerErrorResponseAndRecordStats(rc, "Unknown error while refreshing token", siteId, TokenResponseStatsCollector.Endpoint.RefreshV0, TokenResponseStatsCollector.ResponseStatus.Unknown, siteProvider, e);
        }
    }

    private void handleValidate(RoutingContext rc) {
        try {
            final InputUtil.InputVal input = getTokenInput(rc);
            if (input != null && input.isValid() && Arrays.equals(ValidateIdentityForEmailHash, input.getIdentityInput())) {
                try {
                    final Instant now = Instant.now();
                    if (this.idService.advertisingTokenMatches(rc.queryParam("token").get(0), input.toUserIdentity(this.identityScope, 0, now), now)) {
                        rc.response().end("true");
                    } else {
                        rc.response().end("false");
                    }
                } catch (Exception e) {
                    rc.response().end("false");
                }
            } else {
                rc.response().end("not allowed");
            }
        } catch (Exception e) {
            LOGGER.error("Unknown error while validating token", e);
            rc.fail(500);
        }
    }

    private void handleLogoutAsync(RoutingContext rc) {
        final InputUtil.InputVal input = this.phoneSupport ? getTokenInputV1(rc) : getTokenInput(rc);
        if (input.isValid()) {
            final Instant now = Instant.now();
            this.idService.invalidateTokensAsync(input.toUserIdentity(this.identityScope, 0, now), now, ar -> {
                if (ar.succeeded()) {
                    rc.response().end("OK");
                } else {
                    rc.fail(500);
                }
            });
        } else {
            ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + input);
        }
    }

    private Future handleLogoutAsyncV2(RoutingContext rc) {
        final JsonObject req = (JsonObject) rc.data().get("request");
        final InputUtil.InputVal input = getTokenInputV2(req);
        if (input.isValid()) {
            final Instant now = Instant.now();

            Promise promise = Promise.promise();
            this.idService.invalidateTokensAsync(input.toUserIdentity(this.identityScope, 0, now), now, ar -> {
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
            ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + input);
            return Future.failedFuture("");
        }
    }

    private void handleOptOutGet(RoutingContext rc) {
        final InputUtil.InputVal input = getTokenInputV1(rc);
        if (input.isValid()) {
            try {
                final Instant now = Instant.now();
                final UserIdentity userIdentity = input.toUserIdentity(this.identityScope, 0, now);
                final Instant result = this.idService.getLatestOptoutEntry(userIdentity, now);
                long timestamp = result == null ? -1 : result.getEpochSecond();
                rc.response().setStatusCode(200)
                        .setChunked(true)
                        .write(String.valueOf(timestamp));
                rc.response().end();
            } catch (Exception ex) {
                LOGGER.error("Unexpected error while handling optout get", ex);
                rc.fail(500);
            }
        } else {
            ResponseUtil.Warning(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + input);
        }
    }

    private void handleBucketsV1(RoutingContext rc) {
        final List<String> qp = rc.queryParam("since_timestamp");
        if (qp != null && qp.size() > 0) {
            final Instant sinceTimestamp;
            try {
                LocalDateTime ld = LocalDateTime.parse(qp.get(0), DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                sinceTimestamp = ld.toInstant(ZoneOffset.UTC);
            } catch (Exception e) {
                ResponseUtil.ClientError(rc, "invalid date, must conform to ISO 8601");
                return;
            }
            final List<SaltEntry> modified = this.idService.getModifiedBuckets(sinceTimestamp);
            final JsonArray resp = new JsonArray();
            if (modified != null) {
                for (SaltEntry e : modified) {
                    final JsonObject o = new JsonObject();
                    o.put("bucket_id", e.getHashedId());
                    Instant lastUpdated = Instant.ofEpochMilli(e.getLastUpdated());

                    o.put("last_updated", APIDateTimeFormatter.format(lastUpdated));
                    resp.add(o);
                }
                ResponseUtil.Success(rc, resp);
            }
        } else {
            ResponseUtil.ClientError(rc, "missing parameter since_timestamp");
        }
    }

    private void handleBucketsV2(RoutingContext rc) {
        final JsonObject req = (JsonObject) rc.data().get("request");
        final String qp = req.getString("since_timestamp");

        if (qp != null) {
            final Instant sinceTimestamp;
            try {
                LocalDateTime ld = LocalDateTime.parse(qp, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                sinceTimestamp = ld.toInstant(ZoneOffset.UTC);
            } catch (Exception e) {
                ResponseUtil.ClientError(rc, "invalid date, must conform to ISO 8601");
                return;
            }
            final List<SaltEntry> modified = this.idService.getModifiedBuckets(sinceTimestamp);
            final JsonArray resp = new JsonArray();
            if (modified != null) {
                for (SaltEntry e : modified) {
                    final JsonObject o = new JsonObject();
                    o.put("bucket_id", e.getHashedId());
                    Instant lastUpdated = Instant.ofEpochMilli(e.getLastUpdated());

                    o.put("last_updated", APIDateTimeFormatter.format(lastUpdated));
                    resp.add(o);
                }
                ResponseUtil.SuccessV2(rc, resp);
            }
        } else {
            ResponseUtil.ClientError(rc, "missing parameter since_timestamp");
        }
    }

    private void handleIdentityMapV1(RoutingContext rc) {
        final InputUtil.InputVal input = this.phoneSupport ? this.getTokenInputV1(rc) : this.getTokenInput(rc);
        if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
            return;
        }
        try {
            final Instant now = Instant.now();
            final MappedIdentity mappedIdentity = this.idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
            final JsonObject jsonObject = new JsonObject();
            jsonObject.put("identifier", input.getProvided());
            jsonObject.put("advertising_id", EncodingUtils.toBase64String(mappedIdentity.advertisingId));
            jsonObject.put("bucket_id", mappedIdentity.bucketId);
            ResponseUtil.Success(rc, jsonObject);
        } catch (Exception e) {
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State", e);
        }
    }

    private void handleIdentityMap(RoutingContext rc) {
        final InputUtil.InputVal input = this.getTokenInput(rc);

        try {
            if (input == null) {
                ResponseUtil.ClientError(rc, "Required Parameter Missing: exactly one of email or email_hash must be specified");
            }
            else if (!input.isValid()) {
                ResponseUtil.ClientError(rc, "Invalid email or email_hash");
            }
            else {
                final Instant now = Instant.now();
                final MappedIdentity mappedIdentity = this.idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
                rc.response().end(EncodingUtils.toBase64String(mappedIdentity.advertisingId));
            }
        } catch (Exception ex) {
            LOGGER.error("Unexpected error while mapping identity", ex);
            rc.fail(500);
        }
    }

    private InputUtil.InputVal getTokenInput(RoutingContext rc) {
        final InputUtil.InputVal input;
        final List<String> emailInput = rc.queryParam("email");
        final List<String> emailHashInput = rc.queryParam("email_hash");
        if (emailInput != null && emailInput.size() > 0) {
            if (emailHashInput != null && emailHashInput.size() > 0) {
                // cannot specify both
                input = null;
            } else {
                input = InputUtil.normalizeEmail(emailInput.get(0));
            }
        } else if (emailHashInput != null && emailHashInput.size() > 0) {
            input = InputUtil.normalizeEmailHash(emailHashInput.get(0));
        } else {
            input = null;
        }
        return input;
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

    private InputUtil.InputVal getTokenInputV1(RoutingContext rc) {
        final List<String> emailInput = rc.queryParam("email");
        final List<String> emailHashInput = rc.queryParam("email_hash");
        final List<String> phoneInput = rc.queryParam("phone");
        final List<String> phoneHashInput = rc.queryParam("phone_hash");

        int validInputs = 0;
        if (emailInput != null && emailInput.size() > 0) {
            ++validInputs;
        }
        if (emailHashInput != null && emailHashInput.size() > 0) {
            ++validInputs;
        }
        if (phoneInput != null && phoneInput.size() > 0) {
            ++validInputs;
        }
        if (phoneHashInput != null && phoneHashInput.size() > 0) {
            ++validInputs;
        }

        if (validInputs != 1) {
            // there can be only 1 set of valid input
            return null;
        }

        if (emailInput != null && emailInput.size() > 0) {
            return InputUtil.normalizeEmail(emailInput.get(0));
        } else if (phoneInput != null && phoneInput.size() > 0) {
            return InputUtil.normalizePhone(phoneInput.get(0));
        } else if (emailHashInput != null && emailHashInput.size() > 0) {
            return InputUtil.normalizeEmailHash(emailHashInput.get(0));
        } else if (phoneHashInput != null && phoneHashInput.size() > 0) {
            return InputUtil.normalizePhoneHash(phoneHashInput.get(0));
        }

        return null;
    }

    private boolean checkTokenInput(InputUtil.InputVal input, RoutingContext rc) {
        if (input == null) {
            ResponseUtil.ClientError(rc, "Required Parameter Missing: exactly one of email or email_hash must be specified");
            return false;
        } else if (!input.isValid()) {
            ResponseUtil.ClientError(rc, "Invalid Identifier");
            return false;
        }
        return true;
    }

    private boolean checkTokenInputV1(InputUtil.InputVal input, RoutingContext rc) {
        if (input == null) {
            ResponseUtil.ClientError(rc, "Required Parameter Missing: exactly one of [email, email_hash, phone, phone_hash] must be specified");
            return false;
        } else if (!input.isValid()) {
            ResponseUtil.ClientError(rc, "Invalid Identifier");
            return false;
        }
        return true;
    }

    private InputUtil.InputVal[] getIdentityBulkInput(RoutingContext rc) {
        final JsonObject obj = rc.body().asJsonObject();
        final JsonArray emails = obj.getJsonArray("email");
        final JsonArray emailHashes = obj.getJsonArray("email_hash");
        // FIXME TODO. Avoid Double Iteration. Turn to a decorator pattern
        if (emails == null && emailHashes == null) {
            ResponseUtil.ClientError(rc, "Exactly one of email or email_hash must be specified");
            return null;
        } else if (emails != null && !emails.isEmpty()) {
            if (emailHashes != null && !emailHashes.isEmpty()) {
                ResponseUtil.ClientError(rc, "Only one of email or email_hash can be specified");
                return null;
            }
            return createInputList(emails, false);
        } else {
            return createInputList(emailHashes, true);
        }
    }


    private InputUtil.InputVal[] getIdentityBulkInputV1(RoutingContext rc) {
        final JsonObject obj = rc.body().asJsonObject();
        final JsonArray emails = obj.getJsonArray("email");
        final JsonArray emailHashes = obj.getJsonArray("email_hash");
        final JsonArray phones = obj.getJsonArray("phone");
        final JsonArray phoneHashes = obj.getJsonArray("phone_hash");

        int validInputs = 0;
        int nonEmptyInputs = 0;
        if (emails != null) {
            ++validInputs;
            if (!emails.isEmpty()) ++nonEmptyInputs;
        }
        if (emailHashes != null) {
            ++validInputs;
            if (!emailHashes.isEmpty()) ++nonEmptyInputs;
        }
        if (phones != null) {
            ++validInputs;
            if (!phones.isEmpty()) ++nonEmptyInputs;
        }
        if (phoneHashes != null) {
            ++validInputs;
            if (!phoneHashes.isEmpty()) ++nonEmptyInputs;
        }

        if (validInputs == 0 || nonEmptyInputs > 1) {
            ResponseUtil.ClientError(rc, "Exactly one of [email, email_hash, phone, phone_hash] must be specified");
            return null;
        }

        if (emails != null && !emails.isEmpty()) {
            return createInputListV1(emails, IdentityType.Email, InputUtil.IdentityInputType.Raw);
        } else if (emailHashes != null && !emailHashes.isEmpty()) {
            return createInputListV1(emailHashes, IdentityType.Email, InputUtil.IdentityInputType.Hash);
        } else if (phones != null && !phones.isEmpty()) {
            return createInputListV1(phones, IdentityType.Phone, InputUtil.IdentityInputType.Raw);
        } else if (phoneHashes != null && !phoneHashes.isEmpty()) {
            return createInputListV1(phoneHashes, IdentityType.Phone, InputUtil.IdentityInputType.Hash);
        } else {
            // handle empty array
            return createInputListV1(null, IdentityType.Email, InputUtil.IdentityInputType.Raw);
        }
    }

    private JsonObject handleIdentityMapCommon(RoutingContext rc, InputUtil.InputVal[] inputList) {
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
                                now));

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

    private void handleIdentityMapBatchV1(RoutingContext rc) {
        try {
            final InputUtil.InputVal[] inputList = this.phoneSupport ? getIdentityBulkInputV1(rc) : getIdentityBulkInput(rc);
            if (inputList == null) return;

            final JsonObject resp = handleIdentityMapCommon(rc, inputList);
            ResponseUtil.Success(rc, resp);
        } catch (Exception e) {
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown error while mapping batched identity", e);
        }
    }

    private void handleIdentityMapV2(RoutingContext rc) {
        try {
            final InputUtil.InputVal[] inputList = getIdentityMapV2Input(rc);
            if (inputList == null) {
                if (this.phoneSupport)
                    ResponseUtil.ClientError(rc, "Exactly one of [email, email_hash, phone, phone_hash] must be specified");
                else
                    ResponseUtil.ClientError(rc, "Required Parameter Missing: exactly one of email or email_hash must be specified");
                return;
            }

            JsonObject requestJsonObject = (JsonObject) rc.data().get(REQUEST);
            if (!this.secureLinkValidatorService.validateRequest(rc, requestJsonObject, Role.MAPPER)) {
                ResponseUtil.Error(ResponseStatus.Unauthorized, HttpStatus.SC_UNAUTHORIZED, rc, "Invalid link_id");
                return;
            }

            final JsonObject resp = handleIdentityMapCommon(rc, inputList);
            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown error while mapping identity v2", e);
        }
    }

    private InputUtil.InputVal[] getIdentityMapV2Input(RoutingContext rc) {
        final JsonObject obj = (JsonObject) rc.data().get("request");

        Supplier<InputUtil.InputVal[]> getInputList = null;

        final JsonArray emails = obj.getJsonArray("email");
        if (emails != null && !emails.isEmpty()) {
            getInputList = () -> createInputListV1(emails, IdentityType.Email, InputUtil.IdentityInputType.Raw);
        }

        final JsonArray emailHashes = obj.getJsonArray("email_hash");
        if (emailHashes != null && !emailHashes.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputListV1(emailHashes, IdentityType.Email, InputUtil.IdentityInputType.Hash);
        }

        final JsonArray phones = this.phoneSupport ? obj.getJsonArray("phone") : null;
        if (phones != null && !phones.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputListV1(phones, IdentityType.Phone, InputUtil.IdentityInputType.Raw);
        }

        final JsonArray phoneHashes = this.phoneSupport ? obj.getJsonArray("phone_hash") : null;
        if (phoneHashes != null && !phoneHashes.isEmpty()) {
            if (getInputList != null) {
                return null;        // only one type of input is allowed
            }
            getInputList = () -> createInputListV1(phoneHashes, IdentityType.Phone, InputUtil.IdentityInputType.Hash);
        }

        if (emails == null && emailHashes == null && phones == null && phoneHashes == null) {
            return null;
        }

        return getInputList == null ?
                createInputListV1(null, IdentityType.Email, InputUtil.IdentityInputType.Raw) :  // handle empty array
                getInputList.get();
    }

    private void handleIdentityMapBatch(RoutingContext rc) {
        try {
            final JsonObject obj = rc.body().asJsonObject();
            final InputUtil.InputVal[] inputList;
            final JsonArray emails = obj.getJsonArray("email");
            final JsonArray emailHashes = obj.getJsonArray("email_hash");
            if (emails == null && emailHashes == null) {
                ResponseUtil.ClientError(rc, "Exactly one of email or email_hash must be specified");
                return;
            } else if (emails != null && !emails.isEmpty()) {
                if (emailHashes != null && !emailHashes.isEmpty()) {
                    ResponseUtil.ClientError(rc, "Only one of email or email_hash can be specified");
                    return;
                }
                inputList = createInputList(emails, false);
            } else {
                inputList = createInputList(emailHashes, true);
            }

            final JsonObject resp = handleIdentityMapCommon(rc, inputList);
            sendJsonResponse(rc, resp);
        } catch (Exception e) {
            LOGGER.error("Unknown error while mapping batched identity", e);
            rc.fail(500);
        }
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
                .builder("uid2.operator.identity.map.inputs")
                .description("number of emails or email hashes passed to identity map batch endpoint")
                .tags("api_contact", apiContact)
                .register(Metrics.globalRegistry));
        ds.record(inputCount);

        Tuple.Tuple2<Counter, Counter> ids = _identityMapUnmappedIdentifiers.computeIfAbsent(apiContact, k -> new Tuple.Tuple2<>(
                Counter.builder("uid2.operator.identity.map.unmapped")
                        .description("invalid identifiers")
                        .tags("api_contact", apiContact, "reason", "invalid")
                        .register(Metrics.globalRegistry),
                Counter.builder("uid2.operator.identity.map.unmapped")
                        .description("optout identifiers")
                        .tags("api_contact", apiContact, "reason", "optout")
                        .register(Metrics.globalRegistry)));
        if (invalidCount > 0) ids.getItem1().increment(invalidCount);
        if (optoutCount > 0) ids.getItem2().increment(optoutCount);

        Counter rs = _identityMapRequestWithUnmapped.computeIfAbsent(apiContact, k -> Counter
                .builder("uid2.operator.identity.map.unmapped_requests")
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
                    k -> DistributionSummary.builder("uid2.operator.identity.map.services.inputs")
                .description("number of emails or phone numbers passed to identity map batch endpoint by services")
                .tags(Arrays.asList(Tag.of("api_contact", apiContact),
                Tag.of("service_name", serviceName),
                Tag.of("service_link_name", serviceLinkName)))
                .register(Metrics.globalRegistry));
            ds.record(inputCount);

            Tuple.Tuple2<Counter, Counter> counterTuple = _identityMapUnmappedIdentifiers.computeIfAbsent(metricKey,
                k -> new Tuple.Tuple2<>(
                Counter.builder("uid2.operator.identity.map.services.unmapped")
                .description("number of invalid identifiers passed to identity map batch endpoint by services")
                .tags(Arrays.asList(Tag.of("api_contact", apiContact),
                    Tag.of("reason", "invalid"),
                    Tag.of("service_name", serviceName),
                    Tag.of("service_link_name", serviceLinkName)))
                .register(Metrics.globalRegistry),
                Counter.builder("uid2.operator.identity.map.services.unmapped")
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

    private RefreshResponse refreshIdentity(RoutingContext rc, String tokenStr) {
        final RefreshToken refreshToken;
        try {
            if (AuthMiddleware.isAuthenticated(rc)) {
                rc.put(Const.RoutingContextData.SiteId, AuthMiddleware.getAuthClient(ClientKey.class, rc).getSiteId());
            }

            refreshToken = this.encoder.decodeRefreshToken(tokenStr);
        } catch (ClientInputValidationException cie) {
            return RefreshResponse.Invalid;
        }
        if (refreshToken == null) {
            return RefreshResponse.Invalid;
        }
        if (!AuthMiddleware.isAuthenticated(rc)) {
            rc.put(Const.RoutingContextData.SiteId, refreshToken.publisherIdentity.siteId);
        }

        return this.idService.refreshIdentity(refreshToken);
    }

    public static String getSiteName(ISiteStore siteStore, Integer siteId) {
        if (siteId == null) return "unknown";
        if (siteStore == null) return "unknown"; //this is expected if CSTG is not enabled, eg for private operators

        final Site site = siteStore.getSite(siteId);
        return (site == null) ? "unknown" : site.getName();
    }

    private void recordRefreshDurationStats(Integer siteId, String apiContact, Duration durationSinceLastRefresh, boolean hasOriginHeader) {
        DistributionSummary ds = _refreshDurationMetricSummaries.computeIfAbsent(new Tuple.Tuple2<>(apiContact, hasOriginHeader), k ->
                DistributionSummary
                        .builder("uid2.token_refresh_duration_seconds")
                        .description("duration between token refreshes")
                        .tag("site_id", String.valueOf(siteId))
                        .tag("site_name", getSiteName(siteProvider, siteId))
                        .tag("api_contact", apiContact)
                        .tag("has_origin_header", hasOriginHeader ? "true" : "false")
                        .register(Metrics.globalRegistry)
        );
        ds.record(durationSinceLastRefresh.getSeconds());

        boolean isExpired = durationSinceLastRefresh.compareTo(this.idService.getIdentityExpiryDuration()) > 0;
        Counter c = _advertisingTokenExpiryStatus.computeIfAbsent(new Tuple.Tuple3<>(String.valueOf(siteId), hasOriginHeader, isExpired), k ->
                Counter
                        .builder("uid2.advertising_token_expired_on_refresh")
                        .description("status of advertiser token expiry")
                        .tag("site_id", String.valueOf(siteId))
                        .tag("site_name", getSiteName(siteProvider, siteId))
                        .tag("has_origin_header", hasOriginHeader ? "true" : "false")
                        .tag("is_expired", isExpired ? "true" : "false")
                        .register(Metrics.globalRegistry)
        );
        c.increment();
    }

    private InputUtil.InputVal[] createInputList(JsonArray a, boolean inputAsHash) {
        if (a == null || a.size() == 0) {
            return new InputUtil.InputVal[0];
        }
        final int size = a.size();
        final InputUtil.InputVal[] resp = new InputUtil.InputVal[size];

        for (int i = 0; i < size; ++i) {
            if (inputAsHash) {
                resp[i] = InputUtil.normalizeEmailHash(a.getString(i));
            } else {
                resp[i] = InputUtil.normalizeEmail(a.getString(i));
            }
        }
        return resp;

    }

    private InputUtil.InputVal[] createInputListV1(JsonArray a, IdentityType identityType, InputUtil.IdentityInputType inputType) {
        if (a == null || a.isEmpty()) {
            return new InputUtil.InputVal[0];
        }
        final int size = a.size();
        final InputUtil.InputVal[] resp = new InputUtil.InputVal[size];

        if (identityType == IdentityType.Email) {
            if (inputType == InputUtil.IdentityInputType.Raw) {
                for (int i = 0; i < size; ++i) {
                    resp[i] = InputUtil.normalizeEmail(a.getString(i));
                }
            } else if (inputType == InputUtil.IdentityInputType.Hash) {
                for (int i = 0; i < size; ++i) {
                    resp[i] = InputUtil.normalizeEmailHash(a.getString(i));
                }
            } else {
                throw new IllegalStateException("inputType");
            }
        } else if (identityType == IdentityType.Phone) {
            if (inputType == InputUtil.IdentityInputType.Raw) {
                for (int i = 0; i < size; ++i) {
                    resp[i] = InputUtil.normalizePhone(a.getString(i));
                }
            } else if (inputType == InputUtil.IdentityInputType.Hash) {
                for (int i = 0; i < size; ++i) {
                    resp[i] = InputUtil.normalizePhoneHash(a.getString(i));
                }
            } else {
                throw new IllegalStateException("inputType");
            }
        } else {
            throw new IllegalStateException("identityType");
        }

        return resp;
    }

    private UserConsentStatus validateUserConsent(JsonObject req) {
        // TCF string is an optional parameter and we should only check tcf if in EUID and the string is present
        if (identityScope.equals(IdentityScope.EUID) && req.containsKey("tcf_consent_string")) {
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
                .builder("uid2.token_generate_policy_usage")
                .description("Counter for token generate policy usage")
                .tags("api_contact", triple.getItem1(), "policy", String.valueOf(triple.getItem2()), "policy_parameter", triple.getItem3())
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

    private JsonObject toJsonV1(IdentityTokens t) {
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

    private JsonObject toJson(IdentityTokens t) {
        final JsonObject json = new JsonObject();
        json.put("advertisement_token", t.getAdvertisingToken());
        json.put("advertising_token", t.getAdvertisingToken());
        json.put("refresh_token", t.getRefreshToken());

        return json;
    }

    private void sendJsonResponse(RoutingContext rc, JsonObject json) {
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    private void sendJsonResponse(RoutingContext rc, JsonArray json) {
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    private void handleInvalidHttpOriginError(int siteId, String origin) {
        Set<String> uniqueInvalidOrigins = siteIdToInvalidOrigins.computeIfAbsent(siteId, k -> new HashSet<>());
        uniqueInvalidOrigins.add(origin);

        if (Duration.between(lastInvalidOriginProcessTime, Instant.now()).compareTo(Duration.ofMinutes(60)) >= 0) {
            lastInvalidOriginProcessTime = Instant.now();
            LOGGER.error(generateInvalidHttpOriginMessage(siteIdToInvalidOrigins));
            siteIdToInvalidOrigins.clear();
        }
    }

    private String generateInvalidHttpOriginMessage(Map<Integer, Set<String>> siteIdToInvalidOrigins) {
        StringBuilder invalidHttpOriginMessage = new StringBuilder();
        invalidHttpOriginMessage.append("InvalidHttpOrigin: ");
        boolean mapHasFirstElement = false;
        for (Map.Entry<Integer, Set<String>> entry : siteIdToInvalidOrigins.entrySet()) {
            if(mapHasFirstElement) {
                invalidHttpOriginMessage.append(" | ");
            }
            mapHasFirstElement = true;
            int siteId = entry.getKey();
            Set<String> origins = entry.getValue();
            String siteName = getSiteName(siteProvider, siteId);
            String site = "site " + siteName + " (" + siteId + "): ";
            invalidHttpOriginMessage.append(site);
            boolean setHasFirstElement = false;
            for (String origin : origins) {
                if(setHasFirstElement) {
                    invalidHttpOriginMessage.append(", ");
                }
                setHasFirstElement = true;
                invalidHttpOriginMessage.append(origin);
            }
        }
        return invalidHttpOriginMessage.toString();
    }

    public enum UserConsentStatus {
        SUFFICIENT,
        INSUFFICIENT,
        INVALID,
    }
}
