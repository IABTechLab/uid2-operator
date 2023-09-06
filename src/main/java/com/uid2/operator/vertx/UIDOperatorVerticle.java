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
import com.uid2.shared.model.ClientSideKeypair;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.model.Site;
import com.uid2.shared.store.*;
import com.uid2.shared.store.ACLMode.MissingAclMode;
import com.uid2.shared.store.IClientKeyProvider;
import com.uid2.shared.store.IClientSideKeypairStore;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.vertx.RequestCapturingHandler;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
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

import static com.uid2.operator.IdentityConst.ClientSideTokenGenerateOptOutIdentityForEmail;
import static com.uid2.operator.IdentityConst.ClientSideTokenGenerateOptOutIdentityForPhone;
import static com.uid2.operator.service.V2RequestUtil.V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES;
import static com.uid2.shared.middleware.AuthMiddleware.API_CLIENT_PROP;

public class UIDOperatorVerticle extends AbstractVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorVerticle.class);

    public static final String ValidationInputEmail = "validate@email.com";
    public static final byte[] ValidationInputEmailHash = EncodingUtils.getSha256Bytes(ValidationInputEmail);
    public static final String ValidationInputPhone = "+12345678901";
    public static final byte[] ValidationInputPhoneHash = EncodingUtils.getSha256Bytes(ValidationInputPhone);

    public static final long MAX_REQUEST_BODY_SIZE = 1 << 20; // 1MB
    private static final DateTimeFormatter APIDateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.of("UTC"));

    private static final String REQUEST = "request";
    private static final String LINK_ID = "link_id";
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
    private final Clock clock;
    protected IUIDOperatorService idService;
    private final Map<String, DistributionSummary> _identityMapMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple2<String, Boolean>, DistributionSummary> _refreshDurationMetricSummaries = new HashMap<>();
    private final Map<Tuple.Tuple3<String, Boolean, Boolean>, Counter> _advertisingTokenExpiryStatus = new HashMap<>();
    private final Map<Tuple.Tuple2<String, TokenGeneratePolicy>, Counter> _tokenGeneratePolicyCounters = new HashMap<>();
    private final Map<Tuple.Tuple2<String, IdentityMapPolicy>, Counter> _identityMapPolicyCounters = new HashMap<>();
    private final Map<String, Tuple.Tuple2<Counter, Counter>> _identityMapUnmappedIdentifiers = new HashMap<>();
    private final Map<String, Counter> _identityMapRequestWithUnmapped = new HashMap<>();
    private final IdentityScope identityScope;
    private final V2PayloadHandler v2PayloadHandler;
    private Handler<RoutingContext> disableHandler = null;
    private final boolean phoneSupport;
    private final int tcfVendorId;
    private final IStatsCollectorQueue _statsCollectorQueue;
    private final KeyManager keyManager;
    private final boolean checkServiceLinkIdForIdentityMap;
    private final String privateLinkId;

    private final boolean cstgDoDomainNameCheck;
    public final static int MASTER_KEYSET_ID_FOR_SDKS = 9999999; //this is because SDKs have an issue where they assume keyset ids are always positive; that will be fixed.


    public UIDOperatorVerticle(JsonObject config,
                               boolean clientSideTokenGenerate,
                               ISiteStore siteProvider,
                               IClientKeyProvider clientKeyProvider,
                               IClientSideKeypairStore clientSideKeypairProvider,
                               KeyManager keyManager,
                               ISaltProvider saltProvider,
                               IOptOutStore optOutStore,
                               Clock clock,
                               IStatsCollectorQueue statsCollectorQueue) {
        this.keyManager = keyManager;
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
        this.v2PayloadHandler = new V2PayloadHandler(keyManager, config.getBoolean("enable_v2_encryption", true), this.identityScope);
        this.phoneSupport = config.getBoolean("enable_phone_support", true);
        this.tcfVendorId = config.getInteger("tcf_vendor_id", 21);
        this.checkServiceLinkIdForIdentityMap = config.getBoolean(Const.Config.CheckServiceLinkIdForIdentityMapProp, false);
        this.privateLinkId = config.getString(Const.Config.PrivateLinkIdProp, "");
        this.cstgDoDomainNameCheck = config.getBoolean("client_side_token_generate_domain_name_check_enabled", true);
        this._statsCollectorQueue = statsCollectorQueue;
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
                this.identityScope
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

    public void setDisableHandler(Handler<RoutingContext> h) {
        this.disableHandler = h;
    }

    private Router createRoutesSetup() throws IOException {
        final Router router = Router.router(vertx);

        if (this.disableHandler != null) {
            router.route().handler(this.disableHandler);
        }

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
            LOGGER.error("Unknown error while handling client side token generate", e);
            rc.fail(500);
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
        final JsonObject body = rc.body().asJsonObject();
        if (body == null) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "json payload expected but not found");
            // We don't have a site ID, so we don't bother calling TokenResponseStatsCollector.record.
            return;
        }

        final CstgRequest request = body.mapTo(CstgRequest.class);

        final ClientSideKeypair clientSideKeypair = this.clientSideKeypairProvider.getSnapshot().getKeypair(request.getSubscriptionId());
        if (clientSideKeypair == null) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "bad subscription_id");
            return;
        }

        if (cstgDoDomainNameCheck) {
            final Set<String> domainNames = getDomainNameListForClientSideTokenGenerate(clientSideKeypair);
            String origin = rc.request().getHeader("origin");

            boolean allowedDomain = DomainNameCheckUtil.isDomainNameAllowed(origin, domainNames);
            if (!allowedDomain) {
                ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.InvalidHttpOrigin, 403, rc, "unexpected http origin");
                TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.InvalidHttpOrigin);
                return;
            }
        }

        if (Math.abs(Duration.between(Instant.ofEpochMilli(request.getTimestamp()), clock.instant()).toMinutes()) >=
                V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES) {
            ResponseUtil.Error(ResponseStatus.GenericError, 400, rc, "invalid timestamp: request too old or client time drift");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadTimestamp);
            return;
        }

        if (request.getPayload() == null || request.getIv() == null || request.getPublicKey() == null) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "required parameters: payload, iv, public_key");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams);
            return;
        }

        final KeyFactory kf = KeyFactory.getInstance("EC");

        final PublicKey clientPublicKey;
        try {
            final byte[] clientPublicKeyBytes = Base64.getDecoder().decode(request.getPublicKey());
            final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPublicKeyBytes);
            clientPublicKey = kf.generatePublic(pkSpec);
        } catch (Exception e) {
            ResponseUtil.Error(ResponseStatus.ClientError,400, rc, "bad public key");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPublicKey);
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
                ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "bad iv");
                TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV);
                return;
            }
        } catch (IllegalArgumentException e) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "bad iv");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadIV);
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
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "payload decryption failed");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload);
            return;
        }

        final JsonObject requestPayload;
        try {
            requestPayload = new JsonObject(Buffer.buffer(Unpooled.wrappedBuffer(requestPayloadBytes)));
        } catch (DecodeException e) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "encrypted payload contains invalid json");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload);
            return;
        }

        final String emailHash = requestPayload.getString("email_hash");
        final String phoneHash = requestPayload.getString("phone_hash");
        final InputUtil.InputVal input;


        if (phoneHash != null && !phoneSupport) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, "phone support not enabled");
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload);
            return;
        }

        final String errString = phoneSupport ?  "please provide exactly one of: email_hash, phone_hash" : "please provide email_hash";
        if (emailHash == null && phoneHash == null) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, errString);
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.MissingParams);
            return;
        }
        else if (emailHash != null && phoneHash != null) {
            ResponseUtil.Error(ResponseStatus.ClientError, 400, rc, errString);
            TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload);
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

        IdentityTokens identityTokens = this.idService.generateIdentity(
                new IdentityRequest(
                        new PublisherIdentity(clientSideKeypair.getSiteId(), 0, 0),
                        input.toUserIdentity(this.identityScope, privacyBits.getAsInt(), Instant.now()),
                        TokenGeneratePolicy.RespectOptOut));


        if (identityTokens.isEmptyToken()) {
            //user opted out we will generate a token with the opted out user identity
            privacyBits.setClientSideTokenGenerateOptout();
            UserIdentity cstgOptOutIdentity;
            if(input.getIdentityType() == IdentityType.Email) {
                cstgOptOutIdentity = InputUtil.InputVal.validEmail(ClientSideTokenGenerateOptOutIdentityForEmail, ClientSideTokenGenerateOptOutIdentityForEmail).toUserIdentity(identityScope, privacyBits.getAsInt(),  Instant.now());
            }
            else {
                cstgOptOutIdentity = InputUtil.InputVal.validPhone(ClientSideTokenGenerateOptOutIdentityForPhone, ClientSideTokenGenerateOptOutIdentityForPhone).toUserIdentity(identityScope, privacyBits.getAsInt(),  Instant.now());
            }
            identityTokens = this.idService.generateIdentity(
                    new IdentityRequest(
                            new PublisherIdentity(clientSideKeypair.getSiteId(), 0, 0),
                            cstgOptOutIdentity, TokenGeneratePolicy.JustGenerate));
        }
        JsonObject response = ResponseUtil.SuccessV2(toJsonV1(identityTokens));
        V2RequestUtil.handleRefreshTokenInResponseBody(response.getJsonObject("body"), keyManager, this.identityScope);

        final byte[] encryptedResponse = AesGcm.encrypt(response.toBuffer().getBytes(), sharedSecret);
        rc.response().setStatusCode(200).end(Buffer.buffer(Unpooled.wrappedBuffer(Base64.getEncoder().encode(encryptedResponse))));
        TokenResponseStatsCollector.record(clientSideKeypair.getSiteId(), TokenResponseStatsCollector.Endpoint.ClientSideTokenGenerateV2, TokenResponseStatsCollector.ResponseStatus.Success);
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
            ResponseUtil.Error("invalid_client", 401, rc, "Unexpected client site id " + Integer.toString(clientSiteId));
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
            final JsonArray keys = new JsonArray();

            KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
            List<KeysetKey> keysetKeyStore = keyManagerSnapshot.getKeysetKeys();
            Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();
            KeysetSnapshot keysetSnapshot = keyManagerSnapshot.getKeysetSnapshot();
            // defaultKeysetId allows calling sdk.Encrypt(rawUid) without specifying the keysetId
            Keyset defaultKeyset = keyManagerSnapshot.getDefaultKeyset();

            MissingAclMode mode = MissingAclMode.DENY_ALL;
            // This will break if another Type is added to this map
            IRoleAuthorizable<Role> roleAuthorize = (IRoleAuthorizable<Role>) rc.data().get(API_CLIENT_PROP);
            if (roleAuthorize.hasRole(Role.ID_READER)) {
                mode = MissingAclMode.ALLOW_ALL;
            }

            final JsonObject resp = new JsonObject();
            resp.put("caller_site_id", clientKey.getSiteId());
            resp.put("master_keyset_id", MASTER_KEYSET_ID_FOR_SDKS);
            if (defaultKeyset != null) {
                resp.put("default_keyset_id", defaultKeyset.getKeysetId());
            }
            resp.put("token_expiry_seconds", getSharingTokenExpirySeconds());

            // include 'keyset_id' field, if:
            //   (a) a key belongs to caller's enabled site
            //   (b) a key belongs to master_keyset
            // otherwise, when a key is accessible by caller, the key can be used for decryption only. skip 'keyset_id' field.
            for (KeysetKey key: keysetKeyStore) {
                JsonObject keyObj = new JsonObject();
                Keyset keyset = keysetMap.get(key.getKeysetId());

                if (keyset == null || !keyset.isEnabled()) {
                    continue;
                } else if (clientKey.getSiteId() == keyset.getSiteId()) {
                    keyObj.put("keyset_id", key.getKeysetId());
                } else if (key.getKeysetId() == Data.MasterKeysetId) {
                    keyObj.put("keyset_id", MASTER_KEYSET_ID_FOR_SDKS);
                } else if (!keysetSnapshot.canClientAccessKey(clientKey, key, mode)) {
                    continue;
                }
                keyObj.put("id", key.getId());
                keyObj.put("created", key.getCreated().getEpochSecond());
                keyObj.put("activates", key.getActivates().getEpochSecond());
                keyObj.put("expires", key.getExpires().getEpochSecond());
                keyObj.put("secret", EncodingUtils.toBase64String(key.getKeyBytes()));
                keys.add(keyObj);
            }
            resp.put("keys", keys);

            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            LOGGER.error("handleKeysSharing", e);
            rc.fail(500);
        }
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
        if (tokenList == null || tokenList.size() == 0) {
            ResponseUtil.ClientError(rc, "Required Parameter Missing: refresh_token");
            return;
        }

        String refreshToken = tokenList.get(0);
        if (refreshToken.length() == V2RequestUtil.V2_REFRESH_PAYLOAD_LENGTH) {
            // V2 token sent by V1 JSSDK. Decrypt and extract original refresh token
            V2RequestUtil.V2Request v2req = V2RequestUtil.parseRefreshRequest(refreshToken, this.keyManager);
            if (v2req.isValid()) {
                refreshToken = (String) v2req.payload;
            } else {
                ResponseUtil.ClientError(rc, v2req.errorMessage);
                return;
            }
        }

        try {
            final RefreshResponse r = this.refreshIdentity(rc, refreshToken);
            Integer siteId = rc.get(Const.RoutingContextData.SiteId);
            if (!r.isRefreshed()) {
                if (r.isOptOut() || r.isDeprecated()) {
                    ResponseUtil.SuccessNoBody(ResponseStatus.OptOut, rc);
                } else if (!AuthMiddleware.isAuthenticated(rc)) {
                    // unauthenticated clients get a generic error
                    ResponseUtil.Error(ResponseStatus.GenericError, 400, rc, "Error refreshing token");
                } else if (r.isInvalidToken()) {
                    ResponseUtil.Error(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented " + tokenList.get(0));
                } else if (r.isExpired()) {
                    ResponseUtil.Error(ResponseStatus.ExpiredToken, 400, rc, "Expired Token presented");
                } else {
                    ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
                }
            } else {
                ResponseUtil.Success(rc, toJsonV1(r.getTokens()));
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }

            TokenResponseStatsCollector.record(siteId, TokenResponseStatsCollector.Endpoint.RefreshV1, r);
        } catch (Exception e) {
            LOGGER.error("unknown error while refreshing token", e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Service Error");
        }
    }

    private void handleTokenRefreshV2(RoutingContext rc) {
        try {
            String tokenStr = (String) rc.data().get("request");
            final RefreshResponse r = this.refreshIdentity(rc, tokenStr);
            Integer siteId = rc.get(Const.RoutingContextData.SiteId);
            if (!r.isRefreshed()) {
                if (r.isOptOut() || r.isDeprecated()) {
                    ResponseUtil.SuccessNoBodyV2(ResponseStatus.OptOut, rc);
                } else if (!AuthMiddleware.isAuthenticated(rc)) {
                    // unauthenticated clients get a generic error
                    ResponseUtil.Error(ResponseStatus.GenericError, 400, rc, "Error refreshing token");
                } else if (r.isInvalidToken()) {
                    ResponseUtil.Error(ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented");
                } else if (r.isExpired()) {
                    ResponseUtil.Error(ResponseStatus.ExpiredToken, 400, rc, "Expired Token presented");
                } else {
                    ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
                }
            } else {
                ResponseUtil.SuccessV2(rc, toJsonV1(r.getTokens()));
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }
            TokenResponseStatsCollector.record(siteId, TokenResponseStatsCollector.Endpoint.RefreshV2, r);
        } catch (Exception e) {
            LOGGER.error("Unknown error while refreshing token v2", e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Service Error");
        }
    }

    private void handleTokenValidateV1(RoutingContext rc) {
        try {
            final InputUtil.InputVal input = this.phoneSupport ? getTokenInputV1(rc) : getTokenInput(rc);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            }
            if ((Arrays.equals(ValidationInputEmailHash, input.getIdentityInput()) && input.getIdentityType() == IdentityType.Email)
                    || (Arrays.equals(ValidationInputPhoneHash, input.getIdentityInput()) && input.getIdentityType() == IdentityType.Phone)) {
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
            if ((input.getIdentityType() == IdentityType.Email && Arrays.equals(ValidationInputEmailHash, input.getIdentityInput()))
                    || (input.getIdentityType() == IdentityType.Phone && Arrays.equals(ValidationInputPhoneHash, input.getIdentityInput()))) {
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
        try {
            final InputUtil.InputVal input = this.phoneSupport ? this.getTokenInputV1(rc) : this.getTokenInput(rc);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            } else {
                final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(rc);
                final IdentityTokens t = this.idService.generateIdentity(
                        new IdentityRequest(
                                new PublisherIdentity(clientKey.getSiteId(), 0, 0),
                                input.toUserIdentity(this.identityScope, 1, Instant.now()),
                                TokenGeneratePolicy.defaultPolicy()));

                //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

                ResponseUtil.Success(rc, toJsonV1(t));
                TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV1, TokenResponseStatsCollector.ResponseStatus.Success);
            }
        } catch (Exception e) {
            LOGGER.error("Unknown error while generating token v1", e);
            rc.fail(500);
        }
    }

    private void handleTokenGenerateV2(RoutingContext rc) {
        try {
            JsonObject req = (JsonObject) rc.data().get("request");

            final InputUtil.InputVal input = this.getTokenInputV2(req);
            if (this.phoneSupport ? !checkTokenInputV1(input, rc) : !checkTokenInput(input, rc)) {
                return;
            } else {
                final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(rc);
                final String apiContact = getApiContact(rc);

                switch (validateUserConsent(req)) {
                    case INVALID: {
                        rc.fail(400);
                        TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InvalidUserConsentString);
                        return;
                    }
                    case INSUFFICIENT: {
                        ResponseUtil.SuccessNoBodyV2(UIDOperatorVerticle.ResponseStatus.InsufficientUserConsent, rc);
                        TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.InsufficientUserConsent);
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

                final TokenGeneratePolicy tokenGeneratePolicy = readTokenGeneratePolicy(req);
                final IdentityTokens t = this.idService.generateIdentity(
                        new IdentityRequest(
                                new PublisherIdentity(clientKey.getSiteId(), 0, 0),
                                input.toUserIdentity(this.identityScope, 1, Instant.now()),
                                tokenGeneratePolicy));
                recordTokenGeneratePolicy(apiContact, tokenGeneratePolicy);

                if (t.isEmptyToken()) {
                    ResponseUtil.SuccessNoBodyV2("optout", rc);
                    TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.OptOut);
                } else {
                    ResponseUtil.SuccessV2(rc, toJsonV1(t));
                    TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.Success);
                }
            }
        } catch (IllegalArgumentException iae) {
            LOGGER.warn("request body contains invalid argument(s)", iae);
            ResponseUtil.ClientError(rc, "request body contains invalid argument(s)");
        } catch (Exception e) {
            LOGGER.error("Unknown error while generating token v2", e);
            rc.fail(500);
        }
    }

    private void handleTokenGenerate(RoutingContext rc) {
        final InputUtil.InputVal input = this.getTokenInput(rc);
        if (input == null || !input.isValid()) {
            rc.fail(400);
            return;
        }

        try {
            final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(rc);
            final IdentityTokens t = this.idService.generateIdentity(
                    new IdentityRequest(
                            new PublisherIdentity(clientKey.getSiteId(), 0, 0),
                            input.toUserIdentity(this.identityScope, 1, Instant.now()),
                            TokenGeneratePolicy.defaultPolicy()));

            //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

            TokenResponseStatsCollector.record(clientKey.getSiteId(), TokenResponseStatsCollector.Endpoint.GenerateV0, TokenResponseStatsCollector.ResponseStatus.Success);
            sendJsonResponse(rc, toJson(t));

        } catch (Exception e) {
            LOGGER.error("Unknown error while generating token", e);
            rc.fail(500);
        }
    }

    private void handleTokenRefresh(RoutingContext rc) {
        final List<String> tokenList = rc.queryParam("refresh_token");
        if (tokenList == null || tokenList.size() == 0) {
            rc.fail(400);
            return;
        }

        try {
            final RefreshResponse r = this.refreshIdentity(rc, tokenList.get(0));

            sendJsonResponse(rc, toJson(r.getTokens()));

            Integer siteId = rc.get(Const.RoutingContextData.SiteId);
            if (r.isRefreshed()) {
                this.recordRefreshDurationStats(siteId, getApiContact(rc), r.getDurationSinceLastRefresh(), rc.request().headers().contains("Origin"));
            }
            TokenResponseStatsCollector.record(siteId, TokenResponseStatsCollector.Endpoint.RefreshV0, r);
        } catch (Exception e) {
            LOGGER.error("Unknown error while refreshing token", e);
            rc.fail(500);
        }
    }

    private void handleValidate(RoutingContext rc) {
        try {
            final InputUtil.InputVal input = getTokenInput(rc);
            if (input != null && input.isValid() && Arrays.equals(ValidationInputEmailHash, input.getIdentityInput())) {
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
            rc.fail(400);
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
            rc.fail(400);
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
            rc.fail(400);
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
            LOGGER.error("Unknown error while mapping identity v1", e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
        }
    }

    private void handleIdentityMap(RoutingContext rc) {
        final InputUtil.InputVal input = this.getTokenInput(rc);

        try {
            if (input != null && input.isValid()) {
                final Instant now = Instant.now();
                final MappedIdentity mappedIdentity = this.idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
                rc.response().end(EncodingUtils.toBase64String(mappedIdentity.advertisingId));
            } else {
                rc.fail(400);
            }
        } catch (Exception ex) {
            LOGGER.error("Unexpected error while mapping identity", ex);
            rc.fail(500);
        }
    }

    private boolean isServiceLinkAuthenticated(RoutingContext rc, JsonObject requestJsonObject) {
        if (requestJsonObject.containsKey(LINK_ID)) {
            String linkId = requestJsonObject.getString(LINK_ID);
            if (!linkId.equalsIgnoreCase(privateLinkId)) {
                ResponseUtil.Error(ResponseStatus.Unauthorized, HttpStatus.SC_UNAUTHORIZED, rc, "Invalid link_id");
                return false;
            }
        }
        return true;
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

    private void handleIdentityMapBatchV1(RoutingContext rc) {
        try {
            final InputUtil.InputVal[] inputList = this.phoneSupport ? getIdentityBulkInputV1(rc) : getIdentityBulkInput(rc);
            if (inputList == null) return;

            IdentityMapPolicy identityMapPolicy = readIdentityMapPolicy(rc.getBodyAsJson());
            recordIdentityMapPolicy(getApiContact(rc), identityMapPolicy);

            final Instant now = Instant.now();
            final JsonArray mapped = new JsonArray();
            final JsonArray unmapped = new JsonArray();
            final int count = inputList.length;
            int invalidCount = 0;
            int optoutCount = 0;
            for (int i = 0; i < count; ++i) {
                final InputUtil.InputVal input = inputList[i];
                if (input != null && input.isValid()) {
                    final MappedIdentity mappedIdentity = this.idService.mapIdentity(
                            new MapRequest(
                                    input.toUserIdentity(this.identityScope, 0, now),
                                    identityMapPolicy,
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
            ResponseUtil.Success(rc, resp);
        } catch (Exception e) {
            LOGGER.error("Unknown error while mapping batched identity", e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
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
            if (checkServiceLinkIdForIdentityMap) {
                if (!isServiceLinkAuthenticated(rc, requestJsonObject)) {
                    return;
                }
            }

            IdentityMapPolicy identityMapPolicy = readIdentityMapPolicy(requestJsonObject);
            recordIdentityMapPolicy(getApiContact(rc), identityMapPolicy);

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
                                    identityMapPolicy,
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
            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            LOGGER.error("Unknown error while mapping identity v2", e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Unknown State");
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
                rc.fail(400);
                return;
            } else if (emails != null && !emails.isEmpty()) {
                if (emailHashes != null && !emailHashes.isEmpty()) {
                    rc.fail(400);
                    return;
                }
                inputList = createInputList(emails, false);
            } else {
                inputList = createInputList(emailHashes, true);
            }

            final IdentityMapPolicy identityMapPolicy = readIdentityMapPolicy(obj);
            recordIdentityMapPolicy(getApiContact(rc), identityMapPolicy);

            final Instant now = Instant.now();
            final JsonArray mapped = new JsonArray();
            final JsonArray unmapped = new JsonArray();
            final int count = inputList.length;
            int invalidCount = 0;
            int optoutCount = 0;
            for (int i = 0; i < count; ++i) {
                final InputUtil.InputVal input = inputList[i];
                if (input != null && input.isValid()) {
                    final MappedIdentity mappedIdentity = this.idService.mapIdentity(
                            new MapRequest(
                                    input.toUserIdentity(this.identityScope, 0, now),
                                    identityMapPolicy,
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
    }

    private RefreshResponse refreshIdentity(RoutingContext rc, String tokenStr) {
        final RefreshToken refreshToken;
        try {
            if (AuthMiddleware.isAuthenticated(rc)) {
                rc.put(Const.RoutingContextData.SiteId, AuthMiddleware.getAuthClient(ClientKey.class, rc).getSiteId());
            }

            refreshToken = this.encoder.decodeRefreshToken(tokenStr);
        } catch (Throwable t) {
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

    private void recordRefreshDurationStats(Integer siteId, String apiContact, Duration durationSinceLastRefresh, boolean hasOriginHeader) {
        DistributionSummary ds = _refreshDurationMetricSummaries.computeIfAbsent(new Tuple.Tuple2<>(apiContact, hasOriginHeader), k ->
                DistributionSummary
                        .builder("uid2.token_refresh_duration_seconds")
                        .description("duration between token refreshes")
                        .tag("site_id", String.valueOf(siteId))
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
        if (a == null || a.size() == 0) {
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
        if (identityScope.equals(IdentityScope.EUID)) {
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

    private static final String TOKEN_GENERATE_POLICY_PARAM = "policy";

    private TokenGeneratePolicy readTokenGeneratePolicy(JsonObject req) {
        return req.containsKey(TOKEN_GENERATE_POLICY_PARAM) ?
                TokenGeneratePolicy.fromValue(req.getInteger(TOKEN_GENERATE_POLICY_PARAM)) :
                TokenGeneratePolicy.defaultPolicy();
    }

    private static final String IDENTITY_MAP_POLICY_PARAM = "policy";

    private IdentityMapPolicy readIdentityMapPolicy(JsonObject req) {
        return req.containsKey(IDENTITY_MAP_POLICY_PARAM) ?
                IdentityMapPolicy.fromValue(req.getInteger(IDENTITY_MAP_POLICY_PARAM)) :
                IdentityMapPolicy.defaultPolicy();
    }

    private void recordTokenGeneratePolicy(String apiContact, TokenGeneratePolicy policy) {
        _tokenGeneratePolicyCounters.computeIfAbsent(new Tuple.Tuple2<>(apiContact, policy), pair -> Counter
                .builder("uid2.token_generate_policy_usage")
                .description("Counter for token generate policy usage")
                .tags("api_contact", pair.getItem1(), "policy", String.valueOf(pair.getItem2()))
                .register(Metrics.globalRegistry)).increment();
    }

    private void recordIdentityMapPolicy(String apiContact, IdentityMapPolicy policy) {
        _identityMapPolicyCounters.computeIfAbsent(new Tuple.Tuple2<>(apiContact, policy), pair -> Counter
                .builder("uid2.identity_map_policy_usage")
                .description("Counter for identity map policy usage")
                .tags("api_contact", pair.getItem1(), "policy", String.valueOf(pair.getItem2()))
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
        } catch (IllegalArgumentException e) {
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

    private JsonArray getAccessibleKeysAsJson(List<KeysetKey> keys, ClientKey clientKey) {
        MissingAclMode mode = MissingAclMode.DENY_ALL;
        if (clientKey.getRoles().contains(Role.ID_READER)) {
            mode = MissingAclMode.ALLOW_ALL;
        }

        KeyManagerSnapshot keyManagerSnapshot = this.keyManager.getKeyManagerSnapshot(clientKey.getSiteId());
        Map<Integer, Keyset> keysetMap = keyManagerSnapshot.getAllKeysets();
        KeysetSnapshot keysetSnapshot = keyManagerSnapshot.getKeysetSnapshot();

        final JsonArray a = new JsonArray();
        for (KeysetKey k : keys) {
            if (!keysetSnapshot.canClientAccessKey(clientKey, k, mode)) {
                continue;
            }

            final JsonObject o = new JsonObject();
            o.put("id", k.getId());
            o.put("created", k.getCreated().getEpochSecond());
            o.put("activates", k.getActivates().getEpochSecond());
            o.put("expires", k.getExpires().getEpochSecond());
            o.put("secret", EncodingUtils.toBase64String(k.getKeyBytes()));
            o.put("site_id", keysetMap.get(k.getKeysetId()).getSiteId());
            a.add(o);
        }
        return a;
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

    public static class ResponseStatus {
        public static final String Success = "success";
        public static final String Unauthorized = "unauthorized";
        public static final String ClientError = "client_error";
        public static final String OptOut = "optout";
        public static final String InvalidToken = "invalid_token";
        public static final String ExpiredToken = "expired_token";
        public static final String GenericError = "error";
        public static final String UnknownError = "unknown";
        public static final String InsufficientUserConsent = "insufficient_user_consent";
        public static final String InvalidHttpOrigin = "invalid_http_origin";
    }

    public static enum UserConsentStatus {
        SUFFICIENT,
        INSUFFICIENT,
        INVALID,
    }
}
