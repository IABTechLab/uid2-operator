package com.uid2.operator.vertx;

import com.uid2.operator.Const;
import com.uid2.operator.model.*;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.StatsCollectorHandler;
import com.uid2.operator.privacy.tcf.TransparentConsent;
import com.uid2.operator.privacy.tcf.TransparentConsentParseResult;
import com.uid2.operator.privacy.tcf.TransparentConsentPurpose;
import com.uid2.operator.privacy.tcf.TransparentConsentSpecialFeature;
import com.uid2.operator.service.*;
import com.uid2.operator.store.*;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.health.HealthComponent;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.*;
import com.uid2.shared.vertx.RequestCapturingHandler;
import io.micrometer.core.instrument.*;
import io.vertx.core.*;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.StaticHandler;

import java.io.IOException;
import java.time.*;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class UIDOperatorVerticle extends AbstractVerticle{
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorVerticle.class);

    public static final String ValidationInputEmail = "validate@email.com";
    public static final byte[] ValidationInputEmailHash = EncodingUtils.getSha256Bytes(ValidationInputEmail);
    public static final String ValidationInputPhone = "+12345678901";
    public static final byte[] ValidationInputPhoneHash = EncodingUtils.getSha256Bytes(ValidationInputPhone);
    public static final long MAX_REQUEST_BODY_SIZE = 1 << 20; // 1MB
    private static DateTimeFormatter APIDateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.of("UTC"));
    private final HealthComponent healthComponent = HealthManager.instance.registerComponent("http-server");
    private final JsonObject config;
    private final AuthMiddleware auth;
    private final IKeyStore keyStore;
    private final IKeyAclProvider keyAclProvider;
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final Clock clock;
    private IUIDOperatorService idService;
    private final Map<String, DistributionSummary> _identityMapMetricSummaries = new HashMap<>();
    private final Map<String, DistributionSummary> _refreshDurationMetricSummaries = new HashMap<>();
    private final IdentityScope identityScope;
    private final V2PayloadHandler v2PayloadHandler;
    private Handler<RoutingContext> disableHandler = null;
    private final boolean phoneSupport;
    private final int tcfVendorId;

    private IStatsCollectorQueue _statsCollectorQueue;

    public UIDOperatorVerticle(JsonObject config,
                               IClientKeyProvider clientKeyProvider,
                               IKeyStore keyStore,
                               IKeyAclProvider keyAclProvider,
                               ISaltProvider saltProvider,
                               IOptOutStore optOutStore,
                               Clock clock,
                               IStatsCollectorQueue statsCollectorQueue) {
        this.config = config;
        this.healthComponent.setHealthStatus(false, "not started");
        this.auth = new AuthMiddleware(clientKeyProvider);
        this.keyStore = keyStore;
        this.keyAclProvider = keyAclProvider;
        this.saltProvider = saltProvider;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = IdentityScope.fromString(config.getString("identity_scope", "uid2"));
        this.v2PayloadHandler = new V2PayloadHandler(keyStore, config.getBoolean("enable_v2_encryption", true), this.identityScope);
        this.phoneSupport = config.getBoolean("enable_phone_support", true);
        this.tcfVendorId = config.getInteger("tcf_vendor_id", 21);

        this._statsCollectorQueue = statsCollectorQueue;
    }

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        this.healthComponent.setHealthStatus(false, "still starting");

        this.idService = new UIDOperatorService(
            this.config,
            this.optOutStore,
            this.saltProvider,
            new EncryptedTokenEncoder(this.keyStore),
            this.clock,
            this.identityScope
        );

        final Router router = createRoutesSetup();
        final int port = Const.Port.ServicePortForOperator + Utils.getPortOffset();
        LOGGER.info("starting service on http.port: " + port);
        vertx
            .createHttpServer()
            .requestHandler(router::handle)
            .listen(port, result -> {
                if (result.succeeded()) {
                    this.healthComponent.setHealthStatus(true);
                    startPromise.complete();
                } else {
                    this.healthComponent.setHealthStatus(false, result.cause().getMessage());
                    startPromise.fail(result.cause());
                }

                LOGGER.info("UIDOperatorVerticle instance started");
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

        router.route().handler(new RequestCapturingHandler());
        router.route().handler(new ClientVersionCapturingHandler("static/js", "*.js"));
        router.route().handler(CorsHandler.create(".*.")
            .allowedMethod(io.vertx.core.http.HttpMethod.GET)
            .allowedMethod(io.vertx.core.http.HttpMethod.POST)
            .allowedMethod(io.vertx.core.http.HttpMethod.OPTIONS)
            .allowedHeader(com.uid2.shared.Const.Http.ClientVersionHeader)
            .allowedHeader("Access-Control-Request-Method")
            .allowedHeader("Access-Control-Allow-Credentials")
            .allowedHeader("Access-Control-Allow-Origin")
            .allowedHeader("Access-Control-Allow-Headers")
            .allowedHeader("Content-Type"));
        router.route().handler(BodyHandler.create().setBodyLimit(MAX_REQUEST_BODY_SIZE));

        router.route("/static/*").handler(StaticHandler.create("static"));
        router.route().handler(new StatsCollectorHandler(_statsCollectorQueue, vertx));

        setupV2Routes(router);

        // Static and health check
        router.get("/ops/healthcheck").handler(this::handleHealthCheck);

        if (this.config.getBoolean(Const.Config.AllowLegacyAPIProp, true)) {
            // V1 APIs
            router.get("/v1/token/generate").handler(auth.handleV1(this::handleTokenGenerateV1, Role.GENERATOR));
            router.get("/v1/token/validate").handler(this::handleTokenValidateV1);
            router.get("/v1/token/refresh").handler(auth.handleWithOptionalAuth(this::handleTokenRefreshV1));
            router.get("/v1/identity/buckets").handler(auth.handle(this::handleBucketsV1, Role.MAPPER));
            router.get("/v1/identity/map").handler(auth.handle(this::handleIdentityMapV1, Role.MAPPER));
            router.post("/v1/identity/map").handler(auth.handle(this::handleIdentityMapBatchV1, Role.MAPPER));
            router.get("/v1/key/latest").handler(auth.handle(this::handleKeysRequestV1, Role.ID_READER));

            // Deprecated APIs
            router.get("/key/latest").handler(auth.handle(this::handleKeysRequest, Role.ID_READER));
            router.get("/token/generate").handler(auth.handle(this::handleTokenGenerate, Role.GENERATOR));
            router.get("/token/refresh").handler(this::handleTokenRefresh);
            router.get("/token/validate").handler(this::handleValidate);
            router.get("/identity/map").handler(auth.handle(this::handleIdentityMap, Role.MAPPER));
            router.post("/identity/map").handler(auth.handle(this::handleIdentityMapBatch, Role.MAPPER));

            // Internal service APIs
            router.get("/token/logout").handler(auth.handle(this::handleLogoutAsync, Role.OPTOUT));

            // only uncomment to do local testing
            //router.get("/internal/optout/get").handler(auth.loopbackOnly(this::handleOptOutGet));
        }

        return router;
    }

    private void setupV2Routes(Router mainRouter) {
        final Router v2Router = Router.router(vertx);

        v2Router.post("/token/generate").handler(auth.handleV1(
            rc -> v2PayloadHandler.handleTokenGenerate(rc, this::handleTokenGenerateV2), Role.GENERATOR));
        v2Router.post("/token/refresh").handler(auth.handleWithOptionalAuth(
            rc -> v2PayloadHandler.handleTokenRefresh(rc, this::handleTokenRefreshV2)));
        v2Router.post("/token/validate").handler(auth.handleV1(
            rc -> v2PayloadHandler.handle(rc, this::handleTokenValidateV2), Role.GENERATOR));
        v2Router.post("/identity/buckets").handler(auth.handleV1(
            rc -> v2PayloadHandler.handle(rc, this::handleBucketsV2), Role.MAPPER));
        v2Router.post("/identity/map").handler(auth.handleV1(
            rc -> v2PayloadHandler.handle(rc, this::handleIdentityMapV2), Role.MAPPER));
        v2Router.post("/key/latest").handler(auth.handleV1(
            rc -> v2PayloadHandler.handle(rc, this::handleKeysRequestV2), Role.ID_READER));
        v2Router.post("/token/logout").handler(auth.handleV1(
            rc -> v2PayloadHandler.handleAsync(rc, this::handleLogoutAsyncV2), Role.OPTOUT));

        mainRouter.mountSubRouter("/v2", v2Router);
    }

    private void handleKeysRequestCommon(RoutingContext rc, Handler<JsonArray> onSuccess) {
        final ClientKey clientKey = AuthMiddleware.getAuthClient(ClientKey.class, rc);
        final int clientSiteId = clientKey.getSiteId();
        if (!clientKey.hasValidSiteId()) {
            ResponseUtil.Error("invalid_client", 401, rc, "Unexpected client site id " + Integer.toString(clientSiteId));
            return;
        }

        final List<EncryptionKey> keys = this.keyStore.getSnapshot().getActiveKeySet()
            .stream().filter(k -> k.getSiteId() != Const.Data.RefreshKeySiteId)
            .collect(Collectors.toList());
        final IKeysAclSnapshot acls = this.keyAclProvider.getSnapshot();
        onSuccess.handle(toJson(keys, clientKey, acls));
    }

    public void handleKeysRequestV1(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> ResponseUtil.Success(rc, keys));
        } catch (Exception e) {
            LOGGER.error(e);
            rc.fail(500);
        }
    }

    public void handleKeysRequestV2(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> ResponseUtil.SuccessV2(rc, keys));
        } catch (Exception e) {
            LOGGER.error(e);
            rc.fail(500);
        }
    }

    public void handleKeysRequest(RoutingContext rc) {
        try {
            handleKeysRequestCommon(rc, keys -> sendJsonResponse(rc, keys));
        } catch (Exception e) {
            LOGGER.error(e);
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
            V2RequestUtil.V2Request v2req = V2RequestUtil.parseRefreshRequest(refreshToken, keyStore);
            if (v2req.isValid()) {
                refreshToken = (String) v2req.payload;
            }
            else {
                ResponseUtil.ClientError(rc, v2req.errorMessage);
                return;
            }
        }

        try {
            RefreshResponse r = idService.refreshIdentity(refreshToken);
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
                this.recordRefreshDurationStats(rc, r.getDurationSinceLastRefresh());
                ResponseUtil.Success(rc, toJsonV1(r.getTokens()));
            }
        } catch (Exception e) {
            LOGGER.error(e);
            ResponseUtil.Error(ResponseStatus.UnknownError, 500, rc, "Service Error");
        }
    }

    private void handleTokenRefreshV2(RoutingContext rc) {
        try {
            String tokenStr = (String) rc.data().get("request");
            RefreshResponse r = idService.refreshIdentity(tokenStr);
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
                this.recordRefreshDurationStats(rc, r.getDurationSinceLastRefresh());
                ResponseUtil.SuccessV2(rc, toJsonV1(r.getTokens()));
            }
        } catch (Exception e) {
            LOGGER.error(e);
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
            LOGGER.error(e);
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
            LOGGER.error(e);
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
                        input.toUserIdentity(this.identityScope, 1, Instant.now())));

                //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

                ResponseUtil.Success(rc, toJsonV1(t));
            }
        } catch (Exception e) {
            LOGGER.error(e);
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

                switch (validateUserConsent(req)) {
                    case INVALID: {
                        rc.fail(400);
                        return;
                    }
                    case INSUFFICIENT: {
                        ResponseUtil.SuccessNoBodyV2(UIDOperatorVerticle.ResponseStatus.InsufficientUserConsent, rc);
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

                final IdentityTokens t = this.idService.generateIdentity(
                    new IdentityRequest(
                        new PublisherIdentity(clientKey.getSiteId(), 0, 0),
                        input.toUserIdentity(this.identityScope, 1, Instant.now())));
                ResponseUtil.SuccessV2(rc, toJsonV1(t));
            }
        } catch (Exception e) {
            LOGGER.error(e);
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
                            input.toUserIdentity(this.identityScope, 1, Instant.now())));

            //Integer.parseInt(rc.queryParam("privacy_bits").get(0))));

            sendJsonResponse(rc, toJson(t));

        } catch (Exception e) {
            LOGGER.error(e);
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
            final RefreshResponse r = this.idService.refreshIdentity(tokenList.get(0));
            sendJsonResponse(rc, toJson(r.getTokens()));
        } catch (Exception e) {
            LOGGER.error(e);
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
            LOGGER.error(e);
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
                    .write(String.valueOf(timestamp))
                    .end();
            } catch (Exception ex) {
                LOGGER.error(ex);
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
            jsonObject.put("advertising_id", mappedIdentity.advertisingId);
            jsonObject.put("bucket_id", mappedIdentity.bucketId);
            ResponseUtil.Success(rc, jsonObject);
        } catch (Exception e) {
            LOGGER.error(e);
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
        }
        catch (Exception ex) {
            LOGGER.error(ex);
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
        final JsonObject obj = rc.getBodyAsJson();
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
        final JsonObject obj = rc.getBodyAsJson();
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
        } else if (phoneHashes != null && !phoneHashes.isEmpty()){
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

            recordIdentityMapStats(rc, inputList.length);

            final Instant now = Instant.now();
            final JsonArray mapped = new JsonArray();
            final int count = inputList.length;
            for (int i = 0; i < count; ++i) {
                final InputUtil.InputVal input = inputList[i];
                if (input != null && input.isValid()) {
                    final MappedIdentity mappedIdentity = this.idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
                    final JsonObject resp = new JsonObject();
                    resp.put("identifier", input.getProvided());
                    resp.put("advertising_id", mappedIdentity.advertisingId);
                    resp.put("bucket_id", mappedIdentity.bucketId);
                    mapped.add(resp);
                }
            }

            final JsonObject resp = new JsonObject();
            resp.put("mapped", mapped);
            ResponseUtil.Success(rc, resp);
        } catch (Exception e) {
            LOGGER.error(e);
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

            recordIdentityMapStats(rc, inputList.length);

            final Instant now = Instant.now();
            final JsonArray mapped = new JsonArray();
            final int count = inputList.length;
            for (int i = 0; i < count; ++i) {
                final InputUtil.InputVal input = inputList[i];
                if (input != null && input.isValid()) {
                    final MappedIdentity mappedIdentity = idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
                    final JsonObject resp = new JsonObject();
                    resp.put("identifier", input.getProvided());
                    resp.put("advertising_id", mappedIdentity.advertisingId);
                    resp.put("bucket_id", mappedIdentity.bucketId);
                    mapped.add(resp);
                }
            }

            final JsonObject resp = new JsonObject();
            resp.put("mapped", mapped);
            ResponseUtil.SuccessV2(rc, resp);
        } catch (Exception e) {
            LOGGER.error(e);
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
            getInputList = () -> createInputListV1(phoneHashes, IdentityType.Phone, InputUtil.IdentityInputType.Hash);;
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
            final JsonObject obj = rc.getBodyAsJson();
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

            recordIdentityMapStats(rc, inputList.length);

            final Instant now = Instant.now();
            final JsonArray mapped = new JsonArray();
            final int count = inputList.length;
            for (int i = 0; i < count; ++i) {
                final InputUtil.InputVal input = inputList[i];
                if (input != null && input.isValid()) {
                    final MappedIdentity mappedIdentity = this.idService.map(input.toUserIdentity(this.identityScope, 0, now), now);
                    final JsonObject resp = new JsonObject();
                    resp.put("identifier", input.getProvided());
                    resp.put("advertising_id", mappedIdentity.advertisingId);
                    mapped.add(resp);
                }
            }

            final JsonObject resp = new JsonObject();
            resp.put("mapped", mapped);
            sendJsonResponse(rc, resp);
        } catch (Exception e) {
            LOGGER.error(e);
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

    private void recordIdentityMapStats(RoutingContext rc, int inputCount) {
        String apiContact = getApiContact(rc);

        DistributionSummary ds = _identityMapMetricSummaries.computeIfAbsent(apiContact, k -> DistributionSummary
            .builder("uid2.operator.identity.map.inputs")
            .description("number of emails or email hashes passed to identity map batch endpoint")
            .tags("api_contact", apiContact)
            .register(Metrics.globalRegistry));
        ds.record(inputCount);
    }

    private void recordRefreshDurationStats(RoutingContext rc, Duration durationSinceLastRefresh) {
        String apiContact = getApiContact(rc);

        DistributionSummary ds = _refreshDurationMetricSummaries.computeIfAbsent(apiContact, k ->
            DistributionSummary
                    .builder("uid2.token_refresh_duration_seconds")
                    .description("duration between token refreshes")
                    .tag("api_contact", apiContact)
                    .register(Metrics.globalRegistry)
        );
        ds.record(durationSinceLastRefresh.getSeconds());
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
        json.put("user_token", t.getUserToken());
        json.put("refresh_token", t.getRefreshToken());
        json.put("identity_expires", t.getIdentityExpires().toEpochMilli());
        json.put("refresh_expires", t.getRefreshExpires().toEpochMilli());
        json.put("refresh_from", t.getRefreshFrom().toEpochMilli());
        return json;
    }

    private JsonArray toJson(List<EncryptionKey> keys, ClientKey clientKey, IKeysAclSnapshot acls) {
        final JsonArray a = new JsonArray();
        for (int i = 0; i < keys.size(); ++i) {
            final EncryptionKey k = keys.get(i);
            if (!acls.canClientAccessKey(clientKey, k)) {
                continue;
            }

            final JsonObject o = new JsonObject();
            o.put("id", k.getId());
            o.put("created", k.getCreated().getEpochSecond());
            o.put("activates", k.getActivates().getEpochSecond());
            o.put("expires", k.getExpires().getEpochSecond());
            o.put("secret", EncodingUtils.toBase64String(k.getKeyBytes()));
            o.put("site_id", k.getSiteId());
            a.add(o);
        }
        return a;
    }

    private JsonObject toJson(IdentityTokens t) {
        final JsonObject json = new JsonObject();
        json.put("advertisement_token", t.getAdvertisingToken());
        json.put("advertising_token", t.getAdvertisingToken());
        json.put("user_token", t.getUserToken());
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
        public static String Success = "success";
        public static String Unauthorized = "unauthorized";
        public static String ClientError = "client_error";
        public static String OptOut = "optout";
        public static String InvalidToken = "invalid_token";
        public static String ExpiredToken = "expired_token";
        public static String GenericError = "error";
        public static String UnknownError = "unknown";
        public static String InsufficientUserConsent = "insufficient_user_consent";
    }

    public static enum UserConsentStatus {
        SUFFICIENT,
        INSUFFICIENT,
        INVALID, 
    }
}

