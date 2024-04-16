package com.uid2.operator.vertx;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.KeyManager;
import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.ResponseUtil;
import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.InstantClock;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.store.ISiteStore;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import static com.uid2.operator.service.ResponseUtil.SendClientErrorResponseAndRecordStats;

public class V2PayloadHandler {
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(V2PayloadHandler.class);

    private KeyManager keyManager;

    private Boolean enableEncryption;

    private IdentityScope identityScope;

    private ISiteStore siteProvider;

    public V2PayloadHandler(KeyManager keyManager, Boolean enableEncryption, IdentityScope identityScope, ISiteStore siteProvider) {
        this.keyManager = keyManager;
        this.enableEncryption = enableEncryption;
        this.identityScope = identityScope;
        this.siteProvider = siteProvider;
    }

    public void handle(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, rc), new InstantClock());
        if (!request.isValid()) {
            ResponseUtil.ClientError(rc, request.errorMessage);
            return;
        }
        rc.data().put("request", request.payload);

        apiHandler.handle(rc);

        handleResponse(rc, request);
    }

    public void handleAsync(RoutingContext rc, Function<RoutingContext, Future> apiHandler) {
        if (!enableEncryption) {
            apiHandler.apply(rc);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, rc), new InstantClock());
        if (!request.isValid()) {
            ResponseUtil.ClientError(rc, request.errorMessage);
            return;
        }
        rc.data().put("request", request.payload);

        apiHandler.apply(rc).onComplete(ar -> {
            handleResponse(rc, request);
        });
    }

    public void handleTokenGenerate(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, rc), new InstantClock());
        if (!request.isValid()) {
            SendClientErrorResponseAndRecordStats(ResponseUtil.ResponseStatus.ClientError, 400, rc, request.errorMessage, null, TokenResponseStatsCollector.Endpoint.GenerateV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
            return;
        }
        rc.data().put("request", request.payload);

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) rc.data().get("response");

            // DevNote: 200 does not guarantee a token.
            if (respJson.getString("status").equals(ResponseUtil.ResponseStatus.Success) && respJson.containsKey("body")) {
                V2RequestUtil.handleRefreshTokenInResponseBody(respJson.getJsonObject("body"), this.keyManager, this.identityScope);
            }

            writeResponse(rc, request.nonce, respJson, request.encryptionKey);
        }
        catch (Exception ex){
            LOGGER.error("Failed to generate token", ex);
            ResponseUtil.Error(ResponseUtil.ResponseStatus.GenericError, 500, rc, "");
        }
    }

    public void handleTokenRefresh(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        String bodyString = rc.body().asString();

        V2RequestUtil.V2Request request = null;
        if (bodyString != null && bodyString.length() == V2RequestUtil.V2_REFRESH_PAYLOAD_LENGTH) {
            request = V2RequestUtil.parseRefreshRequest(bodyString, this.keyManager);
            if (!request.isValid()) {
                SendClientErrorResponseAndRecordStats(ResponseUtil.ResponseStatus.ClientError, 400, rc, request.errorMessage, null, TokenResponseStatsCollector.Endpoint.RefreshV2, TokenResponseStatsCollector.ResponseStatus.BadPayload, siteProvider);
                return;
            }
            rc.data().put("request", request.payload);
        }
        else {
            rc.data().put("request", bodyString);
        }

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) rc.data().get("response");

            JsonObject bodyJson = respJson.getJsonObject("body");
            if (bodyJson != null)
                V2RequestUtil.handleRefreshTokenInResponseBody(bodyJson, this.keyManager, this.identityScope);

            if (request != null) {
                rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
                // Encrypt whole payload using key shared with client.
                byte[] encryptedResp = AesGcm.encrypt(
                    respJson.encode().getBytes(StandardCharsets.UTF_8),
                    request.encryptionKey);
                rc.response().end(Utils.toBase64String(encryptedResp));
            }
            else {
                rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(respJson.encode());
            }
        }
        catch (Exception ex){
            LOGGER.error("Failed to refresh token", ex);
            ResponseUtil.Error(ResponseUtil.ResponseStatus.GenericError, 500, rc, "");
        }
    }

    private void passThrough(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        rc.data().put("request", rc.body().asJsonObject());
        apiHandler.handle(rc);
        if (rc.response().getStatusCode() != 200 || rc.response().ended()) {
            return;
        }
        JsonObject respJson = (JsonObject) rc.data().get("response");
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(respJson.encode());

    }

    private void writeResponse(RoutingContext rc, byte[] nonce, JsonObject resp, byte[] keyBytes) {
        if (rc.response().ended()) {
            return;
        }
        Buffer buffer = Buffer.buffer();
        buffer.appendLong(EncodingUtils.NowUTCMillis().toEpochMilli());
        buffer.appendBytes(nonce);
        buffer.appendBytes(resp.encode().getBytes(StandardCharsets.UTF_8));

        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
        rc.response().end(Utils.toBase64String(AesGcm.encrypt(buffer.getBytes(), keyBytes)));
    }

    private void handleResponse(RoutingContext rc, V2RequestUtil.V2Request request) {
        if (rc.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) rc.data().get("response");

            writeResponse(rc, request.nonce, respJson, request.encryptionKey);
        } catch (Exception ex) {
            LOGGER.error("Failed to generate response", ex);
            ResponseUtil.Error(ResponseUtil.ResponseStatus.GenericError, 500, rc, "");
        }
    }
}

