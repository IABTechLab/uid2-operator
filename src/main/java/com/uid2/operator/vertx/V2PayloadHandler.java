package com.uid2.operator.vertx;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.ResponseUtil;
import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.encryption.AesGcm;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class V2PayloadHandler {
    private static final io.vertx.core.logging.Logger LOGGER = LoggerFactory.getLogger(V2PayloadHandler.class);

    private IKeyStore keyStore;

    private Boolean enableEncryption;

    private IdentityScope identityScope;

    public V2PayloadHandler(IKeyStore keyStore, Boolean enableEncryption, IdentityScope identityScope) {
        this.keyStore = keyStore;
        this.enableEncryption = enableEncryption;
        this.identityScope = identityScope;
    }

    public void handle(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.getBodyAsString(), AuthMiddleware.getAuthClient(ClientKey.class, rc));
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

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.getBodyAsString(), AuthMiddleware.getAuthClient(ClientKey.class, rc));
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

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(rc.getBodyAsString(), AuthMiddleware.getAuthClient(ClientKey.class, rc));
        if (!request.isValid()) {
            ResponseUtil.ClientError(rc, request.errorMessage);
            return;
        }
        rc.data().put("request", request.payload);

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) rc.data().get("response");

            V2RequestUtil.handleRefreshTokenInResponseBody(respJson.getJsonObject("body"), keyStore, this.identityScope);

            writeResponse(rc, request.nonce, respJson, request.encryptionKey);
        }
        catch (Exception ex){
            LOGGER.error("Failed to generate token", ex);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, rc, "");
        }
    }

    public void handleTokenRefresh(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        String bodyString = rc.getBodyAsString();

        V2RequestUtil.V2Request request = null;
        if (bodyString.length() == V2RequestUtil.V2_REFRESH_PAYLOAD_LENGTH) {
            request = V2RequestUtil.parseRefreshRequest(bodyString, this.keyStore);
            if (!request.isValid()) {
                ResponseUtil.ClientError(rc, request.errorMessage);
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
                V2RequestUtil.handleRefreshTokenInResponseBody(bodyJson, keyStore, this.identityScope);

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
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, rc, "");
        }
    }

    private void passThrough(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        rc.data().put("request", rc.getBodyAsJson());
        apiHandler.handle(rc);
        if (rc.response().getStatusCode() != 200) {
            return;
        }
        JsonObject respJson = (JsonObject) rc.data().get("response");
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .end(respJson.encode());
    }

    private void writeResponse(RoutingContext rc, byte[] nonce, JsonObject resp, byte[] keyBytes) {
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
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, rc, "");
        }
    }
}

