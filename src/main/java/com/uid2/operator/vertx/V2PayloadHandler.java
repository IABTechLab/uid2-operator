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
import org.slf4j.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class V2PayloadHandler {
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(V2PayloadHandler.class);

    private final IKeyStore keyStore;
    private final Boolean enableEncryption;
    private final IdentityScope identityScope;

    public V2PayloadHandler(IKeyStore keyStore, Boolean enableEncryption, IdentityScope identityScope) {
        this.keyStore = keyStore;
        this.enableEncryption = enableEncryption;
        this.identityScope = identityScope;
    }

    public void handle(RoutingContext ctx, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(ctx, apiHandler);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(ctx.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, ctx));
        if (!request.isValid()) {
            ResponseUtil.ClientError(ctx, request.errorMessage);
            return;
        }
        ctx.data().put("request", request.payload);

        apiHandler.handle(ctx);

        handleResponse(ctx, request);
    }

    public void handleAsync(RoutingContext ctx, Function<RoutingContext, Future> apiHandler) {
        if (!enableEncryption) {
            apiHandler.apply(ctx);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(ctx.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, ctx));
        if (!request.isValid()) {
            ResponseUtil.ClientError(ctx, request.errorMessage);
            return;
        }
        ctx.data().put("request", request.payload);

        apiHandler.apply(ctx).onComplete(ar -> {
            handleResponse(ctx, request);
        });
    }

    public void handleTokenGenerate(RoutingContext ctx, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(ctx, apiHandler);
            return;
        }

        V2RequestUtil.V2Request request = V2RequestUtil.parseRequest(ctx.body().asString(), AuthMiddleware.getAuthClient(ClientKey.class, ctx));
        if (!request.isValid()) {
            ResponseUtil.ClientError(ctx, request.errorMessage);
            return;
        }
        ctx.data().put("request", request.payload);

        apiHandler.handle(ctx);

        if (ctx.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) ctx.data().get("response");

            // DevNote: 200 does not guarantee a token.
            if (respJson.getString("status").equals(UIDOperatorVerticle.ResponseStatus.Success) && respJson.containsKey("body")) {
                V2RequestUtil.handleRefreshTokenInResponseBody(respJson.getJsonObject("body"), keyStore, this.identityScope);
            }

            writeResponse(ctx, request.nonce, respJson, request.encryptionKey);
        }
        catch (Exception e){
            LOGGER.error("Failed to generate token", e);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, ctx, "");
        }
    }

    public void handleTokenRefresh(RoutingContext ctx, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(ctx, apiHandler);
            return;
        }

        String bodyString = ctx.body().asString();

        V2RequestUtil.V2Request request = null;
        if (bodyString.length() == V2RequestUtil.V2_REFRESH_PAYLOAD_LENGTH) {
            request = V2RequestUtil.parseRefreshRequest(bodyString, this.keyStore);
            if (!request.isValid()) {
                ResponseUtil.ClientError(ctx, request.errorMessage);
                return;
            }
            ctx.data().put("request", request.payload);
        }
        else {
            ctx.data().put("request", bodyString);
        }

        apiHandler.handle(ctx);

        if (ctx.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) ctx.data().get("response");

            JsonObject bodyJson = respJson.getJsonObject("body");
            if (bodyJson != null)
                V2RequestUtil.handleRefreshTokenInResponseBody(bodyJson, keyStore, this.identityScope);

            if (request != null) {
                ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
                // Encrypt whole payload using key shared with client.
                byte[] encryptedResp = AesGcm.encrypt(
                        respJson.encode().getBytes(StandardCharsets.UTF_8),
                        request.encryptionKey);
                ctx.response().end(Utils.toBase64String(encryptedResp));
            }
            else {
                ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .end(respJson.encode());
            }
        }
        catch (Exception e){
            LOGGER.error("Failed to refresh token", e);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, ctx, "");
        }
    }

    private void passThrough(RoutingContext ctx, Handler<RoutingContext> apiHandler) {
        ctx.data().put("request", ctx.body().asJsonObject());
        apiHandler.handle(ctx);
        if (ctx.response().getStatusCode() != 200) {
            return;
        }
        JsonObject respJson = (JsonObject) ctx.data().get("response");
        ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(respJson.encode());
    }

    private void writeResponse(RoutingContext ctx, byte[] nonce, JsonObject resp, byte[] keyBytes) {
        Buffer buffer = Buffer.buffer();
        buffer.appendLong(EncodingUtils.NowUTCMillis().toEpochMilli());
        buffer.appendBytes(nonce);
        buffer.appendBytes(resp.encode().getBytes(StandardCharsets.UTF_8));

        ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
        ctx.response().end(Utils.toBase64String(AesGcm.encrypt(buffer.getBytes(), keyBytes)));
    }

    private void handleResponse(RoutingContext ctx, V2RequestUtil.V2Request request) {
        if (ctx.response().getStatusCode() != 200) {
            return;
        }

        try {
            JsonObject respJson = (JsonObject) ctx.data().get("response");

            writeResponse(ctx, request.nonce, respJson, request.encryptionKey);
        } catch (Exception e) {
            LOGGER.error("Failed to generate response", e);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, ctx, "");
        }
    }
}
