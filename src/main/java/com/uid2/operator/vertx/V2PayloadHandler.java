package com.uid2.operator.vertx;

import com.uid2.operator.service.EncryptionHelper;
import com.uid2.operator.service.ResponseUtil;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.IKeyStore;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class V2PayloadHandler {
    private static final io.vertx.core.logging.Logger LOGGER = LoggerFactory.getLogger(V2PayloadHandler.class);

    // version: 1 byte, IV: 12 bytes, GCM tag: 16 bytes, timestamp: 8 bytes, nonce: 8 bytes
    private static final int MIN_PAYLOAD_LENGTH = 1 + EncryptionHelper.GCM_IV_LENGTH + EncryptionHelper.GCM_AUTHTAG_LENGTH + 8 + 8;

    private static final byte VERSION = 1;

    private IKeyStore keyStore;

    private Boolean enableEncryption;

    private final Clock clock;

    public final int V2_REFRESH_PAYLOAD_LENGTH = 360;

    public V2PayloadHandler(IKeyStore keyStore, Boolean enableEncryption, Clock clock) {
        this.keyStore = keyStore;
        this.enableEncryption = enableEncryption;
        this.clock = clock;
    }

    public void handle(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        ClientKey ck = AuthMiddleware.getAuthClient(ClientKey.class, rc);

        byte[] decryptedBody = decryptAndValidate(ck, rc);
        if (decryptedBody == null) {
            return;
        }

        if (decryptedBody.length > 16) {
            // Skip 8 bytes timestamp, 8 bytes nonce
            String bodyStr = new String(decryptedBody, 16, decryptedBody.length - 16, StandardCharsets.UTF_8);
            JsonObject reqJson = new JsonObject(bodyStr);
            rc.data().put("request", reqJson);
        }

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        JsonObject respJson = (JsonObject) rc.data().get("response");

        // Echo nonce back for client to validate response
        String nonce = Utils.toBase64String(Buffer.buffer(decryptedBody).slice(8, 16).getBytes());
        respJson.put("nonce", nonce);

        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
        rc.response().end(Utils.toBase64String(EncryptionHelper.encryptGCM(respJson.encode().getBytes(StandardCharsets.UTF_8), ck.getSecretBytes())));
    }

    public void handleTokenGenerate(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        ClientKey ck = AuthMiddleware.getAuthClient(ClientKey.class, rc);

        byte[] decryptedBody = decryptAndValidate(ck, rc);
        if (decryptedBody == null) {
            return;
        }

        try {
            String bodyStr = new String(decryptedBody, 16, decryptedBody.length - 16, StandardCharsets.UTF_8);
            JsonObject reqJson = new JsonObject(bodyStr);
            rc.data().put("request", reqJson);
        } catch (Exception ex) {
            ResponseUtil.ClientError(rc, "cannot parse request");
            return;
        }

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        JsonObject respJson = (JsonObject) rc.data().get("response");

        // Echo nonce back for client to validate response
        String nonce = Utils.toBase64String(Buffer.buffer(decryptedBody).slice(8, 16).getBytes());
        respJson.put("nonce", nonce);

        try {
            handleRefreshTokenInResponse(respJson);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
            rc.response().end(Utils.toBase64String(EncryptionHelper.encryptGCM(respJson.encode().getBytes(StandardCharsets.UTF_8), ck.getSecretBytes())));
        }
        catch (Exception ex){
            LOGGER.error("Failed to encrypt refresh token", ex);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, rc, "fail to encrypt refresh token");
        }
    }

    public void handleTokenRefresh(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        byte[] responseKey = null;

        String bodyStr = rc.getBodyAsString();
        if (bodyStr.length() != V2_REFRESH_PAYLOAD_LENGTH) {
            // Pass through unencrypted v1 refresh token
            rc.data().put("refresh_token", bodyStr);
        } else {
            try {
                JsonObject v2Payload = decodeV2RefreshPayload(this.keyStore, bodyStr);
                responseKey = Utils.decodeBase64String(v2Payload.getString("refresh_response_key"));

                String refreshToken = v2Payload.getString("refresh_token");
                rc.data().put("refresh_token", refreshToken);
            } catch (Exception ex) {
                LOGGER.error("Failed to decode", ex);
                ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.InvalidToken, 400, rc, "Invalid Token presented");
                return;
            }
        }

        apiHandler.handle(rc);

        if (rc.response().getStatusCode() != 200) {
            return;
        }

        JsonObject respJson = (JsonObject) rc.data().get("response");
        try {
            handleRefreshTokenInResponse(respJson);

            if (responseKey != null) {
                rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
                // Encrypt whole payload using key shared with client.
                byte[] encryptedResp = EncryptionHelper.encryptGCM(
                    respJson.encode().getBytes(StandardCharsets.UTF_8),
                    responseKey);
                rc.response().end(Utils.toBase64String(encryptedResp));
            }
            else {
                rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(respJson.encode());
            }
        }
        catch (Exception ex){
            LOGGER.error("Failed to encrypt refresh token", ex);
            ResponseUtil.Error(UIDOperatorVerticle.ResponseStatus.GenericError, 500, rc, "fail to encrypt refresh token");
        }
    }

    public static JsonObject decodeV2RefreshPayload(IKeyStore keyStore, String body) {
        // Refresh token envelop format:
        //  byte 0-4: ID of key used to encrypt body
        //  byte 5-N: IV + encrypted body + GCM AUTH TAG
        byte[] bytes = Utils.decodeBase64String(body);

        int keyId = Buffer.buffer(bytes).getInt(0);

        EncryptionKey key = keyStore.getSnapshot().getKey(keyId);
        if (key == null) {
            throw new RuntimeException("Key not found");
        }

        byte[] decrypted = EncryptionHelper.decryptGCM(bytes, 4, key);
        return new JsonObject(new String(decrypted, StandardCharsets.UTF_8));
    }

    private void handleRefreshTokenInResponse(JsonObject respJson) throws Exception {
        EncryptionKey refreshKey = keyStore.getSnapshot().getRefreshKey(clock.instant());

        JsonObject tokenKeyJson = new JsonObject();

        String refreshResponseKey = Utils.toBase64String(EncryptionHelper.getRandomKeyBytes());
        tokenKeyJson.put("refresh_response_key", refreshResponseKey);

        JsonObject bodyJson = respJson.getJsonObject("body");
        String origToken = bodyJson.getString("refresh_token");
        tokenKeyJson.put("refresh_token", origToken);

        byte[] encrypted = EncryptionHelper.encryptGCM(tokenKeyJson.encode().getBytes(StandardCharsets.UTF_8), refreshKey).getPayload();

        String modifiedToken = Utils.toBase64String(Buffer.buffer()
            .appendInt(refreshKey.getId())
            .appendBytes(encrypted)
            .getBytes());
        bodyJson.put("refresh_token", modifiedToken);
        bodyJson.put("refresh_response_key", refreshResponseKey);
    }

    private byte[] decryptAndValidate(ClientKey ck, RoutingContext rc) {
        // Payload envelop format:
        //  byte 0: version
        //  byte 1-12: GCM IV
        //  byte 13-end: encrypted payload + GCM AUTH TAG
        byte[] bodyBytes = Utils.decodeBase64String(rc.getBodyAsString());
        if (!sanityCheck(bodyBytes, MIN_PAYLOAD_LENGTH)) {
            ResponseUtil.ClientError(rc, "wrong format");
            return null;
        }

        byte[] decryptedBody;
        try {
            decryptedBody = EncryptionHelper.decryptGCM(bodyBytes, 1, ck.getSecretBytes());
        }
        catch (Exception ex) {
            ResponseUtil.ClientError(rc, "fail to decrypt");
            return null;
        }

        // Request envelop format:
        //  byte 0-7: timestamp
        //  byte 8-15: nonce
        //  byte 16-end: base64 encoded request json
        Buffer b = Buffer.buffer(decryptedBody);
        Instant tm = Instant.ofEpochMilli(b.getLong(0));
        if (Math.abs(Duration.between(tm, Instant.now(clock)).toMinutes()) > 1.0) {
            ResponseUtil.ClientError(rc, "invalid timestamp");
            return null;
        }

        return decryptedBody;
    }

    private boolean sanityCheck(byte[] buf, int minLength) {
        if (buf.length < minLength) {
            return false;
        }

        if (buf[0] != VERSION) {
            return false;
        }

        return true;
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
}

