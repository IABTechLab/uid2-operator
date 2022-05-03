package com.uid2.operator.vertx;

import com.sun.org.apache.xpath.internal.operations.Bool;
import com.uid2.operator.service.EncryptionHelper;
import com.uid2.operator.service.ResponseUtil;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.store.IClientKeyProvider;
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

    private Boolean enableEncryption;

    private final Clock clock;

    public V2PayloadHandler(Boolean enableEncryption, Clock clock) {
        this.enableEncryption = enableEncryption;
        this.clock = clock;
    }

    public void handle(RoutingContext rc, Handler<RoutingContext> apiHandler) {
        if (!enableEncryption) {
            passThrough(rc, apiHandler);
            return;
        }

        ClientKey ck = AuthMiddleware.getAuthClient(ClientKey.class, rc);

        // Payload envelop format:
        //  byte 0: version
        //  byte 1-12: GCM IV
        //  byte 13-end: encrypted payload
        byte[] bodyBytes = Utils.decodeBase64String(rc.getBodyAsString());
        if (!sanityCheck(bodyBytes, MIN_PAYLOAD_LENGTH)) {
            ResponseUtil.ClientError(rc, "wrong format");
            return;
        }

        // Request envelop format:
        //  byte 0-7: timestamp
        //  byte 8-15: nonce
        //  byte 16-end: base64 encoded request JSON
        byte[] decryptedBody;
        try {
            decryptedBody = EncryptionHelper.decryptGCM(bodyBytes, 1, ck.getSecretBytes());
        }
        catch (Exception ex) {
            ResponseUtil.ClientError(rc, "fail to decrypt");
            return;
        }

        Buffer b = Buffer.buffer(decryptedBody);
        Instant tm = Instant.ofEpochMilli(b.getLong(0));
        if (Math.abs(Duration.between(tm, Instant.now(clock)).toMinutes()) > 1.0) {
            ResponseUtil.ClientError(rc, "invalid timestamp");
            return;
        }

        if (decryptedBody.length > 16) {
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

        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
        rc.response().end(Utils.toBase64String(EncryptionHelper.encryptGCM(respJson.encode().getBytes(StandardCharsets.UTF_8), ck.getSecretBytes())));
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

