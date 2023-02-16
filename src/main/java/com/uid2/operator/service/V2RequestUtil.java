package com.uid2.operator.service;

import com.uid2.operator.model.IdentityScope;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.encryption.Random;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class V2RequestUtil {
    public static class V2Request {
        public final String errorMessage;
        public final byte[] nonce;
        public final Object payload;
        public final byte[] encryptionKey;

        V2Request(String errorMessage) {
            this.errorMessage = errorMessage;
            this.nonce = null;
            this.payload = null;
            this.encryptionKey = null;
        }

        V2Request(byte[] nonce, Object payload, byte[] encryptionKey) {
            this.errorMessage = null;
            this.nonce = nonce;
            this.payload = payload;
            this.encryptionKey = encryptionKey;
        }

        public boolean isValid() {
            return errorMessage == null;
        }
    }

    // version: 1 byte, IV: 12 bytes, GCM tag: 16 bytes, timestamp: 8 bytes, nonce: 8 bytes
    private static final int MIN_PAYLOAD_LENGTH = 1 + AesGcm.GCM_IV_LENGTH + AesGcm.GCM_AUTHTAG_LENGTH + 8 + 8;

    private static final byte VERSION = 1;

    public static final int V2_REFRESH_PAYLOAD_LENGTH = 388;
    public static final long V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES = 1;

    private static final Logger LOGGER = LoggerFactory.getLogger(V2RequestUtil.class);

    public static V2Request parseRequest(String bodyString, ClientKey ck) {
        byte[] bodyBytes;
        try {
            // Payload envelop format:
            //  byte 0: version
            //  byte 1-12: GCM IV
            //  byte 13-end: encrypted payload + GCM AUTH TAG
            bodyBytes = Utils.decodeBase64String(bodyString);
        }
        catch (IllegalArgumentException e) {
            return new V2Request("Invalid body: Body is not valid base64.");
        }

        if (bodyBytes.length < MIN_PAYLOAD_LENGTH) {
            return new V2Request("Invalid body: Body too short. Check encryption method.");
        }

        if (bodyBytes[0] != VERSION) {
            return new V2Request("Invalid body: Version mismatch.");
        }

        byte[] decryptedBody;
        try {
            decryptedBody = AesGcm.decrypt(bodyBytes, 1, ck.getSecretBytes());
        } catch (Exception e) {
            return new V2Request("Invalid body: Check encryption key (ClientSecret)");
        }

        // Request envelop format:
        //  byte 0-7: timestamp
        //  byte 8-15: nonce
        //  byte 16-end: base64 encoded request json
        Buffer b = Buffer.buffer(decryptedBody);
        Instant tm = Instant.ofEpochMilli(b.getLong(0));
        if (Math.abs(Duration.between(tm, Clock.systemUTC().instant()).toMinutes()) >
                V2_REQUEST_TIMESTAMP_DRIFT_THRESHOLD_IN_MINUTES) {
            return new V2Request("Invalid timestamp: Request too old or client time drift.");
        }

        JsonObject payload = null;
        if (decryptedBody.length > 16) {
            try {
                // Skip 8 bytes timestamp, 8 bytes nonce
                String bodyStr = new String(decryptedBody, 16, decryptedBody.length - 16, StandardCharsets.UTF_8);
                payload = new JsonObject(bodyStr);
            } catch (Exception e) {
                LOGGER.error("Invalid payload in body: Data is not valid json string.", e);
                return new V2Request("Invalid payload in body: Data is not valid json string.");
            }
        }

        return new V2Request(b.slice(8, 16).getBytes(), payload, ck.getSecretBytes());
    }

    public static V2Request parseRefreshRequest(String bodyString, IKeyStore keyStore) {
        byte[] bytes;
        try {
            // Refresh token envelop format:
            //  byte 0:   identity scope
            //  byte 1-4: ID of key used to encrypt body
            //  byte 5-N: IV + encrypted body + GCM AUTH TAG
            bytes = Utils.decodeBase64String(bodyString);
        }
        catch (IllegalArgumentException e) {
            return new V2Request("Invalid body: Body is not valid base64.");
        }

        // Skip first identity scope byte
        int keyId = Buffer.buffer(bytes).getInt(1);

        EncryptionKey key = keyStore.getSnapshot().getKey(keyId);
        if (key == null) {
            return new V2Request("Invalid key: Generator of this token does not exist.");
        }

        byte[] decrypted;
        try {
            decrypted = AesGcm.decrypt(bytes, 5, key);
        } catch (Exception e) {
            LOGGER.error("Invalid data: Check encryption method and encryption key", e);
            return new V2Request("Invalid data: Check encryption method and encryption key");
        }

        try {
            JsonObject tokenJson = new JsonObject(new String(decrypted, StandardCharsets.UTF_8));
            byte[] responseKey = Utils.decodeBase64String(tokenJson.getString("refresh_response_key"));
            String refreshToken = tokenJson.getString("refresh_token");

            return new V2Request(null, refreshToken, responseKey);
        } catch (Exception e) {
            LOGGER.error("Invalid format: Payload is not valid json or missing required data", e);
            return new V2Request("Invalid format: Payload is not valid json or missing required data");
        }
    }

    public static void handleRefreshTokenInResponseBody(JsonObject bodyJson, IKeyStore keyStore, IdentityScope identityScope) throws Exception {
        EncryptionKey refreshKey = keyStore.getSnapshot().getRefreshKey(Clock.systemUTC().instant());

        JsonObject tokenKeyJson = new JsonObject();

        String refreshResponseKey = Utils.toBase64String(Random.getRandomKeyBytes());
        tokenKeyJson.put("refresh_response_key", refreshResponseKey);

        String origToken = bodyJson.getString("refresh_token");
        tokenKeyJson.put("refresh_token", origToken);

        byte[] encrypted = AesGcm.encrypt(tokenKeyJson.encode().getBytes(StandardCharsets.UTF_8), refreshKey).getPayload();

        String modifiedToken = Utils.toBase64String(Buffer.buffer()
            .appendByte(TokenUtils.encodeIdentityScope(identityScope))
            .appendInt(refreshKey.getId())
            .appendBytes(encrypted)
            .getBytes());
        assert modifiedToken.length() == V2_REFRESH_PAYLOAD_LENGTH;

        bodyJson.put("refresh_token", modifiedToken);
        bodyJson.put("refresh_response_key", refreshResponseKey);
    }
}
