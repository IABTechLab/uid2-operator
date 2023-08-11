package com.uid2.operator;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ClientSideTokenGenerateTestUtil {

    // in UIDOperatorVerticle (but probably should be moved)
    public static PublicKey stringToPublicKey(String publicKeyString, KeyFactory kf) {
        final byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(publicKeyBytes);
        try {
            return kf.generatePublic(pkSpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey stringToPrivateKey(String privateKeyString, KeyFactory kf) {
        final byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        try {
            return kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // in UIDOperatorVerticleTest
    public static SecretKey deriveKey(PublicKey serverPublicKey, PrivateKey clientPrivateKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "SunEC");
            keyAgreement.init(clientPrivateKey);
            keyAgreement.doPhase(serverPublicKey, true);

            byte[] secret = keyAgreement.generateSecret();

            // Use the derived secret as the AES key
            SecretKey aesKey = new SecretKeySpec(secret, "AES");

            return aesKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decrypt(byte[] encryptedBytes, int offset, byte[] secretBytes) {
        try {
            final Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");

            //todo, re-use code between here and verticle
            SecretKey key = new SecretKeySpec(secretBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, encryptedBytes, offset, 12);
            aesGcm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return aesGcm.doFinal(encryptedBytes, offset + 12, encryptedBytes.length - offset - 12);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(byte[] data, byte[] secretKey, byte[] iv, byte[] additionalData) {
        try { //todo, re-use code between here and verticle
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
            cipher.updateAAD(additionalData);

            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

/*    private void sendClientSideTokenGenerate(Vertx vertx, JsonObject unencryptedPayload, int expectedHttpCode, Handler<JsonObject> handler) throws NoSuchAlgorithmException {
        final KeyFactory kf = KeyFactory.getInstance("EC");
        final PublicKey serverPublicKey = UIDOperatorVerticle.stringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsziOqRXZ7II0uJusaMxxCxlxgj8el/MUYLFMtWfB71Q3G1juyrAnzyqruNiPPnIuTETfFOridglP9UQNlwzNQg==", kf);
        final PrivateKey clientPrivateKey = UIDOperatorVerticle.stringToPrivateKey("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDsqxZicsGytVqN2HZqNDHtV422Lxio8m1vlflq4Jb47Q==", kf);
        final SecretKey secretKey = deriveKey(serverPublicKey, clientPrivateKey);

        final byte[] iv = Random.getBytes(12);

        final long timestamp = 12345;
        final byte[] aad = new JsonArray(List.of(timestamp)).toBuffer().getBytes();
        byte[] payloadBytes = encrypt(unencryptedPayload.toString().getBytes(), secretKey.getEncoded(), iv, aad);
        final String payload = EncodingUtils.toBase64String(payloadBytes);

        JsonObject requestJson = new JsonObject();
        requestJson.put("payload", payload);
        requestJson.put("iv", EncodingUtils.toBase64String(iv));
        requestJson.put("public_key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92+xlW2eIrXsDzV4cSfldDKxLXHsMmjLIqpdwOqJ29pWTNnZMaY2ycZHFpxbp6UlQ6vVSpKwImTKr3uikm9yCw==");
        requestJson.put("timestamp", timestamp);
        requestJson.put("subscription_id", "abcdefg");

        post(vertx, "v2/token/client-generate", requestJson, ar -> {
            assertTrue(ar.succeeded());
            assertEquals(expectedHttpCode, ar.result().statusCode());

            byte[] decrypted = decrypt(Utils.decodeBase64String(ar.result().bodyAsString()), 0, secretKey.getEncoded());
            JsonObject respJson = new JsonObject(new String(decrypted, 0, decrypted.length - 0, StandardCharsets.UTF_8));

            decodeV2RefreshToken(respJson);

            handler.handle(respJson);
        });
    }*/


//    @Test
//    void clientSideTokenGenerateForEmailHash(Vertx vertx, VertxTestContext testContext) throws NoSuchAlgorithmException {
//        final int clientSiteId = 201;
//        final String emailHash = TokenUtils.getIdentityHashString("test@uid2.com");
//        setupSalts();
//        setupKeys();
//
//        JsonObject payload = new JsonObject();
//        payload.put("email_hash", emailHash);
//
//        sendClientSideTokenGenerate(vertx, payload, 200,
//                json -> {
//                    assertEquals("success", json.getString("status"));
//                    JsonObject body = json.getJsonObject("body");
//                    assertNotNull(body);
//                    EncryptedTokenEncoder encoder = new EncryptedTokenEncoder(keyStore);
//
//                    AdvertisingToken advertisingToken = validateAndGetToken(encoder, body, IdentityType.Email);
//                    assertEquals(clientSiteId, advertisingToken.publisherIdentity.siteId);
//                    assertArrayEquals(getAdvertisingIdFromIdentityHash(IdentityType.Email, emailHash, firstLevelSalt, rotatingSalt123.getSalt()), advertisingToken.userIdentity.id);
//
//                    RefreshToken refreshToken = encoder.decodeRefreshToken(body.getString("decrypted_refresh_token"));
//                    assertEquals(clientSiteId, refreshToken.publisherIdentity.siteId);
//                    assertArrayEquals(TokenUtils.getFirstLevelHashFromIdentityHash(emailHash, firstLevelSalt), refreshToken.userIdentity.id);
//
//                    assertEqualsClose(Instant.now().plusMillis(identityExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("identity_expires")), 10);
//                    assertEqualsClose(Instant.now().plusMillis(refreshExpiresAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_expires")), 10);
//                    assertEqualsClose(Instant.now().plusMillis(refreshIdentityAfter.toMillis()), Instant.ofEpochMilli(body.getLong("refresh_from")), 10);
//
//                    testContext.completeNow();
//                });
//    }
}
