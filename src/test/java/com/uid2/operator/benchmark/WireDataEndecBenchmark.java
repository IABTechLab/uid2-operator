package com.uid2.operator.benchmark;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.ECIESKeyEncapsulation;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class WireDataEndecBenchmark {

    private static KeyPair eccKeyPair;
    private static KeyPair rsaKeyPair;
    private static String[] contentToEncrypt;
    private static String[] contentToDecryptEcc;
    private static String[] contentToDecryptRsa;
    private static JsonObject[] contentToDecryptHybrid;
    private static int idxEnc = 0;
    private static int idxDec = 0;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            eccKeyPair = ECC.generateKeyPair();
            rsaKeyPair = RSA.generateKeyPair();
            contentToEncrypt = createResponses(65538);
            contentToDecryptEcc = createEccRequests(65538);
            contentToDecryptRsa = createRsaRequests(65538);
            contentToDecryptHybrid = createHybridRequests(65538);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String EncryptPayloadECC() throws Exception {
        return ECC.encrypt(contentToEncrypt[(idxEnc++) & 65535], eccKeyPair.getPublic());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String DecryptPayloadECC() throws Exception {
        return ECC.decrypt(contentToDecryptEcc[(idxDec++) & 65535], eccKeyPair.getPrivate());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String EncryptPayloadRSA() throws Exception {
        return RSA.encrypt(contentToEncrypt[(idxEnc++) & 65535], rsaKeyPair.getPublic());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String DecryptPayloadRSA() throws Exception {
        return RSA.decrypt(contentToDecryptRsa[(idxDec++) & 65535], rsaKeyPair.getPrivate());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public JsonObject EncryptPayloadHybrid() throws Exception {
        return HybridEcc.encrypt(contentToEncrypt[(idxEnc++) & 65535], eccKeyPair.getPublic());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public String DecryptPayloadHybrid() throws Exception {
        return HybridEcc.decrypt(contentToDecryptHybrid[(idxDec++) & 65535], eccKeyPair.getPrivate());
    }



    private static String[] createEccRequests(int count) throws Exception {
        String[] requests = new String[count];
        for (int i = 0; i < count; i++) {
            JsonObject json = new JsonObject();
            json.put("email", randomString(32) + "@example.com");
            requests[i] = ECC.encrypt(json.encode(), eccKeyPair.getPublic());
        }
        return requests;
    }

    private static String[] createRsaRequests(int count) throws Exception {
        String[] requests = new String[count];
        for (int i = 0; i < count; i++) {
            JsonObject json = new JsonObject();
            json.put("email", randomString(32) + "@example.com");
            requests[i] = RSA.encrypt(json.encode(), rsaKeyPair.getPublic());
        }
        return requests;
    }

    private static JsonObject[] createHybridRequests(int count) throws Exception {
        JsonObject[] requests = new JsonObject[count];
        for (int i = 0; i < count; i++) {
            JsonObject json = new JsonObject();
            json.put("email", randomString(32) + "@example.com");
            requests[i] = HybridEcc.encrypt(json.encode(), eccKeyPair.getPublic());
        }
        return requests;
    }

    private static String[] createResponses(int count) {
        String[] responses = new String[count];
        for (int i = 0; i < count; i++) {
            JsonObject json = new JsonObject();
            JsonObject body = new JsonObject();
            body.put("advertising_token", randomString(180));
            body.put("user_token", randomString(136));
            body.put("refresh_token", randomString(168));
            body.put("identity_expires", 1680043480592L);
            body.put("refresh_expires", 1682634580592L);
            body.put("refresh_from", 1680042880592L);
            json.put("body", body);
            json.put("status", "success");
            responses[i] = json.encode();
        }
        return responses;
    }

    // random alphanumeric string of length
    private static String randomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int index = (int) (chars.length() * Math.random());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }

    static class ECC {
        private static final String ALGORITHM = "ECIES";
        private static final String CURVE_NAME = "secp256k1";
        private static final String PROVIDER = "BC";

        public static KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
            keyPairGenerator.initialize(ecSpec);
            return keyPairGenerator.generateKeyPair();
        }

        public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
            byte[] plainBytes = plainText.getBytes("UTF-8");
            Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        }
    }

    // implementation of RSA algorithm similar to ECC
    static class RSA {
        private static final String ALGORITHM = "RSA";

        // create RSA Key pair
        public static KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        }

        public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
            byte[] plainBytes = plainText.getBytes("UTF-8");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        }
    }

    static class HybridEcc {

        public static JsonObject encrypt(String plainText, PublicKey publicKey) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            JsonObject res = new JsonObject();
            res.put("otp", ECC.encrypt(Base64.getEncoder().encodeToString(aesKey.getEncoded()), publicKey));
            res.put("payload", Base64.getEncoder().encodeToString(aesCipher.doFinal(plainText.getBytes("UTF-8"))));
            return res;
        }

        public static String decrypt(JsonObject encrypted, PrivateKey privateKey) throws Exception {
            String aesKey = ECC.decrypt(encrypted.getString("otp"), privateKey);
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(aesKey), "AES"));
            return new String(aesCipher.doFinal(Base64.getDecoder().decode(encrypted.getString("payload"))), "UTF-8");
        }
    }

}
