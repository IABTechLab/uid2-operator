package com.uid2.operator.nitro;

import com.uid2.shared.Const;
import com.uid2.shared.attest.AttestationFactory;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.NitroAttestationProvider;
import com.uid2.shared.secure.NitroEnclaveIdentifier;
import com.uid2.shared.secure.nitro.AttestationRequest;
import com.uid2.shared.secure.nitro.InMemoryAWSCertificateStore;
import org.junit.Test;

import javax.crypto.Cipher;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AttestationTest {

//    @Test
//    public void testAttestation() throws Exception {
//        String enclaveEnvironment = System.getenv("ENCLAVE_ENVIRONMENT");
//        if (enclaveEnvironment == null || enclaveEnvironment.isEmpty()) {
//            return;
//        }
//
//        if (enclaveEnvironment.equals("aws-nitro")) {
//            testNitroAttestation();
//        }
//    }
//
//    private void testNitroAttestation() throws Exception {
//        final com.uid2.shared.secure.NitroAttestationProvider server = new NitroAttestationProvider();
//        final com.uid2.enclave.IAttestationProvider client = AttestationFactory.getNitroAttestation();
//
//        final KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
//        gen.initialize(2048, new SecureRandom());
//        final KeyPair keyPair = gen.generateKeyPair();
//        final byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7};
//
//        Object nitroParams = AttestationFactory.getNitroRequestParameters(keyPair.getPublic().getEncoded(), nonce);
//        byte[] attestationRequest = client.getAttestationRequest(nitroParams);
//        AttestationRequest originalRequest = AttestationRequest.createFrom(attestationRequest);
//        String pcr0String = Base64.getEncoder().encodeToString(originalRequest.getAttestationDocument().getPcr(0));
//        server.addIdentifier(NitroEnclaveIdentifier.fromBase64(pcr0String));
//        AttestationResult result = server.attest(attestationRequest, new InMemoryAWSCertificateStore());
//        assertTrue(result.isSuccess());
//        assertArrayEquals(keyPair.getPublic().getEncoded(), result.getPublicKey());
//        assertArrayEquals(nonce, result.getNonce());
//
//        final String payload = "hello, world";
//        Cipher encryption  = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
//        KeySpec keySpec = new X509EncodedKeySpec(result.getPublicKey());
//        PublicKey publicKey = KeyFactory.getInstance(Const.Name.AsymetricEncryptionKeyClass).generatePublic(keySpec);
//        encryption.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encrypted = encryption.doFinal(payload.getBytes(StandardCharsets.UTF_8));
//
//        Cipher decryption  = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
//        decryption.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
//        byte[] plaintext = decryption.doFinal(encrypted);
//
//        assertEquals(payload, new String(plaintext, StandardCharsets.UTF_8));
//    }
//
//    @Test
//    public void testCipherMatching() throws Exception {
//        final KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
//        gen.initialize(2048, new SecureRandom());
//        final KeyPair keyPair = gen.generateKeyPair();
//        final byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7};
//
//        final String payload = "hello, world";
//        Cipher encryption = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
//        KeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
//        PublicKey publicKey = KeyFactory.getInstance(Const.Name.AsymetricEncryptionKeyClass).generatePublic(keySpec);
//        encryption.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encrypted = encryption.doFinal(payload.getBytes(StandardCharsets.UTF_8));
//
//        Cipher decryption  = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
//        decryption.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
//        byte[] plaintext = decryption.doFinal(encrypted);
//
//        assertEquals(payload, new String(plaintext, StandardCharsets.UTF_8));
//    }

}
