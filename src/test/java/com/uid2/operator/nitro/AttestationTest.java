// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

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
