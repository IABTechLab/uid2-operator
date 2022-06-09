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

package com.uid2.operator.service;

import com.uid2.operator.model.EncryptedPayload;
import com.uid2.shared.model.EncryptionKey;
import io.vertx.core.buffer.Buffer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EncryptionHelper {

    // private static String cipherScheme = "AES/CBC/PKCS5Padding";
    // private static String cipherScheme = "AES/CBC/PKCS5Padding";

    private static String cipherScheme = "AES/CBC/PKCS5Padding";

    private static String gcmCipherScheme = "AES/GCM/NoPadding";

    public static final int GCM_AUTHTAG_LENGTH = 16;

    public static final int GCM_IV_LENGTH = 12;

    private static ThreadLocal<SecureRandom> threadLocalSecureRandom = ThreadLocal.withInitial(() -> {
        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    });

    public static EncryptedPayload encrypt(byte[] b, EncryptionKey key) {
        try {
            final SecretKey k = new SecretKeySpec(key.getKeyBytes(), "AES");
            final Cipher c = Cipher.getInstance(cipherScheme);
            final byte[] ivBytes = new byte[16];
            threadLocalSecureRandom.get().nextBytes(ivBytes);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            c.init(Cipher.ENCRYPT_MODE, k, ivParameterSpec);
            final byte[] encryptedBytes = c.doFinal(b);
            return new EncryptedPayload(key.getKeyIdentifier(), Buffer.buffer().appendBytes(ivBytes).appendBytes(encryptedBytes).getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static EncryptedPayload encrypt(String s, EncryptionKey key) {
        try {
            return encrypt(s.getBytes("UTF-8"), key);
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static byte[] decrypt(byte[] encryptedBytes, EncryptionKey key) {
        try {
            final SecretKey k = new SecretKeySpec(key.getKeyBytes(), "AES");
            return decrypt(encryptedBytes, k);
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static byte[] decrypt(byte[] encryptedBytes, SecretKey key) {
        try {
            final IvParameterSpec iv = new IvParameterSpec(encryptedBytes, 0, 16);
            final Cipher c = Cipher.getInstance(cipherScheme);
            c.init(Cipher.DECRYPT_MODE, key, iv);
            return c.doFinal(encryptedBytes, 16, encryptedBytes.length - 16);
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static EncryptedPayload encryptGCM(byte[] b, EncryptionKey key) {
        try {
            byte[] encypted = encryptGCM(b, key.getKeyBytes());
            return new EncryptedPayload(key.getKeyIdentifier(), encypted);
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static byte[] encryptGCM(byte[] b, byte[] secretBytes) {
        try {
            final SecretKey k = new SecretKeySpec(secretBytes, "AES");
            final Cipher c = Cipher.getInstance(gcmCipherScheme);
            final byte[] ivBytes = new byte[GCM_IV_LENGTH];
            threadLocalSecureRandom.get().nextBytes(ivBytes);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_AUTHTAG_LENGTH * 8, ivBytes);
            c.init(Cipher.ENCRYPT_MODE, k, gcmParameterSpec);
            return Buffer.buffer().appendBytes(ivBytes).appendBytes(c.doFinal(b)).getBytes();
        } catch (Exception e) {
            throw new RuntimeException("Unable to Encrypt", e);
        }
    }

    public static byte[] decryptGCM(byte[] encryptedBytes, int offset, EncryptionKey key) {
        try {
            return decryptGCM(encryptedBytes, offset, key.getKeyBytes());
        } catch (Exception e) {
            throw new RuntimeException("Unable to Decrypt", e);
        }
    }

    public static byte[] decryptGCM(byte[] encryptedBytes, int offset, byte[] secretBytes) {
        try {
            final SecretKey key = new SecretKeySpec(secretBytes, "AES");
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_AUTHTAG_LENGTH * 8, encryptedBytes, offset, GCM_IV_LENGTH);
            final Cipher c = Cipher.getInstance(gcmCipherScheme);
            c.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return c.doFinal(encryptedBytes, offset + GCM_IV_LENGTH, encryptedBytes.length - offset - GCM_IV_LENGTH);
        } catch (Exception e) {
            throw new RuntimeException("Unable to Decrypt", e);
        }
    }

    public static byte[] getRandomKeyBytes() {
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Trouble Generating Random Key Bytes", e);
        }
    }

}
