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

package com.uid2.operator;

import com.uid2.operator.model.EncryptedPayload;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.operator.service.EncryptionHelper;
import junit.framework.TestCase;
import org.junit.Assert;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assume.assumeTrue;

public class EncryptionTest extends TestCase {

    private int count = 0;

    public void testEncryption() throws Exception {

        final EncryptionKey key = new EncryptionKey(1, EncryptionHelper.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), -1);
        final String testString = "foo@bar.comasdadsjahjhafjhjkfhakjhfkjshdkjfhaskdjfh";

        final EncryptedPayload payload = EncryptionHelper.encrypt(testString, key);
        final byte[] decrypted = EncryptionHelper.decrypt(payload.getPayload(), key);

        final String decryptedString = new String(decrypted, "UTF-8");
        Assert.assertEquals(testString, decryptedString);
    }

    public void testBenchmark() throws Exception {
        if (System.getenv("SLOW_DEV_URANDOM") != null) {
            System.err.println("ignore this test since environment variable SLOW_DEV_URANDOM is set");
            return;
        }
        System.out.println("Java VM property java.security.egd: " + System.getProperty("java.security.egd"));
        final int runs = 1000000;
        final EncryptionKey key = new EncryptionKey(1, EncryptionHelper.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), -1);

        final EncryptedPayload[] payloads = new EncryptedPayload[runs];

        final String[] inputs = new String[runs];
        for (int i = 0; i < runs; ++i) {
            final String input = "foo@bar.com" + i;
            inputs[i] = input;
            payloads[i] = EncryptionHelper.encrypt(input, key);
        }

        long startBase = System.nanoTime();
        for (int i = 0; i < runs; ++i) {
            doSomething(payloads[0]);
        }
        long endBase = System.nanoTime();

        final SecretKey decryptionKey = new SecretKeySpec(key.getKeyBytes(), "AES");
        long startDecrypt = System.nanoTime();
        for (int i = 0; i < runs; ++i) {
            EncryptionHelper.decrypt(payloads[0].getPayload(), decryptionKey);
        }
        long endDecrypt = System.nanoTime();

        long baseTime = endBase - startBase;
        long decryptTime = endDecrypt - startDecrypt;

        long overhead = (decryptTime - baseTime);
        double overheadPerEntry = overhead / (runs * 1.0);

        System.out.println("Number of Entries Tested = " + runs);
        System.out.println("Decryption Overhead per Entry (ms) = " + overheadPerEntry / (1000000 * 1.0));

        // System.out.println("Entries = "+runs+", Base Operation Execution Time (ms) = " + baseTime/(1000000*1.0) + ", With Decryption(ms) = " + decryptTime/(1000000*1.0) + ", Overhead/Entry (ms) = "  + ((decryptTime-baseTime)/(runs*1.0)/(1000000*1.0)));

    }

    public void testSecureRandom() throws NoSuchAlgorithmException {
        if (System.getenv("SLOW_DEV_URANDOM") != null) {
            System.err.println("ignore this test since environment variable SLOW_DEV_URANDOM is set");
            return;
        }
        System.out.println("Java VM property java.security.egd: " + System.getProperty("java.security.egd"));
        final byte[] ivBytes = new byte[16];
        {
            long startTime = System.nanoTime();
            for (int i = 0; i < 1000000; ++i) {
                ThreadLocalRandom.current().nextBytes(ivBytes);
            }
            long elapsedTimeMs = (System.nanoTime() - startTime) / 1000000;
            System.out.println("1 million ThreadLocalRandom::nextBytes byte[16]: " + elapsedTimeMs + "ms");
        }

        {
            ThreadLocal<SecureRandom> srand = ThreadLocal.withInitial(() -> {
                try {
                    return SecureRandom.getInstance("SHA1PRNG");
                } catch (NoSuchAlgorithmException e) {
                    return null;
                }
            });
            long startTime = System.nanoTime();
            for (int i = 0; i < 1000000; ++i) {
                srand.get().nextBytes(ivBytes);
            }
            long elapsedTimeMs = (System.nanoTime() - startTime) / 1000000;
            System.out.println("1 million SecureRandom::nextBytes byte[16]: " + elapsedTimeMs + "ms");
        }
    }

    public void testNewInstancesReturned() throws NoSuchAlgorithmException {
        SecureRandom r1 = SecureRandom.getInstance("SHA1PRNG");
        SecureRandom r2 = SecureRandom.getInstance("SHA1PRNG");
        assertNotSame(r1, r2);
    }

    public void doSomething(EncryptedPayload loag) {
        count++;
    }

    public void testGCMEncryptionDecryption() {
        final EncryptionKey key = new EncryptionKey(1, EncryptionHelper.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), -1);
        String plaintxt = "hello world";
        EncryptedPayload payload = EncryptionHelper.encryptGCM(plaintxt.getBytes(StandardCharsets.UTF_8), key);
        String decryptedText = new String(EncryptionHelper.decryptGCM(payload.getPayload(), 0, key), StandardCharsets.UTF_8);
        assertEquals(plaintxt, decryptedText);
    }
}
