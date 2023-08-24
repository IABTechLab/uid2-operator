package com.uid2.operator;

import com.uid2.shared.encryption.AesCbc;
import com.uid2.shared.encryption.Random;
import com.uid2.shared.model.EncryptedPayload;
import com.uid2.shared.encryption.AesGcm;
import com.uid2.shared.model.KeysetKey;
import junit.framework.TestCase;
import org.junit.Assert;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

public class EncryptionTest extends TestCase {

    private int count = 0;

    public void testEncryption() throws Exception {

        final KeysetKey key = new KeysetKey(1, Random.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), 10);
        final String testString = "foo@bar.comasdadsjahjhafjhjkfhakjhfkjshdkjfhaskdjfh";

        final EncryptedPayload payload = AesCbc.encrypt(testString, key);
        final byte[] decrypted = AesCbc.decrypt(payload.getPayload(), key);

        final String decryptedString = new String(decrypted, StandardCharsets.UTF_8);
        Assert.assertEquals(testString, decryptedString);
    }

    public void testBenchmark() throws Exception {
        if (System.getenv("SLOW_DEV_URANDOM") != null) {
            System.err.println("ignore this test since environment variable SLOW_DEV_URANDOM is set");
            return;
        }
        System.out.println("Java VM property java.security.egd: " + System.getProperty("java.security.egd"));
        final int runs = 1000000;
        final KeysetKey key = new KeysetKey(1, Random.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), 10);

        final EncryptedPayload[] payloads = new EncryptedPayload[runs];

        final String[] inputs = new String[runs];
        for (int i = 0; i < runs; ++i) {
            final String input = "foo@bar.com" + i;
            inputs[i] = input;
            payloads[i] = AesCbc.encrypt(input, key);
        }

        long startBase = System.nanoTime();
        for (int i = 0; i < runs; ++i) {
            doSomething(payloads[0]);
        }
        long endBase = System.nanoTime();

        final SecretKey decryptionKey = new SecretKeySpec(key.getKeyBytes(), "AES");
        long startDecrypt = System.nanoTime();
        for (int i = 0; i < runs; ++i) {
            AesCbc.decrypt(payloads[0].getPayload(), decryptionKey);
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
        final KeysetKey key = new KeysetKey(1, Random.getRandomKeyBytes(), Instant.now(), Instant.now(), Instant.now(), 10);
        String plaintxt = "hello world";
        EncryptedPayload payload = AesGcm.encrypt(plaintxt.getBytes(StandardCharsets.UTF_8), key);
        String decryptedText = new String(AesGcm.decrypt(payload.getPayload(), 0, key), StandardCharsets.UTF_8);
        assertEquals(plaintxt, decryptedText);
    }
}
