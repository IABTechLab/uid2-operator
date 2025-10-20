package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.TokenUtils;
import io.vertx.core.buffer.Buffer;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class ProofOfConceptAdvertisingIDV4 {

    private byte[] generateIV(String salt, byte[] firstLevelHashLast16Bytes, String metadata, int keyId) {
        int iv_length = 12;
        String iv_base = salt
                .concat(Arrays.toString(firstLevelHashLast16Bytes))
                .concat(String.valueOf(metadata))
                .concat(String.valueOf(keyId));
        return Arrays.copyOfRange(EncodingUtils.getSha256Bytes(iv_base), 0, iv_length);
    }

    private byte[] padIV16Bytes(byte[] iv12Bytes) {
        // Pad the 12-byte IV to 16 bytes for AES-CTR (standard block size)
        byte[] ctrIV = new byte[16];
        System.arraycopy(iv12Bytes, 0, ctrIV, 0, 12); // Copy 12-byte IV
        // Remaining 4 bytes are already zero-initialized (counter starts at 0)
        System.out.println("Padded IV for AES-CTR (16 bytes): " + EncodingUtils.toBase64String(ctrIV));
        return ctrIV;
    }

    private byte[] encryptFirstLevelHash(String encryptionKey, byte[] firstLevelHashLast16Bytes, byte[] iv) throws Exception {
        // AES256-CTR Encryption

        // Set up AES256-CTR cipher
        Cipher aesCtr = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(padIV16Bytes(iv));

        // Encrypt the 16-byte first level hash
        aesCtr.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return aesCtr.doFinal(firstLevelHashLast16Bytes);
    }

    private byte[] decryptEncryptedFirstLevelHash(String encryptionKey, byte[] encryptedFirstLevelHash, byte[] iv) throws Exception {
        Cipher aesCtr = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(padIV16Bytes(iv));
        aesCtr.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return aesCtr.doFinal(encryptedFirstLevelHash);
    }

    private byte generateChecksum(byte[] data) {
        // Simple XOR checksum of all bytes
        byte checksum = 0;
        for (byte b : data) {
            checksum ^= b;
        }
        System.out.println("Checksum: 0x" + String.format("%02X", checksum));
        return checksum;
    }

    private byte[] constructUIDv4(byte metadata, int keyId, byte[] iv, byte[] encryptedFirstLevelHash) {
        Buffer buffer = Buffer.buffer();
        buffer.appendByte(metadata);
        buffer.appendBytes(new byte[] {
                (byte) (keyId & 0xFF),           // LSB
                (byte) ((keyId >> 8) & 0xFF),    // Middle
                (byte) ((keyId >> 16) & 0xFF)    // MSB
        });
        buffer.appendBytes(iv);
        buffer.appendBytes(encryptedFirstLevelHash);

        byte checksum = generateChecksum(buffer.getBytes());
        buffer.appendByte(checksum);

        return buffer.getBytes();
    }

    @Test
    public void encryptDecryptAdvertisingID() throws Exception {
        String salt = "salt1234salt1234salt1234salt1234";
        String key = "key12345key12345key12345key12345";
        int encryptionKeyId = 1000000;
        byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity("test@example.com", salt);
        byte[] firstLevelHashLast16Bytes = Arrays.copyOfRange(firstLevelHash, firstLevelHash.length - 16, firstLevelHash.length);
        byte metadata = (byte) 0b10110101;

        // generating advertising ID
        byte[] iv = generateIV(salt, firstLevelHashLast16Bytes, key, encryptionKeyId);
        byte[] encryptedFirstLevelHash = encryptFirstLevelHash(key, firstLevelHashLast16Bytes, iv);
        
        // Construct v4 UID: metadata + key id + iv + encrypted first level hash + checksum
        byte[] v4UID = constructUIDv4(metadata, encryptionKeyId, iv, encryptedFirstLevelHash);

        assertEquals(33, v4UID.length);

        // Test extraction of components
        byte extractedMetadata = v4UID[0];
        byte[] keyIdBytes = Arrays.copyOfRange(v4UID, 1, 4);
        int extractedKeyId = (keyIdBytes[0] & 0xFF) | ((keyIdBytes[1] & 0xFF) << 8) | ((keyIdBytes[2] & 0xFF) << 16);
        byte[] extractedIV = Arrays.copyOfRange(v4UID, 4, 16);
        byte[] extractedEncryptedHash = Arrays.copyOfRange(v4UID, 16, 32);
        byte extractedChecksum = v4UID[32];

        assertEquals(metadata, extractedMetadata);
        assertEquals(encryptionKeyId, extractedKeyId);
        assertArrayEquals(iv, extractedIV);
        assertArrayEquals(encryptedFirstLevelHash, extractedEncryptedHash);

        // Verify checksum
        byte recomputedChecksum = generateChecksum(Arrays.copyOfRange(v4UID, 0, 32));
        assertEquals(extractedChecksum, recomputedChecksum);

        // Test decryption to verify correctness
        byte[] decryptedFirstLevelHash = decryptEncryptedFirstLevelHash(key, extractedEncryptedHash, extractedIV);
        assertEquals(16, decryptedFirstLevelHash.length);
        assertArrayEquals(firstLevelHashLast16Bytes, decryptedFirstLevelHash);

        // Recalculate IV
        byte[] recalculatedIV = generateIV(salt, decryptedFirstLevelHash, key, extractedKeyId);
        assertArrayEquals(extractedIV, recalculatedIV);

        // Rebuild UID
        byte[] reconstructedUID = constructUIDv4(metadata, encryptionKeyId, recalculatedIV, encryptFirstLevelHash(key, decryptedFirstLevelHash, recalculatedIV));

        assertArrayEquals(reconstructedUID, v4UID);

        // Print results for verification
        System.out.println("Original metadata: 0x" + String.format("%02X", extractedMetadata));
        System.out.println("Original key ID: " + encryptionKeyId);
        System.out.println("Original IV (12 bytes): " + EncodingUtils.toBase64String(iv));
        System.out.println("Original 16-byte first level hash: " + EncodingUtils.toBase64String(firstLevelHashLast16Bytes));
        System.out.println("Encrypted hash: " + EncodingUtils.toBase64String(encryptedFirstLevelHash));
        System.out.println("V4 UID (33 bytes): " + EncodingUtils.toBase64String(v4UID));
        System.out.println();
        System.out.println("=== EXTRACTION VERIFICATION ===");
        System.out.println("Extracted metadata: 0x" + String.format("%02X", extractedMetadata));
        System.out.println("Extracted key ID: " + extractedKeyId);
        System.out.println("Extracted IV (12 bytes): " + EncodingUtils.toBase64String(extractedIV));
        System.out.println("Extracted encrypted hash: " + EncodingUtils.toBase64String(extractedEncryptedHash));
        System.out.println("Extracted checksum: 0x" + String.format("%02X", extractedChecksum));
        System.out.println("Decrypted 16-byte first level hash: " + EncodingUtils.toBase64String(decryptedFirstLevelHash));
        System.out.println("Reconstructed V4 UID (33 bytes): " + EncodingUtils.toBase64String(reconstructedUID));
        System.out.println("✓ All verifications passed - V4 UID format is correct and functional!");
    }
} 