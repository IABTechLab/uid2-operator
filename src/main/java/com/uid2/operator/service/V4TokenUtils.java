package com.uid2.operator.service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import io.vertx.core.buffer.Buffer;

import java.util.Arrays;

public final class V4TokenUtils {
    private static final int IV_LENGTH = 12;

    private V4TokenUtils() {
    }

    public static byte[] buildAdvertisingIdV4(byte metadata, byte[] firstLevelHash, int keyId, String key, String salt) throws Exception {
        byte[] firstLevelHashLast16Bytes = Arrays.copyOfRange(firstLevelHash, firstLevelHash.length - 16, firstLevelHash.length);
        byte[] iv = V4TokenUtils.generateIV(salt, firstLevelHashLast16Bytes, metadata, keyId);
        byte[] encryptedFirstLevelHash = V4TokenUtils.encryptHash(key, firstLevelHashLast16Bytes, iv);

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

    public static byte[] generateIV(String salt, byte[] firstLevelHashLast16Bytes, byte metadata, int keyId) {
        String ivBase = salt
                .concat(Arrays.toString(firstLevelHashLast16Bytes))
                .concat(Byte.toString(metadata))
                .concat(String.valueOf(keyId));
        return Arrays.copyOfRange(EncodingUtils.getSha256Bytes(ivBase), 0, IV_LENGTH);
    }

    public static byte[] encryptHash(String encryptionKey, byte[] hash, byte[] iv) throws Exception {
        // Set up AES256-CTR cipher
        Cipher aesCtr = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(padIV16Bytes(iv));

        aesCtr.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return aesCtr.doFinal(hash);
    }

    public static byte generateChecksum(byte[] data) {
        // Simple XOR checksum of all bytes
        byte checksum = 0;
        for (byte b : data) {
            checksum ^= b;
        }
        return checksum;
    }

    private static byte[] padIV16Bytes(byte[] iv) {
        // Pad the 12-byte IV to 16 bytes for AES-CTR (standard block size)
        byte[] paddedIV = new byte[16];
        System.arraycopy(iv, 0, paddedIV, 0, 12);
        // Remaining 4 bytes are already zero-initialized (counter starts at 0)
        return paddedIV;
    }
}
