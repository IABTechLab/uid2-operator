package com.uid2.operator.service;

import com.uid2.shared.model.SaltEntry;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static com.uid2.operator.service.V4TokenUtils.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class V4TokenUtilsTest {
    @Test
    void testBuildAdvertisingIdV4() throws Exception {
        SaltEntry.KeyMaterial encryptionKey = new SaltEntry.KeyMaterial(
                1000000,
                "key12345key12345key12345key12345",
                "salt1234salt1234salt1234salt1234"
        );
        byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity("test@example.com", encryptionKey.salt());
        byte metadata = (byte) 0b00100000;
        byte[] v4UID = buildAdvertisingIdV4(metadata, firstLevelHash, encryptionKey.id(), encryptionKey.key(), encryptionKey.salt());
        assertEquals(33, v4UID.length);

        byte[] firstLevelHashLast16Bytes = Arrays.copyOfRange(firstLevelHash, firstLevelHash.length - 16, firstLevelHash.length);
        byte[] iv = generateIV(encryptionKey.salt(), firstLevelHashLast16Bytes, metadata, encryptionKey.id());
        byte[] encryptedFirstLevelHash = encryptHash(encryptionKey.key(), firstLevelHashLast16Bytes, iv);

        byte extractedMetadata = v4UID[0];
        byte[] keyIdBytes = Arrays.copyOfRange(v4UID, 1, 4);
        int extractedKeyId = ((keyIdBytes[0] & 0xFF) << 16) | ((keyIdBytes[1] & 0xFF) << 8) | (keyIdBytes[2] & 0xFF);
        byte[] extractedIV = Arrays.copyOfRange(v4UID, 4, 16);
        byte[] extractedEncryptedHash = Arrays.copyOfRange(v4UID, 16, 32);
        byte extractedChecksum = v4UID[32];

        assertEquals(metadata, extractedMetadata);
        assertEquals(encryptionKey.id(), extractedKeyId);
        assertArrayEquals(iv, extractedIV);
        assertArrayEquals(encryptedFirstLevelHash, extractedEncryptedHash);

        // Verify checksum
        byte recomputedChecksum = generateChecksum(Arrays.copyOfRange(v4UID, 0, 32));
        assertEquals(extractedChecksum, recomputedChecksum);
    }
}
