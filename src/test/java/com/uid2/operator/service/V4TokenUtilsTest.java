package com.uid2.operator.service;

import com.uid2.operator.model.IdentityEnvironment;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.shared.model.SaltEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Set;

import static com.uid2.operator.service.V4TokenUtils.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class V4TokenUtilsTest {
    private static Set<Arguments> getIdentityMetadata() {
        return Set.of(
                Arguments.of(IdentityScope.EUID, IdentityType.Phone, IdentityEnvironment.Test, (byte) 0b00110100),
                Arguments.of(IdentityScope.UID2, IdentityType.Email, IdentityEnvironment.Integ, (byte) 0b01100000),
                Arguments.of(IdentityScope.UID2, IdentityType.Email, IdentityEnvironment.Prod, (byte) 0b10100000)
        );
    }
    @ParameterizedTest
    @MethodSource("getIdentityMetadata")
    void testBuildAdvertisingIdV4(IdentityScope identityScope, IdentityType identityType, IdentityEnvironment identityEnvironment, byte expectedMetadata) throws Exception {
        SaltEntry.KeyMaterial encryptionKey = new SaltEntry.KeyMaterial(
                1000000,
                "key12345key12345key12345key12345",
                "salt1234salt1234salt1234salt1234"
        );
        byte[] firstLevelHash = TokenUtils.getFirstLevelHashFromIdentity("test@example.com", encryptionKey.salt());

        byte[] v4UID = TokenUtils.getAdvertisingIdV4(identityScope, identityType, identityEnvironment, firstLevelHash, encryptionKey);
        assertEquals(33, v4UID.length);

        byte[] firstLevelHashLast16Bytes = Arrays.copyOfRange(firstLevelHash, firstLevelHash.length - 16, firstLevelHash.length);
        byte[] iv = generateIV(encryptionKey.salt(), firstLevelHashLast16Bytes, expectedMetadata, encryptionKey.id());
        byte[] encryptedFirstLevelHash = encryptHash(encryptionKey.key(), firstLevelHashLast16Bytes, iv);

        byte extractedMetadata = v4UID[0];
        byte[] keyIdBytes = Arrays.copyOfRange(v4UID, 1, 4);
        int extractedKeyId = (keyIdBytes[0] & 0xFF) | ((keyIdBytes[1] & 0xFF) << 8) | ((keyIdBytes[2] & 0xFF) << 16);
        byte[] extractedIV = Arrays.copyOfRange(v4UID, 4, 16);
        byte[] extractedEncryptedHash = Arrays.copyOfRange(v4UID, 16, 32);
        byte extractedChecksum = v4UID[32];

        assertEquals(expectedMetadata, extractedMetadata);
        assertEquals(encryptionKey.id(), extractedKeyId);
        assertArrayEquals(iv, extractedIV);
        assertArrayEquals(encryptedFirstLevelHash, extractedEncryptedHash);

        // Verify checksum
        byte recomputedChecksum = generateChecksum(Arrays.copyOfRange(v4UID, 0, 32));
        assertEquals(extractedChecksum, recomputedChecksum);
    }
}
