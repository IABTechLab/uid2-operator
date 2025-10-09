package com.uid2.operator.service;

import com.uid2.operator.model.IdentityEnvironment;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenUtilsTest {
    @ParameterizedTest
    @MethodSource("v4Metadata")
    void testEncodeV4Metadata(IdentityScope scope, IdentityType type, IdentityEnvironment environment, byte expectedMetadata) {
        byte metadata = TokenUtils.encodeV4Metadata(scope, type, environment);

        assertEquals(expectedMetadata, metadata);
    }

    private static Stream<Arguments> v4Metadata() {
        return Stream.of(
                Arguments.of(IdentityScope.UID2, IdentityType.Email, IdentityEnvironment.TEST, (byte) 0b00100000),
                Arguments.of(IdentityScope.UID2, IdentityType.Phone, IdentityEnvironment.TEST, (byte) 0b00100100),
                Arguments.of(IdentityScope.EUID, IdentityType.Email, IdentityEnvironment.TEST, (byte) 0b00110000),
                Arguments.of(IdentityScope.EUID, IdentityType.Phone, IdentityEnvironment.TEST, (byte) 0b00110100),

                Arguments.of(IdentityScope.UID2, IdentityType.Email, IdentityEnvironment.INTEG, (byte) 0b01100000),
                Arguments.of(IdentityScope.UID2, IdentityType.Phone, IdentityEnvironment.INTEG, (byte) 0b01100100),
                Arguments.of(IdentityScope.EUID, IdentityType.Email, IdentityEnvironment.INTEG, (byte) 0b01110000),
                Arguments.of(IdentityScope.EUID, IdentityType.Phone, IdentityEnvironment.INTEG, (byte) 0b01110100),

                Arguments.of(IdentityScope.UID2, IdentityType.Email, IdentityEnvironment.PROD, (byte) 0b10100000),
                Arguments.of(IdentityScope.UID2, IdentityType.Phone, IdentityEnvironment.PROD, (byte) 0b10100100),
                Arguments.of(IdentityScope.EUID, IdentityType.Email, IdentityEnvironment.PROD, (byte) 0b10110000),
                Arguments.of(IdentityScope.EUID, IdentityType.Phone, IdentityEnvironment.PROD, (byte) 0b10110100)
        );
    }
}
