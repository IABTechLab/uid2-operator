package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

public class RuntimeConfigTest {
    private final JsonObject validConfig = new JsonObject()
            .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 259200)
            .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2592000)
            .put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 3600)
            .put(SharingTokenExpiryProp,  2592000);

    @Test
    void validConfigDoesNotThrow() {
        assertDoesNotThrow(this::mapToRuntimeConfig);
    }

    @Test
    void mapToRuntimeConfigPreservesValues() {
        RuntimeConfig config = mapToRuntimeConfig();

        assertEquals(validConfig.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), config.getIdentityTokenExpiresAfterSeconds());
        assertEquals(validConfig.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), config.getRefreshTokenExpiresAfterSeconds());
        assertEquals(validConfig.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS), config.getRefreshIdentityTokenAfterSeconds());
        assertEquals(validConfig.getInteger(SharingTokenExpiryProp), config.getSharingTokenExpirySeconds());
    }

    @Test
    void runtimeConfigUsesCorrectDefaultValues() {
        RuntimeConfig config = mapToRuntimeConfig();

        assertEquals(validConfig.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), config.getMaxBidstreamLifetimeSeconds());
        assertEquals(validConfig.getInteger(SharingTokenExpiryProp), config.getMaxSharingLifetimeSeconds());
    }

    @Test
    void maxBidstreamLifetimeSecondsIsReturnedIfSet() {
        int maxBidstreamLifetimeSeconds = validConfig.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS) + 1;
        validConfig.put(MaxBidstreamLifetimeSecondsProp, maxBidstreamLifetimeSeconds);

        RuntimeConfig config = mapToRuntimeConfig();

        assertEquals(maxBidstreamLifetimeSeconds, config.getMaxBidstreamLifetimeSeconds());
    }

    @Test
    void maxSharingLifetimeSecondsIsReturnedIfSet() {
        validConfig.put(MaxSharingLifetimeProp, 123);

        RuntimeConfig config = mapToRuntimeConfig();

        assertEquals(123, config.getMaxSharingLifetimeSeconds());
    }

    @Test
    void extraPropertyDoesNotThrow() {
        validConfig.put("some_new_property", 1);

        assertDoesNotThrow(this::mapToRuntimeConfig);
    }

    @ParameterizedTest
    @MethodSource("requiredFields")
    void requiredFieldIsNullThrows(String propertyName) {
        validConfig.putNull(propertyName);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);

        assertThat(ex.getMessage()).contains("is required");
    }

    @ParameterizedTest
    @MethodSource("requiredFields")
    void requiredFieldIsMissingThrows(String propertyName) {
        validConfig.remove(propertyName);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);

        assertThat(ex.getMessage()).contains("is required");
    }

    private RuntimeConfig mapToRuntimeConfig() {
        return validConfig.mapTo(RuntimeConfig.class);
    }

    private static Stream<Arguments> requiredFields() {
        return Stream.of(
                Arguments.of(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                Arguments.of(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Arguments.of(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Arguments.of(SharingTokenExpiryProp)
        );
    }

    @Test
    void identityTokenExpiresAfterSecondsIsGreaterThanRefreshTokenExpiresAfterSecondsThrows() {
        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 10);
        validConfig.put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 5);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
        assertThat(ex.getMessage()).contains("Refresh token expires after seconds must be >= identity token expires after seconds");
    }

    @Test
    void refreshIdentityAfterSecondsIsGreaterThanIdentityTokenExpiresAfterSecondsThrows() {
        validConfig.put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 6);
        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 5);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
        assertThat(ex.getMessage()).contains("Identity token expires after seconds must be >= refresh identity token after seconds");
    }

    @Test
    void maxBidStreamLifetimeSecondsIsLessThanIdentityTokenExpiresAfterSecondsThrows() {
        validConfig.put(MaxBidstreamLifetimeSecondsProp, 5);
        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 10);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
        assertThat(ex.getMessage()).contains("Identity token expires after seconds must be >= refresh identity token after seconds");
    }
    
    @Test
    void toBuilderBuildReturnsEquivalentObject() {
        RuntimeConfig config = mapToRuntimeConfig();
        
        RuntimeConfig toBuilderBuild = config.toBuilder().build();

        assertThat(toBuilderBuild)
                .usingRecursiveComparison()
                .isEqualTo(config);
    }
}
