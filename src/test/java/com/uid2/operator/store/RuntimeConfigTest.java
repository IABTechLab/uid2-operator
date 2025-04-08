package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.uid2.operator.Const.Config.MaxBidstreamLifetimeSecondsProp;
import static com.uid2.operator.Const.Config.SharingTokenExpiryProp;
import static com.uid2.operator.service.UIDOperatorService.*;
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
    void extraPropertyDoesNotThrow() {
        validConfig.put("some_new_property", 1);
        assertDoesNotThrow(this::mapToRuntimeConfig);
    }
    
    @ParameterizedTest
    @MethodSource("requiredFields")
    void requiredFieldIsNullThrows(String propertyName) {
        validConfig.putNull(propertyName);
        assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
    }

    @ParameterizedTest
    @MethodSource("requiredFields")
    void requiredFieldIsMissingThrows(String propertyName) {
        validConfig.remove(propertyName);
        assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
    }

    private void mapToRuntimeConfig() {
        validConfig.mapTo(RuntimeConfig.class);
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
    }
    
    @Test
    void refreshIdentityAfterSecondsIsGreaterThanIdentityTokenExpiresAfterSecondsThrows() {
        validConfig.put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 6);
        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 5);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
    }
    
    @Test
    void maxBidStreamLifetimeSecondsIsLessThanIdentityTokenExpiresAfterSecondsThrows() {
        validConfig.put(MaxBidstreamLifetimeSecondsProp, 5);
        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 10);
        
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, this::mapToRuntimeConfig);
    }
}
