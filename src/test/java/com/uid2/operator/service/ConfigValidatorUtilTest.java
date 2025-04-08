package com.uid2.operator.service;

import com.uid2.operator.store.RuntimeConfig;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.uid2.operator.Const.Config.SharingTokenExpiryProp;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.junit.jupiter.api.Assertions.*;

public class ConfigValidatorUtilTest {
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
        // identityExpiresAfter is greater than refreshExpiresAfter

        validConfig.put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 10);
        validConfig.put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 5);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> validConfig.mapTo(RuntimeConfig.class) );
    }
    
//
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, 5, 3));
//
//        // refreshIdentityAfter is greater than identityExpiresAfter
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 6));
//
//        // refreshIdentityAfter is greater than refreshExpiresAfter
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 11));
//
//        // all conditions are valid
//        assertTrue(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 3));

    @Test
    void testValidateBidstreamLifetime() {
        // maxBidstreamLifetimeSeconds is less than identityTokenExpiresAfterSeconds
//        assertFalse(ConfigValidatorUtil.validateBidstreamLifetime(5, 10));
//
//        // maxBidstreamLifetimeSeconds is greater than or equal to identityTokenExpiresAfterSeconds
//        assertTrue(ConfigValidatorUtil.validateBidstreamLifetime(10, 5));
//        assertTrue(ConfigValidatorUtil.validateBidstreamLifetime(10, 10));
    }

    @Test
    void testValidateIdentityRefreshTokensWithNullValues() {
//        // identityExpiresAfter is null
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(null, 10, 5));
//
//        // refreshExpiresAfter is null
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, null, 5));
//
//        // refreshIdentityAfter is null
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, 5, null));
//
//        // all values are null
//        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(null, null, null));
    }
}
