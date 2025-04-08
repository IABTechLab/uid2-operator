package com.uid2.operator.service;

import com.uid2.operator.store.RuntimeConfig;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ConfigValidatorUtilTest {
    private final JsonObject validConfig = new JsonObject()
            .put("identity_token_expires_after_seconds", 259200)
            .put("refresh_token_expires_after_seconds", 2592000)
            .put("refresh_identity_token_after_seconds", 3600)
            .put("sharing_token_expiry_seconds",  2592000);
    
    @Test
    void testValidConfigDoesNotThrow() {
        assertDoesNotThrow(() -> validConfig.mapTo(RuntimeConfig.class));
    }
    
    @Test
    void testExtraPropertyDoesNotThrow() {
        assertDoesNotThrow(() -> validConfig.put("some_new_property", 1).mapTo(RuntimeConfig.class));
    }
    
    @Test
    void testIdentityTokenExpiresAfterSecondsIsGreaterThanRefreshTokenExpiresAfterSecondsThrows() {
        // identityExpiresAfter is greater than refreshExpiresAfter
        IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () ->
                validConfig.put("identity_token_expires_after_seconds", 10)
                        .put("refresh_token_expires_after_seconds", 5)
                        .mapTo(RuntimeConfig.class)
        );
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
    }

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
