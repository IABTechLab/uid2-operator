package com.uid2.operator.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ConfigValidatorUtilTest {
    @Test
    void testValidateIdentityRefreshTokens() {
        // identityExpiresAfter is greater than refreshExpiresAfter
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, 5, 3));

        // refreshIdentityAfter is greater than identityExpiresAfter
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 6));

        // refreshIdentityAfter is greater than refreshExpiresAfter
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 11));

        // all conditions are valid
        assertTrue(ConfigValidatorUtil.validateIdentityRefreshTokens(5, 10, 3));
    }

    @Test
    void testValidateBidstreamLifetime() {
        // maxBidstreamLifetimeSeconds is less than identityTokenExpiresAfterSeconds
        assertFalse(ConfigValidatorUtil.validateBidstreamLifetime(5, 10));

        // maxBidstreamLifetimeSeconds is greater than or equal to identityTokenExpiresAfterSeconds
        assertTrue(ConfigValidatorUtil.validateBidstreamLifetime(10, 5));
        assertTrue(ConfigValidatorUtil.validateBidstreamLifetime(10, 10));
    }

    @Test
    void testValidateIdentityRefreshTokensWithNullValues() {
        // identityExpiresAfter is null
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(null, 10, 5));

        // refreshExpiresAfter is null
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, null, 5));

        // refreshIdentityAfter is null
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(10, 5, null));

        // all values are null
        assertFalse(ConfigValidatorUtil.validateIdentityRefreshTokens(null, null, null));
    }
}
