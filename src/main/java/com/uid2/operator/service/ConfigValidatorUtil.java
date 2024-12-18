package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigValidatorUtil {
    private static final Logger logger = LoggerFactory.getLogger(ConfigValidatorUtil.class);

    public static Boolean validateIdentityRefreshTokens(Integer identityExpiresAfter, Integer refreshExpiresAfter, Integer refreshIdentityAfter) {
        boolean isValid = true;
        if (identityExpiresAfter > refreshExpiresAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
            isValid = false;
        }
        if (refreshIdentityAfter > identityExpiresAfter) {
            logger.error(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
            isValid = false;
        }
        if (refreshIdentityAfter > refreshExpiresAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }
        return isValid;
    }

    public static Boolean validateBidstreamLifetime(Integer maxBidstreamLifetimeSeconds, Integer identityTokenExpiresAfterSeconds) {
        if (maxBidstreamLifetimeSeconds < identityTokenExpiresAfterSeconds) {
            logger.error("Max bidstream lifetime seconds ({} seconds) is less than identity token lifetime ({} seconds)", maxBidstreamLifetimeSeconds, identityTokenExpiresAfterSeconds);
            return false;
        }
        return true;
    }
}
