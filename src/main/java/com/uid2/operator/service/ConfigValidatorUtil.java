package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.Const.Config.MaxBidstreamLifetimeSecondsProp;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigValidatorUtil {
    private static final Logger logger = LoggerFactory.getLogger(ConfigValidatorUtil.class);
    public static final String VALUES_ARE_NULL = "Required config values are null";

    public static Boolean validateIdentityRefreshTokens(Integer identityExpiresAfter, Integer refreshExpiresAfter, Integer refreshIdentityAfter) {
        boolean isValid = true;

        if (areValuesNull(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter)) {
            logger.error(VALUES_ARE_NULL);
            return false;
        }


        if (refreshExpiresAfter < identityExpiresAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
            isValid = false;
        }
        if (identityExpiresAfter < refreshIdentityAfter) {
            logger.error(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
            isValid = false;
        }
        if (refreshExpiresAfter < refreshIdentityAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }
        return isValid;
    }

    public static Boolean validateBidstreamLifetime(Integer maxBidstreamLifetimeSeconds, Integer identityTokenExpiresAfterSeconds) {
        if (maxBidstreamLifetimeSeconds < identityTokenExpiresAfterSeconds) {
            logger.error(MaxBidstreamLifetimeSecondsProp + " must be >= " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
            return false;
        }
        return true;
    }

    private static boolean areValuesNull(Integer... values) {
        for (Integer value : values) {
            if (value == null) {
                return true;
            }
        }
        return false;
    }
}
