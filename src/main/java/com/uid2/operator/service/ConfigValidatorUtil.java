package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.Const.Config.MaxBidstreamLifetimeSecondsProp;
import static com.uid2.operator.Const.Config.SharingTokenExpiryProp;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigValidatorUtil {
    private static final Logger logger = LoggerFactory.getLogger(ConfigValidatorUtil.class);
    public static final String VALUES_ARE_NULL = "ABU ADDED One or more of the following required config values are null: ";

    public static Boolean validateIdentityRefreshTokens(Integer identityExpiresAfter, Integer refreshExpiresAfter, Integer refreshIdentityAfter) {
        boolean isValid = true;

        if (areValuesNull(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter)) {
            logger.error(VALUES_ARE_NULL + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + ", " + REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + ", " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
            return false;
        }

        if (refreshExpiresAfter < identityExpiresAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " ({}) < " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " ({})", refreshExpiresAfter, identityExpiresAfter);
            isValid = false;
        }
        if (identityExpiresAfter < refreshIdentityAfter) {
            logger.error(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " ({}) < " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS + " ({})", identityExpiresAfter, refreshIdentityAfter);
            isValid = false;
        }
        if (refreshExpiresAfter < refreshIdentityAfter) {
            logger.error(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " ({}) < " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS + " ({})", refreshExpiresAfter, refreshIdentityAfter);
        }
        return isValid;
    }

    public static Boolean validateBidstreamLifetime(Integer maxBidstreamLifetimeSeconds, Integer identityTokenExpiresAfterSeconds) {
        if (areValuesNull(maxBidstreamLifetimeSeconds, identityTokenExpiresAfterSeconds)) {
            logger.error(VALUES_ARE_NULL + MaxBidstreamLifetimeSecondsProp + ", " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
            return false;
        }
        if (maxBidstreamLifetimeSeconds < identityTokenExpiresAfterSeconds) {
            logger.error(MaxBidstreamLifetimeSecondsProp + " ({}) < " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " ({})", maxBidstreamLifetimeSeconds, identityTokenExpiresAfterSeconds);
            return false;
        }
        return true;
    }

    public static Boolean validateSharingTokenExpiry(Integer sharingTokenExpiry) {
        if (areValuesNull(sharingTokenExpiry)) {
            logger.error(VALUES_ARE_NULL + SharingTokenExpiryProp);
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
