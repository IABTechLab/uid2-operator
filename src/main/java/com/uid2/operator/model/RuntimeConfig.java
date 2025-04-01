package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import static com.uid2.operator.service.ConfigValidatorUtil.*;

public class RuntimeConfig {
    private Integer identity_token_expires_after_seconds;
    private Integer refresh_token_expires_after_seconds;
    private Integer refresh_identity_token_after_seconds;
    private Integer sharing_token_expiry_seconds;
    private Integer max_bidstream_lifetime_seconds;

    public Integer getIdentityTokenExpiresAfterSeconds() {
        return identity_token_expires_after_seconds;
    }

    public Integer getRefreshTokenExpiresAfterSeconds() {
        return refresh_token_expires_after_seconds;
    }

    public Integer getRefreshIdentityTokenAfterSeconds() {
        return refresh_identity_token_after_seconds;
    }

    public Integer getMaxBidstreamLifetimeSeconds() {
        if (max_bidstream_lifetime_seconds != null) {
            return max_bidstream_lifetime_seconds;
        } else {
            return identity_token_expires_after_seconds;
        }
    }

    public Integer getSharingTokenExpirySeconds() {
        return sharing_token_expiry_seconds;
    }

    public boolean isValid() {
        boolean isValid = true;
        isValid &= validateIdentityRefreshTokens(identity_token_expires_after_seconds, refresh_token_expires_after_seconds, refresh_identity_token_after_seconds);

        isValid &= validateBidstreamLifetime(max_bidstream_lifetime_seconds, refresh_identity_token_after_seconds);

        isValid &= validateSharingTokenExpiry(sharing_token_expiry_seconds);
        return isValid;
    }

}
