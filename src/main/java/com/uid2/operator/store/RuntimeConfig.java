package com.uid2.operator.store;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

import static com.uid2.operator.service.ConfigValidatorUtil.*;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RuntimeConfig {
    @JsonProperty("identity_token_expires_after_seconds")
    private Integer identityTokenExpiresAfterSeconds;
    @JsonProperty("refresh_token_expires_after_seconds")
    private Integer refreshTokenExpiresAfterSeconds;
    @JsonProperty("refresh_identity_token_after_seconds")
    private Integer refreshIdentityTokenAfterSeconds;
    @JsonProperty("sharing_token_expiry_seconds")
    private Integer sharingTokenExpirySeconds;
    @JsonProperty("max_bidstream_lifetime_seconds")
    private Integer maxBidstreamLifetimeSeconds;
    @JsonProperty("max_sharing_lifetime_seconds")
    private Integer maxSharingLifetimeSeconds;

    public Integer getIdentityTokenExpiresAfterSeconds() {
        return identityTokenExpiresAfterSeconds;
    }

    public Integer getRefreshTokenExpiresAfterSeconds() {
        return refreshTokenExpiresAfterSeconds;
    }

    public Integer getRefreshIdentityTokenAfterSeconds() {
        return refreshIdentityTokenAfterSeconds;
    }

    public Integer getMaxBidstreamLifetimeSeconds() {
        if (maxBidstreamLifetimeSeconds != null) {
            return maxBidstreamLifetimeSeconds;
        } else {
            return identityTokenExpiresAfterSeconds;
        }
    }

    public Integer getMaxSharingLifetimeSeconds() {
        if (maxSharingLifetimeSeconds != null) {
            return maxSharingLifetimeSeconds;
        } else {
            return sharingTokenExpirySeconds;
        }
    }

    public Integer getSharingTokenExpirySeconds() {
        return sharingTokenExpirySeconds;
    }

    // @JsonIgnore is needed to exclude 'valid' field from JSON conversion via JsonObject.mapFrom()."
    @JsonIgnore
    public boolean isValid() {
        boolean isValid = true;
        isValid &= validateIdentityRefreshTokens(getIdentityTokenExpiresAfterSeconds(), getRefreshTokenExpiresAfterSeconds(), getRefreshIdentityTokenAfterSeconds());

        isValid &= validateBidstreamLifetime(getMaxBidstreamLifetimeSeconds(), getRefreshIdentityTokenAfterSeconds());

        isValid &= validateSharingTokenExpiry(getSharingTokenExpirySeconds());
        return isValid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RuntimeConfig that = (RuntimeConfig) o;
        return Objects.equals(identityTokenExpiresAfterSeconds, that.identityTokenExpiresAfterSeconds) &&
                Objects.equals(refreshTokenExpiresAfterSeconds, that.refreshTokenExpiresAfterSeconds) &&
                Objects.equals(refreshIdentityTokenAfterSeconds, that.refreshIdentityTokenAfterSeconds) &&
                Objects.equals(sharingTokenExpirySeconds, that.sharingTokenExpirySeconds) &&
                Objects.equals(maxBidstreamLifetimeSeconds, that.maxBidstreamLifetimeSeconds) &&
                Objects.equals(maxSharingLifetimeSeconds, that.maxSharingLifetimeSeconds);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identityTokenExpiresAfterSeconds, refreshTokenExpiresAfterSeconds, refreshIdentityTokenAfterSeconds, sharingTokenExpirySeconds, maxBidstreamLifetimeSeconds, maxSharingLifetimeSeconds);
    }
}
