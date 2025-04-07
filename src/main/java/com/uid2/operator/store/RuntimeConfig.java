package com.uid2.operator.store;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import static com.uid2.operator.service.ConfigValidatorUtil.*;

@JsonDeserialize(builder = RuntimeConfig.Builder.class)
public class RuntimeConfig {
    private final Integer identityTokenExpiresAfterSeconds;
    private final Integer refreshTokenExpiresAfterSeconds;
    private final Integer refreshIdentityTokenAfterSeconds;
    private final Integer sharingTokenExpirySeconds;
    private final Integer maxBidstreamLifetimeSeconds;
    private final Integer maxSharingLifetimeSeconds;

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

    private RuntimeConfig(Builder builder) {
        this.identityTokenExpiresAfterSeconds = builder.identityTokenExpiresAfterSeconds;
        this.refreshTokenExpiresAfterSeconds = builder.refreshTokenExpiresAfterSeconds;
        this.refreshIdentityTokenAfterSeconds = builder.refreshIdentityTokenAfterSeconds;
        this.sharingTokenExpirySeconds = builder.sharingTokenExpirySeconds;
        this.maxBidstreamLifetimeSeconds = builder.maxBidstreamLifetimeSeconds;
        this.maxSharingLifetimeSeconds = builder.maxSharingLifetimeSeconds;

        if (this.identityTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("");
        }
        
        if (this.refreshTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("");
        }
        
        if (this.refreshIdentityTokenAfterSeconds == null) {
            throw new IllegalArgumentException("");
        }
            
        validateIdentityRefreshTokens(getIdentityTokenExpiresAfterSeconds(), getRefreshTokenExpiresAfterSeconds(), getRefreshIdentityTokenAfterSeconds());

        validateBidstreamLifetime(getMaxBidstreamLifetimeSeconds(), getRefreshIdentityTokenAfterSeconds());

        validateSharingTokenExpiry(getSharingTokenExpirySeconds());
    }
    
    @JsonPOJOBuilder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Builder {
        private Integer identityTokenExpiresAfterSeconds;
        private Integer refreshTokenExpiresAfterSeconds;
        private Integer refreshIdentityTokenAfterSeconds;
        private Integer sharingTokenExpirySeconds;
        private Integer maxBidstreamLifetimeSeconds;
        private Integer maxSharingLifetimeSeconds;

        public Builder withIdentityTokenExpiresAfterSeconds(@JsonProperty("identity_token_expires_after_seconds") Integer identityTokenExpiresAfterSeconds) {
            this.identityTokenExpiresAfterSeconds = identityTokenExpiresAfterSeconds;
            return this;
        }
        
        public Builder withRefreshTokenExpiresAfterSeconds(@JsonProperty("refresh_token_expires_after_seconds") Integer refreshTokenExpiresAfterSeconds) {
            this.refreshTokenExpiresAfterSeconds = refreshTokenExpiresAfterSeconds;
            return this;
        }
        
        public Builder withRefreshIdentityTokenAfterSeconds(@JsonProperty("refresh_identity_token_after_seconds") Integer refreshIdentityTokenAfterSeconds) {
            this.refreshIdentityTokenAfterSeconds = refreshIdentityTokenAfterSeconds;
            return this;
        }

        public Builder withSharingTokenExpirySeconds(@JsonProperty("sharing_token_expiry_seconds") Integer sharingTokenExpirySeconds) {
            this.sharingTokenExpirySeconds = sharingTokenExpirySeconds;
            return this;
        }

        public Builder withMaxBidstreamLifetimeSeconds(@JsonProperty("max_bidstream_lifetime_seconds") Integer maxBidstreamLifetimeSeconds) {
            this.maxBidstreamLifetimeSeconds = maxBidstreamLifetimeSeconds;
            return this;
        }

        public Builder withMaxSharingLifetimeSeconds(@JsonProperty("max_sharing_lifetime_seconds") Integer maxSharingLifetimeSeconds) {
            this.maxSharingLifetimeSeconds = maxSharingLifetimeSeconds;
            return this;
        }
        
        public RuntimeConfig build() {
            return new RuntimeConfig(this);
        }
    }
}
