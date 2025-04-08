package com.uid2.operator.store;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

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

        validateIdentityRefreshTokens();
        validateBidstreamLifetime();
        validateSharingTokenExpiry();
    }
    
    public RuntimeConfig.Builder toBuilder() {
        return new Builder()
                .withIdentityTokenExpiresAfterSeconds(this.identityTokenExpiresAfterSeconds)
                .withRefreshTokenExpiresAfterSeconds(this.refreshTokenExpiresAfterSeconds)
                .withRefreshIdentityTokenAfterSeconds(this.refreshIdentityTokenAfterSeconds)
                .withSharingTokenExpirySeconds(this.sharingTokenExpirySeconds)
                .withMaxBidstreamLifetimeSeconds(this.maxBidstreamLifetimeSeconds)
                .withMaxSharingLifetimeSeconds(this.maxSharingLifetimeSeconds);
    }
    
    private void validateIdentityRefreshTokens() {
        if (this.identityTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("Identity token expires after seconds is required");
        }

        if (this.refreshTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("Refresh token expires after seconds is required");
        }

        if (this.refreshIdentityTokenAfterSeconds == null) {
            throw new IllegalArgumentException("Refresh identity token after seconds is required");
        }
        
        if (this.refreshTokenExpiresAfterSeconds < this.identityTokenExpiresAfterSeconds) {
            throw new IllegalArgumentException("Refresh token expires after seconds must be >= identity token expires after seconds");
        }
        
        if (this.identityTokenExpiresAfterSeconds < this.refreshIdentityTokenAfterSeconds) {
            throw new IllegalArgumentException("Identity token expires after seconds must be >= refresh identity token after seconds");
        }
    }
    
    private void validateBidstreamLifetime() {
        if (this.maxBidstreamLifetimeSeconds != null && this.maxBidstreamLifetimeSeconds < this.identityTokenExpiresAfterSeconds) {
            throw new IllegalArgumentException("Max bidstream lifetime seconds must be >= identity token expires after seconds");
        }
    }
    
    private void validateSharingTokenExpiry() {
        if (this.sharingTokenExpirySeconds == null) {
            throw new IllegalArgumentException("Sharing token expiry seconds is required");
        }
    }
    
    @JsonPOJOBuilder
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Builder {
        @JsonProperty
        private Integer identityTokenExpiresAfterSeconds;
        @JsonProperty
        private Integer refreshTokenExpiresAfterSeconds;
        @JsonProperty
        private Integer refreshIdentityTokenAfterSeconds;
        @JsonProperty
        private Integer sharingTokenExpirySeconds;
        @JsonProperty
        private Integer maxBidstreamLifetimeSeconds;
        @JsonProperty
        private Integer maxSharingLifetimeSeconds;

        public Builder withIdentityTokenExpiresAfterSeconds(Integer identityTokenExpiresAfterSeconds) {
            this.identityTokenExpiresAfterSeconds = identityTokenExpiresAfterSeconds;
            return this;
        }

        public Builder withRefreshTokenExpiresAfterSeconds(Integer refreshTokenExpiresAfterSeconds) {
            this.refreshTokenExpiresAfterSeconds = refreshTokenExpiresAfterSeconds;
            return this;
        }

        public Builder withRefreshIdentityTokenAfterSeconds(Integer refreshIdentityTokenAfterSeconds) {
            this.refreshIdentityTokenAfterSeconds = refreshIdentityTokenAfterSeconds;
            return this;
        }

        public Builder withSharingTokenExpirySeconds(Integer sharingTokenExpirySeconds) {
            this.sharingTokenExpirySeconds = sharingTokenExpirySeconds;
            return this;
        }

        public Builder withMaxBidstreamLifetimeSeconds(Integer maxBidstreamLifetimeSeconds) {
            this.maxBidstreamLifetimeSeconds = maxBidstreamLifetimeSeconds;
            return this;
        }

        public Builder withMaxSharingLifetimeSeconds(Integer maxSharingLifetimeSeconds) {
            this.maxSharingLifetimeSeconds = maxSharingLifetimeSeconds;
            return this;
        }

        public RuntimeConfig build() {
            return new RuntimeConfig(this);
        }
    }
}
