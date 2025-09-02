package com.uid2.operator.store;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.uid2.operator.model.IdentityEnvironment;

import java.time.Duration;

@JsonDeserialize(builder = RuntimeConfig.Builder.class)
public class RuntimeConfig {
    private final Integer identityTokenExpiresAfterSeconds;
    private final Integer refreshTokenExpiresAfterSeconds;
    private final Integer refreshIdentityTokenAfterSeconds;
    private final Integer sharingTokenExpirySeconds;
    private final Integer maxBidstreamLifetimeSeconds;
    private final Integer maxSharingLifetimeSeconds;
    private final IdentityEnvironment identityEnvironment;

    public Duration getIdentityTokenExpires() {
        return Duration.ofSeconds(identityTokenExpiresAfterSeconds);
    }

    public Duration getRefreshTokenExpires() {
        return Duration.ofSeconds(refreshTokenExpiresAfterSeconds);
    }

    public Duration getRefreshIdentityTokenExpires() {
        return Duration.ofSeconds(refreshIdentityTokenAfterSeconds);
    }

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

    public IdentityEnvironment getIdentityEnvironment() {
        return identityEnvironment;
    }

    private RuntimeConfig(Builder builder) {
        this.identityTokenExpiresAfterSeconds = builder.identityTokenExpiresAfterSeconds;
        this.refreshTokenExpiresAfterSeconds = builder.refreshTokenExpiresAfterSeconds;
        this.refreshIdentityTokenAfterSeconds = builder.refreshIdentityTokenAfterSeconds;
        this.sharingTokenExpirySeconds = builder.sharingTokenExpirySeconds;
        this.maxBidstreamLifetimeSeconds = builder.maxBidstreamLifetimeSeconds;
        this.maxSharingLifetimeSeconds = builder.maxSharingLifetimeSeconds;
        this.identityEnvironment = builder.identityEnvironment;

        validateIdentityRefreshTokens();
        validateBidstreamLifetime();
        validateSharingTokenExpiry();
        validateIdentityEnvironment();
    }
    
    public RuntimeConfig.Builder toBuilder() {
        return new Builder()
                .withIdentityTokenExpiresAfterSeconds(this.identityTokenExpiresAfterSeconds)
                .withRefreshTokenExpiresAfterSeconds(this.refreshTokenExpiresAfterSeconds)
                .withRefreshIdentityTokenAfterSeconds(this.refreshIdentityTokenAfterSeconds)
                .withSharingTokenExpirySeconds(this.sharingTokenExpirySeconds)
                .withMaxBidstreamLifetimeSeconds(this.maxBidstreamLifetimeSeconds)
                .withMaxSharingLifetimeSeconds(this.maxSharingLifetimeSeconds)
                .withIdentityEnvironment(this.identityEnvironment);
    }
    
    private void validateIdentityRefreshTokens() {
        if (this.identityTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("identity_token_expires_after_seconds is required");
        }

        if (this.refreshTokenExpiresAfterSeconds == null) {
            throw new IllegalArgumentException("refresh_token_expires_after_seconds is required");
        }

        if (this.refreshIdentityTokenAfterSeconds == null) {
            throw new IllegalArgumentException("refresh_identity_token_after_seconds is required");
        }
        
        if (this.refreshTokenExpiresAfterSeconds < this.identityTokenExpiresAfterSeconds) {
            throw new IllegalArgumentException(String.format("refresh_token_expires_after_seconds (%d) must be >= identity_token_expires_after_seconds (%d)", refreshTokenExpiresAfterSeconds, identityTokenExpiresAfterSeconds));
        }
        
        if (this.identityTokenExpiresAfterSeconds < this.refreshIdentityTokenAfterSeconds) {
            throw new IllegalArgumentException(String.format("identity_token_expires_after_seconds (%d) must be >= refresh_identity_token_after_seconds (%d)", identityTokenExpiresAfterSeconds, refreshIdentityTokenAfterSeconds));
        }
    }
    
    private void validateBidstreamLifetime() {
        if (this.maxBidstreamLifetimeSeconds != null && this.maxBidstreamLifetimeSeconds < this.identityTokenExpiresAfterSeconds) {
            throw new IllegalArgumentException(String.format("max_bidstream_lifetime_seconds (%d) must be >= identity_token_expires_after_seconds (%d)", maxBidstreamLifetimeSeconds, identityTokenExpiresAfterSeconds));
        }
    }
    
    private void validateSharingTokenExpiry() {
        if (this.sharingTokenExpirySeconds == null) {
            throw new IllegalArgumentException("sharing_token_expiry_seconds is required");
        }
    }

    private void validateIdentityEnvironment() {
        if (this.identityEnvironment == null) {
            throw new IllegalArgumentException("identity_environment is required");
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
        @JsonProperty
        private IdentityEnvironment identityEnvironment;

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

        public Builder withIdentityEnvironment(IdentityEnvironment identityEnvironment) {
            this.identityEnvironment = identityEnvironment;
            return this;
        }

        public RuntimeConfig build() {
            return new RuntimeConfig(this);
        }
    }
}
