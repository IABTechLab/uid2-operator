package com.uid2.operator.model;

import java.time.Duration;

public class TokenRefreshResponse {

    public static final TokenRefreshResponse Invalid = new TokenRefreshResponse(Status.Invalid,
            IdentityResponse.OptOutResponse);
    public static final TokenRefreshResponse Optout = new TokenRefreshResponse(Status.Optout, IdentityResponse.OptOutResponse);
    public static final TokenRefreshResponse Expired = new TokenRefreshResponse(Status.Expired, IdentityResponse.OptOutResponse);
    public static final TokenRefreshResponse Deprecated = new TokenRefreshResponse(Status.Deprecated, IdentityResponse.OptOutResponse);
    public static final TokenRefreshResponse NoActiveKey = new TokenRefreshResponse(Status.NoActiveKey, IdentityResponse.OptOutResponse);
    private final Status status;
    private final IdentityResponse identityResponse;
    private final Duration durationSinceLastRefresh;
    private final boolean isCstg;

    private TokenRefreshResponse(Status status, IdentityResponse identityResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        this.status = status;
        this.identityResponse = identityResponse;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
        this.isCstg = isCstg;
    }

    private TokenRefreshResponse(Status status, IdentityResponse identityResponse) {
        this(status, identityResponse, null, false);
    }

    public static TokenRefreshResponse createRefreshedResponse(IdentityResponse identityResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        return new TokenRefreshResponse(Status.Refreshed, identityResponse, durationSinceLastRefresh, isCstg);
    }

    public Status getStatus() {
        return status;
    }

    public IdentityResponse getIdentityResponse() {
        return identityResponse;
    }

    public Duration getDurationSinceLastRefresh() {
        return durationSinceLastRefresh;
    }

    public boolean isCstg() { return isCstg;}

    public boolean isRefreshed() {
        return Status.Refreshed.equals(this.status);
    }

    public boolean isOptOut() {
        return Status.Optout.equals(this.status);
    }

    public boolean isInvalidToken() {
        return Status.Invalid.equals(this.status);
    }

    public boolean isDeprecated() {
        return Status.Deprecated.equals(this.status);
    }

    public boolean isExpired() {
        return Status.Expired.equals(this.status);
    }

    public boolean noActiveKey() {
        return Status.NoActiveKey.equals(this.status);
    }

    public enum Status {
        Refreshed,
        Invalid,
        Optout,
        Expired,
        Deprecated,
        NoActiveKey
    }

}
