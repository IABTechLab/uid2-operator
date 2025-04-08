package com.uid2.operator.model;

import java.time.Duration;

public class TokenRefreshResponse {

    public static final TokenRefreshResponse Invalid = new TokenRefreshResponse(Status.Invalid,
            TokenGenerateResponse.OptOutResponse);
    public static final TokenRefreshResponse Optout = new TokenRefreshResponse(Status.Optout, TokenGenerateResponse.OptOutResponse);
    public static final TokenRefreshResponse Expired = new TokenRefreshResponse(Status.Expired, TokenGenerateResponse.OptOutResponse);
    public static final TokenRefreshResponse Deprecated = new TokenRefreshResponse(Status.Deprecated, TokenGenerateResponse.OptOutResponse);
    public static final TokenRefreshResponse NoActiveKey = new TokenRefreshResponse(Status.NoActiveKey, TokenGenerateResponse.OptOutResponse);
    private final Status status;
    private final TokenGenerateResponse tokenGenerateResponse;
    private final Duration durationSinceLastRefresh;
    private final boolean isCstg;

    private TokenRefreshResponse(Status status, TokenGenerateResponse tokenGenerateResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        this.status = status;
        this.tokenGenerateResponse = tokenGenerateResponse;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
        this.isCstg = isCstg;
    }

    private TokenRefreshResponse(Status status, TokenGenerateResponse tokenGenerateResponse) {
        this(status, tokenGenerateResponse, null, false);
    }

    public static TokenRefreshResponse createRefreshedResponse(TokenGenerateResponse tokenGenerateResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        return new TokenRefreshResponse(Status.Refreshed, tokenGenerateResponse, durationSinceLastRefresh, isCstg);
    }

    public Status getStatus() {
        return status;
    }

    public TokenGenerateResponse getIdentityResponse() {
        return tokenGenerateResponse;
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
