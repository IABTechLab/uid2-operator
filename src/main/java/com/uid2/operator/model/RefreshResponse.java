package com.uid2.operator.model;

import java.time.Duration;

public class RefreshResponse {

    public static RefreshResponse Invalid = new RefreshResponse(Status.Invalid, IdentityTokens.LogoutToken);
    public static RefreshResponse Optout = new RefreshResponse(Status.Optout, IdentityTokens.LogoutToken);
    public static RefreshResponse Expired = new RefreshResponse(Status.Expired, IdentityTokens.LogoutToken);
    public static RefreshResponse Deprecated = new RefreshResponse(Status.Deprecated, IdentityTokens.LogoutToken);
    private final Status status;
    private final IdentityTokens tokens;
    private final Duration durationSinceLastRefresh;
    private final boolean isCstg;

    private RefreshResponse(Status status, IdentityTokens tokens, Duration durationSinceLastRefresh, boolean isCstg) {
        this.status = status;
        this.tokens = tokens;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
        this.isCstg = isCstg;
    }

    private RefreshResponse(Status status, IdentityTokens tokens) {
        this(status, tokens, null, false);
    }

    public static RefreshResponse createRefreshedResponse(IdentityTokens tokens, Duration durationSinceLastRefresh, boolean isCstg) {
        return new RefreshResponse(Status.Refreshed, tokens, durationSinceLastRefresh, isCstg);
    }

    public Status getStatus() {
        return status;
    }

    public IdentityTokens getTokens() {
        return tokens;
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

    public enum Status {
        Refreshed,
        Invalid,
        Optout,
        Expired,
        Deprecated
    }

}
