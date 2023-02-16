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

    private RefreshResponse(Status status, IdentityTokens tokens, Duration durationSinceLastRefresh) {
        this.status = status;
        this.tokens = tokens;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
    }

    private RefreshResponse(Status status, IdentityTokens tokens) {
        this(status, tokens, null);
    }

    public static RefreshResponse Refreshed(IdentityTokens tokens, Duration durationSinceLastRefresh) {
        return new RefreshResponse(Status.Refreshed, tokens, durationSinceLastRefresh);
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
