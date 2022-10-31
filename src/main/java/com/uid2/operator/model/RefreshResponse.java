package com.uid2.operator.model;

public class RefreshResponse {

    public static RefreshResponse Invalid = new RefreshResponse(Status.Invalid, IdentityTokens.LogoutToken);
    public static RefreshResponse Optout = new RefreshResponse(Status.Optout, IdentityTokens.LogoutToken);
    public static RefreshResponse Expired = new RefreshResponse(Status.Expired, IdentityTokens.LogoutToken);
    public static RefreshResponse Deprecated = new RefreshResponse(Status.Deprecated, IdentityTokens.LogoutToken);
    private final Status status;
    private final IdentityTokens tokens;

    private RefreshResponse(Status status, IdentityTokens tokens) {
        this.status = status;
        this.tokens = tokens;
    }

    public static RefreshResponse Refreshed(IdentityTokens tokens) {
        return new RefreshResponse(Status.Refreshed, tokens);
    }

    public Status getStatus() {
        return status;
    }

    public IdentityTokens getTokens() {
        return tokens;
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
