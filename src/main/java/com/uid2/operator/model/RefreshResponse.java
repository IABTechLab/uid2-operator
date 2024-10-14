package com.uid2.operator.model;

import java.time.Duration;

public class RefreshResponse {

    public static RefreshResponse Invalid = new RefreshResponse(Status.Invalid, IdentityResponse.invalidIdentityResponse);
    public static RefreshResponse Optout = new RefreshResponse(Status.Optout, IdentityResponse.invalidIdentityResponse);
    public static RefreshResponse Expired = new RefreshResponse(Status.Expired, IdentityResponse.invalidIdentityResponse);
    public static RefreshResponse Deprecated = new RefreshResponse(Status.Deprecated, IdentityResponse.invalidIdentityResponse);
    public static RefreshResponse NoActiveKey = new RefreshResponse(Status.NoActiveKey, IdentityResponse.invalidIdentityResponse);
    private final Status status;
    private final IdentityResponse identityResponse;
    private final Duration durationSinceLastRefresh;
    private final boolean isCstg;

    private RefreshResponse(Status status, IdentityResponse identityResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        this.status = status;
        this.identityResponse = identityResponse;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
        this.isCstg = isCstg;
    }

    private RefreshResponse(Status status, IdentityResponse identityResponse) {
        this(status, identityResponse, null, false);
    }

    public static RefreshResponse createRefreshedResponse(IdentityResponse identityResponse, Duration durationSinceLastRefresh, boolean isCstg) {
        return new RefreshResponse(Status.Refreshed, identityResponse, durationSinceLastRefresh, isCstg);
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
