package com.uid2.operator.model;

import java.time.Duration;

public class RefreshResponse {

    public static RefreshResponse Invalid = new RefreshResponse(Status.Invalid, Identity.LogoutToken);
    public static RefreshResponse Optout = new RefreshResponse(Status.Optout, Identity.LogoutToken);
    public static RefreshResponse Expired = new RefreshResponse(Status.Expired, Identity.LogoutToken);
    public static RefreshResponse Deprecated = new RefreshResponse(Status.Deprecated, Identity.LogoutToken);
    public static RefreshResponse NoActiveKey = new RefreshResponse(Status.NoActiveKey, Identity.LogoutToken);
    private final Status status;
    private final Identity identity;
    private final Duration durationSinceLastRefresh;
    private final boolean isCstg;

    private RefreshResponse(Status status, Identity identity, Duration durationSinceLastRefresh, boolean isCstg) {
        this.status = status;
        this.identity = identity;
        this.durationSinceLastRefresh = durationSinceLastRefresh;
        this.isCstg = isCstg;
    }

    private RefreshResponse(Status status, Identity identity) {
        this(status, identity, null, false);
    }

    public static RefreshResponse createRefreshedResponse(Identity identity, Duration durationSinceLastRefresh, boolean isCstg) {
        return new RefreshResponse(Status.Refreshed, identity, durationSinceLastRefresh, isCstg);
    }

    public Status getStatus() {
        return status;
    }

    public Identity getIdentity() {
        return identity;
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
