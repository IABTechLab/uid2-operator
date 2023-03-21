package com.uid2.operator.model;

import java.time.Instant;

public final class MapRequest {
    public final UserIdentity userIdentity;
    public final IdentityMapPolicy identityMapPolicy;
    public final Instant asOf;

    public MapRequest(
            UserIdentity userIdentity,
            IdentityMapPolicy identityMapPolicy,
            Instant asOf)
    {
        this.userIdentity = userIdentity;
        this.identityMapPolicy = identityMapPolicy;
        this.asOf = asOf;
    }

    public boolean shouldCheckOptOut() {
        return identityMapPolicy.equals(IdentityMapPolicy.RespectOptOut);
    }
}
