package com.uid2.operator.model;

import java.time.Instant;

public final class MapRequest {
    public final UserIdentity userIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;
    public final Instant asOf;
    public final IdentityEnvironment identityEnvironment;

    public MapRequest(
            UserIdentity userIdentity,
            OptoutCheckPolicy optoutCheckPolicy,
            Instant asOf,
            IdentityEnvironment identityEnvironment)
    {
        this.userIdentity = userIdentity;
        this.optoutCheckPolicy = optoutCheckPolicy;
        this.asOf = asOf;
        this.identityEnvironment = identityEnvironment;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
