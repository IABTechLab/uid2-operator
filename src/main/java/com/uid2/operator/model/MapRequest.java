package com.uid2.operator.model;

import java.time.Instant;

public final class MapRequest {
    public final UserIdentity userIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;
    public final Instant asOf;

    public MapRequest(
            UserIdentity userIdentity,
            OptoutCheckPolicy optoutCheckPolicy,
            Instant asOf)
    {
        this.userIdentity = userIdentity;
        this.optoutCheckPolicy = optoutCheckPolicy;
        this.asOf = asOf;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
