package com.uid2.operator.model;

import java.time.Instant;

public final class MapRequest {
    public final HashedDiiIdentity hashedDiiIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;
    public final Instant asOf;

    public MapRequest(
            HashedDiiIdentity hashedDiiIdentity,
            OptoutCheckPolicy optoutCheckPolicy,
            Instant asOf)
    {
        this.hashedDiiIdentity = hashedDiiIdentity;
        this.optoutCheckPolicy = optoutCheckPolicy;
        this.asOf = asOf;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
