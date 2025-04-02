package com.uid2.operator.model;

import com.uid2.operator.model.identities.HashedDii;

import java.time.Instant;

public final class IdentityMapRequestItem {
    public final HashedDii hashedDii;
    public final OptoutCheckPolicy optoutCheckPolicy;
    public final Instant asOf;

    public IdentityMapRequestItem(
            HashedDii hashedDii,
            OptoutCheckPolicy optoutCheckPolicy,
            Instant asOf) {
        this.hashedDii = hashedDii;
        this.optoutCheckPolicy = optoutCheckPolicy;
        this.asOf = asOf;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
