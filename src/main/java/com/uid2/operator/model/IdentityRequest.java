package com.uid2.operator.model;

public final class IdentityRequest {
    public final SourcePublisher sourcePublisher;
    public final HashedDiiIdentity hashedDiiIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;

    public IdentityRequest(
            SourcePublisher sourcePublisher,
            HashedDiiIdentity hashedDiiIdentity,
            OptoutCheckPolicy tokenGeneratePolicy)
    {
        this.sourcePublisher = sourcePublisher;
        this.hashedDiiIdentity = hashedDiiIdentity;
        this.optoutCheckPolicy = tokenGeneratePolicy;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
