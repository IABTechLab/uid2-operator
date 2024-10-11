package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final HashedDiiIdentity hashedDiiIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;

    public IdentityRequest(
            PublisherIdentity publisherIdentity,
            HashedDiiIdentity hashedDiiIdentity,
            OptoutCheckPolicy tokenGeneratePolicy)
    {
        this.publisherIdentity = publisherIdentity;
        this.hashedDiiIdentity = hashedDiiIdentity;
        this.optoutCheckPolicy = tokenGeneratePolicy;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
