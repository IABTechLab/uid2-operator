package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;

    public IdentityRequest(
            PublisherIdentity publisherIdentity,
            UserIdentity userIdentity,
            OptoutCheckPolicy tokenGeneratePolicy)
    {
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
        this.optoutCheckPolicy = tokenGeneratePolicy;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
