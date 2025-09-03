package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;
    public final IdentityEnvironment identityEnvironment;

    public IdentityRequest(
            PublisherIdentity publisherIdentity,
            UserIdentity userIdentity,
            OptoutCheckPolicy tokenGeneratePolicy,
            IdentityEnvironment identityEnvironment) {
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
        this.optoutCheckPolicy = tokenGeneratePolicy;
        this.identityEnvironment = identityEnvironment;
    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
