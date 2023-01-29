package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;
    public final TokenGeneratePolicy tokenGeneratePolicy;

    public IdentityRequest(
            PublisherIdentity publisherIdentity,
            UserIdentity userIdentity,
            TokenGeneratePolicy tokenGeneratePolicy)
    {
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
        this.tokenGeneratePolicy = tokenGeneratePolicy;
    }

    public boolean shouldCheckOptOut() {
        return tokenGeneratePolicy.equals(TokenGeneratePolicy.RespectOptOut);
    }
}
