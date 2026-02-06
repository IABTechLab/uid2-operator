package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;
    public final IdentityEnvironment identityEnvironment;

    public IdentityRequest(
            PublisherIdentity publisherIdentity,
            UserIdentity userIdentity,
            IdentityEnvironment identityEnvironment) {
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
        this.identityEnvironment = identityEnvironment;
    }
}
