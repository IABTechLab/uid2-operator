package com.uid2.operator.model;

public final class IdentityRequest {
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;

    public IdentityRequest(PublisherIdentity publisherIdentity, UserIdentity userIdentity) {
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
    }
}
