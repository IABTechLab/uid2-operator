package com.uid2.operator.model;

public class PublisherIdentity {
    public final int siteId;
    public final int clientKeyId;
    public final long publisherId;

    public PublisherIdentity(int siteId, int clientKeyId, long publisherId) {
        this.siteId = siteId;
        this.clientKeyId = clientKeyId;
        this.publisherId = publisherId;
    }
}
