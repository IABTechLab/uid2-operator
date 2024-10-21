package com.uid2.operator.model;

// The original publisher that requests to generate a UID token
public class SourcePublisher {
    public final int siteId;
    public final int clientKeyId;
    public final long publisherId;

    public SourcePublisher(int siteId, int clientKeyId, long publisherId) {
        this.siteId = siteId;
        this.clientKeyId = clientKeyId;
        this.publisherId = publisherId;
    }
}
