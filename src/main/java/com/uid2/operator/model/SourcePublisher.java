package com.uid2.operator.model;

// The original publisher that requests to generate a UID token
public class SourcePublisher {
    public final int siteId;

    // these 2 values are added into adverting/UID token and refresh token payload but
    // are not really used for any real purposes currently so sometimes are set to 0
    // see the constructor below
    public final int clientKeyId;
    public final long publisherId;

    public SourcePublisher(int siteId, int clientKeyId, long publisherId) {
        this.siteId = siteId;
        this.clientKeyId = clientKeyId;
        this.publisherId = publisherId;
    }

    public SourcePublisher(int siteId) {
        this.siteId = siteId;
        this.clientKeyId = 0;
        this.publisherId = 0;
    }
}
