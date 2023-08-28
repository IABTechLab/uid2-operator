package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CstgRequest {
    private String payload;
    private String iv;
    private String subscriptionId;
    private String publicKey;
    private long timestamp;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getSubscriptionId() {
        return subscriptionId;
    }

    @JsonProperty("subscription_id")
    public void setSubscriptionId(String subscriptionId) {
        this.subscriptionId = subscriptionId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    @JsonProperty("public_key")
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}

