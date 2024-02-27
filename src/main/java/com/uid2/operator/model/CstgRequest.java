package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CstgRequest {
    private String payload;
    private String iv;
    @JsonProperty("subscription_id")
    private String subscriptionId;
    @JsonProperty("public_key")
    private String publicKey;
    private long timestamp;

    @JsonProperty("app_name")
    private String appName;

    public String getPayload() {
        return payload;
    }

    public String getIv() {
        return iv;
    }

    public String getSubscriptionId() {
        return subscriptionId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getAppName() {
        return appName;
    }
}

