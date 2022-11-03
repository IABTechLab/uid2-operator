package com.uid2.operator.model;

public class OperatorIdentity {
    public final int siteId;
    public final OperatorType operatorType;
    public final int operatorVersion;
    public final int operatorKeyId;

    public OperatorIdentity(int siteId, OperatorType operatorType, int operatorVersion, int operatorKeyId) {
        this.siteId = siteId;
        this.operatorType = operatorType;
        this.operatorVersion = operatorVersion;
        this.operatorKeyId = operatorKeyId;
    }
}
