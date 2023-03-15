package com.uid2.operator.model;

public class MappedIdentity {
    public final byte[] advertisingId;
    public final String bucketId;

    public MappedIdentity(byte[] advertisingId, String bucketId) {
        this.advertisingId = advertisingId;
        this.bucketId = bucketId;
    }
}
