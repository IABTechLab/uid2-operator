package com.uid2.operator.model;

import java.time.Instant;

public class MappedIdentity {
    public static MappedIdentity LogoutIdentity = new MappedIdentity(new byte[33], "");
    public final byte[] advertisingId;
    public final String bucketId;

    public MappedIdentity(byte[] advertisingId, String bucketId) {
        this.advertisingId = advertisingId;
        this.bucketId = bucketId;
    }

    public boolean isOptedOut() {
        return this.equals(LogoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
