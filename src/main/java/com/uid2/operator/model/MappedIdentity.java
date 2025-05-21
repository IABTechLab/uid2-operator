package com.uid2.operator.model;

public class MappedIdentity {
    public static final MappedIdentity LogoutIdentity = new MappedIdentity(new byte[33], "", null, null);
    public final byte[] advertisingId;
    public final String bucketId;
    public final byte[] previousAdvertisingId;
    public final Long refreshFrom;

    public MappedIdentity(byte[] advertisingId, String bucketId, byte[] previousAdvertisingId, Long refreshFrom) {
        this.advertisingId = advertisingId;
        this.bucketId = bucketId;
        this.previousAdvertisingId = previousAdvertisingId;
        this.refreshFrom = refreshFrom;
    }

    public boolean isOptedOut() {
        return this.equals(LogoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
