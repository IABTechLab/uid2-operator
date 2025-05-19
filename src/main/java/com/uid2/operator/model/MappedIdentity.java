package com.uid2.operator.model;

public class MappedIdentity {
    public static MappedIdentity LogoutIdentity = new MappedIdentity(new byte[33], "", null, null);
    public final byte[] advertisingId;
    public final String bucketId;
    public final byte[] previousId;
    public final Long refreshFrom;

    public MappedIdentity(byte[] advertisingId, String bucketId, byte[] previousId, Long refreshFrom) {
        this.advertisingId = advertisingId;
        this.bucketId = bucketId;
        this.previousId = previousId;
        this.refreshFrom = refreshFrom;
    }

    public boolean isOptedOut() {
        return this.equals(LogoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
