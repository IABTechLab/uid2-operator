package com.uid2.operator.model;

// Contains the computed raw UID and its bucket ID from identity/map request
public class RawUidResult {
    public static RawUidResult OptoutIdentity = new RawUidResult(new byte[33], "");
    // The raw UID is also known as Advertising Id (historically)
    public final byte[] rawUid;
    public final String bucketId;

    public RawUidResult(byte[] rawUid, String bucketId) {
        this.rawUid = rawUid;
        this.bucketId = bucketId;
    }

    public boolean isOptedOut() {
        return this.equals(OptoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
