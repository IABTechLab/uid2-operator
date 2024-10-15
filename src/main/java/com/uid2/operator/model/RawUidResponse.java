package com.uid2.operator.model;

// Contains the computed raw UID and its bucket ID from identity/map request
public class RawUidResponse {
    public static RawUidResponse OptoutIdentity = new RawUidResponse(new byte[33], "");
    // The raw UID is also known as Advertising Id (historically)
    public final byte[] rawUid;
    public final String bucketId;

    public RawUidResponse(byte[] rawUid, String bucketId) {
        this.rawUid = rawUid;
        this.bucketId = bucketId;
    }

    // historically Optout is known as Logout
    public boolean isOptedOut() {
        return this.equals(OptoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
