package com.uid2.operator.model;

// Contains the generated raw UID
public class MappedIdentity {
    public static MappedIdentity OptoutIdentity = new MappedIdentity(new byte[33], "");
    // The raw UID is also known as Advertising Id (historically)
    public final byte[] rawUid;
    public final String bucketId;

    public MappedIdentity(byte[] rawUid, String bucketId) {
        this.rawUid = rawUid;
        this.bucketId = bucketId;
    }

    public boolean isOptedOut() {
        return this.equals(OptoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
