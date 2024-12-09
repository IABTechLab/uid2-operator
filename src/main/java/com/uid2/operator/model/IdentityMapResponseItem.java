package com.uid2.operator.model;

// Contains the computed raw UID and its bucket ID from identity/map request
public class IdentityMapResponseItem {
    public static final IdentityMapResponseItem OptoutIdentity = new IdentityMapResponseItem(new byte[33], "");
    // The raw UID is also known as Advertising Id (historically)
    public final byte[] rawUid;
    public final String bucketId;

    public IdentityMapResponseItem(byte[] rawUid, String bucketId) {
        this.rawUid = rawUid;
        this.bucketId = bucketId;
    }

    // historically Optout is known as Logout
    public boolean isOptedOut() {
        return this.equals(OptoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
