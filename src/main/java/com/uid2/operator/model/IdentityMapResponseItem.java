package com.uid2.operator.model;

// Contains the computed raw UID and its bucket ID from identity/map request
public class IdentityMapResponseItem {
    public static final IdentityMapResponseItem OptoutIdentity = new IdentityMapResponseItem(new byte[33], "", null, null);
    // The raw UID is also known as Advertising Id (historically)
    public final byte[] rawUid;
    public final String bucketId;
    public final byte[] previousRawUid;
    public final Long refreshFrom;

    public IdentityMapResponseItem(byte[] rawUid, String bucketId, byte[] previousRawUid, Long refreshFrom) {
        this.rawUid = rawUid;
        this.bucketId = bucketId;
        this.previousRawUid = previousRawUid;
        this.refreshFrom = refreshFrom;
    }

    // historically Optout is known as Logout
    public boolean isOptedOut() {
        return this.equals(OptoutIdentity) || this.bucketId == null || this.bucketId.isEmpty();
    }
}
