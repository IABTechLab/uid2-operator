package com.uid2.operator.model;

public class MappedIdentity {
    public static final MappedIdentity LogoutIdentity = new MappedIdentity(new byte[33], "", null, null);
    public final byte[] advertisingId;
    public final String bucketId;
    /**
     * The advertising ID computed using the previous rotating salt, or {@code null} if:
     * <ul>
     *   <li>The caller did not request it (i.e. {@code MapRequest.includePreviousAdvertisingId} was {@code false}), or</li>
     *   <li>No previous salt is available, or the salt was last rotated more than 90 days ago.</li>
     * </ul>
     */
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
