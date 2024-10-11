package com.uid2.operator.model;

import java.time.Instant;
import java.util.Arrays;

// Contains a hash computed from a raw email/phone number DII input or the hash is provided by the UID Participant
// directly
public class HashedDiiIdentity implements UserIdentity{
    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final byte[] hashedDii;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public HashedDiiIdentity(IdentityScope identityScope, IdentityType identityType, byte[] hashedDii, int privacyBits,
                             Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.hashedDii = hashedDii;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }

    public boolean matches(HashedDiiIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.hashedDii, that.hashedDii);
    }

    public IdentityScope GetIdentityScope() { return identityScope; }
    public IdentityType GetIdentityType() { return identityType; }
    public Instant GetEstablishedAt() { return establishedAt; };
    public Instant GetIRefreshedAt() { return refreshedAt; }
}
