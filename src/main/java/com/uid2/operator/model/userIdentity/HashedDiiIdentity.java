package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;

// Contains a hash computed from a raw email/phone number DII input or the hash is provided by the UID Participant
// directly
public class HashedDiiIdentity extends UserIdentity{
    public final byte[] hashedDii;

    public HashedDiiIdentity(IdentityScope identityScope, IdentityType identityType, byte[] hashedDii, int privacyBits,
                             Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.hashedDii = hashedDii;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }
}
