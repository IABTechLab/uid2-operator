package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;

// Contains a hash DII,
// This hash can either be computed from a raw email/phone number DII input or provided by the UID Participant directly
public class HashedDiiIdentity extends UserIdentity {
    public final byte[] hashedDii;

    public HashedDiiIdentity(IdentityScope identityScope, IdentityType identityType, byte[] hashedDii) {
        super(identityScope, identityType);
        this.hashedDii = hashedDii;
    }
}
