package com.uid2.operator.model.identities;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

// Contains a hash DII,
// This hash can either be computed from a raw email/phone number DII input or provided by the UID Participant directly
public record HashedDii(IdentityScope identityScope, IdentityType identityType, byte[] hashedDii) {
}
