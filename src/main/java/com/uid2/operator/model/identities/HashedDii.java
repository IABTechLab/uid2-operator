package com.uid2.operator.model.identities;

// Contains a hash Directly Identifying Information (DII) (email or phone) see https://unifiedid.com/docs/ref-info/glossary-uid#gl-dii
// This hash can either be computed from a raw email/phone number DII input or provided by the UID Participant directly
//
public record HashedDii(IdentityScope identityScope, DiiType diiType, byte[] hashedDii) {
}
