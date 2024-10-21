package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

// Contains a first level salted hash computed from Hashed DII (email/phone number)
public class FirstLevelHashIdentity extends UserIdentity {
    public final byte[] firstLevelHash;

    public FirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] firstLevelHash, int privacyBits,
                                  Instant establishedAt, Instant refreshedAt) {
        super(identityScope, identityType, privacyBits, establishedAt, refreshedAt);
        this.firstLevelHash = firstLevelHash;
    }

    public boolean matches(FirstLevelHashIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.firstLevelHash, that.firstLevelHash);
    }
}
