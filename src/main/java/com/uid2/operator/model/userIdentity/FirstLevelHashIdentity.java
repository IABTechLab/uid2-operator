package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

// Contains a first level salted hash computed from Hashed DII (email/phone number)
public class FirstLevelHashIdentity extends UserIdentity {
    public final byte[] firstLevelHash;

    // for brand new token generation, it should be the time it is generated
    // if the first level hash is from token/refresh call, it will be when the raw UID was originally created in the earliest token generation
    public final Instant establishedAt;

    public FirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] firstLevelHash,
                                  Instant establishedAt) {
        super(identityScope, identityType);
        this.firstLevelHash = firstLevelHash;
        this.establishedAt = establishedAt;
    }

    // explicitly not checking establishedAt - this is only for making sure the first level hash matches a new input
    public boolean matches(FirstLevelHashIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.firstLevelHash, that.firstLevelHash);
    }
}
