package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

// Contains a first level salted hash computed from Hashed DII (email/phone number)
public class FirstLevelHashIdentity extends UserIdentity {
    public final byte[] firstLevelHash;

    // for brand new token generation, it should contain 1
    // if the first level hash is from token/refresh call, it will inherit from the refresh token
    public final int privacyBits;

    // for brand new token generation, it should be the time it is generated
    // if the first level hash is from token/refresh call, it will be when the raw UID was originally created in the earliest token generation
    public final Instant establishedAt;

    public FirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] firstLevelHash, int privacyBits,
                                  Instant establishedAt) {
        super(identityScope, identityType);
        this.firstLevelHash = firstLevelHash;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
    }

    public boolean matches(FirstLevelHashIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.firstLevelHash, that.firstLevelHash);
    }
}
